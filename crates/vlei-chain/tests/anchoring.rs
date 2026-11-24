//! A QVI runs a no-backer registry: `vcp`, `iss` and `rev` are anchored in its
//! KEL with `ixn` seals, and a verifier derives the credential's status.

use keri_controller::{
    config::ControllerConfig, controller::Controller, BasicPrefix, CryptoBox, KeyManager,
    RedbController, RedbIdentifier, SelfSigningPrefix,
};
use keri_core::event_message::signed_event_message::Notice;
use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
use vlei_chain::tel::{self, Status, TelError, TelEvent};

const DT: &str = "2026-11-24T00:00:00.000000+00:00";
const LE_SCHEMA: &str = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";

struct Issuer {
    c: RedbController,
    id: RedbIdentifier,
    keys: CryptoBox,
    _dir: tempfile::TempDir,
}

impl Issuer {
    async fn new() -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let c = Controller::new(ControllerConfig { db_path: dir.path().into(), ..Default::default() })?;
        let keys = CryptoBox::new()?;
        let icp = c
            .incept(vec![BasicPrefix::Ed25519(keys.public_key())], vec![BasicPrefix::Ed25519(keys.next_public_key())], vec![], 0)
            .await?;
        let sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes())?);
        let id = c.finalize_incept(icp.as_bytes(), &sig)?;
        Ok(Self { c, id, keys, _dir: dir })
    }

    fn aid(&self) -> String {
        self.id.id().to_string()
    }

    async fn anchor(&mut self, e: &TelEvent) -> anyhow::Result<()> {
        let ixn = self.id.anchor_with_seal(&[e.seal()?])?.encode()?;
        let sig = SelfSigningPrefix::Ed25519Sha512(self.keys.sign(&ixn)?);
        self.id.finalize_anchor(&ixn, sig).await?;
        Ok(())
    }

    fn kel(&self) -> Vec<Notice> {
        self.c.get_kel_with_receipts(self.id.id()).unwrap_or_default()
    }
}

/// An ACDC 1.0 Legal Entity credential issued in `registry`.
fn le_credential(issuer: &str, registry: &str) -> anyhow::Result<String> {
    let mut a: Sad = serde_json::from_str(&format!(
        r#"{{"d":"","i":"EHolderAIDplaceholder0000000000000000000000","dt":"{DT}","LEI":"254900OPPU84GM83MG36"}}"#
    ))?;
    saidify(&mut a, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["d"])?;
    let mut acdc: Sad = serde_json::from_str(&format!(
        r#"{{"v":"ACDC10JSON000000_","d":"","i":"{issuer}","ri":"{registry}","s":"{LE_SCHEMA}","a":{}}}"#,
        serde_json::to_string(&a)?
    ))?;
    let (said, raw) = saidify(&mut acdc, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["d"])?;
    let parsed = acdc::legacy::LegacyAcdc::parse(&raw)?;
    assert_eq!((parsed.issuer(), parsed.registry()), (issuer, Some(registry)));
    Ok(said.to_string())
}

#[async_std::test]
async fn issue_then_revoke() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let vcp = tel::vcp(&qvi.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    qvi.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;

    let iss = tel::iss(&cred, vcp.prefix(), DT)?;
    qvi.anchor(&iss).await?;
    assert_eq!(tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &iss, None)?, Status::Issued);

    let rev = tel::rev(&cred, vcp.prefix(), iss.said(), DT)?;
    qvi.anchor(&rev).await?;
    assert_eq!(tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &iss, Some(&rev))?, Status::Revoked);

    // Events round-trip through their serialized form.
    for e in [&vcp, &iss, &rev] {
        assert_eq!(&TelEvent::parse(e.raw())?, e);
    }
    Ok(())
}

#[async_std::test]
async fn unanchored_issuance_is_rejected() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let vcp = tel::vcp(&qvi.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    qvi.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;
    let iss = tel::iss(&cred, vcp.prefix(), DT)?; // never anchored
    let err = tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &iss, None).unwrap_err();
    assert!(matches!(err, TelError::NotAnchored { ref kind, .. } if kind == "iss"), "{err}");
    Ok(())
}

#[async_std::test]
async fn unanchored_revocation_is_rejected() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let vcp = tel::vcp(&qvi.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    qvi.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;
    let iss = tel::iss(&cred, vcp.prefix(), DT)?;
    qvi.anchor(&iss).await?;
    let rev = tel::rev(&cred, vcp.prefix(), iss.said(), DT)?; // forged: not anchored
    let err = tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &iss, Some(&rev)).unwrap_err();
    assert!(matches!(err, TelError::NotAnchored { ref kind, .. } if kind == "rev"), "{err}");
    Ok(())
}

#[async_std::test]
async fn revocation_must_chain_to_issuance() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let vcp = tel::vcp(&qvi.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    qvi.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;
    let iss = tel::iss(&cred, vcp.prefix(), DT)?;
    qvi.anchor(&iss).await?;
    let rev = tel::rev(&cred, vcp.prefix(), vcp.said(), DT)?; // wrong prior
    qvi.anchor(&rev).await?;
    let err = tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &iss, Some(&rev)).unwrap_err();
    assert!(matches!(err, TelError::Mismatch(_)), "{err}");
    Ok(())
}

#[async_std::test]
async fn registry_of_another_issuer_is_rejected() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let mut rogue = Issuer::new().await?;
    // The rogue runs its own registry and "issues" a credential naming the QVI.
    let vcp = tel::vcp(&rogue.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    rogue.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;
    let iss = tel::iss(&cred, vcp.prefix(), DT)?;
    rogue.anchor(&iss).await?;
    let _ = &mut qvi;
    let err = tel::credential_status(&cred, &qvi.aid(), &rogue.kel(), &vcp, &iss, None).unwrap_err();
    assert!(matches!(err, TelError::Mismatch(_)), "{err}");
    Ok(())
}

#[async_std::test]
async fn issuance_of_a_different_credential_is_rejected() -> anyhow::Result<()> {
    let mut qvi = Issuer::new().await?;
    let vcp = tel::vcp(&qvi.aid(), "0ABhY2RjLXRlc3RiZWQtbm9uY2U")?;
    qvi.anchor(&vcp).await?;
    let cred = le_credential(&qvi.aid(), vcp.prefix())?;
    let other_said = said::derivation::HashFunction::from(HashFunctionCode::Blake3_256).derive(b"another credential").to_string();
    let other = tel::iss(&other_said, vcp.prefix(), DT)?;
    qvi.anchor(&other).await?;
    let err = tel::credential_status(&cred, &qvi.aid(), &qvi.kel(), &vcp, &other, None).unwrap_err();
    assert!(matches!(err, TelError::Mismatch(_)), "{err}");
    Ok(())
}
