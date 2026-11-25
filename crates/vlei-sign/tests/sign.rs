//! Signs a `signer_payload` as each kind of signer and checks the result with
//! keriox's own verification against the key state at `kel_seq_num`.

use c2pa::{identity::SignerPayload, HashedUri};
use keri_core::{
    event::sections::seal::{DigestSeal, EventSeal, Seal},
    event_message::signature::{Signature, SignerData},
    prefix::{IdentifierPrefix, IndexedSignature},
};
use vlei_chain::chain::{self, World};
use vlei_sign::{bundle_for, cbor, digest, encode_signer_payload, sign, Encoding, Options, VleiSignaturePayload};

fn signer_payload() -> SignerPayload {
    SignerPayload {
        referenced_assertions: vec![HashedUri::new("self#jumbf=c2pa.assertions/c2pa.hash.data".into(), None, &[7u8; 32])],
        sig_type: "cawg.vlei".into(),
        roles: vec!["cawg.creator".into()],
    }
}

/// Verifies `aid_sig` over `payload` against the signer's establishment event
/// `kel_seq_num`, using keriox (threshold included).
fn verify(w: &World, p: &VleiSignaturePayload, payload: &[u8]) -> anyhow::Result<()> {
    let aid: IdentifierPrefix = p.signer_aid.parse()?;
    let est = w.controller.known_events.storage.get_last_establishment_event_seal(&aid).unwrap();
    anyhow::ensure!(est.sn == p.kel_seq_num, "kel_seq_num");
    let sigs: Vec<IndexedSignature> = p.aid_sig.iter().map(|s| s.parse()).collect::<Result<_, _>>()?;
    let seal = EventSeal::new(aid, p.kel_seq_num, est.event_digest());
    w.controller.verify(payload, &Signature::Transferable(SignerData::EventSeal(seal), sigs))?;
    Ok(())
}

async fn world() -> anyhow::Result<(tempfile::TempDir, World)> {
    let dir = tempfile::tempdir()?;
    let w = chain::build(dir.path()).await?;
    Ok((dir, w))
}

#[async_std::test]
async fn each_signer_produces_a_verifiable_map() -> anyhow::Result<()> {
    let (_d, mut w) = world().await?;
    let payload = encode_signer_payload(&signer_payload(), Encoding::Deterministic);
    for (signer, sigs, role) in [("Alice", 1, true), ("Bob", 1, true), ("Carol", 1, true), ("Dana", 2, true), ("Fabrikam", 2, false)] {
        let bundle = bundle_for(&w, signer)?;
        let p = sign(&mut w, signer, bundle, &payload, Options::default()).await?;
        assert_eq!(p.aid_sig.len(), sigs, "{signer}");
        assert_eq!(p.role_cred.is_some(), role, "{signer}");
        assert_eq!(p.signer_aid_oobi.len(), 1, "{signer} has an OOBI");
        assert_eq!(p.anchor_seq_num, None);
        verify(&w, &p, &payload).map_err(|e| anyhow::anyhow!("{signer}: {e}"))?;

        // Round trip through deterministic CBOR.
        let bytes = p.to_cbor();
        assert!(cbor::is_deterministic(&bytes), "{signer}");
        assert_eq!(VleiSignaturePayload::from_cbor(&bytes)?, p);
        println!("{signer}: map {} bytes", bytes.len());
    }
    // Carol's ECR was issued by the legal entity: empty auth_cred.
    let b = bundle_for(&w, "Carol")?;
    let carol = sign(&mut w, "Carol", b, &payload, Options::default()).await?;
    assert_eq!(carol.role_cred.unwrap().auth_cred, "");
    Ok(())
}

#[async_std::test]
async fn one_of_two_group_signatures_fails_threshold() -> anyhow::Result<()> {
    let (_d, mut w) = world().await?;
    let payload = encode_signer_payload(&signer_payload(), Encoding::Deterministic);
    let b = bundle_for(&w, "Dana")?;
    let mut p = sign(&mut w, "Dana", b, &payload, Options::default()).await?;
    p.aid_sig.truncate(1);
    assert!(verify(&w, &p, &payload).is_err());
    Ok(())
}

#[async_std::test]
async fn anchored_signature_records_payload_digest() -> anyhow::Result<()> {
    let (_d, mut w) = world().await?;
    let payload = encode_signer_payload(&signer_payload(), Encoding::Deterministic);
    for signer in ["Alice", "Dana"] {
        let b = bundle_for(&w, signer)?;
        let p = sign(&mut w, signer, b, &payload, Options { anchor: true }).await?;
        let sn = p.anchor_seq_num.expect("anchored");
        let aid: IdentifierPrefix = p.signer_aid.parse()?;
        let kel = w.controller.get_kel_with_receipts(&aid).unwrap();
        let seal = Seal::Digest(DigestSeal::new(digest(&payload).parse()?));
        let event = kel.iter().find_map(|n| match n {
            keri_core::event_message::signed_event_message::Notice::Event(e) if e.event_message.data.get_sn() == sn => Some(e),
            _ => None,
        });
        let event = event.expect("event at anchor_seq_num");
        assert!(event.event_message.data.event_data.seals().contains(&seal), "{signer}");
        // Anchoring is an ixn, so the establishment event doesn't move.
        assert!(p.kel_seq_num < sn);
        verify(&w, &p, &payload)?;
    }
    Ok(())
}

#[test]
fn signed_bytes_depend_on_encoding_choice() {
    // Finding F1: the PR's deterministic bytes differ from what c2pa-rs stores.
    let sp = signer_payload();
    let det = encode_signer_payload(&sp, Encoding::Deterministic);
    let native = encode_signer_payload(&sp, Encoding::C2paRs);
    assert_ne!(det, native);
    assert!(cbor::is_deterministic(&det));
    assert!(!cbor::is_deterministic(&native));
    assert_eq!(cbor::deterministic(&native).unwrap(), det);
}

#[test]
fn diag_shows_embedded_map() {
    let p = VleiSignaturePayload {
        signer_aid: "EAID".into(),
        qvi_cred: "{}".into(),
        le_cred: "{}".into(),
        role_cred: None,
        signer_aid_oobi: vec!["http://w/oobi".into()],
        kel_seq_num: 0,
        anchor_seq_num: None,
        aid_sig: vec!["AA".into()],
    };
    let mut outer = Vec::new();
    let v = ciborium::value::Value::Map(vec![(
        ciborium::value::Value::Text("signature".into()),
        ciborium::value::Value::Bytes(p.to_cbor()),
    )]);
    ciborium::into_writer(&v, &mut outer).unwrap();
    let d = cbor::diag(&outer).unwrap();
    assert!(d.contains("\"signature\": << {") && d.contains("\"kel_seq_num\": 0"), "{d}");
}
