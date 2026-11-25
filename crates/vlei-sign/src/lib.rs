//! The `cawg.vlei` signature (CAWG identity assertion PR 269).
//!
//! [`encode_signer_payload`] produces the bytes that get signed,
//! [`sign`] produces a [`VleiSignaturePayload`], and
//! [`VleiSignaturePayload::to_cbor`] the bytes for the identity assertion's
//! `signature` field.
//!
//! The map follows PR 269's `vlei-signature-payload-map`, with its CDDL
//! corrected (`role_cred` is a map, entries separated by commas):
//!
//! ```cddl
//! vlei-signature-payload-map = {
//!   "signer_aid": tstr,
//!   "qvi_cred": tstr,
//!   "le_cred": tstr,
//!   ? "role_cred": { "auth_cred": tstr, "cred": tstr },
//!   "signer_aid_oobi": [+ tstr],
//!   "kel_seq_num": uint,
//!   ? "anchor_seq_num": uint,
//!   "aid_sig": [+ tstr],
//! }
//! ```

pub mod cbor;

use c2pa::identity::SignerPayload;
use keri_core::{
    event::sections::seal::{DigestSeal, Seal},
    prefix::{CesrPrimitive, IndexedSignature},
};
use keri_controller::{BasicPrefix, KeyManager, SelfSigningPrefix};
use said::derivation::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use vlei_chain::chain::{ChainError, World};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleCred {
    pub auth_cred: String,
    pub cred: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VleiSignaturePayload {
    pub signer_aid: String,
    pub qvi_cred: String,
    pub le_cred: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub role_cred: Option<RoleCred>,
    pub signer_aid_oobi: Vec<String>,
    pub kel_seq_num: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub anchor_seq_num: Option<u64>,
    pub aid_sig: Vec<String>,
}

impl VleiSignaturePayload {
    /// Core deterministic CBOR, as PR 269 requires for this map.
    pub fn to_cbor(&self) -> Vec<u8> {
        cbor::deterministic_from_serialize(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SignError> {
        ciborium::from_reader(bytes).map_err(|e| SignError::Cbor(e.to_string()))
    }
}

/// Which bytes of `signer_payload` are signed. PR 269 says core deterministic
/// encoding; c2pa-rs (and its X.509 credential holder) signs its own
/// encoding, which orders keys differently. See finding F1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// RFC 8949 §4.2.1 core deterministic encoding (PR 269).
    Deterministic,
    /// The encoding c2pa-rs writes into the assertion.
    C2paRs,
}

pub fn encode_signer_payload(sp: &SignerPayload, encoding: Encoding) -> Vec<u8> {
    let mut native = Vec::new();
    c2pa_cbor::to_writer(&mut native, sp).expect("SignerPayload encodes");
    match encoding {
        Encoding::C2paRs => native,
        Encoding::Deterministic => cbor::deterministic(&native).expect("own CBOR decodes"),
    }
}

/// CESR-encoded Blake3-256 digest, as anchored with `anchor_seq_num`.
pub fn digest(bytes: &[u8]) -> String {
    HashFunction::from(HashFunctionCode::Blake3_256).derive(bytes).to_string()
}

/// The credentials a signer presents.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub qvi_cred: String,
    pub le_cred: String,
    pub role_cred: Option<RoleCred>,
}

/// The standard bundle for each signer in the testbed world.
pub fn bundle_for(world: &World, signer: &str) -> Result<Bundle, SignError> {
    let cred = |n: &str| {
        world.credentials.get(n).map(|c| c.credential.json.clone()).ok_or_else(|| SignError::Unknown(n.into()))
    };
    let role = match signer {
        "Alice" => Some((cred("oor-auth-alice")?, cred("oor-alice")?)),
        "Dana" => Some((cred("oor-auth-dana")?, cred("oor-dana")?)),
        "Bob" => Some((cred("ecr-auth-bob")?, cred("ecr-bob")?)),
        // ECR issued by the legal entity: no authorisation credential.
        "Carol" => Some((String::new(), cred("ecr-carol")?)),
        // The legal entity signing for itself.
        "Fabrikam" => None,
        other => return Err(SignError::Unknown(other.into())),
    };
    Ok(Bundle {
        qvi_cred: cred("qvi")?,
        le_cred: cred("le")?,
        role_cred: role.map(|(auth_cred, cred)| RoleCred { auth_cred, cred }),
    })
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Anchor the payload digest in the signer's KEL (`anchor_seq_num`).
    pub anchor: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("unknown signer or credential `{0}`")]
    Unknown(String),
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("KERI: {0}")]
    Keri(String),
    #[error("CBOR: {0}")]
    Cbor(String),
}

fn keri(e: impl std::fmt::Display) -> SignError {
    SignError::Keri(e.to_string())
}

/// Signs `payload` (the encoded `signer_payload`) as `signer`, a person or a
/// group in `world`, and assembles the `vlei-signature-payload-map`.
pub async fn sign(
    world: &mut World,
    signer: &str,
    bundle: Bundle,
    payload: &[u8],
    options: Options,
) -> Result<VleiSignaturePayload, SignError> {
    let (aid, oobis) = if let Some(p) = world.people.get(signer) {
        (p.id.id().clone(), p.oobis.clone())
    } else if let Some(o) = world.orgs.get(signer) {
        (o.prefix.clone(), o.oobis.clone())
    } else {
        return Err(SignError::Unknown(signer.into()));
    };

    let anchor_seq_num = if options.anchor {
        let seal = Seal::Digest(DigestSeal::new(digest(payload).parse().map_err(keri)?));
        if world.people.contains_key(signer) {
            let p = world.people.get_mut(signer).unwrap();
            let ixn = p.id.anchor_with_seal(&[seal]).map_err(keri)?.encode().map_err(keri)?;
            let sig = p.sign(&ixn)?;
            p.id.finalize_anchor(&ixn, sig).await.map_err(keri)?;
            world.publish(signer).await?;
        } else {
            world.anchor(signer, &[seal]).await?;
        }
        Some(world.controller.find_state(&aid).map_err(keri)?.sn)
    } else {
        None
    };

    let state = world.controller.find_state(&aid).map_err(keri)?;
    let kel_seq_num = world
        .controller
        .known_events
        .storage
        .get_last_establishment_event_seal(&aid)
        .ok_or_else(|| keri("no establishment event"))?
        .sn;
    let keys: Vec<String> = state.current.public_keys.iter().map(|k| k.to_str()).collect();

    // Each signing key signs; the index is the key's position in `k`.
    let mut signers: Vec<(&keri_controller::CryptoBox, BasicPrefix)> = Vec::new();
    if let Some(p) = world.people.get(signer) {
        signers.push((&p.keys, BasicPrefix::Ed25519(p.keys.public_key())));
    } else {
        let org = &world.orgs[signer];
        for m in org.members.iter().take(org.threshold) {
            signers.push((&m.keys, BasicPrefix::Ed25519(m.keys.public_key())));
        }
    }
    let mut aid_sig = Vec::new();
    for (keys_box, public) in signers {
        let index = keys.iter().position(|k| *k == public.to_str()).ok_or_else(|| keri("signing key not current"))?;
        let sig = SelfSigningPrefix::Ed25519Sha512(keys_box.sign(payload).map_err(keri)?);
        aid_sig.push(IndexedSignature::new_both_same(sig, index as u16).to_str());
    }

    Ok(VleiSignaturePayload {
        signer_aid: aid.to_string(),
        qvi_cred: bundle.qvi_cred,
        le_cred: bundle.le_cred,
        role_cred: bundle.role_cred,
        signer_aid_oobi: oobis,
        kel_seq_num,
        anchor_seq_num,
        aid_sig,
    })
}
