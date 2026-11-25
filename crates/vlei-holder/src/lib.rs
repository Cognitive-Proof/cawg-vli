//! Puts `cawg.vlei` identity assertions into real C2PA assets with c2pa-rs.
//!
//! [`VleiCredentialHolder`] is a c2pa-rs [`CredentialHolder`]: c2pa-rs builds
//! the `signer_payload` (with the hashes of the referenced assertions), hands
//! it over, and stores whatever `sign` returns in the identity assertion's
//! `signature` field — here, the CBOR `vlei-signature-payload-map`.

use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};

use c2pa::{
    identity::{
        builder::{CredentialHolder, IdentityBuilderError},
        IdentityAssertion, SignerPayload,
    },
    BoxedSigner, Builder, Reader, SigningAlg,
};
use vlei_chain::chain::World;
use vlei_sign::{Encoding, Options, VleiSignaturePayload};

pub const SIG_TYPE: &str = "cawg.vlei";

/// Room reserved for the `signature` field. Measured maps are 3–7.5 KB (the
/// ECR bundle is the largest); keep headroom for more OOBIs and signatures.
pub const RESERVE_SIZE: usize = 16 * 1024;

pub struct VleiCredentialHolder {
    pub world: Arc<Mutex<World>>,
    pub signer: String,
    pub options: Options,
    pub encoding: Encoding,
}

impl CredentialHolder for VleiCredentialHolder {
    fn sig_type(&self) -> &'static str {
        SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        RESERVE_SIZE
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        let fail = |e: &dyn std::fmt::Display| IdentityBuilderError::SignerError(e.to_string());
        let payload = vlei_sign::encode_signer_payload(signer_payload, self.encoding);
        let mut world = self.world.lock().map_err(|e| fail(&e))?;
        let bundle = vlei_sign::bundle_for(&world, &self.signer).map_err(|e| fail(&e))?;
        let map = async_std::task::block_on(vlei_sign::sign(&mut world, &self.signer, bundle, &payload, self.options))
            .map_err(|e| fail(&e))?;
        Ok(map.to_cbor())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HolderError {
    #[error("certificate: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("c2pa: {0}")]
    C2pa(#[from] c2pa::Error),
    #[error("{0}")]
    Other(String),
}

/// A throwaway ES256 claim signer: a test CA and an end-entity certificate
/// with the key usages C2PA expects. Generated per call; nothing on disk.
pub fn test_claim_signer() -> Result<BoxedSigner, HolderError> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    let dn = |cn: &str| {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        d.push(DnType::OrganizationName, "cawg-vlei testbed");
        d
    };

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.distinguished_name = dn("cawg-vlei testbed CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ee = CertificateParams::new(Vec::<String>::new())?;
    ee.distinguished_name = dn("cawg-vlei testbed claim signer");
    ee.is_ca = IsCa::ExplicitNoCa;
    ee.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    // C2PA's certificate profile requires an Authority Key Identifier.
    ee.use_authority_key_identifier_extension = true;
    let now = rcgen::date_time_ymd(2026, 1, 1);
    ee.not_before = now;
    ee.not_after = rcgen::date_time_ymd(2036, 1, 1);
    ca.not_before = now;
    ca.not_after = rcgen::date_time_ymd(2036, 1, 1);
    let ca_cert = ca.self_signed(&ca_key)?;
    let issuer = Issuer::from_params(&ca, &ca_key);
    let ee_cert = ee.signed_by(&ee_key, &issuer)?;

    let chain = format!("{}{}", ee_cert.pem(), ca_cert.pem());
    Ok(c2pa::create_signer::from_keys(chain.as_bytes(), ee_key.serialize_pem().as_bytes(), SigningAlg::Es256, None)?)
}

/// A 1×1 transparent PNG.
pub const BLANK_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49,
    0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

/// Signs a PNG with a C2PA manifest whose identity assertion is a
/// `cawg.vlei` signature by `signer` (a person or group in `world`).
pub fn sign_asset(
    world: Arc<Mutex<World>>,
    signer: &str,
    options: Options,
    encoding: Encoding,
    title: &str,
) -> Result<Vec<u8>, HolderError> {
    let definition = serde_json::json!({
        "claim_generator_info": [{ "name": "cawg-vlei-testbed", "version": env!("CARGO_PKG_VERSION") }],
        "title": title,
        "assertions": [{
            "label": "c2pa.actions",
            "data": { "actions": [{
                "action": "c2pa.created",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
            }] }
        }]
    });
    let mut builder = Builder::default().with_definition(definition.to_string())?;
    let holder = VleiCredentialHolder { world, signer: signer.into(), options, encoding };
    let signer = c2pa::create_signer::from_credential_holder(
        test_claim_signer()?,
        Box::new(holder),
        // c2pa-rs writes actions as `c2pa.actions.v2`; references match labels exactly.
        &["c2pa.actions.v2"],
        &["cawg.creator"],
    );
    let mut source = Cursor::new(BLANK_PNG);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(signer.as_ref(), "image/png", &mut source, &mut dest)?;
    Ok(dest.into_inner())
}

/// What a reader finds in a signed asset's identity assertion.
#[derive(Debug, Clone)]
pub struct ReadBack {
    pub signer_payload: SignerPayload,
    /// `signer_payload` as stored in the assertion (c2pa-rs encoding).
    pub signer_payload_cbor: Vec<u8>,
    pub signature: Vec<u8>,
    pub map: VleiSignaturePayload,
    /// The identity assertion as stored (CBOR).
    pub assertion_cbor: Vec<u8>,
}

/// Reads the (single) identity assertion of a signed PNG.
pub fn read_identity_assertion(asset: &[u8]) -> Result<ReadBack, HolderError> {
    let reader = Reader::default().with_stream("image/png", Cursor::new(asset))?;
    let manifest = reader.active_manifest().ok_or_else(|| HolderError::Other("no active manifest".into()))?;
    // `IdentityAssertion::from_manifest` is crate-private in c2pa 0.92, so go
    // through the generic assertion lookup.
    let label = manifest
        .assertions()
        .iter()
        .map(|a| a.label().to_owned())
        .find(|l| l.starts_with("cawg.identity"))
        .ok_or_else(|| HolderError::Other("no identity assertion".into()))?;
    let ia: IdentityAssertion = manifest.find_assertion(&label)?;
    let mut assertion_cbor = Vec::new();
    c2pa_cbor::to_writer(&mut assertion_cbor, &ia).map_err(|e| HolderError::Other(e.to_string()))?;
    let value: ciborium::value::Value =
        ciborium::from_reader(assertion_cbor.as_slice()).map_err(|e| HolderError::Other(e.to_string()))?;
    let field = |name: &str| {
        value.as_map().and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some(name)).map(|(_, v)| v.clone()))
    };
    let signature = field("signature").and_then(|v| v.as_bytes().cloned()).unwrap_or_default();
    let mut signer_payload_cbor = Vec::new();
    ciborium::into_writer(&field("signer_payload").unwrap_or(ciborium::value::Value::Null), &mut signer_payload_cbor)
        .map_err(|e| HolderError::Other(e.to_string()))?;
    let map = VleiSignaturePayload::from_cbor(&signature).map_err(|e| HolderError::Other(e.to_string()))?;
    Ok(ReadBack { signer_payload: ia.signer_payload().clone(), signer_payload_cbor, signature, map, assertion_cbor })
}
