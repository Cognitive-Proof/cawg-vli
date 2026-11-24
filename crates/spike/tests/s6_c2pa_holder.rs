//! Q6. Does c2pa-rs accept a custom credential holder for `sig_type`
//! "cawg.vlei" (signing) and a custom verifier (validation)?

use c2pa::identity::{
    builder::{CredentialHolder, IdentityBuilderError},
    SignerPayload,
};

struct VleiHolder;

impl CredentialHolder for VleiHolder {
    fn sig_type(&self) -> &'static str {
        "cawg.vlei"
    }
    fn reserve_size(&self) -> usize {
        // Three JSON ACDCs plus OOBIs and signatures: budget generously.
        64 * 1024
    }
    fn sign(&self, _signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        Ok(vec![0xa0]) // empty CBOR map; Phase 3 fills this in.
    }
}

#[test]
fn custom_holder_plugs_into_identity_builder() {
    let _builder = c2pa::identity::builder::IdentityAssertionBuilder::for_credential_holder(VleiHolder);
}
