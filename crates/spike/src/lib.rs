//! Phase 0 capability checks. Each test file answers one question about the
//! Rust KERI / ACDC / C2PA stack; see `PHASE0.md` at the repository root.

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    BasicPrefix, CryptoBox, KeyManager, RedbController, RedbIdentifier,
    SelfSigningPrefix,
};
use std::path::Path;

/// A controller backed by a fresh database in `dir`, with no witnesses.
pub fn controller(dir: &Path) -> Result<RedbController, ControllerError> {
    Controller::new(ControllerConfig {
        db_path: dir.to_owned(),
        ..Default::default()
    })
}

/// Incepts a single-key, witness-less identifier.
pub async fn incept(
    controller: &RedbController,
    keys: &CryptoBox,
) -> Result<RedbIdentifier, ControllerError> {
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            vec![],
            0,
        )
        .await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes())?);
    controller.finalize_incept(icp.as_bytes(), &sig)
}

pub fn sign(keys: &CryptoBox, data: &[u8]) -> SelfSigningPrefix {
    SelfSigningPrefix::Ed25519Sha512(keys.sign(data).expect("sign"))
}

