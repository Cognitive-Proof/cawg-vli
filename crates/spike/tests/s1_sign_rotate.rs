//! Q1. Can an AID sign arbitrary bytes (the CBOR `signer_payload`), and does a
//! signature made under an earlier establishment event still verify after a
//! rotation? PR 269 pins the keys by `kel_seq_num`, so it must.

use keri_controller::{BasicPrefix, CryptoBox, KeyManager};
use spike::{controller, incept, sign};

#[async_std::test]
async fn sign_then_rotate_then_verify_old_signature() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let c = controller(dir.path())?;
    let mut keys = CryptoBox::new()?;
    let mut id = incept(&c, &keys).await?;

    let payload = b"\xa2dtextfsigner";
    let before = id.sign_data(payload, &[sign(&keys, payload)])?;
    c.verify(payload, &before)?;
    assert_eq!(c.find_state(id.id())?.sn, 0);

    // Rotate to the pre-committed next key.
    keys.rotate()?;
    let rot = id
        .rotate(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            1,
            vec![],
            vec![],
            0,
        )
        .await?;
    id.finalize_rotate(rot.as_bytes(), sign(&keys, rot.as_bytes()))
        .await?;
    assert_eq!(c.find_state(id.id())?.sn, 1);

    // The old signature names establishment event sn 0 and must still verify.
    c.verify(payload, &before)?;

    // A new signature uses the rotated key.
    let after = id.sign_data(payload, &[sign(&keys, payload)])?;
    c.verify(payload, &after)?;
    Ok(())
}
