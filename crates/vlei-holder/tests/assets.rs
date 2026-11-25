//! Signs PNGs with c2pa-rs and a `cawg.vlei` identity assertion, reads them
//! back, and checks the KERI signatures over the stored `signer_payload`.

use std::sync::{Arc, Mutex};

use c2pa::{Reader, ValidationState};
use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::{Signature, SignerData},
    prefix::{IdentifierPrefix, IndexedSignature},
};
use vlei_chain::chain::{self, World};
use vlei_holder::{read_identity_assertion, sign_asset, SIG_TYPE};
use vlei_sign::{cbor, encode_signer_payload, Encoding, Options};

fn verify_aid_sig(w: &World, map: &vlei_sign::VleiSignaturePayload, signed: &[u8]) -> anyhow::Result<()> {
    let aid: IdentifierPrefix = map.signer_aid.parse()?;
    let est = w.controller.known_events.storage.get_last_establishment_event_seal(&aid).unwrap();
    let sigs: Vec<IndexedSignature> = map.aid_sig.iter().map(|s| s.parse()).collect::<Result<_, _>>()?;
    let seal = EventSeal::new(aid, map.kel_seq_num, est.event_digest());
    w.controller.verify(signed, &Signature::Transferable(SignerData::EventSeal(seal), sigs))?;
    Ok(())
}

#[async_std::test]
async fn signed_assets_carry_verifiable_vlei_signatures() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let world = Arc::new(Mutex::new(chain::build(dir.path()).await?));

    for (signer, anchor) in [("Alice", false), ("Bob", false), ("Carol", false), ("Fabrikam", false), ("Alice", true), ("Dana", false)] {
        let png = sign_asset(world.clone(), signer, Options { anchor }, Encoding::Deterministic, signer)?;

        // The outer C2PA manifest is well formed (its test certificate is not
        // on any trust list, so "valid" rather than "trusted" is the best case).
        let reader = Reader::default().with_stream("image/png", std::io::Cursor::new(&png))?;
        assert!(
            matches!(reader.validation_state(), ValidationState::Valid | ValidationState::Trusted),
            "{signer}: {:?}",
            reader.validation_status()
        );

        let rb = read_identity_assertion(&png)?;
        assert_eq!(rb.signer_payload.sig_type, SIG_TYPE);
        let refs: Vec<String> = rb.signer_payload.referenced_assertions.iter().map(|r| r.url()).collect();
        println!("{signer}: referenced {refs:?}");
        assert!(refs.iter().any(|r| r.contains("c2pa.actions")), "{refs:?}");
        assert!(refs.iter().any(|r| r.contains("c2pa.hash")), "hard binding: {refs:?}");
        assert_eq!(rb.map.anchor_seq_num.is_some(), anchor);

        // F1 in practice: the payload as stored is not in deterministic form,
        // so a validator following PR 269 must re-encode before verifying.
        assert!(!cbor::is_deterministic(&rb.signer_payload_cbor), "{signer}");
        let w = world.lock().unwrap();
        let signed = encode_signer_payload(&rb.signer_payload, Encoding::Deterministic);
        verify_aid_sig(&w, &rb.map, &signed).map_err(|e| anyhow::anyhow!("{signer}: {e}"))?;
        assert!(verify_aid_sig(&w, &rb.map, &rb.signer_payload_cbor).is_err(), "{signer}: stored bytes must not verify");
        println!("{signer}{}: {} byte PNG, signature field {} bytes", if anchor { " (anchored)" } else { "" }, png.len(), rb.signature.len());
    }
    Ok(())
}
