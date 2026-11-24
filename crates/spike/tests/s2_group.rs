//! Q2. Can we build a 2-of-2 multisig AID (the legal entity's LARs), and does
//! verification enforce the threshold when only one member signs?

use keri_controller::{ActionRequired, CryptoBox};
use keri_core::{
    event_message::signature::{Signature, SignerData},
    prefix::IndexedSignature,
};
use spike::{controller, incept, sign};

#[async_std::test]
async fn two_of_two_group_threshold_is_enforced() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let c = controller(dir.path())?;
    let (k1, k2) = (CryptoBox::new()?, CryptoBox::new()?);
    let mut a = incept(&c, &k1).await?;
    let mut b = incept(&c, &k2).await?;

    let (icp, exns) = a.incept_group(vec![b.id().clone()], 2, Some(2), None, None, None)?;
    let exn_sig = a.sign_with_index(sign(&k1, exns[0].as_bytes()), 0)?;
    let (group, forwards) = a
        .finalize_group_incept(
            icp.as_bytes(),
            sign(&k1, icp.as_bytes()),
            vec![(exns[0].as_bytes().to_vec(), exn_sig)],
        )
        .await?;
    let actions = b.receive_forwards(&forwards[0].message).await?;
    assert!(matches!(actions.as_slice(), [ActionRequired::MultisigRequest(..)]));
    b.finalize_group_event(icp.as_bytes(), sign(&k2, icp.as_bytes()), vec![])
        .await?;
    let state = c.find_state(&group)?;
    assert_eq!(state.current.public_keys.len(), 2);

    let payload = b"signer_payload bytes";
    let seal = keri_core::event::sections::seal::EventSeal::new(
        group.clone(),
        0,
        state.last_event_digest.clone().into(),
    );
    let both = Signature::Transferable(
        SignerData::EventSeal(seal.clone()),
        vec![
            IndexedSignature::new_both_same(sign(&k1, payload), 0),
            IndexedSignature::new_both_same(sign(&k2, payload), 1),
        ],
    );
    c.verify(payload, &both)?;

    let one = Signature::Transferable(
        SignerData::EventSeal(seal),
        vec![IndexedSignature::new_both_same(sign(&k1, payload), 0)],
    );
    let result = c.verify(payload, &one);
    println!("one-of-two verify result: {result:?}");
    assert!(result.is_err(), "threshold kt=2 must reject a single signature");
    Ok(())
}
