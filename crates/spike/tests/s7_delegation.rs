//! Q7. Delegation (GLEIF Root → GEDA → QVI): can a delegator approve a
//! delegated inception with an in-process witness?

use std::{collections::HashMap, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, ActionRequired, BasicPrefix, CryptoBox,
    KeyManager, LocationScheme, RedbController, RedbIdentifier,
};
use keri_core::{
    event_message::signed_event_message::Message,
    prefix::{IdentifierPrefix, IndexedSignature},
    transport::test::{TestActorMap, TestTransport},
};
use spike::sign;
use url::{Host, Url};
use witness::{WitnessEscrowConfig, WitnessListener};

async fn incept_witnessed(c: &RedbController, k: &CryptoBox, w: &LocationScheme) -> anyhow::Result<RedbIdentifier> {
    let icp = c
        .incept(vec![BasicPrefix::Ed25519(k.public_key())], vec![BasicPrefix::Ed25519(k.next_public_key())], vec![w.clone()], 1)
        .await?;
    let mut id = c.finalize_incept(icp.as_bytes(), &sign(k, icp.as_bytes()))?;
    id.notify_witnesses().await?;
    Ok(id)
}

async fn collect_receipts(id: &mut RedbIdentifier, k: &CryptoBox, about: &IdentifierPrefix, w: &BasicPrefix) -> anyhow::Result<()> {
    let qs = id
        .query_receipts(about, std::slice::from_ref(w))?
        .into_iter()
        .map(|q| { let s = sign(k, &q.encode().unwrap()); (q, s) })
        .collect();
    id.finalize_query_receipts(qs).await?;
    Ok(())
}

#[async_std::test]
async fn geda_delegates_qvi() -> anyhow::Result<()> {
    let wdir = tempfile::tempdir()?;
    let witness = Arc::new(WitnessListener::setup_with_redb(
        Url::parse("http://witness1:3232/")?, wdir.path(), Some("AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH".into()),
        WitnessEscrowConfig::default(), keri_core::event_message::keri_version::KeriVersion::V1_0,
    )?);
    let wid = witness.get_prefix();
    let wloc = LocationScheme { eid: IdentifierPrefix::Basic(wid.clone()), scheme: keri_core::oobi::Scheme::Http, url: Some(Url::parse("http://witness1:3232")?) };
    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".into()), 3232), witness);
    let transport = TestTransport::new(actors);

    let (d1, d2) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let qvi_c = Controller::new(ControllerConfig { db_path: d1.path().into(), transport: Box::new(transport.clone()), ..Default::default() })?;
    let geda_c = Controller::new(ControllerConfig { db_path: d2.path().into(), transport: Box::new(transport.clone()), ..Default::default() })?;

    let (qk, gk) = (CryptoBox::new()?, CryptoBox::new()?);
    let mut qvi = incept_witnessed(&qvi_c, &qk, &wloc).await?;
    let qid = qvi.id().clone();
    collect_receipts(&mut qvi, &qk, &qid, &wid).await?;
    let mut geda = incept_witnessed(&geda_c, &gk, &wloc).await?;
    let gid = geda.id().clone();
    collect_receipts(&mut geda, &gk, &gid, &wid).await?;
    for n in qvi_c.get_kel_with_receipts(&qid).unwrap() { geda_c.known_events.save(&Message::Notice(n))?; }
    for n in geda_c.get_kel_with_receipts(&gid).unwrap() { qvi_c.known_events.save(&Message::Notice(n))?; }

    let (dip, exns) = qvi.incept_group(vec![], 1, Some(1), Some(vec![wid.clone()]), Some(1), Some(gid.clone()))?;
    let exn_sig = qvi.sign_with_index(sign(&qk, exns[0].as_bytes()), 0)?;
    let (delegated, fwd) = qvi.finalize_group_incept(dip.as_bytes(), sign(&qk, dip.as_bytes()), vec![(exns[0].as_bytes().to_vec(), exn_sig)]).await?;

    let actions = geda.receive_forwards(&fwd[0].message).await?;
    let [ActionRequired::DelegationRequest(ixn, exn)] = actions.as_slice() else { panic!("{actions:?}") };
    let ixn_sig = sign(&gk, &ixn.encode()?);
    let exn_isig = geda.sign_with_index(sign(&gk, &exn.encode()?), 0)?;
    geda.finalize_group_event(&ixn.encode()?, ixn_sig.clone(), vec![]).await?;
    geda.notify_witnesses().await?;
    collect_receipts(&mut geda, &gk, &gid, &wid).await?;
    let approval = geda.finalize_exchange(&exn.encode()?, exn_isig, ixn, IndexedSignature::new_both_same(ixn_sig, 0))?;

    qvi.receive_forwards(&approval.message).await?;
    collect_receipts(&mut qvi, &qk, &delegated, &wid).await?;
    let state = qvi.find_state(&delegated)?;
    println!("delegated QVI {delegated} sn={} delegator={:?}", state.sn, state.delegator);
    assert_eq!(state.delegator, Some(gid));
    Ok(())
}
