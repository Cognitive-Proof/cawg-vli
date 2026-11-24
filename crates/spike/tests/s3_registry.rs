//! Q3. Can we issue and revoke a credential in a TEL anchored in the issuer's
//! KEL, and read the status back? (teliox: ACDC v2 registries only.)

use keri_controller::{
    registry::{AcdcBinding, Blinding, Policy, Verdict},
    CryptoBox,
};
use spike::{controller, incept, sign};

#[async_std::test]
async fn issue_then_revoke_le_credential_v2() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let c = controller(dir.path())?;
    let keys = CryptoBox::new()?;
    let mut qvi = incept(&c, &keys).await?;

    let rip = qvi.incept_registry()?;
    let registry = rip.event.said().unwrap();
    let blinding = Blinding::private();
    let cred = acdc::Acdc::builder(qvi.id().to_string(), "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY")
        .private()
        .registry(registry.to_string())
        .attributes(acdc::Block::new().with("LEI", "254900OPPU84GM83MG36"))
        .build(acdc::Kind::Json, acdc::HashFunctionCode::Blake3_256)?;
    let said: said::SelfAddressingIdentifier = cred.said().parse()?;
    let binding = AcdcBinding { said: said.clone(), issuer: qvi.id().clone(), registry: Some(registry.clone()) };
    let policy = Policy::default();

    let (issued, ixn) = qvi.issue_in(rip, &blinding, &said)?;
    let ixn = ixn.encode()?;
    qvi.finalize_registry_events(&issued, &ixn, sign(&keys, &ixn)).await?;
    match qvi.registry_verdict(&registry, Some(&binding), &policy)? {
        Verdict::Valid { state, .. } => assert_eq!(state.state.as_deref(), Some("issued")),
        other => panic!("{other:?}"),
    }
    println!("v2 credential version: {:?}", cred.version());

    let (revoked, ixn) = qvi.revoke(&registry, &blinding, &said)?;
    let ixn = ixn.encode()?;
    qvi.finalize_registry_events(&revoked, &ixn, sign(&keys, &ixn)).await?;
    match qvi.registry_verdict(&registry, Some(&binding), &policy)? {
        Verdict::Valid { state, .. } => assert_eq!(state.state.as_deref(), Some("revoked")),
        other => panic!("{other:?}"),
    }
    Ok(())
}
