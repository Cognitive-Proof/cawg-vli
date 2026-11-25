//! Builds the full trust chain and checks each link the way PR 269's trust
//! model describes it.

use keri_controller::config::ControllerConfig;
use keri_controller::controller::Controller;
use vlei_chain::{
    chain::{self, Fixtures},
    schema::Kind,
    tel::{self, Status, TelEvent},
};

fn status(f: &Fixtures, w: &chain::World, name: &str) -> Status {
    let issued = &f.credentials[name];
    let cred = &issued.credential;
    let issuer = cred.issuer.parse().unwrap();
    let kel = w.controller.get_kel_with_receipts(&issuer).unwrap();
    let registry_org = f.aids.iter().find(|(_, a)| a.prefix == cred.issuer).unwrap().0;
    let vcp = TelEvent::parse(f.registries[registry_org].as_bytes()).unwrap();
    let iss = TelEvent::parse(issued.tel[0].as_bytes()).unwrap();
    let rev = issued.tel.get(1).map(|r| TelEvent::parse(r.as_bytes()).unwrap());
    tel::credential_status(&cred.said, &cred.issuer, &kel, &vcp, &iss, rev.as_ref()).unwrap()
}

#[async_std::test]
async fn full_chain_builds_and_links() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let w = chain::build(dir.path()).await?;
    let f = w.fixtures()?;

    // Identifiers: multisig root, delegation GLEIF → GEDA → QVI, multisig LE.
    let root = w.controller.find_state(&w.orgs["GLEIF-Root"].prefix)?;
    assert_eq!(root.current.public_keys.len(), 3);
    let geda = w.controller.find_state(&w.orgs["GEDA"].prefix)?;
    assert_eq!(geda.delegator, Some(w.orgs["GLEIF-Root"].prefix.clone()));
    let qvi = w.controller.find_state(&w.orgs["QVI"].prefix)?;
    assert_eq!(qvi.delegator, Some(w.orgs["GEDA"].prefix.clone()));
    let le = w.controller.find_state(&w.orgs["Fabrikam"].prefix)?;
    assert_eq!(le.current.public_keys.len(), 2);

    // Credentials: all seven, schema-valid (checked on issue), all issued.
    let names = ["qvi", "le", "oor-auth-alice", "oor-alice", "oor-auth-dana", "oor-dana", "ecr-auth-bob", "ecr-bob", "ecr-carol"];
    assert_eq!(f.credentials.len(), names.len());
    for n in names {
        assert_eq!(status(&f, &w, n), Status::Issued, "{n}");
    }

    // Chaining as the vLEI EGF requires.
    let c = |n: &str| &f.credentials[n].credential;
    let aid = |n: &str| f.aids[n].prefix.clone();
    assert_eq!((c("qvi").issuer.clone(), c("qvi").issuee.clone()), (aid("GEDA"), aid("QVI")));
    assert_eq!((c("le").issuer.clone(), c("le").issuee.clone()), (aid("QVI"), aid("Fabrikam")));
    assert_eq!(c("le").edges[0].n, c("qvi").said);
    // OOR auth is issued by the LE *to the QVI*; the OOR's I2I edge requires
    // the OOR's issuer to be that auth's issuee.
    assert_eq!(c("oor-auth-alice").issuee, c("oor-alice").issuer);
    assert_eq!(c("oor-alice").edges[0].n, c("oor-auth-alice").said);
    assert_eq!(c("oor-alice").issuee, aid("Alice"));
    assert_eq!(c("ecr-auth-bob").issuee, c("ecr-bob").issuer);
    assert_eq!(c("ecr-carol").issuer, aid("Fabrikam"));
    assert_eq!(c("ecr-carol").edges[0].label, "le");

    // Fixtures carry every KEL and they replay into a fresh verifier.
    let vdir = tempfile::tempdir()?;
    let verifier = Controller::new(ControllerConfig { db_path: vdir.path().into(), ..Default::default() })?;
    // Members before groups, delegators before delegates.
    let order = |k: &str| match f.aids.values().find(|a| a.prefix == k).map(|a| a.kind.as_str()) {
        Some("member") | Some("person") => 0,
        _ => 1,
    };
    let mut prefixes: Vec<&String> = f.kels.keys().collect();
    prefixes.sort_by_key(|p| order(p));
    for _pass in 0..3 {
        for p in &prefixes {
            verifier.known_events.process_stream(f.kels[*p].as_bytes())?;
        }
    }
    for (name, info) in &f.aids {
        let state = verifier.find_state(&info.prefix.parse()?);
        assert!(state.is_ok(), "verifier could not replay KEL of {name}: {state:?}");
    }

    let json = serde_json::to_string_pretty(&f)?;
    let back: Fixtures = serde_json::from_str(&json)?;
    assert_eq!(back.credentials.len(), 9);
    println!("fixtures: {} bytes, {} KELs", json.len(), f.kels.len());
    Ok(())
}

#[async_std::test]
async fn revocation_flips_status() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut w = chain::build(dir.path()).await?;
    w.revoke("oor-alice").await?;
    let f = w.fixtures()?;
    assert_eq!(status(&f, &w, "oor-alice"), Status::Revoked);
    assert_eq!(status(&f, &w, "ecr-bob"), Status::Issued);
    Ok(())
}

#[test]
fn embedded_schema_saids_reproduce() {
    for k in Kind::ALL {
        assert_eq!(k.computed_said(), k.said(), "{k:?}");
    }
}

#[async_std::test]
async fn delegated_kel_alone_does_not_verify() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let w = chain::build(dir.path()).await?;
    let f = w.fixtures()?;
    let vdir = tempfile::tempdir()?;
    let verifier = Controller::new(ControllerConfig { db_path: vdir.path().into(), ..Default::default() })?;
    // GEDA's KEL and its member's, but not GLEIF Root's.
    for name in ["GEDA-member-1", "GEDA"] {
        let _ = verifier.known_events.process_stream(f.kels[&f.aids[name].prefix].as_bytes());
    }
    assert!(verifier.find_state(&f.aids["GEDA"].prefix.parse()?).is_err(), "GEDA accepted without its delegator's anchor");
    // Adding Root (and its members) releases it.
    for name in ["GLEIF-Root-member-1", "GLEIF-Root-member-2", "GLEIF-Root-member-3", "GLEIF-Root", "GEDA"] {
        verifier.known_events.process_stream(f.kels[&f.aids[name].prefix].as_bytes())?;
    }
    assert!(verifier.find_state(&f.aids["GEDA"].prefix.parse()?).is_ok());
    Ok(())
}

#[test]
fn missing_required_claim_fails_schema() {
    let err = vlei_chain::credential::issue(vlei_chain::credential::Spec {
        kind: Kind::Oor,
        issuer: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        registry: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        issuee: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        dt: chain::DT,
        claims: vec![("LEI", serde_json::json!("x")), ("personLegalName", serde_json::json!("x"))], // no officialRole
        edges: vec![],
        salt_seed: None,
    })
    .unwrap_err();
    let msg = err.to_string();
    // No `e` section, and `a` lacks `officialRole`.
    assert!(msg.contains("is a required property") && msg.contains("at /a"), "{msg}");
}

#[async_std::test]
async fn signer_oobi_resolves_to_kel_in_fresh_verifier() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let w = chain::build(dir.path()).await?;
    let f = w.fixtures()?;
    let oobi = &f.oobis["Alice"][0];
    assert!(oobi.starts_with("http://witness1:3232/oobi/") && oobi.contains("/witness/"), "{oobi}");

    let vdir = tempfile::tempdir()?;
    let verifier = Controller::new(ControllerConfig {
        db_path: vdir.path().into(),
        transport: Box::new(w.transport.clone()),
        ..Default::default()
    })?;
    let alice = f.aids["Alice"].prefix.parse()?;
    assert!(verifier.find_state(&alice).is_err());
    let resolved = vlei_chain::oobi::resolve(&verifier, oobi).await?;
    assert_eq!(resolved, alice);
    // The 2-of-3 group signer resolves the same way.
    let dana = vlei_chain::oobi::resolve(&verifier, &f.oobis["Dana"][0]).await?;
    assert_eq!(verifier.find_state(&dana)?.current.public_keys.len(), 3);
    assert_eq!(verifier.find_state(&alice)?.current.public_keys, w.controller.find_state(&alice)?.current.public_keys);

    // An OOBI for a witness that doesn't exist fails.
    let broken = oobi.replace("witness1", "witness9");
    assert!(vlei_chain::oobi::resolve(&verifier, &broken).await.is_err());
    Ok(())
}
