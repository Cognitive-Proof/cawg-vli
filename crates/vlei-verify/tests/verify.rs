//! Signs the six Phase 3 cases and validates each asset with a fresh
//! verifier that knows only the trust anchors and public evidence, and
//! fetches every person's KEL from the OOBI in the assertion.

use std::sync::{Arc, Mutex};

use vlei_chain::chain::{self, Fixtures};
use vlei_sign::{Encoding, Options};
use vlei_verify::{Evidence, KelSource, Policy, Report, Role, Trust, Verifier};

const CASES: &[(&str, &str, bool)] = &[
    ("oor", "Alice", false),
    ("ecr-qvi", "Bob", false),
    ("ecr-le", "Carol", false),
    ("no-role", "Fabrikam", false),
    ("anchored", "Alice", true),
    ("multisig", "Dana", false),
];

/// Signers whose KELs the verifier must fetch by OOBI.
const BY_OOBI: &[&str] = &["Alice", "Bob", "Carol", "Dana"];

struct Signed {
    _dir: tempfile::TempDir,
    world: Arc<Mutex<chain::World>>,
    fixtures: Fixtures,
    /// Fixtures taken before the anchored case added an event to Alice's KEL.
    before_anchor: Fixtures,
    assets: Vec<(&'static str, Vec<u8>)>,
}

async fn signed() -> anyhow::Result<Signed> {
    let dir = tempfile::tempdir()?;
    let world = Arc::new(Mutex::new(chain::build(dir.path()).await?));
    let mut assets = Vec::new();
    let mut before_anchor = None;
    for (case, signer, anchor) in CASES {
        if *anchor {
            before_anchor = Some(world.lock().unwrap().fixtures()?);
        }
        let png = vlei_holder::sign_asset(world.clone(), signer, Options { anchor: *anchor }, Encoding::Deterministic, case)?;
        assets.push((*case, png));
    }
    let fixtures = world.lock().unwrap().fixtures()?;
    Ok(Signed { _dir: dir, world, fixtures, before_anchor: before_anchor.unwrap(), assets })
}

fn verifier(s: &Signed, trust: Trust, without: &[&str], policy: Policy, online: bool) -> anyhow::Result<(tempfile::TempDir, Verifier)> {
    let dir = tempfile::tempdir()?;
    let transport = online.then(|| Box::new(s.world.lock().unwrap().transport.clone()) as _);
    let v = Verifier::new(dir.path(), trust, Evidence::from_fixtures(&s.fixtures, without), policy, transport)?;
    Ok((dir, v))
}

#[async_std::test]
async fn every_case_validates() -> anyhow::Result<()> {
    let s = signed().await?;
    let (_d, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), BY_OOBI, Policy::default(), true)?;
    let aid = |n: &str| s.fixtures.aids[n].prefix.clone();
    for (case, png) in &s.assets {
        let r: Report = v.verify_asset(png).await.map_err(|e| anyhow::anyhow!("{case}: {e}"))?;
        println!("{case:9} {}", serde_json::to_string(&r)?);
        assert_eq!(r.lei, chain::LE_LEI, "{case}");
        assert!(r.keys_current, "{case}");
        let (signer, role, creds, sigs, keys) = match *case {
            "oor" | "anchored" => ("Alice", Role::Oor { person: "Alice Example".into(), role: "Chief Financial Officer".into() }, 4, 1, 1),
            "ecr-qvi" => ("Bob", Role::EcrByQvi { person: "Bob Example".into(), role: "Press Officer".into() }, 4, 1, 1),
            "ecr-le" => ("Carol", Role::EcrByLe { person: "Carol Example".into(), role: "Editor".into() }, 3, 1, 1),
            "no-role" => ("Fabrikam", Role::LegalEntity, 2, 2, 2),
            "multisig" => ("Dana", Role::Oor { person: "Dana Example".into(), role: "Chief Executive Officer".into() }, 4, 2, 3),
            _ => unreachable!(),
        };
        assert_eq!(r.signer_aid, aid(signer), "{case}");
        assert_eq!(r.role, role, "{case}");
        assert_eq!(r.credentials.len(), creds, "{case}");
        assert_eq!((r.signatures, r.keys), (sigs, keys), "{case}");
        assert_eq!(r.anchor_seq_num.is_some(), *case == "anchored", "{case}");
        // People and Dana come by OOBI the first time; Fabrikam is known.
        if *case == "no-role" {
            assert_eq!(r.kel_source, KelSource::Known);
        }
        if *case == "oor" {
            assert!(matches!(r.kel_source, KelSource::Oobi(_)), "{case}: {:?}", r.kel_source);
        }
        assert!(r.notes.is_empty(), "{case}: {:?}", r.notes);
    }
    Ok(())
}

#[async_std::test]
async fn offline_verifier_needs_the_signer_kel() -> anyhow::Result<()> {
    let s = signed().await?;
    // No transport and no KEL for Alice: step 2.b fails after trying the OOBI.
    let (_d, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), &["Alice"], Policy::default(), false)?;
    let e = v.verify_asset(&s.assets[0].1).await.unwrap_err();
    assert_eq!(e.step, "2.b", "{e}");
    // With the full evidence it validates offline.
    let (_d2, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), &[], Policy::default(), false)?;
    assert_eq!(v.verify_asset(&s.assets[0].1).await?.kel_source, KelSource::Known);
    Ok(())
}

#[async_std::test]
async fn signatures_do_not_cover_the_stored_signer_payload_bytes() -> anyhow::Result<()> {
    // Finding F1: verifying over c2pa-rs's stored encoding fails at step 4.
    let s = signed().await?;
    let policy = Policy { encoding: Encoding::C2paRs, ..Policy::default() };
    let (_d, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), &[], policy, false)?;
    for (case, png) in &s.assets {
        let e = v.verify_asset(png).await.unwrap_err();
        // The anchored case already fails at the anchor, which digests the same bytes.
        let expected = if *case == "anchored" { "3" } else { "4" };
        assert_eq!(e.step, expected, "{case}: {e}");
    }
    Ok(())
}

#[async_std::test]
async fn wrong_trust_anchor_fails_setup() -> anyhow::Result<()> {
    let s = signed().await?;
    let mut trust = Trust::from_fixtures(&s.fixtures);
    // Pin the QVI as if it were GEDA: it is delegated by GEDA, not by Root.
    trust.geda = s.fixtures.aids["QVI"].prefix.clone();
    let dir = tempfile::tempdir()?;
    let e = Verifier::new(dir.path(), trust, Evidence::from_fixtures(&s.fixtures, &[]), Policy::default(), None).err().unwrap();
    assert_eq!(e.step, "setup", "{e}");
    Ok(())
}

#[async_std::test]
async fn stale_signer_kel_is_refreshed_for_the_anchor() -> anyhow::Result<()> {
    // The verifier already knows Alice's KEL, but only up to her inception:
    // kel_seq_num 0 is there, the anchoring event at sn 1 is not.
    let s = signed().await?;
    let dir = tempfile::tempdir()?;
    let transport = Box::new(s.world.lock().unwrap().transport.clone());
    let evidence = Evidence::from_fixtures(&s.before_anchor, &[]);
    let v = Verifier::new(dir.path(), Trust::from_fixtures(&s.fixtures), evidence, Policy::default(), Some(transport))?;
    let anchored = &s.assets.iter().find(|(c, _)| *c == "anchored").unwrap().1;
    let r = v.verify_asset(anchored).await?;
    assert!(matches!(r.kel_source, KelSource::Oobi(_)), "{:?}", r.kel_source);
    assert_eq!(r.anchor_seq_num, Some(1));
    Ok(())
}

#[async_std::test]
async fn borrowed_credentials_pass_the_steps_as_written() -> anyhow::Result<()> {
    // Finding F13: Carol signs with her own keys but presents Alice's public
    // OOR credentials. Every step of PR 269 passes; only the added signer
    // binding (2.c.signer) rejects it.
    let s = signed().await?;
    let payload = c2pa::identity::SignerPayload {
        referenced_assertions: vec![c2pa::HashedUri::new("self#jumbf=c2pa.assertions/c2pa.hash.data".into(), None, &[7u8; 32])],
        sig_type: "cawg.vlei".into(),
        roles: vec!["cawg.creator".into()],
    };
    let bytes = vlei_sign::encode_signer_payload(&payload, Encoding::Deterministic);
    let map = {
        let mut w = s.world.lock().unwrap();
        let alices = vlei_sign::bundle_for(&w, "Alice")?;
        async_std::task::block_on(vlei_sign::sign(&mut w, "Carol", alices, &bytes, Options::default()))?
    };
    let carol = s.fixtures.aids["Carol"].prefix.clone();
    assert_eq!(map.signer_aid, carol);

    let as_written = Policy { bind_signer: false, ..Policy::default() };
    let (_d, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), &[], as_written, false)?;
    let r = v.verify(&payload, &map.to_cbor()).await?;
    assert_eq!(r.signer_aid, carol);
    assert_eq!(r.role, Role::Oor { person: "Alice Example".into(), role: "Chief Financial Officer".into() });

    let (_d2, v) = verifier(&s, Trust::from_fixtures(&s.fixtures), &[], Policy::default(), false)?;
    let e = v.verify(&payload, &map.to_cbor()).await.unwrap_err();
    assert_eq!(e.step, "2.c.signer", "{e}");
    Ok(())
}
