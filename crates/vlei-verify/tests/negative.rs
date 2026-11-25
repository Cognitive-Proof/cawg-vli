//! Phase 5: negative tests. Each case changes one thing in a valid
//! assertion (or in the world around it) and checks *which* validation step
//! rejects it. The step names follow PR 269's `validating.adoc`; see the
//! table in `vlei_verify`'s crate docs.

use std::sync::{Arc, Mutex};

use c2pa::identity::SignerPayload;
use keri_core::prefix::{CesrPrimitive, IndexedSignature};
use vlei_chain::{
    chain::{self, Fixtures, World},
    credential::{self, Spec},
    schema::Kind,
};
use vlei_holder::ReadBack;
use vlei_sign::{Encoding, Options, RoleCred, VleiSignaturePayload};
use vlei_verify::{Evidence, Policy, Trust, Verifier};

struct Signed {
    _dir: tempfile::TempDir,
    world: Arc<Mutex<World>>,
    fixtures: Fixtures,
    /// Case name → what a reader finds in the signed asset.
    cases: Vec<(&'static str, Vec<u8>, ReadBack)>,
}

impl Signed {
    fn case(&self, name: &str) -> (&[u8], &ReadBack) {
        let (_, png, rb) = self.cases.iter().find(|(n, _, _)| *n == name).expect("case");
        (png, rb)
    }
    fn cred(&self, name: &str) -> String {
        self.fixtures.credentials[name].credential.json.clone()
    }
    fn refresh(&mut self) -> anyhow::Result<()> {
        self.fixtures = self.world.lock().unwrap().fixtures()?;
        Ok(())
    }
}

async fn sign(cases: &[(&'static str, &str, bool)]) -> anyhow::Result<Signed> {
    let dir = tempfile::tempdir()?;
    let world = Arc::new(Mutex::new(chain::build(dir.path()).await?));
    let mut out = Vec::new();
    for (case, signer, anchor) in cases {
        let png = vlei_holder::sign_asset(world.clone(), signer, Options { anchor: *anchor }, Encoding::Deterministic, case)?;
        let rb = vlei_holder::read_identity_assertion(&png)?;
        out.push((*case, png, rb));
    }
    let fixtures = world.lock().unwrap().fixtures()?;
    Ok(Signed { _dir: dir, world, fixtures, cases: out })
}

const ALL: &[(&str, &str, bool)] = &[
    ("oor", "Alice", false),
    ("ecr-qvi", "Bob", false),
    ("ecr-le", "Carol", false),
    ("no-role", "Fabrikam", false),
    ("anchored", "Alice", true),
    ("multisig", "Dana", false),
];

fn verifier_with(s: &Signed, evidence: Evidence, policy: Policy) -> anyhow::Result<(tempfile::TempDir, Verifier)> {
    let dir = tempfile::tempdir()?;
    let v = Verifier::new(dir.path(), Trust::from_fixtures(&s.fixtures), evidence, policy, None)?;
    Ok((dir, v))
}

fn verifier(s: &Signed) -> anyhow::Result<(tempfile::TempDir, Verifier)> {
    verifier_with(s, Evidence::from_fixtures(&s.fixtures, &[]), Policy::default())
}

/// Validates `sp` with `map` and asserts rejection at `step`.
async fn rejects(v: &Verifier, id: &str, sp: &SignerPayload, map: &[u8], step: &str) {
    match v.verify(sp, map).await {
        Ok(r) => panic!("{id}: accepted, expected rejection at step {step}: {r:?}"),
        Err(e) => {
            assert_eq!(e.step, step, "{id}: rejected at the wrong step: {e}");
            println!("{id:4} step {:12} {}", e.step, e.reason);
        }
    }
}

/// Alice's map with one change.
fn alice(s: &Signed, f: impl FnOnce(&mut VleiSignaturePayload)) -> (SignerPayload, Vec<u8>) {
    with(s, "oor", f)
}

fn with(s: &Signed, case: &str, f: impl FnOnce(&mut VleiSignaturePayload)) -> (SignerPayload, Vec<u8>) {
    let rb = s.case(case).1;
    let mut map = rb.map.clone();
    f(&mut map);
    (rb.signer_payload.clone(), map.to_cbor())
}

fn reindex(sig: &str, index: u16) -> String {
    let s: IndexedSignature = sig.parse().unwrap();
    IndexedSignature::new_both_same(s.signature, index).to_str()
}

#[async_std::test]
async fn map_and_credential_tampering() -> anyhow::Result<()> {
    let s = sign(ALL).await?;
    let (_d, v) = verifier(&s)?;

    // Baseline: every case is valid with this verifier.
    for (case, _, rb) in &s.cases {
        v.verify(&rb.signer_payload, &rb.signature).await.map_err(|e| anyhow::anyhow!("{case}: {e}"))?;
    }

    // N1 Signature type.
    let mut sp = s.case("oor").1.signer_payload.clone();
    sp.sig_type = "cawg.x509.cose".into();
    rejects(&v, "N1", &sp, &s.case("oor").1.signature, "1").await;

    // N2 Not a vlei-signature-payload-map.
    let sp = s.case("oor").1.signer_payload.clone();
    rejects(&v, "N2", &sp, &[0xa0], "2.a").await;
    rejects(&v, "N2b", &sp, b"not cbor", "2.a").await;

    // N3 kel_seq_num names no establishment event.
    let (sp, m) = alice(&s, |m| m.kel_seq_num = 7);
    rejects(&v, "N3", &sp, &m, "2.b").await;
    // N3b Alice's anchoring ixn (sn 1) is not an establishment event.
    let (sp, m) = with(&s, "anchored", |m| m.kel_seq_num = 1);
    rejects(&v, "N3b", &sp, &m, "2.b").await;

    // N4 QVI credential replaced by the LE credential.
    let le = s.cred("le");
    let (sp, m) = alice(&s, |m| m.qvi_cred = le.clone());
    rejects(&v, "N4", &sp, &m, "2.c.qvi").await;

    // N5 LE credential edited (LEI changed, SAIDs not recomputed).
    let edited = s.cred("le").replace(chain::LE_LEI, "9845000FABRIKAM00043");
    let (sp, m) = alice(&s, |m| m.le_cred = edited.clone());
    rejects(&v, "N5", &sp, &m, "2.c.i").await;

    // N6 Role credential with an unknown schema.
    let unknown = s.cred("oor-alice").replace(Kind::Oor.said(), "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let (sp, m) = alice(&s, |m| m.role_cred.as_mut().unwrap().cred = unknown.clone());
    rejects(&v, "N6", &sp, &m, "2.c.ii").await;

    // N7 Forged OOR: SAIDs and schema valid, but never issued (no TEL).
    let real = &s.fixtures.credentials["oor-alice"].credential;
    let forged = credential::issue(Spec {
        kind: Kind::Oor,
        issuer: &real.issuer,
        registry: &real.registry,
        issuee: &real.issuee,
        dt: chain::DT,
        claims: vec![
            ("LEI", serde_json::json!(chain::LE_LEI)),
            ("personLegalName", serde_json::json!("Alice Example")),
            ("officialRole", serde_json::json!("Chief Executive Officer")),
        ],
        edges: real.edges.clone(),
        salt_seed: None,
    })?;
    let (sp, m) = alice(&s, |m| m.role_cred.as_mut().unwrap().cred = forged.json.clone());
    rejects(&v, "N7", &sp, &m, "2.c.ii").await;

    // N8 Dana's OOR presented with Alice's authorisation.
    let (dana_oor, alice_auth) = (s.cred("oor-dana"), s.cred("oor-auth-alice"));
    let (sp, m) = alice(&s, |m| m.role_cred = Some(RoleCred { auth_cred: alice_auth.clone(), cred: dana_oor.clone() }));
    rejects(&v, "N8", &sp, &m, "2.c.ii.auth").await;

    // N9 LE-issued ECR with a (non-empty) authorisation credential.
    let bob_auth = s.cred("ecr-auth-bob");
    let (sp, m) = with(&s, "ecr-le", |m| m.role_cred.as_mut().unwrap().auth_cred = bob_auth.clone());
    rejects(&v, "N9", &sp, &m, "2.c.ii.auth").await;

    // N10 QVI-issued ECR without its authorisation.
    let (sp, m) = with(&s, "ecr-qvi", |m| m.role_cred.as_mut().unwrap().auth_cred = String::new());
    rejects(&v, "N10", &sp, &m, "2.c.ii.auth").await;

    // N11 OOR presented with the ECR authorisation (wrong kind).
    let (sp, m) = alice(&s, |m| m.role_cred.as_mut().unwrap().auth_cred = bob_auth.clone());
    rejects(&v, "N11", &sp, &m, "2.c.ii.auth").await;

    // N12 Alice drops her role credential: she is not the legal entity.
    let (sp, m) = alice(&s, |m| m.role_cred = None);
    rejects(&v, "N12", &sp, &m, "2.c.signer").await;

    // N13 Anchor at an event without the digest (Alice's inception).
    let (sp, m) = with(&s, "anchored", |m| m.anchor_seq_num = Some(0));
    rejects(&v, "N13", &sp, &m, "3").await;
    // N13b An anchor claimed for an unanchored signature.
    let (sp, m) = alice(&s, |m| m.anchor_seq_num = Some(1));
    rejects(&v, "N13b", &sp, &m, "3").await;

    // N14 Dana (2-of-3) with one signature.
    let (sp, m) = with(&s, "multisig", |m| m.aid_sig.truncate(1));
    rejects(&v, "N14", &sp, &m, "4").await;

    // N15 The same signature twice.
    let (sp, m) = with(&s, "multisig", |m| m.aid_sig[1] = m.aid_sig[0].clone());
    rejects(&v, "N15", &sp, &m, "4").await;

    // N16 Alice's signature with a wrong key index (out of range).
    let (sp, m) = alice(&s, |m| m.aid_sig[0] = reindex(&m.aid_sig[0], 1));
    rejects(&v, "N16", &sp, &m, "4").await;
    // N16b Dana's two signatures with their indexes swapped.
    let (sp, m) = with(&s, "multisig", |m| {
        let (a, b) = (m.aid_sig[0].clone(), m.aid_sig[1].clone());
        let ia = a.parse::<IndexedSignature>().unwrap().index.current();
        let ib = b.parse::<IndexedSignature>().unwrap().index.current();
        m.aid_sig = vec![reindex(&a, ib), reindex(&b, ia)];
    });
    rejects(&v, "N16b", &sp, &m, "4").await;

    // N17 Dana: two valid signatures plus one over other data (F19). keriox
    // alone would drop the bad one and accept.
    let bob_sig = s.case("ecr-qvi").1.map.aid_sig[0].clone();
    let (sp, m) = with(&s, "multisig", |m| m.aid_sig.push(reindex(&bob_sig, 2)));
    rejects(&v, "N17", &sp, &m, "4").await;
    // keriox's own check accepts that map: it drops the bad signature.
    {
        use keri_core::{event::sections::seal::EventSeal, event_message::signature::{Signature, SignerData}, prefix::IdentifierPrefix};
        let map = VleiSignaturePayload::from_cbor(&m)?;
        let w = s.world.lock().unwrap();
        let aid: IdentifierPrefix = map.signer_aid.parse()?;
        let est = w.controller.known_events.storage.get_last_establishment_event_seal(&aid).unwrap();
        let sigs: Vec<IndexedSignature> = map.aid_sig.iter().map(|x| x.parse()).collect::<Result<_, _>>()?;
        let payload = vlei_sign::encode_signer_payload(&sp, Encoding::Deterministic);
        let seal = EventSeal::new(aid, map.kel_seq_num, est.event_digest());
        w.controller.verify(&payload, &Signature::Transferable(SignerData::EventSeal(seal), sigs))?;
    }

    // N18 signer_payload changed after signing.
    let (mut sp, m) = alice(&s, |_| {});
    sp.roles = vec!["cawg.editor".into()];
    rejects(&v, "N18", &sp, &m, "4").await;
    // N18b The same with the anchored case fails at the anchor first.
    let (mut sp, m) = with(&s, "anchored", |_| {});
    sp.roles = vec!["cawg.editor".into()];
    rejects(&v, "N18b", &sp, &m, "3").await;

    // N19 No signatures.
    let (sp, m) = alice(&s, |m| m.aid_sig.clear());
    rejects(&v, "N19", &sp, &m, "4").await;
    Ok(())
}

#[async_std::test]
async fn revoked_credentials() -> anyhow::Result<()> {
    let mut s = sign(&[("oor", "Alice", false), ("ecr-le", "Carol", false)]).await?;
    // N20 Alice's OOR is revoked after she signed.
    s.world.lock().unwrap().revoke("oor-alice").await?;
    s.refresh()?;
    let (_d, v) = verifier(&s)?;
    let rb = s.case("oor").1;
    rejects(&v, "N20", &rb.signer_payload, &rb.signature, "2.c.ii").await;
    // Carol is unaffected.
    let carol = s.case("ecr-le").1.clone();
    v.verify(&carol.signer_payload, &carol.signature).await?;

    // N21 The LE credential is revoked: everyone under it fails at 2.c.i.
    s.world.lock().unwrap().revoke("le").await?;
    s.refresh()?;
    let (_d, v) = verifier(&s)?;
    rejects(&v, "N21", &carol.signer_payload, &carol.signature, "2.c.i").await;
    Ok(())
}

#[async_std::test]
async fn missing_evidence() -> anyhow::Result<()> {
    let s = sign(&[("oor", "Alice", false)]).await?;
    let rb = s.case("oor").1;
    let le_said = s.fixtures.credentials["le"].credential.said.clone();

    // N22 No TEL for the LE credential.
    let mut e = Evidence::from_fixtures(&s.fixtures, &[]);
    e.tels.remove(&le_said);
    let (_d, v) = verifier_with(&s, e, Policy::default())?;
    rejects(&v, "N22", &rb.signer_payload, &rb.signature, "2.c.i").await;

    // N23 No KEL for the QVI: its credentials' anchors can't be checked.
    let (_d, v) = verifier_with(&s, Evidence::from_fixtures(&s.fixtures, &["QVI"]), Policy::default())?;
    rejects(&v, "N23", &rb.signer_payload, &rb.signature, "2.c.qvi").await;

    // N24 No KEL for GLEIF Root: setup fails.
    let dir = tempfile::tempdir()?;
    let e = Verifier::new(dir.path(), Trust::from_fixtures(&s.fixtures), Evidence::from_fixtures(&s.fixtures, &["GLEIF-Root"]), Policy::default(), None)
        .err()
        .expect("setup must fail");
    assert_eq!(e.step, "setup", "{e}");
    println!("N24  step setup        {}", e.reason);

    // N25 No KEL for the signer and only an unreachable OOBI.
    let (_d, v) = verifier_with(&s, Evidence::from_fixtures(&s.fixtures, &["Alice"]), Policy::default())?;
    let (sp, m) = alice(&s, |m| m.signer_aid_oobi = vec![m.signer_aid_oobi[0].replace("witness1", "witness9")]);
    rejects(&v, "N25", &sp, &m, "2.b").await;
    Ok(())
}

#[async_std::test]
async fn rotated_keys() -> anyhow::Result<()> {
    // Alice signs twice (plain and anchored), then rotates her keys.
    let mut s = sign(&[("oor", "Alice", false), ("anchored", "Alice", true)]).await?;
    s.world.lock().unwrap().rotate_person("Alice").await?;
    s.refresh()?;

    // N26 A plain signature by the replaced keys is rejected by default.
    let (_d, v) = verifier(&s)?;
    let rb = s.case("oor").1;
    rejects(&v, "N26", &rb.signer_payload, &rb.signature, "2.b").await;

    // The anchored signature was dated before the rotation: accepted, noted.
    let a = s.case("anchored").1;
    let r = v.verify(&a.signer_payload, &a.signature).await?;
    assert!(!r.keys_current);
    assert!(r.notes.iter().any(|n| n.contains("rotated")), "{:?}", r.notes);

    // Following the PR as written (any establishment event), it passes.
    let lax = Policy { reject_superseded_keys: false, ..Policy::default() };
    let (_d2, v) = verifier_with(&s, Evidence::from_fixtures(&s.fixtures, &[]), lax)?;
    let r = v.verify(&rb.signer_payload, &rb.signature).await?;
    assert!(!r.keys_current);

    // N27 After rotating, new signatures still name kel_seq_num 0: the old
    // keys can't produce them, and the new keys don't verify against sn 0.
    let png = vlei_holder::sign_asset(s.world.clone(), "Alice", Options::default(), Encoding::Deterministic, "after")?;
    let after = vlei_holder::read_identity_assertion(&png)?;
    s.refresh()?;
    let (_d3, v) = verifier(&s)?;
    assert!(after.map.kel_seq_num > 0, "signer uses the rotation event");
    v.verify(&after.signer_payload, &after.signature).await?;
    let mut stale = after.map.clone();
    stale.kel_seq_num = 0;
    rejects(&v, "N27", &after.signer_payload, &stale.to_cbor(), "2.b").await;
    let (_d4, v) = verifier_with(&s, Evidence::from_fixtures(&s.fixtures, &[]), lax)?;
    rejects(&v, "N27b", &after.signer_payload, &stale.to_cbor(), "4").await;
    Ok(())
}

#[async_std::test]
async fn tampered_asset_fails_c2pa() -> anyhow::Result<()> {
    // N28 Editing the embedded map inside the asset breaks the C2PA
    // assertion hash: the vLEI signature itself does not cover the map.
    let s = sign(&[("oor", "Alice", false)]).await?;
    let (_d, v) = verifier(&s)?;
    let mut png = s.case("oor").0.to_vec();
    let needle = b"Chief Financial Officer";
    let at = png.windows(needle.len()).position(|w| w == needle).expect("role in asset");
    png[at] = b'X';
    let e = v.verify_asset(&png).await.unwrap_err();
    assert_eq!(e.step, "c2pa", "{e}");
    println!("N28  step c2pa         {}", e.reason);
    Ok(())
}
