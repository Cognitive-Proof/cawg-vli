//! Testbed CLI.
//!
//! `testbed chain [--out DIR]` builds the vLEI trust chain and writes public
//! fixtures (no private keys):
//!
//! ```text
//! DIR/fixtures.json         everything below, in one file
//! DIR/credentials/NAME.json each credential as issued (ACDC 1.0 JSON)
//! DIR/tel/NAME.json         its TEL events, one per line
//! DIR/registries/ORG.json   registry inception (vcp) per issuer
//! DIR/kels/NAME.cesr        KEL of each AID (CESR, attachments in CESR 2.0)
//! ```
//!
//! `testbed sign [--out DIR]` builds the chain, then signs one PNG per
//! signing case and writes, per case:
//!
//! ```text
//! DIR/assets/CASE.png                 the signed asset
//! DIR/maps/CASE.cbor                  the identity assertion's `signature` (vlei-signature-payload-map)
//! DIR/diag/CASE.cbordiag              the whole identity assertion, CBOR diagnostic notation
//! DIR/fixtures.json                   chain fixtures, as for `chain`
//! DIR/trust.json                      what a verifier pins: GLEIF Root, GEDA, schema SAIDs
//! DIR/evidence.json                   public KELs, registries and TELs (stands in for witnesses)
//! ```
//!
//! `testbed verify [--out DIR]` validates every `DIR/assets/*.png` offline
//! from `trust.json` and `evidence.json`, following PR 269's validation
//! steps, and writes `DIR/reports/CASE.json`. It exits non-zero if any
//! asset fails.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use vlei_sign::{Encoding, Options};

/// (case, signer, anchored)
pub const CASES: &[(&str, &str, bool)] = &[
    ("oor", "Alice", false),
    ("ecr-qvi", "Bob", false),
    ("ecr-le", "Carol", false),
    ("no-role", "Fabrikam", false),
    ("anchored", "Alice", true),
    ("multisig", "Dana", false),
];

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = |default: &str| {
        args.iter()
            .position(|a| a == "--out")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default))
    };
    match args.first().map(String::as_str) {
        Some("chain") => chain(out("fixtures/generated")).await,
        Some("sign") => sign(out("fixtures/generated")).await,
        Some("verify") => verify(out("fixtures/generated")).await,
        _ => {
            eprintln!("usage: testbed chain [--out DIR]\n       testbed sign [--out DIR]\n       testbed verify [--out DIR]");
            std::process::exit(2);
        }
    }
}

fn fresh(out: &Path, subdirs: &[&str]) -> anyhow::Result<()> {
    if out.exists() {
        fs::remove_dir_all(out)?;
    }
    for sub in subdirs {
        fs::create_dir_all(out.join(sub))?;
    }
    Ok(())
}

fn write_fixtures(f: &vlei_chain::chain::Fixtures, out: &Path) -> anyhow::Result<()> {
    for sub in ["credentials", "tel", "registries", "kels"] {
        fs::create_dir_all(out.join(sub))?;
    }
    fs::write(out.join("fixtures.json"), serde_json::to_string_pretty(f)?)?;
    for (name, issued) in &f.credentials {
        fs::write(out.join("credentials").join(format!("{name}.json")), &issued.credential.json)?;
        fs::write(out.join("tel").join(format!("{name}.json")), issued.tel.join("\n"))?;
    }
    for (org, vcp) in &f.registries {
        fs::write(out.join("registries").join(format!("{org}.json")), vcp)?;
    }
    for (name, aid) in &f.aids {
        fs::write(out.join("kels").join(format!("{name}.cesr")), &f.kels[&aid.prefix])?;
    }
    Ok(())
}

async fn chain(out: PathBuf) -> anyhow::Result<()> {
    let db = tempfile::tempdir()?;
    let world = vlei_chain::chain::build(db.path()).await?;
    let f = world.fixtures()?;
    fresh(&out, &[])?;
    write_fixtures(&f, &out)?;
    println!("wrote {}", out.display());
    println!("  trust anchors : GLEIF-Root {}  GEDA {}", f.trust["gleif-root"], f.trust["geda"]);
    println!("  AIDs          : {}", f.aids.len());
    println!("  credentials   : {}", f.credentials.keys().cloned().collect::<Vec<_>>().join(", "));
    Ok(())
}

async fn sign(out: PathBuf) -> anyhow::Result<()> {
    let db = tempfile::tempdir()?;
    let world = Arc::new(Mutex::new(vlei_chain::chain::build(db.path()).await?));
    fresh(&out, &["assets", "maps", "diag"])?;
    for (case, signer, anchor) in CASES {
        let png = vlei_holder::sign_asset(world.clone(), signer, Options { anchor: *anchor }, Encoding::Deterministic, case)?;
        let rb = vlei_holder::read_identity_assertion(&png)?;
        fs::write(out.join("assets").join(format!("{case}.png")), &png)?;
        fs::write(out.join("maps").join(format!("{case}.cbor")), &rb.signature)?;
        fs::write(out.join("diag").join(format!("{case}.cbordiag")), vlei_sign::cbor::diag(&rb.assertion_cbor)?)?;
        println!("{case:9} signer {signer:8} map {:5} bytes  asset {} bytes", rb.signature.len(), png.len());
    }
    // Fixtures after signing, so KELs include any anchoring events.
    let f = world.lock().unwrap().fixtures()?;
    write_fixtures(&f, &out)?;
    fs::write(out.join("trust.json"), serde_json::to_string_pretty(&vlei_verify::Trust::from_fixtures(&f))?)?;
    fs::write(out.join("evidence.json"), serde_json::to_string_pretty(&vlei_verify::Evidence::from_fixtures(&f, &[]))?)?;
    println!("wrote {}", out.display());
    Ok(())
}

async fn verify(dir: PathBuf) -> anyhow::Result<()> {
    let trust: vlei_verify::Trust = serde_json::from_str(&fs::read_to_string(dir.join("trust.json"))?)?;
    let evidence: vlei_verify::Evidence = serde_json::from_str(&fs::read_to_string(dir.join("evidence.json"))?)?;
    let db = tempfile::tempdir()?;
    let verifier = vlei_verify::Verifier::new(db.path(), trust, evidence, vlei_verify::Policy::default(), None)?;
    fs::create_dir_all(dir.join("reports"))?;
    let mut assets: Vec<PathBuf> = fs::read_dir(dir.join("assets"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "png"))
        .collect();
    assets.sort();
    let mut failed = 0;
    for path in assets {
        let case = path.file_stem().unwrap().to_string_lossy().into_owned();
        match verifier.verify_asset(&fs::read(&path)?).await {
            Ok(r) => {
                let role = match &r.role {
                    vlei_verify::Role::LegalEntity => "legal entity".to_owned(),
                    vlei_verify::Role::Oor { person, role } => format!("OOR  {person}, {role}"),
                    vlei_verify::Role::EcrByQvi { person, role } => format!("ECR  {person}, {role} (QVI-issued)"),
                    vlei_verify::Role::EcrByLe { person, role } => format!("ECR  {person}, {role} (LE-issued)"),
                };
                let anchor = r.anchor_seq_num.map(|a| format!("  anchored at sn {a}")).unwrap_or_default();
                println!("{case:9} VALID  LEI {}  {role}  {}/{} sigs  {} creds{anchor}", r.lei, r.signatures, r.keys, r.credentials.len());
                fs::write(dir.join("reports").join(format!("{case}.json")), serde_json::to_string_pretty(&r)?)?;
            }
            Err(e) => {
                failed += 1;
                println!("{case:9} FAIL   {e}");
            }
        }
    }
    anyhow::ensure!(failed == 0, "{failed} asset(s) failed validation");
    Ok(())
}
