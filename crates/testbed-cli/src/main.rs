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

use std::{fs, path::PathBuf};

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("chain") => {
            let out = args
                .iter()
                .position(|a| a == "--out")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("fixtures/generated"));
            chain(out).await
        }
        _ => {
            eprintln!("usage: testbed chain [--out DIR]");
            std::process::exit(2);
        }
    }
}

async fn chain(out: PathBuf) -> anyhow::Result<()> {
    let db = tempfile::tempdir()?;
    let world = vlei_chain::chain::build(db.path()).await?;
    let f = world.fixtures()?;

    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    for sub in ["credentials", "tel", "registries", "kels"] {
        fs::create_dir_all(out.join(sub))?;
    }
    fs::write(out.join("fixtures.json"), serde_json::to_string_pretty(&f)?)?;
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

    println!("wrote {}", out.display());
    println!("  trust anchors : GLEIF-Root {}  GEDA {}", f.trust["gleif-root"], f.trust["geda"]);
    println!("  AIDs          : {}", f.aids.len());
    println!("  credentials   : {}", f.credentials.keys().cloned().collect::<Vec<_>>().join(", "));
    Ok(())
}
