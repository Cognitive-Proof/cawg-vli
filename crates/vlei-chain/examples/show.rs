//! Prints one credential, its registry inception and its issuance event.
#[async_std::main]
async fn main() {
    let dir = std::env::temp_dir().join(format!("vlei-show-{}", std::process::id()));
    let w = vlei_chain::chain::build(&dir).await.unwrap();
    let f = w.fixtures().unwrap();
    println!("{}", f.credentials["ecr-bob"].credential.json);
    println!("{}", f.registries["QVI"]);
    println!("{}", f.credentials["ecr-bob"].tel[0]);
    let _ = std::fs::remove_dir_all(dir);
}
