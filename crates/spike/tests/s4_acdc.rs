//! Q4. Credentials. vLEI credentials are ACDC v1 (`ri`, `ACDC10JSON…`), the
//! Rust `acdc` crate writes v2 and only *reads* v1. Can we (a) reproduce the
//! SAIDs of GLEIF's published schemas, and (b) hand-build a v1 ACDC whose SAIDs
//! the crate accepts?

use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
use std::fs;

const SCHEMAS: &[(&str, &str)] = &[
    ("qualified-vLEI-issuer-vLEI-credential", "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"),
    ("legal-entity-vLEI-credential", "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"),
    ("oor-authorization-vlei-credential", "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E"),
    ("legal-entity-official-organizational-role-vLEI-credential", "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy"),
    ("ecr-authorization-vlei-credential", "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g"),
    ("legal-entity-engagement-context-role-vLEI-credential", "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"),
];

#[test]
fn gleif_schema_saids_reproduce() -> anyhow::Result<()> {
    for (name, expected) in SCHEMAS {
        let path = format!("{}/../../infra/schemas/{name}.json", env!("CARGO_MANIFEST_DIR"));
        let mut sad: Sad = serde_json::from_slice(&fs::read(path)?)?;
        let (said, _) = saidify(&mut sad, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["$id"])?;
        assert_eq!(said.to_string(), *expected, "{name}");
    }
    Ok(())
}

#[test]
fn hand_built_v1_le_credential_is_accepted_by_legacy_reader() -> anyhow::Result<()> {
    // Attributes block first: its own SAID in `d`.
    let mut attrs: Sad = serde_json::from_str(
        r#"{"d":"","i":"EIssueeAIDplaceholder000000000000000000000000","dt":"2026-11-24T00:00:00.000000+00:00","LEI":"254900OPPU84GM83MG36"}"#,
    )?;
    let (attrs_said, _) = saidify(&mut attrs, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["d"])?;

    let mut acdc: Sad = serde_json::from_value(serde_json::json!({
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": "EQviAIDplaceholder00000000000000000000000000",
        "ri": "ERegistryplaceholder000000000000000000000000",
        "s": "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
        "a": serde_json::to_value(&attrs)?,
    }))?;
    let (said, bytes) = saidify(&mut acdc, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["d"])?;
    println!("v1 LE credential {said}: {}", String::from_utf8_lossy(&bytes));

    let parsed = acdc::legacy::LegacyAcdc::parse(&bytes)?;
    assert_eq!(parsed.said(), said.to_string());
    assert_eq!(parsed.registry(), Some("ERegistryplaceholder000000000000000000000000"));
    assert_eq!(parsed.schema_said(), "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY");
    let _ = attrs_said;
    Ok(())
}
