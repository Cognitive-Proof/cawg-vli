//! ACDC 1.0 credentials in the shape keripy issues for the vLEI ecosystem.
//!
//! Layout (field order matters, SAIDs are digests of exact bytes):
//! `{v, d, [u], i, ri, s, a: {d, [u], i, dt, …claims}, [e: {d, label: {n, s, [o]}}], r: {d, rule: {l}}}`.
//! Each of `a`, `e`, `r` carries its own SAID; the top-level `d` is computed
//! last over the whole credential.

use crate::schema::Kind;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Edge {
    pub label: String,
    /// SAID of the credential the edge points to.
    pub n: String,
    /// Schema SAID that credential must have.
    pub s: String,
    /// Edge operator, e.g. `I2I` (issuer of this = issuee of that).
    pub o: Option<String>,
}

pub struct Spec<'a> {
    pub kind: Kind,
    pub issuer: &'a str,
    pub registry: &'a str,
    /// Issuee AID (`a.i`). Every vLEI credential is targeted.
    pub issuee: &'a str,
    pub dt: &'a str,
    pub claims: Vec<(&'a str, Value)>,
    pub edges: Vec<Edge>,
    /// Seed for the `u` salts of private credentials (ECR); `None` → no salts.
    pub salt_seed: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub kind: Kind,
    pub said: String,
    pub issuer: String,
    pub issuee: String,
    pub registry: String,
    pub edges: Vec<Edge>,
    /// The serialized credential (JSON), as it would go into `qvi_cred` etc.
    pub json: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("SAID: {0}")]
    Said(String),
    #[error("credential does not satisfy schema {kind:?}: {errors:?}")]
    Schema { kind: Kind, errors: Vec<String> },
}

/// A deterministic 128-bit CESR salt (`0A` + 22 chars), so fixtures reproduce.
pub fn salt(seed: &str, label: &str) -> String {
    let digest = blake3::hash(format!("{seed}/{label}").as_bytes());
    let mut raw = vec![0u8; 2]; // CESR lead bytes for code `0A`
    raw.extend_from_slice(&digest.as_bytes()[..16]);
    format!("0A{}", &URL_SAFE_NO_PAD.encode(&raw)[2..])
}

fn obj(fields: Vec<(&str, Value)>) -> Map<String, Value> {
    fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn saidified(map: Map<String, Value>) -> Result<(String, Value, Vec<u8>), CredentialError> {
    // serde_json::Map with preserve_order keeps insertion order; go through
    // a string to be independent of that feature.
    let json = ordered_json(&map);
    let mut sad: Sad = serde_json::from_str(&json).map_err(|e| CredentialError::Said(e.to_string()))?;
    let (said, raw) = saidify(&mut sad, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["d"])
        .map_err(|e| CredentialError::Said(e.to_string()))?;
    let value: Value = serde_json::from_slice(&raw).map_err(|e| CredentialError::Said(e.to_string()))?;
    Ok((said.to_string(), value, raw))
}

/// Serializes `map` keeping key order, whatever serde_json's map type is.
fn ordered_json(map: &Map<String, Value>) -> String {
    let mut out = String::from("{");
    for (n, (k, v)) in map.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(k).unwrap());
        out.push(':');
        match v {
            Value::Object(m) => out.push_str(&ordered_json(m)),
            other => out.push_str(&serde_json::to_string(other).unwrap()),
        }
    }
    out.push('}');
    out
}

pub fn issue(spec: Spec) -> Result<Credential, CredentialError> {
    let salt_of = |label: &str| spec.salt_seed.map(|s| salt(s, label));

    let mut a = vec![("d", Value::from(""))];
    if let Some(u) = salt_of("a") {
        a.push(("u", u.into()));
    }
    a.push(("i", spec.issuee.into()));
    a.push(("dt", spec.dt.into()));
    a.extend(spec.claims.iter().cloned());
    let (_, a, _) = saidified(obj(a))?;

    let e = if spec.edges.is_empty() {
        None
    } else {
        let mut e = Map::new();
        e.insert("d".into(), "".into());
        for edge in &spec.edges {
            let mut node = Map::new();
            node.insert("n".into(), edge.n.clone().into());
            node.insert("s".into(), edge.s.clone().into());
            if let Some(o) = &edge.o {
                node.insert("o".into(), o.clone().into());
            }
            e.insert(edge.label.clone(), Value::Object(node));
        }
        Some(saidified(e)?.1)
    };

    let mut r = vec![("d", Value::from(""))];
    for (k, l) in spec.kind.rules() {
        r.push((k, Value::Object(obj(vec![("l", l.into())]))));
    }
    let (_, r, _) = saidified(obj(r))?;

    let mut top = vec![("v", Value::from("ACDC10JSON000000_")), ("d", "".into())];
    if let Some(u) = salt_of("top") {
        top.push(("u", u.into()));
    }
    top.extend([
        ("i", spec.issuer.into()),
        ("ri", spec.registry.into()),
        ("s", spec.kind.said().into()),
        ("a", a),
    ]);
    if let Some(e) = e {
        top.push(("e", e));
    }
    top.push(("r", r));
    let (said, value, raw) = saidified(obj(top))?;

    spec.kind
        .validate(&value)
        .map_err(|errors| CredentialError::Schema { kind: spec.kind, errors })?;
    acdc::legacy::LegacyAcdc::parse(&raw).map_err(|e| CredentialError::Said(e.to_string()))?;

    Ok(Credential {
        kind: spec.kind,
        said,
        issuer: spec.issuer.into(),
        issuee: spec.issuee.into(),
        registry: spec.registry.into(),
        edges: spec.edges,
        json: String::from_utf8(raw).expect("JSON is UTF-8"),
    })
}
