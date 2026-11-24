//! Q5. PR 269 requires `signer_payload` in RFC 8949 §4.2.1 core deterministic
//! encoding. Does c2pa-rs's encoding (used by the X.509 path) already match?

use c2pa::{identity::SignerPayload, HashedUri};
use ciborium::value::Value;

fn deterministic(v: &Value) -> Vec<u8> {
    // §4.2.1: map keys sorted by the bytewise order of their encodings.
    fn canon(v: &Value) -> Value {
        match v {
            Value::Map(m) => {
                let mut entries: Vec<(Vec<u8>, Value, Value)> = m
                    .iter()
                    .map(|(k, val)| {
                        let k = canon(k);
                        let mut kb = Vec::new();
                        ciborium::into_writer(&k, &mut kb).unwrap();
                        (kb, k, canon(val))
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    let mut out = Vec::new();
    ciborium::into_writer(&canon(v), &mut out).unwrap();
    out
}

#[test]
fn c2pa_signer_payload_encoding_vs_core_deterministic() -> anyhow::Result<()> {
    let sp = SignerPayload {
        referenced_assertions: vec![HashedUri::new(
            "self#jumbf=c2pa.assertions/c2pa.hash.data".into(),
            None,
            &[0u8; 32],
        )],
        sig_type: "cawg.vlei".into(),
        roles: vec!["cawg.creator".into()],
    };
    let mut c2pa_bytes = Vec::new();
    c2pa_cbor::to_writer(&mut c2pa_bytes, &sp)?;
    let as_value: Value = ciborium::from_reader(c2pa_bytes.as_slice())?;
    let det = deterministic(&as_value);
    println!("c2pa_cbor     : {}", hex(&c2pa_bytes));
    println!("deterministic : {}", hex(&det));
    println!("identical     : {}", c2pa_bytes == det);
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
