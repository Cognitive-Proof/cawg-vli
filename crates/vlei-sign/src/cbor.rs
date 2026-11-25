//! RFC 8949 §4.2.1 core deterministic encoding: definite lengths, shortest
//! integer forms (ciborium's default), and map keys sorted by the bytewise
//! order of their encodings.

use ciborium::value::Value;

fn canon(v: &Value) -> Value {
    match v {
        Value::Map(m) => {
            let mut entries: Vec<(Vec<u8>, Value, Value)> = m
                .iter()
                .map(|(k, val)| {
                    let k = canon(k);
                    let mut kb = Vec::new();
                    ciborium::into_writer(&k, &mut kb).expect("CBOR value encodes");
                    (kb, k, canon(val))
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
        Value::Tag(t, inner) => Value::Tag(*t, Box::new(canon(inner))),
        other => other.clone(),
    }
}

/// Re-encodes CBOR `bytes` deterministically.
pub fn deterministic(bytes: &[u8]) -> Result<Vec<u8>, ciborium::de::Error<std::io::Error>> {
    let value: Value = ciborium::from_reader(bytes)?;
    let mut out = Vec::new();
    ciborium::into_writer(&canon(&value), &mut out).expect("CBOR value encodes");
    Ok(out)
}

pub fn deterministic_from_serialize<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let v = Value::serialized(value).expect("serializable");
    let mut out = Vec::new();
    ciborium::into_writer(&canon(&v), &mut out).expect("CBOR value encodes");
    out
}

/// True if `bytes` are already in core deterministic form.
pub fn is_deterministic(bytes: &[u8]) -> bool {
    deterministic(bytes).map(|d| d == bytes).unwrap_or(false)
}

/// CBOR diagnostic notation (RFC 8949 §8), indented. Byte strings that hold
/// CBOR themselves (the identity assertion's `signature`) are shown as
/// embedded CBOR, `<< … >>` (RFC 8610 Appendix G.3).
pub fn diag(bytes: &[u8]) -> Result<String, ciborium::de::Error<std::io::Error>> {
    let v: Value = ciborium::from_reader(bytes)?;
    let mut out = String::new();
    write_diag(&v, 0, &mut out, true);
    out.push('\n');
    Ok(out)
}

fn write_diag(v: &Value, indent: usize, out: &mut String, embed: bool) {
    let pad = |n: usize| "  ".repeat(n);
    match v {
        Value::Integer(i) => out.push_str(&i128::from(*i).to_string()),
        Value::Bytes(b) => {
            let nested: Option<Value> = if embed && !b.is_empty() && matches!(b[0] >> 5, 4 | 5) {
                ciborium::from_reader::<Value, _>(b.as_slice()).ok().filter(|n| {
                    let mut re = Vec::new();
                    ciborium::into_writer(n, &mut re).is_ok() && re.len() == b.len()
                })
            } else {
                None
            };
            match nested {
                Some(n) => {
                    out.push_str("<< ");
                    write_diag(&n, indent, out, false);
                    out.push_str(" >>");
                }
                None => {
                    out.push_str("h'");
                    for x in b {
                        out.push_str(&format!("{x:02x}"));
                    }
                    out.push('\'');
                }
            }
        }
        Value::Text(s) => out.push_str(&serde_json::to_string(s).expect("string")),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Float(f) => out.push_str(&format!("{f:?}")),
        Value::Tag(t, inner) => {
            out.push_str(&format!("{t}("));
            write_diag(inner, indent, out, embed);
            out.push(')');
        }
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Array(a) => {
            out.push_str("[\n");
            for (n, item) in a.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                write_diag(item, indent + 1, out, embed);
                out.push_str(if n + 1 < a.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push(']');
        }
        Value::Map(m) if m.is_empty() => out.push_str("{}"),
        Value::Map(m) => {
            out.push_str("{\n");
            for (n, (k, val)) in m.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                write_diag(k, indent + 1, out, embed);
                out.push_str(": ");
                write_diag(val, indent + 1, out, true);
                out.push_str(if n + 1 < m.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push('}');
        }
        _ => out.push_str("undefined"),
    }
}
