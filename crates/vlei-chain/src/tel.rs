//! KERI 1.0 transaction event logs for ACDC 1.0 credentials, as written by
//! keripy and used by the vLEI ecosystem.
//!
//! A registry is incepted with a `vcp` event, credentials are issued with
//! `iss` and revoked with `rev`. The registry has no backers (`c: ["NB"]`):
//! every event is made authoritative by a seal `{i, s, d}` anchored in the
//! issuer's KEL.
//!
//! Field order and SAID derivation follow keripy:
//!
//! | event | fields | SAID labels |
//! |---|---|---|
//! | `vcp` | `v t d i ii s c bt b n` | `d` and `i` (the registry identifier is the inception SAID) |
//! | `iss` | `v t d i s ri dt` | `d` |
//! | `rev` | `v t d i s ri p dt` | `d` |

use keri_core::{
    event::sections::seal::{EventSeal, Seal},
    event_message::signed_event_message::Notice,
    prefix::IdentifierPrefix,
};
use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TelError {
    #[error("malformed TEL event: {0}")]
    Malformed(String),
    #[error("SAID of {0} event does not match its content")]
    BadSaid(&'static str),
    #[error("expected a `{expected}` event, found `{found}`")]
    WrongType { expected: &'static str, found: String },
    #[error("{0}")]
    Mismatch(String),
    #[error("{kind} event {said} is not anchored in the issuer's KEL")]
    NotAnchored { kind: String, said: String },
}

/// A serialized KERI 1.0 TEL event.
#[derive(Debug, Clone, PartialEq)]
pub struct TelEvent {
    raw: Vec<u8>,
    fields: serde_json::Map<String, Value>,
}

/// Credential status according to its TEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Issued,
    Revoked,
}

const VERSION_PLACEHOLDER: &str = "KERI10JSON000000_";

fn make(fields: &[(&str, Value)], labels: &[&str]) -> Result<TelEvent, TelError> {
    // Build in field order: Sad preserves insertion order.
    let mut json = String::from("{");
    for (n, (k, v)) in fields.iter().enumerate() {
        if n > 0 {
            json.push(',');
        }
        json.push_str(&serde_json::to_string(k).unwrap());
        json.push(':');
        json.push_str(&serde_json::to_string(v).unwrap());
    }
    json.push('}');
    let mut sad: Sad = serde_json::from_str(&json).map_err(|e| TelError::Malformed(e.to_string()))?;
    let (_, raw) = saidify(&mut sad, HashFunctionCode::Blake3_256, SerializationFormats::JSON, labels)
        .map_err(|e| TelError::Malformed(e.to_string()))?;
    TelEvent::parse(&raw)
}

/// Registry inception: a no-backer registry controlled by `issuer`.
/// `nonce` is a CESR salt (keripy uses a random 128-bit salt, `0A…`).
pub fn vcp(issuer: &str, nonce: &str) -> Result<TelEvent, TelError> {
    make(
        &[
            ("v", VERSION_PLACEHOLDER.into()),
            ("t", "vcp".into()),
            ("d", "".into()),
            ("i", "".into()),
            ("ii", issuer.into()),
            ("s", "0".into()),
            ("c", Value::Array(vec!["NB".into()])),
            ("bt", "0".into()),
            ("b", Value::Array(vec![])),
            ("n", nonce.into()),
        ],
        &["d", "i"],
    )
}

/// Simple issuance of credential `credential` in `registry`.
pub fn iss(credential: &str, registry: &str, dt: &str) -> Result<TelEvent, TelError> {
    make(
        &[
            ("v", VERSION_PLACEHOLDER.into()),
            ("t", "iss".into()),
            ("d", "".into()),
            ("i", credential.into()),
            ("s", "0".into()),
            ("ri", registry.into()),
            ("dt", dt.into()),
        ],
        &["d"],
    )
}

/// Simple revocation; `prior` is the SAID of the `iss` event.
pub fn rev(credential: &str, registry: &str, prior: &str, dt: &str) -> Result<TelEvent, TelError> {
    make(
        &[
            ("v", VERSION_PLACEHOLDER.into()),
            ("t", "rev".into()),
            ("d", "".into()),
            ("i", credential.into()),
            ("s", "1".into()),
            ("ri", registry.into()),
            ("p", prior.into()),
            ("dt", dt.into()),
        ],
        &["d"],
    )
}

impl TelEvent {
    /// Parses a TEL event and checks its SAID(s).
    pub fn parse(raw: &[u8]) -> Result<Self, TelError> {
        let fields: serde_json::Map<String, Value> =
            serde_json::from_slice(raw).map_err(|e| TelError::Malformed(e.to_string()))?;
        let event = Self { raw: raw.to_vec(), fields };
        let (kind, labels): (&'static str, &[&str]) = match event.ilk() {
            "vcp" => ("vcp", &["d", "i"]),
            "iss" => ("iss", &["d"]),
            "rev" => ("rev", &["d"]),
            other => return Err(TelError::Malformed(format!("unsupported event type `{other}`"))),
        };
        // Recompute over a copy with the SAID fields blanked.
        let mut sad: Sad = serde_json::from_slice(raw).map_err(|e| TelError::Malformed(e.to_string()))?;
        let (said, reserialized) =
            saidify(&mut sad, HashFunctionCode::Blake3_256, SerializationFormats::JSON, labels)
                .map_err(|_| TelError::BadSaid(kind))?;
        if reserialized != raw || labels.iter().any(|l| event.str(l) != said.to_string()) {
            return Err(TelError::BadSaid(kind));
        }
        Ok(event)
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn ilk(&self) -> &str {
        self.str("t")
    }
    pub fn said(&self) -> &str {
        self.str("d")
    }
    /// The registry identifier (`vcp`) or credential SAID (`iss`, `rev`).
    pub fn prefix(&self) -> &str {
        self.str("i")
    }
    pub fn sn(&self) -> u64 {
        u64::from_str_radix(self.str("s"), 16).unwrap_or(u64::MAX)
    }
    pub fn str(&self, field: &str) -> &str {
        self.fields.get(field).and_then(Value::as_str).unwrap_or("")
    }

    /// The seal `{i, s, d}` the issuer anchors in its KEL for this event.
    pub fn seal(&self) -> Result<Seal, TelError> {
        let i: IdentifierPrefix = self.prefix().parse().map_err(|_| TelError::Malformed("bad i".into()))?;
        let d = self.said().parse().map_err(|_| TelError::Malformed("bad d".into()))?;
        Ok(Seal::Event(EventSeal::new(i, self.sn(), d)))
    }

    fn expect(&self, ilk: &'static str) -> Result<(), TelError> {
        if self.ilk() == ilk {
            Ok(())
        } else {
            Err(TelError::WrongType { expected: ilk, found: self.ilk().into() })
        }
    }
}

/// True if any event of `kel` anchors `seal`.
pub fn kel_anchors(kel: &[Notice], seal: &Seal) -> bool {
    kel.iter().any(|n| match n {
        Notice::Event(e) => e.event_message.data.event_data.seals().contains(seal),
        _ => false,
    })
}

/// Determines a credential's status from its registry inception, issuance
/// and optional revocation, checking that every event is well formed, chained
/// to the previous one, and anchored in the issuer's KEL.
pub fn credential_status(
    credential: &str,
    issuer: &str,
    issuer_kel: &[Notice],
    vcp: &TelEvent,
    iss: &TelEvent,
    rev: Option<&TelEvent>,
) -> Result<Status, TelError> {
    vcp.expect("vcp")?;
    if vcp.str("ii") != issuer {
        return Err(TelError::Mismatch(format!(
            "registry {} is controlled by {}, not the credential issuer {issuer}",
            vcp.prefix(),
            vcp.str("ii")
        )));
    }
    if vcp.fields.get("c") != Some(&Value::Array(vec!["NB".into()])) {
        return Err(TelError::Mismatch("only no-backer (`NB`) registries are supported".into()));
    }

    iss.expect("iss")?;
    if iss.prefix() != credential || iss.str("ri") != vcp.prefix() || iss.sn() != 0 {
        return Err(TelError::Mismatch("`iss` does not issue this credential in this registry at sn 0".into()));
    }

    let mut events = vec![vcp, iss];
    if let Some(rev) = rev {
        rev.expect("rev")?;
        if rev.prefix() != credential || rev.str("ri") != vcp.prefix() || rev.sn() != 1 {
            return Err(TelError::Mismatch("`rev` does not revoke this credential in this registry at sn 1".into()));
        }
        if rev.str("p") != iss.said() {
            return Err(TelError::Mismatch("`rev` does not chain to the `iss` event".into()));
        }
        events.push(rev);
    }

    for e in events {
        if !kel_anchors(issuer_kel, &e.seal()?) {
            return Err(TelError::NotAnchored { kind: e.ilk().into(), said: e.said().into() });
        }
    }
    Ok(if rev.is_some() { Status::Revoked } else { Status::Issued })
}
