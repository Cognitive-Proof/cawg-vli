//! Validator for `cawg.vlei` identity assertions (CAWG identity assertion
//! PR 269), following the steps of the PR's `validating.adoc` in order.
//!
//! The validator uses no private keys and nothing from the signer's world:
//! it starts from a [`Trust`] configuration (the pinned GLEIF Root and GEDA
//! AIDs and the schema SAIDs) and an [`Evidence`] bundle of KELs and TELs
//! that stands in for witnesses and watchers. The signer's KEL is taken
//! from the evidence when it is there and otherwise fetched from the OOBIs
//! in `signer_aid_oobi`, as step 2.b says.
//!
//! Every failure names the PR step it comes from ([`VerifyError::step`]), so
//! negative tests can check *where* a bad assertion is rejected.
//!
//! Steps (numbering as in `validating.adoc`):
//!
//! | step      | check |
//! |-----------|-------|
//! | `setup`   | trust anchors' KELs, GEDA delegated by Root, schema SAIDs |
//! | `c2pa`    | the manifest itself validates (assets only) |
//! | `1`       | `sig_type` is `cawg.vlei` |
//! | `2.a`     | `signature` decodes as `vlei-signature-payload-map` |
//! | `2.b`     | signer's KEL has an establishment event at `kel_seq_num` |
//! | `2.c.qvi` | QVI credential (the PR assumes this is done at setup) |
//! | `2.c.i`   | LE credential |
//! | `2.c.ii`  | role credential (OOR or ECR) |
//! | `2.c.ii.auth` | role authorisation credential |
//! | `2.c.signer` | the credentials name the signer (not in the PR) |
//! | `3`       | anchor (`anchor_seq_num`) |
//! | `4`       | signatures and threshold |

use std::{collections::BTreeMap, path::Path};

use c2pa::identity::SignerPayload;
use keri_controller::{config::ControllerConfig, controller::Controller, IdentifierState, RedbController};
use keri_core::{
    event::{event_data::EventData, sections::seal::Seal},
    event_message::signed_event_message::Notice,
    prefix::{CesrPrimitive, IdentifierPrefix, IndexedSignature},
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use vlei_chain::{
    chain::Fixtures,
    credential::{self, Parsed},
    schema::Kind,
    tel::{self, Status, TelEvent},
};
use vlei_sign::{encode_signer_payload, Encoding, VleiSignaturePayload};

/// What a verifier is configured with before it sees any asset
/// (`trust.json`). PR 269 assumes this setup but does not define it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    pub gleif_root: String,
    pub geda: String,
    /// Schema SAIDs by credential kind, as installed.
    pub schemas: BTreeMap<String, String>,
}

impl Trust {
    pub fn from_fixtures(f: &Fixtures) -> Self {
        Trust {
            gleif_root: f.trust["gleif-root"].clone(),
            geda: f.trust["geda"].clone(),
            schemas: Kind::ALL.iter().map(|k| (kind_name(*k).to_owned(), k.said().to_owned())).collect(),
        }
    }
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Qvi => "qvi",
        Kind::Le => "le",
        Kind::OorAuth => "oor-auth",
        Kind::Oor => "oor",
        Kind::EcrAuth => "ecr-auth",
        Kind::Ecr => "ecr",
    }
}

/// KELs and TELs the verifier can consult. In production these come from
/// witnesses and watchers; PR 269 does not say where TELs and the issuers'
/// KELs come from (finding F5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// KEL CESR streams, keyed by AID.
    pub kels: BTreeMap<String, String>,
    /// Registry inception (`vcp`), keyed by registry identifier.
    pub registries: BTreeMap<String, String>,
    /// TEL events (`iss`, then `rev` if revoked), keyed by credential SAID.
    pub tels: BTreeMap<String, Vec<String>>,
}

impl Evidence {
    /// Everything public in the fixtures, except the KELs of the AIDs named
    /// in `without` (so that the verifier must resolve them by OOBI).
    pub fn from_fixtures(f: &Fixtures, without: &[&str]) -> Self {
        let skip: Vec<&str> = without.iter().filter_map(|n| f.aids.get(*n)).map(|a| a.prefix.as_str()).collect();
        let kels = f
            .kels
            .iter()
            .filter(|(k, _)| !skip.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let registries = f
            .registries
            .values()
            .filter_map(|vcp| TelEvent::parse(vcp.as_bytes()).ok().map(|e| (e.prefix().to_owned(), vcp.clone())))
            .collect();
        let tels = f.credentials.values().map(|c| (c.credential.said.clone(), c.tel.clone())).collect();
        Evidence { kels, registries, tels }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Which bytes of `signer_payload` the signatures cover (finding F1).
    pub encoding: Encoding,
    /// Reject signatures made with keys that a later establishment event
    /// replaced, unless an anchor before that rotation dates them. PR 269 is
    /// silent on this.
    pub reject_superseded_keys: bool,
    /// Require `signer_aid` to be the subject of the presented credentials
    /// (step `2.c.signer`). PR 269 has no such step (finding F13); turning
    /// this off validates exactly as the PR is written.
    pub bind_signer: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { encoding: Encoding::Deterministic, reject_superseded_keys: true, bind_signer: true }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("step {step}: {reason}")]
pub struct VerifyError {
    pub step: &'static str,
    pub reason: String,
}

fn fail<T>(step: &'static str, reason: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError { step, reason: reason.into() })
}

fn err(step: &'static str, e: impl std::fmt::Display) -> VerifyError {
    VerifyError { step, reason: e.to_string() }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KelSource {
    /// Already known (from the evidence).
    Known,
    /// Fetched from this OOBI.
    Oobi(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Role {
    /// The legal entity signing for itself: no role credential.
    LegalEntity,
    Oor { person: String, role: String },
    EcrByQvi { person: String, role: String },
    EcrByLe { person: String, role: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckedCredential {
    pub kind: &'static str,
    pub said: String,
    pub issuer: String,
}

/// What a successful validation established.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub signer_aid: String,
    pub lei: String,
    pub role: Role,
    pub kel_source: KelSource,
    pub kel_seq_num: u64,
    /// False when a later establishment event replaced the signing keys.
    pub keys_current: bool,
    pub anchor_seq_num: Option<u64>,
    pub signatures: usize,
    pub keys: usize,
    /// Every credential checked (schema, SAIDs, edges, TEL status).
    pub credentials: Vec<CheckedCredential>,
    pub notes: Vec<String>,
}

pub struct Verifier {
    controller: RedbController,
    trust: Trust,
    evidence: Evidence,
    policy: Policy,
}

impl Verifier {
    /// A verifier with its own KERI database at `db`. `transport` reaches
    /// witnesses for OOBI resolution (the in-process one in tests).
    pub fn new(
        db: &Path,
        trust: Trust,
        evidence: Evidence,
        policy: Policy,
        transport: Option<Box<dyn Transport + Send + Sync>>,
    ) -> Result<Self, VerifyError> {
        let mut config = ControllerConfig { db_path: db.into(), ..Default::default() };
        if let Some(t) = transport {
            config.transport = t;
        }
        let controller = Controller::new(config).map_err(|e| err("setup", e))?;
        let v = Verifier { controller, trust, evidence, policy };
        v.setup()?;
        Ok(v)
    }

    /// The preparation the PR assumes: schemas installed and fingerprinted,
    /// trust anchors' KELs known, GEDA delegated by the pinned Root.
    fn setup(&self) -> Result<(), VerifyError> {
        for k in Kind::ALL {
            let pinned = self.trust.schemas.get(kind_name(k));
            if pinned.map(String::as_str) != Some(k.said()) || k.computed_said() != k.said() {
                return fail("setup", format!("schema {} is not the pinned, self-addressing one", kind_name(k)));
            }
        }
        // Escrowed events (delegates before delegators, groups before
        // members) are released by later passes.
        for _ in 0..3 {
            for kel in self.evidence.kels.values() {
                let _ = self.controller.known_events.process_stream(kel.as_bytes());
            }
        }
        let root = self.state("setup", &self.trust.gleif_root)?;
        let geda = self.state("setup", &self.trust.geda)?;
        if root.delegator.is_some() {
            return fail("setup", "GLEIF Root is itself delegated");
        }
        if geda.delegator.map(|d| d.to_str()) != Some(self.trust.gleif_root.clone()) {
            return fail("setup", "GEDA is not delegated by the pinned GLEIF Root");
        }
        Ok(())
    }

    fn state(&self, step: &'static str, aid: &str) -> Result<IdentifierState, VerifyError> {
        let prefix: IdentifierPrefix = aid.parse().map_err(|_| err(step, format!("bad AID `{aid}`")))?;
        self.controller.find_state(&prefix).map_err(|_| err(step, format!("KEL of {aid} is not available")))
    }

    fn kel(&self, aid: &str) -> Vec<Notice> {
        aid.parse().ok().and_then(|p| self.controller.get_kel_with_receipts(&p)).unwrap_or_default()
    }

    /// Validates a signed asset: the C2PA manifest first, then its
    /// `cawg.vlei` identity assertion.
    pub async fn verify_asset(&self, asset: &[u8]) -> Result<Report, VerifyError> {
        let reader = c2pa::Reader::default()
            .with_stream("image/png", std::io::Cursor::new(asset))
            .map_err(|e| err("c2pa", e))?;
        match reader.validation_state() {
            c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted => {}
            other => return fail("c2pa", format!("manifest validation state {other:?}")),
        }
        let rb = vlei_holder::read_identity_assertion(asset).map_err(|e| err("2.a", e))?;
        self.verify(&rb.signer_payload, &rb.signature).await
    }

    /// Validates the `signer_payload` and `signature` of an identity
    /// assertion whose `sig_type` is `cawg.vlei`.
    pub async fn verify(&self, signer_payload: &SignerPayload, signature: &[u8]) -> Result<Report, VerifyError> {
        let mut notes = Vec::new();

        // 1. Check signature type.
        if signer_payload.sig_type != "cawg.vlei" {
            return fail("1", format!("sig_type is `{}`", signer_payload.sig_type));
        }

        // 2.a Decode the map.
        let map = VleiSignaturePayload::from_cbor(signature).map_err(|e| err("2.a", e))?;
        if !vlei_sign::cbor::is_deterministic(signature) {
            notes.push("signature map is not in core deterministic encoding".into());
        }

        // 2.b Signer's keys at kel_seq_num.
        let kel_source = self.sync_signer(&map).await?;
        let est = self.establishment_events(&map.signer_aid);
        let next_est = est.iter().copied().find(|sn| *sn > map.kel_seq_num);

        // 2.c Trust chain.
        let mut checked = Vec::new();
        let (role, lei) = self.trust_chain(&map, &mut checked)?;

        // 3. Anchor.
        let payload = encode_signer_payload(signer_payload, self.policy.encoding);
        if let Some(sn) = map.anchor_seq_num {
            let anchored = self.kel(&map.signer_aid).iter().any(|n| match n {
                Notice::Event(e) if e.event_message.data.get_sn() == sn => {
                    e.event_message.data.event_data.seals().iter().any(|s| match s {
                        // The seal's own derivation code says which hash to use.
                        Seal::Digest(d) => d.digest().verify_binding(&payload),
                        _ => false,
                    })
                }
                _ => false,
            });
            if !anchored {
                return fail("3", format!("event {sn} of the signer's KEL does not anchor the signer_payload digest"));
            }
        }

        // Keys replaced later are only acceptable with an anchor that dates
        // the signature before the rotation.
        let keys_current = next_est.is_none();
        if let Some(rot) = next_est {
            if map.anchor_seq_num.is_some_and(|a| a < rot) {
                notes.push(format!("signing keys were rotated at sn {rot}; the anchor at an earlier sn dates the signature"));
            } else if self.policy.reject_superseded_keys {
                return fail("2.b", format!("signing keys (sn {}) were replaced at sn {rot}", map.kel_seq_num));
            } else {
                notes.push(format!("signing keys were replaced at sn {rot}"));
            }
        }

        // 4. Signatures and threshold.
        let (signatures, keys) = self.check_signatures(&map, &payload)?;

        Ok(Report {
            signer_aid: map.signer_aid.clone(),
            lei,
            role,
            kel_source,
            kel_seq_num: map.kel_seq_num,
            keys_current,
            anchor_seq_num: map.anchor_seq_num,
            signatures,
            keys,
            credentials: checked,
            notes,
        })
    }

    async fn sync_signer(&self, map: &VleiSignaturePayload) -> Result<KelSource, VerifyError> {
        // PR 269 only asks for the establishment event at `kel_seq_num`; a
        // cached KEL that predates the anchoring event must be refreshed too.
        let known = || {
            self.establishment_events(&map.signer_aid).contains(&map.kel_seq_num)
                && map.anchor_seq_num.is_none_or(|a| self.last_sn(&map.signer_aid).is_some_and(|l| l >= a))
        };
        if known() {
            return Ok(KelSource::Known);
        }
        let mut errors = Vec::new();
        for oobi in &map.signer_aid_oobi {
            match vlei_chain::oobi::resolve(&self.controller, oobi).await {
                Ok(cid) if cid.to_str() != map.signer_aid => errors.push(format!("{oobi} introduces {}", cid.to_str())),
                Ok(_) if known() => return Ok(KelSource::Oobi(oobi.clone())),
                Ok(_) => errors.push(format!("{oobi}: no establishment event at sn {}", map.kel_seq_num)),
                Err(e) => errors.push(e.to_string()),
            }
        }
        if errors.is_empty() {
            errors.push("no OOBIs".into());
        }
        fail("2.b", format!("signer's keys at sn {} not available: {}", map.kel_seq_num, errors.join("; ")))
    }

    fn last_sn(&self, aid: &str) -> Option<u64> {
        self.kel(aid)
            .iter()
            .filter_map(|n| match n {
                Notice::Event(e) => Some(e.event_message.data.get_sn()),
                _ => None,
            })
            .max()
    }

    /// Sequence numbers of the establishment events in `aid`'s KEL.
    fn establishment_events(&self, aid: &str) -> Vec<u64> {
        self.kel(aid)
            .iter()
            .filter_map(|n| match n {
                Notice::Event(e) => match e.event_message.data.event_data {
                    EventData::Icp(_) | EventData::Rot(_) | EventData::Dip(_) | EventData::Drt(_) => {
                        Some(e.event_message.data.get_sn())
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// Parses `json` as a credential of one of `kinds` and checks that its
    /// TEL says issued, anchored in the issuer's KEL.
    fn credential(
        &self,
        step: &'static str,
        json: &str,
        kinds: &[Kind],
        checked: &mut Vec<CheckedCredential>,
    ) -> Result<Parsed, VerifyError> {
        if json.is_empty() {
            return fail(step, "credential is empty");
        }
        let p = credential::parse(json).map_err(|e| err(step, e))?;
        let c = &p.credential;
        if !kinds.contains(&c.kind) {
            return fail(step, format!("credential has schema {:?}, expected one of {kinds:?}", c.kind));
        }
        self.state(step, &c.issuer)?;
        let vcp = self
            .evidence
            .registries
            .get(&c.registry)
            .ok_or_else(|| err(step, format!("registry {} of {} is not available", c.registry, c.said)))?;
        let events = self.evidence.tels.get(&c.said).ok_or_else(|| err(step, format!("TEL of {} is not available", c.said)))?;
        let parse = |s: &String| TelEvent::parse(s.as_bytes()).map_err(|e| err(step, e));
        let vcp = parse(vcp)?;
        let iss = parse(events.first().ok_or_else(|| err(step, "empty TEL"))?)?;
        let rev = events.get(1).map(parse).transpose()?;
        let status = tel::credential_status(&c.said, &c.issuer, &self.kel(&c.issuer), &vcp, &iss, rev.as_ref())
            .map_err(|e| err(step, e))?;
        if status == Status::Revoked {
            return fail(step, format!("{} credential {} is revoked", kind_name(c.kind), c.said));
        }
        checked.push(CheckedCredential { kind: kind_name(c.kind), said: c.said.clone(), issuer: c.issuer.clone() });
        Ok(p)
    }

    fn trust_chain(
        &self,
        map: &VleiSignaturePayload,
        checked: &mut Vec<CheckedCredential>,
    ) -> Result<(Role, String), VerifyError> {
        // QVI credential: the PR assumes it is validated at setup.
        let qvi = self.credential("2.c.qvi", &map.qvi_cred, &[Kind::Qvi], checked)?;
        if qvi.credential.issuer != self.trust.geda {
            return fail("2.c.qvi", "QVI credential is not issued by the pinned GEDA");
        }
        let qvi_aid = qvi.credential.issuee.clone();
        if self.state("2.c.qvi", &qvi_aid)?.delegator.map(|d| d.to_str()) != Some(self.trust.geda.clone()) {
            return fail("2.c.qvi", "QVI AID is not delegated by GEDA");
        }

        // 2.c.i LE credential.
        let le = self.credential("2.c.i", &map.le_cred, &[Kind::Le], checked)?;
        if le.credential.issuer != qvi_aid {
            return fail("2.c.i", "LE credential is not issued by the QVI");
        }
        edge_to("2.c.i", &le, "qvi", &qvi)?;
        let le_aid = le.credential.issuee.clone();
        let lei = le.claim("LEI").unwrap_or_default().to_owned();

        // 2.c.ii Role credential.
        let Some(rc) = &map.role_cred else {
            if self.policy.bind_signer && map.signer_aid != le_aid {
                return fail("2.c.signer", "no role credential, and the signer is not the legal entity");
            }
            return Ok((Role::LegalEntity, lei));
        };
        let cred = self.credential("2.c.ii", &rc.cred, &[Kind::Oor, Kind::Ecr], checked)?;
        if cred.claim("LEI") != Some(lei.as_str()) {
            return fail("2.c.ii", "role credential's LEI differs from the LE credential's");
        }
        let person = cred.claim("personLegalName").unwrap_or_default().to_owned();
        let (role_claim, auth_kind) = match cred.credential.kind {
            Kind::Oor => ("officialRole", Kind::OorAuth),
            _ => ("engagementContextRole", Kind::EcrAuth),
        };
        let role_name = cred.claim(role_claim).unwrap_or_default().to_owned();

        let role = if cred.edge("le").is_some() {
            // ECR issued by the legal entity itself.
            if cred.credential.kind != Kind::Ecr || cred.credential.issuer != le_aid {
                return fail("2.c.ii", "a role credential with an `le` edge must be an ECR issued by the legal entity");
            }
            edge_to("2.c.ii", &cred, "le", &le)?;
            if !rc.auth_cred.is_empty() {
                return fail("2.c.ii.auth", "auth_cred must be empty for an ECR issued by the legal entity");
            }
            Role::EcrByLe { person, role: role_name }
        } else {
            if cred.credential.issuer != qvi_aid {
                return fail("2.c.ii", "role credential is not issued by the QVI");
            }
            // 2.c.ii.auth The authorisation behind it.
            let auth = self.credential("2.c.ii.auth", &rc.auth_cred, &[auth_kind], checked)?;
            edge_to("2.c.ii.auth", &cred, "auth", &auth)?;
            if cred.edge("auth").and_then(|e| e.o.as_deref()) != Some("I2I") || auth.credential.issuee != cred.credential.issuer {
                return fail("2.c.ii.auth", "I2I: the authorisation is not issued to the role credential's issuer");
            }
            if auth.credential.issuer != le_aid {
                return fail("2.c.ii.auth", "authorisation is not issued by the legal entity");
            }
            edge_to("2.c.ii.auth", &auth, "le", &le)?;
            for claim in ["LEI", "personLegalName", role_claim] {
                if auth.claim(claim) != cred.claim(claim) {
                    return fail("2.c.ii.auth", format!("`{claim}` differs between authorisation and role credential"));
                }
            }
            if auth.claim("AID") != Some(cred.credential.issuee.as_str()) {
                return fail("2.c.ii.auth", "authorisation names a different AID than the role credential's issuee");
            }
            match cred.credential.kind {
                Kind::Oor => Role::Oor { person, role: role_name },
                _ => Role::EcrByQvi { person, role: role_name },
            }
        };
        if self.policy.bind_signer && cred.credential.issuee != map.signer_aid {
            return fail("2.c.signer", "role credential is issued to a different AID than signer_aid");
        }
        Ok((role, lei))
    }

    fn check_signatures(&self, map: &VleiSignaturePayload, payload: &[u8]) -> Result<(usize, usize), VerifyError> {
        let prefix: IdentifierPrefix = map.signer_aid.parse().map_err(|_| err("4", "bad signer AID"))?;
        let storage = &self.controller.known_events.storage;
        let event = storage
            .get_event_at_sn(&prefix, map.kel_seq_num)
            .ok_or_else(|| err("4", "establishment event not found"))?;
        let digest = event.signed_event_message.event_message.digest().map_err(|e| err("4", e))?;
        let config = storage
            .get_keys_at_event(&prefix, map.kel_seq_num, &digest)
            .map_err(|e| err("4", e))?
            .ok_or_else(|| err("4", "no key configuration at kel_seq_num"))?;

        if map.aid_sig.is_empty() {
            return fail("4", "aid_sig is empty");
        }
        let mut indexes = Vec::new();
        for (n, s) in map.aid_sig.iter().enumerate() {
            let sig: IndexedSignature =
                s.parse().map_err(|_| err("4", format!("aid_sig[{n}] is not an indexed CESR signature")))?;
            let index = sig.index.current() as usize;
            let key = config.public_keys.get(index).ok_or_else(|| {
                err("4", format!("aid_sig[{n}] names key {index}; the establishment event has {}", config.public_keys.len()))
            })?;
            if !key.verify(payload, &sig.signature).unwrap_or(false) {
                return fail("4", format!("aid_sig[{n}] does not verify with key {index}"));
            }
            if indexes.contains(&index) {
                return fail("4", format!("aid_sig[{n}] repeats key {index}"));
            }
            indexes.push(index);
        }
        config
            .threshold
            .enough_signatures(&indexes)
            .map_err(|_| err("4", format!("{} signature(s) do not satisfy the key threshold", indexes.len())))?;
        Ok((indexes.len(), config.public_keys.len()))
    }
}

/// `from` has edge `label` pointing at `to`, with `to`'s schema.
fn edge_to(step: &'static str, from: &Parsed, label: &str, to: &Parsed) -> Result<(), VerifyError> {
    match from.edge(label) {
        Some(e) if e.n == to.credential.said && e.s == to.credential.kind.said() => Ok(()),
        Some(_) => fail(step, format!("edge `{label}` does not point at the presented credential")),
        None => fail(step, format!("credential has no `{label}` edge")),
    }
}
