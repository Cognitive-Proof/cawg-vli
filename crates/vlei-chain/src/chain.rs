//! Builds the testbed's vLEI trust chain in one in-process KERI world:
//!
//! ```text
//! GLEIF Root (2-of-3 multisig)
//!   └─ GEDA (delegated from Root)
//!        └─ QVI "Northwind" (delegated from GEDA) ── QVI credential, issued by GEDA
//!             └─ Legal entity "Fabrikam" (2-of-2 multisig) ── LE credential, issued by QVI
//!                  ├─ Alice, CFO ── OOR auth (Fabrikam → QVI), OOR (QVI → Alice)
//!                  ├─ Bob, Press Officer ── ECR auth (Fabrikam → QVI), ECR (QVI → Bob)
//!                  └─ Carol, Editor ── ECR (Fabrikam → Carol, edge to the LE credential)
//! ```
//!
//! Organisation AIDs are group identifiers controlled by member identifiers;
//! people have single-key AIDs. All parties share one controller database,
//! so no witnesses or message delivery are needed while building. The
//! public results are exported as [`Fixtures`].

use std::{collections::BTreeMap, path::Path};

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError, ActionRequired,
    BasicPrefix, CryptoBox, KeyManager, RedbController, RedbIdentifier, SelfSigningPrefix,
};
use keri_core::{
    event::sections::seal::{EventSeal, Seal},
    event_message::signed_event_message::Message,
    prefix::IdentifierPrefix,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    credential::{self, Credential, Edge, Spec},
    schema::Kind,
    tel::{self, TelEvent},
};

pub const DT: &str = "2026-11-24T00:00:00.000000+00:00";
pub const QVI_LEI: &str = "9845000NORTHWIND0007";
pub const LE_LEI: &str = "9845000FABRIKAM00042";

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("controller: {0}")]
    Controller(#[from] ControllerError),
    #[error("KERI: {0}")]
    Mechanics(#[from] keri_controller::identifier::mechanics::MechanicsError),
    #[error("keys: {0}")]
    Keys(#[from] keri_core::error::Error),
    #[error("TEL: {0}")]
    Tel(#[from] tel::TelError),
    #[error("credential: {0}")]
    Credential(#[from] credential::CredentialError),
    #[error("{0}")]
    Other(String),
}

fn other(e: impl std::fmt::Display) -> ChainError {
    ChainError::Other(e.to_string())
}

/// A single-key identifier with its keys.
pub struct Member {
    pub name: String,
    pub keys: CryptoBox,
    pub id: RedbIdentifier,
}

impl Member {
    pub fn aid(&self) -> String {
        self.id.id().to_string()
    }
    pub fn sign(&self, data: &[u8]) -> Result<SelfSigningPrefix, ChainError> {
        Ok(SelfSigningPrefix::Ed25519Sha512(self.keys.sign(data)?))
    }
}

/// A group (organisation) identifier and the members that control it.
pub struct Org {
    pub name: String,
    pub prefix: IdentifierPrefix,
    pub members: Vec<Member>,
    /// How many member signatures an event needs.
    pub threshold: usize,
    pub registry: Option<TelEvent>,
}

impl Org {
    pub fn aid(&self) -> String {
        self.prefix.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidInfo {
    pub prefix: String,
    /// `person`, `group`, or `member` (a key holder of a group).
    pub kind: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threshold: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub credential: Credential,
    /// The `iss` event (and `rev`, once revoked) as serialized JSON.
    pub tel: Vec<String>,
}

/// Everything a verifier may know: public, no private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixtures {
    pub dt: String,
    /// The trust anchors a verifier is configured with (PR 269 leaves this undefined).
    pub trust: BTreeMap<String, String>,
    pub aids: BTreeMap<String, AidInfo>,
    /// KEL of every AID as a CESR stream, keyed by prefix.
    pub kels: BTreeMap<String, String>,
    /// Registry inception (`vcp`) per issuing organisation name.
    pub registries: BTreeMap<String, String>,
    pub credentials: BTreeMap<String, IssuedCredential>,
}

pub struct World {
    pub controller: RedbController,
    pub orgs: BTreeMap<String, Org>,
    pub people: BTreeMap<String, Member>,
    pub credentials: BTreeMap<String, IssuedCredential>,
}

async fn member(c: &RedbController, name: &str) -> Result<Member, ChainError> {
    let keys = CryptoBox::new()?;
    let icp = c
        .incept(vec![BasicPrefix::Ed25519(keys.public_key())], vec![BasicPrefix::Ed25519(keys.next_public_key())], vec![], 0)
        .await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes())?);
    let id = c.finalize_incept(icp.as_bytes(), &sig)?;
    Ok(Member { name: name.into(), keys, id })
}

impl World {
    pub fn new(db: &Path) -> Result<Self, ChainError> {
        let controller = Controller::new(ControllerConfig { db_path: db.to_owned(), ..Default::default() })?;
        Ok(Self { controller, orgs: BTreeMap::new(), people: BTreeMap::new(), credentials: BTreeMap::new() })
    }

    /// Incepts a group of `n` fresh members with signing threshold `threshold`,
    /// optionally delegated from the organisation `delegator`.
    pub async fn incept_org(
        &mut self,
        name: &str,
        n: usize,
        threshold: usize,
        delegator: Option<&str>,
    ) -> Result<(), ChainError> {
        let mut members = Vec::new();
        for i in 0..n {
            members.push(member(&self.controller, &format!("{name}-member-{}", i + 1)).await?);
        }
        let delegator_prefix = delegator.map(|d| self.orgs[d].prefix.clone());
        let others: Vec<IdentifierPrefix> = members[1..].iter().map(|m| m.id.id().clone()).collect();

        let (icp, exns) = members[0].id.incept_group(
            others,
            threshold as u64,
            Some(threshold as u64),
            None,
            None,
            delegator_prefix.clone(),
        )?;
        let mut signed_exns = Vec::new();
        for exn in exns.iter().take(n - 1) {
            let sig = members[0].sign(exn.as_bytes())?;
            signed_exns.push((exn.as_bytes().to_vec(), members[0].id.sign_with_index(sig, 0)?));
        }
        let sig = members[0].sign(icp.as_bytes())?;
        let (prefix, forwards) = members[0].id.finalize_group_incept(icp.as_bytes(), sig, signed_exns).await?;

        // The other members co-sign the inception until the threshold is met.
        for m in members.iter_mut().skip(1).take(threshold - 1) {
            let fwd = forwards.iter().find(|f| &f.to == m.id.id()).ok_or_else(|| other("no forward for member"))?;
            let actions = m.id.receive_forwards(&fwd.message).await?;
            if !matches!(actions.as_slice(), [ActionRequired::MultisigRequest(..)]) {
                return Err(other(format!("{name}: expected a multisig request, got {actions:?}")));
            }
            let sig = m.sign(icp.as_bytes())?;
            m.id.finalize_group_event(icp.as_bytes(), sig, vec![]).await?;
        }

        // A delegated inception waits for the delegator to anchor it.
        if let Some(delegator) = delegator {
            let seal = Seal::Event(EventSeal::new(
                prefix.clone(),
                0,
                icp_said(icp.as_bytes())?.parse().map_err(other)?,
            ));
            self.anchor(delegator, &[seal]).await?;
        }

        let state = self.controller.find_state(&prefix).map_err(|e| other(format!("{name} not accepted: {e}")))?;
        if state.sn != 0 {
            return Err(other(format!("{name}: unexpected sn {}", state.sn)));
        }
        self.orgs.insert(name.into(), Org { name: name.into(), prefix, members, threshold, registry: None });
        Ok(())
    }

    pub async fn add_person(&mut self, name: &str) -> Result<(), ChainError> {
        let m = member(&self.controller, name).await?;
        self.people.insert(name.into(), m);
        Ok(())
    }

    /// Anchors `seals` in organisation `org`'s KEL with an `ixn` signed by
    /// `threshold` members.
    pub async fn anchor(&mut self, org: &str, seals: &[Seal]) -> Result<(), ChainError> {
        let org = self.orgs.get_mut(org).ok_or_else(|| other("unknown organisation"))?;
        let participants: Vec<IdentifierPrefix> = org.members.iter().map(|m| m.id.id().clone()).collect();
        let (ixn, _) = org.members[0].id.anchor_group_with_seals(&org.prefix, seals, &participants)?;
        for m in org.members.iter_mut().take(org.threshold) {
            let sig = m.sign(ixn.as_bytes())?;
            m.id.finalize_group_event(ixn.as_bytes(), sig, vec![]).await?;
        }
        let kel = self.controller.get_kel_with_receipts(&org.prefix).unwrap_or_default();
        if !seals.iter().all(|s| tel::kel_anchors(&kel, s)) {
            return Err(other(format!("{}: anchoring ixn was not accepted", org.name)));
        }
        Ok(())
    }

    /// Incepts a no-backer registry for `org`.
    pub async fn incept_registry(&mut self, org: &str) -> Result<(), ChainError> {
        let issuer = self.orgs[org].aid();
        let vcp = tel::vcp(&issuer, &credential::salt(&issuer, "registry-nonce"))?;
        self.anchor(org, &[vcp.seal()?]).await?;
        self.orgs.get_mut(org).unwrap().registry = Some(vcp);
        Ok(())
    }

    /// Issues a credential from organisation `issuer` and anchors its `iss`.
    pub async fn issue(
        &mut self,
        name: &str,
        issuer: &str,
        kind: Kind,
        issuee: &str,
        claims: Vec<(&str, serde_json::Value)>,
        edges: Vec<Edge>,
    ) -> Result<Credential, ChainError> {
        let org = &self.orgs[issuer];
        let registry = org.registry.as_ref().ok_or_else(|| other("issuer has no registry"))?.prefix().to_owned();
        let issuer_aid = org.aid();
        let private = kind == Kind::Ecr;
        let cred = credential::issue(Spec {
            kind,
            issuer: &issuer_aid,
            registry: &registry,
            issuee,
            dt: DT,
            claims,
            edges,
            salt_seed: private.then_some(name),
        })?;
        let iss = tel::iss(&cred.said, &registry, DT)?;
        self.anchor(issuer, &[iss.seal()?]).await?;
        self.credentials.insert(
            name.into(),
            IssuedCredential { credential: cred.clone(), tel: vec![String::from_utf8_lossy(iss.raw()).into()] },
        );
        Ok(cred)
    }

    /// Revokes credential `name` (used by negative tests).
    pub async fn revoke(&mut self, name: &str) -> Result<(), ChainError> {
        let issued = self.credentials.get(name).ok_or_else(|| other("unknown credential"))?.clone();
        let iss = TelEvent::parse(issued.tel[0].as_bytes())?;
        let rev = tel::rev(&issued.credential.said, &issued.credential.registry, iss.said(), DT)?;
        let issuer = self
            .orgs
            .values()
            .find(|o| o.aid() == issued.credential.issuer)
            .map(|o| o.name.clone())
            .ok_or_else(|| other("issuer not found"))?;
        self.anchor(&issuer, &[rev.seal()?]).await?;
        self.credentials.get_mut(name).unwrap().tel.push(String::from_utf8_lossy(rev.raw()).into());
        Ok(())
    }

    pub fn kel_cesr(&self, prefix: &IdentifierPrefix) -> Result<String, ChainError> {
        let notices = self.controller.get_kel_with_receipts(prefix).ok_or_else(|| other("unknown KEL"))?;
        let mut out = Vec::new();
        for n in notices {
            out.extend(Message::Notice(n).to_cesr().map_err(other)?);
        }
        String::from_utf8(out).map_err(other)
    }

    pub fn fixtures(&self) -> Result<Fixtures, ChainError> {
        let mut aids = BTreeMap::new();
        let mut kels = BTreeMap::new();
        let delegators = [("GEDA", "GLEIF-Root"), ("QVI", "GEDA")];
        for org in self.orgs.values() {
            let delegator = delegators.iter().find(|(o, _)| *o == org.name).map(|(_, d)| self.orgs[*d].aid());
            aids.insert(
                org.name.clone(),
                AidInfo {
                    prefix: org.aid(),
                    kind: "group".into(),
                    members: org.members.iter().map(|m| m.name.clone()).collect(),
                    threshold: Some(org.threshold),
                    delegator,
                },
            );
            kels.insert(org.aid(), self.kel_cesr(&org.prefix)?);
            for m in &org.members {
                aids.insert(m.name.clone(), AidInfo { prefix: m.aid(), kind: "member".into(), members: vec![], threshold: None, delegator: None });
                kels.insert(m.aid(), self.kel_cesr(m.id.id())?);
            }
        }
        for p in self.people.values() {
            aids.insert(p.name.clone(), AidInfo { prefix: p.aid(), kind: "person".into(), members: vec![], threshold: None, delegator: None });
            kels.insert(p.aid(), self.kel_cesr(p.id.id())?);
        }
        let registries = self
            .orgs
            .values()
            .filter_map(|o| o.registry.as_ref().map(|r| (o.name.clone(), String::from_utf8_lossy(r.raw()).into())))
            .collect();
        let trust = [("gleif-root", "GLEIF-Root"), ("geda", "GEDA")]
            .into_iter()
            .map(|(k, o)| (k.to_owned(), self.orgs[o].aid()))
            .collect();
        Ok(Fixtures { dt: DT.into(), trust, aids, kels, registries, credentials: self.credentials.clone() })
    }
}

fn icp_said(raw: &[u8]) -> Result<String, ChainError> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(other)?;
    v["d"].as_str().map(str::to_owned).ok_or_else(|| other("event without d"))
}

fn edge(label: &str, cred: &Credential, operator: Option<&str>) -> Edge {
    Edge { label: label.into(), n: cred.said.clone(), s: cred.kind.said().into(), o: operator.map(Into::into) }
}

/// Builds the whole chain described in the module docs.
pub async fn build(db: &Path) -> Result<World, ChainError> {
    let mut w = World::new(db)?;

    // Phase 1: identifiers.
    w.incept_org("GLEIF-Root", 3, 2, None).await?;
    w.incept_org("GEDA", 1, 1, Some("GLEIF-Root")).await?;
    w.incept_org("QVI", 1, 1, Some("GEDA")).await?;
    w.incept_org("Fabrikam", 2, 2, None).await?;
    for p in ["Alice", "Bob", "Carol"] {
        w.add_person(p).await?;
    }

    // Phase 2: registries and credentials.
    for org in ["GEDA", "QVI", "Fabrikam"] {
        w.incept_registry(org).await?;
    }
    let qvi_aid = w.orgs["QVI"].aid();
    let le_aid = w.orgs["Fabrikam"].aid();
    let (alice, bob, carol) = (w.people["Alice"].aid(), w.people["Bob"].aid(), w.people["Carol"].aid());

    let qvi = w.issue("qvi", "GEDA", Kind::Qvi, &qvi_aid, vec![("LEI", json!(QVI_LEI))], vec![]).await?;
    let le = w
        .issue("le", "QVI", Kind::Le, &le_aid, vec![("LEI", json!(LE_LEI))], vec![edge("qvi", &qvi, None)])
        .await?;

    let oor_auth = w
        .issue(
            "oor-auth-alice",
            "Fabrikam",
            Kind::OorAuth,
            &qvi_aid,
            vec![("AID", json!(alice)), ("LEI", json!(LE_LEI)), ("personLegalName", json!("Alice Example")), ("officialRole", json!("Chief Financial Officer"))],
            vec![edge("le", &le, None)],
        )
        .await?;
    w.issue(
        "oor-alice",
        "QVI",
        Kind::Oor,
        &alice,
        vec![("LEI", json!(LE_LEI)), ("personLegalName", json!("Alice Example")), ("officialRole", json!("Chief Financial Officer"))],
        vec![edge("auth", &oor_auth, Some("I2I"))],
    )
    .await?;

    let ecr_auth = w
        .issue(
            "ecr-auth-bob",
            "Fabrikam",
            Kind::EcrAuth,
            &qvi_aid,
            vec![("AID", json!(bob)), ("LEI", json!(LE_LEI)), ("personLegalName", json!("Bob Example")), ("engagementContextRole", json!("Press Officer"))],
            vec![edge("le", &le, None)],
        )
        .await?;
    w.issue(
        "ecr-bob",
        "QVI",
        Kind::Ecr,
        &bob,
        vec![("LEI", json!(LE_LEI)), ("personLegalName", json!("Bob Example")), ("engagementContextRole", json!("Press Officer"))],
        vec![edge("auth", &ecr_auth, Some("I2I"))],
    )
    .await?;

    w.issue(
        "ecr-carol",
        "Fabrikam",
        Kind::Ecr,
        &carol,
        vec![("LEI", json!(LE_LEI)), ("personLegalName", json!("Carol Example")), ("engagementContextRole", json!("Editor"))],
        vec![edge("le", &le, None)],
    )
    .await?;

    Ok(w)
}
