//! Witness OOBIs in keripy's URL form: `{base}/oobi/{cid}/witness/{eid}`.
//! Resolving one fetches the witness's location and the controller's KEL.

use keri_controller::{EndRole, LocationScheme, RedbController};
use keri_core::{oobi::Role, prefix::IdentifierPrefix};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct WitnessOobi {
    /// The witness's base URL.
    pub base: Url,
    /// The AID whose KEL the OOBI introduces.
    pub cid: IdentifierPrefix,
    /// The witness AID.
    pub eid: IdentifierPrefix,
}

#[derive(Debug, thiserror::Error)]
pub enum OobiError {
    #[error("not a witness OOBI URL: {0}")]
    Format(String),
    #[error("resolving {url}: {reason}")]
    Resolve { url: String, reason: String },
}

pub fn parse(oobi: &str) -> Result<WitnessOobi, OobiError> {
    let bad = || OobiError::Format(oobi.into());
    let url = Url::parse(oobi).map_err(|_| bad())?;
    let segments: Vec<&str> = url.path_segments().ok_or_else(bad)?.filter(|s| !s.is_empty()).collect();
    let [.., "oobi", cid, "witness", eid] = segments.as_slice() else { return Err(bad()) };
    let mut base = url.clone();
    let prefix_len = segments.len() - 4;
    base.set_path(&format!("/{}", segments[..prefix_len].iter().map(|s| format!("{s}/")).collect::<String>()));
    Ok(WitnessOobi {
        base,
        cid: cid.parse().map_err(|_| bad())?,
        eid: eid.parse().map_err(|_| bad())?,
    })
}

/// Resolves a witness OOBI into `controller`: afterwards the controller knows
/// the KEL of `cid` (as the witness has it).
pub async fn resolve(controller: &RedbController, oobi: &str) -> Result<IdentifierPrefix, OobiError> {
    let o = parse(oobi)?;
    let fail = |e: &dyn std::fmt::Display| OobiError::Resolve { url: oobi.into(), reason: e.to_string() };
    controller
        .communication
        .resolve_loc_schema(&LocationScheme { eid: o.eid.clone(), scheme: keri_core::oobi::Scheme::Http, url: Some(o.base.clone()) })
        .await
        .map_err(|e| fail(&e))?;
    controller
        .communication
        .resolve_end_role(&EndRole { cid: o.cid.clone(), role: Role::Witness, eid: o.eid.clone() })
        .await
        .map_err(|e| fail(&e))?;
    controller.find_state(&o.cid).map_err(|e| fail(&e))?;
    Ok(o.cid)
}
