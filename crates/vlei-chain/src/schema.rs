//! GLEIF's published vLEI credential schemas (ACDC 1.0, JSON Schema draft-07),
//! embedded from `infra/schemas`.

use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Qvi,
    Le,
    OorAuth,
    Oor,
    EcrAuth,
    Ecr,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Qvi, Kind::Le, Kind::OorAuth, Kind::Oor, Kind::EcrAuth, Kind::Ecr];

    fn source(self) -> &'static str {
        match self {
            Kind::Qvi => include_str!("../../../infra/schemas/qualified-vLEI-issuer-vLEI-credential.json"),
            Kind::Le => include_str!("../../../infra/schemas/legal-entity-vLEI-credential.json"),
            Kind::OorAuth => include_str!("../../../infra/schemas/oor-authorization-vlei-credential.json"),
            Kind::Oor => include_str!("../../../infra/schemas/legal-entity-official-organizational-role-vLEI-credential.json"),
            Kind::EcrAuth => include_str!("../../../infra/schemas/ecr-authorization-vlei-credential.json"),
            Kind::Ecr => include_str!("../../../infra/schemas/legal-entity-engagement-context-role-vLEI-credential.json"),
        }
    }

    /// The schema SAID (`$id`), as published.
    pub fn said(self) -> &'static str {
        match self {
            Kind::Qvi => "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            Kind::Le => "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
            Kind::OorAuth => "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E",
            Kind::Oor => "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
            Kind::EcrAuth => "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",
            Kind::Ecr => "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
        }
    }

    pub fn from_said(said: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.said() == said)
    }

    pub fn json(self) -> &'static Value {
        static CACHE: OnceLock<Vec<Value>> = OnceLock::new();
        let all = CACHE.get_or_init(|| {
            Kind::ALL.iter().map(|k| serde_json::from_str(k.source()).expect("embedded schema is JSON")).collect()
        });
        &all[Kind::ALL.iter().position(|k| *k == self).unwrap()]
    }

    /// Recomputes the schema's SAID from its content.
    pub fn computed_said(self) -> String {
        let mut sad: Sad = serde_json::from_str(self.source()).expect("schema");
        saidify(&mut sad, HashFunctionCode::Blake3_256, SerializationFormats::JSON, &["$id"])
            .expect("saidify")
            .0
            .to_string()
    }

    /// The rule texts (`r` section) the schema fixes, in issuance order.
    pub fn rules(self) -> Vec<(&'static str, String)> {
        let rules = &self.json()["properties"]["r"]["oneOf"][1]["properties"];
        ["usageDisclaimer", "issuanceDisclaimer", "privacyDisclaimer"]
            .into_iter()
            .filter_map(|k| rules[k]["properties"]["l"]["const"].as_str().map(|l| (k, l.to_owned())))
            .collect()
    }

    /// Validates a credential against this schema; returns every violation.
    pub fn validate(self, credential: &Value) -> Result<(), Vec<String>> {
        let validator = jsonschema::draft7::new(self.json()).map_err(|e| vec![e.to_string()])?;
        let errors: Vec<String> =
            validator.iter_errors(credential).map(|e| format!("{} at {}", e, e.instance_path())).collect();
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}
