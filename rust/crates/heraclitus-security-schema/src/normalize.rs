//! `operational-fact/1.0` -> `heraclitus-security-event/1.0`.
//!
//! Funcao pura: tudo o que nao esta no Fato entra pelo `NormalizationContext`.
//! E isso que torna o gate CM0 verificavel — a mesma observacao com o mesmo
//! contexto da sempre os mesmos bytes, sem ler relogio nem ambiente.
//!
//! O Fato Operacional continua a ser o que era. Esta traducao NAO o substitui
//! (gate CM2): um `.hcx` sem `security_schema` continua a produzir Fatos que
//! ninguem tem de normalizar.

use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::canonical;
use crate::error::SchemaError;
use crate::mapping::{MappingSpec, ObservedAt};
use crate::model::{
    hash32, CanonicalSecurityEvent, CanonicalValue, EndpointRef, EntityRef,
    NormalizationProvenance, RESERVED_EXTENSION_NAMESPACE, SCHEMA_VERSION,
};
use crate::validate;

/// Algoritmo com que o Forge escreve `fact.evidence.raw_observation_hash`.
const EVIDENCE_HASH_ALGORITHM: &str = "b3";

/// O que o Fato nao sabe sobre si proprio: quem o recolheu, para que tenant,
/// em que ponto da sequencia da fonte, e com que artefato verificado.
#[derive(Debug, Clone)]
pub struct NormalizationContext<'a> {
    pub tenant_id: &'a str,
    pub datasource_id: &'a str,
    pub sensor_id: &'a str,
    /// Posicao na sequencia da propria fonte (offset, EventRecordID, cursor).
    /// `None` quando o adapter nao tem uma — nao se inventa um contador.
    pub source_sequence: Option<&'a str>,
    pub normalized_at_micros: i64,
    pub forge_source_id: &'a str,
    pub forge_lsn: u64,
    pub source_event_id: Option<&'a str>,
    /// Digest SHA-256 do `.hcx` JA VERIFICADO (`hcx::verify_artifact`).
    /// Normalizar com um digest que ninguem verificou seria assinar por baixo.
    pub connector_digest: [u8; 32],
}

/// Resultado da normalizacao.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Normalized {
    Event(Box<CanonicalSecurityEvent>),
    /// O mapping declara que esta acao nao e evento de seguranca (ruido
    /// operacional do servico). Nao ha evento — e nao ha invencao.
    NotSecurityRelevant {
        action: String,
    },
}

impl Normalized {
    pub fn event(&self) -> Option<&CanonicalSecurityEvent> {
        match self {
            Normalized::Event(event) => Some(event),
            Normalized::NotSecurityRelevant { .. } => None,
        }
    }

    pub fn into_event(self) -> Option<CanonicalSecurityEvent> {
        match self {
            Normalized::Event(event) => Some(*event),
            Normalized::NotSecurityRelevant { .. } => None,
        }
    }

    /// Digest canonico, quando ha evento.
    pub fn digest_hex(&self) -> Option<String> {
        self.event().map(canonical::canonical_digest_hex)
    }
}

fn at<'a>(fact: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut cursor = fact;
    for step in path {
        cursor = cursor.get(step)?;
    }
    match cursor {
        Json::Null => None,
        value => Some(value),
    }
}

fn label(path: &[&str]) -> String {
    path.join(".")
}

fn optional_text(fact: &Json, path: &[&str]) -> Result<Option<String>, SchemaError> {
    match at(fact, path) {
        None => Ok(None),
        Some(Json::String(text)) if text.trim().is_empty() => Ok(None),
        Some(Json::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(SchemaError::InvalidField {
            field: label(path),
            reason: format!("esperava texto, veio {other}"),
        }),
    }
}

fn required_text(fact: &Json, path: &[&str]) -> Result<String, SchemaError> {
    optional_text(fact, path)?.ok_or_else(|| SchemaError::MissingField(label(path)))
}

fn required_i64(fact: &Json, path: &[&str]) -> Result<i64, SchemaError> {
    match at(fact, path) {
        None => Err(SchemaError::MissingField(label(path))),
        Some(value) => value.as_i64().ok_or_else(|| SchemaError::InvalidField {
            field: label(path),
            reason: format!("esperava inteiro, veio {value}"),
        }),
    }
}

fn owned(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

/// Traduz um Fato Operacional para o modelo canonico segundo `mapping`.
pub fn from_operational_fact(
    fact: &Json,
    mapping: &MappingSpec,
    context: &NormalizationContext,
) -> Result<Normalized, SchemaError> {
    // --- conector: o mapping certo para este artefato, ou nenhum ---
    let knowledge_version = required_text(fact, &["fact.knowledge_version"])?;
    let (connector_id, connector_version) =
        knowledge_version
            .split_once('@')
            .ok_or_else(|| SchemaError::InvalidField {
                field: "fact.knowledge_version".to_owned(),
                reason: format!("esperava <id>@<versao>, veio {knowledge_version:?}"),
            })?;
    if !mapping.accepts_manifest(connector_id) {
        return Err(SchemaError::ConnectorMismatch {
            mapping_version: mapping.mapping_version.clone(),
            expected: mapping.connector.clone(),
            found: connector_id.to_owned(),
        });
    }

    // --- semantica declarada para esta acao ---
    let action = required_text(fact, &["fact.behavior", "action"])?;
    let declared = mapping.action(&action)?;
    if !declared.security_relevant {
        return Ok(Normalized::NotSecurityRelevant { action });
    }
    let risk = required_text(fact, &["fact.behavior", "risk_level"])?;
    let severity = mapping.severity_for(&risk)?;

    // --- tempo ---
    let ingested_at_micros = required_i64(fact, &["fact.time", "system_timestamp"])?;
    let observed_at_micros = match &mapping.observed_at {
        ObservedAt::IngestFallback => ingested_at_micros,
        ObservedAt::FactField { path } => required_i64(fact, &owned(path))?,
    };

    // --- identidade: o que a borda observou, e nada alem disso ---
    let observed = |path: &[&str]| -> Result<Option<String>, SchemaError> {
        Ok(optional_text(fact, path)?.filter(|value| !mapping.identity.is_absent(value)))
    };
    let actor_id = observed(&["fact.identity", "actor.id"])?;
    let actor_name = observed(&["fact.identity", "actor.name"])?;
    // Sem id e sem nome nao ha ator nenhum — e uma referencia vazia seria
    // afirmar que existiu alguem.
    let actor = if actor_id.is_some() || actor_name.is_some() {
        Some(EntityRef {
            kind: mapping.identity.actor_kind,
            id: actor_id,
            name: actor_name,
            domain: None,
        })
    } else {
        None
    };
    let target = observed(&["fact.identity", "target.id"])?.map(|id| EntityRef {
        kind: mapping.identity.target_kind,
        id: Some(id),
        name: None,
        domain: None,
    });
    let source = observed(&["fact.identity", "source.ip"])?.map(|address| EndpointRef {
        address: Some(address),
        port: None,
        hostname: None,
    });

    // --- extensoes do proprio Heraclitus ---
    // Namespace reservado: sao campos do Forge, nao do vendor. O primeiro diz
    // se `observed_at_micros` e o carimbo da fonte ou uma aproximacao — sem
    // ele, um relogio atrasado ficaria indistinguivel de ingestao atrasada.
    let mut extensions: BTreeMap<String, CanonicalValue> = BTreeMap::new();
    let ext = |name: &str| format!("{RESERVED_EXTENSION_NAMESPACE}.{name}");
    extensions.insert(
        ext("observed_at_source"),
        CanonicalValue::from(mapping.observed_at.marker()),
    );
    extensions.insert(
        ext("behavior_class"),
        CanonicalValue::from(required_text(fact, &["fact.behavior", "class"])?),
    );
    extensions.insert(ext("risk_level"), CanonicalValue::from(risk));
    if let Some(confidence) = at(fact, &["fact.confidence"]).and_then(Json::as_f64) {
        // Por mil, inteiro: o modelo canonico nao carrega ponto flutuante
        // (ver `CanonicalValue`) e 0.972 tem de sobreviver a ida e volta.
        extensions.insert(
            ext("confidence_permille"),
            CanonicalValue::Int((confidence * 1000.0).round() as i64),
        );
    }

    // --- proveniencia: o caminho de volta ate a evidencia na borda ---
    let raw_observation_hash = hash32::from_hex(
        &required_text(fact, &["fact.evidence", "raw_observation_hash"])?,
        Some(EVIDENCE_HASH_ALGORITHM),
    )
    .map_err(|reason| SchemaError::InvalidField {
        field: "fact.evidence.raw_observation_hash".to_owned(),
        reason,
    })?;
    let transformation_steps = match at(fact, &["fact.lineage", "transformation_steps"]) {
        Some(Json::Array(steps)) => steps
            .iter()
            .map(|step| {
                step.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| SchemaError::InvalidField {
                        field: "fact.lineage.transformation_steps".to_owned(),
                        reason: format!("passo nao textual: {step}"),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(other) => {
            return Err(SchemaError::InvalidField {
                field: "fact.lineage.transformation_steps".to_owned(),
                reason: format!("esperava lista, veio {other}"),
            })
        }
        None => {
            return Err(SchemaError::MissingField(
                "fact.lineage.transformation_steps".to_owned(),
            ))
        }
    };

    let provenance = NormalizationProvenance {
        forge_source_id: context.forge_source_id.to_owned(),
        forge_lsn: context.forge_lsn,
        source_event_id: context.source_event_id.map(str::to_owned),
        raw_observation_hash,
        connector_id: connector_id.to_owned(),
        connector_version: connector_version.to_owned(),
        connector_digest: context.connector_digest,
        parser_signature: required_text(fact, &["fact.integrity", "parser_signature"])?,
        matched_rule: required_text(fact, &["fact.lineage", "matched_rule"])?,
        transformation_steps,
    };

    let event = CanonicalSecurityEvent {
        schema_version: SCHEMA_VERSION.to_owned(),
        category: declared.category.unwrap_or(mapping.primary_category),
        event_type: action.clone(),
        outcome: declared.outcome,
        severity,
        observed_at_micros,
        ingested_at_micros,
        normalized_at_micros: context.normalized_at_micros,
        tenant_id: context.tenant_id.to_owned(),
        datasource_id: context.datasource_id.to_owned(),
        sensor_id: context.sensor_id.to_owned(),
        source_sequence: context.source_sequence.map(str::to_owned),
        actor,
        target,
        source,
        // O Fato Operacional nao observa o destino. Deduzi-lo do alvo seria
        // exatamente o que o gate CM3 proibe.
        destination: None,
        extensions,
        provenance,
    };

    validate::validate(&event)?;
    validate::validate_required(&event, &mapping.required_fields)?;
    Ok(Normalized::Event(Box::new(event)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping;
    use crate::model::{Outcome, SecurityCategory};
    use crate::test_support::{sample_context, sshd_fact};

    fn sshd_mapping() -> &'static MappingSpec {
        mapping::mapping("linux-sshd/1.0.0").expect("mapping")
    }

    #[test]
    fn maps_a_real_shaped_fact_into_a_canonical_event() {
        let event = from_operational_fact(&sshd_fact(), sshd_mapping(), &sample_context())
            .expect("normaliza")
            .into_event()
            .expect("acao relevante");

        assert_eq!(event.category, SecurityCategory::Authentication);
        assert_eq!(event.event_type, "authentication.failure");
        assert_eq!(event.outcome, Some(Outcome::Failure));
        assert_eq!(event.provenance.matched_rule, "ssh_auth_failure");
        assert_eq!(
            event.actor.as_ref().and_then(|a| a.name.as_deref()),
            Some("root")
        );
        assert_eq!(
            event.source.as_ref().and_then(|s| s.address.as_deref()),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn same_fact_and_context_produce_the_same_bytes() {
        // Gate CM0.
        let first = from_operational_fact(&sshd_fact(), sshd_mapping(), &sample_context())
            .expect("normaliza");
        let second = from_operational_fact(&sshd_fact(), sshd_mapping(), &sample_context())
            .expect("normaliza");
        assert_eq!(first.digest_hex(), second.digest_hex());
    }

    #[test]
    fn destination_is_null_because_nothing_observed_it() {
        // Gate CM3.
        let event = from_operational_fact(&sshd_fact(), sshd_mapping(), &sample_context())
            .expect("normaliza")
            .into_event()
            .expect("evento");
        assert!(event.destination.is_none());
    }

    #[test]
    fn observed_at_falls_back_to_ingestion_and_says_so() {
        let event = from_operational_fact(&sshd_fact(), sshd_mapping(), &sample_context())
            .expect("normaliza")
            .into_event()
            .expect("evento");
        assert_eq!(event.observed_at_micros, event.ingested_at_micros);
        assert_eq!(
            event.extensions.get("heraclitus.observed_at_source"),
            Some(&CanonicalValue::from("ingest_fallback"))
        );
    }

    #[test]
    fn applying_another_connectors_mapping_is_refused() {
        let postgres = mapping::mapping("postgresql/1.0.0").expect("mapping");
        let error =
            from_operational_fact(&sshd_fact(), postgres, &sample_context()).expect_err("recusa");
        assert!(matches!(error, SchemaError::ConnectorMismatch { .. }));
    }

    #[test]
    fn missing_evidence_hash_is_refused() {
        let mut fact = sshd_fact();
        fact["fact.evidence"]["raw_observation_hash"] = Json::Null;
        let error =
            from_operational_fact(&fact, sshd_mapping(), &sample_context()).expect_err("recusa");
        assert!(matches!(error, SchemaError::MissingField(_)));
    }

    #[test]
    fn evidence_hash_from_another_algorithm_is_refused() {
        let mut fact = sshd_fact();
        fact["fact.evidence"]["raw_observation_hash"] =
            Json::String(format!("sha256:{}", "b".repeat(64)));
        let error =
            from_operational_fact(&fact, sshd_mapping(), &sample_context()).expect_err("recusa");
        assert!(matches!(error, SchemaError::InvalidField { .. }));
    }

    #[test]
    fn escalated_risk_raises_severity_without_changing_the_action() {
        // A janela deslizante do Behavior Engine so muda `class`/`risk_level`;
        // a acao continua `authentication.failure`. A severidade tem de subir.
        let mut fact = sshd_fact();
        fact["fact.behavior"]["class"] = Json::String("brute_force_attack".to_owned());
        fact["fact.behavior"]["risk_level"] = Json::String("Critical".to_owned());
        let event = from_operational_fact(&fact, sshd_mapping(), &sample_context())
            .expect("normaliza")
            .into_event()
            .expect("evento");
        assert_eq!(event.event_type, "authentication.failure");
        assert_eq!(event.severity, 9);
    }

    #[test]
    fn non_security_action_produces_no_event() {
        let postgres = mapping::mapping("postgresql/1.0.0").expect("mapping");
        let mut fact = sshd_fact();
        fact["fact.knowledge_version"] =
            Json::String("br.gov.heraclitus.pipelines.postgresql-v1.2.0@1.2.0".to_owned());
        fact["fact.behavior"]["action"] = Json::String("log.info".to_owned());
        let result = from_operational_fact(&fact, postgres, &sample_context()).expect("normaliza");
        assert_eq!(
            result,
            Normalized::NotSecurityRelevant {
                action: "log.info".to_owned()
            }
        );
    }

    #[test]
    fn combined_log_dash_is_not_an_actor() {
        // No log combinado, "-" e campo ausente. Um ator chamado "-" seria uma
        // identidade que a fonte nunca observou (gate CM3).
        let nginx = mapping::mapping("nginx-access/1.0.0").expect("mapping");
        let mut fact = sshd_fact();
        fact["fact.knowledge_version"] =
            Json::String("br.gov.heraclitus.pipelines.nginx_access-v1.0.0@1.0.0".to_owned());
        fact["fact.behavior"]["action"] = Json::String("data.access".to_owned());
        fact["fact.behavior"]["class"] = Json::String("session".to_owned());
        fact["fact.behavior"]["risk_level"] = Json::String("Low".to_owned());
        fact["fact.identity"]["actor.id"] = Json::String("-".to_owned());
        fact["fact.identity"]["actor.name"] = Json::String("-".to_owned());
        fact["fact.identity"]["target.id"] = Json::String("/admin".to_owned());

        let event = from_operational_fact(&fact, nginx, &sample_context())
            .expect("normaliza")
            .into_event()
            .expect("evento");
        assert!(event.actor.is_none(), "o ator nao foi observado");
        assert_eq!(
            event.target.as_ref().and_then(|t| t.id.as_deref()),
            Some("/admin")
        );
        assert_eq!(event.category, SecurityCategory::Http);
    }

    #[test]
    fn legacy_fact_without_knowledge_version_is_refused() {
        let mut fact = sshd_fact();
        fact["fact.knowledge_version"] = Json::Null;
        let error =
            from_operational_fact(&fact, sshd_mapping(), &sample_context()).expect_err("recusa");
        assert_eq!(
            error,
            SchemaError::MissingField("fact.knowledge_version".to_owned())
        );
    }
}
