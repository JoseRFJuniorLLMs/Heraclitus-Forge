//! Instancias de referencia partilhadas pelos testes do crate e pelo teste de
//! paridade com o `.proto`.
//!
//! Fazem parte da API publica de proposito: o `sample_event()` e a UNICA
//! instancia com todos os campos preenchidos, e e contra ela que a paridade
//! entre Rust, JSON e protobuf e verificada. Se um campo novo aparecer no
//! modelo e nao aqui, o teste de paridade cai.

use std::collections::BTreeMap;

use serde_json::json;
use serde_json::Value as Json;

use crate::model::{
    CanonicalSecurityEvent, CanonicalValue, EndpointRef, EntityKind, EntityRef,
    NormalizationProvenance, Outcome, SecurityCategory, SCHEMA_VERSION,
};
use crate::normalize::NormalizationContext;

/// Instante fixo (2026-06-26T01:20:05Z) — nada aqui le o relogio.
pub const OBSERVED_AT_MICROS: i64 = 1_782_782_405_000_000;

/// Identidade da origem `.hdb` — BLAKE3 da chave publica da ancora, 64 hex.
pub const FORGE_SOURCE_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn sample_digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// Contexto determinista para os testes de normalizacao.
pub fn sample_context() -> NormalizationContext<'static> {
    NormalizationContext {
        tenant_id: "tenant-demo",
        datasource_id: "sshd://bastion-01/var/log/auth.log",
        sensor_id: "forge-edge-01",
        source_sequence: Some("4210"),
        normalized_at_micros: OBSERVED_AT_MICROS + 1_000,
        forge_source_id: FORGE_SOURCE_ID,
        forge_lsn: 42,
        source_event_id: Some("auth.log:4210"),
        connector_digest: sample_digest(0x11),
    }
}

/// Fato Operacional com a forma exata que o `ReconstitutiveRunner` emite para
/// uma falha de autenticacao do OpenSSH.
pub fn sshd_fact() -> Json {
    json!({
        "fact_id": "019f2c1e-0000-7000-8000-000000000001",
        "fact.identity": {
            "actor.id": "root",
            "actor.name": "root",
            "target.id": "bastion-01",
            "source.ip": "203.0.113.7"
        },
        "fact.time": { "system_timestamp": OBSERVED_AT_MICROS, "log_sequence_number": 0 },
        "fact.behavior": {
            "class": "credential_attack",
            "action": "authentication.failure",
            "risk_level": "High"
        },
        "fact.evidence": {
            "raw_observation_hash": format!("b3:{}", "c".repeat(64)),
            "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo"
        },
        "fact.integrity": { "parser_signature": "format=hcx-v3\nalg=ed25519" },
        "fact.lineage": {
            "transformation_steps": ["parse", "normalize", "behavior", "emit"],
            "input_source": "br.gov.heraclitus.pipelines.linux_sshd-v1.1.0",
            "matched_rule": "ssh_auth_failure"
        },
        "fact.confidence": 0.972,
        "fact.knowledge_version": "br.gov.heraclitus.pipelines.linux_sshd-v1.1.0@1.1.0",
        "fact.reasoning_version": "reasoner-core-v6.0",
        "fact.ontology_version": "v9"
    })
}

/// Evento canonico com TODOS os campos preenchidos, incluindo os opcionais.
pub fn sample_event() -> CanonicalSecurityEvent {
    let mut extensions = BTreeMap::new();
    extensions.insert(
        "heraclitus.observed_at_source".to_owned(),
        CanonicalValue::from("ingest_fallback"),
    );
    extensions.insert(
        "heraclitus.behavior_class".to_owned(),
        CanonicalValue::from("credential_attack"),
    );
    extensions.insert(
        "heraclitus.risk_level".to_owned(),
        CanonicalValue::from("High"),
    );
    extensions.insert(
        "heraclitus.confidence_permille".to_owned(),
        CanonicalValue::Int(972),
    );

    CanonicalSecurityEvent {
        schema_version: SCHEMA_VERSION.to_owned(),
        category: SecurityCategory::Authentication,
        event_type: "authentication.failure".to_owned(),
        outcome: Some(Outcome::Failure),
        severity: 7,
        observed_at_micros: OBSERVED_AT_MICROS,
        ingested_at_micros: OBSERVED_AT_MICROS,
        normalized_at_micros: OBSERVED_AT_MICROS + 1_000,
        tenant_id: "tenant-demo".to_owned(),
        datasource_id: "sshd://bastion-01/var/log/auth.log".to_owned(),
        sensor_id: "forge-edge-01".to_owned(),
        source_sequence: Some("4210".to_owned()),
        actor: Some(EntityRef {
            kind: EntityKind::User,
            id: Some("root".to_owned()),
            name: Some("root".to_owned()),
            domain: Some("bastion-01".to_owned()),
        }),
        target: Some(EntityRef {
            kind: EntityKind::Host,
            id: Some("bastion-01".to_owned()),
            name: Some("bastion-01".to_owned()),
            domain: Some("gov.br".to_owned()),
        }),
        source: Some(EndpointRef {
            address: Some("203.0.113.7".to_owned()),
            port: Some(52_344),
            hostname: Some("unknown.example".to_owned()),
        }),
        destination: Some(EndpointRef {
            address: Some("198.51.100.4".to_owned()),
            port: Some(22),
            hostname: Some("bastion-01".to_owned()),
        }),
        extensions,
        provenance: NormalizationProvenance {
            forge_source_id: FORGE_SOURCE_ID.to_owned(),
            forge_lsn: 42,
            source_event_id: Some("auth.log:4210".to_owned()),
            raw_observation_hash: sample_digest(0xcc),
            connector_id: "br.gov.heraclitus.pipelines.linux_sshd-v1.1.0".to_owned(),
            connector_version: "1.1.0".to_owned(),
            connector_digest: sample_digest(0x11),
            parser_signature: "format=hcx-v3".to_owned(),
            matched_rule: "ssh_auth_failure".to_owned(),
            transformation_steps: vec![
                "parse".to_owned(),
                "normalize".to_owned(),
                "behavior".to_owned(),
                "emit".to_owned(),
            ],
        },
    }
}
