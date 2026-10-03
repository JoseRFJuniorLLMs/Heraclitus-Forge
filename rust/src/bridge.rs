//! Runtime da ponte Forge -> HeraclitusDB.
//!
//! Esta unidade contém a semântica que antes vivia apenas em `bridge.py`:
//! mapeamento do Operational Fact, pseudonimização HMAC, validação fail-closed,
//! chave idempotente e checkpoint durável. O binário `bridge` acrescenta o
//! transporte gRPC assíncrono e o modo contínuo.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::export::{BRIDGE_CONTRACT_VERSION, DESTINATION_API_VERSION, FACT_SCHEMA_VERSION};

pub const SECURITY_SCHEMA_VERSION: &str = "heraclitus-security-event/1.0";
pub const TELEMETRY_SCHEMA_VERSION: &str = "heraclitus-telemetry-health/1.0";
pub const TELEMETRY_KIND: &str = "TelemetryHealth";
pub const TELEMETRY_AGENT_ID: &str = "heraclitus-forge";
pub const KIND: &str = "OperationalFact";
pub const PRODUCER: &str = "heraclitus-forge";
pub const SUBJECT_PREFIX: &str = "titular:hmac-sha256:";
pub const SESSION_PREFIX: &str = "forge-session:hmac-sha256:";
pub const NO_SUBJECT: &str = "sistema:sem-titular";

const SECURITY_CATEGORIES: &[&str] = &[
    "authentication",
    "network",
    "dns",
    "http",
    "process",
    "file",
    "registry",
    "endpoint",
    "cloud",
    "identity",
    "threat_intel",
    "vulnerability",
    "email",
    "data_access",
    "privilege",
    "alert",
    "finding",
    "incident",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    pub kind: String,
    pub content: String,
    pub agent_id: String,
    pub session_id: String,
    pub attrs: HashMap<String, String>,
    pub parents: Vec<String>,
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.as_object()?.get(*key)?;
    }
    Some(current)
}

fn value_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(v) => Some(v.to_string()),
        Value::Number(v) => Some(v.to_string()),
        other => Some(other.to_string()),
    }
}

fn text_at(value: &Value, path: &[&str]) -> Option<String> {
    value_text(at(value, path))
}

fn insert_attr(attrs: &mut HashMap<String, String>, key: &str, value: Option<&Value>) {
    if let Some(value) = value_text(value) {
        attrs.insert(key.to_string(), value);
    }
}

fn insert_owned(attrs: &mut HashMap<String, String>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() {
        attrs.insert(key.to_string(), value);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// HMAC-SHA-256 sem dependência extra: RFC 2104 sobre o `sha2` que o runtime
/// já usa. Mantém byte-a-byte a mesma derivação da antiga bridge Python.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        normalized[..32].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= normalized[index];
        opad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

pub fn subject_of(fact: &Value, secret: &[u8]) -> String {
    let actor = text_at(fact, &["fact.identity", "actor.id"]);
    match actor.as_deref() {
        None | Some("") | Some("unknown") => NO_SUBJECT.to_string(),
        Some(actor) => format!(
            "{SUBJECT_PREFIX}{}",
            hex_lower(&hmac_sha256(secret, actor.as_bytes()))
        ),
    }
}

pub fn session_of(fact: &Value, secret: &[u8]) -> String {
    let version = text_at(fact, &["fact.knowledge_version"]).unwrap_or_default();
    let mut message = b"session\0".to_vec();
    message.extend_from_slice(version.as_bytes());
    format!(
        "{SESSION_PREFIX}{}",
        hex_lower(&hmac_sha256(secret, &message))
    )
}

pub fn render_content(fact: &Value) -> String {
    let actor =
        text_at(fact, &["fact.identity", "actor.name"]).unwrap_or_else(|| "unknown".to_string());
    let target =
        text_at(fact, &["fact.identity", "target.id"]).unwrap_or_else(|| "unknown".to_string());
    let action =
        text_at(fact, &["fact.behavior", "action"]).unwrap_or_else(|| "unknown".to_string());
    let source = text_at(fact, &["fact.identity", "source.ip"]);
    match source {
        Some(source) => format!("{actor} executed {action} on {target} from {source}"),
        None => format!("{actor} executed {action} on {target}"),
    }
}

pub fn map_fact(lsn: u64, fact: &Value, attestation: &Value, secret: &[u8]) -> Episode {
    let mut attrs = HashMap::new();

    for (key, path) in [
        ("tenant_id", &["fact.datasource", "tenant_id"][..]),
        ("datasource_id", &["fact.datasource", "datasource_id"][..]),
        ("sensor_id", &["fact.datasource", "sensor_id"][..]),
        ("actor_id", &["fact.identity", "actor.id"][..]),
        ("actor_name", &["fact.identity", "actor.name"][..]),
        ("target_id", &["fact.identity", "target.id"][..]),
        ("source_ip", &["fact.identity", "source.ip"][..]),
        ("action", &["fact.behavior", "action"][..]),
        ("action_class", &["fact.behavior", "class"][..]),
        ("risk_level", &["fact.behavior", "risk_level"][..]),
        ("system_timestamp", &["fact.time", "system_timestamp"][..]),
        (
            "evidence_hash",
            &["fact.evidence", "raw_observation_hash"][..],
        ),
        (
            "carimbo_tempo_legal",
            &["fact.evidence", "carimbo_tempo_legal"][..],
        ),
        ("leaf_hash", &["fact.integrity", "leaf_hash"][..]),
        (
            "merkle_root_anchor",
            &["fact.integrity", "merkle_root_anchor"][..],
        ),
        ("integrity_signature", &["fact.integrity", "signature"][..]),
        (
            "parser_signature",
            &["fact.integrity", "parser_signature"][..],
        ),
        ("matched_rule", &["fact.lineage", "matched_rule"][..]),
        ("input_source", &["fact.lineage", "input_source"][..]),
    ] {
        insert_attr(&mut attrs, key, at(fact, path));
    }

    for key in [
        "fact_id",
        "fact.confidence",
        "fact.knowledge_version",
        "fact.ontology_version",
        "fact.reasoning_version",
    ] {
        let attr = match key {
            "fact_id" => "fact_id",
            "fact.confidence" => "confidence",
            "fact.knowledge_version" => "knowledge_version",
            "fact.ontology_version" => "ontology_version",
            "fact.reasoning_version" => "reasoning_version",
            _ => key,
        };
        insert_attr(&mut attrs, attr, at(fact, &[key]));
    }

    insert_owned(&mut attrs, "producer", PRODUCER);
    insert_owned(&mut attrs, "forge_lsn", lsn.to_string());
    insert_owned(&mut attrs, "generated_by", "heraclitus_forge_bridge_rust");
    insert_owned(&mut attrs, "schema_version", FACT_SCHEMA_VERSION);

    insert_attr(
        &mut attrs,
        "forge_verified_root",
        at(attestation, &["verified_root"]),
    );
    insert_attr(
        &mut attrs,
        "forge_source_id",
        at(attestation, &["source_id"]),
    );
    insert_attr(
        &mut attrs,
        "forge_public_key",
        at(attestation, &["public_key"]),
    );
    insert_attr(
        &mut attrs,
        "forge_anchor_signature",
        at(attestation, &["anchor_signature"]),
    );
    insert_attr(
        &mut attrs,
        "forge_integrity_algorithm",
        at(attestation, &["algorithm"]),
    );
    insert_owned(
        &mut attrs,
        "forge_integrity_verified",
        (attestation["status"] == "INTEG_OK").to_string(),
    );

    if let Some(security) = fact.get("fact.security").and_then(Value::as_object) {
        for (attr, key) in [
            ("security_schema", "schema_version"),
            ("security_category", "category"),
            ("security_event_type", "event_type"),
            ("security_outcome", "outcome"),
            ("security_severity", "severity"),
            ("security_tenant_id", "tenant_id"),
            ("security_datasource_id", "datasource_id"),
            ("security_sensor_id", "sensor_id"),
            ("security_observed_at", "observed_at_micros"),
            ("security_source_sequence", "source_sequence"),
        ] {
            insert_attr(&mut attrs, attr, security.get(key));
        }
        if let Some(provenance) = security.get("provenance").and_then(Value::as_object) {
            insert_attr(
                &mut attrs,
                "security_connector_digest",
                provenance.get("connector_digest"),
            );
        }
    }

    Episode {
        kind: KIND.to_string(),
        content: render_content(fact),
        agent_id: subject_of(fact, secret),
        session_id: session_of(fact, secret),
        attrs,
        parents: Vec::new(),
    }
}

fn positive_integer(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(number)) => {
            number.as_u64().is_some_and(|v| v > 0) || number.as_i64().is_some_and(|v| v > 0)
        }
        _ => false,
    }
}

pub fn validate_security(fact: &Value) -> Vec<String> {
    let Some(security) = fact.get("fact.security") else {
        return Vec::new();
    };
    let Some(security) = security.as_object() else {
        return vec!["fact.security presente mas não é um objeto".to_string()];
    };

    let mut errors = Vec::new();
    if security.get("schema_version").and_then(Value::as_str) != Some(SECURITY_SCHEMA_VERSION) {
        errors.push("schema canónico incompatível".to_string());
    }
    let category = security.get("category").and_then(Value::as_str);
    if !category.is_some_and(|value| SECURITY_CATEGORIES.contains(&value)) {
        errors.push(format!("categoria fora do vocabulário v1: {category:?}"));
    }
    if security
        .get("event_type")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        errors.push("fact.security.event_type ausente".to_string());
    }
    if let Some(outcome) = security.get("outcome").filter(|v| !v.is_null()) {
        let valid = matches!(outcome.as_str(), Some("success" | "failure"));
        if !valid {
            errors.push("fact.security.outcome inválido".to_string());
        }
    }
    match security.get("severity").and_then(Value::as_i64) {
        Some(0..=10) => {}
        _ => errors.push("fact.security.severity fora da escala 0..10".to_string()),
    }
    for field in ["tenant_id", "datasource_id", "sensor_id"] {
        if security
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            errors.push(format!("fact.security.{field} ausente"));
        }
    }
    for field in [
        "observed_at_micros",
        "ingested_at_micros",
        "normalized_at_micros",
    ] {
        if !positive_integer(security.get(field)) {
            errors.push(format!("fact.security.{field} não é um instante válido"));
        }
    }

    let Some(provenance) = security.get("provenance").and_then(Value::as_object) else {
        errors.push("fact.security.provenance ausente".to_string());
        return errors;
    };
    for field in [
        "forge_source_id",
        "connector_id",
        "connector_version",
        "connector_digest",
        "raw_observation_hash",
        "matched_rule",
    ] {
        if provenance
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            errors.push(format!("fact.security.provenance.{field} ausente"));
        }
    }

    if let Some(evidence) = text_at(fact, &["fact.evidence", "raw_observation_hash"]) {
        if let Some(stripped) = evidence.strip_prefix("b3:") {
            if provenance
                .get("raw_observation_hash")
                .and_then(Value::as_str)
                != Some(stripped)
            {
                errors.push("evento canónico aponta para outra observação".to_string());
            }
        }
    }
    if let Some(rule) = text_at(fact, &["fact.lineage", "matched_rule"]) {
        if provenance.get("matched_rule").and_then(Value::as_str) != Some(rule.as_str()) {
            errors.push("evento canónico aponta para outra regra".to_string());
        }
    }
    if let Some(knowledge) = text_at(fact, &["fact.knowledge_version"]) {
        if let Some((connector, version)) = knowledge.split_once('@') {
            if provenance.get("connector_id").and_then(Value::as_str) != Some(connector) {
                errors.push("evento canónico atribuído a outro conector".to_string());
            }
            if provenance.get("connector_version").and_then(Value::as_str) != Some(version) {
                errors.push("evento canónico atribuído a outra versão".to_string());
            }
        }
    }
    errors
}

pub fn validate_fact(lsn: u64, fact: &Value, attestation: &Value) -> Vec<String> {
    let required = [
        ("fact_id", at(fact, &["fact_id"])),
        (
            "fact.datasource.tenant_id",
            at(fact, &["fact.datasource", "tenant_id"]),
        ),
        (
            "fact.datasource.datasource_id",
            at(fact, &["fact.datasource", "datasource_id"]),
        ),
        (
            "fact.datasource.sensor_id",
            at(fact, &["fact.datasource", "sensor_id"]),
        ),
        (
            "fact.time.system_timestamp",
            at(fact, &["fact.time", "system_timestamp"]),
        ),
        (
            "fact.behavior.action",
            at(fact, &["fact.behavior", "action"]),
        ),
        ("fact.behavior.class", at(fact, &["fact.behavior", "class"])),
        (
            "fact.evidence.raw_observation_hash",
            at(fact, &["fact.evidence", "raw_observation_hash"]),
        ),
        (
            "fact.integrity.leaf_hash",
            at(fact, &["fact.integrity", "leaf_hash"]),
        ),
        (
            "fact.integrity.merkle_root_anchor",
            at(fact, &["fact.integrity", "merkle_root_anchor"]),
        ),
        (
            "fact.knowledge_version",
            at(fact, &["fact.knowledge_version"]),
        ),
    ];
    let mut errors = required
        .into_iter()
        .filter(|(_, value)| value_text(*value).is_none())
        .map(|(name, _)| format!("{name} ausente"))
        .collect::<Vec<_>>();

    if attestation["status"] != "INTEG_OK" {
        errors.push("snapshot Forge não possui atestação INTEG_OK".to_string());
    }
    if attestation["bridge_contract"].as_str() != Some(BRIDGE_CONTRACT_VERSION) {
        errors.push("contrato da ponte incompatível".to_string());
    }
    if attestation["fact_schema"].as_str() != Some(FACT_SCHEMA_VERSION) {
        errors.push("schema do Fato incompatível".to_string());
    }
    if attestation["destination_api"].as_str() != Some(DESTINATION_API_VERSION) {
        errors.push("API de destino incompatível".to_string());
    }
    if attestation["public_key"].as_str().map_or(0, str::len) != 64 {
        errors.push("chave pública Ed25519 inválida".to_string());
    }
    if attestation["anchor_signature"].as_str().map_or(0, str::len) != 128 {
        errors.push("assinatura Ed25519 da âncora inválida".to_string());
    }
    if attestation["source_id"]
        .as_str()
        .is_none_or(|value| value.is_empty())
        || attestation["verified_root"]
            .as_str()
            .is_none_or(|value| value.is_empty())
    {
        errors.push("identidade/raiz verificadas da origem ausentes".to_string());
    }
    errors.extend(validate_security(fact));
    errors
        .into_iter()
        .map(|error| format!("LSN {lsn}: {error}"))
        .collect()
}

pub fn map_telemetry(
    lsn: u64,
    identity: &crate::hfb2::SecurityIdentity,
    envelope: &str,
) -> Result<Episode, String> {
    let parsed: Value =
        serde_json::from_str(envelope).map_err(|error| format!("telemetria JSON: {error}"))?;
    let event_type = parsed
        .get("event")
        .and_then(|event| event.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let mut attrs = HashMap::new();
    insert_owned(&mut attrs, "telemetry.schema", TELEMETRY_SCHEMA_VERSION);
    insert_owned(&mut attrs, "telemetry.event_type", event_type);
    insert_owned(&mut attrs, "tenant_id", identity.tenant_id.clone());
    insert_owned(&mut attrs, "datasource_id", identity.datasource_id.clone());
    insert_owned(&mut attrs, "sensor_id", identity.sensor_id.clone());
    insert_owned(&mut attrs, "producer", PRODUCER);
    insert_owned(&mut attrs, "forge_lsn", lsn.to_string());
    insert_owned(&mut attrs, "generated_by", "heraclitus_forge_bridge_rust");

    Ok(Episode {
        kind: TELEMETRY_KIND.to_string(),
        content: envelope.to_string(),
        agent_id: TELEMETRY_AGENT_ID.to_string(),
        session_id: identity.datasource_id.clone(),
        attrs,
        parents: Vec::new(),
    })
}

pub fn validate_telemetry(
    lsn: u64,
    identity: &crate::hfb2::SecurityIdentity,
    envelope: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, value) in [
        ("tenant_id", identity.tenant_id.as_str()),
        ("datasource_id", identity.datasource_id.as_str()),
        ("sensor_id", identity.sensor_id.as_str()),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{name} ausente"));
        }
    }

    match serde_json::from_str::<Value>(envelope) {
        Ok(parsed) => {
            if parsed["schema"].as_str() != Some(TELEMETRY_SCHEMA_VERSION) {
                errors.push("schema de telemetria incompatível".to_string());
            }
            if parsed
                .get("event")
                .and_then(|event| event.get("type"))
                .and_then(Value::as_str)
                .is_none_or(|value| value.is_empty())
            {
                errors.push("envelope sem tipo de evento".to_string());
            }
            let expected = serde_json::json!({
                "tenant_id": identity.tenant_id,
                "datasource_id": identity.datasource_id,
                "sensor_id": identity.sensor_id
            });
            if parsed.get("identity") != Some(&expected) {
                errors.push("identidade do envelope diverge da autenticada".to_string());
            }
        }
        Err(error) => errors.push(format!("envelope de telemetria ilegível: {error}")),
    }

    errors
        .into_iter()
        .map(|error| format!("LSN {lsn}: {error}"))
        .collect()
}

pub fn source_event_identity(lsn: u64, fact: &Value, attestation: &Value) -> (String, String) {
    let source = attestation["source_id"].as_str().unwrap_or_default();
    let fact_id = fact["fact_id"].as_str().unwrap_or_default();
    let identity = format!("forge:{source}:{lsn}:{fact_id}");
    let digest = Sha256::digest(identity.as_bytes());
    (identity, hex_lower(&digest))
}

pub fn telemetry_event_identity(lsn: u64, attestation: &Value) -> (String, String) {
    let source = attestation["source_id"].as_str().unwrap_or_default();
    let identity = format!("forge-telemetry:{source}:{lsn}");
    let digest = Sha256::digest(identity.as_bytes());
    (identity, hex_lower(&digest))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceState {
    #[serde(default)]
    pub last_lsn: u64,
    #[serde(default)]
    pub total_appended: u64,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub last_event_id: String,
    #[serde(default)]
    pub source_id: String,
}

pub type BridgeState = BTreeMap<String, SourceState>;

pub fn state_key(hdb: &Path) -> String {
    fs::canonicalize(hdb)
        .unwrap_or_else(|_| hdb.to_path_buf())
        .to_string_lossy()
        .to_string()
}

pub fn load_state(path: &Path) -> io::Result<BridgeState> {
    if !path.exists() {
        return Ok(BridgeState::new());
    }
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("estado de retoma ilegível em {}: {error}", path.display()),
        )
    })
}

pub fn save_state(
    path: &Path,
    hdb: &Path,
    last_lsn: u64,
    appended: u64,
    last_event_id: &str,
    source_id: &str,
) -> io::Result<()> {
    let mut state = load_state(path)?;
    let key = state_key(hdb);
    let previous = state.get(&key).cloned().unwrap_or_default();
    let updated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.insert(
        key,
        SourceState {
            last_lsn,
            total_appended: previous.total_appended.saturating_add(appended),
            updated: format!("unix:{updated}"),
            last_event_id: if last_event_id.is_empty() {
                previous.last_event_id
            } else {
                last_event_id.to_string()
            },
            source_id: if source_id.is_empty() {
                previous.source_id
            } else {
                source_id.to_string()
            },
        },
    );

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("bridge_state"),
        std::process::id()
    ));
    let raw = serde_json::to_vec_pretty(&state)?;
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&raw)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Lock de processo cross-platform. Ao contrário de um ficheiro sentinela,
/// locks do SO são libertados automaticamente quando o processo morre.
pub struct StateLock {
    file: File,
    _path: PathBuf,
}

impl StateLock {
    pub fn acquire(state_path: &Path, timeout: Duration) -> io::Result<Self> {
        let lock_path = state_path.with_extension(format!(
            "{}lock",
            state_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!("{ext}."))
                .unwrap_or_default()
        ));
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        let deadline = Instant::now() + timeout;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    return Ok(Self {
                        file,
                        _path: lock_path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            format!(
                                "outra bridge mantém o lock há mais de {}s",
                                timeout.as_secs()
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fact() -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.datasource": {
                "tenant_id": "gov.br/orgao-a",
                "datasource_id": "postgresql://db-01/postgresql.log",
                "sensor_id": "forge-edge-01"
            },
            "fact.identity": {
                "actor.id": "admin",
                "actor.name": "admin",
                "target.id": "postgresql",
                "source.ip": "187.65.12.99"
            },
            "fact.time": {"system_timestamp": 1782467794979937u64},
            "fact.behavior": {
                "class": "authentication",
                "action": "authentication.failure",
                "risk_level": "High"
            },
            "fact.evidence": {
                "raw_observation_hash": "b3:9611cd00aabbccddeeff00112233445566778899aabbccddeeff001122334455"
            },
            "fact.integrity": {
                "leaf_hash": "aa",
                "merkle_root_anchor": "bb"
            },
            "fact.lineage": {
                "input_source": "postgresql",
                "matched_rule": "R_AUTH_FAIL_CORE"
            },
            "fact.confidence": 0.99,
            "fact.knowledge_version": "postgresql@1.2.0",
            "fact.reasoning_version": "r1",
            "fact.ontology_version": "v1"
        })
    }

    fn attestation() -> Value {
        json!({
            "status": "INTEG_OK",
            "bridge_contract": BRIDGE_CONTRACT_VERSION,
            "fact_schema": FACT_SCHEMA_VERSION,
            "destination_api": DESTINATION_API_VERSION,
            "verified_root": "cc",
            "source_id": "dd",
            "public_key": "11".repeat(32),
            "anchor_signature": "22".repeat(64),
            "algorithm": "ed25519+blake3+crc32c"
        })
    }

    #[test]
    fn rust_mapping_preserves_privacy_and_custody_fields() {
        let fact = fact();
        let secret = [7u8; 32];
        let episode = map_fact(42, &fact, &attestation(), &secret);
        assert_eq!(episode.kind, KIND);
        assert_eq!(
            episode.content,
            "admin executed authentication.failure on postgresql from 187.65.12.99"
        );
        assert!(episode.agent_id.starts_with(SUBJECT_PREFIX));
        assert!(!episode.agent_id.contains("admin"));
        assert_eq!(episode.attrs["forge_lsn"], "42");
        assert_eq!(episode.attrs["leaf_hash"], "aa");
        assert_eq!(episode.attrs["producer"], PRODUCER);
    }

    #[test]
    fn idempotency_key_is_stable_and_ascii() {
        let fact = fact();
        let attestation = attestation();
        let first = source_event_identity(42, &fact, &attestation);
        let second = source_event_identity(42, &fact, &attestation);
        assert_eq!(first, second);
        assert_eq!(first.1.len(), 64);
        assert!(first.1.is_ascii());
    }

    #[test]
    fn state_is_compatible_with_the_old_python_shape() {
        let dir = tempfile::tempdir().unwrap();
        let hdb = dir.path().join("edge.hdb");
        fs::write(&hdb, b"x").unwrap();
        let state = dir.path().join(".bridge_state.json");
        save_state(&state, &hdb, 42, 1, "01EVENT", "source").unwrap();
        let loaded = load_state(&state).unwrap();
        let source = &loaded[&state_key(&hdb)];
        assert_eq!(source.last_lsn, 42);
        assert_eq!(source.total_appended, 1);
        assert_eq!(source.last_event_id, "01EVENT");
        assert_eq!(source.source_id, "source");
    }
}
