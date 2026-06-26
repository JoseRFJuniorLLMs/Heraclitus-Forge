//! Primitivas compartilhadas do Fato Operacional.

use std::time::{SystemTime, UNIX_EPOCH};

/// Epoch UNIX em microssegundos (UTC) — `fact.time.system_timestamp`.
pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// `fact.id` — UUIDv7 (time-ordered).
pub fn uuid7() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Hash bruto BLAKE3 (32 bytes) da observacao de origem (spec secoes 2 e 8).
pub fn evidence_hash(raw: &str) -> String {
    format!("b3:{}", blake3::hash(raw.as_bytes()).to_hex())
}
