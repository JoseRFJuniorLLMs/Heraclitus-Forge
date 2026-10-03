//! Snapshot verificado compartilhado por `export_facts` e pela bridge Rust.
//!
//! O HDB2 continua a ser a caixa-preta de borda. Antes de qualquer byte sair
//! da máquina, copiamos dados + sidecars públicos para uma fotografia privada,
//! verificamos CRC-32C, cadeia BLAKE3 e âncora Ed25519, e só então iteramos os
//! registos. Assim o caminho online e o exportador offline usam exatamente a
//! mesma fronteira de confiança.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

use crate::db::{self, ExportStats, ExportedRecord};

pub const BRIDGE_CONTRACT_VERSION: &str = "forge-heraclitusdb/2";
pub const FACT_SCHEMA_VERSION: &str = "operational-fact/1.0";
pub const DESTINATION_API_VERSION: &str = "heraclitus.v1";

/// Fotografia privada e criptograficamente verificada de um HDB2.
///
/// O `TempDir` é mantido vivo pelo struct; ao cair, a fotografia desaparece.
pub struct VerifiedSnapshot {
    _dir: tempfile::TempDir,
    path: String,
    attestation: Value,
    source_id: String,
}

impl VerifiedSnapshot {
    pub fn open(db_path: impl AsRef<Path>) -> io::Result<Self> {
        let db_path = db_path.as_ref();
        let dir = tempfile::tempdir()?;
        let snapshot_path = dir.path().join("source.hdb");
        let snapshot = snapshot_path.to_string_lossy().to_string();

        for ext in ["", ".anchor", ".pub"] {
            let src = format!("{}{}", db_path.to_string_lossy(), ext);
            let dst = format!("{snapshot}{ext}");
            fs::copy(&src, &dst).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("sidecar obrigatório ausente/ilegível {src}: {error}"),
                )
            })?;
        }

        let verified = db::verify_file(&snapshot);
        if verified.status != "INTEG_OK" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "snapshot HDB2 recusado: status={} facts={} {}",
                    verified.status, verified.facts, verified.message
                ),
            ));
        }

        let public_key = fs::read_to_string(format!("{snapshot}.pub"))?
            .trim()
            .to_string();
        if public_key.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chave pública Ed25519 do snapshot tem comprimento inválido",
            ));
        }

        let anchor_signature = fs::read_to_string(format!("{snapshot}.anchor"))?
            .lines()
            .find_map(|line| line.trim().strip_prefix("sig=").map(str::to_owned))
            .unwrap_or_default();
        if anchor_signature.len() != 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "assinatura Ed25519 da âncora ausente ou inválida",
            ));
        }

        let source_id = blake3::hash(public_key.as_bytes()).to_hex().to_string();
        let attestation = json!({
            "status": "INTEG_OK",
            "bridge_contract": BRIDGE_CONTRACT_VERSION,
            "fact_schema": FACT_SCHEMA_VERSION,
            "destination_api": DESTINATION_API_VERSION,
            "verified_root": verified.root,
            "verified_facts": verified.facts,
            "source_id": source_id,
            "public_key": public_key,
            "anchor_signature": anchor_signature,
            "algorithm": "ed25519+blake3+crc32c"
        });

        Ok(Self {
            _dir: dir,
            path: snapshot,
            source_id: attestation["source_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            attestation,
        })
    }

    pub fn attestation(&self) -> &Value {
        &self.attestation
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn verified_root(&self) -> &str {
        self.attestation["verified_root"]
            .as_str()
            .unwrap_or_default()
    }

    /// Itera os registos em streaming, limitando a quantidade entregue ao
    /// callback. A verificação criptográfica já aconteceu em `open`.
    pub fn export_records<F>(
        &self,
        from_lsn: u64,
        limit: Option<u64>,
        mut consume: F,
    ) -> io::Result<ExportStats>
    where
        F: FnMut(u64, ExportedRecord) -> bool,
    {
        let limit = limit.unwrap_or(u64::MAX);
        if limit == 0 {
            return Ok(ExportStats::default());
        }
        let mut emitted = 0u64;
        db::export_records(&self.path, from_lsn, |lsn, record| {
            emitted += 1;
            let keep_going = consume(lsn, record);
            keep_going && emitted < limit
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FactStore;
    use serde_json::json;

    #[test]
    fn snapshot_verified_reads_the_same_fact_and_attests_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge.hdb");
        let mut store = FactStore::new(path.to_str().unwrap()).unwrap();
        let mut fact = json!({
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
            "fact.time": {"system_timestamp": 1_782_467_794_979_937i64},
            "fact.behavior": {
                "class": "authentication",
                "action": "authentication.failure",
                "risk_level": "High"
            },
            "fact.evidence": {
                "raw_observation_hash": "b3:9611cd00aabbccddeeff00112233445566778899aabbccddeeff001122334455"
            },
            "fact.lineage": {
                "input_source": "postgresql",
                "matched_rule": "R_AUTH_FAIL_CORE"
            },
            "fact.confidence": 0.99,
            "fact.knowledge_version": "postgresql@1.2.0",
            "fact.reasoning_version": "r1",
            "fact.ontology_version": "v1"
        });
        store.write_fact(&mut fact).unwrap();

        let snapshot = VerifiedSnapshot::open(&path).unwrap();
        assert_eq!(snapshot.attestation()["status"], "INTEG_OK");
        assert_eq!(snapshot.source_id().len(), 64);
        assert!(!snapshot.verified_root().is_empty());

        let mut seen = Vec::new();
        let stats = snapshot
            .export_records(0, None, |lsn, record| {
                seen.push((lsn, record.record_type().to_owned()));
                true
            })
            .unwrap();
        assert_eq!(stats.exported, 1);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, "OperationalFact");
    }
}
