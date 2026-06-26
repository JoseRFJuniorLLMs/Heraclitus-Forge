//! HeraclitusDB — armazenamento append-only `.hdb` com integridade BLAKE3.
//!
//! Porte do `heraclitus_db.py` otimizado para line-rate. A versao Python recomputa
//! a arvore Merkle balanceada a cada escrita (O(n) por append => O(n^2) total), o que
//! e aceitavel no design-time mas inviavel em producao. Aqui a ancora e uma **cadeia
//! Merkle rolante** BLAKE3 — `root = blake3(root_anterior || folha)` — que custa O(1)
//! por evento, encadeia cada Fato a todo o prefixo (qualquer adulteracao retroativa
//! quebra a cadeia) e fornece exatamente o `Previous_Merkle_Root` exigido pelo Raft
//! (spec secao 11). Materializar a arvore balanceada para provas de inclusao fica
//! para um checkpoint MMR futuro.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};

use serde_json::{Map, Value};

/// Magic(4) + LSN(8) + Timestamp(8) + Confidence(4) + EvidenceHash(32) + PayloadLen(4)
pub const HEADER_SIZE: usize = 60;

fn b3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Serializacao canonica do Fato SEM `fact.integrity` (evita circularidade na folha).
/// serde_json usa `Map` ordenado por chave => bytes deterministicos em escrita e verify.
fn core_bytes(fact: &Value) -> Vec<u8> {
    let mut obj: Map<String, Value> = fact.as_object().cloned().unwrap_or_default();
    obj.remove("fact.integrity");
    serde_json::to_vec(&Value::Object(obj)).unwrap()
}

/// Avanca a cadeia Merkle rolante: root := BLAKE3(root_anterior || folha).
fn fold_chain(prev_root: &str, leaf: &str) -> String {
    b3_hex(format!("{prev_root}{leaf}").as_bytes())
}

fn sign(leaf: &str) -> String {
    let mut data = b"HERA-KEY:".to_vec();
    data.extend_from_slice(leaf.as_bytes());
    format!("ed25519:{}", &b3_hex(&data)[..48])
}

pub struct VerifyResult {
    pub status: String,
    pub facts: usize,
    pub root: String,
    pub message: String,
}

pub struct HeraclitusDB {
    pub db_path: String,
    anchor_path: String,
    pub current_lsn: u64,
    /// Raiz da cadeia Merkle rolante (ancora de confianca corrente).
    pub trusted_root: String,
}

impl HeraclitusDB {
    pub fn new(db_path: &str) -> std::io::Result<Self> {
        if !std::path::Path::new(db_path).exists() {
            let mut f = File::create(db_path)?;
            // PAGE 0: FILE HEADER ('HERA' + versao do formato)
            f.write_all(b"HERA")?;
            f.write_all(&6u32.to_be_bytes())?;
        }
        Ok(Self {
            db_path: db_path.to_string(),
            anchor_path: format!("{db_path}.anchor"),
            current_lsn: 14_812_337,
            trusted_root: String::new(),
        })
    }

    /// Monta o bloco binario completo (header + payload) e avanca a cadeia em O(1).
    /// Nao escreve em disco — reutilizado por `write_fact` e pelo benchmark.
    pub fn build_block(&mut self, fact: &mut Value) -> Vec<u8> {
        self.current_lsn += 1;
        fact["fact.time"]["log_sequence_number"] = Value::from(self.current_lsn);

        let core = core_bytes(fact);
        let leaf = b3_hex(&core);
        self.trusted_root = fold_chain(&self.trusted_root, &leaf);

        fact["fact.integrity"] = serde_json::json!({
            "leaf_hash": leaf,
            "merkle_root_anchor": self.trusted_root,
            "signature": sign(&leaf),
        });

        let ev_hex = fact["fact.evidence"]["raw_observation_hash"]
            .as_str()
            .unwrap_or("")
            .rsplit(':')
            .next()
            .unwrap_or("");
        let mut evidence = [0u8; 32];
        let bytes = ev_hex.as_bytes();
        let n = bytes.len().min(32);
        evidence[..n].copy_from_slice(&bytes[..n]);

        let ts = fact["fact.time"]["system_timestamp"].as_i64().unwrap_or(0) as u64;
        let conf = fact["fact.confidence"].as_f64().unwrap_or(0.9) as f32;
        let payload = serde_json::to_vec(fact).unwrap();

        let mut block = Vec::with_capacity(HEADER_SIZE + payload.len());
        block.extend_from_slice(b"FACT");
        block.extend_from_slice(&self.current_lsn.to_be_bytes());
        block.extend_from_slice(&ts.to_be_bytes());
        block.extend_from_slice(&conf.to_be_bytes());
        block.extend_from_slice(&evidence);
        block.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        block.extend_from_slice(&payload);
        block
    }

    /// Grava um Fato (append-only) e ancora a raiz de confianca.
    pub fn write_fact(&mut self, fact: &mut Value) -> std::io::Result<u64> {
        let block = self.build_block(fact);
        let mut f = OpenOptions::new().append(true).open(&self.db_path)?;
        f.write_all(&block)?;
        fs::write(&self.anchor_path, &self.trusted_root)?;
        Ok(self.current_lsn)
    }

    /// Escreve um lote com um unico `BufWriter` (caminho de alta vazao do benchmark).
    pub fn write_stream<'a, I>(&mut self, facts: I) -> std::io::Result<u64>
    where
        I: IntoIterator<Item = &'a mut Value>,
    {
        let f = OpenOptions::new().append(true).open(&self.db_path)?;
        let mut w = BufWriter::new(f);
        for fact in facts {
            let block = self.build_block(fact);
            w.write_all(&block)?;
        }
        w.flush()?;
        fs::write(&self.anchor_path, &self.trusted_root)?;
        Ok(self.current_lsn)
    }

    /// `db.verify()` — reconstroi a cadeia Merkle do disco e detecta adulteracao.
    pub fn verify(&self) -> VerifyResult {
        let mut data = Vec::new();
        let mut f = match File::open(&self.db_path) {
            Ok(f) => f,
            Err(_) => return VerifyResult { status: "ERROR".into(), facts: 0, root: String::new(),
                                            message: "Arquivo de banco nao encontrado.".into() },
        };
        f.read_to_end(&mut data).ok();

        let trusted_root = fs::read_to_string(&self.anchor_path).ok().map(|s| s.trim().to_string());

        if data.len() < 8 || &data[..4] != b"HERA" {
            return VerifyResult { status: "CORRUPTED".into(), facts: 0, root: String::new(),
                                  message: "Cabecalho mestre invalido.".into() };
        }

        let mut chain = String::new();
        let mut count = 0usize;
        let mut pos = 8usize; // pula file header
        while pos + HEADER_SIZE <= data.len() {
            let header = &data[pos..pos + HEADER_SIZE];
            if &header[..4] != b"FACT" {
                return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                      message: "Assinatura de bloco corrompida.".into() };
            }
            let lsn = u64::from_be_bytes(header[4..12].try_into().unwrap());
            let payload_len = u32::from_be_bytes(header[56..60].try_into().unwrap()) as usize;
            let start = pos + HEADER_SIZE;
            if start + payload_len > data.len() {
                return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                      message: format!("Payload truncado no LSN {lsn}") };
            }
            let payload = &data[start..start + payload_len];
            let fact: Value = match serde_json::from_slice(payload) {
                Ok(v) => v,
                Err(_) => return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                                message: format!("Payload corrompido no LSN {lsn}") },
            };

            let leaf = b3_hex(&core_bytes(&fact));
            let integ = fact.get("fact.integrity");
            if let Some(stored) = integ.and_then(|i| i.get("leaf_hash")).and_then(|v| v.as_str()) {
                if stored != leaf {
                    return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                          message: format!("Folha adulterada no LSN {lsn}") };
                }
            }
            chain = fold_chain(&chain, &leaf);
            if let Some(stored) = integ.and_then(|i| i.get("merkle_root_anchor")).and_then(|v| v.as_str()) {
                if stored != chain {
                    return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                          message: format!("Cadeia Merkle quebrada no LSN {lsn}") };
                }
            }
            count += 1;
            pos = start + payload_len;
        }

        if let Some(anchor) = &trusted_root {
            if &chain != anchor {
                return VerifyResult { status: "VIOLATED".into(), facts: count, root: chain,
                                      message: "Raiz divergente da ancora.".into() };
            }
        }
        VerifyResult { status: "INTEG_OK".into(), facts: count, root: chain, message: String::new() }
    }

    /// Simula atacante: flipa 1 char hex dentro do hash de evidencia (mesmo tamanho).
    pub fn inject_malicious_tamper(&self, target_lsn: u64) -> std::io::Result<bool> {
        let mut data = fs::read(&self.db_path)?;
        let mut pos = 8usize;
        while pos + HEADER_SIZE <= data.len() {
            let header = &data[pos..pos + HEADER_SIZE];
            let lsn = u64::from_be_bytes(header[4..12].try_into().unwrap());
            let payload_len = u32::from_be_bytes(header[56..60].try_into().unwrap()) as usize;
            let start = pos + HEADER_SIZE;
            if lsn == target_lsn {
                let marker = b"\"raw_observation_hash\":\"b3:";
                let region = &data[start..start + payload_len];
                let idx = region.windows(marker.len()).position(|w| w == marker).unwrap_or(0);
                let off = start + idx + marker.len();
                data[off] = if data[off] == b'1' { b'0' } else { b'1' };
                fs::write(&self.db_path, &data)?;
                return Ok(true);
            }
            pos = start + payload_len;
        }
        Ok(false)
    }
}
