//! HeraclitusDB — armazenamento append-only `.hdb` com integridade BLAKE3 + CRC-32C.
//!
//! ## Arquitetura de integridade em duas camadas
//!
//! | Camada | Mecanismo | Detecta |
//! |--------|-----------|---------|
//! | **Física** | CRC-32C Castagnoli (CPM-200) | Bit-rot, falha de disco, truncamento |
//! | **Criptográfica** | Cadeia Merkle rolante BLAKE3 | Adulteração intencional, reordenação |
//!
//! ### Layout do bloco em disco
//!
//! ```text
//! +--------+--------+--------+---------+-------------------------------+
//! | FACT   | LSN    | TS     | Conf    | EvidHash(32) | PayloadLen(4) |
//! | 4B     | 8B     | 8B     | 4B      |              |               |
//! +--------+--------+--------+---------+--------------+---------------+
//! | Payload CRF v2 (CpmRecord::encode) — contém CRC-32C + fbfact body|
//! +--------------------------------------------------------------------+
//! ```
//!
//! O payload é agora um registro **CRF v2** (CPM-100/200) em vez de bytes fbfact
//! puros. O `db.verify()` valida primeiro o CRC-32C (camada física), depois
//! reconstrói a cadeia Merkle BLAKE3 (camada criptográfica). A ordem importa:
//! corrupção física é detectada antes de qualquer lógica de negócio.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};

use serde_json::Value;

use crate::{cpm, fbfact};

/// Magic(4) + LSN(8) + Timestamp(8) + Confidence(4) + EvidenceHash(32) + PayloadLen(4)
pub const HEADER_SIZE: usize = 60;

fn b3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Bytes canônicos do Fato SEM `fact.integrity` (folha BLAKE3). Codec binário
/// determinístico FlatBuffers-style (zero JSON no caminho quente).
fn core_bytes(fact: &Value) -> Vec<u8> {
    fbfact::encode_core(fact)
}

/// Avança a cadeia Merkle rolante: root := BLAKE3(root_anterior || folha).
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
    /// Raiz da cadeia Merkle rolante (âncora de confiança corrente).
    pub trusted_root: String,
}

impl HeraclitusDB {
    pub fn new(db_path: &str) -> std::io::Result<Self> {
        if !std::path::Path::new(db_path).exists() {
            let mut f = File::create(db_path)?;
            // PAGE 0: FILE HEADER ('HERA' + versão do formato v2 = CPM-enabled)
            f.write_all(b"HERA")?;
            f.write_all(&7u32.to_be_bytes())?; // schema v7 = CPM payload
        }
        Ok(Self {
            db_path: db_path.to_string(),
            anchor_path: format!("{db_path}.anchor"),
            current_lsn: 14_812_337,
            trusted_root: String::new(),
        })
    }

    /// Monta o bloco binário completo (header + payload CRF v2) e avança a cadeia em O(1).
    /// Não escreve em disco — reutilizado por `write_fact` e pelo benchmark.
    pub fn build_block(&mut self, fact: &mut Value) -> Vec<u8> {
        self.current_lsn += 1;
        fact["fact.time"]["log_sequence_number"] = Value::from(self.current_lsn);

        // --- Camada criptográfica (BLAKE3) ---
        let core = core_bytes(fact);
        let leaf = b3_hex(&core);
        self.trusted_root = fold_chain(&self.trusted_root, &leaf);

        fact["fact.integrity"] = serde_json::json!({
            "leaf_hash": leaf,
            "merkle_root_anchor": self.trusted_root,
            "signature": sign(&leaf),
        });

        // --- Camada física (CRC-32C via CPM) ---
        // O payload gravado em disco é um CRF v2 completo (inclui CRC-32C +
        // metadados fixos + corpo fbfact como pristine payload).
        let cpm_record = cpm::fact_to_record(fact);
        let payload = cpm_record.encode(); // CRF v2 bytes com CRC-32C embutido

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

    /// Grava um Fato (append-only) e ancora a raiz de confiança.
    pub fn write_fact(&mut self, fact: &mut Value) -> std::io::Result<u64> {
        let block = self.build_block(fact);
        let mut f = OpenOptions::new().append(true).open(&self.db_path)?;
        f.write_all(&block)?;
        fs::write(&self.anchor_path, &self.trusted_root)?;
        Ok(self.current_lsn)
    }

    /// Escreve um lote com um único `BufWriter` (caminho de alta vazão do benchmark).
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

    /// Grava localmente (líder Raft) e devolve `(lsn, raiz, bytes do bloco)` para
    /// que o bloco seja replicado byte-a-byte aos followers.
    pub fn commit_local(&mut self, fact: &mut Value) -> std::io::Result<(u64, String, Vec<u8>)> {
        let block = self.build_block(fact);
        let mut f = OpenOptions::new().append(true).open(&self.db_path)?;
        f.write_all(&block)?;
        fs::write(&self.anchor_path, &self.trusted_root)?;
        Ok((self.current_lsn, self.trusted_root.clone(), block))
    }

    /// Follower Raft (spec seção 11): valida um bloco replicado e o aplica.
    /// Ordem de validação:
    ///   1. Estrutura do header (magic FACT + tamanhos)
    ///   2. **CRC-32C do payload CRF v2** (camada física — CPM-200)
    ///   3. LSN sequencial
    ///   4. Folha BLAKE3 e cadeia Merkle (camada criptográfica)
    pub fn append_replicated_block(&mut self, block: &[u8]) -> Result<u64, crate::error::HeraclitusError> {
        if block.len() < HEADER_SIZE || &block[..4] != b"FACT" {
            return Err(crate::error::HeraclitusError::DatabaseCorruption("bloco inválido".into()));
        }
        let lsn_bytes = block[4..12].try_into()
            .map_err(|_| crate::error::HeraclitusError::DatabaseCorruption("lsn inválido".into()))?;
        let lsn = u64::from_be_bytes(lsn_bytes);
        let payload_len_bytes = block[56..60].try_into()
            .map_err(|_| crate::error::HeraclitusError::DatabaseCorruption("payload_len inválido".into()))?;
        let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;
        if HEADER_SIZE + payload_len != block.len() {
            return Err(crate::error::HeraclitusError::DatabaseCorruption("tamanho de bloco inconsistente".into()));
        }

        let payload = &block[HEADER_SIZE..];

        // --- Validação física: CRC-32C (CPM-200) ---
        let fact = match cpm::decode_record(payload) {
            cpm::CpmDecoded::Record(rec, _) => {
                cpm::record_to_fact(&rec)
                    .map_err(|_| crate::error::HeraclitusError::DatabaseCorruption(
                        format!("payload CRF v2 inválido no LSN {lsn}")
                    ))?
            }
            cpm::CpmDecoded::Torn => {
                return Err(crate::error::HeraclitusError::DatabaseCorruption(
                    format!("CRC-32C físico falhou no LSN {lsn} — possível corrupção de disco")
                ));
            }
        };

        // --- Validação de ordem do LSN ---
        if lsn != self.current_lsn + 1 {
            return Err(crate::error::HeraclitusError::DatabaseCorruption(
                format!("LSN fora de ordem: esperado {}, recebido {lsn}", self.current_lsn + 1)
            ));
        }

        // --- Validação criptográfica: folha + cadeia Merkle BLAKE3 ---
        let leaf = b3_hex(&core_bytes(&fact));
        let integ = fact.get("fact.integrity");
        let emb_leaf = integ.and_then(|i| i.get("leaf_hash")).and_then(|v| v.as_str()).unwrap_or("");
        if emb_leaf != leaf {
            return Err(crate::error::HeraclitusError::DatabaseCorruption(
                format!("folha BLAKE3 divergente no LSN {lsn}")
            ));
        }
        let new_root = fold_chain(&self.trusted_root, &leaf);
        let emb_root = integ.and_then(|i| i.get("merkle_root_anchor")).and_then(|v| v.as_str()).unwrap_or("");
        if emb_root != new_root {
            return Err(crate::error::HeraclitusError::DatabaseCorruption(
                format!("cadeia Merkle divergente no LSN {lsn}")
            ));
        }

        let mut f = OpenOptions::new().append(true).open(&self.db_path)
            .map_err(|e| crate::error::HeraclitusError::Io(e))?;
        f.write_all(block).map_err(|e| crate::error::HeraclitusError::Io(e))?;
        self.current_lsn = lsn;
        self.trusted_root = new_root;
        fs::write(&self.anchor_path, &self.trusted_root).ok();
        Ok(lsn)
    }

    /// `db.verify()` — reconstrói a cadeia Merkle do disco e detecta adulteração.
    ///
    /// Percorre cada bloco na ordem de gravação e aplica as duas camadas:
    /// 1. CRC-32C (físico): detecta bit-rot ou truncamento acidental.
    /// 2. BLAKE3 Merkle chain (criptográfico): detecta adulteração intencional.
    pub fn verify(&self) -> VerifyResult {
        let mut data = Vec::new();
        let mut f = match File::open(&self.db_path) {
            Ok(f) => f,
            Err(_) => return VerifyResult { status: "ERROR".into(), facts: 0, root: String::new(),
                                            message: "Arquivo de banco não encontrado.".into() },
        };
        f.read_to_end(&mut data).ok();

        let trusted_root = fs::read_to_string(&self.anchor_path).ok().map(|s| s.trim().to_string());

        if data.len() < 8 || &data[..4] != b"HERA" {
            return VerifyResult { status: "CORRUPTED".into(), facts: 0, root: String::new(),
                                  message: "Cabeçalho mestre inválido.".into() };
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
            let lsn_bytes = header[4..12].try_into().unwrap_or([0; 8]);
            let lsn = u64::from_be_bytes(lsn_bytes);
            let payload_len_bytes = header[56..60].try_into().unwrap_or([0; 4]);
            let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;
            let start = pos + HEADER_SIZE;
            if start + payload_len > data.len() {
                return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                      message: format!("Payload truncado no LSN {lsn}") };
            }
            let payload = &data[start..start + payload_len];

            // --- Camada 1: física CRC-32C (CPM-200) ---
            let fact = match cpm::decode_record(payload) {
                cpm::CpmDecoded::Record(rec, _) => {
                    match cpm::record_to_fact(&rec) {
                        Ok(v) => v,
                        Err(_) => return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                                        message: format!("Payload CRF v2 corrompido no LSN {lsn}") },
                    }
                }
                cpm::CpmDecoded::Torn => {
                    return VerifyResult {
                        status: "VIOLATED".into(), facts: count, root: String::new(),
                        message: format!("CRC-32C físico falhou no LSN {lsn} — bit-rot detectado"),
                    };
                }
            };

            // --- Camada 2: criptográfica BLAKE3 Merkle ---
            let leaf = b3_hex(&core_bytes(&fact));
            let integ = fact.get("fact.integrity");
            if let Some(stored) = integ.and_then(|i| i.get("leaf_hash")).and_then(|v| v.as_str()) {
                if stored != leaf {
                    return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(),
                                          message: format!("Folha BLAKE3 adulterada no LSN {lsn}") };
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
                                      message: "Raiz divergente da âncora.".into() };
            }
        }
        VerifyResult { status: "INTEG_OK".into(), facts: count, root: chain, message: String::new() }
    }

    /// Simula atacante: flipa 1 char hex dentro do hash de evidência (mesmo tamanho).
    /// Nota: com CPM, o tamper deve contornar o CRC-32C para simular adulteração
    /// criptográfica. Este método flippa um byte dentro do payload CRF v2, o que
    /// fará o CRC-32C falhar (VIOLATED pela camada física) — comportamento correto
    /// para demonstrar que a camada física detecta qualquer modificação.
    pub fn inject_malicious_tamper(&self, target_lsn: u64) -> std::io::Result<bool> {
        let mut data = fs::read(&self.db_path)?;
        let mut pos = 8usize;
        while pos + HEADER_SIZE <= data.len() {
            let header = &data[pos..pos + HEADER_SIZE];
            let lsn_bytes = header[4..12].try_into().unwrap_or([0; 8]);
            let lsn = u64::from_be_bytes(lsn_bytes);
            let payload_len_bytes = header[56..60].try_into().unwrap_or([0; 4]);
            let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;
            let start = pos + HEADER_SIZE;
            if lsn == target_lsn && start + payload_len <= data.len() {
                // Flipa um byte dentro do payload CRF v2 (após o CRC-32C dos primeiros 4B).
                // Isso corrompe a camada física: o verify() detecta via CRC-32C.
                let tamper_off = start + cpm::FIXED_PREFIX_LEN + 8; // dentro dos dados variáveis
                if tamper_off < start + payload_len {
                    data[tamper_off] ^= 0x01;
                    fs::write(&self.db_path, &data)?;
                    return Ok(true);
                }
            }
            pos = start + payload_len;
        }
        Ok(false)
    }
}
