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
use std::io::{BufWriter, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

use crate::raft::BASE_LSN;
use crate::{cpm, fbfact};

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Restringe as permissões de um ficheiro de chave a 0600 (só o dono). No
/// Windows é no-op (a ACL default do perfil já isola o utilizador); a chave
/// **tem** de ser protegida/movida para fora da máquina em produção — sem isso
/// a assinatura da âncora não protege contra um atacante que a leia e re-assine.
fn restrict_key_perms(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Carrega a chave de assinatura de `key_path` ou gera uma nova (seed do CSPRNG
/// do SO). Persiste a chave privada (0600) e a pública ao lado — a pública é o
/// que o `verify()` usa para conferir a assinatura da âncora.
fn load_or_create_key(key_path: &str, pub_path: &str) -> std::io::Result<SigningKey> {
    if let Ok(txt) = fs::read_to_string(key_path) {
        if let Some(bytes) = from_hex(&txt) {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(SigningKey::from_bytes(&seed));
            }
        }
        // Ficheiro de chave ilegível: falha alto em vez de gerar outra chave em
        // silêncio (isso invalidaria a assinatura de toda a âncora existente).
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("chave de assinatura ilegível em {key_path}"),
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("getrandom: {e}")))?;
    let sk = SigningKey::from_bytes(&seed);
    fs::write(key_path, to_hex(&seed))?;
    restrict_key_perms(key_path);
    fs::write(pub_path, to_hex(sk.verifying_key().as_bytes()))?;
    Ok(sk)
}

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

/// Tag por-Fato NÃO-autoritativa (BLAKE3 da folha). A assinatura de verdade é a
/// **ed25519 da âncora** (`<db>.anchor.sig`, conferida no `verify()`); assinar
/// cada Fato com a chave real mataria a vazão (~87k EPS). Prefixo honesto
/// `b3tag:` — não é uma assinatura criptográfica.
fn leaf_tag(leaf: &str) -> String {
    let mut data = b"HERA-LEAF:".to_vec();
    data.extend_from_slice(leaf.as_bytes());
    format!("b3tag:{}", &b3_hex(&data)[..48])
}

pub struct VerifyResult {
    pub status: String,
    pub facts: usize,
    pub root: String,
    pub message: String,
}

/// Desfecho de um [`scan_blocks`] (varredura estrutural em streaming).
pub(crate) enum ScanOutcome {
    /// Fim limpo (EOF) ou paragem antecipada pelo callback.
    Done,
    /// O ficheiro não existe / não abre.
    NoFile,
    /// Cabeçalho mestre `HERA` inválido.
    BadMaster,
    /// Magic `FACT` de um bloco corrompido.
    BadBlockMagic,
    /// `payload_len` declara mais bytes do que o ficheiro tem (cauda truncada).
    Truncated { lsn: u64 },
}

/// Varre os blocos do `.hdb` em **streaming** (Marco A §2.5 do AUDIT.md): um
/// bloco em RAM de cada vez via `BufReader`, nunca `read_to_end` do ficheiro
/// inteiro — `verify()`/HQL passam a escalar com o tamanho do bloco, não do
/// banco. O `payload_len` (não confiável, vem do disco) é LIMITADO pelos bytes
/// restantes do ficheiro antes de qualquer alocação.
///
/// Chama `f(lsn, payload)` por bloco estruturalmente íntegro; devolver `false`
/// interrompe (early-exit do LIMIT do HQL). A validação de CONTEÚDO
/// (CRC/Merkle) é do callback — aqui é só o enquadramento físico.
pub(crate) fn scan_blocks<F>(db_path: &str, mut f: F) -> std::io::Result<ScanOutcome>
where
    F: FnMut(u64, &[u8]) -> bool,
{
    use std::io::{BufReader, Read as _};
    let file = match File::open(db_path) {
        Ok(f) => f,
        Err(_) => return Ok(ScanOutcome::NoFile),
    };
    let file_size = file.metadata()?.len();
    let mut r = BufReader::new(file);

    let mut master = [0u8; 8];
    if r.read_exact(&mut master).is_err() || &master[..4] != b"HERA" {
        return Ok(ScanOutcome::BadMaster);
    }

    let mut pos: u64 = 8;
    let mut header = [0u8; HEADER_SIZE];
    let mut payload = Vec::new();
    loop {
        // Menos de um header restante = fim limpo (mesma semântica do scan
        // antigo, que ignorava uma cauda menor que HEADER_SIZE).
        if file_size - pos < HEADER_SIZE as u64 {
            return Ok(ScanOutcome::Done);
        }
        r.read_exact(&mut header)?;
        pos += HEADER_SIZE as u64;
        if &header[..4] != b"FACT" {
            return Ok(ScanOutcome::BadBlockMagic);
        }
        let lsn = u64::from_be_bytes(header[4..12].try_into().unwrap());
        let payload_len = u32::from_be_bytes(header[56..60].try_into().unwrap()) as u64;
        if payload_len > file_size - pos {
            return Ok(ScanOutcome::Truncated { lsn });
        }
        payload.clear();
        payload.resize(payload_len as usize, 0);
        r.read_exact(&mut payload)?;
        pos += payload_len;
        if !f(lsn, &payload) {
            return Ok(ScanOutcome::Done);
        }
    }
}

pub struct HeraclitusDB {
    pub db_path: String,
    anchor_path: String,
    /// `<db>.anchor.sig` — assinatura ed25519 (hex) sobre a raiz da âncora.
    anchor_sig_path: String,
    /// `<db>.pub` — chave pública ed25519 (hex) para o `verify()` conferir.
    pub_path: String,
    pub current_lsn: u64,
    /// Raiz da cadeia Merkle rolante (âncora de confiança corrente).
    pub trusted_root: String,
    /// Chave de assinatura ed25519 (privada — nunca sai daqui; persiste em
    /// `<db>.key` com 0600). Marco B: assina a âncora ao persisti-la.
    signing_key: SigningKey,
}

impl HeraclitusDB {
    pub fn new(db_path: &str) -> std::io::Result<Self> {
        let existed = std::path::Path::new(db_path).exists();
        if !existed {
            let mut f = File::create(db_path)?;
            // PAGE 0: FILE HEADER ('HERA' + versão do formato v2 = CPM-enabled)
            f.write_all(b"HERA")?;
            f.write_all(&7u32.to_be_bytes())?; // schema v7 = CPM payload
        }
        let key_path = format!("{db_path}.key");
        let pub_path = format!("{db_path}.pub");
        let signing_key = load_or_create_key(&key_path, &pub_path)?;
        let mut db = Self {
            db_path: db_path.to_string(),
            anchor_path: format!("{db_path}.anchor"),
            anchor_sig_path: format!("{db_path}.anchor.sig"),
            pub_path,
            current_lsn: BASE_LSN,
            trusted_root: String::new(),
            signing_key,
        };
        // RECUPERAÇÃO no reabrir: sem isto, `new()` de um `.hdb` EXISTENTE
        // repunha `current_lsn = BASE_LSN` e `trusted_root = ""`. O próximo
        // `write_fact` então: (a) atribuía um LSN já usado, e (b) dobrava a
        // cadeia Merkle a partir do vazio em vez de continuar a raiz on-disk —
        // o `merkle_root_anchor` embutido no bloco novo divergia do que o
        // `verify()` recalcula sobre TODO o ficheiro ⇒ um append legítimo
        // pós-restart marcava o banco como VIOLATED. Reconstrói o estado do
        // disco (mesma filosofia replay-from-log do HeraclitusDB de produção).
        if existed {
            db.recover()?;
        }
        Ok(db)
    }

    /// Reconstrói `current_lsn` + `trusted_root` percorrendo o log em disco.
    /// A raiz recuperada é a cadeia Merkle rolante sobre todos os blocos; o LSN
    /// é o do último bloco íntegro. Blocos truncados/corrompidos na cauda param
    /// o replay (a verificação criptográfica fica a cargo do `verify()`).
    fn recover(&mut self) -> std::io::Result<()> {
        let mut chain = String::new();
        let mut last_lsn = BASE_LSN;
        // Streaming (nunca o ficheiro inteiro em RAM). Replay leniente: o
        // primeiro bloco ilegível para a recuperação (o verify() é quem julga).
        let _ = scan_blocks(&self.db_path, |lsn, payload| {
            let fact = match cpm::decode_record(payload) {
                cpm::CpmDecoded::Record(rec, _) => match cpm::record_to_fact(&rec) {
                    Ok(v) => v,
                    Err(_) => return false,
                },
                cpm::CpmDecoded::Torn => return false,
            };
            chain = fold_chain(&chain, &b3_hex(&core_bytes(&fact)));
            last_lsn = lsn;
            true
        })?;
        self.current_lsn = last_lsn;
        self.trusted_root = chain;
        Ok(())
    }

    /// Persiste a âncora (raiz da cadeia) E a sua assinatura ed25519. O atacante
    /// que reescreva o `.hdb` + `.anchor` não consegue produzir um `.anchor.sig`
    /// válido sem a chave privada — o `verify()` deteta. (Segurança condicionada
    /// à proteção da chave; ver `restrict_key_perms`.)
    fn persist_anchor(&self) -> std::io::Result<()> {
        fs::write(&self.anchor_path, &self.trusted_root)?;
        let sig = self.signing_key.sign(self.trusted_root.as_bytes());
        fs::write(&self.anchor_sig_path, to_hex(&sig.to_bytes()))?;
        Ok(())
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
            "signature": leaf_tag(&leaf),
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
        f.sync_all()?; // fsync ANTES do ack — durabilidade real (o bloco não pode
                       // ser dado como gravado se um corte de energia o perde).
        self.persist_anchor()?;
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
        // fsync do lote inteiro antes de ancorar (o `flush` do BufWriter só
        // empurra para o SO; sem `sync_all` a durabilidade não é garantida).
        w.get_ref().sync_all()?;
        self.persist_anchor()?;
        Ok(self.current_lsn)
    }

    /// Grava localmente (líder Raft) e devolve `(lsn, raiz, bytes do bloco)` para
    /// que o bloco seja replicado byte-a-byte aos followers.
    pub fn commit_local(&mut self, fact: &mut Value) -> std::io::Result<(u64, String, Vec<u8>)> {
        let block = self.build_block(fact);
        let mut f = OpenOptions::new().append(true).open(&self.db_path)?;
        f.write_all(&block)?;
        f.sync_all()?; // líder Raft: durável ANTES de replicar/ackar aos followers.
        self.persist_anchor()?;
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
        f.sync_all().map_err(|e| crate::error::HeraclitusError::Io(e))?; // follower durável antes do ack
        self.current_lsn = lsn;
        self.trusted_root = new_root;
        self.persist_anchor().ok();
        Ok(lsn)
    }

    /// `db.verify()` — reconstrói a cadeia Merkle do disco e detecta adulteração.
    ///
    /// Percorre cada bloco na ordem de gravação e aplica as duas camadas:
    /// 1. CRC-32C (físico): detecta bit-rot ou truncamento acidental.
    /// 2. BLAKE3 Merkle chain (criptográfico): detecta adulteração intencional.
    pub fn verify(&self) -> VerifyResult {
        let trusted_root = fs::read_to_string(&self.anchor_path).ok().map(|s| s.trim().to_string());

        // Streaming (Marco A): um bloco em RAM de cada vez — verify() escala
        // com o tamanho do BLOCO, não do banco. Semântica de status idêntica.
        let mut chain = String::new();
        let mut count = 0usize;
        let mut violation: Option<String> = None;
        let outcome = scan_blocks(&self.db_path, |lsn, payload| {
            // --- Camada 1: física CRC-32C (CPM-200) ---
            let fact = match cpm::decode_record(payload) {
                cpm::CpmDecoded::Record(rec, _) => match cpm::record_to_fact(&rec) {
                    Ok(v) => v,
                    Err(_) => {
                        violation = Some(format!("Payload CRF v2 corrompido no LSN {lsn}"));
                        return false;
                    }
                },
                cpm::CpmDecoded::Torn => {
                    violation = Some(format!("CRC-32C físico falhou no LSN {lsn} — bit-rot detectado"));
                    return false;
                }
            };

            // --- Camada 2: criptográfica BLAKE3 Merkle ---
            let leaf = b3_hex(&core_bytes(&fact));
            let integ = fact.get("fact.integrity");
            if let Some(stored) = integ.and_then(|i| i.get("leaf_hash")).and_then(|v| v.as_str()) {
                if stored != leaf {
                    violation = Some(format!("Folha BLAKE3 adulterada no LSN {lsn}"));
                    return false;
                }
            }
            chain = fold_chain(&chain, &leaf);
            if let Some(stored) = integ.and_then(|i| i.get("merkle_root_anchor")).and_then(|v| v.as_str()) {
                if stored != chain {
                    violation = Some(format!("Cadeia Merkle quebrada no LSN {lsn}"));
                    return false;
                }
            }
            count += 1;
            true
        });

        if let Some(msg) = violation {
            return VerifyResult { status: "VIOLATED".into(), facts: count, root: String::new(), message: msg };
        }
        match outcome {
            Err(e) => VerifyResult { status: "ERROR".into(), facts: count, root: String::new(),
                                     message: format!("Erro de leitura: {e}") },
            Ok(ScanOutcome::NoFile) => VerifyResult { status: "ERROR".into(), facts: 0, root: String::new(),
                                                      message: "Arquivo de banco não encontrado.".into() },
            Ok(ScanOutcome::BadMaster) => VerifyResult { status: "CORRUPTED".into(), facts: 0, root: String::new(),
                                                         message: "Cabeçalho mestre inválido.".into() },
            Ok(ScanOutcome::BadBlockMagic) => VerifyResult { status: "VIOLATED".into(), facts: count,
                root: String::new(), message: "Assinatura de bloco corrompida.".into() },
            Ok(ScanOutcome::Truncated { lsn }) => VerifyResult { status: "VIOLATED".into(), facts: count,
                root: String::new(), message: format!("Payload truncado no LSN {lsn}") },
            Ok(ScanOutcome::Done) => {
                if let Some(anchor) = &trusted_root {
                    if &chain != anchor {
                        return VerifyResult { status: "VIOLATED".into(), facts: count, root: chain,
                                              message: "Raiz divergente da âncora.".into() };
                    }
                }
                // --- Camada 3: assinatura ed25519 da âncora (Marco B) ---
                // Fecha o buraco "atacante reescreve .hdb + .anchor consistentes":
                // sem a chave privada não há `.anchor.sig` válido. Se a chave
                // pública existe, a assinatura é OBRIGATÓRIA.
                if let Some(msg) = self.verify_anchor_signature(&chain) {
                    return VerifyResult { status: "VIOLATED".into(), facts: count, root: chain, message: msg };
                }
                VerifyResult { status: "INTEG_OK".into(), facts: count, root: chain, message: String::new() }
            }
        }
    }

    /// Confere a assinatura ed25519 da âncora (`<db>.anchor.sig`) sobre a raiz
    /// recalculada, usando a chave pública `<db>.pub`. Devolve `Some(msg)` se
    /// houver violação, `None` se OK (ou se o banco é intencionalmente sem
    /// chave pública — modo legado, sem assinatura). `root` é a raiz que o
    /// `verify()` acabou de reconstruir do disco.
    fn verify_anchor_signature(&self, root: &str) -> Option<String> {
        let pub_hex = match fs::read_to_string(&self.pub_path) {
            Ok(s) => s,
            Err(_) => return None, // sem chave pública ⇒ modo legado (Merkle-only)
        };
        let vk = from_hex(&pub_hex)
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok());
        let vk = match vk {
            Some(v) => v,
            None => return Some("chave pública ed25519 ilegível".into()),
        };
        let sig = fs::read_to_string(&self.anchor_sig_path)
            .ok()
            .and_then(|s| from_hex(&s))
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
            .map(|b| Signature::from_bytes(&b));
        let sig = match sig {
            Some(s) => s,
            None => return Some("assinatura da âncora ausente ou ilegível".into()),
        };
        match vk.verify(root.as_bytes(), &sig) {
            Ok(()) => None,
            Err(_) => Some("assinatura ed25519 da âncora inválida — adulteração".into()),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn tmp_path(tag: &str) -> String {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("forge_{}_{}_{}.hdb", tag, std::process::id(), n));
        let s = p.to_str().unwrap().to_string();
        for ext in ["", ".anchor", ".anchor.sig", ".key", ".pub"] {
            let _ = fs::remove_file(format!("{s}{ext}"));
        }
        s
    }

    fn fact(action: &str) -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.identity": {"actor.id":"a","actor.name":"a","target.id":"t","source.ip":null},
            "fact.time": {"system_timestamp": 1_782_467_794_979_937i64, "log_sequence_number": 0u64},
            "fact.behavior": {"class":"c","action":action,"risk_level":"Medium"},
            "fact.evidence": {"raw_observation_hash":"b3:abcd","carimbo_tempo_legal":"icp"},
            "fact.lineage": {"transformation_steps":["parse"],"input_source":"pg","matched_rule":"r"},
            "fact.confidence": 0.9,
            "fact.knowledge_version":"k-v1","fact.reasoning_version":"r-v6","fact.ontology_version":"v9"
        })
    }

    /// Regressão do bug-chave: reabrir um `.hdb` existente TEM de recuperar
    /// `current_lsn` + `trusted_root` do disco. Sem `recover()`, o append da
    /// segunda sessão dobrava a cadeia Merkle a partir do vazio e o `verify()`
    /// marcava um banco íntegro como VIOLATED.
    #[test]
    fn reopen_preserves_chain_and_verifies() {
        let base = std::env::temp_dir().join(format!("forge_reopen_{}.hdb", std::process::id()));
        let p = base.to_str().unwrap();
        let _ = fs::remove_file(p);
        let _ = fs::remove_file(format!("{p}.anchor"));

        // Sessão 1: cria e escreve 3 fatos.
        {
            let mut db = HeraclitusDB::new(p).unwrap();
            for i in 0..3 {
                let mut f = fact(&format!("a{i}"));
                db.write_fact(&mut f).unwrap();
            }
            assert_eq!(db.verify().status, "INTEG_OK");
        }
        // Sessão 2: REABRE e escreve mais 2.
        {
            let mut db = HeraclitusDB::new(p).unwrap();
            assert_eq!(db.current_lsn, BASE_LSN + 3, "LSN não recuperado no reabrir");
            for i in 3..5 {
                let mut f = fact(&format!("a{i}"));
                db.write_fact(&mut f).unwrap();
            }
            let r = db.verify();
            assert_eq!(r.status, "INTEG_OK", "reabrir+append quebrou a cadeia: {}", r.message);
            assert_eq!(r.facts, 5);
        }
        let _ = fs::remove_file(p);
        let _ = fs::remove_file(format!("{p}.anchor"));
    }

    /// Marco B: uma assinatura de âncora corrompida é rejeitada — a integridade
    /// cripto (camada 3) é imposta, não decorativa.
    #[test]
    fn tampered_anchor_signature_is_rejected() {
        let p = tmp_path("sigtamper");
        {
            let mut db = HeraclitusDB::new(&p).unwrap();
            for i in 0..2 {
                db.write_fact(&mut fact(&format!("a{i}"))).unwrap();
            }
            assert_eq!(db.verify().status, "INTEG_OK");
        }
        // Sobrescreve a assinatura com uma de tamanho válido mas errada.
        fs::write(format!("{p}.anchor.sig"), "0".repeat(128)).unwrap();
        let db = HeraclitusDB::new(&p).unwrap();
        assert_eq!(db.verify().status, "VIOLATED", "sig corrompida devia falhar");
    }

    /// Marco B — a propriedade central: um atacante com acesso de ESCRITA aos
    /// ficheiros de dados (mas SEM a chave privada) reescreve `.hdb` + `.anchor`
    /// + `.anchor.sig` de forma internamente consistente, assinando com a SUA
    /// chave. A chave pública fixada da vítima (`.pub`) rejeita a assinatura
    /// estranha — o buraco "reescreve tudo consistente" fica fechado.
    #[test]
    fn foreign_key_signature_is_rejected() {
        let victim = tmp_path("victim");
        {
            let mut db = HeraclitusDB::new(&victim).unwrap();
            for i in 0..2 {
                db.write_fact(&mut fact(&format!("v{i}"))).unwrap();
            }
            assert_eq!(db.verify().status, "INTEG_OK");
        }
        // Atacante: banco próprio (⇒ chave própria) com Fatos diferentes.
        let attacker = tmp_path("attacker");
        {
            let mut db = HeraclitusDB::new(&attacker).unwrap();
            for i in 0..3 {
                db.write_fact(&mut fact(&format!("x{i}"))).unwrap();
            }
        }
        // Substitui os dados da vítima pelos do atacante — MENOS a `.pub`, que
        // continua a fixar a chave original da vítima.
        fs::copy(&attacker, &victim).unwrap();
        fs::copy(format!("{attacker}.anchor"), format!("{victim}.anchor")).unwrap();
        fs::copy(format!("{attacker}.anchor.sig"), format!("{victim}.anchor.sig")).unwrap();

        let db = HeraclitusDB::new(&victim).unwrap();
        let r = db.verify();
        assert_eq!(r.status, "VIOLATED", "assinatura de chave estranha devia ser rejeitada: {}", r.message);
    }
}
