//! `FactStore` — armazenamento append-only `.hdb`, geracao **HDB2**.
//!
//! > **Nao confundir com o [HeraclitusDB](https://github.com/JoseRFJuniorLLMs/HeraclitusDB).**
//! > Este e o store **embebido** do runtime de borda; aquele e um banco
//! > event-sourced em rede (gRPC :7474, segmentos `HRKL`/`HFTR`). Os formatos
//! > sao incompativeis de proposito — por isso existe uma ponte
//! > (`export_facts` + `bridge.py`), e nao uma migracao. Ver
//! > `INTEGRATION_CONTRACT.md`.
//!
//! ## O que mudou do HDB1 para o HDB2
//!
//! No HDB1 a folha criptografica era calculada **reserializando** o Fato:
//! `decode -> Value -> encode_core -> BLAKE3`. Isso fazia da integridade uma
//! funcao do codigo do descodificador em vez dos bytes gravados — qualquer
//! campo novo invalidava ficheiros intactos — e permitia que um campo que o
//! codec nao entendesse desaparecesse em silencio.
//!
//! No HDB2 a folha e calculada sobre os **bytes canonicos persistidos**
//! ([`crate::hfb2`]). Verificar deixou de exigir compreender: um leitor que nao
//! conheca uma extensao nova ainda afirma que o registo e integro.
//!
//! ```text
//! bytes canonicos no disco  ->  folha BLAKE3  ->  cadeia Merkle  ->  ancora Ed25519
//! ```
//!
//! ## Layout fisico
//!
//! ```text
//! master:  "HDB2" (4) | generation u32 (4)
//!
//! bloco:   "FCT2" (4) | lsn u64 (8) | leaf [32] | chain_root [32]
//!          | record_len u32 (4) | header_crc32c u32 (4)      = 84 bytes
//!          | registo HFB2 (record_len bytes, com CRC proprio)
//! ```
//!
//! `leaf` e `chain_root` sao valores DERIVADOS e por isso vivem no bloco, nunca
//! dentro do registo: gravar dentro do registo um hash do proprio registo seria
//! circular. O `verify()` recalcula ambos a partir dos bytes e compara.
//!
//! ## Duas camadas, duas responsabilidades
//!
//! | Camada | Mecanismo | Deteta |
//! |---|---|---|
//! | Fisica | CRC-32C Castagnoli | bit-rot, disco a falhar, escrita truncada |
//! | Criptografica | BLAKE3 com dominio + Ed25519 | adulteracao intencional, reordenacao |
//!
//! O CRC nao e material criptografico e nao pretende ser: quem altera os bytes
//! recalcula-o. Quem altera os bytes **nao** consegue reproduzir a assinatura da
//! ancora sem a chave privada.

use std::fs::{self, File, OpenOptions};
use std::io::Write;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

use crate::crc32c::crc32c;
use crate::hfb2::{self, Hfb2Error};
use crate::raft::BASE_LSN;

// ---------------------------------------------------------------------------
// Constantes do formato fisico
// ---------------------------------------------------------------------------

/// Magic do cabecalho mestre desta geracao.
pub const MASTER_MAGIC: &[u8; 4] = b"HDB2";
/// Geracao do ficheiro. Um numero diferente e recusado, nao interpretado.
pub const GENERATION: u32 = 2;
/// Magic do cabecalho mestre da geracao legada (`HERA` + schema v7).
pub const LEGACY_MASTER_MAGIC: &[u8; 4] = b"HERA";
pub const MASTER_HEADER_SIZE: usize = 8;

/// Magic de bloco. Distinto do `FACT` do HDB1 para que um ficheiro mal
/// concatenado nunca seja lido meio numa geracao e meio noutra.
pub const BLOCK_MAGIC: &[u8; 4] = b"FCT2";
/// `magic(4) + lsn(8) + leaf(32) + root(32) + record_len(4) + crc(4)`.
pub const BLOCK_HEADER_SIZE: usize = 84;

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
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

/// Restringe as permissoes de um ficheiro de chave a 0600 (so o dono). No
/// Windows e no-op (a ACL default do perfil ja isola o utilizador); a chave
/// **tem** de ser protegida/movida para fora da maquina em producao — sem isso
/// a assinatura da ancora nao protege contra um atacante que a leia e re-assine.
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
/// do SO). Persiste a chave privada (0600) e a publica ao lado — a publica e o
/// que o `verify()` usa para conferir a assinatura da ancora.
fn load_or_create_key(key_path: &str, pub_path: &str) -> std::io::Result<SigningKey> {
    if let Ok(txt) = fs::read_to_string(key_path) {
        if let Some(bytes) = from_hex(&txt) {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(SigningKey::from_bytes(&seed));
            }
        }
        // Ficheiro de chave ilegivel: falha alto em vez de gerar outra chave em
        // silencio (isso invalidaria a assinatura de toda a ancora existente).
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("chave de assinatura ilegivel em {key_path}"),
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| std::io::Error::other(format!("getrandom: {e}")))?;
    let sk = SigningKey::from_bytes(&seed);
    fs::write(key_path, to_hex(&seed))?;
    restrict_key_perms(key_path);
    fs::write(pub_path, to_hex(sk.verifying_key().as_bytes()))?;
    Ok(sk)
}

/// Escrita atomica e duravel: tmp -> fsync -> rename -> fsync do diretorio.
///
/// A ancora e o unico ficheiro que autentica o log. Escreve-la com um
/// `fs::write` normal deixa duas janelas de corte de energia — uma com o
/// ficheiro truncado, outra com o conteudo no cache do SO — e em ambas o banco
/// reabre a acusar adulteracao onde so houve falta de luz.
fn write_atomic(path: &str, contents: &[u8]) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        // Sem fsync do diretorio o rename pode nao sobreviver ao corte. Falhar
        // aqui nao e fatal em sistemas que nao o permitem (Windows).
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Varredura fisica
// ---------------------------------------------------------------------------

/// Cabecalho de um bloco, ja validado estruturalmente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub lsn: u64,
    pub leaf: [u8; 32],
    pub chain_root: [u8; 32],
    pub record_len: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Chegou ao fim do ficheiro sem sobras.
    Done,
    /// O ficheiro nao existe / nao abre.
    NoFile,
    /// Cabecalho mestre irreconhecivel.
    BadMaster,
    /// Cabecalho mestre de uma geracao anterior — recusado, nunca reinterpretado.
    LegacyGeneration,
    /// Magic de bloco corrompido no deslocamento indicado.
    BadBlockMagic { offset: u64 },
    /// CRC do cabecalho do bloco nao bate.
    BadBlockHeaderCrc { offset: u64 },
    /// O bloco declara mais bytes do que o ficheiro tem (cauda truncada).
    Truncated { lsn: u64, offset: u64 },
}

/// Varre os blocos em streaming — um bloco em RAM de cada vez. O `record_len`
/// vem do disco e portanto nao e confiavel: e confrontado com os bytes que
/// restam **antes** de qualquer alocacao.
///
/// Chama `f(header, record)` por bloco fisicamente integro; devolver `false`
/// interrompe (early-exit do LIMIT do HQL). A validacao CRIPTOGRAFICA e do
/// chamador — aqui e so enquadramento fisico.
pub(crate) fn scan_blocks<F>(db_path: &str, mut f: F) -> std::io::Result<ScanOutcome>
where
    F: FnMut(&BlockHeader, &[u8]) -> bool,
{
    use std::io::{BufReader, Read as _};
    let file = match File::open(db_path) {
        Ok(f) => f,
        Err(_) => return Ok(ScanOutcome::NoFile),
    };
    let file_size = file.metadata()?.len();
    let mut r = BufReader::new(file);

    let mut master = [0u8; MASTER_HEADER_SIZE];
    if r.read_exact(&mut master).is_err() {
        return Ok(ScanOutcome::BadMaster);
    }
    if &master[..4] == LEGACY_MASTER_MAGIC {
        return Ok(ScanOutcome::LegacyGeneration);
    }
    if &master[..4] != MASTER_MAGIC {
        return Ok(ScanOutcome::BadMaster);
    }
    if u32::from_be_bytes([master[4], master[5], master[6], master[7]]) != GENERATION {
        return Ok(ScanOutcome::BadMaster);
    }

    let mut pos: u64 = MASTER_HEADER_SIZE as u64;
    let mut header = [0u8; BLOCK_HEADER_SIZE];
    let mut record = Vec::new();
    loop {
        // Menos de um cabecalho restante = fim limpo.
        if file_size - pos < BLOCK_HEADER_SIZE as u64 {
            return Ok(ScanOutcome::Done);
        }
        r.read_exact(&mut header)?;
        let offset = pos;
        pos += BLOCK_HEADER_SIZE as u64;
        if &header[..4] != BLOCK_MAGIC {
            return Ok(ScanOutcome::BadBlockMagic { offset });
        }
        let stored_crc = u32::from_be_bytes([header[80], header[81], header[82], header[83]]);
        if crc32c(&header[..80]) != stored_crc {
            return Ok(ScanOutcome::BadBlockHeaderCrc { offset });
        }
        let mut lsn_bytes = [0u8; 8];
        lsn_bytes.copy_from_slice(&header[4..12]);
        let lsn = u64::from_be_bytes(lsn_bytes);
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&header[12..44]);
        let mut chain_root = [0u8; 32];
        chain_root.copy_from_slice(&header[44..76]);
        let record_len = u32::from_be_bytes([header[76], header[77], header[78], header[79]]);

        if record_len as u64 > file_size - pos {
            return Ok(ScanOutcome::Truncated { lsn, offset });
        }
        if record_len as usize > hfb2::MAX_RECORD_LEN {
            return Ok(ScanOutcome::Truncated { lsn, offset });
        }
        record.clear();
        record.resize(record_len as usize, 0);
        r.read_exact(&mut record)?;
        pos += record_len as u64;

        let parsed = BlockHeader {
            lsn,
            leaf,
            chain_root,
            record_len,
        };
        if !f(&parsed, &record) {
            return Ok(ScanOutcome::Done);
        }
    }
}

/// Resultado de uma exportacao (ver [`export_facts`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    /// Blocos varridos no ficheiro.
    pub scanned: u64,
    /// Fatos entregues ao callback.
    pub exported: u64,
    /// Blocos cujo registo falhou o CRC-32C interno.
    pub torn: u64,
    /// Blocos cujo registo nao descodificou (estrutura ou semantica).
    pub undecodable: u64,
    /// Registos integros de um tipo que este binario nao sabe interpretar.
    /// Contados a parte: nao sao corrupcao, e engoli-los em silencio seria
    /// perda invisivel.
    pub skipped: u64,
    /// Ultimo LSN entregue — ponto de retoma.
    pub last_lsn: u64,
}

/// Um registo exportado. O log e partilhado por mais do que um tipo de registo;
/// quem consome tem de saber o que recebeu em vez de assumir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportedRecord {
    Fact(serde_json::Value),
    TelemetryHealth {
        identity: hfb2::SecurityIdentity,
        /// Envelope `heraclitus-telemetry-health/1.0`, tal como foi gravado.
        envelope: String,
    },
}

impl ExportedRecord {
    pub fn record_type(&self) -> &'static str {
        match self {
            ExportedRecord::Fact(_) => "OperationalFact",
            ExportedRecord::TelemetryHealth { .. } => "TelemetryHealth",
        }
    }
}

/// Exporta todos os registos com LSN > `from_lsn`, em streaming.
///
/// Nenhum campo persistido desaparece aqui: o Fato devolvido traz identidade de
/// seguranca, identidade de schema, extensoes conhecidas nos seus lugares
/// semanticos e as desconhecidas em `fact.extensions`.
pub fn export_records<F>(db_path: &str, from_lsn: u64, mut f: F) -> std::io::Result<ExportStats>
where
    F: FnMut(u64, ExportedRecord) -> bool,
{
    let mut st = ExportStats::default();
    scan_blocks(db_path, |header, record| {
        st.scanned += 1;
        if header.lsn <= from_lsn {
            return true;
        }
        let view = match hfb2::RecordView::parse(record) {
            Ok(view) => view,
            Err(Hfb2Error::Crc { .. }) => {
                st.torn += 1;
                return true;
            }
            Err(_) => {
                st.undecodable += 1;
                return true;
            }
        };
        let exported = match view.record_type {
            hfb2::RECORD_TYPE_OPERATIONAL_FACT => match hfb2::decode_fact(record) {
                Ok(mut fact) => {
                    fact["fact.integrity"] = serde_json::json!({
                        "leaf_hash": to_hex(&header.leaf),
                        "merkle_root_anchor": to_hex(&header.chain_root),
                    });
                    ExportedRecord::Fact(fact)
                }
                Err(_) => {
                    st.undecodable += 1;
                    return true;
                }
            },
            hfb2::RECORD_TYPE_TELEMETRY_HEALTH => match hfb2::decode_health_event(record) {
                Ok((identity, envelope)) => ExportedRecord::TelemetryHealth { identity, envelope },
                Err(_) => {
                    st.undecodable += 1;
                    return true;
                }
            },
            // Tipo de registo que este binario nao conhece: NAO e ilegivel — a
            // estrutura e a integridade ja foram afirmadas. So nao e exportavel
            // por quem nao lhe sabe a semantica.
            _ => {
                st.skipped += 1;
                return true;
            }
        };
        st.exported += 1;
        st.last_lsn = header.lsn;
        f(header.lsn, exported)
    })?;
    Ok(st)
}

/// Exporta apenas os Fatos Operacionais — a superficie que a ponte consome.
pub fn export_facts<F>(db_path: &str, from_lsn: u64, mut f: F) -> std::io::Result<ExportStats>
where
    F: FnMut(u64, serde_json::Value) -> bool,
{
    export_records(db_path, from_lsn, |lsn, record| match record {
        ExportedRecord::Fact(fact) => f(lsn, fact),
        _ => true,
    })
}

// ---------------------------------------------------------------------------
// FactStore
// ---------------------------------------------------------------------------

pub struct FactStore {
    pub(crate) db_path: String,
    anchor_path: String,
    pub_path: String,
    /// Ultimo LSN **durave**l. So avanca depois do fsync.
    pub current_lsn: u64,
    /// Raiz da cadeia Merkle correspondente a `current_lsn`.
    trusted_root: [u8; 32],
    signing_key: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub status: String,
    pub facts: usize,
    pub root: String,
    pub message: String,
}

/// Resultado de uma escrita em lote. O supervisor precisa de saber quantos
/// Fatos ficaram DURAVEIS para poder avancar o checkpoint da fonte sem
/// arriscar perder o que nao chegou ao disco.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchOutcome {
    pub first_lsn: u64,
    pub last_lsn: u64,
    pub persisted: usize,
}

/// Verifica um `.hdb` sem construir um `FactStore` (nao toca na chave privada).
pub fn verify_file(db_path: &str) -> VerifyResult {
    let verifier = FactStore {
        db_path: db_path.to_string(),
        anchor_path: format!("{db_path}.anchor"),
        pub_path: format!("{db_path}.pub"),
        current_lsn: BASE_LSN,
        trusted_root: hfb2::EMPTY_ROOT,
        signing_key: SigningKey::from_bytes(&[0u8; 32]),
    };
    verifier.verify()
}

/// Conteudo do ficheiro de ancora. Raiz, LSN e assinatura vivem no MESMO
/// ficheiro: com dois ficheiros existia um estado intermedio em que a raiz era
/// nova e a assinatura velha, e o banco reabria a acusar adulteracao.
struct Anchor {
    root: [u8; 32],
    lsn: u64,
    signature: [u8; 64],
}

impl Anchor {
    fn encode(&self) -> Vec<u8> {
        format!(
            "generation={GENERATION}\nroot={}\nlsn={}\nsig={}\n",
            to_hex(&self.root),
            self.lsn,
            to_hex(&self.signature)
        )
        .into_bytes()
    }

    fn parse(text: &str) -> Option<Self> {
        let mut fields = std::collections::BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        if fields.get("generation")? != &GENERATION.to_string() {
            return None;
        }
        let root = <[u8; 32]>::try_from(from_hex(fields.get("root")?)?.as_slice()).ok()?;
        let lsn = fields.get("lsn")?.parse().ok()?;
        let signature = <[u8; 64]>::try_from(from_hex(fields.get("sig")?)?.as_slice()).ok()?;
        Some(Anchor {
            root,
            lsn,
            signature,
        })
    }
}

/// Bloco pronto a gravar, com os valores derivados que o descrevem. E o
/// resultado de uma funcao PURA: montar o bloco nao toca no estado do store,
/// para que um erro de I/O nao deixe o `FactStore` a descrever um bloco que
/// nunca chegou ao disco.
struct EncodedBlock {
    bytes: Vec<u8>,
    leaf: [u8; 32],
    root: [u8; 32],
}

/// Mensagem que a ancora assina. Inclui o LSN para que uma ancora antiga nao
/// possa ser reapresentada como valida para um log mais curto.
fn anchor_message(root: &[u8; 32], lsn: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(hfb2::domain::ANCHOR.len() + 41);
    message.extend_from_slice(hfb2::domain::ANCHOR);
    message.push(0x00);
    message.extend_from_slice(root);
    message.extend_from_slice(&lsn.to_be_bytes());
    message
}

impl FactStore {
    pub fn new(db_path: &str) -> std::io::Result<Self> {
        let existed = std::path::Path::new(db_path).exists();
        if existed {
            // Recusa explicita antes de qualquer outra coisa: a geracao antiga
            // nao e interpretada "com cuidado", e simplesmente recusada.
            Self::require_supported_generation(db_path)?;
        } else {
            let mut f = File::create(db_path)?;
            f.write_all(MASTER_MAGIC)?;
            f.write_all(&GENERATION.to_be_bytes())?;
            f.sync_all()?;
        }
        let key_path = format!("{db_path}.key");
        let pub_path = format!("{db_path}.pub");
        let signing_key = load_or_create_key(&key_path, &pub_path)?;
        let mut db = Self {
            db_path: db_path.to_string(),
            anchor_path: format!("{db_path}.anchor"),
            pub_path,
            current_lsn: BASE_LSN,
            trusted_root: hfb2::EMPTY_ROOT,
            signing_key,
        };
        if existed {
            db.recover()?;
            let verified = db.verify();
            if verified.status != "INTEG_OK" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "recusa abrir .hdb nao integro ({}): {}",
                        verified.status, verified.message
                    ),
                ));
            }
        } else {
            // Um banco vazio tambem tem ancora assinada: sem isso, fechar antes
            // do primeiro Fato e reabrir pareceria adulteracao por ausencia.
            db.persist_anchor()?;
        }
        Ok(db)
    }

    /// Le so o cabecalho mestre e decide se este runtime pode abrir o ficheiro.
    fn require_supported_generation(db_path: &str) -> std::io::Result<()> {
        use std::io::Read as _;
        let mut master = [0u8; MASTER_HEADER_SIZE];
        let mut file = File::open(db_path)?;
        let read = file.read(&mut master)?;
        if read < MASTER_HEADER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{db_path}: cabecalho mestre incompleto ({read} bytes)"),
            ));
        }
        if &master[..4] == LEGACY_MASTER_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unsupported database generation: HDB1\nExpected: HDB2\n\
                     ({db_path}) — nao ha migracao automatica; ver md/HDB2-HFB2.md"
                ),
            ));
        }
        if &master[..4] != MASTER_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{db_path}: cabecalho mestre desconhecido"),
            ));
        }
        let generation = u32::from_be_bytes([master[4], master[5], master[6], master[7]]);
        if generation != GENERATION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unsupported database generation: HDB{generation}\nExpected: HDB{GENERATION}"
                ),
            ));
        }
        Ok(())
    }

    /// Reconstroi `current_lsn` + `trusted_root` a partir do disco.
    ///
    /// A folha e **recalculada** dos bytes gravados, nunca lida do cabecalho do
    /// bloco: confiar no valor gravado seria deixar o atacante escolher a folha.
    fn recover(&mut self) -> std::io::Result<()> {
        let mut chain = hfb2::EMPTY_ROOT;
        let mut last_lsn = BASE_LSN;
        let mut stop = None;
        let outcome = scan_blocks(&self.db_path, |header, record| {
            let leaf = match hfb2::record_leaf(record) {
                Ok(leaf) => leaf,
                Err(error) => {
                    stop = Some(format!("LSN {}: {error}", header.lsn));
                    return false;
                }
            };
            chain = hfb2::fold_chain(&chain, &leaf);
            last_lsn = header.lsn;
            true
        })?;
        // O resultado da varredura NAO e descartado: uma cauda truncada ou um
        // magic partido tem de chegar a quem abre o banco, senao o store abre
        // com um LSN atrasado e volta a usar LSNs ja gravados.
        match outcome {
            ScanOutcome::Done | ScanOutcome::NoFile => {}
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varredura interrompida: {other:?}"),
                ))
            }
        }
        if let Some(message) = stop {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("registo ilegivel durante a recuperacao — {message}"),
            ));
        }
        self.current_lsn = last_lsn;
        self.trusted_root = chain;
        Ok(())
    }

    fn persist_anchor(&self) -> std::io::Result<()> {
        let signature = self
            .signing_key
            .sign(&anchor_message(&self.trusted_root, self.current_lsn));
        let anchor = Anchor {
            root: self.trusted_root,
            lsn: self.current_lsn,
            signature: signature.to_bytes(),
        };
        write_atomic(&self.anchor_path, &anchor.encode())
    }

    /// Raiz atual em hexadecimal.
    pub fn trusted_root_hex(&self) -> String {
        to_hex(&self.trusted_root)
    }

    /// Caminho da chave publica — a ponte deriva dela a identidade da origem.
    pub fn pub_path(&self) -> &str {
        &self.pub_path
    }

    /// Monta um bloco completo para `lsn`, a partir da raiz `previous_root`.
    ///
    /// **Nao muta estado.** No HDB1 o LSN e a raiz avancavam antes de qualquer
    /// I/O e nao havia rollback: um unico ENOSPC transitorio deixava o store a
    /// descrever um bloco que nunca chegou ao disco, e o banco ficava
    /// permanentemente irrecuperavel. Aqui o estado so avanca depois do fsync.
    fn encode_block(
        fact: &Value,
        lsn: u64,
        previous_root: &[u8; 32],
    ) -> Result<EncodedBlock, Hfb2Error> {
        Self::encode_block_from_record(hfb2::encode_fact(fact, lsn)?, lsn, previous_root)
    }

    /// Mesma coisa para um registo ja codificado (Fato ou saude do sensor).
    ///
    /// A folha vem da vista do PROPRIO registo — nunca de um schema assumido:
    /// calcula-la com uma identidade de schema fixa produziria, para um tipo de
    /// registo novo, uma folha que o `verify()` jamais reproduziria.
    fn encode_block_from_record(
        record: Vec<u8>,
        lsn: u64,
        previous_root: &[u8; 32],
    ) -> Result<EncodedBlock, Hfb2Error> {
        let leaf = hfb2::RecordView::parse(&record)?.leaf();
        let root = hfb2::fold_chain(previous_root, &leaf);

        let mut block = Vec::with_capacity(BLOCK_HEADER_SIZE + record.len());
        block.extend_from_slice(BLOCK_MAGIC);
        block.extend_from_slice(&lsn.to_be_bytes());
        block.extend_from_slice(&leaf);
        block.extend_from_slice(&root);
        block.extend_from_slice(&(record.len() as u32).to_be_bytes());
        let header_crc = crc32c(&block);
        block.extend_from_slice(&header_crc.to_be_bytes());
        debug_assert_eq!(block.len(), BLOCK_HEADER_SIZE);
        block.extend_from_slice(&record);
        Ok(EncodedBlock {
            bytes: block,
            leaf,
            root,
        })
    }

    /// Anota no Fato o que so se sabe depois de gravar.
    fn stamp(fact: &mut Value, lsn: u64, leaf: &[u8; 32], root: &[u8; 32]) {
        fact["fact.time"]["log_sequence_number"] = Value::from(lsn);
        fact["fact.integrity"] = serde_json::json!({
            "leaf_hash": to_hex(leaf),
            "merkle_root_anchor": to_hex(root),
        });
    }

    /// Grava um Fato e ancora a raiz. Durave l antes de devolver.
    pub fn write_fact(&mut self, fact: &mut Value) -> std::io::Result<u64> {
        let outcome = self.write_batch(std::slice::from_mut(fact))?;
        Ok(outcome.last_lsn)
    }

    /// Grava um lote com um unico `write_all` e um unico fsync.
    ///
    /// O lote inteiro e montado em memoria antes de tocar no disco: assim nunca
    /// se escreve meio bloco por causa do enchimento de um buffer. O estado so
    /// avanca depois do fsync, portanto um erro a meio nao deixa o store a
    /// descrever Fatos que nao existem.
    pub fn write_batch(&mut self, facts: &mut [Value]) -> std::io::Result<BatchOutcome> {
        if facts.is_empty() {
            return Ok(BatchOutcome {
                first_lsn: self.current_lsn,
                last_lsn: self.current_lsn,
                persisted: 0,
            });
        }
        let mut buffer = Vec::new();
        let mut root = self.trusted_root;
        let mut stamps = Vec::with_capacity(facts.len());
        let first_lsn = self.current_lsn + 1;
        for (index, fact) in facts.iter().enumerate() {
            let lsn = first_lsn + index as u64;
            let encoded = Self::encode_block(fact, lsn, &root).map_err(std::io::Error::other)?;
            buffer.extend_from_slice(&encoded.bytes);
            stamps.push((lsn, encoded.leaf, encoded.root));
            root = encoded.root;
        }

        let mut file = OpenOptions::new().append(true).open(&self.db_path)?;
        file.write_all(&buffer)?;
        file.sync_all()?;

        // Ponto de nao retorno: a partir daqui os Fatos existem no disco.
        let last_lsn = first_lsn + facts.len() as u64 - 1;
        self.current_lsn = last_lsn;
        self.trusted_root = root;
        self.persist_anchor()?;
        for (fact, (lsn, leaf, new_root)) in facts.iter_mut().zip(stamps.iter()) {
            Self::stamp(fact, *lsn, leaf, new_root);
        }
        Ok(BatchOutcome {
            first_lsn,
            last_lsn,
            persisted: facts.len(),
        })
    }

    /// Grava um evento de Telemetry Health no MESMO log dos Fatos.
    ///
    /// Partilhar o log e o ponto: a saude do sensor entra na mesma cadeia
    /// Merkle e na mesma ancora Ed25519 que a evidencia. Um sensor que queira
    /// esconder que esteve cego teria de partir a cadeia para o fazer.
    pub fn write_health_event(
        &mut self,
        identity: &hfb2::SecurityIdentity,
        emitted_at_micros: i64,
        envelope_json: &str,
    ) -> std::io::Result<u64> {
        let lsn = self.current_lsn + 1;
        let event_id = uuid::Uuid::now_v7().into_bytes();
        let record =
            hfb2::encode_health_event(identity, event_id, emitted_at_micros, lsn, envelope_json)
                .map_err(std::io::Error::other)?;
        let encoded = Self::encode_block_from_record(record, lsn, &self.trusted_root)
            .map_err(std::io::Error::other)?;

        let mut file = OpenOptions::new().append(true).open(&self.db_path)?;
        file.write_all(&encoded.bytes)?;
        file.sync_all()?;
        self.current_lsn = lsn;
        self.trusted_root = encoded.root;
        self.persist_anchor()?;
        Ok(lsn)
    }

    /// Grava localmente (lider Raft) e devolve `(lsn, raiz, bytes do bloco)`
    /// para que o bloco seja replicado byte a byte aos followers.
    pub fn commit_local(&mut self, fact: &mut Value) -> std::io::Result<(u64, String, Vec<u8>)> {
        let lsn = self.current_lsn + 1;
        let encoded =
            Self::encode_block(fact, lsn, &self.trusted_root).map_err(std::io::Error::other)?;
        let mut file = OpenOptions::new().append(true).open(&self.db_path)?;
        file.write_all(&encoded.bytes)?;
        file.sync_all()?; // lider Raft: duravel ANTES de replicar/ackar.
        self.current_lsn = lsn;
        self.trusted_root = encoded.root;
        self.persist_anchor()?;
        Self::stamp(fact, lsn, &encoded.leaf, &encoded.root);
        Ok((lsn, to_hex(&encoded.root), encoded.bytes))
    }

    /// Follower Raft: valida um bloco replicado e aplica-o.
    ///
    /// Ordem: estrutura do bloco -> CRC do cabecalho -> registo HFB2 (estrutura
    /// + CRC) -> LSN sequencial -> folha recalculada -> cadeia Merkle.
    pub fn append_replicated_block(
        &mut self,
        block: &[u8],
    ) -> Result<u64, crate::error::HeraclitusError> {
        use crate::error::HeraclitusError::DatabaseCorruption;
        if block.len() < BLOCK_HEADER_SIZE || &block[..4] != BLOCK_MAGIC {
            return Err(DatabaseCorruption("bloco invalido".into()));
        }
        let stored_crc = u32::from_be_bytes([block[80], block[81], block[82], block[83]]);
        if crc32c(&block[..80]) != stored_crc {
            return Err(DatabaseCorruption(
                "CRC-32C do cabecalho do bloco falhou".into(),
            ));
        }
        let mut lsn_bytes = [0u8; 8];
        lsn_bytes.copy_from_slice(&block[4..12]);
        let lsn = u64::from_be_bytes(lsn_bytes);
        let record_len = u32::from_be_bytes([block[76], block[77], block[78], block[79]]) as usize;
        if BLOCK_HEADER_SIZE + record_len != block.len() {
            return Err(DatabaseCorruption("tamanho de bloco inconsistente".into()));
        }
        let record = &block[BLOCK_HEADER_SIZE..];

        let view = hfb2::RecordView::parse(record).map_err(|error| {
            DatabaseCorruption(format!("registo invalido no LSN {lsn}: {error}"))
        })?;
        if view.lsn != lsn {
            return Err(DatabaseCorruption(format!(
                "LSN do bloco ({lsn}) diverge do registo ({})",
                view.lsn
            )));
        }
        if lsn != self.current_lsn + 1 {
            return Err(DatabaseCorruption(format!(
                "LSN fora de ordem: esperado {}, recebido {lsn}",
                self.current_lsn + 1
            )));
        }

        let leaf = view.leaf();
        if leaf != block[12..44] {
            return Err(DatabaseCorruption(format!("folha divergente no LSN {lsn}")));
        }
        let root = hfb2::fold_chain(&self.trusted_root, &leaf);
        if root != block[44..76] {
            return Err(DatabaseCorruption(format!(
                "cadeia Merkle divergente no LSN {lsn}"
            )));
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.db_path)
            .map_err(crate::error::HeraclitusError::Io)?;
        file.write_all(block)
            .map_err(crate::error::HeraclitusError::Io)?;
        file.sync_all().map_err(crate::error::HeraclitusError::Io)?;
        self.current_lsn = lsn;
        self.trusted_root = root;
        // A ancora e o que autentica o log: um follower que falhe a grava-la
        // nao pode ackar como se estivesse tudo bem.
        self.persist_anchor()
            .map_err(crate::error::HeraclitusError::Io)?;
        Ok(lsn)
    }

    /// Reconstroi a cadeia a partir do disco e deteta adulteracao.
    ///
    /// Nao desserializa o Fato para verificar: a folha e calculada sobre os
    /// bytes canonicos gravados. Um registo com uma extensao que este binario
    /// nao conhece continua a verificar.
    pub fn verify(&self) -> VerifyResult {
        let anchor = fs::read_to_string(&self.anchor_path)
            .ok()
            .as_deref()
            .and_then(Anchor::parse);

        let mut chain = hfb2::EMPTY_ROOT;
        let mut count = 0usize;
        let mut last_lsn = BASE_LSN;
        let mut violation: Option<String> = None;
        // Raiz no ponto que a ancora diz ter assinado — permite distinguir
        // "ancora atrasada sobre um log intacto" de "log adulterado".
        let anchor_lsn = anchor.as_ref().map(|a| a.lsn);
        let mut chain_at_anchor: Option<[u8; 32]> = None;

        let outcome = scan_blocks(&self.db_path, |header, record| {
            // --- Camada fisica: estrutura + CRC-32C do registo ---
            let view = match hfb2::RecordView::parse(record) {
                Ok(view) => view,
                Err(error) => {
                    violation = Some(format!("LSN {}: {error}", header.lsn));
                    return false;
                }
            };
            if view.lsn != header.lsn {
                violation = Some(format!(
                    "LSN {}: o registo declara LSN {}",
                    header.lsn, view.lsn
                ));
                return false;
            }
            if header.lsn != last_lsn + 1 {
                violation = Some(format!(
                    "LSN fora de sequencia: esperado {}, encontrado {}",
                    last_lsn + 1,
                    header.lsn
                ));
                return false;
            }

            // --- Camada criptografica: folha recalculada + cadeia ---
            let leaf = view.leaf();
            if leaf != header.leaf {
                violation = Some(format!("folha BLAKE3 adulterada no LSN {}", header.lsn));
                return false;
            }
            chain = hfb2::fold_chain(&chain, &leaf);
            if chain != header.chain_root {
                violation = Some(format!("cadeia Merkle quebrada no LSN {}", header.lsn));
                return false;
            }
            last_lsn = header.lsn;
            if anchor_lsn == Some(header.lsn) {
                chain_at_anchor = Some(chain);
            }
            count += 1;
            true
        });

        let root_hex = to_hex(&chain);
        if let Some(message) = violation {
            return VerifyResult {
                status: "VIOLATED".into(),
                facts: count,
                root: String::new(),
                message,
            };
        }
        match outcome {
            Err(e) => VerifyResult {
                status: "ERROR".into(),
                facts: count,
                root: String::new(),
                message: format!("Erro de leitura: {e}"),
            },
            Ok(ScanOutcome::NoFile) => VerifyResult {
                status: "ERROR".into(),
                facts: 0,
                root: String::new(),
                message: "Arquivo de banco nao encontrado.".into(),
            },
            Ok(ScanOutcome::LegacyGeneration) => VerifyResult {
                status: "UNSUPPORTED".into(),
                facts: 0,
                root: String::new(),
                message: "Unsupported database generation: HDB1\nExpected: HDB2".into(),
            },
            Ok(ScanOutcome::BadMaster) => VerifyResult {
                status: "CORRUPTED".into(),
                facts: 0,
                root: String::new(),
                message: "Cabecalho mestre invalido.".into(),
            },
            Ok(ScanOutcome::BadBlockMagic { offset }) => VerifyResult {
                status: "VIOLATED".into(),
                facts: count,
                root: String::new(),
                message: format!("Assinatura de bloco corrompida no byte {offset}"),
            },
            Ok(ScanOutcome::BadBlockHeaderCrc { offset }) => VerifyResult {
                status: "VIOLATED".into(),
                facts: count,
                root: String::new(),
                message: format!("CRC-32C do cabecalho falhou no byte {offset}"),
            },
            Ok(ScanOutcome::Truncated { lsn, offset }) => VerifyResult {
                status: "VIOLATED".into(),
                facts: count,
                root: String::new(),
                message: format!("Registo truncado no LSN {lsn} (byte {offset})"),
            },
            Ok(ScanOutcome::Done) => {
                // A assinatura prova o que a ancora DIZ; a comparacao com a
                // cadeia recalculada prova que o que ela diz continua a valer.
                if let Some(message) = self.verify_anchor_signature(anchor.as_ref()) {
                    return VerifyResult {
                        status: "VIOLATED".into(),
                        facts: count,
                        root: root_hex,
                        message,
                    };
                }
                if let Some(anchor) = &anchor {
                    match anchor.lsn.cmp(&last_lsn) {
                        std::cmp::Ordering::Equal if anchor.root == chain => {}
                        std::cmp::Ordering::Less if chain_at_anchor == Some(anchor.root) => {
                            // O log tem blocos alem do ultimo ponto assinado.
                            // Acontece num corte de energia entre o fsync do
                            // bloco e a gravacao da ancora — e e tambem o que se
                            // veria se alguem tivesse acrescentado blocos sem a
                            // chave. As duas hipoteses sao indistinguiveis a
                            // partir do ficheiro, portanto isto NAO se resolve
                            // sozinho: precisa de uma decisao de quem opera.
                            return VerifyResult {
                                status: "ANCHOR_BEHIND".into(),
                                facts: count,
                                root: root_hex,
                                message: format!(
                                    "log intacto ate ao LSN {last_lsn}, ancora assinada no LSN {} \
                                     ({} bloco(s) por assinar)",
                                    anchor.lsn,
                                    last_lsn - anchor.lsn
                                ),
                            };
                        }
                        std::cmp::Ordering::Greater => {
                            return VerifyResult {
                                status: "VIOLATED".into(),
                                facts: count,
                                root: root_hex,
                                message: format!(
                                    "Ancora descreve LSN {}, o log termina em {last_lsn}",
                                    anchor.lsn
                                ),
                            }
                        }
                        _ => {
                            return VerifyResult {
                                status: "VIOLATED".into(),
                                facts: count,
                                root: root_hex,
                                message: "Raiz divergente da ancora.".into(),
                            }
                        }
                    }
                }
                VerifyResult {
                    status: "INTEG_OK".into(),
                    facts: count,
                    root: root_hex,
                    message: String::new(),
                }
            }
        }
    }

    /// Confere a assinatura Ed25519 sobre o par `(raiz, lsn)` que a propria
    /// ancora declara. Devolve `Some(mensagem)` se houver violacao.
    fn verify_anchor_signature(&self, anchor: Option<&Anchor>) -> Option<String> {
        let pub_hex = match fs::read_to_string(&self.pub_path) {
            Ok(s) => s,
            Err(_) => {
                return Some("chave publica ed25519 ausente — cadeia Merkle nao autenticada".into())
            }
        };
        let key = from_hex(&pub_hex)
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok());
        let key = match key {
            Some(key) => key,
            None => return Some("chave publica ed25519 ilegivel".into()),
        };
        let anchor = match anchor {
            Some(anchor) => anchor,
            None => return Some("ancora ausente ou ilegivel".into()),
        };
        match key.verify(
            &anchor_message(&anchor.root, anchor.lsn),
            &Signature::from_bytes(&anchor.signature),
        ) {
            Ok(()) => None,
            Err(_) => Some("assinatura ed25519 da ancora invalida — adulteracao".into()),
        }
    }

    /// Simula um atacante a alterar um byte do registo do LSN indicado.
    /// Usado pelos testes e pela demo para provar que a deteccao funciona.
    pub fn inject_malicious_tamper(&self, target_lsn: u64) -> std::io::Result<bool> {
        let mut data = fs::read(&self.db_path)?;
        let mut pos = MASTER_HEADER_SIZE;
        while pos + BLOCK_HEADER_SIZE <= data.len() {
            let header = &data[pos..pos + BLOCK_HEADER_SIZE];
            let mut lsn_bytes = [0u8; 8];
            lsn_bytes.copy_from_slice(&header[4..12]);
            let lsn = u64::from_be_bytes(lsn_bytes);
            let record_len =
                u32::from_be_bytes([header[76], header[77], header[78], header[79]]) as usize;
            let start = pos + BLOCK_HEADER_SIZE;
            if start + record_len > data.len() {
                return Ok(false);
            }
            if lsn == target_lsn {
                // Dentro do core do registo: o CRC do registo passa a falhar e
                // a folha recalculada deixa de bater. As duas camadas acusam.
                let offset = start + hfb2::FIXED_HEADER_LEN;
                if offset < start + record_len {
                    data[offset] ^= 0x01;
                    fs::write(&self.db_path, &data)?;
                    return Ok(true);
                }
            }
            pos = start + record_len;
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
        let p =
            std::env::temp_dir().join(format!("forge_{}_{}_{}.hdb", tag, std::process::id(), n));
        let s = p.to_str().unwrap().to_string();
        for ext in ["", ".anchor", ".anchor.tmp", ".key", ".pub"] {
            let _ = fs::remove_file(format!("{s}{ext}"));
        }
        s
    }

    fn fact(action: &str) -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.datasource": {
                "tenant_id": "gov.br/orgao-a",
                "datasource_id": "teste://fixture",
                "sensor_id": "forge-teste"
            },
            "fact.identity": {"actor.id":"a","actor.name":"a","target.id":"t","source.ip":null},
            "fact.time": {"system_timestamp": 1_782_467_794_979_937i64, "log_sequence_number": 0u64},
            "fact.behavior": {"class":"c","action":action,"risk_level":"Medium"},
            "fact.evidence": {
                "raw_observation_hash": "b3:9611cd00aabbccddeeff00112233445566778899aabbccddeeff001122334455",
                "carimbo_tempo_legal": "icp"
            },
            "fact.lineage": {"transformation_steps":["parse"],"input_source":"pg","matched_rule":"r"},
            "fact.confidence": 0.9,
            "fact.knowledge_version":"k-v1","fact.reasoning_version":"r-v6","fact.ontology_version":"v9"
        })
    }

    // -- geracao do ficheiro -------------------------------------------------

    #[test]
    fn a_new_store_declares_the_hdb2_generation() {
        let path = tmp_path("gen");
        let db = FactStore::new(&path).unwrap();
        assert_eq!(db.verify().status, "INTEG_OK");
        let master = fs::read(&path).unwrap();
        assert_eq!(&master[..4], MASTER_MAGIC);
        assert_eq!(
            u32::from_be_bytes([master[4], master[5], master[6], master[7]]),
            GENERATION
        );
    }

    #[test]
    fn a_legacy_hdb1_file_is_refused_by_name() {
        // Nao ha migracao automatica e nao ha reinterpretacao silenciosa: o
        // formato antigo e nomeado e recusado.
        let path = tmp_path("legacy");
        let mut file = File::create(&path).unwrap();
        file.write_all(LEGACY_MASTER_MAGIC).unwrap();
        file.write_all(&7u32.to_be_bytes()).unwrap();
        drop(file);

        let error = FactStore::new(&path)
            .err()
            .expect("HDB1 tem de ser recusado");
        let message = error.to_string();
        assert!(
            message.contains("Unsupported database generation: HDB1"),
            "{message}"
        );
        assert!(message.contains("Expected: HDB2"), "{message}");
        assert_eq!(verify_file(&path).status, "UNSUPPORTED");
    }

    #[test]
    fn an_unknown_generation_number_is_refused() {
        let path = tmp_path("gen99");
        let mut file = File::create(&path).unwrap();
        file.write_all(MASTER_MAGIC).unwrap();
        file.write_all(&99u32.to_be_bytes()).unwrap();
        drop(file);
        let message = FactStore::new(&path).err().expect("recusa").to_string();
        assert!(message.contains("HDB99"), "{message}");
    }

    // -- round-trip sem perda ------------------------------------------------

    #[test]
    fn every_persisted_field_comes_back_out_of_the_store() {
        let path = tmp_path("roundtrip");
        let mut db = FactStore::new(&path).unwrap();
        let mut written = fact("authentication.failure");
        written["fact.security"] = json!({"category": "authentication", "severity": 7});
        written["fact.extensions"] = json!([{"tag": "0xffff0003", "value_hex": "0badc0de"}]);
        db.write_fact(&mut written).unwrap();

        let mut read = Vec::new();
        export_facts(&path, 0, |_, fact| {
            read.push(fact);
            true
        })
        .unwrap();
        assert_eq!(read.len(), 1);
        let out = &read[0];

        assert_eq!(out["fact_id"], written["fact_id"]);
        assert_eq!(out["fact.datasource"], written["fact.datasource"]);
        assert_eq!(out["fact.behavior"], written["fact.behavior"]);
        assert_eq!(out["fact.security"], written["fact.security"]);
        assert_eq!(out["fact.extensions"][0]["tag"], "0xffff0003");
        assert_eq!(out["fact.extensions"][0]["value_hex"], "0badc0de");
        assert_eq!(out["fact.evidence"]["carimbo_tempo_legal"], "icp");
        assert_eq!(out["fact.confidence"], 0.9);
        assert_eq!(out["fact.schema"]["label"], "operational-fact/1.0");
        // A integridade vem do BLOCO, nao do registo — nao ha circularidade.
        assert_eq!(
            out["fact.integrity"]["leaf_hash"],
            written["fact.integrity"]["leaf_hash"]
        );
    }

    #[test]
    fn export_facts_yields_every_written_fact_in_lsn_order() {
        let path = tmp_path("export_all");
        let mut db = FactStore::new(&path).unwrap();
        for i in 0..5 {
            db.write_fact(&mut fact(&format!("a{i}"))).unwrap();
        }
        let mut seen = Vec::new();
        let stats = export_facts(&path, 0, |lsn, fact| {
            seen.push((
                lsn,
                fact["fact.behavior"]["action"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ));
            true
        })
        .unwrap();
        assert_eq!(stats.exported, 5);
        assert_eq!(stats.last_lsn, BASE_LSN + 5);
        assert_eq!(
            seen.iter().map(|(lsn, _)| *lsn).collect::<Vec<_>>(),
            (1..=5).map(|i| BASE_LSN + i).collect::<Vec<_>>()
        );
        assert_eq!(seen[4].1, "a4");
    }

    #[test]
    fn export_facts_from_lsn_resumes_without_duplicates() {
        let path = tmp_path("export_resume");
        let mut db = FactStore::new(&path).unwrap();
        for i in 0..4 {
            db.write_fact(&mut fact(&format!("a{i}"))).unwrap();
        }
        let mut seen = Vec::new();
        export_facts(&path, BASE_LSN + 2, |lsn, _| {
            seen.push(lsn);
            true
        })
        .unwrap();
        assert_eq!(seen, vec![BASE_LSN + 3, BASE_LSN + 4]);
    }

    // -- lote e estado -------------------------------------------------------

    #[test]
    fn a_batch_gets_consecutive_lsns_and_one_anchor() {
        let path = tmp_path("batch");
        let mut db = FactStore::new(&path).unwrap();
        let mut lote: Vec<Value> = (0..3).map(|i| fact(&format!("b{i}"))).collect();
        let outcome = db.write_batch(&mut lote).unwrap();
        assert_eq!(
            (outcome.first_lsn, outcome.last_lsn, outcome.persisted),
            (BASE_LSN + 1, BASE_LSN + 3, 3)
        );
        for (index, item) in lote.iter().enumerate() {
            assert_eq!(
                item["fact.time"]["log_sequence_number"],
                BASE_LSN + index as u64 + 1
            );
            assert!(item["fact.integrity"]["leaf_hash"].is_string());
        }
        assert_eq!(db.verify().status, "INTEG_OK");
    }

    #[test]
    fn a_failed_write_does_not_advance_the_chain() {
        // No HDB1 o LSN e a raiz avancavam ANTES do I/O e nao havia rollback:
        // um unico erro transitorio deixava o banco irrecuperavel para sempre.
        let path = tmp_path("rollback");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("antes")).unwrap();
        let lsn_before = db.current_lsn;
        let root_before = db.trusted_root_hex();

        fs::remove_file(&path).unwrap(); // o append passa a falhar
        assert!(db.write_fact(&mut fact("durante")).is_err());

        assert_eq!(db.current_lsn, lsn_before);
        assert_eq!(db.trusted_root_hex(), root_before);
    }

    #[test]
    fn an_empty_batch_changes_nothing() {
        let path = tmp_path("batch_vazio");
        let mut db = FactStore::new(&path).unwrap();
        let outcome = db.write_batch(&mut []).unwrap();
        assert_eq!(outcome.persisted, 0);
        assert_eq!(db.current_lsn, BASE_LSN);
    }

    #[test]
    fn a_fact_without_identity_is_refused_before_touching_the_disk() {
        let path = tmp_path("sem_identidade");
        let mut db = FactStore::new(&path).unwrap();
        let mut orphan = fact("x");
        orphan.as_object_mut().unwrap().remove("fact.datasource");
        assert!(db.write_fact(&mut orphan).is_err());
        assert_eq!(db.current_lsn, BASE_LSN);
        assert_eq!(db.verify().facts, 0);
    }

    // -- reabertura e integridade -------------------------------------------

    #[test]
    fn reopen_preserves_chain_and_verifies() {
        let path = tmp_path("reopen");
        let root = {
            let mut db = FactStore::new(&path).unwrap();
            for i in 0..3 {
                db.write_fact(&mut fact(&format!("a{i}"))).unwrap();
            }
            db.trusted_root_hex()
        };
        let reopened = FactStore::new(&path).unwrap();
        assert_eq!(reopened.current_lsn, BASE_LSN + 3);
        assert_eq!(reopened.trusted_root_hex(), root);
        assert_eq!(reopened.verify().status, "INTEG_OK");
    }

    #[test]
    fn tampering_with_a_record_is_detected() {
        let path = tmp_path("tamper");
        let mut db = FactStore::new(&path).unwrap();
        for i in 0..3 {
            db.write_fact(&mut fact(&format!("a{i}"))).unwrap();
        }
        assert!(db.inject_malicious_tamper(BASE_LSN + 2).unwrap());
        let verified = db.verify();
        assert_eq!(verified.status, "VIOLATED");
        assert!(
            verified.message.contains(&format!("LSN {}", BASE_LSN + 2)),
            "{}",
            verified.message
        );
    }

    #[test]
    fn rewriting_the_tenant_on_disk_breaks_the_leaf() {
        // O teste que justifica pôr a identidade no cabecalho autenticado em
        // vez de numa extensao protegida so por CRC. Aqui o atacante corrige
        // os DOIS CRC (registo e cabecalho do bloco) e mesmo assim e apanhado.
        let path = tmp_path("tenant");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        drop(db);

        let mut data = fs::read(&path).unwrap();
        let record_start = MASTER_HEADER_SIZE + BLOCK_HEADER_SIZE;
        let record_len = u32::from_be_bytes([
            data[MASTER_HEADER_SIZE + 76],
            data[MASTER_HEADER_SIZE + 77],
            data[MASTER_HEADER_SIZE + 78],
            data[MASTER_HEADER_SIZE + 79],
        ]) as usize;
        let identity_at = record_start + crate::hfb2::FIXED_HEADER_LEN;
        let original = String::from_utf8(data[identity_at..identity_at + 14].to_vec()).unwrap();
        assert_eq!(original, "gov.br/orgao-a");
        data[identity_at..identity_at + 14].copy_from_slice(b"gov.br/orgao-b");

        // Reparar o CRC do registo...
        let record_end = record_start + record_len;
        let crc = crc32c(&data[record_start..record_end - crate::hfb2::CRC_LEN]);
        data[record_end - crate::hfb2::CRC_LEN..record_end].copy_from_slice(&crc.to_be_bytes());
        // ...e o CRC do cabecalho do bloco.
        let header_crc = crc32c(&data[MASTER_HEADER_SIZE..MASTER_HEADER_SIZE + 80]);
        data[MASTER_HEADER_SIZE + 80..MASTER_HEADER_SIZE + 84]
            .copy_from_slice(&header_crc.to_be_bytes());
        fs::write(&path, &data).unwrap();

        let verified = verify_file(&path);
        assert_eq!(verified.status, "VIOLATED");
        assert!(verified.message.contains("folha"), "{}", verified.message);
        // E o banco recusa-se a abrir.
        assert!(FactStore::new(&path).is_err());
    }

    #[test]
    fn a_truncated_tail_fails_deterministically() {
        let path = tmp_path("truncado");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        db.write_fact(&mut fact("b")).unwrap();
        drop(db);

        let mut data = fs::read(&path).unwrap();
        data.truncate(data.len() - 20);
        fs::write(&path, &data).unwrap();

        let verified = verify_file(&path);
        assert_eq!(verified.status, "VIOLATED");
        assert!(
            verified.message.contains("truncado"),
            "{}",
            verified.message
        );
        assert_eq!(verified, verify_file(&path)); // deterministico
        assert!(FactStore::new(&path).is_err());
    }

    #[test]
    fn an_anchor_behind_the_log_is_named_not_called_tampering() {
        // Corte de energia entre o fsync do bloco e a gravacao da ancora. O
        // HDB1 chamava a isto "adulteracao" e transformava uma falta de luz
        // numa perda de servico permanente sem explicacao.
        let path = tmp_path("ancora_atrasada");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        let anchor_after_first = fs::read(format!("{path}.anchor")).unwrap();
        db.write_fact(&mut fact("b")).unwrap();
        drop(db);
        fs::write(format!("{path}.anchor"), &anchor_after_first).unwrap();

        let verified = verify_file(&path);
        assert_eq!(verified.status, "ANCHOR_BEHIND");
        assert!(
            verified.message.contains(&format!("LSN {}", BASE_LSN + 1)),
            "{}",
            verified.message
        );
        // Continua a NAO abrir: as duas hipoteses (corte de energia ou blocos
        // acrescentados por outrem) sao indistinguiveis a partir do ficheiro.
        assert!(FactStore::new(&path).is_err());
    }

    #[test]
    fn an_anchor_ahead_of_the_log_is_a_violation() {
        let path = tmp_path("ancora_adiantada");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        db.write_fact(&mut fact("b")).unwrap();
        let anchor = fs::read(format!("{path}.anchor")).unwrap();
        drop(db);

        // Remove o ultimo bloco mas mantem a ancora que o cobria.
        let data = fs::read(&path).unwrap();
        let record_len = u32::from_be_bytes([
            data[MASTER_HEADER_SIZE + 76],
            data[MASTER_HEADER_SIZE + 77],
            data[MASTER_HEADER_SIZE + 78],
            data[MASTER_HEADER_SIZE + 79],
        ]) as usize;
        fs::write(
            &path,
            &data[..MASTER_HEADER_SIZE + BLOCK_HEADER_SIZE + record_len],
        )
        .unwrap();
        fs::write(format!("{path}.anchor"), &anchor).unwrap();

        let verified = verify_file(&path);
        assert_eq!(verified.status, "VIOLATED");
    }

    #[test]
    fn tampered_anchor_signature_is_rejected() {
        let path = tmp_path("ancora_sig");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        drop(db);

        let anchor = fs::read_to_string(format!("{path}.anchor")).unwrap();
        let forged: String = anchor
            .lines()
            .map(|line| {
                if let Some(sig) = line.strip_prefix("sig=") {
                    let mut bytes: Vec<char> = sig.chars().collect();
                    bytes[0] = if bytes[0] == 'a' { 'b' } else { 'a' };
                    format!("sig={}", bytes.into_iter().collect::<String>())
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(format!("{path}.anchor"), forged).unwrap();

        let verified = verify_file(&path);
        assert_eq!(verified.status, "VIOLATED");
        assert!(
            verified.message.contains("assinatura"),
            "{}",
            verified.message
        );
    }

    #[test]
    fn a_foreign_public_key_is_rejected() {
        let path = tmp_path("chave_alheia");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        drop(db);

        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let outra = SigningKey::from_bytes(&seed);
        fs::write(
            format!("{path}.pub"),
            to_hex(outra.verifying_key().as_bytes()),
        )
        .unwrap();

        assert_eq!(verify_file(&path).status, "VIOLATED");
    }

    #[test]
    fn a_record_whose_block_lsn_disagrees_is_a_violation() {
        let path = tmp_path("lsn_divergente");
        let mut db = FactStore::new(&path).unwrap();
        db.write_fact(&mut fact("a")).unwrap();
        drop(db);

        let mut data = fs::read(&path).unwrap();
        data[MASTER_HEADER_SIZE + 4..MASTER_HEADER_SIZE + 12].copy_from_slice(&99u64.to_be_bytes());
        let header_crc = crc32c(&data[MASTER_HEADER_SIZE..MASTER_HEADER_SIZE + 80]);
        data[MASTER_HEADER_SIZE + 80..MASTER_HEADER_SIZE + 84]
            .copy_from_slice(&header_crc.to_be_bytes());
        fs::write(&path, &data).unwrap();

        assert_eq!(verify_file(&path).status, "VIOLATED");
    }

    // -- replicacao ----------------------------------------------------------

    #[test]
    fn a_replicated_block_is_accepted_and_its_tampering_is_not() {
        let leader_path = tmp_path("lider");
        let follower_path = tmp_path("seguidor");
        let mut leader = FactStore::new(&leader_path).unwrap();
        let mut follower = FactStore::new(&follower_path).unwrap();

        let (lsn, _, block) = leader.commit_local(&mut fact("a")).unwrap();
        assert_eq!(follower.append_replicated_block(&block).unwrap(), lsn);
        assert_eq!(follower.verify().status, "INTEG_OK");

        let (_, _, mut second) = leader.commit_local(&mut fact("b")).unwrap();
        let at = BLOCK_HEADER_SIZE + crate::hfb2::FIXED_HEADER_LEN;
        second[at] ^= 0x01;
        assert!(follower.append_replicated_block(&second).is_err());
        assert_eq!(follower.current_lsn, BASE_LSN + 1);
    }

    // -- verificacao sem semantica ------------------------------------------

    #[test]
    fn health_events_share_the_log_and_the_chain_with_facts() {
        // A saude do sensor entra na MESMA cadeia Merkle que a evidencia. E
        // esse o ponto: um sensor nao consegue esconder que esteve cego sem
        // partir a cadeia que assina os Fatos.
        let path = tmp_path("saude");
        let mut db = FactStore::new(&path).unwrap();
        let identity =
            hfb2::SecurityIdentity::new("gov.br/orgao-a", "teste://fixture", "forge-teste")
                .unwrap();

        db.write_fact(&mut fact("a")).unwrap();
        let health_lsn = db
            .write_health_event(&identity, 1_782_467_794_979_937, r#"{"schema":"x"}"#)
            .unwrap();
        db.write_fact(&mut fact("b")).unwrap();
        assert_eq!(db.verify().status, "INTEG_OK");

        let mut tipos = Vec::new();
        export_records(&path, 0, |lsn, record| {
            tipos.push((lsn, record.record_type()));
            if let ExportedRecord::TelemetryHealth { identity, envelope } = &record {
                assert_eq!(identity.tenant_id, "gov.br/orgao-a");
                assert_eq!(envelope, r#"{"schema":"x"}"#);
            }
            true
        })
        .unwrap();
        assert_eq!(
            tipos,
            vec![
                (BASE_LSN + 1, "OperationalFact"),
                (BASE_LSN + 2, "TelemetryHealth"),
                (BASE_LSN + 3, "OperationalFact"),
            ]
        );
        assert_eq!(health_lsn, BASE_LSN + 2);

        // E o exportador de Fatos continua a devolver so Fatos.
        let mut fatos = 0;
        export_facts(&path, 0, |_, _| {
            fatos += 1;
            true
        })
        .unwrap();
        assert_eq!(fatos, 2);
    }

    #[test]
    fn tampering_with_a_health_event_is_detected_like_any_other_record() {
        let path = tmp_path("saude_adulterada");
        let mut db = FactStore::new(&path).unwrap();
        let identity =
            hfb2::SecurityIdentity::new("gov.br/orgao-a", "teste://fixture", "forge-teste")
                .unwrap();
        db.write_health_event(&identity, 1_782_467_794_979_937, r#"{"schema":"x"}"#)
            .unwrap();
        assert!(db.inject_malicious_tamper(BASE_LSN + 1).unwrap());
        assert_eq!(db.verify().status, "VIOLATED");
    }

    #[test]
    fn verification_does_not_depend_on_understanding_the_record() {
        // Um registo com uma extensao que este binario nao sabe interpretar
        // continua a verificar: a folha e sobre os BYTES, nao sobre o que o
        // descodificador conseguiu reconstruir.
        let path = tmp_path("opaco");
        let mut db = FactStore::new(&path).unwrap();
        let mut opaque = fact("a");
        opaque["fact.extensions"] = json!([
            {"tag": "0x00070042", "value_hex": "deadbeefdeadbeef"}
        ]);
        db.write_fact(&mut opaque).unwrap();
        assert_eq!(db.verify().status, "INTEG_OK");

        let mut exported = Vec::new();
        export_facts(&path, 0, |_, fact| {
            exported.push(fact);
            true
        })
        .unwrap();
        assert_eq!(exported[0]["fact.extensions"][0]["namespace"], "case");
        assert_eq!(
            exported[0]["fact.extensions"][0]["value_hex"],
            "deadbeefdeadbeef"
        );
    }
}
