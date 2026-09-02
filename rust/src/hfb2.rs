//! HFB2 — o registo canonico persistido do Heraclitus (geracao HDB2).
//!
//! Porque e que existe
//! -------------------
//! O HFB1 tinha um defeito estrutural, nao cosmetico: a integridade dependia de
//! **reserializar** o Fato. O `verify()` descodificava os bytes para um `Value`,
//! voltava a codificar e comparava o hash. Isso faz da integridade uma funcao do
//! *codigo do descodificador*, nao dos *bytes gravados* — qualquer campo novo,
//! qualquer correccao no codec, invalida ficheiros que ninguem tocou. E o que o
//! codec nao entendia desaparecia em silencio: um campo desconhecido era
//! descartado na escrita, e o teste de round-trip passava na mesma porque ambos
//! os lados o descartavam.
//!
//! No HFB2 a direccao inverte-se:
//!
//! ```text
//! bytes canonicos persistidos  ->  folha criptografica  ->  cadeia Merkle
//! ```
//!
//! A folha e calculada sobre os bytes que estao mesmo no disco. Verificar nao
//! exige compreender: um leitor que nao conheca uma extensao nova consegue,
//! ainda assim, afirmar que o registo e estruturalmente valido e
//! criptograficamente integro (ver [`RecordView::parse`] e [`record_leaf`]).
//!
//! Identidade de seguranca
//! -----------------------
//! `tenant_id`, `datasource_id` e `sensor_id` sao campos ESTRUTURAIS do
//! cabecalho autenticado, nao extensoes opcionais. Sao eles que decidem
//! isolamento multi-tenant, autorizacao, correlacao e cadeia de custodia:
//! proteje-los apenas com CRC seria deixar a atribuicao de um evento a outro
//! orgao ao alcance de quem consiga escrever no ficheiro. Alterar qualquer um
//! muda a folha e, por consequencia, a raiz Merkle.
//!
//! Layout
//! ------
//! ```text
//! off  tam  campo
//!   0    4  magic "HFB2"
//!   4    2  format_version (=2)
//!   6    2  flags            (reservado; tem de ser 0)
//!   8    2  record_type
//!  10    2  reserved         (tem de ser 0)
//!  12    4  schema_id
//!  16    2  schema_major
//!  18    2  schema_minor
//!  20   16  event_id (UUID em bytes)
//!  36    8  system_timestamp_micros (i64)
//!  44    8  lsn (u64; 0 = ainda nao atribuido)
//!  52    4  tenant_id_len
//!  56    4  datasource_id_len
//!  60    4  sensor_id_len
//!  64    4  core_len
//!  68    4  extensions_len
//!  72    -  tenant_id | datasource_id | sensor_id | core | extensions
//!   -    4  crc32c (sobre tudo o que vem antes)
//! ```
//!
//! Canonicalizacao
//! ---------------
//! A mesma informacao logica tem de dar exactamente os mesmos bytes, senao a
//! folha deixa de ser uma identidade de conteudo. As regras estao em
//! `md/HDB2-HFB2.md` e sao impostas na LEITURA, nao apenas na escrita: um
//! registo com extensoes fora de ordem canonica e recusado em vez de aceite e
//! reescrito de outra maneira.
//!
//! Tudo aqui assume entrada hostil. Nenhum comprimento lido do disco e usado
//! para alocar antes de ser confrontado com os bytes que restam.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};

use crate::crc32c::crc32c;

// ---------------------------------------------------------------------------
// Separacao de dominio
// ---------------------------------------------------------------------------

/// Prefixos de dominio. Um hash sem dominio e ambiguo: os mesmos 32 bytes
/// podiam ser lidos como folha, como no de Merkle ou como mensagem assinada, e
/// uma prova de um contexto passaria a valer noutro. Cada uso protocolar tem o
/// seu, e o `0x00` separador impede que um prefixo seja sufixo de outro.
pub mod domain {
    /// Folha do registo HFB2.
    pub const RECORD_LEAF: &[u8] = b"HERACLITUS/HFB2/RECORD-LEAF/v1";
    /// No interno da cadeia Merkle rolante do HDB2.
    pub const MERKLE_NODE: &[u8] = b"HERACLITUS/HDB2/MERKLE-NODE/v1";
    /// Mensagem que a ancora Ed25519 assina.
    pub const ANCHOR: &[u8] = b"HERACLITUS/HDB2/ANCHOR/v1";
    /// Identidade compacta de um schema.
    pub const SCHEMA: &[u8] = b"HERACLITUS/SCHEMA/v1";

    /// Comeca um hash no dominio indicado.
    pub fn hasher(domain: &[u8]) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0x00]);
        hasher
    }
}

// ---------------------------------------------------------------------------
// Constantes e limites
// ---------------------------------------------------------------------------

pub const MAGIC: &[u8; 4] = b"HFB2";
pub const FORMAT_VERSION: u16 = 2;

/// Cabecalho de tamanho fixo, antes das tres identidades.
pub const FIXED_HEADER_LEN: usize = 72;
/// CRC-32C no fim do registo.
pub const CRC_LEN: usize = 4;

/// Um registo e UMA observacao, nao um ficheiro.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;
/// Tecto de qualquer string do core.
pub const MAX_STRING_LEN: usize = 1024 * 1024;
/// Tecto de um identificador (tenant/datasource/sensor).
pub const MAX_IDENTITY_LEN: usize = 512;
pub const MAX_EXTENSIONS: usize = 256;
pub const MAX_EXTENSION_LEN: usize = 8 * 1024 * 1024;
pub const MAX_LINEAGE_STEPS: usize = 64;

/// Confianca viaja em partes por milhao. Ponto flutuante nao entra no formato:
/// a sua representacao textual varia entre serializadores e a folha tem de ser
/// identica em qualquer implementacao.
pub const CONFIDENCE_SCALE: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Tipos de registo, schema e extensoes
// ---------------------------------------------------------------------------

/// Tipo do registo. Um leitor que nao conheca um tipo novo continua a poder
/// verificar a integridade — so nao interpreta o core.
pub const RECORD_TYPE_OPERATIONAL_FACT: u16 = 1;
/// Evento de saude do sensor (`heraclitus-telemetry-health/1.0`).
pub const RECORD_TYPE_TELEMETRY_HEALTH: u16 = 2;

/// Identidade do schema do core. A associacao registo <-> schema e inequivoca
/// sem tabela externa: o triplo esta no cabecalho autenticado e entra na folha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaIdentity {
    pub id: u32,
    pub major: u16,
    pub minor: u16,
}

impl SchemaIdentity {
    /// `operational-fact/1.0`.
    pub const OPERATIONAL_FACT_V1: SchemaIdentity = SchemaIdentity {
        id: 1,
        major: 1,
        minor: 0,
    };

    /// `heraclitus-telemetry-health/1.0`.
    pub const TELEMETRY_HEALTH_V1: SchemaIdentity = SchemaIdentity {
        id: 2,
        major: 1,
        minor: 0,
    };

    /// Identidade compacta e estavel, calculavel sem conhecer a semantica.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = domain::hasher(domain::SCHEMA);
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.major.to_be_bytes());
        hasher.update(&self.minor.to_be_bytes());
        hasher.finalize().into()
    }

    /// Nome legivel, quando conhecido. So para diagnostico — a verificacao
    /// nunca depende desta tabela.
    pub fn label(&self) -> Option<&'static str> {
        match (self.id, self.major, self.minor) {
            (1, 1, 0) => Some("operational-fact/1.0"),
            (2, 1, 0) => Some("heraclitus-telemetry-health/1.0"),
            _ => None,
        }
    }
}

impl fmt::Display for SchemaIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.label() {
            Some(label) => write!(f, "{label}"),
            None => write!(f, "schema:{}/{}.{}", self.id, self.major, self.minor),
        }
    }
}

/// Espaco de tags das extensoes, por namespace. Cada namespace tem 64 Ki tags,
/// o que chega para evoluir sem precisar de HFB3 a cada campo novo.
pub mod tags {
    /// `security.*` — modelo canonico de evento de seguranca.
    pub const NS_SECURITY: u32 = 0x0001;
    /// `telemetry.*` — janelas, heartbeats, saude do sensor.
    pub const NS_TELEMETRY: u32 = 0x0002;
    /// `identity.*`
    pub const NS_IDENTITY: u32 = 0x0003;
    /// `network.*`
    pub const NS_NETWORK: u32 = 0x0004;
    /// `cloud.*`
    pub const NS_CLOUD: u32 = 0x0005;
    /// `provenance.*`
    pub const NS_PROVENANCE: u32 = 0x0006;
    /// `case.*`
    pub const NS_CASE: u32 = 0x0007;
    /// `evidence.*`
    pub const NS_EVIDENCE: u32 = 0x0008;
    /// `vendor.*` — fora do controlo do projeto; nunca ganha significado aqui.
    pub const NS_VENDOR: u32 = 0xFFFF;

    pub const fn tag(namespace: u32, index: u16) -> u32 {
        (namespace << 16) | index as u32
    }

    pub const fn namespace_of(tag: u32) -> u32 {
        tag >> 16
    }

    pub fn namespace_label(tag: u32) -> &'static str {
        match namespace_of(tag) {
            NS_SECURITY => "security",
            NS_TELEMETRY => "telemetry",
            NS_IDENTITY => "identity",
            NS_NETWORK => "network",
            NS_CLOUD => "cloud",
            NS_PROVENANCE => "provenance",
            NS_CASE => "case",
            NS_EVIDENCE => "evidence",
            NS_VENDOR => "vendor",
            _ => "unassigned",
        }
    }

    /// `security.canonical_event` — evento `heraclitus-security-event/1.0`
    /// serializado em JSON compacto.
    pub const SECURITY_CANONICAL_EVENT: u32 = tag(NS_SECURITY, 1);
    /// `evidence.legal_receipt` — recibo de carimbo de tempo legal.
    pub const EVIDENCE_LEGAL_RECEIPT: u32 = tag(NS_EVIDENCE, 1);

    /// Tags que o codec projeta em campos semanticos do Fato. Uma delas dentro
    /// de `fact.extensions` seria uma segunda representacao do mesmo dado — e
    /// duas representacoes destroem a canonicalizacao.
    pub const PROJECTED: &[u32] = &[SECURITY_CANONICAL_EVENT, EVIDENCE_LEGAL_RECEIPT];

    /// Tags que nao podem repetir dentro de um registo.
    pub const SINGLETON: &[u32] = &[SECURITY_CANONICAL_EVENT, EVIDENCE_LEGAL_RECEIPT];
}

// ---------------------------------------------------------------------------
// Erros
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hfb2Error {
    /// Nao comeca por `HFB2`.
    BadMagic,
    /// Versao de formato que este codigo nao sabe verificar.
    UnsupportedVersion(u16),
    /// Estrutura invalida: comprimentos, fronteiras, campos reservados.
    Structure(String),
    /// CRC-32C nao bate — corrupcao acidental.
    Crc { stored: u32, computed: u32 },
    /// Bytes que deviam ser UTF-8 e nao sao.
    Utf8(&'static str),
    /// Ordem canonica das extensoes violada.
    NotCanonical(String),
    /// Excedeu um tecto de seguranca.
    TooLarge(String),
    /// O Fato nao traz um campo obrigatorio do formato.
    MissingField(&'static str),
    /// Campo presente mas com forma invalida.
    InvalidField { field: &'static str, reason: String },
    /// O core nao corresponde ao tipo de registo pedido.
    UnsupportedRecordType(u16),
}

impl fmt::Display for Hfb2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hfb2Error::BadMagic => write!(f, "registo nao e HFB2"),
            Hfb2Error::UnsupportedVersion(v) => {
                write!(
                    f,
                    "versao HFB2 nao suportada: {v} (esperado {FORMAT_VERSION})"
                )
            }
            Hfb2Error::Structure(m) => write!(f, "estrutura HFB2 invalida: {m}"),
            Hfb2Error::Crc { stored, computed } => write!(
                f,
                "CRC-32C divergente: gravado {stored:#010x}, calculado {computed:#010x}"
            ),
            Hfb2Error::Utf8(field) => write!(f, "{field} nao e UTF-8 valido"),
            Hfb2Error::NotCanonical(m) => write!(f, "codificacao nao canonica: {m}"),
            Hfb2Error::TooLarge(m) => write!(f, "acima do tecto: {m}"),
            Hfb2Error::MissingField(field) => write!(f, "campo obrigatorio ausente: {field}"),
            Hfb2Error::InvalidField { field, reason } => {
                write!(f, "campo invalido {field}: {reason}")
            }
            Hfb2Error::UnsupportedRecordType(t) => write!(f, "tipo de registo desconhecido: {t}"),
        }
    }
}

impl std::error::Error for Hfb2Error {}

impl From<Hfb2Error> for crate::error::HeraclitusError {
    fn from(error: Hfb2Error) -> Self {
        crate::error::HeraclitusError::FactEncodingError(error.to_string())
    }
}

// ---------------------------------------------------------------------------
// Leitura estrutural (sem semantica)
// ---------------------------------------------------------------------------

/// Uma extensao tal como esta no disco. O valor NUNCA e interpretado aqui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionView<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

/// Vista estrutural de um registo. E o que basta para verificar integridade:
/// nao interpreta o core nem as extensoes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordView<'a> {
    pub format_version: u16,
    pub flags: u16,
    pub record_type: u16,
    pub schema: SchemaIdentity,
    pub event_id: [u8; 16],
    pub system_timestamp_micros: i64,
    pub lsn: u64,
    pub tenant_id: &'a str,
    pub datasource_id: &'a str,
    pub sensor_id: &'a str,
    pub core: &'a [u8],
    pub extensions: Vec<ExtensionView<'a>>,
    /// Bytes cobertos pela folha: tudo menos o CRC final.
    pub body: &'a [u8],
    pub crc: u32,
}

fn be_u16(d: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([d[at], d[at + 1]])
}
fn be_u32(d: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}
fn be_u64(d: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[at..at + 8]);
    u64::from_be_bytes(out)
}

/// Identificador aceite: nao vazio, dentro do tecto, sem caracteres de
/// controlo. Um `datasource_id` com `\n` envenena qualquer log ou relatorio que
/// o imprima, e um vazio nao isola tenant nenhum.
fn check_identity(value: &str, field: &'static str) -> Result<(), Hfb2Error> {
    if value.is_empty() {
        return Err(Hfb2Error::MissingField(field));
    }
    if value.len() > MAX_IDENTITY_LEN {
        return Err(Hfb2Error::TooLarge(format!(
            "{field} tem {} bytes (max {MAX_IDENTITY_LEN})",
            value.len()
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(Hfb2Error::InvalidField {
            field,
            reason: "identificador com caractere de controlo".into(),
        });
    }
    Ok(())
}

impl<'a> RecordView<'a> {
    /// Valida a estrutura e devolve a vista. Nao aloca em funcao de nenhum
    /// comprimento antes de o confrontar com os bytes disponiveis.
    pub fn parse(record: &'a [u8]) -> Result<Self, Hfb2Error> {
        if record.len() < FIXED_HEADER_LEN + CRC_LEN {
            return Err(Hfb2Error::Structure(format!(
                "registo com {} bytes, minimo {}",
                record.len(),
                FIXED_HEADER_LEN + CRC_LEN
            )));
        }
        if record.len() > MAX_RECORD_LEN {
            return Err(Hfb2Error::TooLarge(format!(
                "registo com {} bytes (max {MAX_RECORD_LEN})",
                record.len()
            )));
        }
        if &record[..4] != MAGIC {
            return Err(Hfb2Error::BadMagic);
        }
        let format_version = be_u16(record, 4);
        if format_version != FORMAT_VERSION {
            return Err(Hfb2Error::UnsupportedVersion(format_version));
        }
        let flags = be_u16(record, 6);
        if flags != 0 {
            return Err(Hfb2Error::NotCanonical(format!(
                "flags reservadas tem de ser 0, sao {flags:#06x}"
            )));
        }
        let record_type = be_u16(record, 8);
        let reserved = be_u16(record, 10);
        if reserved != 0 {
            return Err(Hfb2Error::NotCanonical(format!(
                "campo reservado tem de ser 0, e {reserved:#06x}"
            )));
        }
        let schema = SchemaIdentity {
            id: be_u32(record, 12),
            major: be_u16(record, 16),
            minor: be_u16(record, 18),
        };
        let mut event_id = [0u8; 16];
        event_id.copy_from_slice(&record[20..36]);
        let system_timestamp_micros = be_u64(record, 36) as i64;
        let lsn = be_u64(record, 44);

        let tenant_len = be_u32(record, 52) as usize;
        let datasource_len = be_u32(record, 56) as usize;
        let sensor_len = be_u32(record, 60) as usize;
        let core_len = be_u32(record, 64) as usize;
        let ext_len = be_u32(record, 68) as usize;

        // Soma em u64 e comparacao unica: nenhum somatorio pode dar a volta ao
        // tipo e passar a caber num registo pequeno.
        let declared = tenant_len as u64
            + datasource_len as u64
            + sensor_len as u64
            + core_len as u64
            + ext_len as u64;
        let available = (record.len() - FIXED_HEADER_LEN - CRC_LEN) as u64;
        if declared != available {
            return Err(Hfb2Error::Structure(format!(
                "comprimentos declaram {declared} bytes, o registo tem {available}"
            )));
        }

        let body = &record[..record.len() - CRC_LEN];
        let stored_crc = be_u32(record, record.len() - CRC_LEN);
        let computed = crc32c(body);
        if stored_crc != computed {
            return Err(Hfb2Error::Crc {
                stored: stored_crc,
                computed,
            });
        }

        let mut at = FIXED_HEADER_LEN;
        let tenant_id = std::str::from_utf8(&record[at..at + tenant_len])
            .map_err(|_| Hfb2Error::Utf8("tenant_id"))?;
        at += tenant_len;
        let datasource_id = std::str::from_utf8(&record[at..at + datasource_len])
            .map_err(|_| Hfb2Error::Utf8("datasource_id"))?;
        at += datasource_len;
        let sensor_id = std::str::from_utf8(&record[at..at + sensor_len])
            .map_err(|_| Hfb2Error::Utf8("sensor_id"))?;
        at += sensor_len;
        check_identity(tenant_id, "tenant_id")?;
        check_identity(datasource_id, "datasource_id")?;
        check_identity(sensor_id, "sensor_id")?;

        let core = &record[at..at + core_len];
        at += core_len;
        let extensions = parse_extensions(&record[at..at + ext_len])?;

        Ok(RecordView {
            format_version,
            flags,
            record_type,
            schema,
            event_id,
            system_timestamp_micros,
            lsn,
            tenant_id,
            datasource_id,
            sensor_id,
            core,
            extensions,
            body,
            crc: stored_crc,
        })
    }

    /// Folha criptografica deste registo.
    pub fn leaf(&self) -> [u8; 32] {
        leaf_over(self.format_version, self.schema, self.body)
    }

    pub fn extension(&self, tag: u32) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|ext| ext.tag == tag)
            .map(|ext| ext.value)
    }
}

/// As extensoes vem ordenadas por `(tag, valor)`. A ordem e imposta na LEITURA
/// e nao apenas na escrita: sem isso o mesmo conteudo logico teria varias
/// codificacoes validas e a folha deixaria de identificar conteudo.
fn parse_extensions(mut region: &[u8]) -> Result<Vec<ExtensionView<'_>>, Hfb2Error> {
    let mut out: Vec<ExtensionView> = Vec::new();
    while !region.is_empty() {
        if region.len() < 8 {
            return Err(Hfb2Error::Structure(
                "cauda de extensao mais curta que o cabecalho tag+len".into(),
            ));
        }
        let tag = be_u32(region, 0);
        let len = be_u32(region, 4) as usize;
        if len > MAX_EXTENSION_LEN {
            return Err(Hfb2Error::TooLarge(format!(
                "extensao {tag:#010x} declara {len} bytes (max {MAX_EXTENSION_LEN})"
            )));
        }
        if region.len() - 8 < len {
            return Err(Hfb2Error::Structure(format!(
                "extensao {tag:#010x} declara {len} bytes, restam {}",
                region.len() - 8
            )));
        }
        let value = &region[8..8 + len];
        if out.len() >= MAX_EXTENSIONS {
            return Err(Hfb2Error::TooLarge(format!(
                "mais de {MAX_EXTENSIONS} extensoes"
            )));
        }
        if let Some(previous) = out.last() {
            let order = (previous.tag, previous.value).cmp(&(tag, value));
            if order == std::cmp::Ordering::Greater {
                return Err(Hfb2Error::NotCanonical(format!(
                    "extensao {tag:#010x} fora de ordem apos {:#010x}",
                    previous.tag
                )));
            }
            if order == std::cmp::Ordering::Equal {
                return Err(Hfb2Error::NotCanonical(format!(
                    "extensao {tag:#010x} duplicada byte a byte"
                )));
            }
            if previous.tag == tag && tags::SINGLETON.contains(&tag) {
                return Err(Hfb2Error::NotCanonical(format!(
                    "extensao {tag:#010x} nao pode repetir"
                )));
            }
        }
        out.push(ExtensionView { tag, value });
        region = &region[8 + len..];
    }
    Ok(out)
}

/// `leaf = BLAKE3(dominio || format_version || identidade de schema || corpo)`.
///
/// O corpo e exactamente o que esta no disco menos o CRC. O CRC fica de fora
/// porque nao acrescenta entropia — e uma funcao dos mesmos bytes — e porque
/// misturar um detector de corrupcao acidental no material criptografico so
/// baralha as duas responsabilidades. A versao e o schema entram tambem em
/// separado, ainda que ja estejam no corpo: um digest tem de ser inequivoco
/// mesmo que um dia se mude o que o corpo cobre.
pub fn leaf_over(format_version: u16, schema: SchemaIdentity, body: &[u8]) -> [u8; 32] {
    let mut hasher = domain::hasher(domain::RECORD_LEAF);
    hasher.update(&format_version.to_be_bytes());
    hasher.update(&schema.id.to_be_bytes());
    hasher.update(&schema.major.to_be_bytes());
    hasher.update(&schema.minor.to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

/// Folha de um registo ja validado estruturalmente.
pub fn record_leaf(record: &[u8]) -> Result<[u8; 32], Hfb2Error> {
    Ok(RecordView::parse(record)?.leaf())
}

/// Avanca a cadeia Merkle rolante.
pub fn fold_chain(previous_root: &[u8; 32], leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = domain::hasher(domain::MERKLE_NODE);
    hasher.update(previous_root);
    hasher.update(leaf);
    hasher.finalize().into()
}

/// Raiz de uma cadeia vazia.
pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Escrita canonica
// ---------------------------------------------------------------------------

fn put_str(buffer: &mut Vec<u8>, value: &str) -> Result<(), Hfb2Error> {
    if value.len() > MAX_STRING_LEN {
        return Err(Hfb2Error::TooLarge(format!(
            "string com {} bytes (max {MAX_STRING_LEN})",
            value.len()
        )));
    }
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Opcional = byte de presenca + (se presente) string. Ausente e string vazia
/// sao coisas diferentes e tem codificacoes diferentes; nenhum comprimento
/// magico faz de sentinela.
fn put_opt_str(buffer: &mut Vec<u8>, value: Option<&str>) -> Result<(), Hfb2Error> {
    match value {
        None => buffer.push(0),
        Some(text) => {
            buffer.push(1);
            put_str(buffer, text)?;
        }
    }
    Ok(())
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, at: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Hfb2Error> {
        if self.data.len() - self.at < n {
            return Err(Hfb2Error::Structure(format!(
                "core truncado a ler {what}: pedia {n} bytes, restam {}",
                self.data.len() - self.at
            )));
        }
        let slice = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, Hfb2Error> {
        Ok(self.take(1, what)?[0])
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, Hfb2Error> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn str(&mut self, what: &'static str) -> Result<&'a str, Hfb2Error> {
        let len = self.u32(what)? as usize;
        if len > MAX_STRING_LEN {
            return Err(Hfb2Error::TooLarge(format!(
                "{what} declara {len} bytes (max {MAX_STRING_LEN})"
            )));
        }
        let bytes = self.take(len, what)?;
        std::str::from_utf8(bytes).map_err(|_| Hfb2Error::Utf8(what))
    }

    fn opt_str(&mut self, what: &'static str) -> Result<Option<&'a str>, Hfb2Error> {
        match self.u8(what)? {
            0 => Ok(None),
            1 => Ok(Some(self.str(what)?)),
            other => Err(Hfb2Error::NotCanonical(format!(
                "byte de presenca de {what} tem de ser 0 ou 1, e {other}"
            ))),
        }
    }

    fn done(&self, what: &'static str) -> Result<(), Hfb2Error> {
        if self.at != self.data.len() {
            return Err(Hfb2Error::Structure(format!(
                "{what} tem {} bytes por consumir",
                self.data.len() - self.at
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Core do `operational-fact/1.0`
// ---------------------------------------------------------------------------

/// Campos do core, ja interpretados. So faz sentido para
/// `RECORD_TYPE_OPERATIONAL_FACT` — a verificacao de integridade nao passa por
/// aqui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalFactCore<'a> {
    pub actor_id: Option<&'a str>,
    pub actor_name: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub source_ip: Option<&'a str>,
    pub behavior_class: &'a str,
    pub behavior_action: &'a str,
    pub risk_level: &'a str,
    pub evidence_algorithm: u8,
    pub evidence_hash: [u8; 32],
    pub transformation_steps: Vec<&'a str>,
    pub input_source: &'a str,
    pub matched_rule: &'a str,
    pub confidence_ppm: u32,
    pub knowledge_version: &'a str,
    pub reasoning_version: &'a str,
    pub ontology_version: &'a str,
}

/// Algoritmo do hash da observacao bruta. So o BLAKE3 e emitido pelo Runner.
pub const EVIDENCE_ALG_BLAKE3: u8 = 1;

impl<'a> OperationalFactCore<'a> {
    pub fn parse(core: &'a [u8]) -> Result<Self, Hfb2Error> {
        let mut cursor = Cursor::new(core);
        let actor_id = cursor.opt_str("actor.id")?;
        let actor_name = cursor.opt_str("actor.name")?;
        let target_id = cursor.opt_str("target.id")?;
        let source_ip = cursor.opt_str("source.ip")?;
        let behavior_class = cursor.str("behavior.class")?;
        let behavior_action = cursor.str("behavior.action")?;
        let risk_level = cursor.str("behavior.risk_level")?;
        let evidence_algorithm = cursor.u8("evidence.algorithm")?;
        if evidence_algorithm != EVIDENCE_ALG_BLAKE3 {
            return Err(Hfb2Error::InvalidField {
                field: "evidence.algorithm",
                reason: format!("algoritmo desconhecido: {evidence_algorithm}"),
            });
        }
        let mut evidence_hash = [0u8; 32];
        evidence_hash.copy_from_slice(cursor.take(32, "evidence.hash")?);
        let count = cursor.u32("lineage.count")? as usize;
        if count > MAX_LINEAGE_STEPS {
            return Err(Hfb2Error::TooLarge(format!(
                "lineage com {count} passos (max {MAX_LINEAGE_STEPS})"
            )));
        }
        let mut transformation_steps = Vec::with_capacity(count.min(MAX_LINEAGE_STEPS));
        for _ in 0..count {
            transformation_steps.push(cursor.str("lineage.step")?);
        }
        let input_source = cursor.str("lineage.input_source")?;
        let matched_rule = cursor.str("lineage.matched_rule")?;
        let confidence_ppm = cursor.u32("confidence")?;
        if confidence_ppm > CONFIDENCE_SCALE {
            return Err(Hfb2Error::InvalidField {
                field: "confidence",
                reason: format!("{confidence_ppm} ppm acima de {CONFIDENCE_SCALE}"),
            });
        }
        let knowledge_version = cursor.str("knowledge_version")?;
        let reasoning_version = cursor.str("reasoning_version")?;
        let ontology_version = cursor.str("ontology_version")?;
        cursor.done("core")?;

        Ok(OperationalFactCore {
            actor_id,
            actor_name,
            target_id,
            source_ip,
            behavior_class,
            behavior_action,
            risk_level,
            evidence_algorithm,
            evidence_hash,
            transformation_steps,
            input_source,
            matched_rule,
            confidence_ppm,
            knowledge_version,
            reasoning_version,
            ontology_version,
        })
    }
}

/// `behavior.action` sem alocar e sem interpretar o resto do core — o caminho
/// quente do filtro HQL.
pub fn core_action(core: &[u8]) -> Option<&str> {
    let mut cursor = Cursor::new(core);
    for what in ["actor.id", "actor.name", "target.id", "source.ip"] {
        cursor.opt_str(what).ok()?;
    }
    cursor.str("behavior.class").ok()?;
    cursor.str("behavior.action").ok()
}

/// `target.id` sem alocar.
pub fn core_target_id(core: &[u8]) -> Option<&str> {
    let mut cursor = Cursor::new(core);
    cursor.opt_str("actor.id").ok()?;
    cursor.opt_str("actor.name").ok()?;
    cursor.opt_str("target.id").ok()?
}

// ---------------------------------------------------------------------------
// Fato (JSON) <-> registo HFB2
// ---------------------------------------------------------------------------

/// Identidade de seguranca que todo o registo carrega. Nao tem `Default`: um
/// default aqui seria um tenant por omissao, e um tenant por omissao e uma
/// falha de isolamento a espera de acontecer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityIdentity {
    pub tenant_id: String,
    pub datasource_id: String,
    pub sensor_id: String,
}

impl SecurityIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        datasource_id: impl Into<String>,
        sensor_id: impl Into<String>,
    ) -> Result<Self, Hfb2Error> {
        let identity = SecurityIdentity {
            tenant_id: tenant_id.into(),
            datasource_id: datasource_id.into(),
            sensor_id: sensor_id.into(),
        };
        check_identity(&identity.tenant_id, "tenant_id")?;
        check_identity(&identity.datasource_id, "datasource_id")?;
        check_identity(&identity.sensor_id, "sensor_id")?;
        Ok(identity)
    }

    /// Identidade EXPLICITAMENTE de demonstracao/teste.
    ///
    /// Existe para que os binarios de demo digam em voz alta que os seus dados
    /// nao sao de ninguem, em vez de herdarem um `tenant_id` por omissao — que
    /// e como uma falha de isolamento entra num sistema multi-tenant. O caminho
    /// operacional (`ingest`) recusa arrancar sem identidade configurada.
    pub fn demo(datasource_id: &str) -> Self {
        SecurityIdentity {
            tenant_id: "demo-tenant".into(),
            datasource_id: format!("demo://{datasource_id}"),
            sensor_id: "demo-sensor".into(),
        }
    }

    /// Le a identidade de `fact.datasource`. Ausente e erro: o formato nao
    /// aceita um registo sem dono.
    pub fn from_fact(fact: &Value) -> Result<Self, Hfb2Error> {
        let block = fact
            .get("fact.datasource")
            .ok_or(Hfb2Error::MissingField("fact.datasource"))?;
        let field = |name: &'static str| -> Result<String, Hfb2Error> {
            block
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Hfb2Error::MissingField(name))
        };
        SecurityIdentity::new(
            field("tenant_id")?,
            field("datasource_id")?,
            field("sensor_id")?,
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "tenant_id": self.tenant_id,
            "datasource_id": self.datasource_id,
            "sensor_id": self.sensor_id,
        })
    }

    /// Carimba a identidade num Fato acabado de sair do Runner. O Runner
    /// observa; quem sabe de que tenant, fonte e sensor se trata e o supervisor.
    pub fn apply(&self, fact: &mut Value) {
        fact["fact.datasource"] = self.to_json();
    }
}

fn opt_str<'a>(fact: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut node = fact;
    for key in path {
        node = node.get(*key)?;
    }
    node.as_str().filter(|text| !text.is_empty())
}

fn req_str<'a>(fact: &'a Value, path: &[&str], field: &'static str) -> Result<&'a str, Hfb2Error> {
    opt_str(fact, path).ok_or(Hfb2Error::MissingField(field))
}

fn hex_to_32(text: &str, field: &'static str) -> Result<[u8; 32], Hfb2Error> {
    let hex = text.rsplit(':').next().unwrap_or(text);
    if hex.len() != 64 {
        return Err(Hfb2Error::InvalidField {
            field,
            reason: format!("esperava 64 digitos hexadecimais, tem {}", hex.len()),
        });
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
            Hfb2Error::InvalidField {
                field,
                reason: "digito nao hexadecimal".into(),
            }
        })?;
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Extensoes de um Fato, ja em ordem canonica.
fn extensions_from_fact(fact: &Value) -> Result<Vec<(u32, Vec<u8>)>, Hfb2Error> {
    let mut out: Vec<(u32, Vec<u8>)> = Vec::new();

    if let Some(event) = fact.get("fact.security") {
        if !event.is_null() {
            // JSON compacto de um `serde_json::Value`: as chaves de um objeto
            // saem sempre pela mesma ordem (mapa ordenado), logo a mesma
            // informacao logica da os mesmos bytes.
            let bytes = serde_json::to_vec(event).map_err(|error| Hfb2Error::InvalidField {
                field: "fact.security",
                reason: error.to_string(),
            })?;
            out.push((tags::SECURITY_CANONICAL_EVENT, bytes));
        }
    }
    if let Some(receipt) = opt_str(fact, &["fact.evidence", "carimbo_tempo_legal"]) {
        out.push((tags::EVIDENCE_LEGAL_RECEIPT, receipt.as_bytes().to_vec()));
    }

    if let Some(extra) = fact.get("fact.extensions") {
        let list = extra.as_array().ok_or(Hfb2Error::InvalidField {
            field: "fact.extensions",
            reason: "tem de ser uma lista".into(),
        })?;
        for entry in list {
            let tag_text = entry
                .get("tag")
                .and_then(Value::as_str)
                .ok_or(Hfb2Error::MissingField("fact.extensions[].tag"))?;
            let tag = u32::from_str_radix(tag_text.trim_start_matches("0x"), 16).map_err(|_| {
                Hfb2Error::InvalidField {
                    field: "fact.extensions[].tag",
                    reason: format!("tag nao hexadecimal: {tag_text:?}"),
                }
            })?;
            if tags::PROJECTED.contains(&tag) {
                return Err(Hfb2Error::NotCanonical(format!(
                    "extensao {tag:#010x} tem projecao semantica propria e nao pode \
                     vir tambem em fact.extensions"
                )));
            }
            let value_hex = entry
                .get("value_hex")
                .and_then(Value::as_str)
                .ok_or(Hfb2Error::MissingField("fact.extensions[].value_hex"))?;
            if !value_hex.len().is_multiple_of(2) {
                return Err(Hfb2Error::InvalidField {
                    field: "fact.extensions[].value_hex",
                    reason: "comprimento impar".into(),
                });
            }
            let mut value = Vec::with_capacity(value_hex.len() / 2);
            for index in (0..value_hex.len()).step_by(2) {
                value.push(
                    u8::from_str_radix(&value_hex[index..index + 2], 16).map_err(|_| {
                        Hfb2Error::InvalidField {
                            field: "fact.extensions[].value_hex",
                            reason: "digito nao hexadecimal".into(),
                        }
                    })?,
                );
            }
            out.push((tag, value));
        }
    }

    out.sort();
    for pair in out.windows(2) {
        if pair[0] == pair[1] {
            return Err(Hfb2Error::NotCanonical(format!(
                "extensao {:#010x} duplicada byte a byte",
                pair[0].0
            )));
        }
        if pair[0].0 == pair[1].0 && tags::SINGLETON.contains(&pair[0].0) {
            return Err(Hfb2Error::NotCanonical(format!(
                "extensao {:#010x} nao pode repetir",
                pair[0].0
            )));
        }
    }
    if out.len() > MAX_EXTENSIONS {
        return Err(Hfb2Error::TooLarge(format!(
            "{} extensoes (max {MAX_EXTENSIONS})",
            out.len()
        )));
    }
    Ok(out)
}

/// Serializa um Fato Operacional em bytes canonicos HFB2.
///
/// `fact.integrity` e ignorado de proposito: e valor DERIVADO do registo, e
/// gravar dentro do registo um hash do proprio registo e uma circularidade.
/// A folha e a raiz vivem no bloco HDB2, ao lado.
pub fn encode_fact(fact: &Value, lsn: u64) -> Result<Vec<u8>, Hfb2Error> {
    let identity = SecurityIdentity::from_fact(fact)?;
    let schema = SchemaIdentity::OPERATIONAL_FACT_V1;

    let fact_id = req_str(fact, &["fact_id"], "fact_id")?;
    let event_id = uuid::Uuid::parse_str(fact_id)
        .map_err(|error| Hfb2Error::InvalidField {
            field: "fact_id",
            reason: error.to_string(),
        })?
        .into_bytes();

    let system_timestamp_micros = fact
        .get("fact.time")
        .and_then(|time| time.get("system_timestamp"))
        .and_then(Value::as_i64)
        .ok_or(Hfb2Error::MissingField("fact.time.system_timestamp"))?;

    // --- core ---
    let mut core = Vec::with_capacity(512);
    put_opt_str(&mut core, opt_str(fact, &["fact.identity", "actor.id"]))?;
    put_opt_str(&mut core, opt_str(fact, &["fact.identity", "actor.name"]))?;
    put_opt_str(&mut core, opt_str(fact, &["fact.identity", "target.id"]))?;
    put_opt_str(&mut core, opt_str(fact, &["fact.identity", "source.ip"]))?;
    put_str(
        &mut core,
        req_str(fact, &["fact.behavior", "class"], "fact.behavior.class")?,
    )?;
    put_str(
        &mut core,
        req_str(fact, &["fact.behavior", "action"], "fact.behavior.action")?,
    )?;
    put_str(
        &mut core,
        req_str(
            fact,
            &["fact.behavior", "risk_level"],
            "fact.behavior.risk_level",
        )?,
    )?;
    let evidence = req_str(
        fact,
        &["fact.evidence", "raw_observation_hash"],
        "fact.evidence.raw_observation_hash",
    )?;
    if !evidence.starts_with("b3:") {
        return Err(Hfb2Error::InvalidField {
            field: "fact.evidence.raw_observation_hash",
            reason: format!("esperava prefixo b3:, veio {evidence:?}"),
        });
    }
    core.push(EVIDENCE_ALG_BLAKE3);
    core.extend_from_slice(&hex_to_32(evidence, "fact.evidence.raw_observation_hash")?);

    let steps = fact
        .get("fact.lineage")
        .and_then(|lineage| lineage.get("transformation_steps"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if steps.len() > MAX_LINEAGE_STEPS {
        return Err(Hfb2Error::TooLarge(format!(
            "lineage com {} passos (max {MAX_LINEAGE_STEPS})",
            steps.len()
        )));
    }
    core.extend_from_slice(&(steps.len() as u32).to_be_bytes());
    for step in steps {
        let text = step.as_str().ok_or(Hfb2Error::InvalidField {
            field: "fact.lineage.transformation_steps",
            reason: "passo nao textual".into(),
        })?;
        put_str(&mut core, text)?;
    }
    put_str(
        &mut core,
        req_str(
            fact,
            &["fact.lineage", "input_source"],
            "fact.lineage.input_source",
        )?,
    )?;
    put_str(
        &mut core,
        req_str(
            fact,
            &["fact.lineage", "matched_rule"],
            "fact.lineage.matched_rule",
        )?,
    )?;
    let confidence = fact
        .get("fact.confidence")
        .and_then(Value::as_f64)
        .ok_or(Hfb2Error::MissingField("fact.confidence"))?;
    if !(0.0..=1.0).contains(&confidence) {
        return Err(Hfb2Error::InvalidField {
            field: "fact.confidence",
            reason: format!("{confidence} fora de 0.0..=1.0"),
        });
    }
    let confidence_ppm = (confidence * CONFIDENCE_SCALE as f64).round() as u32;
    core.extend_from_slice(&confidence_ppm.to_be_bytes());
    put_str(
        &mut core,
        req_str(fact, &["fact.knowledge_version"], "fact.knowledge_version")?,
    )?;
    put_str(
        &mut core,
        req_str(fact, &["fact.reasoning_version"], "fact.reasoning_version")?,
    )?;
    put_str(
        &mut core,
        req_str(fact, &["fact.ontology_version"], "fact.ontology_version")?,
    )?;

    // --- extensoes ---
    let extensions = extensions_from_fact(fact)?;
    let mut ext_bytes = Vec::new();
    for (tag, value) in &extensions {
        if value.len() > MAX_EXTENSION_LEN {
            return Err(Hfb2Error::TooLarge(format!(
                "extensao {tag:#010x} com {} bytes",
                value.len()
            )));
        }
        ext_bytes.extend_from_slice(&tag.to_be_bytes());
        ext_bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        ext_bytes.extend_from_slice(value);
    }

    assemble(
        RECORD_TYPE_OPERATIONAL_FACT,
        schema,
        &event_id,
        system_timestamp_micros,
        lsn,
        &identity,
        &core,
        &ext_bytes,
    )
}

/// Monta o registo canonico. Unica funcao que escreve o cabecalho: um segundo
/// sitio a fazer o mesmo seria um segundo sitio onde a ordem dos campos pode
/// divergir — e a ordem dos campos e a folha.
#[allow(clippy::too_many_arguments)]
fn assemble(
    record_type: u16,
    schema: SchemaIdentity,
    event_id: &[u8; 16],
    timestamp_micros: i64,
    lsn: u64,
    identity: &SecurityIdentity,
    core: &[u8],
    ext_bytes: &[u8],
) -> Result<Vec<u8>, Hfb2Error> {
    let mut record = Vec::with_capacity(FIXED_HEADER_LEN + core.len() + ext_bytes.len() + 64);
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    record.extend_from_slice(&0u16.to_be_bytes()); // flags
    record.extend_from_slice(&record_type.to_be_bytes());
    record.extend_from_slice(&0u16.to_be_bytes()); // reservado
    record.extend_from_slice(&schema.id.to_be_bytes());
    record.extend_from_slice(&schema.major.to_be_bytes());
    record.extend_from_slice(&schema.minor.to_be_bytes());
    record.extend_from_slice(event_id);
    record.extend_from_slice(&(timestamp_micros as u64).to_be_bytes());
    record.extend_from_slice(&lsn.to_be_bytes());
    record.extend_from_slice(&(identity.tenant_id.len() as u32).to_be_bytes());
    record.extend_from_slice(&(identity.datasource_id.len() as u32).to_be_bytes());
    record.extend_from_slice(&(identity.sensor_id.len() as u32).to_be_bytes());
    record.extend_from_slice(&(core.len() as u32).to_be_bytes());
    record.extend_from_slice(&(ext_bytes.len() as u32).to_be_bytes());
    debug_assert_eq!(record.len(), FIXED_HEADER_LEN);
    record.extend_from_slice(identity.tenant_id.as_bytes());
    record.extend_from_slice(identity.datasource_id.as_bytes());
    record.extend_from_slice(identity.sensor_id.as_bytes());
    record.extend_from_slice(core);
    record.extend_from_slice(ext_bytes);

    if record.len() + CRC_LEN > MAX_RECORD_LEN {
        return Err(Hfb2Error::TooLarge(format!(
            "registo com {} bytes (max {MAX_RECORD_LEN})",
            record.len() + CRC_LEN
        )));
    }
    let crc = crc32c(&record);
    record.extend_from_slice(&crc.to_be_bytes());
    Ok(record)
}

/// Serializa um evento de Telemetry Health.
///
/// Vive no MESMO `.hdb` que os Fatos, com a mesma identidade autenticada e a
/// mesma folha: um sensor nao consegue mentir sobre a sua propria saude sem
/// partir a cadeia Merkle. O core e opaco — o envelope JSON tal e qual — porque
/// a semantica pertence ao consumidor (`heraclitus-telemetry-health`) e nao ao
/// formato de armazenamento.
pub fn encode_health_event(
    identity: &SecurityIdentity,
    event_id: [u8; 16],
    emitted_at_micros: i64,
    lsn: u64,
    envelope_json: &str,
) -> Result<Vec<u8>, Hfb2Error> {
    let mut core = Vec::with_capacity(envelope_json.len() + 4);
    put_str(&mut core, envelope_json)?;
    assemble(
        RECORD_TYPE_TELEMETRY_HEALTH,
        SchemaIdentity::TELEMETRY_HEALTH_V1,
        &event_id,
        emitted_at_micros,
        lsn,
        identity,
        &core,
        &[],
    )
}

/// Envelope de Telemetry Health tal como foi gravado, com a identidade que o
/// registo autentica.
pub fn decode_health_event(record: &[u8]) -> Result<(SecurityIdentity, String), Hfb2Error> {
    let view = RecordView::parse(record)?;
    if view.record_type != RECORD_TYPE_TELEMETRY_HEALTH {
        return Err(Hfb2Error::UnsupportedRecordType(view.record_type));
    }
    let mut cursor = Cursor::new(view.core);
    let envelope = cursor.str("telemetry.envelope")?.to_owned();
    cursor.done("core")?;
    let identity = SecurityIdentity::new(view.tenant_id, view.datasource_id, view.sensor_id)?;
    Ok((identity, envelope))
}

/// Reconstroi o Fato Operacional a partir dos bytes persistidos.
///
/// Nenhum campo gravado desaparece: as extensoes conhecidas voltam ao seu
/// lugar semantico e as desconhecidas viajam em `fact.extensions`, com a tag e
/// os bytes intactos, para que um `encode_fact` a seguir as reponha na mesma.
pub fn decode_fact(record: &[u8]) -> Result<Value, Hfb2Error> {
    let view = RecordView::parse(record)?;
    if view.record_type != RECORD_TYPE_OPERATIONAL_FACT {
        return Err(Hfb2Error::UnsupportedRecordType(view.record_type));
    }
    let core = OperationalFactCore::parse(view.core)?;

    let mut fact = json!({
        "fact_id": uuid::Uuid::from_bytes(view.event_id).to_string(),
        "fact.datasource": {
            "tenant_id": view.tenant_id,
            "datasource_id": view.datasource_id,
            "sensor_id": view.sensor_id,
        },
        "fact.schema": {
            "id": view.schema.id,
            "major": view.schema.major,
            "minor": view.schema.minor,
            "label": view.schema.label(),
            "hash": to_hex(&view.schema.hash()),
        },
        "fact.identity": {
            "actor.id": core.actor_id,
            "actor.name": core.actor_name,
            "target.id": core.target_id,
            "source.ip": core.source_ip,
        },
        "fact.time": {
            "system_timestamp": view.system_timestamp_micros,
            "log_sequence_number": view.lsn,
        },
        "fact.behavior": {
            "class": core.behavior_class,
            "action": core.behavior_action,
            "risk_level": core.risk_level,
        },
        "fact.evidence": {
            "raw_observation_hash": format!("b3:{}", to_hex(&core.evidence_hash)),
        },
        "fact.lineage": {
            "transformation_steps": core.transformation_steps,
            "input_source": core.input_source,
            "matched_rule": core.matched_rule,
        },
        "fact.confidence": core.confidence_ppm as f64 / CONFIDENCE_SCALE as f64,
        "fact.knowledge_version": core.knowledge_version,
        "fact.reasoning_version": core.reasoning_version,
        "fact.ontology_version": core.ontology_version,
    });

    let mut unknown = Vec::new();
    for extension in &view.extensions {
        match extension.tag {
            tags::SECURITY_CANONICAL_EVENT => {
                let event: Value = serde_json::from_slice(extension.value).map_err(|error| {
                    Hfb2Error::InvalidField {
                        field: "security.canonical_event",
                        reason: error.to_string(),
                    }
                })?;
                fact["fact.security"] = event;
            }
            tags::EVIDENCE_LEGAL_RECEIPT => {
                let receipt = std::str::from_utf8(extension.value)
                    .map_err(|_| Hfb2Error::Utf8("evidence.legal_receipt"))?;
                fact["fact.evidence"]["carimbo_tempo_legal"] = Value::from(receipt);
            }
            tag => unknown.push(json!({
                "tag": format!("{tag:#010x}"),
                "namespace": tags::namespace_label(tag),
                "value_hex": to_hex(extension.value),
            })),
        }
    }
    if !unknown.is_empty() {
        fact["fact.extensions"] = Value::Array(unknown);
    }
    Ok(fact)
}

/// Hexadecimal minusculo de um digest de 32 bytes — a forma que os contratos
/// de fio usam.
pub fn model_hex(bytes: &[u8; 32]) -> String {
    to_hex(bytes)
}

/// Metadados de um registo sem interpretar o core — para status e diagnostico.
pub fn describe(record: &[u8]) -> Result<BTreeMap<String, String>, Hfb2Error> {
    let view = RecordView::parse(record)?;
    let mut out = BTreeMap::new();
    out.insert("format_version".into(), view.format_version.to_string());
    out.insert("record_type".into(), view.record_type.to_string());
    out.insert("schema".into(), view.schema.to_string());
    out.insert("tenant_id".into(), view.tenant_id.to_string());
    out.insert("datasource_id".into(), view.datasource_id.to_string());
    out.insert("sensor_id".into(), view.sensor_id.to_string());
    out.insert("lsn".into(), view.lsn.to_string());
    out.insert("extensions".into(), view.extensions.len().to_string());
    out.insert("leaf".into(), to_hex(&view.leaf()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Um Fato completo, com identidade e uma extensao conhecida.
    fn fact() -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.datasource": {
                "tenant_id": "gov.br/orgao-a",
                "datasource_id": "postgresql://db-01/postgresql.log",
                "sensor_id": "forge-edge-01",
            },
            "fact.identity": {
                "actor.id": "admin",
                "actor.name": "admin",
                "target.id": "prod",
                "source.ip": null,
            },
            "fact.time": {"system_timestamp": 1_782_782_405_000_000i64, "log_sequence_number": 0},
            "fact.behavior": {
                "class": "credential_attack",
                "action": "authentication.failure",
                "risk_level": "High",
            },
            "fact.evidence": {
                "raw_observation_hash": "b3:9611cd00aabbccddeeff00112233445566778899aabbccddeeff001122334455",
                "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo",
            },
            "fact.lineage": {
                "transformation_steps": ["parse", "normalize", "behavior", "emit"],
                "input_source": "br.gov.heraclitus.pipelines.postgresql-v1.2.0",
                "matched_rule": "pg_auth_failure",
            },
            "fact.confidence": 0.972,
            "fact.knowledge_version": "br.gov.heraclitus.pipelines.postgresql-v1.2.0@1.2.0",
            "fact.reasoning_version": "reasoner-core-v6.0",
            "fact.ontology_version": "v9",
        })
    }

    fn record() -> Vec<u8> {
        encode_fact(&fact(), 42).expect("codifica")
    }

    /// Recalcula o CRC depois de uma adulteracao, para que o teste exercite a
    /// camada criptografica e nao apenas a fisica.
    fn reseal(record: &mut [u8]) {
        let end = record.len() - CRC_LEN;
        let crc = crc32c(&record[..end]);
        record[end..].copy_from_slice(&crc.to_be_bytes());
    }

    // -- estrutura e canonicalizacao ---------------------------------------

    #[test]
    fn round_trip_preserves_every_field() {
        let original = fact();
        let decoded = decode_fact(&record()).expect("descodifica");
        for path in [
            vec!["fact_id"],
            vec!["fact.behavior", "class"],
            vec!["fact.behavior", "action"],
            vec!["fact.behavior", "risk_level"],
            vec!["fact.identity", "actor.id"],
            vec!["fact.identity", "target.id"],
            vec!["fact.evidence", "raw_observation_hash"],
            vec!["fact.evidence", "carimbo_tempo_legal"],
            vec!["fact.lineage", "input_source"],
            vec!["fact.lineage", "matched_rule"],
            vec!["fact.knowledge_version"],
            vec!["fact.confidence"],
        ] {
            let (mut a, mut b) = (&original, &decoded);
            for key in &path {
                a = &a[key];
                b = &b[key];
            }
            assert_eq!(a, b, "campo {path:?} perdeu-se no round-trip");
        }
        assert_eq!(decoded["fact.datasource"], original["fact.datasource"]);
        assert_eq!(decoded["fact.time"]["log_sequence_number"], 42);
        assert_eq!(decoded["fact.schema"]["label"], "operational-fact/1.0");
    }

    #[test]
    fn re_encoding_a_decoded_record_is_byte_identical() {
        let first = record();
        let decoded = decode_fact(&first).expect("descodifica");
        let second = encode_fact(&decoded, 42).expect("recodifica");
        assert_eq!(first, second);
    }

    #[test]
    fn same_logical_content_gives_the_same_bytes() {
        // A ordem por que as chaves foram escritas no JSON nao pode mudar um
        // unico byte do registo.
        let source = fact();
        let mut shuffled = json!({});
        let mut keys: Vec<String> = source.as_object().unwrap().keys().cloned().collect();
        keys.reverse();
        for key in keys {
            shuffled[&key] = source[&key].clone();
        }
        assert_eq!(
            encode_fact(&source, 7).unwrap(),
            encode_fact(&shuffled, 7).unwrap()
        );
    }

    #[test]
    fn confidence_survives_as_integer_parts_per_million() {
        let decoded = decode_fact(&record()).expect("descodifica");
        assert_eq!(decoded["fact.confidence"].as_f64(), Some(0.972));
    }

    #[test]
    fn an_absent_optional_field_stays_absent() {
        let mut absent = fact();
        absent["fact.identity"]["target.id"] = Value::Null;
        let decoded = decode_fact(&encode_fact(&absent, 1).unwrap()).unwrap();
        assert!(decoded["fact.identity"]["target.id"].is_null());
        // Ausente ocupa 1 byte; presente ocupa 1 + 4 + n.
        assert_eq!(
            encode_fact(&fact(), 1).unwrap().len() - encode_fact(&absent, 1).unwrap().len(),
            4 + "prod".len()
        );
    }

    // -- identidade de seguranca -------------------------------------------

    #[test]
    fn security_identity_is_mandatory() {
        let mut orphan = fact();
        orphan.as_object_mut().unwrap().remove("fact.datasource");
        assert_eq!(
            encode_fact(&orphan, 1),
            Err(Hfb2Error::MissingField("fact.datasource"))
        );
    }

    #[test]
    fn changing_tenant_changes_the_leaf() {
        // O ponto de todo o formato: a atribuicao de um evento a um orgao nao
        // pode mudar sem que a folha — e logo a raiz Merkle — mude.
        let before = record_leaf(&record()).unwrap();
        let mut other = fact();
        other["fact.datasource"]["tenant_id"] = Value::from("gov.br/orgao-b");
        let after = record_leaf(&encode_fact(&other, 42).unwrap()).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn changing_datasource_or_sensor_changes_the_leaf() {
        let base = record_leaf(&record()).unwrap();
        for (field, value) in [
            ("datasource_id", "postgresql://db-02/postgresql.log"),
            ("sensor_id", "forge-edge-99"),
        ] {
            let mut other = fact();
            other["fact.datasource"][field] = Value::from(value);
            let leaf = record_leaf(&encode_fact(&other, 42).unwrap()).unwrap();
            assert_ne!(base, leaf, "{field} nao esta autenticado");
        }
    }

    #[test]
    fn empty_identity_is_refused() {
        let mut anonymous = fact();
        anonymous["fact.datasource"]["tenant_id"] = Value::from("");
        assert_eq!(
            encode_fact(&anonymous, 1),
            Err(Hfb2Error::MissingField("tenant_id"))
        );
    }

    #[test]
    fn identity_with_control_characters_is_refused() {
        // Um identificador com newline envenena qualquer log que o imprima.
        let mut poisoned = fact();
        poisoned["fact.datasource"]["datasource_id"] = Value::from("a\nb");
        assert!(matches!(
            encode_fact(&poisoned, 1),
            Err(Hfb2Error::InvalidField { .. })
        ));
    }

    // -- extensoes ----------------------------------------------------------

    #[test]
    fn unknown_extension_survives_a_full_round_trip() {
        let mut with_unknown = fact();
        with_unknown["fact.extensions"] = json!([
            {"tag": "0xffff0007", "value_hex": "cafebabe"}
        ]);
        let encoded = encode_fact(&with_unknown, 3).unwrap();
        let decoded = decode_fact(&encoded).unwrap();
        assert_eq!(decoded["fact.extensions"][0]["tag"], "0xffff0007");
        assert_eq!(decoded["fact.extensions"][0]["value_hex"], "cafebabe");
        assert_eq!(decoded["fact.extensions"][0]["namespace"], "vendor");
        // Reemitir nao perde, nao reordena, nao muda um byte.
        assert_eq!(encode_fact(&decoded, 3).unwrap(), encoded);
    }

    #[test]
    fn a_reader_that_ignores_semantics_still_verifies() {
        // Nao chama `decode_fact`: so estrutura. E o requisito de verificacao
        // independente do descodificador semantico.
        let mut with_unknown = fact();
        with_unknown["fact.extensions"] = json!([
            {"tag": "0x00020009", "value_hex": "00ff00ff"}
        ]);
        let encoded = encode_fact(&with_unknown, 3).unwrap();
        let view = RecordView::parse(&encoded).expect("estrutura valida");
        assert_eq!(view.extensions.len(), 2);
        assert_eq!(view.leaf(), record_leaf(&encoded).unwrap());
        // O leitor sabe que existe e o que ocupa, sem saber o que significa.
        assert_eq!(
            view.extension(0x0002_0009),
            Some(&[0x00u8, 0xff, 0x00, 0xff][..])
        );
    }

    #[test]
    fn extensions_are_sorted_canonically_whatever_the_input_order() {
        let mut ascending = fact();
        ascending["fact.extensions"] = json!([
            {"tag": "0xffff0001", "value_hex": "01"},
            {"tag": "0xffff0002", "value_hex": "02"},
        ]);
        let mut descending = fact();
        descending["fact.extensions"] = json!([
            {"tag": "0xffff0002", "value_hex": "02"},
            {"tag": "0xffff0001", "value_hex": "01"},
        ]);
        assert_eq!(
            encode_fact(&ascending, 1).unwrap(),
            encode_fact(&descending, 1).unwrap()
        );
    }

    #[test]
    fn out_of_order_extensions_on_disk_are_rejected() {
        // A ordem canonica e imposta na LEITURA: senao o mesmo conteudo teria
        // duas codificacoes validas e a folha deixava de identificar conteudo.
        let mut with_two = fact();
        with_two["fact.extensions"] = json!([
            {"tag": "0xffff0001", "value_hex": "01"},
            {"tag": "0xffff0002", "value_hex": "02"},
        ]);
        let mut encoded = encode_fact(&with_two, 1).unwrap();
        let body_len = encoded.len() - CRC_LEN;
        // Duas extensoes de 1 byte: 9 bytes cada, no fim do corpo.
        let start = body_len - 18;
        let first = encoded[start..start + 9].to_vec();
        let second = encoded[start + 9..body_len].to_vec();
        encoded[start..start + 9].copy_from_slice(&second);
        encoded[start + 9..body_len].copy_from_slice(&first);
        reseal(&mut encoded);
        assert!(matches!(
            RecordView::parse(&encoded),
            Err(Hfb2Error::NotCanonical(_))
        ));
    }

    #[test]
    fn a_projected_tag_cannot_also_come_raw() {
        let mut duplicated = fact();
        duplicated["fact.extensions"] = json!([
            {"tag": format!("{:#010x}", tags::EVIDENCE_LEGAL_RECEIPT), "value_hex": "00"}
        ]);
        assert!(matches!(
            encode_fact(&duplicated, 1),
            Err(Hfb2Error::NotCanonical(_))
        ));
    }

    #[test]
    fn tampering_with_an_extension_byte_changes_the_leaf() {
        let mut with_unknown = fact();
        with_unknown["fact.extensions"] = json!([
            {"tag": "0xffff0001", "value_hex": "aabbccdd"}
        ]);
        let encoded = encode_fact(&with_unknown, 1).unwrap();
        let before = record_leaf(&encoded).unwrap();

        let mut tampered = encoded.clone();
        let at = tampered.len() - CRC_LEN - 1;
        tampered[at] ^= 0x01;
        reseal(&mut tampered);

        assert_ne!(before, record_leaf(&tampered).unwrap());
    }

    #[test]
    fn the_canonical_security_event_travels_as_an_extension() {
        let mut with_event = fact();
        with_event["fact.security"] = json!({
            "schema_version": "heraclitus-security-event/1.0",
            "category": "authentication",
            "severity": 7,
        });
        let encoded = encode_fact(&with_event, 1).unwrap();
        let view = RecordView::parse(&encoded).unwrap();
        assert!(view.extension(tags::SECURITY_CANONICAL_EVENT).is_some());
        let decoded = decode_fact(&encoded).unwrap();
        assert_eq!(decoded["fact.security"], with_event["fact.security"]);
    }

    // -- integridade fisica e limites ---------------------------------------

    #[test]
    fn crc_catches_a_flipped_bit() {
        let mut corrupted = record();
        corrupted[FIXED_HEADER_LEN + 2] ^= 0x08;
        assert!(matches!(
            RecordView::parse(&corrupted),
            Err(Hfb2Error::Crc { .. })
        ));
    }

    #[test]
    fn truncation_fails_deterministically_at_every_length() {
        let full = record();
        for len in 0..full.len() {
            let result = RecordView::parse(&full[..len]);
            assert!(result.is_err(), "prefixo de {len} bytes nao devia validar");
            assert_eq!(result, RecordView::parse(&full[..len]));
        }
    }

    #[test]
    fn a_forged_length_does_not_allocate() {
        // `core_len` a declarar 4 GiB num registo de umas centenas de bytes.
        let mut forged = record();
        forged[64..68].copy_from_slice(&u32::MAX.to_be_bytes());
        reseal(&mut forged);
        assert!(matches!(
            RecordView::parse(&forged),
            Err(Hfb2Error::Structure(_))
        ));
    }

    #[test]
    fn lengths_that_would_overflow_are_rejected() {
        let mut forged = record();
        for offset in [52usize, 56, 60] {
            forged[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        reseal(&mut forged);
        assert!(RecordView::parse(&forged).is_err());
    }

    #[test]
    fn reserved_fields_must_be_zero() {
        for offset in [7usize, 11] {
            let mut forged = record();
            forged[offset] = 0x01;
            reseal(&mut forged);
            assert!(
                matches!(RecordView::parse(&forged), Err(Hfb2Error::NotCanonical(_))),
                "byte reservado {offset} aceite"
            );
        }
    }

    #[test]
    fn another_format_version_is_refused_not_guessed() {
        let mut forged = record();
        forged[4..6].copy_from_slice(&99u16.to_be_bytes());
        reseal(&mut forged);
        assert_eq!(
            RecordView::parse(&forged),
            Err(Hfb2Error::UnsupportedVersion(99))
        );
    }

    #[test]
    fn invalid_utf8_in_an_identity_is_refused() {
        let mut forged = record();
        forged[FIXED_HEADER_LEN] = 0xFF;
        reseal(&mut forged);
        assert_eq!(
            RecordView::parse(&forged),
            Err(Hfb2Error::Utf8("tenant_id"))
        );
    }

    #[test]
    fn a_non_uuid_fact_id_is_refused() {
        let mut bad = fact();
        bad["fact_id"] = Value::from("nao-e-um-uuid");
        assert!(matches!(
            encode_fact(&bad, 1),
            Err(Hfb2Error::InvalidField {
                field: "fact_id",
                ..
            })
        ));
    }

    #[test]
    fn an_evidence_hash_of_the_wrong_shape_is_refused() {
        for value in [
            "b3:abcd".to_string(),
            format!("sha256:{}", "a".repeat(64)),
            "abcd".to_string(),
        ] {
            let mut bad = fact();
            bad["fact.evidence"]["raw_observation_hash"] = Value::from(value);
            assert!(encode_fact(&bad, 1).is_err());
        }
    }

    #[test]
    fn an_unknown_record_type_still_verifies_but_does_not_decode() {
        let mut forged = record();
        forged[8..10].copy_from_slice(&999u16.to_be_bytes());
        reseal(&mut forged);
        // Estrutura e integridade: continuam a poder ser afirmadas.
        let view = RecordView::parse(&forged).expect("estrutura valida");
        assert_eq!(view.record_type, 999);
        // Semantica: recusada em vez de adivinhada.
        assert_eq!(
            decode_fact(&forged),
            Err(Hfb2Error::UnsupportedRecordType(999))
        );
    }

    // -- separacao de dominio -----------------------------------------------

    #[test]
    fn domains_are_distinct_and_not_prefixes_of_each_other() {
        let all = [
            domain::RECORD_LEAF,
            domain::MERKLE_NODE,
            domain::ANCHOR,
            domain::SCHEMA,
        ];
        for (index, a) in all.iter().enumerate() {
            for b in all.iter().skip(index + 1) {
                assert_ne!(a, b);
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    #[test]
    fn the_same_bytes_hash_differently_in_different_domains() {
        let payload = b"mesmos bytes";
        let mut leaf = domain::hasher(domain::RECORD_LEAF);
        leaf.update(payload);
        let mut node = domain::hasher(domain::MERKLE_NODE);
        node.update(payload);
        assert_ne!(leaf.finalize().as_bytes(), node.finalize().as_bytes());
    }

    #[test]
    fn schema_identity_is_stable_and_distinguishing() {
        let one = SchemaIdentity::OPERATIONAL_FACT_V1;
        let other = SchemaIdentity {
            minor: 1,
            ..SchemaIdentity::OPERATIONAL_FACT_V1
        };
        assert_eq!(one.hash(), SchemaIdentity::OPERATIONAL_FACT_V1.hash());
        assert_ne!(one.hash(), other.hash());
        assert_eq!(one.to_string(), "operational-fact/1.0");
        assert_eq!(other.label(), None);
    }

    #[test]
    fn the_leaf_binds_the_schema_identity() {
        let body = b"corpo identico";
        let one = leaf_over(FORMAT_VERSION, SchemaIdentity::OPERATIONAL_FACT_V1, body);
        let other = leaf_over(
            FORMAT_VERSION,
            SchemaIdentity {
                minor: 1,
                ..SchemaIdentity::OPERATIONAL_FACT_V1
            },
            body,
        );
        assert_ne!(one, other);
    }

    #[test]
    fn chain_fold_depends_on_order() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(
            fold_chain(&fold_chain(&EMPTY_ROOT, &a), &b),
            fold_chain(&fold_chain(&EMPTY_ROOT, &b), &a)
        );
    }

    // -- robustez contra entrada hostil -------------------------------------

    /// Gerador determinista: um fuzz reprodutivel vale mais do que um aleatorio
    /// que ninguem consegue repetir depois de falhar na CI.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() >> 33) as usize % n.max(1)
        }
    }

    #[test]
    fn random_mutations_never_panic_and_never_keep_the_leaf() {
        let valid = record();
        let original = record_leaf(&valid).unwrap();
        let mut rng = Lcg(0x5EED_1234_ABCD_0001);
        for round in 0..4_000 {
            let mut mutated = valid.clone();
            match round % 4 {
                0 => {
                    let at = rng.below(mutated.len());
                    mutated[at] ^= 1 << rng.below(8);
                }
                1 => {
                    let keep = rng.below(mutated.len());
                    mutated.truncate(keep);
                }
                2 => {
                    let at = rng.below(mutated.len());
                    if at + 4 <= mutated.len() {
                        mutated[at..at + 4].copy_from_slice(&(rng.next() as u32).to_be_bytes());
                    }
                }
                _ => {
                    let extra = rng.below(64);
                    let byte = rng.next() as u8;
                    mutated.extend(std::iter::repeat_n(byte, extra));
                }
            }
            if mutated == valid {
                continue;
            }
            // Nao pode entrar em panico; se a estrutura for aceite, a folha tem
            // de ser diferente da do registo original.
            if let Ok(view) = RecordView::parse(&mutated) {
                assert_ne!(
                    view.leaf(),
                    original,
                    "mutacao {round} produziu a mesma folha"
                );
            }
            let _ = decode_fact(&mutated);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut rng = Lcg(0xDEAD_BEEF_0000_0001);
        for size in [0usize, 1, 7, 71, 72, 76, 200, 1024] {
            for _ in 0..200 {
                let bytes: Vec<u8> = (0..size).map(|_| rng.next() as u8).collect();
                let _ = RecordView::parse(&bytes);
                let _ = decode_fact(&bytes);
                let _ = describe(&bytes);
            }
        }
    }

    #[test]
    fn a_record_that_claims_to_be_hfb1_is_refused() {
        let mut forged = record();
        forged[..4].copy_from_slice(b"HFB1");
        assert_eq!(RecordView::parse(&forged), Err(Hfb2Error::BadMagic));
    }

    #[test]
    fn zero_copy_accessors_agree_with_the_full_decode() {
        let encoded = record();
        let view = RecordView::parse(&encoded).unwrap();
        let decoded = decode_fact(&encoded).unwrap();
        assert_eq!(
            core_action(view.core),
            decoded["fact.behavior"]["action"].as_str()
        );
        assert_eq!(
            core_target_id(view.core),
            decoded["fact.identity"]["target.id"].as_str()
        );
    }

    #[test]
    fn describe_reports_identity_without_decoding_the_core() {
        let described = describe(&record()).unwrap();
        assert_eq!(described["tenant_id"], "gov.br/orgao-a");
        assert_eq!(described["schema"], "operational-fact/1.0");
        assert_eq!(described["lsn"], "42");
    }
}
