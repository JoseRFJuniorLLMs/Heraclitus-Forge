//! HQL — Heraclitus Query Language (porte nativo de `hql_engine.py`).
//!
//! Interpreta a gramática EBNF da spec (seção 10) e varre o `.hdb` binário
//! projetando apenas os Fatos que casam com o comportamento canônico — sem
//! depender do interpretador Python.
//!
//! ## Gramática suportada
//!
//! ```ebnf
//! Query         ::= "FROM FACTS" MatchStmt [TimeStmt] SelectStmt [LimitStmt]
//! MatchStmt     ::= "MATCH" "(" Identifiers ")" "EXECUTES" Action "AGAINST" Object
//! Action        ::= '"' String '"' | '"*"'       (* wildcard *)
//! Object        ::= '"' String '"' | '"*"'       (* wildcard *)
//! TimeStmt      ::= "WITHIN LAST" Integer ("MINUTES" | "HOURS" | "DAYS")
//! SelectStmt    ::= "SELECT" FieldList | "SELECT" "*"
//! LimitStmt     ::= "LIMIT" Integer
//! ```
//!
//! ## Otimização zero-copy
//!
//! O filtro `EXECUTES action AGAINST target` usa os acessores [`crate::fbfact::action`]
//! e [`crate::fbfact::target_id`] para inspecionar o payload CRF v2 **sem
//! desserializar** o Fato completo. Apenas os blocos que passam no filtro são
//! decodificados via [`crate::fbfact::decode`] + [`crate::cpm::record_to_fact`].
//! Em workloads onde >90% dos blocos são rejeitados pelo filtro, isso elimina
//! a maioria das alocações.

use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::cpm;
use crate::db::HEADER_SIZE;

// ---------------------------------------------------------------------------
// Estrutura da query compilada
// ---------------------------------------------------------------------------

pub struct Query {
    pub action: String,   // "*" = wildcard
    pub target: String,   // "*" = wildcard
    pub amount: Option<i64>,
    pub unit: Option<String>,
    pub fields: Vec<String>, // vazio = SELECT *
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Parser robusto (regex EBNF) — suporta wildcard, SELECT *, LIMIT N
// ---------------------------------------------------------------------------

fn query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            // FROM FACTS MATCH (identifiers)
            r#"(?is)FROM\s+FACTS\s+MATCH\s+\([^)]+\)\s+"#,
            // EXECUTES "action" AGAINST "object"  — aceita * como wildcard
            r#"EXECUTES\s+"([^"]+)"\s+AGAINST\s+"([^"]+)""#,
            // [WITHIN LAST N (MINUTES|HOURS|DAYS)]
            r#"(?:\s+WITHIN\s+LAST\s+(\d+)\s+(MINUTES|HOURS|DAYS))?"#,
            // SELECT field,... | SELECT *
            r#"(?:\s+SELECT\s+(.+?))?"#,
            // [LIMIT N]
            r#"(?:\s+LIMIT\s+(\d+))?\s*$"#,
        ))
        .unwrap()
    })
}

pub fn parse_query(q: &str) -> Result<Query, String> {
    let caps = query_re()
        .captures(q.trim())
        .ok_or("Erro de Sintaxe HQL: a consulta não obedece à gramática EBNF v6.0.")?;

    let action = caps[1].trim().to_string();
    let target = caps[2].trim().to_string();

    let fields: Vec<String> = match caps.get(5).map(|m| m.as_str().trim()) {
        None | Some("*") | Some("") => vec![], // SELECT * — retorna tudo
        Some(list) => list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };

    Ok(Query {
        action,
        target,
        amount: caps.get(3).map(|m| m.as_str().parse::<i64>().unwrap_or(0)),
        unit: caps.get(4).map(|m| m.as_str().to_uppercase()),
        fields,
        limit: caps.get(6).and_then(|m| m.as_str().parse::<usize>().ok()),
    })
}

fn unit_secs(u: &str) -> i64 {
    match u {
        "MINUTES" => 60,
        "HOURS"   => 3600,
        "DAYS"    => 86400,
        _         => 0,
    }
}

// ---------------------------------------------------------------------------
// Projeção de campos — resolve aliases HQL → caminho no Fato aninhado
// ---------------------------------------------------------------------------

/// Mapeia um alias plano da HQL para a navegação no Fato aninhado.
fn resolve_field(fact: &Value, field: &str) -> Value {
    let path: Vec<&str> = match field {
        // identidade
        "fact.id"           => vec!["fact_id"],
        "actor.id"          => vec!["fact.identity", "actor.id"],
        "actor.name"        => vec!["fact.identity", "actor.name"],
        "target.id"         => vec!["fact.identity", "target.id"],
        "source.ip"         => vec!["fact.identity", "source.ip"],
        // comportamento
        "fact.behavior.class"      => vec!["fact.behavior", "class"],
        "class"                    => vec!["fact.behavior", "class"],
        "fact.behavior.action"     => vec!["fact.behavior", "action"],
        "action"                   => vec!["fact.behavior", "action"],
        "fact.behavior.risk_level" => vec!["fact.behavior", "risk_level"],
        "risk"                     => vec!["fact.behavior", "risk_level"],
        "risk_level"               => vec!["fact.behavior", "risk_level"],
        // evidência
        "fact.evidence.raw_observation_hash" => vec!["fact.evidence", "raw_observation_hash"],
        "evidence_hash"                      => vec!["fact.evidence", "raw_observation_hash"],
        "carimbo_tempo_legal"                => vec!["fact.evidence", "carimbo_tempo_legal"],
        // temporal
        "fact.confidence"   => vec!["fact.confidence"],
        "confidence"        => vec!["fact.confidence"],
        "lsn"               => vec!["fact.time", "log_sequence_number"],
        "timestamp"         => vec!["fact.time", "system_timestamp"],
        // integridade
        "integrity.merkle_root_anchor" => vec!["fact.integrity", "merkle_root_anchor"],
        "integrity.signature"          => vec!["fact.integrity", "signature"],
        "integrity.leaf_hash"          => vec!["fact.integrity", "leaf_hash"],
        // versões
        "fact.knowledge_version" => vec!["fact.knowledge_version"],
        "fact.ontology_version"  => vec!["fact.ontology_version"],
        // linhagem
        "input_source"  => vec!["fact.lineage", "input_source"],
        "matched_rule"  => vec!["fact.lineage", "matched_rule"],
        // fallback: chave literal no root do Fato
        other => return fact.get(other).cloned().unwrap_or(Value::Null),
    };
    let mut node = fact;
    for k in path {
        match node.get(k) {
            Some(v) => node = v,
            None    => return Value::Null,
        }
    }
    node.clone()
}

/// Projeta todos os campos do Fato em um `Map` plano (SELECT *).
fn project_all(fact: &Value) -> Map<String, Value> {
    let mut row = Map::new();
    let all_fields = [
        "fact.id", "actor.id", "actor.name", "target.id", "source.ip",
        "fact.behavior.class", "fact.behavior.action", "fact.behavior.risk_level",
        "fact.evidence.raw_observation_hash", "carimbo_tempo_legal",
        "fact.confidence", "lsn", "timestamp",
        "integrity.merkle_root_anchor", "integrity.signature",
        "fact.knowledge_version", "fact.ontology_version",
        "input_source", "matched_rule",
    ];
    for &f in &all_fields {
        let v = resolve_field(fact, f);
        if v != Value::Null {
            row.insert(f.to_string(), v);
        }
    }
    row
}

// ---------------------------------------------------------------------------
// Execute — varre .hdb com filtro zero-copy antes do decode completo
// ---------------------------------------------------------------------------

/// Varre o `.hdb`, filtra (MATCH/EXECUTES/AGAINST/WITHIN/LIMIT) e projeta (SELECT).
///
/// ## Estratégia zero-copy
///
/// Para cada bloco no arquivo:
/// 1. Decodifica o `CpmRecord` (valida CRC-32C, extrai o payload fbfact).
/// 2. Usa `fbfact::action(payload)` — lê `&str` direto do buffer, sem alocar.
/// 3. Usa `fbfact::target_id(payload)` — idem.
/// 4. Só se os dois campos casam com o filtro, chama `cpm::record_to_fact`
///    que desserializa o Fato completo para projeção e filtragem temporal.
pub fn execute_query(db_path: &str, q: &str) -> Result<Vec<Map<String, Value>>, String> {
    let plan = parse_query(q)?;

    let mut data = Vec::new();
    File::open(db_path)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() < 8 || &data[..4] != b"HERA" {
        return Err("cabeçalho mestre do .hdb inválido".into());
    }

    let cutoff = match (plan.amount, plan.unit.as_deref()) {
        (Some(a), Some(u)) => {
            let now = crate::fact::now_micros().unwrap_or(0);
            // Aritmética saturante: `WITHIN LAST 999999999999 DAYS` transbordava
            // o `a * unit_secs * 1e6` e o `now - …` fazia underflow (panic em
            // debug, wrap em release). Satura em 0 = "desde o início".
            let window = (a as i64)
                .saturating_mul(unit_secs(u))
                .saturating_mul(1_000_000);
            Some(now.saturating_sub(window))
        }
        _ => None,
    };

    let mut out = Vec::new();
    let mut pos = 8usize; // pula file header
    while pos + HEADER_SIZE <= data.len() {
        // Verifica magic do bloco
        let header = &data[pos..pos + HEADER_SIZE];
        if &header[..4] != b"FACT" {
            break;
        }
        let payload_len_bytes = header[56..60].try_into().unwrap_or([0; 4]);
        let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;
        let start = pos + HEADER_SIZE;
        if start + payload_len > data.len() {
            break;
        }
        let raw_payload = &data[start..start + payload_len];
        pos = start + payload_len;

        // --- Etapa 1: decode CpmRecord (valida CRC-32C — camada física) ---
        let cpm_rec = match cpm::decode_record(raw_payload) {
            cpm::CpmDecoded::Record(rec, _) => rec,
            cpm::CpmDecoded::Torn => {
                // Bloco fisicamente corrompido: reporta mas não aborta o scan
                // (o verify() é quem deve rejeitar; aqui apenas pulamos).
                continue;
            }
        };

        // --- Etapa 2: FILTRO ZERO-COPY — action + target_id direto no fbfact body ---
        // O pristine payload dentro do CpmRecord é o buffer fbfact.
        let fb = &cpm_rec.payload;

        // Filtra ação (sem alocar)
        if plan.action != "*" {
            match crate::fbfact::action(fb) {
                Some(a) if a == plan.action => {}
                _ => continue,
            }
        }

        // Filtra target (sem alocar)
        if plan.target != "*" {
            match crate::fbfact::target_id(fb) {
                Some(t) if t == plan.target => {}
                _ => continue,
            }
        }

        // --- Etapa 3: decode completo apenas dos blocos que passaram no filtro ---
        let fact = match cpm::record_to_fact(&cpm_rec) {
            Ok(v)  => v,
            Err(_) => continue,
        };

        // Filtro temporal (WITHIN LAST)
        if let Some(c) = cutoff {
            if fact["fact.time"]["system_timestamp"].as_i64().unwrap_or(0) < c {
                continue;
            }
        }

        // --- Etapa 4: projeção dos campos (SELECT) ---
        let row = if plan.fields.is_empty() {
            project_all(&fact)
        } else {
            let mut row = Map::new();
            for f in &plan.fields {
                row.insert(f.clone(), resolve_field(&fact, f));
            }
            row
        };
        out.push(row);

        // --- LIMIT: interrompe early se já temos o suficiente ---
        if let Some(lim) = plan.limit {
            if out.len() >= lim {
                break;
            }
        }
    }
    Ok(out)
}
