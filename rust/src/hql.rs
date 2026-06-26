//! HQL — Heraclitus Query Language (porte nativo de `hql_engine.py`).
//!
//! Interpreta a gramática EBNF da spec (secao 10) e varre o `.hdb` binário
//! projetando apenas os Fatos que casam com o comportamento canônico — sem
//! depender do interpretador Python.
//!
//!   FROM FACTS MATCH (actor.id[,actor.name]) EXECUTES "action" AGAINST "object"
//!   [ WITHIN LAST <n> (MINUTES|HOURS|DAYS) ] SELECT field [, field ...]

use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{Map, Value};

use crate::db::HEADER_SIZE;

pub struct Query {
    pub action: String,
    pub target: String,
    pub amount: Option<i64>,
    pub unit: Option<String>,
    pub fields: Vec<String>,
}

fn query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r#"(?is)FROM\s+FACTS\s+MATCH\s+\(([^)]+)\)\s+"#,
            r#"EXECUTES\s+"([^"]+)"\s+AGAINST\s+"([^"]+)""#,
            r#"(?:\s+WITHIN\s+LAST\s+(\d+)\s+(MINUTES|HOURS|DAYS))?"#,
            r#"\s+SELECT\s+(.+)"#,
        ))
        .unwrap()
    })
}

pub fn parse_query(q: &str) -> Result<Query, String> {
    let caps = query_re()
        .captures(q.trim())
        .ok_or("Erro de Sintaxe HQL: a consulta nao obedece a gramatica EBNF v6.0.")?;
    Ok(Query {
        action: caps[2].to_string(),
        target: caps[3].to_string(),
        amount: caps.get(4).map(|m| m.as_str().parse::<i64>().unwrap_or(0)),
        unit: caps.get(5).map(|m| m.as_str().to_uppercase()),
        fields: caps[6]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    })
}

fn unit_secs(u: &str) -> i64 {
    match u {
        "MINUTES" => 60,
        "HOURS" => 3600,
        "DAYS" => 86400,
        _ => 0,
    }
}

/// Mapeia um alias plano da HQL para a navegação no Fato aninhado.
fn resolve_field(fact: &Value, field: &str) -> Value {
    let path: Vec<&str> = match field {
        "fact.id" => vec!["fact_id"],
        "actor.id" => vec!["fact.identity", "actor.id"],
        "actor.name" => vec!["fact.identity", "actor.name"],
        "target.id" => vec!["fact.identity", "target.id"],
        "source.ip" => vec!["fact.identity", "source.ip"],
        "fact.behavior.class" => vec!["fact.behavior", "class"],
        "fact.behavior.action" => vec!["fact.behavior", "action"],
        "fact.behavior.risk_level" => vec!["fact.behavior", "risk_level"],
        "fact.confidence" => vec!["fact.confidence"],
        "fact.knowledge_version" => vec!["fact.knowledge_version"],
        "lsn" => vec!["fact.time", "log_sequence_number"],
        "timestamp" => vec!["fact.time", "system_timestamp"],
        "integrity.merkle_root_anchor" => vec!["fact.integrity", "merkle_root_anchor"],
        "integrity.signature" => vec!["fact.integrity", "signature"],
        other => return fact.get(other).cloned().unwrap_or(Value::Null),
    };
    let mut node = fact;
    for k in path {
        match node.get(k) {
            Some(v) => node = v,
            None => return Value::Null,
        }
    }
    node.clone()
}

/// Varre o `.hdb`, filtra (MATCH/EXECUTES/AGAINST/WITHIN) e projeta (SELECT).
pub fn execute_query(db_path: &str, q: &str) -> Result<Vec<Map<String, Value>>, String> {
    let plan = parse_query(q)?;

    let mut data = Vec::new();
    File::open(db_path)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() < 8 || &data[..4] != b"HERA" {
        return Err("cabecalho mestre do .hdb invalido".into());
    }

    let cutoff = match (plan.amount, plan.unit.as_deref()) {
        (Some(a), Some(u)) => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as i64;
            Some(now - a * unit_secs(u) * 1_000_000)
        }
        _ => None,
    };

    let mut out = Vec::new();
    let mut pos = 8usize; // pula file header
    while pos + HEADER_SIZE <= data.len() {
        let header = &data[pos..pos + HEADER_SIZE];
        if &header[..4] != b"FACT" {
            break;
        }
        let payload_len = u32::from_be_bytes(header[56..60].try_into().unwrap()) as usize;
        let start = pos + HEADER_SIZE;
        if start + payload_len > data.len() {
            break;
        }
        let fact: Value = crate::fbfact::decode(&data[start..start + payload_len])
            .map_err(|e| e.to_string())?;
        pos = start + payload_len;

        let action = fact["fact.behavior"]["action"].as_str().unwrap_or("");
        let target = fact["fact.identity"]["target.id"].as_str().unwrap_or("");
        if plan.action != "*" && plan.action != action {
            continue;
        }
        if plan.target != "*" && plan.target != target {
            continue;
        }
        if let Some(c) = cutoff {
            if fact["fact.time"]["system_timestamp"].as_i64().unwrap_or(0) < c {
                continue;
            }
        }

        let mut row = Map::new();
        for f in &plan.fields {
            row.insert(f.clone(), resolve_field(&fact, f));
        }
        out.push(row);
    }
    Ok(out)
}
