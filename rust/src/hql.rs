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

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::cpm;

// ---------------------------------------------------------------------------
// Estrutura da query compilada
// ---------------------------------------------------------------------------

pub struct Query {
    pub action: String, // "*" = wildcard
    pub target: String, // "*" = wildcard
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
        "HOURS" => 3600,
        "DAYS" => 86400,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Projeção de campos — resolve aliases HQL → caminho no Fato aninhado
// ---------------------------------------------------------------------------

/// Mapeia um alias plano da HQL para a navegação no Fato aninhado.
fn resolve_field(fact: &Value, field: &str) -> Value {
    let path: Vec<&str> = match field {
        // identidade
        "fact.id" => vec!["fact_id"],
        "actor.id" => vec!["fact.identity", "actor.id"],
        "actor.name" => vec!["fact.identity", "actor.name"],
        "target.id" => vec!["fact.identity", "target.id"],
        "source.ip" => vec!["fact.identity", "source.ip"],
        // comportamento
        "fact.behavior.class" => vec!["fact.behavior", "class"],
        "class" => vec!["fact.behavior", "class"],
        "fact.behavior.action" => vec!["fact.behavior", "action"],
        "action" => vec!["fact.behavior", "action"],
        "fact.behavior.risk_level" => vec!["fact.behavior", "risk_level"],
        "risk" => vec!["fact.behavior", "risk_level"],
        "risk_level" => vec!["fact.behavior", "risk_level"],
        // evidência
        "fact.evidence.raw_observation_hash" => vec!["fact.evidence", "raw_observation_hash"],
        "evidence_hash" => vec!["fact.evidence", "raw_observation_hash"],
        "carimbo_tempo_legal" => vec!["fact.evidence", "carimbo_tempo_legal"],
        // temporal
        "fact.confidence" => vec!["fact.confidence"],
        "confidence" => vec!["fact.confidence"],
        "lsn" => vec!["fact.time", "log_sequence_number"],
        "timestamp" => vec!["fact.time", "system_timestamp"],
        // integridade
        "integrity.merkle_root_anchor" => vec!["fact.integrity", "merkle_root_anchor"],
        "integrity.signature" => vec!["fact.integrity", "signature"],
        "integrity.leaf_hash" => vec!["fact.integrity", "leaf_hash"],
        // versões
        "fact.knowledge_version" => vec!["fact.knowledge_version"],
        "fact.ontology_version" => vec!["fact.ontology_version"],
        // linhagem
        "input_source" => vec!["fact.lineage", "input_source"],
        "matched_rule" => vec!["fact.lineage", "matched_rule"],
        // fallback: chave literal no root do Fato
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

/// Projeta todos os campos do Fato em um `Map` plano (SELECT *).
fn project_all(fact: &Value) -> Map<String, Value> {
    let mut row = Map::new();
    let all_fields = [
        "fact.id",
        "actor.id",
        "actor.name",
        "target.id",
        "source.ip",
        "fact.behavior.class",
        "fact.behavior.action",
        "fact.behavior.risk_level",
        "fact.evidence.raw_observation_hash",
        "carimbo_tempo_legal",
        "fact.confidence",
        "lsn",
        "timestamp",
        "integrity.merkle_root_anchor",
        "integrity.signature",
        "fact.knowledge_version",
        "fact.ontology_version",
        "input_source",
        "matched_rule",
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

    let cutoff = match (plan.amount, plan.unit.as_deref()) {
        (Some(a), Some(u)) => {
            let now = crate::fact::now_micros().unwrap_or(0);
            // Aritmética saturante: `WITHIN LAST 999999999999 DAYS` transbordava
            // o `a * unit_secs * 1e6` e o `now - …` fazia underflow (panic em
            // debug, wrap em release). Satura em 0 = "desde o início".
            let window = a.saturating_mul(unit_secs(u)).saturating_mul(1_000_000);
            Some(now.saturating_sub(window))
        }
        _ => None,
    };

    // Varredura em STREAMING (Marco A do AUDIT.md): um bloco em RAM de cada
    // vez via `db::scan_blocks` — a query escala com o tamanho do bloco, não
    // do banco. Magic/truncagem param o scan (semântica do `break` antigo);
    // Torn é pulado (o verify() é quem julga a integridade).
    let mut out = Vec::new();
    let outcome = crate::db::scan_blocks(db_path, |_lsn, raw_payload| {
        // --- Etapa 1: decode CpmRecord (valida CRC-32C — camada física) ---
        let cpm_rec = match cpm::decode_record(raw_payload) {
            cpm::CpmDecoded::Record(rec, _) => rec,
            cpm::CpmDecoded::Torn => return true, // pula bloco corrompido
        };

        // --- Etapa 2: FILTRO ZERO-COPY — action + target_id direto no fbfact body ---
        let fb = &cpm_rec.payload;
        if plan.action != "*" {
            match crate::fbfact::action(fb) {
                Some(a) if a == plan.action => {}
                _ => return true,
            }
        }
        if plan.target != "*" {
            match crate::fbfact::target_id(fb) {
                Some(t) if t == plan.target => {}
                _ => return true,
            }
        }

        // --- Etapa 3: decode completo apenas dos blocos que passaram no filtro ---
        let fact = match cpm::record_to_fact(&cpm_rec) {
            Ok(v) => v,
            Err(_) => return true,
        };

        // Filtro temporal (WITHIN LAST)
        if let Some(c) = cutoff {
            if fact["fact.time"]["system_timestamp"].as_i64().unwrap_or(0) < c {
                return true;
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
        !matches!(plan.limit, Some(lim) if out.len() >= lim)
    });

    match outcome.map_err(|e| e.to_string())? {
        crate::db::ScanOutcome::NoFile => Err(format!("não foi possível abrir {db_path}")),
        crate::db::ScanOutcome::BadMaster => Err("cabeçalho mestre do .hdb inválido".into()),
        // Done / magic corrompido / cauda truncada: devolve o que foi lido
        // (mesma semântica do `break` do scan antigo).
        _ => Ok(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FactStore;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn tmp_with_facts(pairs: &[(&str, &str)]) -> String {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("forge_hql_{}_{}.hdb", std::process::id(), n));
        let s = p.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&s);
        let _ = std::fs::remove_file(format!("{s}.anchor"));
        let mut db = FactStore::new(&s).unwrap();
        for (action, target) in pairs {
            let mut f = json!({
                "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
                "fact.identity": {"actor.id":"a","actor.name":"a","target.id":target,"source.ip":null},
                "fact.time": {"system_timestamp": 1_782_467_794_979_937i64, "log_sequence_number": 0u64},
                "fact.behavior": {"class":"c","action":action,"risk_level":"Medium"},
                "fact.evidence": {"raw_observation_hash":"b3:abcd","carimbo_tempo_legal":"icp"},
                "fact.lineage": {"transformation_steps":["parse"],"input_source":"pg","matched_rule":"r"},
                "fact.confidence": 0.9,
                "fact.knowledge_version":"k","fact.reasoning_version":"r","fact.ontology_version":"v9"
            });
            db.write_fact(&mut f).unwrap();
        }
        s
    }

    #[test]
    fn parse_wildcards_select_and_limit() {
        let q = parse_query(
            r#"FROM FACTS MATCH (actor.id) EXECUTES "*" AGAINST "salaries" WITHIN LAST 10 DAYS SELECT actor.id,action LIMIT 5"#,
        )
        .unwrap();
        assert_eq!(q.action, "*");
        assert_eq!(q.target, "salaries");
        assert_eq!(q.amount, Some(10));
        assert_eq!(q.unit.as_deref(), Some("DAYS"));
        assert_eq!(q.fields, vec!["actor.id".to_string(), "action".to_string()]);
        assert_eq!(q.limit, Some(5));
    }

    #[test]
    fn parse_select_star_is_empty_fields() {
        let q = parse_query(r#"FROM FACTS MATCH (actor.id) EXECUTES "login" AGAINST "*" SELECT *"#)
            .unwrap();
        assert!(q.fields.is_empty());
        assert_eq!(q.limit, None);
    }

    #[test]
    fn malformed_query_is_rejected() {
        assert!(parse_query("SELECT * FROM users").is_err());
    }

    #[test]
    fn huge_time_window_does_not_panic() {
        // Regressão: `WITHIN LAST 999999999999999 DAYS` transbordava/underflow.
        let db = tmp_with_facts(&[("login", "prod")]);
        let rows = execute_query(
            &db,
            r#"FROM FACTS MATCH (actor.id) EXECUTES "*" AGAINST "*" WITHIN LAST 999999999999999 DAYS SELECT *"#,
        )
        .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "janela gigante deve saturar em 'desde o início'"
        );
    }

    #[test]
    fn execute_filters_by_action_target_and_limit() {
        let db = tmp_with_facts(&[
            ("authentication.failure", "prod"),
            ("authentication.failure", "prod"),
            ("authorization.failure", "salaries"),
        ]);

        // Filtro por ação.
        let r = execute_query(
            &db,
            r#"FROM FACTS MATCH (actor.id) EXECUTES "authentication.failure" AGAINST "*" SELECT *"#,
        )
        .unwrap();
        assert_eq!(r.len(), 2);

        // Filtro por target.
        let r = execute_query(
            &db,
            r#"FROM FACTS MATCH (actor.id) EXECUTES "*" AGAINST "salaries" SELECT *"#,
        )
        .unwrap();
        assert_eq!(r.len(), 1);

        // Wildcard total + LIMIT.
        let r = execute_query(
            &db,
            r#"FROM FACTS MATCH (actor.id) EXECUTES "*" AGAINST "*" SELECT * LIMIT 2"#,
        )
        .unwrap();
        assert_eq!(r.len(), 2, "LIMIT deve cortar o scan cedo");
    }
}
