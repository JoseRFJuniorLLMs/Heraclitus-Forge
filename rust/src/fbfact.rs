//! Codec binário determinístico zero-copy do Fato Operacional (substitui JSON).
//!
//! Implementa, à mão, o MESMO layout da IDL FlatBuffers em `schema/operational_fact.fbs`
//! (o `flatc` não está instalado nesta máquina; quando estiver, o código gerado entra
//! no lugar deste módulo sem mudar o `db.rs`). Propriedades:
//!  - **Sem JSON no caminho quente** do `db.rs` (escrita e hashing).
//!  - **Determinístico**: a ordem dos campos é fixa pelo schema, então a mesma
//!    `Value` produz sempre os mesmos bytes — essencial para a folha BLAKE3.
//!  - **Zero-copy**: acessores como `action()`/`risk()`/`target_id()` leem a fatia
//!    `&str` direto do buffer, sem desserializar nem alocar.
//!
//! Formato: magic "HFB1" + campos na ordem do schema. String = u32 len (0xFFFFFFFF=null)
//! + bytes UTF-8. Escalares i64/u64/f64 em 8 bytes big-endian. lineage = u32 count + N strings.

use serde_json::{json, Value};

const MAGIC: &[u8; 4] = b"HFB1";

// ---- primitivas ----------------------------------------------------------

fn put_str(b: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => b.extend_from_slice(&u32::MAX.to_be_bytes()),
        Some(v) => {
            b.extend_from_slice(&(v.len() as u32).to_be_bytes());
            b.extend_from_slice(v.as_bytes());
        }
    }
}
fn get_str(d: &[u8], p: &mut usize) -> Option<String> {
    let len = u32::from_be_bytes(d[*p..*p + 4].try_into().unwrap());
    *p += 4;
    if len == u32::MAX {
        return None;
    }
    let len = len as usize;
    let s = String::from_utf8_lossy(&d[*p..*p + len]).into_owned();
    *p += len;
    Some(s)
}
/// Pula um campo string e devolve a fatia (&str) sem alocar — base do zero-copy.
fn skip_str<'a>(d: &'a [u8], p: &mut usize) -> Option<&'a str> {
    let len = u32::from_be_bytes(d[*p..*p + 4].try_into().unwrap());
    *p += 4;
    if len == u32::MAX {
        return None;
    }
    let len = len as usize;
    let s = std::str::from_utf8(&d[*p..*p + len]).unwrap_or("");
    *p += len;
    Some(s)
}

fn sget<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut n = v;
    for k in path {
        n = n.get(*k)?;
    }
    n.as_str()
}
fn nget<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut n = v;
    for k in path {
        n = n.get(*k)?;
    }
    Some(n)
}

// ---- encode --------------------------------------------------------------

/// Serializa o Fato completo (com `fact.integrity`, se presente).
pub fn encode(fact: &Value) -> Vec<u8> {
    encode_inner(fact, true)
}
/// Serializa o "core" — SEM `fact.integrity` — usado para a folha BLAKE3.
pub fn encode_core(fact: &Value) -> Vec<u8> {
    encode_inner(fact, false)
}

fn encode_inner(f: &Value, with_integrity: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(MAGIC);
    put_str(&mut b, sget(f, &["fact_id"]));
    put_str(&mut b, sget(f, &["fact.identity", "actor.id"]));
    put_str(&mut b, sget(f, &["fact.identity", "actor.name"]));
    put_str(&mut b, sget(f, &["fact.identity", "target.id"]));
    put_str(&mut b, sget(f, &["fact.identity", "source.ip"]));
    let ts = nget(f, &["fact.time", "system_timestamp"]).and_then(|v| v.as_i64()).unwrap_or(0);
    let lsn = nget(f, &["fact.time", "log_sequence_number"]).and_then(|v| v.as_u64()).unwrap_or(0);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&lsn.to_be_bytes());
    put_str(&mut b, sget(f, &["fact.behavior", "class"]));
    put_str(&mut b, sget(f, &["fact.behavior", "action"]));
    put_str(&mut b, sget(f, &["fact.behavior", "risk_level"]));
    put_str(&mut b, sget(f, &["fact.evidence", "raw_observation_hash"]));
    put_str(&mut b, sget(f, &["fact.evidence", "carimbo_tempo_legal"]));
    let steps = nget(f, &["fact.lineage", "transformation_steps"]).and_then(|v| v.as_array());
    let n = steps.map(|a| a.len()).unwrap_or(0);
    b.extend_from_slice(&(n as u32).to_be_bytes());
    if let Some(a) = steps {
        for s in a {
            put_str(&mut b, s.as_str());
        }
    }
    put_str(&mut b, sget(f, &["fact.lineage", "input_source"]));
    put_str(&mut b, sget(f, &["fact.lineage", "matched_rule"]));
    let conf = nget(f, &["fact.confidence"]).and_then(|v| v.as_f64()).unwrap_or(0.0);
    b.extend_from_slice(&conf.to_be_bytes());
    put_str(&mut b, sget(f, &["fact.knowledge_version"]));
    put_str(&mut b, sget(f, &["fact.reasoning_version"]));
    put_str(&mut b, sget(f, &["fact.ontology_version"]));
    // integrity
    let has = with_integrity && f.get("fact.integrity").is_some();
    b.push(if has { 1 } else { 0 });
    if has {
        put_str(&mut b, sget(f, &["fact.integrity", "leaf_hash"]));
        put_str(&mut b, sget(f, &["fact.integrity", "merkle_root_anchor"]));
        put_str(&mut b, sget(f, &["fact.integrity", "signature"]));
    }
    b
}

// ---- decode --------------------------------------------------------------

fn s(v: Option<String>) -> Value {
    v.map(Value::from).unwrap_or(Value::Null)
}

/// Reconstrói a `Value` (mesmas chaves que o Runner produz).
pub fn decode(d: &[u8]) -> Result<Value, String> {
    if d.len() < 4 || &d[..4] != MAGIC {
        return Err("payload fbfact invalido".into());
    }
    let mut p = 4usize;
    let fact_id = get_str(d, &mut p);
    let actor_id = get_str(d, &mut p);
    let actor_name = get_str(d, &mut p);
    let target_id = get_str(d, &mut p);
    let source_ip = get_str(d, &mut p);
    let ts = i64::from_be_bytes(d[p..p + 8].try_into().unwrap()); p += 8;
    let lsn = u64::from_be_bytes(d[p..p + 8].try_into().unwrap()); p += 8;
    let bclass = get_str(d, &mut p);
    let baction = get_str(d, &mut p);
    let brisk = get_str(d, &mut p);
    let ev_hash = get_str(d, &mut p);
    let carimbo = get_str(d, &mut p);
    let nsteps = u32::from_be_bytes(d[p..p + 4].try_into().unwrap()) as usize; p += 4;
    let mut steps = Vec::with_capacity(nsteps);
    for _ in 0..nsteps {
        steps.push(s(get_str(d, &mut p)));
    }
    let input_source = get_str(d, &mut p);
    let matched_rule = get_str(d, &mut p);
    let conf = f64::from_be_bytes(d[p..p + 8].try_into().unwrap()); p += 8;
    let kver = get_str(d, &mut p);
    let rver = get_str(d, &mut p);
    let over = get_str(d, &mut p);

    let mut fact = json!({
        "fact_id": s(fact_id),
        "fact.identity": { "actor.id": s(actor_id), "actor.name": s(actor_name),
                           "target.id": s(target_id), "source.ip": s(source_ip) },
        "fact.time": { "system_timestamp": ts, "log_sequence_number": lsn },
        "fact.behavior": { "class": s(bclass), "action": s(baction), "risk_level": s(brisk) },
        "fact.evidence": { "raw_observation_hash": s(ev_hash), "carimbo_tempo_legal": s(carimbo) },
        "fact.lineage": { "transformation_steps": Value::Array(steps),
                          "input_source": s(input_source), "matched_rule": s(matched_rule) },
        "fact.confidence": conf,
        "fact.knowledge_version": s(kver),
        "fact.reasoning_version": s(rver),
        "fact.ontology_version": s(over),
    });

    if p < d.len() && d[p] == 1 {
        p += 1;
        let leaf = get_str(d, &mut p);
        let root = get_str(d, &mut p);
        let sig = get_str(d, &mut p);
        fact["fact.integrity"] = json!({
            "leaf_hash": s(leaf), "merkle_root_anchor": s(root), "signature": s(sig)
        });
    }
    Ok(fact)
}

// ---- acessores ZERO-COPY (lêem &str direto do buffer, sem alocar) --------

/// `fact.behavior.action` sem desserializar o Fato inteiro.
pub fn action(d: &[u8]) -> Option<&str> {
    if d.len() < 4 || &d[..4] != MAGIC {
        return None;
    }
    let mut p = 4usize;
    for _ in 0..5 { skip_str(d, &mut p); } // fact_id + 4 de identity
    p += 16; // ts + lsn
    skip_str(d, &mut p); // behavior.class
    skip_str(d, &mut p) // behavior.action
}

/// Offset (dentro do payload) do 1º byte do conteúdo de `raw_observation_hash`.
/// Usado pelo simulador de adulteração para flipar 1 byte mantendo o tamanho.
pub fn evidence_hash_offset(d: &[u8]) -> Option<usize> {
    if d.len() < 4 || &d[..4] != MAGIC {
        return None;
    }
    let mut p = 4usize;
    for _ in 0..5 { skip_str(d, &mut p); } // fact_id + 4 de identity
    p += 16; // ts + lsn
    for _ in 0..3 { skip_str(d, &mut p); } // class, action, risk
    let len = u32::from_be_bytes(d[p..p + 4].try_into().ok()?);
    p += 4;
    if len == u32::MAX || len == 0 {
        return None;
    }
    Some(p)
}

/// `fact.identity.target.id` zero-copy.
pub fn target_id(d: &[u8]) -> Option<&str> {
    if d.len() < 4 || &d[..4] != MAGIC {
        return None;
    }
    let mut p = 4usize;
    skip_str(d, &mut p); // fact_id
    skip_str(d, &mut p); // actor.id
    skip_str(d, &mut p); // actor.name
    skip_str(d, &mut p) // target.id
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_e_zero_copy() {
        let of = json!({
            "fact_id": "abc",
            "fact.identity": {"actor.id":"admin","actor.name":"admin","target.id":"postgresql","source.ip":null},
            "fact.time": {"system_timestamp": 1782468000000000i64, "log_sequence_number": 14812340u64},
            "fact.behavior": {"class":"brute_force_attack","action":"authentication.failure","risk_level":"Critical"},
            "fact.evidence": {"raw_observation_hash":"b3:dead","carimbo_tempo_legal":"icp"},
            "fact.lineage": {"transformation_steps":["parse","normalize","behavior","emit"],"input_source":"pg","matched_rule":"pg_auth_failure"},
            "fact.confidence": 0.972,
            "fact.knowledge_version":"k","fact.reasoning_version":"r","fact.ontology_version":"v9"
        });
        let bytes = encode(&of);
        // zero-copy: lê action/target sem decode completo
        assert_eq!(action(&bytes), Some("authentication.failure"));
        assert_eq!(target_id(&bytes), Some("postgresql"));
        // round-trip completo
        let back = decode(&bytes).unwrap();
        assert_eq!(back["fact.behavior"]["action"], of["fact.behavior"]["action"]);
        assert_eq!(back["fact.confidence"], of["fact.confidence"]);
        assert_eq!(back["fact.lineage"]["transformation_steps"], of["fact.lineage"]["transformation_steps"]);
        // determinismo
        assert_eq!(encode(&of), encode(&decode(&encode(&of)).unwrap()));
    }
}
