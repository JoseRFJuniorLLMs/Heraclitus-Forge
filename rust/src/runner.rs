//! ReconstitutiveRunner — runtime declarativo line-rate (porte de `runner_engine.py`).
//!
//! Le um artefato `.hcx` ja compilado pelo Forge e executa o pipeline determinístico
//! Planner (Kahn) -> Parser -> Reasoner (regras) -> Behavior Engine (janela deslizante).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value as Json;

use crate::fact;

// ---------------------------------------------------------------------------
// Modelos de desserializacao do .hcx (serde_yaml)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Manifest {
    id: String,
    #[serde(default)]
    version: String,
    #[serde(default = "default_schema")]
    schema_version: String,
}
fn default_schema() -> String { "v9".into() }

#[derive(Deserialize)]
struct Architecture {
    dag: BTreeMap<String, DagNode>,
}
#[derive(Deserialize)]
struct DagNode {
    engine: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    config: serde_yaml::Value,
}

#[derive(Deserialize)]
struct Reasoning {
    #[serde(default)]
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
struct Rule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    when: Vec<Condition>,
    set: SetSpec,
}
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
struct Condition {
    field: Option<String>,
    matches: Option<String>,
    equals: Option<serde_yaml::Value>,
    contains: Option<String>,
    #[serde(rename = "in")]
    in_: Option<Vec<String>>,
    severity_in: Option<Vec<String>>,
}
#[derive(Deserialize, Clone)]
struct SetSpec {
    #[serde(default = "default_action")]
    action: String,
    #[serde(default = "default_class")]
    behavior_class: String,
    #[serde(default = "default_risk")]
    risk: String,
    #[serde(default)]
    identity: BTreeMap<String, String>,
}
fn default_action() -> String { "log.info".into() }
fn default_class() -> String { "observation".into() }
fn default_risk() -> String { "Low".into() }

#[derive(Deserialize)]
struct BehaviorModel {
    #[serde(default)]
    signatures: Vec<Signature>,
}
#[derive(Deserialize, Clone)]
struct Signature {
    id: String,
    trigger_action: String,
    window_secs: u64,
    threshold: usize,
    escalate_to: Escalate,
}
#[derive(Deserialize, Clone)]
struct Escalate {
    behavior_class: String,
    risk: String,
}

#[derive(Deserialize, Default)]
struct Ontology {
    #[serde(default)]
    behavior_model: OntoBehavior,
}
#[derive(Deserialize, Default)]
struct OntoBehavior {
    #[serde(default = "default_conf")]
    confidence_score: f64,
}
fn default_conf() -> f64 { 0.9 }

// ---------------------------------------------------------------------------
// Representacao compilada (caminho quente)
// ---------------------------------------------------------------------------

struct CompiledCond {
    field: Option<String>,
    matches: Option<Regex>,
    equals: Option<String>,
    contains: Option<String>,
    in_: Option<Vec<String>>,
    severity_in: Option<Vec<String>>,
}
struct CompiledRule {
    id: String,
    when: Vec<CompiledCond>,
    set: SetSpec,
}

#[derive(Clone, Copy, PartialEq)]
enum ParseEngine {
    Regex,
    KeyValue,
}

pub struct ReconstitutiveRunner {
    manifest_id: String,
    pub version: String,
    schema_version: String,
    confidence: f64,
    pub execution_plan: Vec<String>,
    parse_engine: ParseEngine,
    parse_regex: Option<Regex>,
    rules: Vec<CompiledRule>,
    signatures: Vec<Signature>,
    state: HashMap<(String, String), VecDeque<i64>>,
    tpl_re: Regex,
}

fn yaml_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

impl ReconstitutiveRunner {
    pub fn load(artifact_path: &str) -> Result<Self, String> {
        let dir = Path::new(artifact_path);
        let read = |name: &str| -> Result<String, String> {
            std::fs::read_to_string(dir.join(name))
                .map_err(|_| format!("Componente do artefato ausente: {name}"))
        };
        let parse_yaml = |s: &str, name: &str| -> Result<serde_yaml::Value, String> {
            serde_yaml::from_str(s).map_err(|e| format!("YAML invalido em {name}: {e}"))
        };

        let manifest: Manifest =
            serde_yaml::from_str(&read("manifest.yaml")?).map_err(|e| e.to_string())?;
        let architecture: Architecture =
            serde_yaml::from_str(&read("architecture.yaml")?).map_err(|e| e.to_string())?;
        let reasoning: Reasoning =
            serde_yaml::from_str(&read("reasoning.yaml")?).map_err(|e| e.to_string())?;
        let behavior: BehaviorModel =
            serde_yaml::from_str(&read("behavior.model")?).map_err(|e| e.to_string())?;
        let ontology: Ontology =
            serde_yaml::from_str(&read("ontology.yaml")?).unwrap_or_default();
        // valida que os yaml restantes ao menos parseiam
        let _ = parse_yaml(&read("manifest.yaml")?, "manifest.yaml")?;

        // --- Planner (Kahn) + parse engine ---
        let execution_plan = compile_execution_plan(&architecture.dag)?;

        let mut parse_engine = ParseEngine::Regex;
        let mut parse_regex = None;
        for step in &execution_plan {
            let node = &architecture.dag[step];
            match node.engine.as_str() {
                "regex" => {
                    parse_engine = ParseEngine::Regex;
                    if let serde_yaml::Value::Mapping(m) = &node.config {
                        if let Some(p) = m.get(serde_yaml::Value::from("pattern")).and_then(|v| v.as_str()) {
                            parse_regex = Some(Regex::new(p).map_err(|e| format!("regex parse: {e}"))?);
                        }
                    }
                }
                "keyvalue" => parse_engine = ParseEngine::KeyValue,
                _ => {}
            }
        }

        // --- compila regras do Reasoner ---
        let mut rules = Vec::new();
        for r in reasoning.rules {
            let mut conds = Vec::new();
            for c in r.when {
                let matches = match c.matches {
                    Some(p) => Some(Regex::new(&p).map_err(|e| format!("regex reason: {e}"))?),
                    None => None,
                };
                conds.push(CompiledCond {
                    field: c.field,
                    matches,
                    equals: c.equals.as_ref().map(yaml_to_string),
                    contains: c.contains,
                    in_: c.in_,
                    severity_in: c.severity_in,
                });
            }
            rules.push(CompiledRule { id: r.id, when: conds, set: r.set });
        }

        Ok(Self {
            manifest_id: manifest.id,
            version: manifest.version,
            schema_version: manifest.schema_version,
            confidence: ontology.behavior_model.confidence_score,
            execution_plan,
            parse_engine,
            parse_regex,
            rules,
            signatures: behavior.signatures,
            state: HashMap::new(),
            tpl_re: Regex::new(r"\$\{(\w+)\}").unwrap(),
        })
    }

    pub fn plan_str(&self) -> String {
        self.execution_plan.join(" -> ")
    }

    fn parse(&self, raw: &str) -> Option<HashMap<String, String>> {
        let line = raw.trim();
        match self.parse_engine {
            ParseEngine::Regex => {
                let re = self.parse_regex.as_ref()?;
                let caps = re.captures(line)?;
                let mut tokens = HashMap::new();
                for name in re.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        tokens.insert(name.to_string(), m.as_str().to_string());
                    }
                }
                Some(tokens)
            }
            ParseEngine::KeyValue => {
                let mut tokens = HashMap::new();
                for chunk in line.split_whitespace() {
                    if let Some((k, v)) = chunk.split_once('=') {
                        tokens.insert(k.to_string(), v.to_string());
                    }
                }
                if tokens.is_empty() { None } else { Some(tokens) }
            }
        }
    }

    fn render(&self, template: &str, ctx: &HashMap<String, String>) -> Option<String> {
        let out = self
            .tpl_re
            .replace_all(template, |c: &regex::Captures| {
                ctx.get(&c[1]).cloned().unwrap_or_default()
            })
            .trim()
            .to_string();
        if out.is_empty() { None } else { Some(out) }
    }

    fn reason(&self, tokens: &HashMap<String, String>) -> Semantic {
        for rule in &self.rules {
            let mut ctx = tokens.clone();
            if conditions_match(&rule.when, &mut ctx) {
                let id = &rule.set.identity;
                let pick = |key: &str, default: &str| -> Option<String> {
                    self.render(id.get(key).map(|s| s.as_str()).unwrap_or(default), &ctx)
                };
                return Semantic {
                    rule_id: rule.id.clone(),
                    action: self.render(&rule.set.action, &ctx).unwrap_or_else(default_action),
                    behavior_class: self
                        .render(&rule.set.behavior_class, &ctx)
                        .unwrap_or_else(default_class),
                    risk: rule.set.risk.clone(),
                    actor: pick("actor_name", "${user}"),
                    target: pick("target_id", ""),
                    source_ip: pick("source_ip", "${ip}"),
                };
            }
        }
        Semantic {
            rule_id: "__unmatched__".into(),
            action: "log.unknown".into(),
            behavior_class: "observation".into(),
            risk: "Low".into(),
            actor: None,
            target: None,
            source_ip: None,
        }
    }

    fn behavior(&mut self, actor: &str, action: &str, ts: i64) -> (Option<String>, Option<String>) {
        let mut class = None;
        let mut risk = None;
        // Borrows disjuntos de campos distintos de `self` (signatures vs state).
        for sig in &self.signatures {
            if sig.trigger_action != action {
                continue;
            }
            let w = self.state.entry((sig.id.clone(), actor.to_string())).or_default();
            w.push_back(ts);
            let cutoff = ts - (sig.window_secs as i64) * 1_000_000;
            while let Some(&front) = w.front() {
                if front < cutoff {
                    w.pop_front();
                } else {
                    break;
                }
            }
            if w.len() >= sig.threshold {
                class = Some(sig.escalate_to.behavior_class.clone());
                risk = Some(sig.escalate_to.risk.clone());
            }
        }
        (class, risk)
    }

    /// Pipeline core: observacao bruta -> Fato Operacional (None = drift/falha).
    pub fn process_observation(&mut self, raw: &str) -> Option<Json> {
        let ts = fact::now_micros();
        let tokens = self.parse(raw)?;
        let sem = self.reason(&tokens);

        let actor = sem.actor.clone().unwrap_or_else(|| "unknown".into());
        let (beh_class, beh_risk) = self.behavior(&actor, &sem.action, ts);
        let class = beh_class.unwrap_or(sem.behavior_class);
        let risk = beh_risk.unwrap_or(sem.risk);

        Some(serde_json::json!({
            "fact_id": fact::uuid7(),
            "fact.identity": {
                "actor.id": sem.actor,
                "actor.name": sem.actor,
                "target.id": sem.target,
                "source.ip": sem.source_ip,
            },
            "fact.time": { "system_timestamp": ts, "log_sequence_number": 0 },
            "fact.behavior": { "class": class, "action": sem.action, "risk_level": risk },
            "fact.evidence": {
                "raw_observation_hash": fact::evidence_hash(raw),
                "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo",
            },
            "fact.lineage": {
                "transformation_steps": self.execution_plan,
                "input_source": self.manifest_id,
                "matched_rule": sem.rule_id,
            },
            "fact.confidence": self.confidence,
            "fact.knowledge_version": self.manifest_id,
            "fact.reasoning_version": "reasoner-core-v6.0",
            "fact.ontology_version": self.schema_version,
        }))
    }
}

struct Semantic {
    rule_id: String,
    action: String,
    behavior_class: String,
    risk: String,
    actor: Option<String>,
    target: Option<String>,
    source_ip: Option<String>,
}

fn conditions_match(conds: &[CompiledCond], ctx: &mut HashMap<String, String>) -> bool {
    for cond in conds {
        if let Some(re) = &cond.matches {
            let val = cond
                .field
                .as_ref()
                .and_then(|f| ctx.get(f))
                .cloned()
                .unwrap_or_default();
            match re.captures(&val) {
                Some(caps) => {
                    for name in re.capture_names().flatten() {
                        if let Some(m) = caps.name(name) {
                            ctx.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                }
                None => return false,
            }
        } else if let Some(eq) = &cond.equals {
            let field = cond.field.as_deref().unwrap_or("");
            if ctx.get(field).map(|s| s.as_str()) != Some(eq.as_str()) {
                return false;
            }
        } else if let Some(sub) = &cond.contains {
            let field = cond.field.as_deref().unwrap_or("");
            if !ctx.get(field).map(|s| s.contains(sub)).unwrap_or(false) {
                return false;
            }
        } else if let Some(list) = &cond.in_ {
            let field = cond.field.as_deref().unwrap_or("");
            match ctx.get(field) {
                Some(v) if list.contains(v) => {}
                _ => return false,
            }
        } else if let Some(list) = &cond.severity_in {
            match ctx.get("severity") {
                Some(v) if list.contains(v) => {}
                _ => return false,
            }
        }
    }
    true
}

/// Planner — ordenacao topologica da DAG (Algoritmo de Kahn, spec secao 3).
fn compile_execution_plan(nodes: &BTreeMap<String, DagNode>) -> Result<Vec<String>, String> {
    let mut in_degree: BTreeMap<&str, usize> = nodes.keys().map(|k| (k.as_str(), 0)).collect();
    let mut adj: BTreeMap<&str, Vec<&str>> = nodes.keys().map(|k| (k.as_str(), Vec::new())).collect();

    for (u, spec) in nodes {
        for dep in &spec.depends_on {
            if !nodes.contains_key(dep) {
                return Err(format!("Dependencia inexistente '{dep}' em '{u}'."));
            }
            adj.get_mut(dep.as_str()).unwrap().push(u.as_str());
            *in_degree.get_mut(u.as_str()).unwrap() += 1;
        }
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&k, _)| k)
        .collect();
    let mut order = Vec::new();
    while let Some(u) = queue.pop_front() {
        order.push(u.to_string());
        for &v in &adj[u] {
            let e = in_degree.get_mut(v).unwrap();
            *e -= 1;
            if *e == 0 {
                queue.push_back(v);
            }
        }
    }
    if order.len() != nodes.len() {
        return Err("Ciclo detectado na DAG de ingestao.".into());
    }
    Ok(order)
}
