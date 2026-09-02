//! ReconstitutiveRunner — runtime declarativo line-rate (porte de `runner_engine.py`).
//!
//! Le um artefato `.hcx` ja compilado pelo Forge e executa o pipeline determinístico
//! Planner (Kahn) -> Parser -> Reasoner (regras) -> Behavior Engine (janela deslizante).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;

use heraclitus_security_schema::mapping::MappingSpec;
use heraclitus_security_schema::model::hash32;
use heraclitus_security_schema::{from_operational_fact, NormalizationContext, Normalized};
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
    /// Bloco `security:` do manifesto (SPEC-0071 secao 4.4). Ausente = conector
    /// LEGADO: produz Fatos Operacionais validos e nao produz evento canonico.
    /// A ausencia nunca autoriza inventar campos canonicos na leitura.
    #[serde(default)]
    security: Option<SecurityDeclaration>,
}

/// O que o artefato declara sobre o modelo canonico de seguranca.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SecurityDeclaration {
    pub security_schema: String,
    pub category: String,
    pub mapping_version: String,
    pub required_fields: Vec<String>,
}
fn default_schema() -> String {
    "v9".into()
}

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
fn default_action() -> String {
    "log.info".into()
}
fn default_class() -> String {
    "observation".into()
}
fn default_risk() -> String {
    "Low".into()
}

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
fn default_conf() -> f64 {
    0.9
}

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
    pub parser_signature: String,
    /// Digest SHA-256 do `.hcx` **verificado** (`hcx::verify_artifact`). E o
    /// unico valor confiavel: o `digest=` dentro do `signature.sig` e texto que
    /// quem adultera o artefato tambem reescreve.
    connector_digest: [u8; 32],
    /// Mapping canonico resolvido no load. `None` = conector legado.
    security: Option<(SecurityDeclaration, &'static MappingSpec)>,
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
    pub fn load(artifact_path: &str) -> Result<Self, crate::error::HeraclitusError> {
        let dir = Path::new(artifact_path);
        let trust_root = crate::hcx::resolve_trust_root(dir)?;
        Self::load_with_trust_root(dir, &trust_root)
    }

    /// Carrega um `.hcx` usando uma trust root explicita. A assinatura e o
    /// digest sao verificados antes da primeira leitura de YAML.
    pub fn load_with_trust_root(
        dir: &Path,
        trust_root: &Path,
    ) -> Result<Self, crate::error::HeraclitusError> {
        let digest_hex = crate::hcx::verify_artifact(dir, trust_root)?;
        let connector_digest = hash32::from_hex(&digest_hex, None).map_err(|erro| {
            crate::error::HeraclitusError::ArtifactError(format!("digest do .hcx invalido: {erro}"))
        })?;
        let read = |name: &str| -> Result<String, crate::error::HeraclitusError> {
            std::fs::read_to_string(dir.join(name)).map_err(|_| {
                crate::error::HeraclitusError::ArtifactError(format!(
                    "Componente do artefato ausente: {name}"
                ))
            })
        };
        let parse_yaml =
            |s: &str, name: &str| -> Result<serde_yaml::Value, crate::error::HeraclitusError> {
                serde_yaml::from_str(s).map_err(|e| {
                    crate::error::HeraclitusError::ArtifactError(format!(
                        "YAML invalido em {name}: {e}"
                    ))
                })
            };

        let manifest: Manifest = serde_yaml::from_str(&read("manifest.yaml")?)
            .map_err(|e| crate::error::HeraclitusError::ArtifactError(e.to_string()))?;
        let architecture: Architecture = serde_yaml::from_str(&read("architecture.yaml")?)
            .map_err(|e| crate::error::HeraclitusError::ArtifactError(e.to_string()))?;
        let reasoning: Reasoning = serde_yaml::from_str(&read("reasoning.yaml")?)
            .map_err(|e| crate::error::HeraclitusError::ArtifactError(e.to_string()))?;
        let behavior: BehaviorModel = serde_yaml::from_str(&read("behavior.model")?)
            .map_err(|e| crate::error::HeraclitusError::ArtifactError(e.to_string()))?;
        let ontology: Ontology = serde_yaml::from_str(&read("ontology.yaml")?).unwrap_or_default();
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
                        if let Some(p) = m
                            .get(serde_yaml::Value::from("pattern"))
                            .and_then(|v| v.as_str())
                        {
                            parse_regex = Some(Regex::new(p).map_err(|e| {
                                crate::error::HeraclitusError::ArtifactError(format!(
                                    "regex parse: {e}"
                                ))
                            })?);
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
                    Some(p) => Some(Regex::new(&p).map_err(|e| {
                        crate::error::HeraclitusError::ArtifactError(format!("regex reason: {e}"))
                    })?),
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
            rules.push(CompiledRule {
                id: r.id,
                when: conds,
                set: r.set,
            });
        }

        // --- read signature ---
        // Finais de linha canonizados para LF, pela mesma razao que o digest do
        // `.hcx` o faz (ver `hcx::canonical_file_bytes`): o Git materializa o
        // mesmo blob como CRLF no Windows e LF no Linux, e sem isto o MESMO
        // artefato produzia Fatos diferentes conforme o sistema — o que quebra
        // qualquer comparacao byte a byte a jusante.
        let signature_file = read("signature.sig")?;
        let parser_signature = signature_file
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .trim()
            .to_string();

        // --- modelo canonico: resolvido no LOAD, nunca por observacao ---
        // Um artefato que declare um mapping que este binario nao tem, ou que
        // discorde do mapping publicado, impede o datasource de iniciar. Falhar
        // aqui e barato; falhar na milesima linha, em producao, nao e.
        let security = match manifest.security {
            None => None,
            Some(declaration) => {
                let expected = heraclitus_security_schema::SCHEMA_VERSION;
                if declaration.security_schema != expected {
                    return Err(crate::error::HeraclitusError::ArtifactError(format!(
                        "{}: declara o schema canonico {:?}; este runtime implementa {expected:?}",
                        manifest.id, declaration.security_schema
                    )));
                }
                let mapping =
                    heraclitus_security_schema::mapping::mapping(&declaration.mapping_version)
                        .map_err(|erro| {
                            crate::error::HeraclitusError::ArtifactError(format!(
                                "{}: {erro}",
                                manifest.id
                            ))
                        })?;
                if !mapping.accepts_manifest(&manifest.id) {
                    return Err(crate::error::HeraclitusError::ArtifactError(format!(
                        "{}: o mapping {} pertence ao conector {:?}",
                        manifest.id, declaration.mapping_version, mapping.connector
                    )));
                }
                if mapping.primary_category.as_str() != declaration.category {
                    return Err(crate::error::HeraclitusError::ArtifactError(format!(
                        "{}: categoria primaria diverge — artefato diz {:?}, mapping diz {:?}",
                        manifest.id,
                        declaration.category,
                        mapping.primary_category.as_str()
                    )));
                }
                if mapping.required_fields != declaration.required_fields {
                    return Err(crate::error::HeraclitusError::ArtifactError(format!(
                        "{}: required_fields divergem entre artefato e mapping",
                        manifest.id
                    )));
                }
                Some((declaration, mapping))
            }
        };

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
            tpl_re: Regex::new(r"\$\{(\w+)\}")
                .map_err(|e| crate::error::HeraclitusError::ArtifactError(e.to_string()))?,
            parser_signature,
            connector_digest,
            security,
        })
    }

    /// Digest SHA-256 do `.hcx` verificado. E o que liga um evento canonico ao
    /// conteudo exato que o produziu (gate CM1).
    pub fn connector_digest(&self) -> [u8; 32] {
        self.connector_digest
    }

    /// Mapping canonico deste artefato, se ele declarar um.
    pub fn mapping_version(&self) -> Option<&str> {
        self.security
            .as_ref()
            .map(|(declaration, _)| declaration.mapping_version.as_str())
    }

    /// `true` quando o artefato e legado (sem bloco `security:`).
    pub fn is_legacy_connector(&self) -> bool {
        self.security.is_none()
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
                if tokens.is_empty() {
                    None
                } else {
                    Some(tokens)
                }
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
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
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
                    action: self
                        .render(&rule.set.action, &ctx)
                        .unwrap_or_else(default_action),
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
            let w = self
                .state
                .entry((sig.id.clone(), actor.to_string()))
                .or_default();
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
        let ts = fact::now_micros().ok()?;
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
            "fact.integrity": {
                "parser_signature": self.parser_signature.clone(),
            },
            "fact.lineage": {
                "transformation_steps": self.execution_plan,
                "input_source": self.manifest_id.clone(),
                "matched_rule": sem.rule_id,
            },
            "fact.confidence": self.confidence,
            "fact.knowledge_version": format!("{}@{}", self.manifest_id, self.version),
            "fact.reasoning_version": "reasoner-core-v6.0",
            "fact.ontology_version": self.schema_version.clone(),
        }))
    }
}

/// O que o Runner nao pode saber sozinho: de quem e a fonte, onde e que o Fato
/// vai cair no log, e como se volta a ele.
///
/// O Runner observa; quem sabe isto e o supervisor. Passar por parametro em vez
/// de configurar no Runner e o que impede um datasource de herdar a identidade
/// de outro quando ambos partilham o mesmo artefato.
#[derive(Debug, Clone)]
pub struct EmissionContext<'a> {
    pub identity: &'a crate::hfb2::SecurityIdentity,
    /// BLAKE3 da chave publica da ancora do `.hdb` — identifica a origem.
    pub forge_source_id: &'a str,
    /// LSN que este Fato VAI ocupar. O chamador confirma-o depois da escrita.
    pub forge_lsn: u64,
    /// Posicao na sequencia da propria fonte (offset, EventRecordID, cursor).
    /// `None` quando o adapter nao tem uma — nao se inventa um contador.
    pub source_sequence: Option<&'a str>,
    pub source_event_id: Option<&'a str>,
}

impl ReconstitutiveRunner {
    /// Observacao bruta -> Fato Operacional **com** identidade de datasource e,
    /// quando o artefato o declara, o evento canonico em `fact.security`.
    ///
    /// Tres resultados distintos, e a distincao importa:
    ///   * `Ok(None)`      — Schema Drift: nenhuma regra casou. Vai a quarentena.
    ///   * `Ok(Some(f))`   — Fato pronto a gravar.
    ///   * `Err(_)`        — violacao de contrato do artefato. Nao e um problema
    ///     desta linha, e do conector: falha fechado para que o datasource pare
    ///     em vez de degradar em silencio.
    pub fn process_observation_with_context(
        &mut self,
        raw: &str,
        context: &EmissionContext,
    ) -> Result<Option<Json>, crate::error::HeraclitusError> {
        let Some(mut fact) = self.process_observation(raw) else {
            return Ok(None);
        };
        context.identity.apply(&mut fact);

        let Some((declaration, mapping)) = self.security.as_ref() else {
            // Conector legado (gate CM2): Fato valido, sem evento canonico.
            return Ok(Some(fact));
        };

        let ingested = fact["fact.time"]["system_timestamp"].as_i64().unwrap_or(0);
        let normalization = NormalizationContext {
            tenant_id: &context.identity.tenant_id,
            datasource_id: &context.identity.datasource_id,
            sensor_id: &context.identity.sensor_id,
            source_sequence: context.source_sequence,
            // Um salto do relogio para tras entre a ingestao e a normalizacao
            // derrubaria um evento valido; a normalizacao nunca acontece antes
            // da ingestao, por construcao.
            normalized_at_micros: fact::now_micros()?.max(ingested),
            forge_source_id: context.forge_source_id,
            forge_lsn: context.forge_lsn,
            source_event_id: context.source_event_id,
            connector_digest: self.connector_digest,
        };

        match from_operational_fact(&fact, mapping, &normalization) {
            Ok(Normalized::Event(event)) => {
                fact["fact.security"] = serde_json::to_value(&*event).map_err(|erro| {
                    crate::error::HeraclitusError::FactEncodingError(erro.to_string())
                })?;
            }
            // Ruido operacional do servico: ha Fato e nao ha evento de
            // seguranca. Enfia-lo numa categoria seria inventar significado.
            Ok(Normalized::NotSecurityRelevant { .. }) => {}
            Err(erro) => {
                return Err(crate::error::HeraclitusError::ArtifactError(format!(
                    "{}: normalizacao canonica falhou ({}): {erro}",
                    self.manifest_id, declaration.mapping_version
                )))
            }
        }
        Ok(Some(fact))
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
fn compile_execution_plan(
    nodes: &BTreeMap<String, DagNode>,
) -> Result<Vec<String>, crate::error::HeraclitusError> {
    let mut in_degree: BTreeMap<&str, usize> = nodes.keys().map(|k| (k.as_str(), 0)).collect();
    let mut adj: BTreeMap<&str, Vec<&str>> =
        nodes.keys().map(|k| (k.as_str(), Vec::new())).collect();

    for (u, spec) in nodes {
        for dep in &spec.depends_on {
            if !nodes.contains_key(dep) {
                return Err(crate::error::HeraclitusError::ArtifactError(format!(
                    "Dependencia inexistente '{dep}' em '{u}'."
                )));
            }
            if let Some(n) = adj.get_mut(dep.as_str()) {
                n.push(u.as_str());
            }
            if let Some(n) = in_degree.get_mut(u.as_str()) {
                *n += 1;
            }
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
            if let Some(e) = in_degree.get_mut(v) {
                *e -= 1;
                if *e == 0 {
                    queue.push_back(v);
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err(crate::error::HeraclitusError::RunnerError(
            "Ciclo detectado na DAG de ingestao.".into(),
        ));
    }
    Ok(order)
}

/// Resolve a versão MAIS RECENTE de um conector no registry versionado
/// (`<base>/vX.Y.Z.hcx`). O registry passou a ser versionado mas alguns
/// binários ainda apontavam para um caminho fixo `<nome>.hcx` que já não
/// existe — daí este resolver partilhado.
pub fn resolve_latest_artifact(base: &str) -> Option<String> {
    let dir = Path::new(base);
    if !dir.is_dir() {
        return None;
    }
    let mut highest = (0u32, 0u32, 0u32);
    let mut highest_path = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('v') && name.ends_with(".hcx") {
            let parts: Vec<u32> = name[1..name.len() - 4]
                .split('.')
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() == 3 {
                let t = (parts[0], parts[1], parts[2]);
                if t >= highest {
                    highest = t;
                    highest_path = Some(e.path().to_string_lossy().to_string());
                }
            }
        }
    }
    highest_path
}

#[cfg(test)]
mod tests {
    use super::*;

    // Artefato REAL do registry (resolvido a partir do crate, independente do cwd).
    const ARTIFACT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../registry/postgresql/v1.1.0.hcx"
    );

    fn runner() -> ReconstitutiveRunner {
        ReconstitutiveRunner::load(ARTIFACT)
            .expect("artefato postgresql v1.1.0 ausente — rode: python forge_compiler.py")
    }

    #[test]
    fn matches_known_postgres_line_into_a_fact() {
        let mut r = runner();
        let line = "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"";
        let of = r
            .process_observation(line)
            .expect("linha conhecida deveria casar (não é drift)");
        assert_eq!(of["fact.behavior"]["action"], "authentication.failure");
        // O Fato carrega proveniência do artefato que o produziu.
        assert!(of["fact.knowledge_version"]
            .as_str()
            .unwrap()
            .contains("postgresql"));
    }

    #[test]
    fn unknown_line_is_schema_drift() {
        let mut r = runner();
        let of = r.process_observation("=== ruído totalmente fora do schema 42 xyz ===");
        assert!(
            of.is_none(),
            "linha desconhecida deveria cair em Schema Drift (None)"
        );
    }

    #[test]
    fn runner_rejects_tampered_artifact_before_parsing_yaml() {
        let temp = tempfile::tempdir().expect("tempdir");
        let copy = temp.path().join("v1.1.0.hcx");
        copy_dir(Path::new(ARTIFACT), &copy).expect("copiar artefato");
        let architecture = copy.join("architecture.yaml");
        let mut bytes = std::fs::read(&architecture).expect("ler architecture");
        bytes[0] ^= 1;
        std::fs::write(&architecture, bytes).expect("adulterar architecture");
        let trust_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../registry/publisher.pub");

        let error = ReconstitutiveRunner::load_with_trust_root(&copy, &trust_root)
            .err()
            .expect("runner deve falhar fechado");
        assert!(error.to_string().contains("adulterado"));
    }

    fn copy_dir(source: &Path, destination: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }
}
