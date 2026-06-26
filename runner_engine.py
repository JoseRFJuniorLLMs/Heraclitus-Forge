"""
Heraclitus Runner — runtime declarativo (Line-Rate).

Conforme `plataforma.md` (Produto 3) e `Operational-Fact.md` (secoes 2-5), o Runner
NAO contem IA nem gera codigo: ele apenas le um artefato `.hcx` ja homologado e
executa o pipeline determinístico:

    [Observation] -> 1. Planner -> 2. Optimizer -> 3. Reasoner -> 4. Behavior -> [Operational Fact]

Tudo o que define o comportamento do conector vive no `.hcx` (regex de parse,
regras do Reasoner em `reasoning.yaml`, assinaturas do Behavior Engine em
`behavior.model`). Trocar de conector = trocar de artefato, sem tocar neste codigo.
"""

import os
import re
import time
import uuid
from functools import lru_cache

import blake3
import yaml


# ---------------------------------------------------------------------------
# Helpers de baixo nivel (compartilhados pelos motores)
# ---------------------------------------------------------------------------

class CyclicDependencyException(Exception):
    """Disparada pelo Planner quando a DAG do artefato contem um ciclo."""


def uuid7() -> str:
    """
    Gera um UUIDv7 (time-ordered) sem depender de suporte da stdlib.
    Os 48 bits mais significativos sao o epoch em ms => ids ordenaveis no tempo,
    exatamente como exige a especificacao do `fact.id` (uuid-v7-deterministico).
    """
    ts_ms = int(time.time() * 1000)
    raw = bytearray(ts_ms.to_bytes(6, "big") + os.urandom(10))
    raw[6] = (raw[6] & 0x0F) | 0x70  # version 7
    raw[8] = (raw[8] & 0x3F) | 0x80  # variant RFC 4122
    return str(uuid.UUID(bytes=bytes(raw)))


def evidence_hash(raw_line: str) -> str:
    """Hash bruto BLAKE3 (32 bytes) da observacao de origem (spec secoes 2 e 8)."""
    return f"b3:{blake3.blake3(raw_line.encode('utf-8')).hexdigest()}"


@lru_cache(maxsize=512)
def _compile(pattern: str) -> "re.Pattern":
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# 1. THE PLANNER — ordenacao topologica da DAG (Algoritmo de Kahn, spec secao 3)
# ---------------------------------------------------------------------------

class ExecutionPlanner:
    @staticmethod
    def compile_execution_plan(nodes: dict) -> list:
        in_degree = {u: 0 for u in nodes}
        adj_list = {u: [] for u in nodes}

        for u, spec in nodes.items():
            for dep in (spec.get("depends_on") or []):
                if dep not in nodes:
                    raise CyclicDependencyException(
                        f"Dependencia inexistente '{dep}' referenciada por '{u}'.")
                adj_list[dep].append(u)
                in_degree[u] += 1

        queue = [u for u in nodes if in_degree[u] == 0]
        execution_order = []

        while queue:
            u = queue.pop(0)
            execution_order.append(u)
            for v in adj_list[u]:
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    queue.append(v)

        if len(execution_order) != len(nodes):
            raise CyclicDependencyException("Ciclo detectado na DAG de ingestao.")
        return execution_order


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class ReconstitutiveRunner:
    def __init__(self, artifact_path: str):
        self.artifact_path = artifact_path
        self.manifest = self._load_yaml("manifest.yaml")
        self.architecture = self._load_yaml("architecture.yaml")
        self.ontology = self._load_yaml("ontology.yaml")
        self.reasoning = self._load_yaml("reasoning.yaml")
        self.behavior_model = self._load_yaml("behavior.model")

        # Estado interno compilado
        self.execution_plan = []
        self.parse_step = None            # config do passo de parse
        self.compiled_regex = None        # regex pre-compilada (engine 'regex')
        self.reasoning_rules = self.reasoning.get("rules", [])
        self.behavior_signatures = self.behavior_model.get("signatures", [])
        self.behavior_state = {}          # (signature_id, actor) -> janela deslizante
        self.confidence = float(
            self.ontology.get("behavior_model", {}).get("confidence_score", 0.9))

    # -- carga de componentes do artefato -----------------------------------

    def _load_yaml(self, filename: str) -> dict:
        filepath = os.path.join(self.artifact_path, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Componente do artefato ausente: {filename}")
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # -- FASE 1 & 2: PLANNER + OPTIMIZER ------------------------------------

    def compile_and_optimize(self):
        print(f"=== [Heraclitus Runner] Inicializando Artefato: {self.manifest['id']} ===")
        print("[+] Planner: Resolvendo ordem topologica da DAG (Kahn)...")

        dag = self.architecture["dag"]
        self.execution_plan = ExecutionPlanner.compile_execution_plan(dag)
        print(f"[+] Optimizer: Grafo compilado. Ordem: {' -> '.join(self.execution_plan)}")

        # Pre-compila o motor sintatico para garantir line-rate
        for step_name in self.execution_plan:
            step = dag[step_name]
            if step.get("engine") == "regex":
                self.parse_step = step
                self.compiled_regex = _compile(step["config"]["pattern"])
                print("[+] Optimizer: Expressao regular compilada e otimizada na CPU.")
            elif step.get("engine") == "keyvalue":
                self.parse_step = step
                print("[+] Optimizer: Tokenizador key=value preparado.")
        return self.execution_plan

    # -- FASE: PARSE (sintaxe) ---------------------------------------------

    def _parse(self, raw_line: str):
        engine = (self.parse_step or {}).get("engine")
        line = raw_line.strip()

        if engine == "regex":
            match = self.compiled_regex.match(line)
            return match.groupdict() if match else None

        if engine == "keyvalue":
            tokens = {}
            for chunk in line.split():
                if "=" in chunk:
                    k, _, v = chunk.partition("=")
                    tokens[k] = v
            return tokens or None

        return None

    # -- FASE 3: THE REASONER (regras declarativas, spec secao 4) -----------

    @staticmethod
    def _render(template, ctx: dict):
        if template is None:
            return None
        rendered = re.sub(r"\$\{(\w+)\}",
                          lambda m: str(ctx.get(m.group(1)) or ""),
                          str(template))
        rendered = rendered.strip()
        return rendered or None

    def _match_conditions(self, rule: dict, ctx: dict) -> bool:
        for cond in (rule.get("when") or []):
            if "matches" in cond:
                value = ctx.get(cond["field"]) or ""
                m = _compile(cond["matches"]).search(value)
                if not m:
                    return False
                # Injeta os grupos capturados no contexto para uso posterior
                for k, v in m.groupdict().items():
                    if v is not None:
                        ctx[k] = v
            elif "equals" in cond:
                if str(ctx.get(cond["field"])) != str(cond["equals"]):
                    return False
            elif "contains" in cond:
                if cond["contains"] not in (ctx.get(cond["field"]) or ""):
                    return False
            elif "in" in cond:
                if ctx.get(cond["field"]) not in cond["in"]:
                    return False
            elif "severity_in" in cond:
                if ctx.get("severity") not in cond["severity_in"]:
                    return False
        return True

    def _execute_reasoner(self, tokens: dict) -> dict:
        for rule in self.reasoning_rules:
            ctx = dict(tokens)
            if self._match_conditions(rule, ctx):
                spec = rule.get("set", {})
                identity = spec.get("identity", {})
                return {
                    "rule_id": rule.get("id", "?"),
                    "action": self._render(spec.get("action", "log.info"), ctx),
                    "behavior_class": self._render(spec.get("behavior_class", "observation"), ctx),
                    "risk": spec.get("risk", "Low"),
                    "identity": {
                        "actor_name": self._render(identity.get("actor_name", "${user}"), ctx),
                        "target_id": self._render(identity.get("target_id", ""), ctx),
                        "source_ip": self._render(identity.get("source_ip", "${ip}"), ctx),
                    },
                }
        # Nenhuma regra casou -> Fato desconhecido (alimenta o Active Learning / CKE)
        return {
            "rule_id": "__unmatched__",
            "action": "log.unknown",
            "behavior_class": "observation",
            "risk": "Low",
            "identity": {"actor_name": None, "target_id": None, "source_ip": None},
        }

    # -- FASE 4: THE BEHAVIOR ENGINE (janela deslizante, spec secao 5) ------

    def _execute_behavior_engine(self, actor: str, action: str, current_ts: int) -> dict:
        result = {"behavior_class": None, "risk_level": None, "count_in_window": 0}
        actor = actor or "unknown"

        for sig in self.behavior_signatures:
            if sig.get("trigger_action") != action:
                continue
            key = (sig["id"], actor)
            window = self.behavior_state.setdefault(key, [])
            window.append(current_ts)

            cutoff = current_ts - int(sig.get("window_secs", 60)) * 1_000_000
            while window and window[0] < cutoff:
                window.pop(0)

            result["count_in_window"] = len(window)
            if len(window) >= int(sig.get("threshold", 5)):
                esc = sig.get("escalate_to", {})
                result["behavior_class"] = esc.get("behavior_class")
                result["risk_level"] = esc.get("risk")
        return result

    # -- PIPELINE CORE ------------------------------------------------------

    def process_observation(self, raw_line: str):
        """Transforma a observacao bruta em Fato Operacional (OF). None = drift/falha."""
        current_ts = int(time.time() * 1_000_000)  # microssegundos UTC

        tokens = self._parse(raw_line)
        if tokens is None:
            return None  # Falha sintatica -> Schema Drift (tratado pelo Fabric)

        semantic = self._execute_reasoner(tokens)
        identity = semantic["identity"]

        behavior = self._execute_behavior_engine(
            identity["actor_name"], semantic["action"], current_ts)

        # A escalada comportamental (se houver) sobrepoe a classificacao do Reasoner
        behavior_class = behavior["behavior_class"] or semantic["behavior_class"]
        risk_level = behavior["risk_level"] or semantic["risk"]

        operational_fact = {
            "fact_id": uuid7(),
            "fact.identity": {
                "actor.id": identity["actor_name"],
                "actor.name": identity["actor_name"],
                "target.id": identity["target_id"],
                "source.ip": identity["source_ip"],
            },
            "fact.time": {
                "system_timestamp": current_ts,
                "log_sequence_number": 0,  # atribuido pelo WAL do HeraclitusDB
            },
            "fact.behavior": {
                "class": behavior_class,
                "action": semantic["action"],
                "risk_level": risk_level,
            },
            "fact.evidence": {
                "raw_observation_hash": evidence_hash(raw_line),
                "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo",
            },
            "fact.lineage": {
                "transformation_steps": list(self.execution_plan),
                "input_source": self.manifest["id"],
                "matched_rule": semantic["rule_id"],
            },
            # fact.integrity e preenchido pelo HeraclitusDB no momento da escrita
            "fact.confidence": self.confidence,
            "fact.knowledge_version": self.manifest["id"],
            "fact.reasoning_version": "reasoner-core-v6.0",
            "fact.ontology_version": self.manifest.get("schema_version", "v9"),
        }
        return operational_fact


if __name__ == "__main__":
    runner = ReconstitutiveRunner(artifact_path="./registry/linux_sshd.hcx")
    runner.compile_and_optimize()

    print("\n--- Simulacao de Fluxo de Ingestao Linear ---")
    log_sample = "<13> admin failed password for root from 187.4.5.1"

    for i in range(1, 7):
        time.sleep(0.05)
        print(f"\n[*] Processando Observacao #{i}...")
        fact = runner.process_observation(log_sample)
        print(f"   -> Comportamento Identificado: {fact['fact.behavior']['class']}")
        print(f"   -> Nivel de Risco: {fact['fact.behavior']['risk_level']}")
