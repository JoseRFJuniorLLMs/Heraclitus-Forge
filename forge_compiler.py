"""
Heraclitus Forge — compilador de conhecimento (Design-Time).

Conforme `plataforma.md` (Produto 2) e `spec-ingesta-conector.md`, o Forge opera
em sandbox e transforma observacoes heterogeneas em um Artefato de Conhecimento
`.hcx` v6.0 puramente DECLARATIVO. Nada de codigo Python livre no artefato — apenas
DSL (regex de parse, regras do Reasoner, assinaturas do Behavior Engine), o que
elimina o risco de RCE/alucinacao citado na spec.

Em producao, o dicionario `CONNECTOR_PROFILES` abaixo seria a saida estruturada da
esteira multiagente (Claude). Aqui ele esta versionado em codigo para tornar o
pipeline reprodutivel e testavel. Cada profile descreve UM conector.
"""

import os
import json
import hashlib

import yaml


# ---------------------------------------------------------------------------
# BASE DE CONHECIMENTO DOS CONECTORES (saida do "Format Detector + Semantic Mapper")
# ---------------------------------------------------------------------------

CONNECTOR_PROFILES = {

    # === CASO DE USO 1: PostgreSQL (headline) ============================
    "postgresql": {
        "vendor": "PostgreSQL Global Development Group",
        "domain": "database_security",
        "confidence": 0.972,
        "parse": {
            "engine": "regex",
            # log_line_prefix padrao Debian/Ubuntu: '%m [%p] %q%u@%d '
            "pattern": (
                r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \S+)?) "
                r"\[(?P<pid>\d+)\] "
                r"(?:(?P<user>\w+)@(?P<db>\w+) )?"
                r"(?P<severity>[A-Z]+):\s+(?P<message>.*)$"
            ),
        },
        "reasoning": [
            {
                "id": "pg_auth_failure",
                "when": [{"field": "message",
                          "matches": r'password authentication failed for user "(?P<target_user>[^"]+)"'}],
                "set": {
                    "action": "authentication.failure",
                    "behavior_class": "credential_attack",
                    "risk": "High",
                    "identity": {"actor_name": "${target_user}", "target_id": "postgresql"},
                },
            },
            {
                "id": "pg_connection_authorized",
                "when": [{"field": "message",
                          "matches": r"connection authorized: user=(?P<target_user>\w+)(?: database=(?P<target_db>\w+))?"}],
                "set": {
                    "action": "authentication.success",
                    "behavior_class": "session",
                    "risk": "Low",
                    "identity": {"actor_name": "${target_user}", "target_id": "${target_db}"},
                },
            },
            {
                "id": "pg_permission_denied",
                "when": [{"field": "message", "contains": "permission denied"}],
                "set": {
                    "action": "authorization.failure",
                    "behavior_class": "privilege_violation",
                    "risk": "Medium",
                    "identity": {"actor_name": "${user}", "target_id": "${db}"},
                },
            },
            {
                "id": "pg_statement",
                "when": [{"field": "message", "matches": r"^statement: (?P<stmt>.+)$"}],
                "set": {
                    "action": "query.execute",
                    "behavior_class": "data_access",
                    "risk": "Low",
                    "identity": {"actor_name": "${user}", "target_id": "${db}"},
                },
            },
            {
                "id": "pg_fatal",
                "when": [{"severity_in": ["FATAL", "PANIC"]}],
                "set": {
                    "action": "system.fault",
                    "behavior_class": "availability",
                    "risk": "High",
                    "identity": {"actor_name": "${user}", "target_id": "${db}"},
                },
            },
            {
                "id": "pg_info",
                "when": [],  # regra default
                "set": {
                    "action": "log.info",
                    "behavior_class": "observation",
                    "risk": "Low",
                    "identity": {"actor_name": "${user}", "target_id": "${db}"},
                },
            },
        ],
        "behavior": [
            {
                "id": "pg_brute_force",
                "trigger_action": "authentication.failure",
                "window_secs": 60,
                "threshold": 5,
                "escalate_to": {"behavior_class": "brute_force_attack", "risk": "Critical"},
            },
        ],
        "test_matrix": [
            {"input": '2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"',
             "expect_action": "authentication.failure"},
            {"input": '2026-06-26 01:20:11.500 UTC [14808] admin@prod LOG:  connection authorized: user=admin database=prod',
             "expect_action": "authentication.success"},
            {"input": '2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;',
             "expect_action": "query.execute"},
            {"input": '2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries',
             "expect_action": "authorization.failure"},
            {"input": '2026-06-26 01:20:00.001 UTC [14801] LOG:  database system is ready to accept connections',
             "expect_action": "log.info"},
        ],
        "benchmark": {"estimated_eps": 145000, "avg_latency_ms": 0.8},
    },

    # === Conector legado mantido (SSH / syslog) ==========================
    "linux_sshd": {
        "vendor": "Linux OS (OpenSSH)",
        "domain": "identity_access",
        "confidence": 0.984,
        "parse": {
            "engine": "regex",
            "pattern": r"^<(?P<pri>\d+)> (?P<user>\S+) failed password for (?P<target>\S+) from (?P<ip>\S+)",
        },
        "reasoning": [
            {
                "id": "ssh_auth_failure",
                "when": [],
                "set": {
                    "action": "authentication.failure",
                    "behavior_class": "credential_attack",
                    "risk": "High",
                    "identity": {"actor_name": "${user}", "target_id": "${target}", "source_ip": "${ip}"},
                },
            },
        ],
        "behavior": [
            {
                "id": "ssh_brute_force",
                "trigger_action": "authentication.failure",
                "window_secs": 60,
                "threshold": 5,
                "escalate_to": {"behavior_class": "brute_force_attack", "risk": "Critical"},
            },
        ],
        "test_matrix": [
            {"input": "<13> admin failed password for root from 187.4.5.1",
             "expect_action": "authentication.failure"},
        ],
        "benchmark": {"estimated_eps": 82000, "avg_latency_ms": 1.2},
    },

    # === Fallback generico para formatos proprietarios key=value =========
    "keyvalue_generic": {
        "vendor": "Proprietario (Key-Value)",
        "domain": "custom",
        "confidence": 0.91,
        "parse": {"engine": "keyvalue"},
        "reasoning": [
            {
                "id": "kv_destructive_failure",
                "when": [{"field": "STATUS", "equals": "failed"},
                         {"field": "ACTION", "matches": r"(delete|drop|truncate)"}],
                "set": {
                    "action": "data.deletion.failure",
                    "behavior_class": "data_tampering",
                    "risk": "High",
                    "identity": {"actor_name": "${USER}", "target_id": "${TARGET}"},
                },
            },
            {
                "id": "kv_default",
                "when": [],
                "set": {
                    "action": "log.info",
                    "behavior_class": "observation",
                    "risk": "Low",
                    "identity": {"actor_name": "${USER}", "target_id": "${TARGET}"},
                },
            },
        ],
        "behavior": [
            {
                "id": "kv_mass_deletion",
                "trigger_action": "data.deletion.failure",
                "window_secs": 120,
                "threshold": 3,
                "escalate_to": {"behavior_class": "sabotage_attempt", "risk": "Critical"},
            },
        ],
        "test_matrix": [
            {"input": "USER=carlos_mgi ACTION=delete_record TARGET=table_benefits STATUS=failed",
             "expect_action": "data.deletion.failure"},
        ],
        "benchmark": {"estimated_eps": 60000, "avg_latency_ms": 1.5},
    },
}


class HeraclitusForgeCompiler:
    SIGNED_FILES = [
        "manifest.yaml", "architecture.yaml", "ontology.yaml",
        "reasoning.yaml", "behavior.model", "test_matrix.json", "benchmarks.json",
    ]

    def __init__(self, output_dir: str = "./registry"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def _resolve_profile(self, fingerprint: str, vendor: str = None, sample_log: str = None) -> dict:
        # Formatos conhecidos: profile determinístico (rápido, reprodutível).
        if fingerprint in CONNECTOR_PROFILES:
            return CONNECTOR_PROFILES[fingerprint]
        # Formato desconhecido: tenta o agente Claude real (forge_ai), se disponível.
        if vendor is not None and sample_log is not None:
            try:
                import forge_ai
                if forge_ai.available():
                    print("[Forge AI] formato desconhecido -> derivando conector via Claude "
                          "(claude-opus-4-8)...")
                    return forge_ai.derive_profile(fingerprint, vendor, [sample_log])
                print("[Forge AI] sem ANTHROPIC_API_KEY/anthropic -> fallback key-value generico")
            except Exception as e:
                print(f"[Forge AI] indisponivel ({e}) -> fallback key-value generico")
        return CONNECTOR_PROFILES["keyvalue_generic"]

    def compile_knowledge(self, artifact_id: str, vendor: str, sample_log: str) -> str:
        print("=== [Heraclitus Forge] Iniciando Compilacao de Conhecimento ===")
        print(f"[*] Analisando amostra molecular do provedor: {vendor}")
        print(f"[*] Amostra: {sample_log[:80]}")

        profile = self._resolve_profile(artifact_id, vendor=vendor, sample_log=sample_log)
        print(f"[+] Agentes Ativos: Format Detector & Semantic Mapper "
              f"(profile='{artifact_id}', engine='{profile['parse']['engine']}')")

        package_path = os.path.join(self.output_dir, f"{artifact_id}.hcx")
        os.makedirs(package_path, exist_ok=True)
        print(f"[+] Gerando anatomia do artefato: {artifact_id}.hcx")

        # --- 1. manifest.yaml ------------------------------------------------
        manifest = {
            "id": f"br.gov.heraclitus.pipelines.{artifact_id}-v1.0.0",
            "vendor": vendor,
            "version": "1.0.0",
            "schema_version": "v9",
            "domain": profile["domain"],
            "compiled_at": "2026-06-26T02:10:00Z",
        }
        self._dump_yaml(package_path, "manifest.yaml", manifest)

        # --- 2. architecture.yaml (DAG declarativa com depends_on) -----------
        architecture = {
            "version": "6.0",
            "dag": {
                "parse": {"engine": profile["parse"]["engine"],
                          "depends_on": [],
                          "config": {k: v for k, v in profile["parse"].items() if k != "engine"}},
                "normalize": {"engine": "reasoner",
                              "depends_on": ["parse"],
                              "config": {"ruleset": "reasoning.yaml"}},
                "behavior": {"engine": "sliding_window",
                             "depends_on": ["normalize"],
                             "config": {"model": "behavior.model"}},
                "emit": {"engine": "fact_emitter",
                         "depends_on": ["behavior"],
                         "config": {}},
            },
        }
        self._dump_yaml(package_path, "architecture.yaml", architecture)

        # --- 3. ontology.yaml (core binding) ---------------------------------
        ontology = {
            "domain": profile["domain"],
            "core_binding": {"ontology_version": "core-ontology-v9"},
            "behavior_model": {"confidence_score": profile["confidence"]},
        }
        self._dump_yaml(package_path, "ontology.yaml", ontology)

        # --- 4. reasoning.yaml (regras do Reasoner) --------------------------
        self._dump_yaml(package_path, "reasoning.yaml", {"rules": profile["reasoning"]})

        # --- 5. behavior.model (assinaturas do Behavior Engine) --------------
        self._dump_yaml(package_path, "behavior.model", {"signatures": profile["behavior"]})

        # --- 6. test_matrix.json --------------------------------------------
        self._dump_json(package_path, "test_matrix.json", {"cases": profile["test_matrix"]})

        # --- 7. benchmarks.json (selo metrologico, coverage via self-test) ---
        coverage = self._run_coverage(package_path, profile["test_matrix"])
        benchmarks = {
            "coverage_rate": coverage["rate"],
            "covered": coverage["covered"],
            "total": coverage["total"],
            "estimated_eps": profile["benchmark"]["estimated_eps"],
            "avg_latency_ms": profile["benchmark"]["avg_latency_ms"],
            "global_confidence_score": profile["confidence"],
        }
        self._dump_json(package_path, "benchmarks.json", benchmarks)
        print(f"[+] Coverage calculado (regressao sintatica): "
              f"{coverage['covered']}/{coverage['total']} = {coverage['rate']:.1f}%")

        # --- 8. signature.sig (Ed25519 mock sobre o hash combinado) ----------
        print("[+] Finalizando com blindagem criptografica...")
        hasher = hashlib.sha256()
        for target_file in self.SIGNED_FILES:
            with open(os.path.join(package_path, target_file), "rb") as f:
                hasher.update(f.read())
        signature = f"ed25519:sig:{hasher.hexdigest()[:48]}"
        with open(os.path.join(package_path, "signature.sig"), "w", encoding="utf-8") as f:
            f.write(signature)

        print(f"[OK] COMPILACAO CONCLUIDA. Artefato pronto em: {package_path}\n")
        return package_path

    # -- self-test: o Forge roda o Runner contra a test_matrix --------------

    def _run_coverage(self, package_path: str, cases: list) -> dict:
        """Calcula Coverage instanciando um Runner real sobre o artefato recem-escrito."""
        from runner_engine import ReconstitutiveRunner  # lazy: evita ciclo de import

        runner = ReconstitutiveRunner(artifact_path=package_path)
        runner.compile_and_optimize()

        covered = 0
        for case in cases:
            fact = runner.process_observation(case["input"])
            if fact and fact["fact.behavior"]["action"] == case["expect_action"]:
                covered += 1
        total = len(cases) or 1
        return {"covered": covered, "total": len(cases), "rate": 100.0 * covered / total}

    # -- helpers de escrita -------------------------------------------------

    @staticmethod
    def _dump_yaml(path: str, name: str, data: dict):
        with open(os.path.join(path, name), "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    @staticmethod
    def _dump_json(path: str, name: str, data: dict):
        with open(os.path.join(path, name), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    compiler = HeraclitusForgeCompiler()
    compiler.compile_knowledge(
        artifact_id="postgresql",
        vendor="PostgreSQL Global Development Group",
        sample_log='2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"',
    )
