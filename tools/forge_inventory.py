#!/usr/bin/env python3
"""Inventario executavel do baseline Forge/SOC definido pela SPEC-0071."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import tomllib
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import forge_sign  # noqa: E402

# Classificacao conservadora: "homologated" vale para o artefato publicado no
# registry deste baseline, nunca como homologacao universal para todo orgao.
BINARY_CLASS = {
    "connector_postgresql": "demo",
    "bench": "demo",
    "cluster_demo": "demo",
    "gateway": "demo",
    "hql": "demo",
    "probe": "demo",
    "fabric": "demo",
    "coverage": "production",
    "export_facts": "production",
    "ingest": "production",
    "quarantine": "production",
    # Harness de fuzzing do descodificador HFB2: existe para ser corrido contra
    # entrada hostil, nao para operar nada.
    "hfb2_fuzz": "fixture",
}

ADAPTERS = [
    {
        "id": "file-tail",
        "classification": "production",
        "evidence": "rust/src/bin/ingest.rs",
        "runtime_wired": True,
        "known_gaps": ["ainda nao implementa SourceAdapter"],
    },
    {
        "id": "syslog-udp",
        "classification": "demo",
        "evidence": "rust/src/bin/probe.rs",
        "runtime_wired": True,
        "known_gaps": ["embutido no probe", "sem supervisor multi-fonte"],
    },
    {
        "id": "syslog-tcp",
        "classification": "demo",
        "evidence": "rust/src/bin/probe.rs",
        "runtime_wired": True,
        "known_gaps": ["embutido no probe", "sem TLS"],
    },
    {
        "id": "http-webhook",
        "classification": "demo",
        "evidence": "rust/src/bin/gateway.rs",
        "runtime_wired": True,
        "known_gaps": ["gateway demonstrativo", "sem SourceAdapter"],
    },
]


def git_head(repo: Path) -> str:
    git_dir = repo / ".git"
    if git_dir.is_file():
        target = git_dir.read_text(encoding="utf-8").strip()
        if not target.startswith("gitdir: "):
            raise ValueError(f"ponte .git invalida: {git_dir}")
        git_dir = (repo / target.removeprefix("gitdir: ")).resolve()

    head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if not head.startswith("ref: "):
        return head
    ref = head.removeprefix("ref: ")
    loose = git_dir / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip()
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "^")):
                commit, name = line.split(" ", 1)
                if name == ref:
                    return commit
    raise ValueError(f"ref Git nao resolvida: {ref}")


def rust_binaries() -> list[dict[str, Any]]:
    cargo = tomllib.loads((ROOT / "rust" / "Cargo.toml").read_text(encoding="utf-8"))
    binaries = []
    for target in sorted(cargo.get("bin", []), key=lambda item: item["name"]):
        name = target["name"]
        binaries.append(
            {
                "name": name,
                "classification": BINARY_CLASS.get(name, "fixture"),
                "evidence": f"rust/{target['path']}",
            }
        )
    return binaries


def read_security_declaration(manifest: Path) -> dict[str, Any] | None:
    """Bloco `security:` do manifesto (SPEC-0071 §4.4), se existir.

    Ausencia nao e defeito: e um conector LEGADO. Registar a diferenca no
    inventario e o que impede que "sem modelo canonico" passe despercebido
    como se fosse "com modelo canonico".
    """
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    declaration = data.get("security")
    return declaration if isinstance(declaration, dict) else None


def artifacts() -> list[dict[str, Any]]:
    result = []
    for package in forge_sign.iter_artifacts(ROOT / "registry"):
        status, detail = forge_sign.verify_artifact(package)
        manifest = package / "manifest.yaml"
        declaration = read_security_declaration(manifest)
        result.append(
            {
                "connector": package.parent.name,
                "version": package.name.removeprefix("v").removesuffix(".hcx"),
                "classification": "homologated" if status == "OK" else "fixture",
                "scope": "published_registry_baseline_only",
                "signature_status": status,
                "signature_detail": detail,
                "canonical_model": "declared" if declaration else "legacy",
                "security_schema": (declaration or {}).get("security_schema"),
                "mapping_version": (declaration or {}).get("mapping_version"),
                "evidence": manifest.relative_to(ROOT).as_posix(),
            }
        )
    return result


def build_inventory() -> dict[str, Any]:
    # O baseline liga-se aos DOIS commits (SPEC-0071 Marco 0), mas o repositorio
    # companheiro nem sempre esta presente: a CI faz checkout de um so. Exigi-lo
    # transformava o inventario num relatorio que so corre na maquina de quem o
    # escreveu — que e precisamente o oposito de um baseline auditavel. Quando
    # falta, diz-se qual e a razao em vez de rebentar ou, pior, de omitir.
    database_repo = Path(os.environ.get("HERACLITUSDB_REPO") or ROOT.parent / "HeraclitusDB")
    try:
        heraclitusdb_commit = git_head(database_repo)
        heraclitusdb_source = database_repo.as_posix()
    except (OSError, ValueError) as error:
        heraclitusdb_commit = None
        heraclitusdb_source = f"indisponivel: {type(error).__name__} em {database_repo.as_posix()}"
    return {
        "schema": "forge-capability-inventory/1.0",
        "spec": "HeraclitusDB/docs/md/SPEC-new/SPEC-0071.md",
        "baseline": {
            "heraclitus_forge_commit": git_head(ROOT),
            "heraclitusdb_commit": heraclitusdb_commit,
            "heraclitusdb_commit_source": heraclitusdb_source,
        },
        "classification_semantics": {
            "fixture": "presente para teste; nao promovido",
            "demo": "executavel demonstrativo; nao e supervisor de producao",
            "production": "caminho operacional existente; limites ficam em known_gaps",
            "homologated": "conteudo assinado no registry deste baseline; nao universal",
        },
        "binaries": rust_binaries(),
        "adapters": ADAPTERS,
        "artifacts": artifacts(),
        "storage": {
            "generation": "HDB2",
            "record_format": "HFB2",
            "documentation": "md/HDB2-HFB2.md",
            "authenticated_identity": ["tenant_id", "datasource_id", "sensor_id"],
            # A geracao anterior e recusada por nome; nao ha migracao.
            "legacy_generation_supported": False,
            "evidence": [
                "rust/src/hfb2.rs",
                "rust/src/db.rs#rewriting_the_tenant_on_disk_breaks_the_leaf",
                "rust/src/db.rs#a_legacy_hdb1_file_is_refused_by_name",
            ],
        },
        "canonical_model": {
            "schema": "heraclitus-security-event/1.0",
            "crate": "rust/crates/heraclitus-security-schema",
            "wire_contract": ("rust/crates/heraclitus-security-schema/schema/security_event.proto"),
            "mappings": sorted(
                path.name
                for path in (
                    ROOT / "rust" / "crates" / "heraclitus-security-schema" / "mappings"
                ).glob("*.yaml")
            ),
            # O Runner resolve o mapping no load do `.hcx` e emite
            # `fact.security` junto com o Fato; o registo HFB2 autentica-o.
            "wired_into_hot_path": True,
            "emitters": ["ingest", "probe", "gateway"],
        },
        "telemetry_health": {
            "schema": "heraclitus-telemetry-health/1.0",
            "consumer": "HeraclitusDB/crates/heraclitus-telemetry-health",
            "emitter": "ingest",
            "record_type": 2,
            "emitted_events": [
                "ExpectationConfigured",
                "ConnectorActivated",
                "SensorHeartbeat",
                "IngestionWindowClosed",
                "SchemaDriftObserved",
                "CheckpointAdvanced",
                "HealthEvaluationTick",
            ],
            # Nao emitidos, e porque: sem carimbo da fonte nao ha skew
            # observavel; drift e falha de parser sao a MESMA observacao na
            # borda; e nada descarta enquanto nao houver buffer limitado.
            "not_emitted": {
                "SensorClockSkewObserved": "observed_at == ingested_at ate o Marco 2 emitir o carimbo da fonte",
                "ParserFailureObserved": "duplicaria SchemaDriftObserved",
                "TelemetryDropRecorded": "nao ha buffer limitado que possa descartar",
            },
            "evidence": [
                "rust/src/telemetry.rs",
                "rust/src/db.rs#health_events_share_the_log_and_the_chain_with_facts",
                "tests/test_bridge.py#test_o_ingestor_emite_saude_no_mesmo_log_dos_fatos",
            ],
        },
        "gates": {
            "CF0_runtime_trust": {
                "status": "implemented",
                "evidence": [
                    "rust/src/hcx.rs",
                    "rust/src/runner.rs#runner_rejects_tampered_artifact_before_parsing_yaml",
                ],
            },
            "CM0_determinism": {
                "status": "implemented",
                "evidence": [
                    "rust/tests/canonical_golden.rs#canonical_events_are_deterministic_for_the_same_input",
                    "rust/crates/heraclitus-security-schema/src/canonical.rs",
                ],
            },
            "CM1_provenance": {
                "status": "implemented",
                "evidence": [
                    "rust/crates/heraclitus-security-schema/src/normalize.rs",
                    "rust/tests/canonical_golden.rs#the_hot_path_emits_the_same_event_an_independent_normalization_produces",
                    "tests/test_bridge.py#test_evento_canonico_de_outra_observacao_e_recusado",
                ],
            },
            "CM2_compatibility": {
                "status": "implemented",
                "evidence": [
                    "rust/tests/canonical_golden.rs#a_legacy_connector_emits_no_canonical_event_in_the_hot_path",
                    "rust/tests/canonical_golden.rs#a_connector_without_the_security_block_stays_legacy",
                    "tests/test_bridge.py#test_conector_legado_sem_bloco_canonico_continua_a_passar",
                ],
            },
            "CM3_no_invention": {
                "status": "implemented",
                "evidence": [
                    "rust/crates/heraclitus-security-schema/src/normalize.rs#combined_log_dash_is_not_an_actor",
                    "rust/crates/heraclitus-security-schema/src/mapping.rs#unmapped_action_is_an_error_not_a_default",
                ],
            },
        },
    }


def validate(inventory: dict[str, Any]) -> list[str]:
    errors = []
    for section in ("binaries", "adapters", "artifacts"):
        if not inventory[section]:
            errors.append(f"secao vazia: {section}")
    for item in inventory["binaries"] + inventory["adapters"]:
        if not (ROOT / item["evidence"].split("#", 1)[0]).exists():
            errors.append(f"evidencia ausente: {item['evidence']}")
    bad = [
        f"{item['connector']}@{item['version']}={item['signature_status']}"
        for item in inventory["artifacts"]
        if item["signature_status"] != "OK"
    ]
    if bad:
        errors.append("artefatos sem assinatura valida: " + ", ".join(bad))
    unknown = sorted(set(binary["name"] for binary in inventory["binaries"]) - BINARY_CLASS.keys())
    if unknown:
        errors.append("binarios sem classificacao explicita: " + ", ".join(unknown))

    if not inventory["baseline"]["heraclitus_forge_commit"]:
        errors.append("baseline sem o commit do proprio repositorio")
    for evidence in inventory["telemetry_health"]["evidence"]:
        if not (ROOT / evidence.split("#", 1)[0]).exists():
            errors.append(f"telemetry_health: evidencia ausente: {evidence}")
    for evidence in inventory["storage"]["evidence"]:
        if not (ROOT / evidence.split("#", 1)[0]).exists():
            errors.append(f"storage: evidencia ausente: {evidence}")
    if not (ROOT / inventory["storage"]["documentation"]).exists():
        errors.append("storage: documentacao do formato ausente")

    canonical = inventory["canonical_model"]
    if not canonical["mappings"]:
        errors.append("nenhum mapping canonico publicado")
    for item in inventory["artifacts"]:
        if item["canonical_model"] != "declared":
            continue
        name = f"{item['connector']}@{item['version']}"
        if item["security_schema"] != canonical["schema"]:
            errors.append(f"{name} declara outro schema canonico: {item['security_schema']}")
        expected = item["mapping_version"].replace("/", "-") + ".yaml"
        if expected not in canonical["mappings"]:
            errors.append(f"{name} cita mapping inexistente: {item['mapping_version']}")
    for gate, detail in inventory["gates"].items():
        for evidence in detail["evidence"]:
            if not (ROOT / evidence.split("#", 1)[0]).exists():
                errors.append(f"{gate}: evidencia ausente: {evidence}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="falha se o baseline estiver incompleto",
    )
    args = parser.parse_args()

    inventory = build_inventory()
    errors = validate(inventory)
    print(json.dumps(inventory, indent=2, ensure_ascii=False, sort_keys=True))
    if args.check and errors:
        for error in errors:
            print(f"[ERROR] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
