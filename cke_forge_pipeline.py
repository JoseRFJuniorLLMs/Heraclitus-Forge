"""
Heraclitus CKE→Forge Pipeline — loop de aprendizado contínuo.

Fecha o loop de Active Learning descrito em spec-ingesta-conector.md:

  quarantine.log  →  cke.analyze()  →  [Claude ou heurística]  →  novo .hcx

Fluxo por cluster:
  1. CKE clusteriza as linhas da quarentena por template estrutural (Drain/Jaccard).
  2. Para cada cluster com amostras suficientes:
     a. Se ANTHROPIC_API_KEY disponível: deriva o perfil via Claude (forge_ai).
     b. Senão: usa a regex sugerida pelo CKE como heurística mínima.
  3. forge_compiler.HeraclitusForgeCompiler() compila o .hcx e salva no registry/.
  4. Imprime relatório; opcionalmente emite JSON com --json-report.

Uso:
  python cke_forge_pipeline.py                     # dados de demonstração
  python cke_forge_pipeline.py quarantine.log      # arquivo gerado pelo fabric.rs
  python cke_forge_pipeline.py -                   # stdin (pipe do fabric)
  python cke_forge_pipeline.py quarantine.log --min-samples 3 --json-report
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import _console  # noqa: F401  (consola UTF-8 no Windows)
import cke
import forge_ai
import forge_compiler

# Mínimo de logs por cluster para tentar compilar um conector.
# Clusters menores podem ser ruído pontual — não valem um .hcx.
MIN_SAMPLES_DEFAULT = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fingerprint_from_template(tmpl: str, idx: int) -> str:
    """Deriva um fingerprint curto e seguro (a-z0-9_) a partir do template."""
    tokens = re.findall(r"[A-Za-z_]{3,}", tmpl)
    base = "_".join(t.lower() for t in tokens[:4]) or f"cluster{idx}"
    fp = re.sub(r"[^a-z0-9_]", "_", base)[:40]
    return f"auto_{fp}"


def _heuristic_profile(fingerprint: str, cluster_info: dict) -> dict:
    """
    Gera um perfil mínimo a partir da regex sugerida pelo CKE.
    Usado quando forge_ai está indisponível (sem API key).
    O perfil é funcional mas sem classificação semântica rica.
    """
    return {
        "vendor": f"Auto-detectado ({fingerprint})",
        "domain": "custom",
        "confidence": 0.70,
        "parse": {
            "engine": "regex",
            "pattern": cluster_info["suggested_regex"],
        },
        "reasoning": [
            {
                "id": f"{fingerprint}_default",
                "when": [],  # regra catch-all
                "set": {
                    "action": "log.info",
                    "behavior_class": "observation",
                    "risk": "Low",
                    "identity": {
                        "actor_name": "${user}",
                        "target_id": "${target}",
                    },
                },
            }
        ],
        "behavior": [],
        "test_matrix": [{"input": cluster_info["sample"], "expect_action": "log.info"}],
        "benchmark": {"estimated_eps": 50_000, "avg_latency_ms": 1.5},
    }


def _raw_lines_for_cluster(all_lines: list[str], template: str) -> list[str]:
    """Devolve as linhas originais (não mascaradas) que pertencem ao cluster."""
    return [ln for ln in all_lines if cke.template(ln) == template]


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------


def run_pipeline(quarantine_lines: list[str], min_samples: int = MIN_SAMPLES_DEFAULT) -> dict:
    """
    Executa o pipeline CKE→Forge e devolve um relatório.

    Args:
        quarantine_lines: logs brutos que falharam no parse (Schema Drift).
        min_samples: mínimo de ocorrências para compilar um conector.

    Returns:
        dict com keys: total_quarantine, clusters_found, clusters_compiled,
                       compiled, skipped, errors.
    """
    report: dict = {
        "total_quarantine": len(quarantine_lines),
        "clusters_found": 0,
        "clusters_compiled": 0,
        "compiled": [],
        "skipped": [],
        "errors": [],
    }

    if not quarantine_lines:
        print("[CKE→Forge] Quarentena vazia. Nada a fazer.")
        return report

    # 1. Clusterizar
    result = cke.analyze(quarantine_lines)
    clusters = result["clusters"]
    report["clusters_found"] = len(clusters)

    print(
        f"\n[CKE→Forge] {len(quarantine_lines)} log(s) → {len(clusters)} cluster(s) "
        f"| entropia={result['entropy_bits']} bits\n"
    )

    ai_ok = forge_ai.available()
    if ai_ok:
        print("[CKE→Forge] forge_ai ✓ — derivando perfis via Claude.")
    else:
        print("[CKE→Forge] forge_ai ✗ — ANTHROPIC_API_KEY ausente; usando heurística de regex.")

    compiler = forge_compiler.HeraclitusForgeCompiler()

    # 2. Para cada cluster
    for idx, cluster_info in enumerate(clusters, start=1):
        count = cluster_info["count"]
        template = cluster_info["template"]
        sample = cluster_info["sample"]

        print(f"\n[Cluster {idx}/{len(clusters)}] {count} log(s) | {template[:70]}")

        # 2a. Filtro de volume mínimo
        if count < min_samples:
            reason = f"apenas {count} amostra(s) < mínimo {min_samples} — ruído descartado"
            print(f"  ⚠  Pulado: {reason}")
            report["skipped"].append({"cluster": idx, "reason": reason})
            continue

        # 2b. Fingerprint único
        fingerprint = _fingerprint_from_template(template, idx)
        if fingerprint in forge_compiler.CONNECTOR_PROFILES:
            fingerprint = f"{fingerprint}_{idx}"

        print(f"  → fingerprint: '{fingerprint}'")

        # 2c. Derivar profile (AI ou heurística)
        raw = _raw_lines_for_cluster(quarantine_lines, template)
        method = "?"
        try:
            if ai_ok:
                profile = forge_ai.derive_profile(
                    fingerprint=fingerprint,
                    vendor=f"Auto-detectado — cluster {idx}",
                    samples=raw[:6],  # até 6 amostras reais
                )
                method = "claude"
                print(f"  ✓ Perfil derivado via Claude ({len(raw)} amostra(s))")
            else:
                profile = _heuristic_profile(fingerprint, cluster_info)
                method = "heurística"
                print("  ✓ Perfil heurístico gerado (regex CKE)")
        # Cada cluster é uma unidade independente; uma falha de SDK/plugin não
        # pode descartar os demais clusters do lote.
        except Exception as exc:  # noqa: BLE001
            err = f"cluster {idx} ({fingerprint}): erro ao derivar perfil — {exc}"
            print(f"  ✗ {err}")
            report["errors"].append(err)
            continue

        # 2d. Compilar .hcx
        try:
            # Injeta temporariamente o profile derivado para o compiler encontrar
            forge_compiler.CONNECTOR_PROFILES[fingerprint] = profile
            artifact_path = compiler.compile_knowledge(
                artifact_id=fingerprint,
                vendor=profile.get("vendor", fingerprint),
                sample_log=sample[:300],
            )
            print(f"  ✓ Compilado [{method}]: {artifact_path}")
            report["compiled"].append(
                {
                    "cluster": idx,
                    "fingerprint": fingerprint,
                    "count": count,
                    "method": method,
                    "path": artifact_path,
                    "coverage_pct": cluster_info["coverage_pct"],
                }
            )
            report["clusters_compiled"] += 1
        except Exception as exc:  # noqa: BLE001 - isolamento por cluster
            err = f"cluster {idx} ({fingerprint}): erro ao compilar .hcx — {exc}"
            print(f"  ✗ {err}")
            report["errors"].append(err)

    # 3. Resumo
    print(f"\n{'=' * 62}")
    print(
        f"[CKE→Forge] Concluído — "
        f"{report['clusters_compiled']} compilado(s), "
        f"{len(report['skipped'])} pulado(s), "
        f"{len(report['errors'])} erro(s)."
    )
    if report["compiled"]:
        print("  Novos artefatos no registry/:")
        for c in report["compiled"]:
            print(f"    {c['fingerprint']}.hcx  [{c['method']}]  ({c['count']} logs)")
    if report["errors"]:
        print("  Erros:")
        for e in report["errors"]:
            print(f"    • {e}")
    print("=" * 62)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Heraclitus CKE→Forge: clusteriza quarentena e compila novos .hcx"
    )
    parser.add_argument(
        "quarantine",
        nargs="?",
        default=None,
        help="Arquivo quarantine.log (ou '-' para stdin). Omita para demo interno.",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=MIN_SAMPLES_DEFAULT,
        metavar="N",
        help=f"Mínimo de logs por cluster para compilar (padrão: {MIN_SAMPLES_DEFAULT})",
    )
    parser.add_argument(
        "--json-report",
        action="store_true",
        help="Imprime relatório JSON completo no final",
    )
    args = parser.parse_args()

    # Lê a quarentena
    if args.quarantine is None:
        print("=== Heraclitus CKE→Forge — dados de demonstração ===")
        quarantine_lines = [
            "2026-06-26 03:11:01 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.5 action=deny",
            "2026-06-26 03:11:02 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.9 action=deny",
            "2026-06-26 03:11:05 UTC FORTI devid=FGT61D type=traffic srcip=10.0.0.7 action=accept",
            "2026-06-26 03:11:09 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.3 action=deny",
            "SIGRH|user=carlos|op=DELETE|tbl=beneficios|status=erro",
            "SIGRH|user=ana|op=UPDATE|tbl=folha|status=ok",
            "SIGRH|user=joao|op=DELETE|tbl=beneficios|status=erro",
        ]
    elif args.quarantine == "-":
        print("=== Heraclitus CKE→Forge — lendo stdin ===")
        quarantine_lines = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        p = Path(args.quarantine)
        if not p.exists():
            print(f"[ERRO] arquivo não encontrado: {p}", file=sys.stderr)
            sys.exit(1)
        print(f"=== Heraclitus CKE→Forge — {p} ({p.stat().st_size} bytes) ===")
        quarantine_lines = [
            ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]

    report = run_pipeline(quarantine_lines, min_samples=args.min_samples)

    if args.json_report:
        print("\n" + json.dumps(report, indent=2, ensure_ascii=False))

    sys.exit(0 if not report["errors"] else 1)


if __name__ == "__main__":
    main()
