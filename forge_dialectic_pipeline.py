"""
Heraclitus Forge — Pipeline Dialético Completo (End-to-End Orchestrator).

Executa o fluxo completo do Diagrama:
  [Entrada Caótica] -> [A Forja Dialética (Tese/Antítese/Síntese)]
                    -> [Validação & Formatação (Judge + Heurística)]
                    -> [Saída Pronta (SFT, DPO/ORPO, HeraclitusDB)]

Uso:
  python forge_dialectic_pipeline.py --demo
  python forge_dialectic_pipeline.py --input amostras.log --output-dir out/
  python forge_dialectic_pipeline.py --input prompts.json --rounds 2 --export-all
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import _console  # noqa: F401  (garante UTF-8 no Windows)
from forge_chaotic import ChaoticIngestion, ChaoticItem
from forge_datasets import DatasetExporter, HeraclitusDBIndexer
from forge_dialectic import HeraclitusDialecticForge
from forge_validator import ForgeValidator, ValidationPackage


def get_demo_items() -> list[ChaoticItem]:
    """Retorna itens de demonstração representativos dos 3 canais de entrada caótica."""
    raw_logs = [
        "2026-10-01 22:15:30 UTC [19202] FATAL: password authentication failed for user 'admin_db' from 187.65.12.99",
        "2026-10-01 22:16:01 SecurityEvent EventID=4625 Computer=SRV-SEC-01 TargetUserName=carlos.mgi LogonType=3 IpAddress=10.2.4.15 Status=0xC000006D",
        '2026-10-01 22:17:10 192.168.1.10 - ana.secretaria [01/Oct/2026:22:17:10 -0300] "GET /api/v1/folha/exportar HTTP/1.1" 403 412 "-" "curl/8.0"',
    ]
    prompt_seeds = [
        {
            "instruction": "Audite a integridade da cadeia de custódia e determine se o acesso ao endpoint /folha/exportar constitui violação de privilégio funcional conforme a LGPD.",
            "context": "Servidor da folha de pagamento em órgão público federal.",
        }
    ]
    interaction_dumps = [
        [
            {
                "role": "user",
                "content": "Alerta detectado: 5 tentativas de logon falhadas seguidas de uma bem-sucedida para o usuário svc-backup.",
            },
            {
                "role": "assistant",
                "content": "Investigue se o IP de origem pertence à rede interna autorizada e se o horário é compatível com a janela de backup.",
            },
        ]
    ]

    items: list[ChaoticItem] = []
    items.extend(ChaoticIngestion.from_raw_logs(raw_logs, source_name="demo_logs"))
    items.extend(ChaoticIngestion.from_prompt_seeds(prompt_seeds, template_name="demo_seeds"))
    items.extend(
        ChaoticIngestion.from_interaction_dump(interaction_dumps, session_prefix="demo_chats")
    )
    return items


def run_pipeline(
    items: list[ChaoticItem],
    output_dir: Path | None = None,
    rounds: int = 1,
    export_sft: bool = True,
    export_dpo: bool = True,
    export_facts: bool = True,
) -> list[ValidationPackage]:
    """Executa o pipeline completo para os itens caóticos fornecidos."""
    start_time = time.time()
    print("=" * 72)
    print("🔥 HERACLITUS-FORGE: PIPELINE DIALÉTICO DE PROCESSAMENTO DE DADOS")
    print("=" * 72)
    print(f"[*] Total de Entradas Caóticas: {len(items)}")
    print(f"[*] Rodadas Dialéticas por Item: {rounds}")
    print("------------------------------------------------------------------------")

    forge = HeraclitusDialecticForge(max_rounds=rounds)
    validator = ForgeValidator()
    packages: list[ValidationPackage] = []

    for idx, item in enumerate(items, start=1):
        print(f"\n[{idx}/{len(items)}] Processando: [{item.input_type.value.upper()}] {item.id}")
        print(f"    Conteúdo: {item.content[:85]}...")

        # 1 & 2. Executa a Forja Dialética (Tese -> Antítese -> Síntese)
        dialectic_res = forge.forge(item)
        print(f"    ✓ Tese gerada (Rodadas: {len(dialectic_res.turns)})")
        print(
            f"    ✓ Antítese gerou desafio crítico ({len(dialectic_res.turns[0].antithesis)} chars)"
        )
        print(
            f"    ✓ Síntese produziu resposta refinada ({len(dialectic_res.final_synthesis)} chars)"
        )

        # 3. Validação e Formatação (LLM-as-a-Judge + Heurística)
        pkg = validator.process(dialectic_res)
        score = pkg.judge_score
        status_icon = "✓" if pkg.is_valid else "✗"
        print(
            f"    {status_icon} Judge Score: {score.overall_score:.2f}/1.00 ({score.verdict.value})"
        )
        print(
            f"      (Acurácia: {score.factual_accuracy:.2f} | CoT: {score.logical_coherence:.2f} | Anti-Alucinação: {score.anti_hallucination:.2f})"
        )
        packages.append(pkg)

    # 4. Saída Pronta para o Heraclitus
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        print("\n------------------------------------------------------------------------")
        print(f"[*] Gravando Saídas Prontas em: {output_dir}")

        if export_sft:
            sft_path = output_dir / "sft_dataset.jsonl"
            sft_count = DatasetExporter.export_sft_dataset(packages, sft_path)
            print(f"    [+] Dataset SFT: {sft_count} registros gravados em `{sft_path.name}`")

        if export_dpo:
            dpo_path = output_dir / "dpo_orpo_dataset.jsonl"
            dpo_count = DatasetExporter.export_dpo_dataset(packages, dpo_path)
            print(
                f"    [+] Dataset DPO/ORPO: {dpo_count} pares contrastivos gravados em `{dpo_path.name}`"
            )

        if export_facts:
            facts_path = output_dir / "operational_facts.jsonl"
            facts_count = HeraclitusDBIndexer.export_facts_jsonl(packages, facts_path)
            print(
                f"    [+] Fatos Estruturados (HeraclitusDB): {facts_count} fatos em `{facts_path.name}`"
            )

        # Salva também a compilação JSON e XML de cada pacote
        for pkg in packages:
            item_id = pkg.dialectic_result.item.id
            xml_path = output_dir / f"{item_id}.xml"
            xml_path.write_text(pkg.standard_xml, encoding="utf-8")

    elapsed = time.time() - start_time
    approved = sum(1 for p in packages if p.is_valid)
    print("\n" + "=" * 72)
    print("🎯 EXECUÇÃO CONCLUÍDA")
    print(f"    - Processados: {len(packages)} | Aprovados: {approved}/{len(packages)}")
    print(
        f"    - Tempo Total: {elapsed:.2f}s | Taxa: {len(packages) / max(elapsed, 0.001):.1f} itens/s"
    )
    print("=" * 72)

    return packages


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pipeline Dialético de Processamento de Dados (Heraclitus-Forge)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Executa o pipeline com amostras de demonstração completas",
    )
    parser.add_argument(
        "--input", "-i", type=str, help="Caminho do arquivo ou diretório de entrada caótica"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="data/dialectic_output",
        help="Diretório de saída para datasets",
    )
    parser.add_argument(
        "--rounds", "-r", type=int, default=1, help="Número de iterações dialéticas de refinamento"
    )
    parser.add_argument("--no-sft", action="store_true", help="Desativa exportação SFT")
    parser.add_argument("--no-dpo", action="store_true", help="Desativa exportação DPO/ORPO")
    parser.add_argument(
        "--no-facts", action="store_true", help="Desativa exportação de Fatos para HeraclitusDB"
    )

    args = parser.parse_args()

    if args.demo or not args.input:
        items = get_demo_items()
    else:
        items = ChaoticIngestion.load_from_file(args.input)

    out_path = Path(args.output_dir)
    run_pipeline(
        items=items,
        output_dir=out_path,
        rounds=args.rounds,
        export_sft=not args.no_sft,
        export_dpo=not args.no_dpo,
        export_facts=not args.no_facts,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
