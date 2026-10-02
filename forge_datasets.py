"""
Heraclitus Forge — Módulo de Datasets & Indexação para HeraclitusDB.

Conforme o Diagrama do Pipeline de Processamento de Dados:
Saída pronta para o Heraclitus:
  1. Datasets de Treino:
     - SFT (Supervised Fine-Tuning): Formatos Alpaca, ShareGPT e OpenAI messages.
     - DPO / ORPO (Alinhamento de Preferência): Pares contrastivos {prompt, chosen, rejected, metadata}.
  2. Indexação de Conhecimento:
     - Fatos Estruturados: Serialização em formato OperationalFact/1.0.
     - Raciocínio Chain-of-Thought (CoT): Preservação de rastros inferenciais.
  3. Carga e Consumo -> HeraclitusDB:
     - Exportação para JSONL canônico compatível com a ponte gRPC (bridge.py).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forge_validator import ValidationPackage


class DatasetExporter:
    """Exportador de datasets de treinamento SFT e DPO/ORPO."""

    @staticmethod
    def build_sft_record(package: ValidationPackage, format_type: str = "alpaca") -> dict[str, Any]:
        """
        Gera um registro para SFT a partir do pacote dialético validado.
        A instrução/entrada original é o prompt, e a Síntese Refinada
        (com seu Chain-of-Thought) é o target esperado.
        """
        item = package.dialectic_result.item
        synthesis = package.dialectic_result.final_synthesis
        thought = package.dialectic_result.final_thought

        # Inclui o bloco Chain-of-Thought explicitamente se disponível
        full_output = f"<thought>\n{thought}\n</thought>\n\n{synthesis}" if thought else synthesis

        if format_type == "sharegpt":
            return {
                "id": package.dialectic_result.item.id,
                "conversations": [
                    {"from": "human", "value": item.content},
                    {"from": "gpt", "value": full_output},
                ],
                "score": package.judge_score.overall_score,
            }
        elif format_type == "messages":
            return {
                "id": package.dialectic_result.item.id,
                "messages": [
                    {"role": "user", "content": item.content},
                    {"role": "assistant", "content": full_output},
                ],
                "score": package.judge_score.overall_score,
            }
        else:  # formato padrão "alpaca"
            return {
                "id": package.dialectic_result.item.id,
                "instruction": f"Processe, analise e formule a resolução operacional dialética para a seguinte entrada ({item.input_type.value}):",
                "input": item.content,
                "output": full_output,
                "score": package.judge_score.overall_score,
                "source": item.metadata.get("source", "heraclitus_forge"),
            }

    @staticmethod
    def build_dpo_record(package: ValidationPackage) -> dict[str, Any]:
        """
        Gera um registro para DPO/ORPO a partir do conflito Tese vs Síntese.
        - prompt: Entrada caótica original.
        - chosen: Síntese Superior e Refinada (aprovada com louvor pelo Judge).
        - rejected: Tese inicial (que continha as fragilidades e omissões apontadas pela Antítese).
        """
        item = package.dialectic_result.item
        turns = package.dialectic_result.turns
        first_turn = turns[0] if turns else None

        chosen_thought = package.dialectic_result.final_thought
        chosen_text = package.dialectic_result.final_synthesis
        chosen = (
            f"<thought>\n{chosen_thought}\n</thought>\n\n{chosen_text}"
            if chosen_thought
            else chosen_text
        )

        if first_turn:
            rejected_thought = first_turn.thesis_thought
            rejected_text = first_turn.thesis
            critique = first_turn.antithesis
        else:
            rejected_thought = ""
            rejected_text = "Resposta inicial simplificada sem refinamento dialético."
            critique = "Ausência de rigor e validação formal."

        rejected = (
            f"<thought>\n{rejected_thought}\n</thought>\n\n{rejected_text}"
            if rejected_thought
            else rejected_text
        )

        return {
            "id": package.dialectic_result.item.id,
            "prompt": item.content,
            "chosen": chosen,
            "rejected": rejected,
            "antithesis_critique": critique,
            "judge_score_chosen": package.judge_score.overall_score,
            "verdict": package.judge_score.verdict.value,
            "metadata": {
                "input_type": item.input_type.value,
                "rounds": len(turns),
                "model_provider": package.dialectic_result.model_provider,
            },
        }

    @classmethod
    def export_sft_dataset(
        cls,
        packages: list[ValidationPackage],
        output_file: str | Path,
        format_type: str = "alpaca",
        approved_only: bool = True,
    ) -> int:
        """Exporta múltiplos pacotes para arquivo JSONL de SFT."""
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        exported_count = 0
        with open(path, "w", encoding="utf-8") as f:
            for pkg in packages:
                if approved_only and not pkg.is_valid:
                    continue
                record = cls.build_sft_record(pkg, format_type=format_type)
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                exported_count += 1
        return exported_count

    @classmethod
    def export_dpo_dataset(
        cls,
        packages: list[ValidationPackage],
        output_file: str | Path,
        approved_only: bool = True,
    ) -> int:
        """Exporta múltiplos pacotes para arquivo JSONL de DPO / ORPO."""
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        exported_count = 0
        with open(path, "w", encoding="utf-8") as f:
            for pkg in packages:
                if approved_only and not pkg.is_valid:
                    continue
                record = cls.build_dpo_record(pkg)
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                exported_count += 1
        return exported_count


class HeraclitusDBIndexer:
    """Indexador de fatos e conhecimento estruturado para o HeraclitusDB."""

    @staticmethod
    def extract_operational_facts(packages: list[ValidationPackage]) -> list[dict[str, Any]]:
        """Extrai todos os fatos estruturados dos pacotes aprovados."""
        all_facts = []
        for pkg in packages:
            if not pkg.is_valid:
                continue
            for fact in pkg.dialectic_result.structured_facts:
                fact_copy = dict(fact)
                fact_copy.setdefault("item_id", pkg.dialectic_result.item.id)
                fact_copy.setdefault("judge_score", pkg.judge_score.overall_score)
                fact_copy.setdefault("producer", "heraclitus-forge-dialectic")
                all_facts.append(fact_copy)
        return all_facts

    @classmethod
    def export_facts_jsonl(cls, packages: list[ValidationPackage], output_file: str | Path) -> int:
        """Exporta os fatos estruturados em JSONL para carga na bridge."""
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        facts = cls.extract_operational_facts(packages)
        with open(path, "w", encoding="utf-8") as f:
            for fact in facts:
                f.write(json.dumps(fact, ensure_ascii=False) + "\n")
        return len(facts)
