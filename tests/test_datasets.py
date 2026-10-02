from pathlib import Path

from forge_chaotic import ChaoticItem, InputType
from forge_datasets import DatasetExporter, HeraclitusDBIndexer
from forge_dialectic import DeterministicDialecticProvider, HeraclitusDialecticForge
from forge_validator import ForgeValidator


def test_dataset_exporter_sft_and_dpo(tmp_path: Path):
    item = ChaoticItem(
        id="item_dpo_01",
        input_type=InputType.PROMPT_SEED,
        content="Como isolar a chave de quarentena XChaCha20 no Windows?",
    )
    forge = HeraclitusDialecticForge(provider=DeterministicDialecticProvider(), max_rounds=1)
    dial_res = forge.forge(item)
    validator = ForgeValidator()
    pkg = validator.process(dial_res)

    # 1. Testa registro SFT
    sft_rec = DatasetExporter.build_sft_record(pkg, format_type="alpaca")
    assert sft_rec["id"] == "item_dpo_01"
    assert "<thought>" in sft_rec["output"]
    assert "Síntese Refinada" in sft_rec["output"]

    # 2. Testa registro DPO
    dpo_rec = DatasetExporter.build_dpo_record(pkg)
    assert dpo_rec["id"] == "item_dpo_01"
    assert "Síntese Refinada" in dpo_rec["chosen"]
    assert "Tese Inicial" in dpo_rec["rejected"]
    assert "Antítese / Crítica" in dpo_rec["antithesis_critique"]

    # 3. Exporta arquivos físicos
    sft_file = tmp_path / "sft.jsonl"
    dpo_file = tmp_path / "dpo.jsonl"
    facts_file = tmp_path / "facts.jsonl"

    count_sft = DatasetExporter.export_sft_dataset([pkg], sft_file)
    count_dpo = DatasetExporter.export_dpo_dataset([pkg], dpo_file)
    count_facts = HeraclitusDBIndexer.export_facts_jsonl([pkg], facts_file)

    assert count_sft == 1
    assert count_dpo == 1
    assert count_facts >= 1

    assert sft_file.exists()
    assert dpo_file.exists()
    assert facts_file.exists()
