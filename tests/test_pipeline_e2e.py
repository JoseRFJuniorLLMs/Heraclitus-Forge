from pathlib import Path

from forge_dialectic_pipeline import get_demo_items, run_pipeline


def test_pipeline_end_to_end(tmp_path: Path):
    items = get_demo_items()
    assert len(items) == 5

    packages = run_pipeline(
        items=items,
        output_dir=tmp_path,
        rounds=1,
        export_sft=True,
        export_dpo=True,
        export_facts=True,
    )

    assert len(packages) == 5
    assert all(p.is_valid for p in packages)

    # Verifica os arquivos gerados
    sft_file = tmp_path / "sft_dataset.jsonl"
    dpo_file = tmp_path / "dpo_orpo_dataset.jsonl"
    facts_file = tmp_path / "operational_facts.jsonl"

    assert sft_file.exists()
    assert dpo_file.exists()
    assert facts_file.exists()

    # Confirma que há registros em cada um
    assert len(sft_file.read_text(encoding="utf-8").strip().splitlines()) == 5
    assert len(dpo_file.read_text(encoding="utf-8").strip().splitlines()) == 5
    assert len(facts_file.read_text(encoding="utf-8").strip().splitlines()) == 5
