import json
from pathlib import Path

from forge_chaotic import ChaoticIngestion, InputType


def test_chaotic_from_raw_logs():
    raw_logs = [
        "2026-10-01 12:00:00 UTC [1000] FATAL: password authentication failed for user 'postgres'",
        '{"event": "logon", "user": "carlos", "status": "failed"}',
    ]
    items = ChaoticIngestion.from_raw_logs(raw_logs, source_name="test_sys")
    assert len(items) == 2
    assert items[0].input_type == InputType.RAW_LOG
    assert items[0].metadata["source"] == "test_sys"
    assert items[0].metadata["raw_format"] == "text"
    assert items[1].metadata["raw_format"] == "json"
    assert "user" in items[1].metadata["parsed_keys"]


def test_chaotic_from_prompt_seeds():
    seeds = [
        "Identifique padrões de intrusão nos acessos fora do horário comercial.",
        {"instruction": "Extraia regras de firewall", "context": "Palo Alto Networks"},
    ]
    items = ChaoticIngestion.from_prompt_seeds(seeds, template_name="audit_seed")
    assert len(items) == 2
    assert items[0].input_type == InputType.PROMPT_SEED
    assert "padrões de intrusão" in items[0].content
    assert items[1].context == "Palo Alto Networks"
    assert items[1].content == "Extraia regras de firewall"


def test_chaotic_from_interaction_dump():
    interactions = [
        "Usuário: O banco caiu.\nAssistente: Verifique os logs do PostgreSQL.",
        [
            {"role": "user", "content": "Erro 403"},
            {"role": "assistant", "content": "Permissão negada."},
        ],
    ]
    items = ChaoticIngestion.from_interaction_dump(interactions, session_prefix="support")
    assert len(items) == 2
    assert items[0].input_type == InputType.INTERACTION_DUMP
    assert items[1].metadata["format"] == "messages_array"
    assert items[1].metadata["turn_count"] == 2


def test_chaotic_load_from_file_jsonl(tmp_path: Path):
    file_path = tmp_path / "sample.jsonl"
    data = [
        {"instruction": "Analise o log", "context": "Linux"},
        {"instruction": "Audite o login", "context": "Windows"},
    ]
    with open(file_path, "w", encoding="utf-8") as f:
        for d in data:
            f.write(json.dumps(d) + "\n")

    items = ChaoticIngestion.load_from_file(file_path)
    assert len(items) == 2
    assert items[0].input_type == InputType.PROMPT_SEED
    assert items[0].content == "Analise o log"
