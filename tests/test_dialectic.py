from forge_chaotic import ChaoticItem, InputType
from forge_dialectic import DeterministicDialecticProvider, HeraclitusDialecticForge


def test_dialectic_deterministic_cycle():
    item = ChaoticItem(
        id="test_01",
        input_type=InputType.RAW_LOG,
        content="2026-10-01 10:00:00 UTC [1234] FATAL: password authentication failed for user 'root' from 10.0.0.1",
        metadata={"source": "sshd"},
    )
    forge = HeraclitusDialecticForge(provider=DeterministicDialecticProvider(), max_rounds=1)
    result = forge.forge(item)

    assert result.item.id == "test_01"
    assert len(result.turns) == 1
    turn = result.turns[0]

    # Verifica Tese
    assert "Tese Inicial" in turn.thesis
    assert "CoT Rodada 1" in turn.thesis_thought

    # Verifica Antítese
    assert "Antítese / Crítica e Desafio" in turn.antithesis
    assert "Alucinação" in turn.antithesis or "Desafio" in turn.antithesis

    # Verifica Síntese
    assert "Síntese Refinada" in turn.synthesis
    assert "Chain-of-Thought" in turn.synthesis
    assert len(turn.structured_facts) == 1
    assert turn.structured_facts[0]["action"] == "authentication.failure"


def test_dialectic_multi_round():
    item = ChaoticItem(
        id="seed_01",
        input_type=InputType.PROMPT_SEED,
        content="Construa uma regra de firewall para bloquear ataques de força bruta.",
    )
    forge = HeraclitusDialecticForge(provider=DeterministicDialecticProvider(), max_rounds=2)
    result = forge.forge(item)

    assert len(result.turns) == 2
    assert result.turns[0].round_number == 1
    assert result.turns[1].round_number == 2
    assert result.metadata["rounds"] == 2
