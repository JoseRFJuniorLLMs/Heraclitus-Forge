from forge_chaotic import ChaoticItem, InputType
from forge_dialectic import DeterministicDialecticProvider, HeraclitusDialecticForge
from forge_validator import ForgeValidator, HeuristicFilters, VerdictStatus


def test_heuristic_filters():
    heur = HeuristicFilters(min_chars=20, max_chars=500, max_repetition_ratio=0.3)

    # Texto bom
    good_text = (
        "Raciocínio detalhado sobre o log de auditoria. "
        "A Síntese aponta conformidade estrita e Conclusão consistente."
    )
    res_good = heur.evaluate(good_text)
    assert res_good.passed is True
    assert res_good.length_ok is True
    assert res_good.repetition_ok is True

    # Texto curto demais
    res_short = heur.evaluate("Muito curto.")
    assert res_short.passed is False
    assert res_short.length_ok is False

    # Repetição degenerativa
    loop_text = "Raciocínio " + "palavra repetida em loop " * 15
    res_loop = heur.evaluate(loop_text)
    assert res_loop.repetition_ok is False


def test_validator_process():
    item = ChaoticItem(
        id="val_01",
        input_type=InputType.RAW_LOG,
        content="2026-10-01 10:00:00 UTC [1234] FATAL: password authentication failed for user 'root' from 10.0.0.1",
    )
    forge = HeraclitusDialecticForge(provider=DeterministicDialecticProvider(), max_rounds=1)
    dial_res = forge.forge(item)

    validator = ForgeValidator(judge_threshold=0.70)
    package = validator.process(dial_res)

    assert package.is_valid is True
    assert package.judge_score.verdict == VerdictStatus.APPROVED
    assert package.judge_score.overall_score >= 0.70
    assert "schema_version" in package.standard_json
    assert "<heraclitus_dialectic_entry" in package.standard_xml
    assert "<synthesis>" in package.standard_xml
