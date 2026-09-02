"""
Testes dos conectores derivados offline (`forge_seeds`).

Estes conectores foram escritos à mão no formato que a tool
`emit_connector_profile` produz, para o registry ter conectores úteis antes de
haver `ANTHROPIC_API_KEY`. Os testes aqui garantem duas coisas distintas:

  1. que os perfis respeitam o **contrato** que o `forge_ai` também tem de
     respeitar — se o schema mudar, estes falham e avisam;
  2. que o caminho da API está **pronto para a chave** — o schema da tool é
     gerado localmente e pode ser validado sem chamar ninguém.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import forge_ai
import forge_seeds

RISCOS = {"Low", "Medium", "High", "Critical"}


@pytest.fixture(scope="module")
def modelo():
    pytest.importorskip("pydantic")
    return forge_ai._schema()


# ---------------------------------------------------------------------------
# Os perfis respeitam o contrato do forge_ai
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_perfil_valida_contra_o_schema_do_forge_ai(nome, modelo):
    """
    O teste que dá valor a estes perfis: se o schema que o Claude tem de
    preencher mudar, os perfis escritos à mão deixam de validar e alguém é
    avisado — em vez de o registry ficar com conectores num formato morto.
    """
    modelo.model_validate(forge_seeds.SEEDS[nome])


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_regex_de_parse_compila(nome):
    p = forge_seeds.SEEDS[nome]["parse"]
    if p["engine"] == "regex":
        re.compile(p["pattern"])


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_regex_das_regras_compilam(nome):
    for regra in forge_seeds.SEEDS[nome]["reasoning"]:
        for cond in regra["when"]:
            if cond.get("matches"):
                re.compile(cond["matches"])


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_o_parse_casa_todas_as_linhas_do_test_matrix(nome):
    """Uma linha do test_matrix que o parser não casa nunca vira Fato."""
    perfil = forge_seeds.SEEDS[nome]
    if perfil["parse"]["engine"] != "regex":
        pytest.skip("engine não-regex")
    rx = re.compile(perfil["parse"]["pattern"])
    for caso in perfil["test_matrix"]:
        assert rx.match(caso["input"]), f"{nome}: o parser não casa {caso['input'][:60]!r}"


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_cada_caso_do_test_matrix_tem_uma_regra_que_o_produz(nome):
    """
    A cobertura é medida pelo runner Rust na compilação; aqui garante-se antes
    disso que a `expect_action` de cada caso existe mesmo em alguma regra —
    senão o Coverage acusaria e ninguém saberia porquê.
    """
    perfil = forge_seeds.SEEDS[nome]
    acoes = {r["set"]["action"] for r in perfil["reasoning"]}
    for caso in perfil["test_matrix"]:
        assert caso["expect_action"] in acoes, (
            f"{nome}: nenhuma regra produz {caso['expect_action']!r}"
        )


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_riscos_sao_do_vocabulario_canonico(nome):
    perfil = forge_seeds.SEEDS[nome]
    for regra in perfil["reasoning"]:
        assert regra["set"]["risk"] in RISCOS, f"{nome}/{regra['id']}"
    for sig in perfil["behavior"]:
        assert sig["escalate_to"]["risk"] in RISCOS, f"{nome}/{sig['id']}"


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_assinaturas_comportamentais_disparam_em_acoes_que_existem(nome):
    """Uma assinatura que vigia uma ação que nenhuma regra emite nunca dispara."""
    perfil = forge_seeds.SEEDS[nome]
    acoes = {r["set"]["action"] for r in perfil["reasoning"]}
    for sig in perfil["behavior"]:
        assert sig["trigger_action"] in acoes, (
            f"{nome}/{sig['id']}: vigia {sig['trigger_action']!r}, que nenhuma regra emite"
        )


@pytest.mark.parametrize("nome", sorted(forge_seeds.SEEDS))
def test_templates_de_identidade_referem_grupos_existentes(nome):
    """
    Um `${grupo}` que não existe em nenhuma regex vira literal no Fato — o
    actor sairia com o texto `${target_user}` em vez do nome. Silencioso e
    difícil de ver depois de milhares de Fatos gravados.
    """
    perfil = forge_seeds.SEEDS[nome]
    grupos_parse = set(re.compile(perfil["parse"]["pattern"]).groupindex)
    for regra in perfil["reasoning"]:
        grupos = set(grupos_parse)
        for cond in regra["when"]:
            if cond.get("matches"):
                grupos |= set(re.compile(cond["matches"]).groupindex)
        for campo, tmpl in regra["set"]["identity"].items():
            for ref in re.findall(r"\$\{(\w+)\}", tmpl or ""):
                assert ref in grupos, (
                    f"{nome}/{regra['id']}: identity.{campo} usa ${{{ref}}}, "
                    f"que nenhuma regex desta regra captura"
                )


# ---------------------------------------------------------------------------
# O caminho da API está pronto para a chave
# ---------------------------------------------------------------------------


def test_forge_ai_esta_indisponivel_sem_chave(monkeypatch):
    """
    Sem chave, `available()` TEM de dizer que não — é o que impede o pipeline de
    fingir que derivou via Claude quando na verdade usou a heurística.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert forge_ai.available() is False


def test_derive_profile_falha_alto_sem_chave(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        forge_ai.derive_profile("x", "X", ["linha"])


def test_available_exige_modelo_explicito(monkeypatch):
    """Nenhum modelo fica hardcoded: sem FORGE_AI_MODEL, não há chamada."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "chave-de-teste")
    monkeypatch.delenv(forge_ai.MODEL_ENV, raising=False)
    assert forge_ai.available() is False


def test_schema_da_tool_e_json_schema_valido(modelo):
    """
    O `input_schema` da tool é gerado localmente — dá para o validar sem gastar
    uma chamada. Se o Pydantic mudar a forma da geração, isto avisa antes de a
    primeira chamada real falhar em produção.
    """
    sch = modelo.model_json_schema()
    assert sch["type"] == "object"
    assert "properties" in sch
    for obrigatorio in ("vendor", "domain", "confidence", "parse", "reasoning", "behavior"):
        assert obrigatorio in sch["required"], f"{obrigatorio} devia ser obrigatorio"
    # Serializável: a tool viaja como JSON no corpo do pedido.
    json.dumps(sch)
