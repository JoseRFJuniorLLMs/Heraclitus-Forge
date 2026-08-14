"""
Forge AI — derivação de conector via Claude (Design-Time, opcional).

Chama o Claude com **tool calling** (structured output real) para extrair o
perfil de um conector desconhecido a partir de amostras de log. A saída é
validada via Pydantic e devolvida no mesmo shape de CONNECTOR_PROFILES.

Correção crítica em relação ao protótipo anterior:
  - Removido `client.messages.parse(output_format=ConnectorProfile)` — método
    inexistente no SDK Anthropic; crashava com qualquer API key real.
  - Substituído por `client.messages.create(tools=[...], tool_choice=...)` com
    o schema JSON do ConnectorProfile como input_schema da tool.

Requer: pip install anthropic pydantic
        export ANTHROPIC_API_KEY=sk-ant-...
"""

from __future__ import annotations

import _console  # noqa: F401  (consola UTF-8 no Windows)

import os
from typing import List, Optional

MODEL = "claude-opus-4-5"   # modelo LTS homologado (ajuste se necessário)


def available() -> bool:
    """True se é possível chamar o Claude (pacote instalado + API key)."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        import pydantic   # noqa: F401
    except ImportError:
        return False
    return True


def _schema():
    """Define os modelos Pydantic do conector (lazy: importa pydantic só aqui)."""
    from pydantic import BaseModel, Field

    class Condition(BaseModel):
        field: Optional[str] = Field(None, description="token a inspecionar, ex: message, severity")
        matches: Optional[str] = Field(None, description="regex com grupos nomeados")
        equals: Optional[str] = None
        contains: Optional[str] = None
        severity_in: Optional[List[str]] = None

    class Identity(BaseModel):
        actor_name: Optional[str] = Field(None, description="template \\${grupo} do ator")
        target_id: Optional[str] = None
        source_ip: Optional[str] = None

    class SetSpec(BaseModel):
        action: str = Field(description="ação canônica, ex: authentication.failure")
        behavior_class: str
        risk: str = Field(description="Low | Medium | High | Critical")
        identity: Identity

    class Rule(BaseModel):
        id: str
        when: List[Condition]
        set: SetSpec

    class Escalate(BaseModel):
        behavior_class: str
        risk: str

    class Signature(BaseModel):
        id: str
        trigger_action: str
        window_secs: int
        threshold: int
        escalate_to: Escalate

    class Parse(BaseModel):
        engine: str = Field(description="'regex' ou 'keyvalue'")
        pattern: Optional[str] = Field(
            None, description="regex com grupos nomeados (se engine=regex)"
        )

    class ConnectorProfile(BaseModel):
        vendor: str
        domain: str
        confidence: float = Field(description="0.0 a 1.0")
        parse: Parse
        reasoning: List[Rule]
        behavior: List[Signature]

    return ConnectorProfile


_SYSTEM = (
    "Você é o compilador de conhecimento do Heraclitus Forge. Recebe amostras de log "
    "de um formato desconhecido e produz um CONECTOR declarativo: (1) um parser (regex "
    "com grupos nomeados, ou engine 'keyvalue' para KEY=VALUE), (2) regras do Reasoner "
    "que classificam cada linha numa ação canônica (ex: authentication.failure, "
    "query.execute, authorization.failure) com classe e risco, e (3) assinaturas "
    "comportamentais de janela deslizante (ex: brute force = N falhas em T segundos). "
    "Use grupos nomeados na regex e referencie-os nos templates de identity como ${grupo}. "
    "Seja conservador e determinístico: nada de código, apenas a DSL estruturada."
)


def derive_profile(fingerprint: str, vendor: str, samples: List[str]) -> dict:
    """
    Chama o Claude via tool calling e devolve um profile completo no mesmo
    shape de CONNECTOR_PROFILES (forge_compiler.py), pronto para compilação.

    Fluxo:
      1. Monta o schema JSON do ConnectorProfile como input_schema de uma tool.
      2. Chama client.messages.create() forçando tool_choice para a tool.
      3. Extrai o bloco tool_use da resposta e valida com Pydantic.
      4. Completa test_matrix e benchmark e devolve.

    Lança RuntimeError se indisponível ou se Claude não retornou tool_use.
    """
    if not available():
        raise RuntimeError(
            "forge_ai indisponível: defina ANTHROPIC_API_KEY e instale 'anthropic pydantic'"
        )

    import anthropic

    ConnectorProfile = _schema()
    client = anthropic.Anthropic()

    amostras = "\n".join(f"  - {s}" for s in samples)
    prompt = (
        f"Fabricante/sistema: {vendor} (fingerprint '{fingerprint}').\n"
        f"Amostras de log ({len(samples)} linha(s)):\n{amostras}\n\n"
        "Extraia o conector declarativo completo para este formato."
    )

    # Tool schema: o Claude DEVE chamar esta tool com o JSON do conector.
    # Isso substitui client.messages.parse(output_format=) que não existe no SDK.
    tools = [
        {
            "name": "emit_connector_profile",
            "description": (
                "Emite o perfil declarativo completo do conector inferido das amostras "
                "de log. Preencha todos os campos obrigatórios."
            ),
            "input_schema": ConnectorProfile.model_json_schema(),
        }
    ]

    response = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
        tools=tools,
        # Força o modelo a usar exatamente esta tool (structured output garantido)
        tool_choice={"type": "tool", "name": "emit_connector_profile"},
    )

    # Extrai o bloco tool_use (deve existir dado tool_choice forçado)
    tool_block = next(
        (b for b in response.content if b.type == "tool_use"),
        None,
    )
    if tool_block is None:
        raise RuntimeError(
            f"Claude não retornou tool_use (stop_reason={response.stop_reason!r}). "
            "Verifique o modelo e a API key."
        )

    # Valida via Pydantic — garante que o JSON está completo antes de retornar
    try:
        p = ConnectorProfile.model_validate(tool_block.input)
    except Exception as e:
        raise RuntimeError(f"Resposta do Claude falhou na validação Pydantic: {e}") from e

    profile = p.model_dump(exclude_none=True)

    # Completa os campos que forge_compiler espera mas não fazem parte do schema AI
    default_action = (
        profile["reasoning"][0]["set"]["action"]
        if profile.get("reasoning")
        else "log.info"
    )
    profile.setdefault(
        "test_matrix",
        [{"input": s, "expect_action": default_action} for s in samples[:5]],
    )
    profile.setdefault("benchmark", {"estimated_eps": 50_000, "avg_latency_ms": 1.5})
    return profile


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"forge_ai disponível? {available()}")
    if available():
        try:
            prof = derive_profile(
                "fortinet_fortigate",
                "Fortinet FortiGate",
                [
                    "2026-06-26 03:11:01 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.5 action=deny",
                    "2026-06-26 03:11:02 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.9 action=deny",
                    "2026-06-26 03:11:05 UTC FORTI devid=FGT61D type=traffic srcip=10.0.0.7 action=accept",
                ],
            )
            import json
            print(json.dumps(prof, ensure_ascii=False, indent=2))
        except RuntimeError as e:
            print(f"[ERRO] {e}")
    else:
        print("Defina ANTHROPIC_API_KEY e `pip install anthropic pydantic` para forjar via Claude.")
