"""
Forge AI — derivação de conector via Claude (Design-Time, opcional).

Este é o "agente real" do Heraclitus Forge: dado um punhado de amostras de log de
um formato desconhecido, chama o **Claude** (SDK oficial `anthropic`) com **saída
estruturada (Pydantic)** para extrair o perfil do conector — regex de parse, regras
do Reasoner e assinaturas do Behavior Engine — no MESMO shape de `CONNECTOR_PROFILES`
do `forge_compiler.py`.

Permanece em Python por design (o Forge é Design-Time; latência de IA não afeta a
produção — ver `resumo.md`). É **opcional**: requer `pip install anthropic` e a env
`ANTHROPIC_API_KEY`. Sem isso, `forge_compiler` cai nos profiles estáticos.

Modelo: `claude-opus-4-8` (default da plataforma) com adaptive thinking.
"""

from __future__ import annotations

import os
from typing import List, Optional

MODEL = "claude-opus-4-8"


def available() -> bool:
    """True se dá para chamar o Claude (pacote instalado + API key)."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        import pydantic  # noqa: F401
    except Exception:
        return False
    return True


def _schema():
    """Define os modelos Pydantic da saída estruturada (lazy: só com pydantic)."""
    from pydantic import BaseModel, Field

    class Condition(BaseModel):
        field: Optional[str] = Field(None, description="token a inspecionar, ex.: message, severity")
        matches: Optional[str] = Field(None, description="regex com grupos nomeados a capturar")
        equals: Optional[str] = None
        contains: Optional[str] = None
        severity_in: Optional[List[str]] = None

    class Identity(BaseModel):
        actor_name: Optional[str] = Field(None, description="template ${grupo} do ator")
        target_id: Optional[str] = None
        source_ip: Optional[str] = None

    class SetSpec(BaseModel):
        action: str = Field(description="acao canonica, ex.: authentication.failure")
        behavior_class: str
        risk: str = Field(description="Low|Medium|High|Critical")
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
        engine: str = Field(description="regex ou keyvalue")
        pattern: Optional[str] = Field(None, description="regex com grupos nomeados (se engine=regex)")

    class ConnectorProfile(BaseModel):
        vendor: str
        domain: str
        confidence: float = Field(description="0.0 a 1.0")
        parse: Parse
        reasoning: List[Rule]
        behavior: List[Signature]

    return ConnectorProfile


_SYSTEM = (
    "Voce e o compilador de conhecimento do Heraclitus Forge. Recebe amostras de log "
    "de um formato desconhecido e produz um CONECTOR declarativo: (1) um parser (regex "
    "com grupos nomeados, ou engine 'keyvalue' para KEY=VALUE), (2) regras do Reasoner "
    "que classificam cada linha numa acao canonica (ex.: authentication.failure, "
    "query.execute, authorization.failure) com classe e risco, e (3) assinaturas "
    "comportamentais de janela deslizante (ex.: brute force = N falhas em T segundos). "
    "Use grupos nomeados na regex e referencie-os nos templates de identity como ${grupo}. "
    "Seja conservador e deterministico: nada de codigo, apenas a DSL estruturada."
)


def derive_profile(fingerprint: str, vendor: str, samples: List[str]) -> dict:
    """
    Chama o Claude e devolve um profile completo (mesmo shape de CONNECTOR_PROFILES,
    com test_matrix derivada das amostras e benchmark default). Lança se indisponível.
    """
    if not available():
        raise RuntimeError("forge_ai indisponivel: defina ANTHROPIC_API_KEY e instale 'anthropic'")

    import anthropic

    ConnectorProfile = _schema()
    client = anthropic.Anthropic()

    amostras = "\n".join(f"- {s}" for s in samples)
    prompt = (
        f"Fabricante/sistema: {vendor} (fingerprint '{fingerprint}').\n"
        f"Amostras de log:\n{amostras}\n\n"
        "Extraia o conector declarativo para este formato."
    )

    response = client.messages.parse(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
        output_format=ConnectorProfile,
    )
    p = response.parsed_output  # instancia validada de ConnectorProfile
    profile = p.model_dump(exclude_none=True)

    # Completa os campos que o forge_compiler espera (test_matrix + benchmark).
    expect = profile["reasoning"][0]["set"]["action"] if profile.get("reasoning") else "log.info"
    profile.setdefault("test_matrix", [{"input": s, "expect_action": expect} for s in samples[:5]])
    profile.setdefault("benchmark", {"estimated_eps": 50000, "avg_latency_ms": 1.5})
    return profile


if __name__ == "__main__":
    # Smoke test honesto: só roda de verdade se houver API key + pacote.
    print(f"forge_ai disponivel? {available()}")
    if available():
        prof = derive_profile(
            "fortinet",
            "Fortinet FortiGate",
            [
                "2026-06-26 03:11:01 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.5 action=deny",
                "2026-06-26 03:11:02 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.9 action=deny",
            ],
        )
        import json
        print(json.dumps(prof, ensure_ascii=False, indent=2))
    else:
        print("Defina ANTHROPIC_API_KEY e `pip install anthropic` para forjar via Claude.")
