"""
Contrato do compilador: o que um `.hcx` recém-compilado tem de declarar.

O risco que estes testes fecham é silencioso: recompilar um conector e perder a
declaração do modelo canónico. O artefato continuaria válido e assinado, mas
passaria a legado — e ninguém dava por isso até faltarem eventos no SOC.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import forge_compiler

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = ROOT / "rust" / "crates" / "heraclitus-security-schema" / "mappings"


def _compilar(tmp_path: Path, artefato: str) -> dict:
    perfil = forge_compiler.CONNECTOR_PROFILES[artefato]
    compilador = forge_compiler.HeraclitusForgeCompiler(output_dir=str(tmp_path))
    pacote = compilador.compile_knowledge(
        artifact_id=artefato,
        vendor=perfil["vendor"],
        sample_log=perfil["test_matrix"][0]["input"][:300],
    )
    return yaml.safe_load((Path(pacote) / "manifest.yaml").read_text(encoding="utf-8"))


def test_perfil_com_modelo_canonico_declara_o_no_manifesto(tmp_path):
    """SPEC-0071 §4.4: a declaração viaja no artefato, não no código do centro."""
    manifesto = _compilar(tmp_path, "postgresql")
    declaracao = manifesto["security"]
    assert declaracao["security_schema"] == "heraclitus-security-event/1.0"
    assert declaracao["category"] == "data_access"
    assert declaracao["mapping_version"] == "postgresql/1.0.0"
    assert declaracao["required_fields"] == [
        "observed_at_micros",
        "datasource_id",
        "sensor_id",
    ]
    # O mapping citado tem de existir mesmo — citar um inexistente faria o
    # conector falhar fechado só na primeira normalização em produção.
    ficheiro = declaracao["mapping_version"].replace("/", "-") + ".yaml"
    assert (MAPPINGS / ficheiro).is_file()


def test_perfil_sem_modelo_canonico_compila_como_legado(tmp_path):
    """
    Gate CM2: um conector sem mapping publicado continua a ser compilável.

    É o caso do perfil genérico e de qualquer formato que o `forge_ai` derive:
    produz Fatos Operacionais válidos e nenhum evento canónico. O que não pode
    acontecer é o compilador inventar uma `mapping_version` que não existe.
    """
    manifesto = _compilar(tmp_path, "keyvalue_generic")
    assert "security" not in manifesto
    assert manifesto["schema_version"] == "v9"
