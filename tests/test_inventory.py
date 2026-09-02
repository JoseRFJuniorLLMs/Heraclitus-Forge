"""Regressoes do inventario executavel da SPEC-0071/Marco 0."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "forge_inventory", ROOT / "tools" / "forge_inventory.py"
)
assert SPEC and SPEC.loader
forge_inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forge_inventory)


def test_inventory_is_complete_and_all_hcx_are_trusted():
    inventory = forge_inventory.build_inventory()
    assert forge_inventory.validate(inventory) == []
    assert inventory["baseline"]["heraclitus_forge_commit"]
    assert inventory["baseline"]["heraclitusdb_commit"]
    assert all(item["signature_status"] == "OK" for item in inventory["artifacts"])


def test_every_cargo_binary_has_an_explicit_classification():
    inventory = forge_inventory.build_inventory()
    names = {item["name"] for item in inventory["binaries"]}
    assert names == set(forge_inventory.BINARY_CLASS)


def test_p0_connectors_declare_the_canonical_model():
    """SPEC-0071 Marco 1: os quatro conectores P0 mapeados, na versao publicada."""
    inventory = forge_inventory.build_inventory()
    latest = {}
    for item in inventory["artifacts"]:
        version = tuple(int(part) for part in item["version"].split("."))
        if version >= latest.get(item["connector"], ((0, 0, 0), None))[0]:
            latest[item["connector"]] = (version, item)

    assert set(latest) == {"postgresql", "linux_sshd", "nginx_access", "windows_security"}
    for connector, (_, item) in latest.items():
        assert item["canonical_model"] == "declared", connector
        assert item["security_schema"] == inventory["canonical_model"]["schema"]
        arquivo = item["mapping_version"].replace("/", "-") + ".yaml"
        assert arquivo in inventory["canonical_model"]["mappings"], connector


def test_versoes_antigas_continuam_legadas_e_validas():
    """Gate CM2: nao se reescreve conteudo ja publicado para o adaptar."""
    inventory = forge_inventory.build_inventory()
    legadas = [
        item
        for item in inventory["artifacts"]
        if (item["connector"], item["version"])
        in {("postgresql", "1.1.0"), ("linux_sshd", "1.0.0")}
    ]
    assert len(legadas) == 2
    for item in legadas:
        assert item["canonical_model"] == "legacy"
        assert item["signature_status"] == "OK"


def test_existing_adapters_have_real_evidence_paths():
    inventory = forge_inventory.build_inventory()
    for adapter in inventory["adapters"]:
        assert (ROOT / adapter["evidence"]).is_file(), adapter
