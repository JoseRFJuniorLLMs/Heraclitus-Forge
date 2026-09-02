"""
Testes da ponte Forge → HeraclitusDB.

O que corre por omissão (`pytest`) é tudo menos a escrita no banco: o exportador
Rust real, o `.hdb` real e o mapa canónico. A escrita gRPC está atrás do marcador
`live` porque o HeraclitusDB local é o banco de memória do utilizador — um
`pytest` distraído não pode acrescentar-lhe lixo.

    pytest tests/                # seguro, não escreve em lado nenhum
    pytest tests/ -m live        # inclui a escrita real no HeraclitusDB
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge

ROOT = Path(__file__).resolve().parent.parent
HDB = ROOT / "rust" / "target" / "bridge-test" / "source.hdb"


def _release_bin(name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return ROOT / "rust" / "target" / "release" / f"{name}{suffix}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def exporter() -> str:
    cargo = shutil.which("cargo")
    assert cargo is not None, "cargo não encontrado no PATH"
    build_env = os.environ.copy()
    # Binários de outro workspace num target global podem ter o mesmo nome.
    # A integração sempre compila e executa rust/target/release deste checkout.
    build_env.pop("CARGO_TARGET_DIR", None)
    built = subprocess.run(
        [cargo, "build", "--release", "--bins", "--locked"],
        cwd=ROOT / "rust",
        env=build_env,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    try:
        return bridge.exporter_bin()
    except SystemExit as e:
        pytest.skip(str(e))


@pytest.fixture(scope="module")
def signed_hdb(exporter) -> Path:
    """Cria uma origem real, persistente e assinada usando o conector Rust."""
    HDB.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", ".anchor", ".anchor.sig", ".key", ".pub"):
        Path(f"{HDB}{suffix}").unlink(missing_ok=True)
    quarantine = HDB.parent / "source.quarantine.hq"
    quarantine.unlink(missing_ok=True)
    connector = (
        ROOT
        / "rust"
        / "target"
        / "release"
        / ("connector_postgresql.exe" if os.name == "nt" else "connector_postgresql")
    )
    env = os.environ.copy()
    env.update(
        {
            "HERACLITUS_DB_PATH": str(HDB),
            "HERACLITUS_ARTIFACT": str(ROOT / "registry" / "postgresql"),
            "HERACLITUS_SAMPLE": str(ROOT / "samples" / "postgresql.log"),
            "FORGE_QUARANTINE_PATH": str(quarantine),
            bridge.QUARANTINE_KEY_ENV: "ab" * 32,
        }
    )
    made = subprocess.run(
        [str(connector)],
        cwd=ROOT / "rust",
        env=env,
        capture_output=True,
        text=True,
    )
    assert made.returncode == 0, made.stderr
    probe = subprocess.run([exporter, str(HDB), "--limit", "1"], capture_output=True, text=True)
    assert probe.returncode == 0, probe.stderr
    return HDB


@pytest.fixture(scope="module")
def real_facts(exporter, signed_hdb) -> list[tuple[int, dict]]:
    """Fatos reais, lidos de um `.hdb` assinado pelo exportador verdadeiro."""
    facts = list(bridge.export_jsonl(HDB, 0, limit=20))
    if not facts:
        pytest.skip(f"{HDB} não tem Fatos")
    return facts


@pytest.mark.parametrize(
    "binary",
    ["bench", "cluster_demo", "connector_postgresql", "fabric", "hql"],
)
def test_demo_and_utility_bins_fail_closed_by_default(exporter, tmp_path, binary):
    """Executar um utilitário sem opt-in/configuração nunca cria dados no cwd."""
    env = os.environ.copy()
    for name in (
        "HERACLITUS_ARTIFACT",
        "HERACLITUS_DB",
        "HERACLITUS_DB_PATH",
        "HERACLITUS_SAMPLE",
        "FORGE_QUARANTINE_KEY",
        "FORGE_QUARANTINE_PATH",
    ):
        env.pop(name, None)
    result = subprocess.run(
        [str(_release_bin(binary))],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("binary", "args"),
    [
        ("bench", ["--demo", "10"]),
        ("cluster_demo", ["--demo"]),
        ("connector_postgresql", ["--demo"]),
        ("fabric", ["--demo"]),
        ("hql", ["--demo"]),
    ],
)
def test_demo_bins_complete_without_leaving_operational_files(exporter, binary, args):
    rust_dir = ROOT / "rust"
    patterns = ("*.hdb", "*.anchor", "*.anchor.sig", "*.key", "*.pub", "*.hq")
    before = {path.resolve() for pattern in patterns for path in rust_dir.glob(pattern)}
    env = os.environ.copy()
    env.pop("HERACLITUS_DB", None)
    result = subprocess.run(
        [str(_release_bin(binary)), *args],
        cwd=rust_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    after = {path.resolve() for pattern in patterns for path in rust_dir.glob(pattern)}
    assert after == before


def test_gateway_refuses_non_loopback_before_creating_data(exporter, tmp_path):
    db_path = tmp_path / "must-not-exist.hdb"
    quarantine = tmp_path / "must-not-exist.hq"
    env = os.environ.copy()
    env.update(
        {
            "FORGE_GATEWAY_ADDR": "0.0.0.0:7480",
            "FORGE_GATEWAY_DB": str(db_path),
            "FORGE_QUARANTINE_PATH": str(quarantine),
            "FORGE_QUARANTINE_KEY": "ab" * 32,
        }
    )
    result = subprocess.run(
        [str(_release_bin("gateway"))],
        cwd=ROOT / "rust",
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert not db_path.exists()
    assert not quarantine.exists()


def test_gateway_quarantines_drift_without_echoing_pii(exporter, tmp_path):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    db_path = tmp_path / "gateway.hdb"
    quarantine = tmp_path / "gateway.hq"
    key = bytes.fromhex("cd" * 32)
    env = os.environ.copy()
    env.update(
        {
            "FORGE_GATEWAY_ADDR": f"127.0.0.1:{port}",
            "FORGE_GATEWAY_DB": str(db_path),
            "FORGE_ARTIFACT_DIR": str(ROOT / "registry" / "postgresql"),
            "FORGE_QUARANTINE_PATH": str(quarantine),
            "FORGE_QUARANTINE_KEY": key.hex(),
        }
    )
    proc = subprocess.Popen(
        [str(_release_bin("gateway"))],
        cwd=ROOT / "rust",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=0.2) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("gateway não iniciou em 5 segundos")

        pii = "matricula=12345678901 source.ip=10.20.30.40 formato-invalido"
        request = urllib.request.Request(
            f"{base}/ingest",
            data=pii.encode(),
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read().decode()
        assert "quarantined" in body
        assert "12345678901" not in body
        assert "10.20.30.40" not in body
        assert "12345678901" not in quarantine.read_text(encoding="ascii")

        records = list(bridge.decrypt_quarantine(quarantine, key=key))
        assert records[0]["observation"] == pii

        with urllib.request.urlopen(
            f"{base}/query?q=FROM%20FACTS%20MATCH%20(actor.id)%20"
            "EXECUTES%20%22*%22%20AGAINST%20%22*%22%20SELECT%20*",
            timeout=2,
        ) as response:
            query_body = response.read().decode()
        assert "LIMIT" in query_body
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# O mapa canónico
# ---------------------------------------------------------------------------


def _sample_fact() -> dict:
    return {
        "fact_id": "019fd7f9-03a1-76d3-8421-67199b5fb0a8",
        "fact.datasource": {
            "tenant_id": "gov.br/orgao-a",
            "datasource_id": "sshd://srv01/var/log/auth.log",
            "sensor_id": "forge-edge-01",
        },
        "fact.identity": {
            "actor.id": "deploy",
            "actor.name": "deploy",
            "target.id": "srv01",
            "source.ip": "203.0.113.45",
        },
        "fact.time": {"system_timestamp": 1786034848673708, "log_sequence_number": 42},
        "fact.behavior": {
            "class": "credential_attack",
            "action": "authentication.failure",
            "risk_level": "High",
        },
        "fact.evidence": {
            "raw_observation_hash": "b3:9611cd00",
            "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo",
        },
        "fact.integrity": {
            "merkle_root_anchor": "640e6874",
            "leaf_hash": "12cbdea0",
            "signature": "b3tag:bde529d2",
        },
        "fact.lineage": {
            "input_source": "pipelines.linux_sshd",
            "matched_rule": "ssh_auth_failure",
        },
        "fact.confidence": 0.984,
        "fact.knowledge_version": "pipelines.linux_sshd-v1.1.0@1.1.0",
        "fact.ontology_version": "v9",
        "fact.reasoning_version": "reasoner-core-v6.0",
    }


def _attested_fact() -> dict:
    fact = _sample_fact()
    fact["_forge_export_attestation"] = {
        "status": "INTEG_OK",
        "bridge_contract": bridge.BRIDGE_CONTRACT_VERSION,
        "fact_schema": bridge.SCHEMA_VERSION,
        "destination_api": bridge.DESTINATION_API_VERSION,
        "verified_root": "a" * 64,
        "verified_facts": 1,
        "source_id": "b" * 64,
        "public_key": "c" * 64,
        "anchor_signature": "d" * 128,
        "algorithm": "ed25519+blake3+crc32c",
    }
    return fact


def test_kind_e_o_nome_canonico_da_spec():
    """`MATCH (n:OperationalFact)` tem de encontrar o que o Forge produziu."""
    assert bridge.map_fact(1, _sample_fact())["kind"] == "OperationalFact"
    assert bridge.KIND == "OperationalFact"


def test_producer_isola_o_que_veio_do_forge():
    ep = bridge.map_fact(1, _sample_fact())
    assert ep["attrs"]["producer"] == "heraclitus-forge"


def test_agent_id_e_o_titular_dos_dados_nao_o_produtor():
    """
    O `agent_id` do HeraclitusDB é a unidade de APAGAMENTO: existe uma chave
    ChaCha20-Poly1305 por `agent_id` e o `shred(agent_id)` destrói-a.

    A primeira versão da ponte punha `agent_id="heraclitus-forge"` em TODOS os
    Fatos. Com dados pessoais isso é incumprimento da LGPD: para apagar os dados
    de uma pessoa seria preciso destruir a chave de todos os Fatos do Forge —
    o pedido de eliminação de um titular apagaria o histórico de toda a gente.
    """
    ep = bridge.map_fact(1, _sample_fact())
    assert ep["agent_id"] == bridge.subject_of(_sample_fact())
    assert ep["agent_id"].startswith(bridge.SUBJECT_PREFIX)
    assert "deploy" not in ep["agent_id"]
    assert ep["agent_id"] != bridge.PRODUCER


def test_titulares_diferentes_ficam_em_agent_ids_diferentes():
    """Sem isto, um `shred` não consegue ser cirúrgico."""
    a = _sample_fact()
    b = _sample_fact()
    b["fact.identity"]["actor.id"] = "ana"
    assert bridge.map_fact(1, a)["agent_id"] != bridge.map_fact(2, b)["agent_id"]


def test_session_id_pseudonimiza_a_versao_que_pode_conter_origem_e_alvo():
    fact = _sample_fact()
    raw = fact["fact.knowledge_version"]
    hmac_key = bytes(range(32))
    session = bridge.map_fact(1, fact, subject_secret=hmac_key)["session_id"]

    assert session.startswith(bridge.SESSION_PREFIX)
    assert raw not in session
    assert fact["fact.identity"]["target.id"] not in session
    assert bridge.session_of(fact, hmac_key) == session

    changed = _sample_fact()
    changed["fact.knowledge_version"] += "-nova"
    assert bridge.session_of(changed, hmac_key) != session


def test_o_titular_vem_do_id_estavel_e_nao_do_nome():
    """
    O nome muda (casamento, correção de registo). Um apagamento indexado pelo
    nome falharia silenciosamente contra os Fatos gravados com o nome antigo.
    """
    f = _sample_fact()
    f["fact.identity"]["actor.id"] = "mat-4471"
    f["fact.identity"]["actor.name"] = "Carlos Silva"
    assert bridge.map_fact(1, f)["agent_id"] == bridge.subject_of(f)
    assert "mat-4471" not in bridge.map_fact(1, f)["agent_id"]


def test_fato_sem_actor_vai_para_um_balde_proprio():
    """Um log de sistema não pode aterrar no `agent_id` de uma pessoa."""
    f = _sample_fact()
    f["fact.identity"]["actor.id"] = None
    f["fact.identity"]["actor.name"] = None
    assert bridge.map_fact(1, f)["agent_id"] == bridge.NO_SUBJECT
    assert bridge.map_fact(1, {})["agent_id"] == bridge.NO_SUBJECT


def test_a_cadeia_de_custodia_sobrevive_a_traducao():
    """
    Regressão: a primeira versão do mapa deitava fora `fact.integrity` inteiro.
    Sem estes três campos deixa de ser possível, a partir do HeraclitusDB, ligar
    o episódio de volta à cadeia Merkle assinada do Forge — que é a única razão
    para o Forge existir.
    """
    attrs = bridge.map_fact(1, _sample_fact())["attrs"]
    assert attrs["merkle_root_anchor"] == "640e6874"
    assert attrs["leaf_hash"] == "12cbdea0"
    assert attrs["integrity_signature"] == "b3tag:bde529d2"
    assert attrs["evidence_hash"] == "b3:9611cd00"
    assert attrs["carimbo_tempo_legal"] == "icp_brasil_serpro_tst_recibo"


def test_validacao_recusa_fato_sem_atestacao_do_snapshot():
    errors = bridge.validate_fact(1, _sample_fact())
    assert any("atestação INTEG_OK" in error for error in errors)


def test_validacao_aceita_contrato_completo_e_atestado():
    assert bridge.validate_fact(1, _attested_fact()) == []


def test_validacao_recusa_versao_incompativel_antes_do_append():
    fact = _attested_fact()
    fact["_forge_export_attestation"]["bridge_contract"] = "forge-heraclitusdb/999"
    errors = bridge.validate_fact(1, fact)
    assert any("contrato da ponte incompatível" in error for error in errors)


def test_attrs_mantem_os_nomes_que_o_inserir_py_ja_usava():
    """Compatibilidade: uma query que já filtre por estes nomes não pode partir."""
    attrs = bridge.map_fact(1, _sample_fact())["attrs"]
    for k in ("source_ip", "actor_name", "target_id", "risk_level", "action_class"):
        assert k in attrs, f"attr {k} desapareceu — quebra quem já consulta por ele"


def test_forge_lsn_liga_o_episodio_de_volta_ao_hdb():
    assert bridge.map_fact(4242, _sample_fact())["attrs"]["forge_lsn"] == 4242


def test_content_e_deterministico_e_nao_revela_o_log_bruto():
    f = _sample_fact()
    c1 = bridge.render_content(f)
    c2 = bridge.render_content(json.loads(json.dumps(f)))
    assert c1 == c2, "dois Fatos iguais têm de gerar o mesmo texto"
    assert c1 == "deploy executed authentication.failure on srv01 from 203.0.113.45"
    # A observação bruta nunca entra no content — só o seu hash vive nos attrs.
    assert "b3:" not in c1


def test_attrs_vazios_ou_nulos_sao_descartados():
    """Uma chave com None é pior do que chave nenhuma numa query por atributo."""
    f = _sample_fact()
    f["fact.identity"]["source.ip"] = None
    f["fact.lineage"]["matched_rule"] = ""
    attrs = bridge.map_fact(1, f)["attrs"]
    assert "source_ip" not in attrs
    assert "matched_rule" not in attrs
    assert None not in attrs.values()
    assert "" not in attrs.values()


def test_fato_incompleto_nao_rebenta():
    """Um Fato de um conector novo pode não ter todos os campos."""
    ep = bridge.map_fact(1, {"fact_id": "x"})
    assert ep["kind"] == "OperationalFact"
    assert "unknown" in ep["content"]
    assert ep["attrs"]["fact_id"] == "x"


def test_fato_completamente_vazio_nao_rebenta():
    ep = bridge.map_fact(0, {})
    assert ep["attrs"]["generated_by"] == "heraclitus_forge_bridge"


# ---------------------------------------------------------------------------
# Modelo canónico de segurança (SPEC-0071 §4) — extensão compatível
# ---------------------------------------------------------------------------


def _canonical_fact() -> dict:
    """Fato atestado + evento canónico coerente com ele.

    A forma é a que o crate `heraclitus-security-schema` produz; o produtor no
    caminho quente entra no Marco 2. O que se testa aqui é a fronteira: o que a
    ponte aceita, o que recusa, e o que grava no HeraclitusDB.
    """
    fact = _attested_fact()
    fact["fact.security"] = {
        "schema_version": bridge.SECURITY_SCHEMA_VERSION,
        "category": "authentication",
        "event_type": "authentication.failure",
        "outcome": "failure",
        "severity": 7,
        "observed_at_micros": 1786034848673708,
        "ingested_at_micros": 1786034848673708,
        "normalized_at_micros": 1786034848674000,
        "tenant_id": "tenant-demo",
        "datasource_id": "sshd://srv01/var/log/auth.log",
        "sensor_id": "forge-edge-01",
        "source_sequence": "4210",
        "provenance": {
            "forge_source_id": "b" * 64,
            "forge_lsn": 1,
            "raw_observation_hash": "9611cd00",
            "connector_id": "pipelines.linux_sshd-v1.1.0",
            "connector_version": "1.1.0",
            "connector_digest": "e" * 64,
            "matched_rule": "ssh_auth_failure",
        },
    }
    return fact


def test_conector_legado_sem_bloco_canonico_continua_a_passar():
    """Gate CM2: `operational-fact/1.0` sozinho é um contrato completo."""
    fact = _attested_fact()
    assert "fact.security" not in fact
    assert bridge.validate_fact(1, fact) == []
    attrs = bridge.map_fact(1, fact)["attrs"]
    assert not [k for k in attrs if k.startswith("security_")]
    # E o Fato continua a chegar inteiro ao destino.
    assert attrs["schema_version"] == bridge.SCHEMA_VERSION


def test_evento_canonico_sobe_como_attrs_consultaveis():
    attrs = bridge.map_fact(1, _canonical_fact())["attrs"]
    assert bridge.validate_fact(1, _canonical_fact()) == []
    assert attrs["security_schema"] == bridge.SECURITY_SCHEMA_VERSION
    assert attrs["security_category"] == "authentication"
    assert attrs["security_event_type"] == "authentication.failure"
    assert attrs["security_outcome"] == "failure"
    assert attrs["security_severity"] == 7
    # Liga o evento ao artefato exato que o produziu (gate CM1).
    assert attrs["security_connector_digest"] == "e" * 64
    # E o Fato Operacional não foi tocado.
    assert attrs["evidence_hash"] == "b3:9611cd00"
    assert attrs["matched_rule"] == "ssh_auth_failure"


def test_desfecho_desconhecido_nao_vira_atributo():
    """Gate CM3: `null` é desconhecido; não se grava um desfecho inventado."""
    fact = _canonical_fact()
    fact["fact.security"]["outcome"] = None
    assert bridge.validate_fact(1, fact) == []
    assert "security_outcome" not in bridge.map_fact(1, fact)["attrs"]


def test_categoria_fora_do_vocabulario_e_recusada():
    fact = _canonical_fact()
    fact["fact.security"]["category"] = "ransomware"
    erros = bridge.validate_fact(7, fact)
    assert erros and "vocabulário" in erros[0]
    assert erros[0].startswith("LSN 7:")


def test_desfecho_invalido_e_recusado():
    fact = _canonical_fact()
    fact["fact.security"]["outcome"] = "unknown"
    assert any("desfecho" in e for e in bridge.validate_fact(1, fact))


def test_severidade_fora_da_escala_e_recusada():
    fact = _canonical_fact()
    fact["fact.security"]["severity"] = 11
    assert any("escala" in e for e in bridge.validate_fact(1, fact))


def test_evento_canonico_de_outra_observacao_e_recusado():
    """A cadeia de custódia tem de descrever a MESMA linha que o Fato."""
    fact = _canonical_fact()
    fact["fact.security"]["provenance"]["raw_observation_hash"] = "deadbeef"
    assert any("outra observação" in e for e in bridge.validate_fact(1, fact))


def test_evento_canonico_de_outra_regra_e_recusado():
    fact = _canonical_fact()
    fact["fact.security"]["provenance"]["matched_rule"] = "ssh_auth_success"
    assert any("regra divergente" in e for e in bridge.validate_fact(1, fact))


def test_evento_canonico_de_outro_conector_e_recusado():
    fact = _canonical_fact()
    fact["fact.security"]["provenance"]["connector_id"] = "pipelines.postgresql-v1.2.0"
    assert any("outro conector" in e for e in bridge.validate_fact(1, fact))


def test_bloco_canonico_sem_proveniencia_e_recusado():
    fact = _canonical_fact()
    del fact["fact.security"]["provenance"]
    assert any("provenance ausente" in e for e in bridge.validate_fact(1, fact))


def test_bloco_canonico_de_outro_schema_e_recusado():
    fact = _canonical_fact()
    fact["fact.security"]["schema_version"] = "heraclitus-security-event/2.0"
    assert any("schema canónico incompatível" in e for e in bridge.validate_fact(1, fact))


def test_bloco_canonico_malformado_nao_rebenta():
    fact = _canonical_fact()
    fact["fact.security"] = "authentication.failure"
    erros = bridge.validate_fact(1, fact)
    assert any("não é um objeto" in e for e in erros)


# ---------------------------------------------------------------------------
# O exportador Rust, contra o `.hdb` real
# ---------------------------------------------------------------------------


def test_exportador_devolve_fatos_com_lsn_crescente(real_facts):
    lsns = [lsn for lsn, _ in real_facts]
    assert lsns == sorted(lsns), "a retoma da ponte depende da ordem de LSN"
    assert len(lsns) == len(set(lsns)), "o exportador não pode repetir um LSN"


def test_exportador_retoma_sem_duplicar(real_facts, exporter):
    """O contrato de retoma: `--from-lsn N` nunca entrega o LSN N outra vez."""
    corte = real_facts[len(real_facts) // 2][0]
    resto = list(bridge.export_jsonl(HDB, corte, limit=20))
    assert all(lsn > corte for lsn, _ in resto)
    primeiros = {lsn for lsn, _ in real_facts if lsn <= corte}
    assert not (primeiros & {lsn for lsn, _ in resto})


def test_exportador_respeita_o_limite(exporter, signed_hdb):
    assert len(list(bridge.export_jsonl(HDB, 0, limit=3))) == 3


def test_exportador_emite_jsonl_estrito(exporter, signed_hdb):
    """Uma linha = um JSON. O resumo vai para stderr, nunca para stdout."""
    p = subprocess.run([exporter, str(HDB), "--limit", "3"], capture_output=True, text=True)
    linhas = [line for line in p.stdout.splitlines() if line.strip()]
    assert len(linhas) == 3
    for line in linhas:
        rec = json.loads(line)  # rebenta se não for JSON estrito
        # `record_type` entrou na v2 do envelope: uma linha deixou de ser
        # sempre um Fato.
        assert set(rec) == {"contract_version", "lsn", "record_type", "fact", "attestation"}
        assert rec["record_type"] == "OperationalFact"
        assert rec["contract_version"] == bridge.BRIDGE_CONTRACT_VERSION
        assert rec["attestation"]["status"] == "INTEG_OK"
        assert rec["attestation"]["fact_schema"] == bridge.SCHEMA_VERSION
        assert rec["attestation"]["destination_api"] == bridge.DESTINATION_API_VERSION
        assert len(rec["attestation"]["public_key"]) == 64
        assert len(rec["attestation"]["anchor_signature"]) == 128
    assert json.loads(p.stderr.strip().splitlines()[-1])["exported"] == 3


def test_exportador_falha_alto_em_ficheiro_inexistente(exporter):
    """Sem fallback silencioso: origem ou sidecar ausente é falha de integridade."""
    p = subprocess.run([exporter, "nao_existe.hdb"], capture_output=True, text=True)
    assert p.stdout.strip() == ""
    assert p.returncode == 4
    assert json.loads(p.stderr.strip().splitlines()[-1])["status"] == "INTEGRITY_ERROR"


def test_todos_os_fatos_reais_atravessam_o_mapa(real_facts):
    """O mapa tem de aguentar Fatos reais de todos os conectores do .hdb."""
    for lsn, fact in real_facts:
        ep = bridge.map_fact(lsn, fact)
        assert ep["kind"] and ep["content"]
        assert ep["attrs"]["forge_lsn"] == lsn
        # attrs vai para gRPC como map<string,string>: nada pode ser inserializável
        for k, v in ep["attrs"].items():
            assert isinstance(k, str)
            assert str(v)


# ---------------------------------------------------------------------------
# Estado de retoma
# ---------------------------------------------------------------------------


def test_estado_guarda_e_le_o_ultimo_lsn(tmp_path):
    st = tmp_path / "estado.json"
    bridge.save_state(st, HDB, last_lsn=99, appended=5)
    lido = bridge.load_state(st)[str(HDB.resolve())]
    assert lido["last_lsn"] == 99
    assert lido["total_appended"] == 5


def test_estado_acumula_entre_corridas(tmp_path):
    st = tmp_path / "estado.json"
    bridge.save_state(st, HDB, last_lsn=10, appended=3)
    bridge.save_state(st, HDB, last_lsn=20, appended=4)
    lido = bridge.load_state(st)[str(HDB.resolve())]
    assert lido["last_lsn"] == 20
    assert lido["total_appended"] == 7, "o total tem de somar, não substituir"


def test_estado_corrompido_para_fail_closed(tmp_path):
    st = tmp_path / "estado.json"
    st.write_text("{ isto não é json", encoding="utf-8")
    with pytest.raises(bridge.BridgeStateError):
        bridge.load_state(st)


def test_dry_run_nao_escreve_nada(tmp_path, exporter, signed_hdb):
    """Sem --apply, nem o banco nem o ficheiro de estado são tocados."""
    st = tmp_path / "estado.json"
    r = bridge.run(
        HDB, apply=False, addr="127.0.0.1:1", state_path=st, reset=True, limit=2, batch=100
    )
    assert r["appended"] == 0
    assert not st.exists(), "dry-run não pode gravar estado"


def test_quarentena_cifra_pii_e_detecta_adulteracao(tmp_path, monkeypatch):
    key = bytes(range(32))
    monkeypatch.setenv(bridge.QUARANTINE_KEY_ENV, key.hex())
    path = tmp_path / "quarantine.hq"
    fact = _sample_fact()
    fact["fact.identity"]["actor.name"] = "Carlos da Silva"
    fact["fact.identity"]["actor.id"] = "matricula-4471"

    bridge._quarantine(path, 42, fact, ["schema inválido"])
    raw = path.read_text(encoding="ascii")
    assert "Carlos" not in raw
    assert "matricula-4471" not in raw
    assert "203.0.113.45" not in raw
    decoded = list(bridge.decrypt_quarantine(path))
    assert decoded[0]["fact"]["fact.identity"]["actor.id"] == "matricula-4471"

    envelope = json.loads(raw)
    first = envelope["ciphertext"][0]
    envelope["ciphertext"] = ("0" if first != "0" else "1") + envelope["ciphertext"][1:]
    path.write_text(json.dumps(envelope) + "\n", encoding="ascii")
    with pytest.raises(bridge.BridgeStateError):
        list(bridge.decrypt_quarantine(path))


def test_quarentena_python_e_interoperavel_com_cli_rust(tmp_path, monkeypatch):
    binary = (
        ROOT
        / "rust"
        / "target"
        / "release"
        / ("quarantine.exe" if os.name == "nt" else "quarantine")
    )
    if not binary.exists():
        pytest.skip(f"{binary} ausente — rode cargo build --release --bins")
    key_hex = bytes(range(32)).hex()
    monkeypatch.setenv(bridge.QUARANTINE_KEY_ENV, key_hex)
    path = tmp_path / "cross-language.hq"
    bridge._quarantine(path, 77, _sample_fact(), ["teste interoperável"])
    env = os.environ.copy()
    env[bridge.QUARANTINE_KEY_ENV] = key_hex
    result = subprocess.run(
        [str(binary), "decrypt", str(path)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    decoded = json.loads(result.stdout)
    assert decoded["lsn"] == 77
    assert decoded["fact"]["fact.identity"]["actor.id"] == "deploy"


def test_retry_apos_crash_e_exatamente_uma_vez(tmp_path, monkeypatch):
    """Crash entre ACK e checkpoint não pode duplicar o Fato no destino."""
    source = tmp_path / "source.hdb"
    source.write_bytes(b"fixture controlada pelo mock")
    state = tmp_path / "state.json"

    class FakeDb:
        def __init__(self):
            self.by_key = {}

        def append(self, kind, content, **kwargs):
            key = kwargs["idempotency_key"]
            if key in self.by_key:
                old = self.by_key[key]
                return {"lsn": old["lsn"], "event_id": old["event_id"], "deduplicated": True}
            result = {"lsn": 701, "event_id": "01TESTEVENT0000000000000000", "deduplicated": False}
            self.by_key[key] = result
            return result

        def close(self):
            pass

    fake_db = FakeDb()
    monkeypatch.setitem(
        sys.modules,
        "heraclitusdb",
        SimpleNamespace(__version__="1.0.5", connect=lambda *_args, **_kwargs: fake_db),
    )
    monkeypatch.setenv(bridge.SUBJECT_HMAC_ENV, "s" * 32)
    monkeypatch.setenv(bridge.QUARANTINE_KEY_ENV, bytes(range(32)).hex())
    monkeypatch.setattr(
        bridge,
        "export_all",
        lambda *_args, **_kwargs: iter([(42, "OperationalFact", _attested_fact())]),
    )

    real_save = bridge.save_state
    crashed = {"value": False}

    def crash_after_ack(*args, **kwargs):
        if not crashed["value"]:
            crashed["value"] = True
            raise OSError("falha simulada no replace do checkpoint")
        return real_save(*args, **kwargs)

    monkeypatch.setattr(bridge, "save_state", crash_after_ack)
    first = bridge.run(
        source,
        apply=True,
        addr="127.0.0.1:1",
        state_path=state,
        reset=False,
        limit=None,
        batch=100,
        quarantine_path=tmp_path / "quarantine.jsonl",
    )
    assert first["errors"]
    assert len(fake_db.by_key) == 1

    monkeypatch.setattr(bridge, "save_state", real_save)
    second = bridge.run(
        source,
        apply=True,
        addr="127.0.0.1:1",
        state_path=state,
        reset=False,
        limit=None,
        batch=100,
        quarantine_path=tmp_path / "quarantine.jsonl",
    )
    assert second["errors"] == []
    assert second["appended"] == 0
    assert second["deduplicated"] == 1
    assert len(fake_db.by_key) == 1
    assert bridge.load_state(state)[str(source.resolve())]["last_lsn"] == 42


# ---------------------------------------------------------------------------
# Ponta-a-ponta contra o HeraclitusDB a sério (opt-in: -m live)
# ---------------------------------------------------------------------------


def _live_db():
    """Liga ao HeraclitusDB real ou salta o teste. Nunca falha por indisponibilidade."""
    secret = os.environ.get(bridge.SUBJECT_HMAC_ENV, "")
    if len(secret.encode("utf-8")) < 32:
        pytest.skip(f"defina {bridge.SUBJECT_HMAC_ENV} (>=32 bytes) para o teste live")
    quarantine_key = os.environ.get(bridge.QUARANTINE_KEY_ENV, "")
    if len(quarantine_key) != 64:
        pytest.skip(f"defina {bridge.QUARANTINE_KEY_ENV} (32 bytes em hex) para o teste live")
    heraclitusdb = pytest.importorskip("heraclitusdb")
    try:
        db = heraclitusdb.connect(bridge.DEFAULT_ADDR)
        db.head()
        return db
    except Exception as e:
        pytest.skip(f"HeraclitusDB não acessível em {bridge.DEFAULT_ADDR}: {e}")


@pytest.mark.live
def test_ponta_a_ponta_contra_o_heraclitusdb(exporter, signed_hdb):
    """
    O teste que a auditoria disse não existir: um Fato do Forge chega ao
    HeraclitusDB e é encontrado por uma query, com a cadeia de custódia intacta.

    Usa o ficheiro de estado REAL e nunca `reset`: correr este teste N vezes
    escreve no máximo uma vez cada Fato. A primeira versão deste teste usava
    `reset=True` com um `tmp_path`, e por isso reescrevia os mesmos Fatos na
    memória do utilizador a cada `pytest -m live` — o log é append-only, esse
    lixo não se apaga. Se não houver nada de novo para exportar, o teste salta
    em vez de inventar trabalho.
    """
    db = _live_db()
    antes = db.head()

    pendentes = list(bridge.export_jsonl(HDB, _last_bridged(), limit=3))
    if not pendentes:
        pytest.skip("nada de novo no .hdb — a ponte já está em dia (é o estado correto)")

    r = bridge.run(
        HDB,
        apply=True,
        addr=bridge.DEFAULT_ADDR,
        state_path=bridge.DEFAULT_STATE,
        reset=False,
        limit=3,
        batch=100,
    )
    assert r["appended"] == len(pendentes), f"erros: {r['errors']}"
    assert db.head() > antes

    achados = db.query(f'MATCH (n) WHERE n.producer = "{bridge.PRODUCER}" RETURN n LIMIT 500')
    assert achados, "os Fatos escritos têm de ser encontráveis por agent_id"

    esperados = {lsn for lsn, _ in pendentes}
    obtidos = {int(e["attrs"]["forge_lsn"]) for e in achados if "forge_lsn" in e["attrs"]}
    assert esperados <= obtidos, "todos os LSN exportados têm de estar no banco"

    amostra = next(e for e in achados if int(e["attrs"]["forge_lsn"]) in esperados)
    assert amostra["attrs"]["merkle_root_anchor"], "a âncora Merkle tem de sobreviver ao gRPC"
    assert amostra["attrs"]["generated_by"] == "heraclitus_forge_bridge"
    db.close()


def _last_bridged() -> int:
    return int(
        bridge.load_state(bridge.DEFAULT_STATE).get(str(HDB.resolve()), {}).get("last_lsn", 0)
    )


@pytest.mark.live
def test_a_ponte_em_dia_nao_escreve_nada(exporter, signed_hdb):
    """
    A propriedade que torna a ponte segura de agendar: quando não há Fatos
    novos, uma corrida é um no-op — não acrescenta um único episódio.

    Isto é o inverso do teste anterior e não precisa de escrever nada, por isso
    pode correr sempre.
    """
    db = _live_db()
    antes = db.head()

    r = bridge.run(
        HDB,
        apply=True,
        addr=bridge.DEFAULT_ADDR,
        state_path=bridge.DEFAULT_STATE,
        reset=False,
        limit=None,
        batch=100,
    )
    # Segunda corrida imediata: o .hdb não cresceu, logo não há nada a fazer.
    r2 = bridge.run(
        HDB,
        apply=True,
        addr=bridge.DEFAULT_ADDR,
        state_path=bridge.DEFAULT_STATE,
        reset=False,
        limit=None,
        batch=100,
    )

    assert r2["appended"] == 0, "uma ponte em dia não pode reescrever nada"
    assert db.head() == antes + r["appended"], "o banco só cresceu o que a ponte escreveu"
    db.close()


# ---------------------------------------------------------------------------
# Telemetry Health: do ingestor real até ao episódio que a ponte escreveria
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ingested(exporter, tmp_path_factory) -> list[dict]:
    """Corre o `ingest` REAL sobre uma amostra e devolve as linhas do JSONL."""
    work = tmp_path_factory.mktemp("telemetry")
    db_path = work / "telemetry.hdb"
    env = os.environ.copy()
    env[bridge.QUARANTINE_KEY_ENV] = "ef" * 32
    run = subprocess.run(
        [
            str(_release_bin("ingest")),
            str(ROOT / "samples" / "postgresql.log"),
            "--tenant",
            "gov.br/orgao-a",
            "--datasource",
            "postgresql://db-01/postgresql.log",
            "--sensor",
            "forge-edge-01",
            "--artifact",
            str(ROOT / "registry" / "postgresql"),
            "--db",
            str(db_path),
            "--quarantine",
            str(work / "telemetry.hq"),
            "--from-start",
            "--once",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run.returncode == 0, run.stderr

    export = subprocess.run([exporter, str(db_path)], capture_output=True, text=True, timeout=120)
    assert export.returncode == 0, export.stderr
    return [json.loads(line) for line in export.stdout.splitlines() if line.strip()]


def _telemetria(linhas: list[dict], tipo: str) -> list[dict]:
    saida = []
    for linha in linhas:
        if linha.get("record_type") != "TelemetryHealth":
            continue
        envelope = json.loads(linha["telemetry"]["envelope"])
        if envelope["event"]["type"] == tipo:
            saida.append(envelope)
    return saida


def test_o_ingestor_emite_saude_no_mesmo_log_dos_fatos(ingested):
    """O produtor que faltava ao Telemetry Health do HeraclitusDB."""
    tipos = {linha.get("record_type") for linha in ingested}
    assert tipos == {"OperationalFact", "TelemetryHealth"}
    emitidos = {
        json.loads(linha["telemetry"]["envelope"])["event"]["type"]
        for linha in ingested
        if linha.get("record_type") == "TelemetryHealth"
    }
    assert {
        "ExpectationConfigured",
        "ConnectorActivated",
        "SensorHeartbeat",
        "IngestionWindowClosed",
        "HealthEvaluationTick",
    } <= emitidos


def test_a_janela_respeita_o_invariante_do_consumidor(ingested):
    """`normalized <= parsed <= received` é validado do outro lado."""
    janelas = _telemetria(ingested, "IngestionWindowClosed")
    assert janelas, "o ingestor tem de fechar a janela mesmo em --once"
    for envelope in janelas:
        janela = envelope["event"]["data"]
        assert janela["normalized"] <= janela["parsed"] <= janela["received"]
        assert janela["window_start_micros"] <= janela["window_end_micros"]
        assert len(janela["connector_digest"]) == 64
        # Sem carimbo da fonte não há atraso observável — e não se inventa um.
        assert janela["max_observed_lateness_millis"] == 0


def test_a_janela_e_o_conector_ativo_declaram_o_mesmo_digest(ingested):
    """Digest divergente é classificado como adulteração pelo consumidor."""
    ativados = _telemetria(ingested, "ConnectorActivated")
    janelas = _telemetria(ingested, "IngestionWindowClosed")
    assert len(ativados) == 1
    digest = ativados[0]["event"]["data"]["connector_digest"]
    assert ativados[0]["event"]["data"]["approved"] is True
    for envelope in janelas:
        assert envelope["event"]["data"]["connector_digest"] == digest


def test_a_identidade_do_envelope_e_a_do_registo_autenticado(ingested):
    for linha in ingested:
        if linha.get("record_type") != "TelemetryHealth":
            continue
        envelope = json.loads(linha["telemetry"]["envelope"])
        assert envelope["identity"] == linha["telemetry"]["identity"]
        assert envelope["schema"] == bridge.TELEMETRY_SCHEMA_VERSION
        assert envelope["identity"]["tenant_id"] == "gov.br/orgao-a"


def test_o_checkpoint_so_e_anunciado_depois_de_durar(ingested):
    checkpoints = _telemetria(ingested, "CheckpointAdvanced")
    assert checkpoints, "processar linhas tem de avançar o checkpoint"
    for envelope in checkpoints:
        dados = envelope["event"]["data"]
        assert dados["integrity"] == "Verified"
        assert isinstance(dados["source_sequence"], int)


def test_a_ponte_traduz_a_saude_em_episodio_do_heraclitusdb(ingested):
    linhas = [linha for linha in ingested if linha.get("record_type") == "TelemetryHealth"]
    assert linhas
    for lsn, linha in enumerate(linhas, start=1):
        assert bridge.validate_telemetry(lsn, linha) == []
        episodio = bridge.telemetry_episode(lsn, linha)
        assert episodio["kind"] == bridge.TELEMETRY_KIND
        assert episodio["agent_id"] == bridge.TELEMETRY_AGENT_ID
        # O envelope viaja como TEXTO, byte a byte como foi gravado.
        assert episodio["content"] == linha["telemetry"]["envelope"]
        attrs = episodio["attrs"]
        assert attrs["telemetry.schema"] == bridge.TELEMETRY_SCHEMA_VERSION
        assert attrs["tenant_id"] == "gov.br/orgao-a"
        assert attrs["datasource_id"] == "postgresql://db-01/postgresql.log"
        assert attrs["sensor_id"] == "forge-edge-01"
        assert attrs["telemetry.event_type"]


def test_a_ponte_recusa_um_envelope_de_outra_identidade(ingested):
    """Envelope montado noutro sítio não passa a fronteira."""
    linha = next(item for item in ingested if item.get("record_type") == "TelemetryHealth")
    forjada = json.loads(json.dumps(linha))
    forjada["telemetry"]["identity"]["tenant_id"] = "gov.br/orgao-b"
    erros = bridge.validate_telemetry(7, forjada)
    assert any("diverge" in erro for erro in erros), erros


def test_os_fatos_continuam_a_sair_pelo_caminho_de_sempre(ingested):
    """A ponte de Fatos não vê os eventos de saúde."""
    fatos = [linha for linha in ingested if linha.get("record_type") == "OperationalFact"]
    assert fatos
    for linha in fatos:
        assert (
            bridge.validate_fact(
                linha["lsn"], {**linha["fact"], "_forge_export_attestation": linha["attestation"]}
            )
            == []
        )
