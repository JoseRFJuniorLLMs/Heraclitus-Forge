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
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

HDB = Path(__file__).resolve().parent.parent / "rust" / "storage_rs.hdb"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def exporter() -> str:
    try:
        return bridge.exporter_bin()
    except SystemExit as e:
        pytest.skip(str(e))


@pytest.fixture(scope="module")
def real_facts(exporter) -> list[tuple[int, dict]]:
    """Fatos verdadeiros, lidos do `.hdb` verdadeiro pelo exportador verdadeiro."""
    if not HDB.exists():
        pytest.skip(f"{HDB} não existe — compile e corra um conector primeiro")
    facts = list(bridge.export_jsonl(HDB, 0, limit=20))
    if not facts:
        pytest.skip(f"{HDB} não tem Fatos")
    return facts


# ---------------------------------------------------------------------------
# O mapa canónico
# ---------------------------------------------------------------------------

def _sample_fact() -> dict:
    return {
        "fact_id": "019fd7f9-03a1-76d3-8421-67199b5fb0a8",
        "fact.identity": {
            "actor.id": "deploy", "actor.name": "deploy",
            "target.id": "srv01", "source.ip": "203.0.113.45",
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
        "fact.lineage": {"input_source": "pipelines.linux_sshd", "matched_rule": "ssh_auth_failure"},
        "fact.confidence": 0.984,
        "fact.knowledge_version": "pipelines.linux_sshd-v1.1.0@1.1.0",
        "fact.ontology_version": "v9",
        "fact.reasoning_version": "reasoner-core-v6.0",
    }


def test_kind_e_o_nome_canonico_da_spec():
    """`MATCH (n:OperationalFact)` tem de encontrar o que o Forge produziu."""
    assert bridge.map_fact(1, _sample_fact())["kind"] == "OperationalFact"
    assert bridge.KIND == "OperationalFact"


def test_agent_id_isola_o_que_veio_do_forge():
    ep = bridge.map_fact(1, _sample_fact())
    assert ep["agent_id"] == "heraclitus-forge"


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


def test_exportador_respeita_o_limite(exporter):
    assert len(list(bridge.export_jsonl(HDB, 0, limit=3))) == 3


def test_exportador_emite_jsonl_estrito(exporter):
    """Uma linha = um JSON. O resumo vai para stderr, nunca para stdout."""
    p = subprocess.run([exporter, str(HDB), "--limit", "3"],
                       capture_output=True, text=True)
    linhas = [l for l in p.stdout.splitlines() if l.strip()]
    assert len(linhas) == 3
    for l in linhas:
        rec = json.loads(l)  # rebenta se não for JSON estrito
        assert set(rec) == {"lsn", "fact"}
    assert json.loads(p.stderr.strip().splitlines()[-1])["exported"] == 3


def test_exportador_falha_alto_em_ficheiro_inexistente(exporter):
    """Sem fallback silencioso: um .hdb que não existe dá 0 Fatos, não sucesso vazio ambíguo."""
    p = subprocess.run([exporter, "nao_existe.hdb"], capture_output=True, text=True)
    assert p.stdout.strip() == ""
    assert json.loads(p.stderr.strip().splitlines()[-1])["exported"] == 0


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


def test_estado_corrompido_recomeca_do_zero_em_vez_de_rebentar(tmp_path):
    st = tmp_path / "estado.json"
    st.write_text("{ isto não é json", encoding="utf-8")
    assert bridge.load_state(st) == {}


def test_dry_run_nao_escreve_nada(tmp_path, exporter):
    """Sem --apply, nem o banco nem o ficheiro de estado são tocados."""
    st = tmp_path / "estado.json"
    r = bridge.run(HDB, apply=False, addr="127.0.0.1:1", state_path=st,
                   reset=True, limit=2, batch=100)
    assert r["appended"] == 0
    assert not st.exists(), "dry-run não pode gravar estado"


# ---------------------------------------------------------------------------
# Ponta-a-ponta contra o HeraclitusDB a sério (opt-in: -m live)
# ---------------------------------------------------------------------------

@pytest.mark.live
def test_ponta_a_ponta_contra_o_heraclitusdb(tmp_path, exporter):
    """
    O teste que a auditoria disse não existir: um Fato do Forge chega ao
    HeraclitusDB e é encontrado por uma query, com a cadeia de custódia intacta.
    """
    heraclitusdb = pytest.importorskip("heraclitusdb")
    try:
        db = heraclitusdb.connect(bridge.DEFAULT_ADDR)
        antes = db.head()
    except Exception as e:
        pytest.skip(f"HeraclitusDB não acessível em {bridge.DEFAULT_ADDR}: {e}")

    st = tmp_path / "estado.json"
    r = bridge.run(HDB, apply=True, addr=bridge.DEFAULT_ADDR, state_path=st,
                   reset=True, limit=3, batch=100)
    assert r["appended"] == 3, f"erros: {r['errors']}"
    assert db.head() > antes

    achados = db.query(
        f'MATCH (n) WHERE n.agent_id = "{bridge.AGENT_ID}" RETURN n LIMIT 200'
    )
    assert achados, "os Fatos escritos têm de ser encontráveis por agent_id"

    esperados = {lsn for lsn, _ in bridge.export_jsonl(HDB, 0, limit=3)}
    obtidos = {int(e["attrs"]["forge_lsn"]) for e in achados if "forge_lsn" in e["attrs"]}
    assert esperados <= obtidos, "todos os LSN exportados têm de estar no banco"

    amostra = next(e for e in achados if int(e["attrs"]["forge_lsn"]) in esperados)
    assert amostra["attrs"]["merkle_root_anchor"], "a âncora Merkle tem de sobreviver ao gRPC"
    assert amostra["attrs"]["generated_by"] == "heraclitus_forge_bridge"
    db.close()


@pytest.mark.live
def test_correr_a_ponte_duas_vezes_nao_duplica(tmp_path, exporter):
    """A propriedade que torna a ponte segura de agendar: é idempotente."""
    heraclitusdb = pytest.importorskip("heraclitusdb")
    try:
        heraclitusdb.connect(bridge.DEFAULT_ADDR).close()
    except Exception as e:
        pytest.skip(f"HeraclitusDB não acessível: {e}")

    st = tmp_path / "estado.json"
    r1 = bridge.run(HDB, apply=True, addr=bridge.DEFAULT_ADDR, state_path=st,
                    reset=True, limit=2, batch=100)
    r2 = bridge.run(HDB, apply=True, addr=bridge.DEFAULT_ADDR, state_path=st,
                    reset=False, limit=2, batch=100)
    assert r1["appended"] == 2
    assert r2["last_lsn"] > r1["last_lsn"], "a 2ª corrida avança, não repete"
    assert r1["last_lsn"] not in [lsn for lsn, _ in
                                  bridge.export_jsonl(HDB, r1["last_lsn"], limit=2)]
