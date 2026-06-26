"""
HeraclitusDB — Motor de Persistencia Temporal Criptografico (append-only).

Conforme `plataforma.md` (Produto 1) e `Operational-Fact.md` (secoes 8-9), o banco
e despido de semantica: ele apenas grava Fatos Operacionais imutaveis e expoe
`verify()` para validar a integridade retroativa da cadeia Merkle, SEM conhecer o
significado do payload.

Cada Fato gravado recebe a dimensao `fact.integrity` (leaf_hash + merkle_root_anchor
+ assinatura). O `verify()` reconstroi a arvore Merkle a partir do disco e compara
com a raiz ancorada de confianca — e essa comparacao que detecta adulteracao.
"""

import os
import json
import struct

import blake3

# Cabecalho binario de tamanho fixo por bloco (Formato de Linha, spec secao 8):
#   Magic(4s) + LSN(Q,8) + Timestamp(Q,8) + Confidence(f,4) + EvidenceHash(32s) + PayloadLen(I,4)
HEADER_FORMAT = ">4sQQf32sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 60 bytes


def _b3(data: bytes) -> str:
    """Primitiva de integridade da suite: BLAKE3 (spec secoes 8 e 9)."""
    return blake3.blake3(data).hexdigest()


def _canon(obj: dict) -> bytes:
    """Serializacao canonica determinística usada para hashing (proxy de FlatBuffers)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _core_bytes(fact: dict) -> bytes:
    """Bytes do Fato SEM a dimensao de integridade (evita circularidade no hash da folha)."""
    return _canon({k: v for k, v in fact.items() if k != "fact.integrity"})


class HeraclitusDB:
    def __init__(self, db_path: str = "storage.hdb"):
        self.db_path = db_path
        self.anchor_path = db_path + ".anchor"
        self.merkle_leaves = []
        self.current_lsn = 14812337
        self.trusted_root = ""

        if not os.path.exists(self.db_path):
            with open(self.db_path, "wb") as f:
                # PAGE 0: FILE HEADER ('HERA' + versao do formato)
                f.write(b"HERA" + struct.pack(">I", 6))

    # -- Merkle -------------------------------------------------------------

    def _calculate_merkle_root(self, leaves: list) -> str:
        if not leaves:
            return ""
        if len(leaves) == 1:
            return leaves[0]
        next_level = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            right = leaves[i + 1] if i + 1 < len(leaves) else leaves[i]  # duplica no impar
            next_level.append(_b3((left + right).encode("utf-8")))
        return self._calculate_merkle_root(next_level)

    @staticmethod
    def _sign(leaf_hash: str) -> str:
        """Assinatura Ed25519 simulada sobre a folha (mock determinístico)."""
        return "ed25519:" + _b3(b"HERA-KEY:" + leaf_hash.encode())[:48]

    # -- Escrita append-only ------------------------------------------------

    def write_fact(self, fact: dict) -> int:
        self.current_lsn += 1
        fact["fact.time"]["log_sequence_number"] = self.current_lsn

        # Folha = hash(core), onde core e o Fato canonico SEM fact.integrity.
        # O LSN/timestamp/confianca/evidencia ja vivem dentro do core, entao a
        # folha cobre todo o conteudo semantico sem depender do header binario
        # (cujo payload_len so e conhecido depois de anexar a integridade).
        core = _core_bytes(fact)
        leaf_hash = _b3(core)
        self.merkle_leaves.append(leaf_hash)
        self.trusted_root = self._calculate_merkle_root(self.merkle_leaves)

        # Anexa a dimensao de integridade ao Fato (spec: fact.integrity)
        fact["fact.integrity"] = {
            "leaf_hash": leaf_hash,
            "merkle_root_anchor": self.trusted_root,
            "signature": self._sign(leaf_hash),
        }

        ev_hex = fact["fact.evidence"]["raw_observation_hash"].split(":")[-1]
        evidence_hash = ev_hex.encode("utf-8")[:32].ljust(32, b"\x00")

        payload_bytes = _canon(fact)
        header = struct.pack(
            HEADER_FORMAT, b"FACT", self.current_lsn,
            fact["fact.time"]["system_timestamp"], fact["fact.confidence"],
            evidence_hash, len(payload_bytes),
        )

        with open(self.db_path, "ab") as f:
            f.write(header + payload_bytes)

        # Ancora de confianca persistida (lida pelo verify para detectar adulteracao)
        with open(self.anchor_path, "w", encoding="utf-8") as f:
            f.write(self.trusted_root)

        return self.current_lsn

    # -- db.verify() --------------------------------------------------------

    def verify(self) -> dict:
        print("=== [HeraclitusDB] Iniciando Verificacao de Integridade Criptografica ===")
        if not os.path.exists(self.db_path):
            return {"status": "ERROR", "message": "Arquivo de banco nao encontrado."}

        trusted_root = None
        if os.path.exists(self.anchor_path):
            with open(self.anchor_path, "r", encoding="utf-8") as f:
                trusted_root = f.read().strip()

        computed_leaves = []
        with open(self.db_path, "rb") as f:
            if f.read(4) != b"HERA":
                return {"status": "CORRUPTED", "message": "Cabecalho mestre do banco invalido."}
            f.read(4)  # versao do formato

            while True:
                header_bytes = f.read(HEADER_SIZE)
                if not header_bytes or len(header_bytes) < HEADER_SIZE:
                    break
                block_magic, lsn, _ts, _conf, _ev, payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
                if block_magic != b"FACT":
                    return {"status": "VIOLATED", "message": f"Assinatura de bloco corrompida (LSN {lsn})"}

                payload_bytes = f.read(payload_len)
                try:
                    fact = json.loads(payload_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    return {"status": "VIOLATED", "message": f"Payload corrompido no LSN {lsn}"}

                # Recomputa a folha a partir do disco (core sem integrity)
                leaf_hash = _b3(_core_bytes(fact))
                computed_leaves.append(leaf_hash)

                # A folha gravada bate com o disco?
                stored_leaf = fact.get("fact.integrity", {}).get("leaf_hash")
                if stored_leaf and stored_leaf != leaf_hash:
                    print(f"[X] Adulteracao detectada no LSN {lsn}: folha nao confere.")
                    return {"status": "VIOLATED", "message": f"Folha adulterada no LSN {lsn}",
                            "lsn": lsn}

        computed_root = self._calculate_merkle_root(computed_leaves)
        print(f"[+] Arvore Merkle reconstruida. Raiz: {computed_root[:16]}...{computed_root[-8:]}")

        if trusted_root is not None and computed_root != trusted_root:
            print("[X] Raiz Merkle reconstruida NAO bate com a ancora de confianca.")
            return {"status": "VIOLATED", "message": "Raiz Merkle divergente da ancora.",
                    "computed_root": computed_root, "trusted_root": trusted_root}

        print("[OK] Validacao de Nao-Repudio concluida com sucesso.\n")
        return {"status": "INTEG_OK", "merkle_root": computed_root,
                "facts_verified": len(computed_leaves)}

    # -- Simulacao de ataque (1 byte, mesmo tamanho => framing preservado) --

    def inject_malicious_tamper(self, target_lsn: int):
        print(f"[HACKER] Tentando adulterar o registro gravado no LSN {target_lsn}...")
        with open(self.db_path, "r+b") as f:
            f.seek(8)  # pula o file header
            while True:
                block_pos = f.tell()
                header_bytes = f.read(HEADER_SIZE)
                if not header_bytes or len(header_bytes) < HEADER_SIZE:
                    print(f"[HACKER] LSN {target_lsn} nao encontrado.\n")
                    return
                _magic, lsn, _ts, _conf, _ev, payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
                payload_pos = block_pos + HEADER_SIZE
                payload = f.read(payload_len)
                if lsn == target_lsn:
                    # Flipa 1 char hex dentro do hash de evidencia: mesmo tamanho, JSON valido
                    marker = b'"raw_observation_hash":"b3:'
                    idx = payload.find(marker)
                    if idx == -1:
                        idx = 0
                    target_off = payload_pos + idx + len(marker)
                    f.seek(target_off)
                    orig = f.read(1)
                    f.seek(target_off)
                    f.write(b"1" if orig != b"1" else b"0")
                    print("[HACKER] Payload modificado fisicamente no disco (1 byte).\n")
                    return


if __name__ == "__main__":
    from runner_engine import ReconstitutiveRunner

    for path in ("storage.hdb", "storage.hdb.anchor"):
        if os.path.exists(path):
            os.remove(path)

    db = HeraclitusDB(db_path="storage.hdb")
    runner = ReconstitutiveRunner(artifact_path="./registry/postgresql.hcx")
    runner.compile_and_optimize()

    print("\n[*] Gravando Fatos Operacionais no banco...")
    line = '2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"'
    first_lsn = None
    for _ in range(5):
        fact = runner.process_observation(line)
        lsn = db.write_fact(fact)
        if first_lsn is None:
            first_lsn = lsn

    result_1 = db.verify()
    print(f"Auditoria Inicial: {result_1['status']} (Fatos: {result_1.get('facts_verified')})")
    print("-" * 45)

    db.inject_malicious_tamper(target_lsn=first_lsn)
    result_2 = db.verify()
    print(f"Auditoria Pos-Ataque: {result_2['status']}")
    if result_2["status"] != "INTEG_OK":
        print("[ALERTA FORENSE] A Raiz Merkle real nao bate com os registros de auditoria!")
