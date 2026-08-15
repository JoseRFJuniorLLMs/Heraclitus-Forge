"""
compilar_sementes — compila os conectores de `forge_seeds` para o registry.

O Coverage é medido pelo **runner Rust real** (o mesmo caminho que o
`forge_compiler` usa para o PostgreSQL), não por um simulador em Python: se uma
regra não casar a linha que o `test_matrix` diz que devia casar, a cobertura
cai e vê-se aqui.

    python compilar_sementes.py            # compila todas
    python compilar_sementes.py nginx_access
"""
from __future__ import annotations

import _console  # noqa: F401  (consola UTF-8 no Windows)

import sys

import forge_compiler
import forge_seeds


def main() -> int:
    pedidos = [a for a in sys.argv[1:] if not a.startswith("-")] or list(forge_seeds.SEEDS)
    desconhecidos = [p for p in pedidos if p not in forge_seeds.SEEDS]
    if desconhecidos:
        print(f"[ERRO] conector(es) desconhecido(s): {desconhecidos}")
        print(f"       disponiveis: {list(forge_seeds.SEEDS)}")
        return 2

    compiler = forge_compiler.HeraclitusForgeCompiler()
    falhas = []
    for nome in pedidos:
        perfil = forge_seeds.SEEDS[nome]
        # O compilador procura o perfil no dicionário global — a mesma porta que
        # o `cke_forge_pipeline` usa para injetar o que o Claude derivou.
        forge_compiler.CONNECTOR_PROFILES[nome] = perfil
        amostra = perfil["test_matrix"][0]["input"]
        print(f"\n{'=' * 66}\n[semente] {nome} — {perfil['vendor']}\n{'=' * 66}")
        try:
            caminho = compiler.compile_knowledge(
                artifact_id=nome, vendor=perfil["vendor"], sample_log=amostra[:300]
            )
            print(f"[OK] {caminho}")
        except Exception as exc:
            print(f"[FALHOU] {nome}: {type(exc).__name__}: {exc}")
            falhas.append(nome)

    print(f"\n{len(pedidos) - len(falhas)}/{len(pedidos)} conector(es) compilado(s).")
    if falhas:
        print(f"falhas: {falhas}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
