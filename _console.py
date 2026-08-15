"""
Consola em UTF-8 — importar antes de qualquer `print` com acentos ou setas.

A consola do Windows arranca em cp1252. Qualquer `print` com "→", "…", "✓" ou
um acento levanta `UnicodeEncodeError` e mata o processo — não é um problema
cosmético: o `cke_forge_pipeline.py` rebentava na PRIMEIRA linha que imprimia,
antes de clusterizar seja o que for, e o fluxo inteiro de onboarding de um
cliente novo ficava bloqueado numa máquina Windows.

Uso, no topo do módulo:

    import _console  # noqa: F401  (efeito ao importar)
"""

from __future__ import annotations

import sys
from contextlib import suppress

for _stream in (sys.stdout, sys.stderr):
    with suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8", errors="replace")
