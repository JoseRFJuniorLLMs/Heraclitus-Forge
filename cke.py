"""
Heraclitus CKE — Continuous Knowledge Evolution (motor de evolução contínua).

Conforme `plataforma.md` (Knowledge Cloud / CKE): clusteriza as exceções textuais
que os Runners desviaram para a quarentena (Schema Drift) e gera **sementes de
conector** (esqueletos de regex + amostra) que alimentam o Forge para compilar uma
nova versão do `.hcx`.

Implementação REAL (não-supervisionada, sem IA): cada log vira um *template*
estrutural — mascarando timestamps, IPs, hex, strings, números e valores
`chave=valor` (técnica estilo Drain/SLCT). Templates iguais agrupam; clusters
próximos fundem por similaridade de Jaccard sobre os tokens. A entropia da
distribuição mede a heterogeneidade da quarentena. A síntese final (template ->
conector `.hcx` completo) é o passo opcional de IA em `forge_ai.py`
(requer `ANTHROPIC_API_KEY`).
"""

import math
import os
import re
from collections import defaultdict

# Máscaras estruturais (ordem importa: específicas primeiro).
_MASKS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s(?:UTC|GMT|Z))?"), "<TS>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
    (re.compile(r'"[^"]*"'), "<STR>"),
    (re.compile(r"\b\d+\b"), "<NUM>"),
    (re.compile(r"(?<==)[A-Za-z0-9_./@:-]+"), "<VAL>"),  # valor após 'chave='
]

# Esqueleto de regex por token (corpo, sem o nome do grupo).
_RX_BODY = {
    "<TS>": r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\S*",
    "<IP>": r"\d{1,3}(?:\.\d{1,3}){3}",
    "<HEX>": r"[0-9a-fA-F]+",
    "<STR>": r'[^"]*',
    "<NUM>": r"\d+",
    "<VAL>": r"[^\s|]+",
}


def template(line: str) -> str:
    """Reduz um log à sua assinatura estrutural (mascarando valores variáveis)."""
    t = line.strip()
    for rx, tok in _MASKS:
        t = rx.sub(tok, t)
    return re.sub(r"\s+", " ", t)


def _tokens(line: str) -> set:
    return set(re.findall(r"[A-Za-z_]+|<[A-Z]+>", template(line)))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def cluster(lines, threshold: float = 0.6):
    """Agrupa por template exato e funde clusters próximos (Jaccard >= threshold)."""
    groups = defaultdict(list)
    for ln in lines:
        groups[template(ln)].append(ln)

    reps = list(groups.items())  # [(template, [linhas])]
    used = [False] * len(reps)
    clusters = []
    for i in range(len(reps)):
        if used[i]:
            continue
        ti, li = reps[i]
        merged = list(li)
        used[i] = True
        toks_i = _tokens(li[0])
        for j in range(i + 1, len(reps)):
            if used[j]:
                continue
            if _jaccard(toks_i, _tokens(reps[j][1][0])) >= threshold:
                merged.extend(reps[j][1])
                used[j] = True
        clusters.append((ti, merged))
    return clusters


def suggest_regex(tmpl: str) -> str:
    """Converte o template num esqueleto de regex com grupos nomeados ÚNICOS."""
    body = re.escape(tmpl)  # '<' e '>' não são especiais => tokens sobrevivem
    counters = {}

    def emit(tok: str) -> str:
        base = tok.strip("<>").lower()
        counters[base] = counters.get(base, 0) + 1
        name = f"{base}{counters[base]}"
        rx = _RX_BODY[tok]
        return f'"(?P<{name}>{rx})"' if tok == "<STR>" else f"(?P<{name}>{rx})"

    out = body
    for tok in _RX_BODY:
        while tok in out:
            out = out.replace(tok, emit(tok), 1)
    return "^" + out + "$"


def _entropy(sizes) -> float:
    total = sum(sizes)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in sizes if c > 0)


def analyze(quarantine):
    """Pacote de telemetria de falha: clusters + sementes de conector + entropia."""
    clusters = sorted(cluster(quarantine), key=lambda c: -len(c[1]))
    sizes = [len(c[1]) for c in clusters]
    report = []
    for tmpl, lines in clusters:
        seed = suggest_regex(tmpl)
        try:
            re.compile(seed)
            valid = True
        except re.error:
            valid = False
        report.append({
            "template": tmpl,
            "count": len(lines),
            "coverage_pct": round(100.0 * len(lines) / max(len(quarantine), 1), 1),
            "sample": lines[0][:90],
            "suggested_regex": seed,
            "regex_valid": valid,
        })
    return {
        "total_quarantine": len(quarantine),
        "num_clusters": len(clusters),
        "entropy_bits": round(_entropy(sizes), 3),
        "clusters": report,
    }


if __name__ == "__main__":
    import sys

    # Lê a quarentena de um arquivo (handoff do Fabric Rust: `quarantine.log`),
    # ou usa um conjunto de demonstração se nenhum arquivo for passado.
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1], encoding="utf-8") as f:
            quarantine = [ln.strip() for ln in f if ln.strip()]
        print(f"=== Heraclitus CKE — quarentena de {sys.argv[1]} ({len(quarantine)} linhas) ===\n")
    else:
        quarantine = [
            "2026-06-26 03:11:01 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.5 action=deny",
            "2026-06-26 03:11:02 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.9 action=deny",
            "2026-06-26 03:11:05 UTC FORTI devid=FGT61D type=traffic srcip=10.0.0.7 action=accept",
            "SIGRH|user=carlos|op=DELETE|tbl=beneficios|status=erro",
            "SIGRH|user=ana|op=UPDATE|tbl=folha|status=ok",
            "SIGRH|user=joao|op=DELETE|tbl=beneficios|status=erro",
            "!@#$ corrupted blob 9fa8 ::: ???",
        ]
        print("=== Heraclitus CKE — quarentena de demonstracao ===\n")
    result = analyze(quarantine)
    print(f"Total: {result['total_quarantine']} | clusters: {result['num_clusters']} | "
          f"entropia: {result['entropy_bits']} bits\n")
    for i, c in enumerate(result["clusters"], 1):
        print(f"[Cluster {i}] {c['count']} logs ({c['coverage_pct']}%) | regex_valido={c['regex_valid']}")
        print(f"  template: {c['template']}")
        print(f"  amostra : {c['sample']}")
        print(f"  seed rgx: {c['suggested_regex']}")
        print(f"  -> pacote de telemetria enviado ao Forge p/ compilar novo conector\n")
