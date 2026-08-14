# Registry — os Artefatos de Conhecimento (`.hcx`)

Cada pasta é um **conector**; cada `vX.Y.Z.hcx` é uma versão compilada pelo
Forge. Um `.hcx` não é código — é conhecimento operacional declarativo: como
ler o formato de uma fonte, que semântica atribuir ao que lá está, e que
comportamento vigiar.

```
registry/
├── postgresql/          v1.0.0  v1.1.0  v1.2.0
└── linux_sshd/          v1.0.0  v1.1.0
```

## Anatomia (spec §5)

| Ficheiro | O que carrega |
| --- | --- |
| `manifest.yaml` | id, vendor, versão, domínio, `schema_version` da ontologia |
| `architecture.yaml` | o DAG de execução (`parse → normalize → behavior → emit`), ordenado por Kahn |
| `ontology.yaml` | o mapa do formato bruto para o modelo canónico |
| `reasoning.yaml` | as regras do Reasoner: condição → inferência |
| `behavior.model` | janelas temporais do Behavior Engine (ex.: N falhas em M segundos) |
| `test_matrix.json` | linhas reais e a ação que cada uma tem de produzir |
| `benchmarks.json` | EPS estimado + **cobertura medida pelo runner Rust** |
| `signature.sig` | selo do artefato — ver a ressalva abaixo |

## Porque é que isto está versionado no git

Foi ignorado até 2026-08-14. Passou a ser versionado porque um conector
compilado é o **património** do projeto, não um ficheiro temporário: dá diff
entre versões do mesmo conector, permite rever o que o Forge (ou o Claude, via
`forge_ai.py`) derivou antes de aquilo correr em produção, e faz do repositório
a fonte da verdade — em vez da pasta local de quem correu o compilador por
último.

## Ressalva: a assinatura ainda é mock

O `signature.sig` diz `ed25519:sig:…` mas **não é uma assinatura ed25519 real**
— é um selo determinístico gerado pelo `forge_compiler.py`. A âncora do `.hdb`
essa sim é assinada com ed25519 a sério (Marco B); o artefato `.hcx` está à
espera do mesmo tratamento. Ver `AUDIT.md` §2.2 (residual do Marco B).

Até lá: **não trates a presença do `signature.sig` como prova de origem.** A
prova de origem de um `.hcx` neste momento é o histórico do git.

## Compilar um conector novo

```bash
export ANTHROPIC_API_KEY=...          # sem isto, o perfil sai semanticamente vazio
python cke_forge_pipeline.py /caminho/do/cliente.log
```

O `compiled_at` do `manifest.yaml` é fixo de propósito — mantém o artefato
byte-a-byte reproduzível para a mesma entrada, para que um diff no git mostre
mudanças de conhecimento e não de relógio.
