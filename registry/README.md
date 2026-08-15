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

## Assinatura Ed25519 (Marco B — fechado em 2026-08-14)

Cada artefato traz uma assinatura **ed25519 real** sobre um digest canónico de
todo o seu conteúdo, verificável contra `publisher.pub` (versionada aqui — é a
âncora de confiança).

```bash
python forge_sign.py verify-all                        # varre o registry
python forge_sign.py verify registry/postgresql/v1.2.0.hcx
```

O `signature.sig` é autodescritivo e diz **quem** assinou:

```
format=hcx-v3
alg=ed25519
key=5254bdb1…      <- tem de bater com publisher.pub
digest=a1182519…   <- SHA-256 canónico do artefato
sig=fc1e7a94…      <- 64 bytes
```

**O que mudou.** Até 13 de agosto o `signature.sig` dizia `ed25519:sig:<hash>`
mas era um SHA-256 truncado — não havia chave nenhuma, e quem alterasse um
artefato recalculava o selo em duas linhas. O digest antigo cobria uma *lista
fixa* de ficheiros, por isso acrescentar um ficheiro novo ao pacote nem sequer o
mexia. O novo cobre **todos** os ficheiros, com nome e comprimento a enquadrar
cada um. Desde o \`hcx-v3\`, texto UTF-8 usa finais de linha LF canónicos para a
mesma assinatura funcionar em checkouts Windows e Linux; binários continuam
assinados byte a byte.

**Modelo de confiança.** A chave de publicação é distinta da chave da âncora do
`.hdb`: aquela prova que *os dados* não foram adulterados na máquina que os
serve, esta prova que *o conhecimento* foi publicado por quem diz tê-lo
publicado. A privada vive em `~/.heraclitus/publisher.key`, **fora** do
repositório — um `git add -A` distraído nunca a apanha.

**Limite honesto.** Isto prova *quem publicou*, não que o conhecimento esteja
correto. Um conector mal derivado, assinado, continua mal derivado. A revisão do
conteúdo é o code review; a assinatura só garante que o que revíste é o que
corre.

## Compilar um conector novo

```bash
export ANTHROPIC_API_KEY=...          # sem isto, o perfil sai semanticamente vazio
python forge_sign.py keygen           # uma vez por publicador
python cke_forge_pipeline.py /caminho/do/cliente.log
```

Artefatos novos nascem assinados. Sem chave de publicação o compilador emite o
artefato **sem** `signature.sig` e diz que o fez — o que nunca volta a acontecer
é sair um selo a fingir que é uma assinatura.

O `compiled_at` do `manifest.yaml` é fixo de propósito — mantém o artefato
byte-a-byte reproduzível para a mesma entrada, para que um diff no git mostre
mudanças de conhecimento e não de relógio.
