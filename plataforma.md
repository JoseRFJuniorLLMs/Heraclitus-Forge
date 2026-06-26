# ESPECIFICAÇÃO DE ARQUITETURA DE PRODUTO: HERACLITUS SUITE (v6.0)

**Classificação:** Documento de Engenharia de Produto & Especificação de Linha de Negócios

**Paradigma:** Infraestrutura de Conhecimento Operacional Verificável (Operational Knowledge Infrastructure)

**Ano de Emissão:** 2026

## ── THE MANIFESTO ──

> "O Heraclitus é uma infraestrutura para compilação, execução, governança e preservação de conhecimento operacional verificável. Seu objetivo não é armazenar dados, mas transformar observações heterogêneas em Fatos Operacionais determinísticos, criptograficamente verificáveis e semanticamente interoperáveis."

## 1. Desatracação da Suite: As 4 Linhas de Produtos

A plataforma abandona o monólito arquitetural e divide seu ecossistema em quatro componentes de mercado perfeitamente isolados por APIs estritas.

```
                    ┌──────────────────────────────────┐
                    │     HERACLITUS KNOWLEDGE CLOUD   │ ◄── Registry, Marketplace, CKE & Analytics
                    └────────────────┬─────────────────┘
                                     │
                     (Distribui Artefatos .hcx v6)
                                     │
                                     ▼
 ┌──────────────────────┐    ┌──────────────────────┐
 │   HERACLITUS FORGE   │    │  HERACLITUS RUNNER   │
 │                      │    │                      │
 │ (Fábrica / Compiler  │    │ (Planner ➔ Optimizer │
 │  de Conhecimento)    │    │  Reasoner ➔ Behavior)│
 └──────────────────────┘    └──────────┬───────────┘
                                        │
                             (Persiste Fatos Seguros)
                                        │
                                        ▼
                    ┌──────────────────────────────────┐
                    │          HERACLITUSDB            │ ◄── Storage Temporal Baseado em Fatos Estritos
                    └──────────────────────────────────┘
```

### PRODUTO 1: HeraclitusDB

O HeraclitusDB assume o papel exclusivo de **Motor de Persistência Temporal Criptográfico**. Ele foi totalmente despido de inteligência semântica de redes, regras de segurança ou taxonomias de ameaças.

* **Escopo:** Um banco de dados *append-only* de altíssima performance estruturado estritamente para armazenar tuplas imutáveis de Fatos Operacionais.
* **Mecanismo de Confiança:** Expõe uma API minimalista e estável contendo a função nativa `db.verify()`, responsável por validar a integridade retroativa da cadeia Merkle e assinaturas digitais sem conhecer o significado do payload.
* **Características:** Zero dependência de contexto de fabricantes; imutabilidade matemática pura ao nível de armazenamento.

### PRODUTO 2: Heraclitus Forge (The Studio Core)

O Forge opera estritamente em *Design-Time* dentro do ambiente isolado do **Heraclitus Studio**. Ele não possui conexão direta com os runtimes de produção e é completamente agnóstico em relação ao banco de dados final.

* **Escopo:** Uma esteira multiagente de engenharia que ingere observações heterogêneas e as compila em um **Artefato de Conhecimento (`.hcx` v6.0)**.
* **Saída:** Gera especificações puramente declarativas (DSL), matrizes de testes de regressão sintática e perfis de benchmark teóricos que mapeiam o DNA da inteligência extraída.

### PRODUTO 3: Heraclitus Runner

O coração operacional do ecossistema. Um runtime estático, ultra-leve e linear, projetado para executar a transformação em velocidade de linha (*line-rate*). O Runner pode operar de forma autônoma na ponta (*edge*), inclusive em ambientes sem persistência local (sem banco de dados).

O ciclo de vida interno do processamento do Runner é governado por um pipeline de quatro motores internos especializados:

```
[Observation] ➔ 1. Planner ➔ 2. Optimizer ➔ 3. Reasoner ➔ 4. Behavior Engine ➔ [Operational Fact]
```

* **1. The Planner:** Lê o arquivo declarativo `.hcx` e constrói o plano de metas estruturais.
* **2. The Optimizer:** Avalia a arquitetura física da CPU e otimiza o Grafo Acíclico Direcionado (DAG) para execução vetorizada concorrente.
* **3. The Reasoner:** Executa as inferências lógicas baseadas em regras declarativas estáticas de transição de estado da ontologia.
* **4. The Behavior Engine:** Isola a lógica comportamental dinâmica da estrutura do dado. Avalia os padrões cronológicos de ações mutáveis e correlaciona a semântica cross-manufacturer.

### PRODUTO 4: Heraclitus Knowledge Cloud

A camada de negócios, monetização recorrente e governança global do ecossistema (SaaS ou Nuvem Privada Governamental).

* **The Registry & Marketplace:** O hub de distribuição versionada e assinado digitalmente de Artefatos de Conhecimento (`.hcx`) para sistemas de mercado (Cisco, Windows, SAP, Oracle, Protheus).
* **Continuous Knowledge Evolution (CKE):** O motor de aprendizado contínuo centralizado que clusteriza exceções textuais enviadas de forma anônima pelos Runners dos clientes, gerando novas versões de artefatos de forma automatizada.
* **Knowledge Diff:** Interface analítica que compara o genoma de duas versões de inteligência, gerando relatórios de impacto normativo.

## 2. A Unidade Fundamental: Fato Operacional (Operational Fact)

O HeraclitusSuite extingue as abstrações de "logs", "eventos textuais" ou "registros". A única entidade processada e gravada no sistema é o **Fato Operacional (Operational Fact - OF)**.

Cada Fato Operacional é definido formalmente como uma estrutura atômica, tipada e indissociável composta por 10 dimensões obrigatórias:

**JSON**

```
{
  "fact.id": "uuid-v7-deterministico",
  "fact.identity": {
    "actor.id": "usr-0412",
    "actor.name": "admin_service",
    "target.id": "db-prod-01"
  },
  "fact.time": {
    "system_timestamp": "2026-06-26T01:20:00.001234Z",
    "log_sequence_number": 14812337
  },
  "fact.behavior": {
    "class": "credential_attack",
    "action": "authentication.failure",
    "risk_level": "high"
  },
  "fact.evidence": {
    "raw_observation_hash": "blake3_hex_value",
    "carimbo_tempo_legal": "icp_brasil_serpro_tst_recibo"
  },
  "fact.lineage": {
    "transformation_steps": ["parse.syslog", "normalize.identity", "enrich.geoip"],
    "input_source": "syslog.udp.10.0.0.5"
  },
  "fact.integrity": {
    "merkle_root_anchor": "b3:9f2a...e71c",
    "signature": "ed25519_hex_signature"
  },
  "fact.confidence": 98.4,
  "fact.knowledge_version": "br.gov.heraclitus.pipelines.linux-v2.4.1",
  "fact.reasoning_version": "reasoner-core-v3.0",
  "fact.ontology_version": "core-ontology-v9"
}
```

## 3. Desacoplamento Camada 4: Ontologia Hierárquica vs. Modelo Comportamental

A plataforma separa a infraestrutura de dados em dois eixos conceituais totalmente independentes, eliminando a fragilidade estrutural da arquitetura v5.0.

### Eixo 1: Ontologia Relacional (O que existe — Estática)

Mapeia a infraestrutura física e lógica do mundo corporativo. É dividida em uma estrutura hierárquica estrita de quatro subcamadas:

\$\$\\text{Core Ontology} \\longrightarrow \\text{Domain Ontology} \\longrightarrow \\text{Customer Ontology} \\longrightarrow \\text{Pipeline Ontology}\$\$

* **Core Ontology:** O esqueleto imutável do Heraclitus (`Entity`, `Actor`, `Action`, `Object`, `Relationship`, `Evidence`, `Timeline`).
* **Domain Ontology:** Extensões verticais especializadas para mercados específicos (ex: Área Bancária: `PIX`, `TED`, `Conta`; Área Médica: `Paciente`, `Prontuário`, `CID`; Área Militar: `Radar`, `Alvo`).
* **Customer Ontology:** Entidades exclusivas da infraestrutura do cliente (ex: `SIGRH-X`, `SIAFI-Acre`).
* **Pipeline Ontology:** Objetos temporários de transição exigidos por um determinado ativo de tecnologia.

### Eixo 2: Modelo Comportamental (O que aconteceu — Dinâmica)

Mapeia a cronologia das ações sem interferir nas classes estruturais da ontologia. Ele descreve a evolução temporal dos estados de um Actor ou Object (ex: `Authentication`\$\\rightarrow\$`Privilege Escalation`\$\\rightarrow\$`Lateral Movement`\$\\rightarrow\$`Exfiltration`).

Como o comportamento das ameaças e das aplicações muda muito mais rápido do que a topologia do core do sistema, as atualizações no **Behavior Engine** ocorrem sem a necessidade de reescrever ou migrar as tabelas ontológicas do `HeraclitusDB`.

## 4. Provedores de Ameaças (Threat Providers) como Plugins Modularizados

O framework de inteligência contra invasões **MITRE ATT&CK** foi totalmente extraído do núcleo da plataforma. Ele passa a ser tratado como um **Threat Provider Plugin** periférico dentro da arquitetura de conhecimento do arquivo `ontology.yaml`.

```
                        ┌──────────────────────────────┐
                        │    ONTOLOGY_BINDER NODE      │
                        └──────────────┬───────────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                ▼                      ▼                      ▼
       ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
       │  Plugin: MITRE  │    │  Plugin: SIGMA  │    │  Plugin: YARA   │
       │  (T1110)        │    │  (Regras YAML)  │    │  (Assinaturas)  │
       └─────────────────┘    └─────────────────┘    └─────────────────┘
```

A arquitetura aceita nativamente a concorrência e injeção de múltiplos providers em paralelo no mesmo artefato `.hcx`: `MITRE ATT&CK`, `OWASP Top 10`, `CAPEC`, `SIGMA`, `YARA`, ou frameworks de conformidade estritamente nacionais e customizados pelo próprio cliente.

## 5. Anatomia do Novo Artefato de Conhecimento (`.hcx` v6.0)

O output consolidado do Forge expande suas capacidades para atuar como o verdadeiro repositório de propriedade intelectual da suite, carregando os seguintes arquivos imutáveis:

**Plaintext**

```
sap_erp_knowledge.hcx/
├── manifest.yaml          # Metadados, autor, expiração e governança do ciclo de vida
├── architecture.yaml      # Definição declarativa do DAG para o otimizador do Runner
├── core_binding.yaml      # Acoplamento estrito com a versão da Ontologia Hierárquica
├── knowledge.hkg          # Grafo relacional local (Operational Knowledge Network)
├── behavior.model         # Regras dinâmicas para o Behavior Engine
├── reasoning.yaml         # Inferências lógicas de primeira ordem para o Reasoner
├── test_matrix.json       # Biblioteca de testes de regressão sintática e de cobertura
├── benchmarks.json        # Selo metrológico (Métricas teóricas de EPS, RAM e Confiança)
└── signature.sig          # Assinatura digital Ed25519 gerada pelo Heraclitus Studio
```

## 6. Diretrizes Finais de Engenharia para o Claude Code

Para iniciar a construção modular do ecossistema **v6.0**, instrua o agente **Claude Code** a criar a fundação do código respeitando rigorosamente a separação de escopo dos produtos.

### Estrutura do Repositório Mestre

**Plaintext**

```
heraclitus_suite_v6/
├── heraclitus_db/                # Motor estável de persistência de Fatos (Append-Only)
│   ├── storage.py
│   └── integrity.py              # db.verify() criptográfico puro
├── heraclitus_forge/             # O ambiente Studio de compilação de conhecimento
│   ├── agents/
│   │   ├── ontology_compiler.py  # Compilador das 4 camadas de Ontologia
│   │   └── behavior_compiler.py  # Compilador do Modelo Comportamental Dinâmico
│   └── studio_cli.py
├── heraclitus_runner/            # O runtime declarativo de produção (Line-Rate)
│   ├── planner.py
│   ├── optimizer.py
│   ├── reasoner.py               # Interpretador lógico de primeira ordem
│   └── behavior_engine.py        # Processador de assinaturas comportamentais
└── heraclitus_cloud/             # Camada SaaS / CKE / Registry
    ├── registry.py               # Gerenciador de distribuição de pacotes .hcx
    └── cke_analytics.py          # Clusterizador de Fatos Operacionais Desconhecidos
```

### Comando Executivo de Disparo para o Claude Code:

> *"Claude, implemente o esqueleto arquitetural do repositório `heraclitus_suite_v6`. Você deve garantir o isolamento absoluto entre os quatro módulos de produtos. O arquivo `heraclitus_db/integrity.py` deve implementar a lógica do `db.verify()` operando exclusivamente sobre a estrutura imutável do Fato Operacional (OF), sem qualquer conhecimento semântico ou de segurança. O módulo `heraclitus_runner` deve ser projetado de forma declarativa, onde o componente `behavior_engine.py` avalia de forma pura as transições dinâmicas de comportamento do Actor e do Object, segregando a lógica ontológica da lógica de ações cronológicas, em conformidade estrita com o manual v6.0."*
