# Auditoria de prontidão — Heraclitus-Forge 1.0

**Data:** 2026-08-14

**Escopo:** runtime Rust, ferramentas Python, registry assinado e integração com
HeraclitusDB 1.0.5.

**Contexto:** tratamento de logs de servidores de órgão público.

## Veredicto

**APROVADO TECNICAMENTE para homologação controlada e para produção dentro do
perfil documentado, condicionado aos gates externos da seção final.**

Este veredicto não é uma certificação jurídica, ICP-Brasil, LGPD ou de
infraestrutura. Código verde não substitui RIPD, política de retenção, HSM/PKI,
TSA credenciada, teste de restauração na infraestrutura-alvo e autorização do
gestor de segurança.

## Controles implementados e testados

| Controle | Estado | Evidência automatizada |
| --- | --- | --- |
| Integridade física | aprovado | CRC-32C, limites de tamanho e rejeição de bloco corrompido |
| Cadeia de custódia | aprovado | cadeia BLAKE3 + âncora Ed25519 verificada antes da exportação |
| Artefatos `.hcx` | aprovado | assinatura Ed25519 sobre digest canônico de todos os arquivos; 5/5 válidos |
| Exactly-once DB | aprovado | chave persistente e teste de crash entre ACK e checkpoint |
| Contrato DB↔Forge | aprovado | envelope/schema/API versionados e rejeição fail-closed |
| Quarentena | aprovado | XChaCha20-Poly1305; tamper e interoperabilidade Rust/Python |
| PII em respostas/logs | aprovado | gateway devolve somente fingerprint; `agent_id` e `session_id` usam HMAC; inspeção física do WAL |
| Execução acidental | aprovado | binários e loader de massa falham sem opt-in/configuração |
| Rede | aprovado no perfil | gateway loopback; ponte exige TLS fora de loopback; HDB usa RBAC/TLS/mTLS |
| Dependências | aprovado | `cargo audit --deny warnings`; `pip-audit` sobre lock com hashes |
| Qualidade | aprovado | fmt, clippy `-D warnings`, Ruff e suítes Rust/Python |

## Resultado reproduzido nesta auditoria

- Rust: 29 testes aprovados.
- Python/cross-language: 57 testes aprovados e 2 testes `live` opt-in fora da
  suíte segura padrão.
- Registry: PostgreSQL 1.0/1.1/1.2 e Linux SSHD 1.0/1.1 com assinatura válida.
- Dependências Rust do Forge: nenhuma vulnerabilidade ou advisory aceito.
- Dependências Python: instalação exata por `requirements.lock` com hashes e
  nenhuma vulnerabilidade conhecida no momento da auditoria.
- E2E real: 9 fatos aceitos; retry antes e depois de crash retornou 9/9
  deduplicados; 9 fatos permaneceram consultáveis e com custódia completa.
- Privacidade física: 77 valores de conteúdo/atributos foram procurados no WAL
  cifrado antes e depois do restart; zero ocorrência em plaintext.
- Supply chain: Actions fixadas por SHA, Rust 1.96.0 fixado, Dependabot e
  Gitleaks habilitados; histórico e árvore atual sem segredos não justificados.

## Limites operacionais do release 1.0

- O gateway é um receptor; acompanhamento nativo de journald, Windows Event Log
  ou logical replication deve ser feito por coletor homologado.
- O dashboard é exclusivamente demonstrativo e só abre com
  `FORGE_ENABLE_DEMO_DASHBOARD=1`; não faz parte do perímetro de produção.
- A chave privada da âncora `.hdb`, a chave HMAC de titulares, a chave de
  quarentena e o token do writer precisam viver em cofre/HSM com rotação e
  segregação de funções. O repositório contém apenas chaves públicas.
- O teste `live` deve usar instância descartável ou namespace próprio. O banco
  de memória local em `127.0.0.1:7474` não é alvo de testes destrutivos.

## Gates externos obrigatórios antes do go-live do órgão

1. Aprovar RIPD/LGPD, base legal, minimização, retenção e descarte por classe de
   log com encarregado e área jurídica.
2. Provisionar TSA RFC 3161/ICP-Brasil real e validar a cadeia CMS contra as
   raízes oficiais; `LocalTsa` é somente laboratório.
3. Provisionar PKI/mTLS e cofre/HSM; emitir identidades separadas para writer,
   auditor e administrador; ensaiar rotação e revogação.
4. Executar teste de carga, failover e restauração com volume/latência/RPO/RTO
   do ambiente final; o resultado local não dimensiona produção.
5. Aplicar hardening do SO, EDR, firewall, backup imutável/off-site, SIEM,
   monitoramento e resposta a incidentes conforme as normas do órgão.
6. Fazer aceite formal do conector de cada nova fonte com amostras
   representativas e revisão humana antes de assinar/publicar o `.hcx`.
