# Política de segurança

Relate vulnerabilidades de forma privada pelo recurso **Security Advisories**
do repositório. Nunca anexe logs reais, chaves, tokens, dados pessoais ou
artefatos de clientes a issues públicas.

## Gates obrigatórios

- Rust: `fmt`, `clippy -D warnings`, todos os testes/targets, build release e
  `cargo audit --deny warnings` sem exceções.
- Python: ambiente reproduzido por `requirements.lock` com hashes, Ruff,
  testes unitários e cruzados, e `pip-audit`.
- Registry: todo `.hcx` deve validar a assinatura Ed25519 contra
  `registry/publisher.pub`; a chave privada de publicação nunca pertence ao
  repositório.
- Dados rejeitados: quarentena XChaCha20-Poly1305 autenticada; texto bruto não
  pode aparecer em resposta HTTP, console ou arquivo plaintext.

O Forge não deve ser exposto fora de loopback enquanto não houver uma camada
homologada de TLS/mTLS, autenticação, autorização e trilha de acesso. A ponte
para o HeraclitusDB exige TLS para qualquer destino não-loopback.
