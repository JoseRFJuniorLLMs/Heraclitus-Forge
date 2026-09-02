"""
forge_seeds — conectores derivados OFFLINE, sem chamada à API.

Porque é que isto existe
------------------------
O `forge_ai.derive_profile()` pede ao Claude que leia amostras de log e devolva
um conector declarativo. Precisa de `ANTHROPIC_API_KEY` e `FORGE_AI_MODEL`. Sem
elas, o `cke_forge_pipeline` cai na heurística de regex do CKE — que casa as
linhas mas não lhes atribui semântica: tudo sai `log.info` / `observation` /
`Low`, com actor e target a `unknown`. Ingerir milhares de Fatos assim é pior do
que não ingerir: enche o banco de registos que não respondem a pergunta nenhuma.

Estes perfis foram derivados **à mão, no mesmo formato que a tool
`emit_connector_profile` produz**, para que o registry tenha conectores úteis
antes de haver chave. Quando a chave existir, o caminho da API passa a ser o
gerador — e estes ficam como referência do que uma boa derivação produz, e como
base de comparação para avaliar o que o modelo devolve.

**Não** finge que a API foi chamada: o `forge_ai.available()` continua a
devolver `False` sem chave, e o pipeline continua a dizer qual caminho usou.
"""

from __future__ import annotations

import _console  # noqa: F401  (consola UTF-8 no Windows)

# ---------------------------------------------------------------------------
# nginx / Apache — log de acesso combinado
# ---------------------------------------------------------------------------
# O código de estado HTTP é o que carrega a semântica: 401 é falha de
# autenticação, 403 é violação de autorização (o utilizador está autenticado e
# tentou o que não podia — o caso que mais interessa auditar num órgão), 404 em
# rajada é varredura, 5xx é falha do próprio serviço.
NGINX_ACCESS = {
    "vendor": "nginx / Apache (log de acesso combinado)",
    "domain": "web_access",
    "confidence": 0.97,
    # SPEC-0071 §4.4 — modelo canónico. `category` é a categoria PRIMÁRIA; o
    # 401 vai para `authentication` e o 403 para `privilege` por decisão do
    # mapping versionado (rust/crates/heraclitus-security-schema).
    "security": {
        "security_schema": "heraclitus-security-event/1.0",
        "category": "http",
        "mapping_version": "nginx-access/1.0.0",
        "required_fields": ["observed_at_micros", "datasource_id", "sensor_id"],
    },
    "parse": {
        "engine": "regex",
        "pattern": (
            r"^(?P<src_ip>\S+) \S+ (?P<auth_user>\S+) \[(?P<ts>[^\]]+)\] "
            r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
            r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"$'
        ),
    },
    "reasoning": [
        {
            "id": "http_auth_failure",
            "when": [{"field": "status", "equals": "401"}],
            "set": {
                "action": "authentication.failure",
                "behavior_class": "credential_attack",
                "risk": "High",
                "identity": {
                    "actor_name": "${auth_user}",
                    "target_id": "${path}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            # 403 e o achado mais valioso deste conector: quem ja esta dentro a
            # tentar o que nao lhe compete. Num orgao publico e o padrao de
            # acesso indevido a dados de servidores.
            "id": "http_authz_violation",
            "when": [{"field": "status", "equals": "403"}],
            "set": {
                "action": "authorization.failure",
                "behavior_class": "privilege_violation",
                "risk": "Critical",
                "identity": {
                    "actor_name": "${auth_user}",
                    "target_id": "${path}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            "id": "http_not_found",
            "when": [{"field": "status", "equals": "404"}],
            "set": {
                "action": "resource.missing",
                "behavior_class": "reconnaissance",
                "risk": "Medium",
                "identity": {
                    "actor_name": "${auth_user}",
                    "target_id": "${path}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            "id": "http_server_error",
            "when": [{"field": "status", "matches": r"^5\d\d$"}],
            "set": {
                "action": "service.error",
                "behavior_class": "availability",
                "risk": "Medium",
                "identity": {
                    "actor_name": "${auth_user}",
                    "target_id": "${path}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            "id": "http_success",
            "when": [{"field": "status", "matches": r"^2\d\d$"}],
            "set": {
                "action": "data.access",
                "behavior_class": "session",
                "risk": "Low",
                "identity": {
                    "actor_name": "${auth_user}",
                    "target_id": "${path}",
                    "source_ip": "${src_ip}",
                },
            },
        },
    ],
    "behavior": [
        {
            "id": "http_brute_force",
            "trigger_action": "authentication.failure",
            "window_secs": 60,
            "threshold": 3,
            "escalate_to": {"behavior_class": "credential_attack", "risk": "Critical"},
        },
        {
            "id": "http_scan",
            "trigger_action": "resource.missing",
            "window_secs": 30,
            "threshold": 5,
            "escalate_to": {"behavior_class": "reconnaissance", "risk": "High"},
        },
    ],
    "test_matrix": [
        {
            "input": '187.54.12.33 - carlos.silva [15/Aug/2026:03:12:51 -0300] "POST /admin/login HTTP/1.1" 401 172 "-" "Mozilla/5.0"',
            "expect_action": "authentication.failure",
        },
        {
            "input": '10.2.3.44 - ana.pereira [15/Aug/2026:03:13:19 -0300] "GET /rh/folha/exportar HTTP/1.1" 403 199 "-" "Mozilla/5.0"',
            "expect_action": "authorization.failure",
        },
        {
            "input": '203.0.113.7 - - [15/Aug/2026:03:13:27 -0300] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.4.0"',
            "expect_action": "resource.missing",
        },
        {
            "input": '10.2.3.51 - joao.souza [15/Aug/2026:03:13:40 -0300] "GET /rh/servidor/12345 HTTP/1.1" 200 4210 "-" "Mozilla/5.0"',
            "expect_action": "data.access",
        },
        {
            "input": '10.2.3.51 - joao.souza [15/Aug/2026:03:13:55 -0300] "DELETE /rh/beneficios/9981 HTTP/1.1" 500 617 "-" "Mozilla/5.0"',
            "expect_action": "service.error",
        },
    ],
    "benchmark": {"estimated_eps": 120_000, "avg_latency_ms": 0.8},
}

# ---------------------------------------------------------------------------
# Windows Security Event Log (renderizado em texto)
# ---------------------------------------------------------------------------
# O EventID e a chave. Para auditar servidores publicos, os que contam sao:
# 4625 (falha de autenticacao), 4624 (logon), 4634 (logoff), 4672 (privilegio
# especial atribuido), 4720 (conta criada) e 4726 (conta eliminada) -- os dois
# ultimos sao alteracoes ao cadastro, que exigem trilha por si so.
WINDOWS_SECURITY = {
    "vendor": "Microsoft Windows (Security Event Log)",
    "domain": "identity_access",
    "confidence": 0.96,
    # SPEC-0071 §4.4. Categoria primária `identity`: 4720/4726 são ciclo de
    # vida de conta. Os 4624/4625 sobrepõem para `authentication` e o 4672
    # para `privilege`, no mapping versionado.
    "security": {
        "security_schema": "heraclitus-security-event/1.0",
        "category": "identity",
        "mapping_version": "windows-security/1.0.0",
        "required_fields": ["observed_at_micros", "datasource_id", "sensor_id"],
    },
    "parse": {
        "engine": "regex",
        "pattern": (
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) SecurityEvent "
            r"(?P<message>EventID=\d+ .*)$"
        ),
    },
    "reasoning": [
        {
            "id": "win_logon_failure",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4625 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+) .*IpAddress=(?P<src_ip>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "authentication.failure",
                "behavior_class": "credential_attack",
                "risk": "High",
                "identity": {
                    "actor_name": "${target_user}",
                    "target_id": "${host}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            "id": "win_privilege_assigned",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4672 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "privilege.granted",
                "behavior_class": "privilege_violation",
                "risk": "High",
                "identity": {"actor_name": "${target_user}", "target_id": "${host}"},
            },
        },
        {
            "id": "win_account_created",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4720 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "account.created",
                "behavior_class": "identity_lifecycle",
                "risk": "High",
                "identity": {"actor_name": "${target_user}", "target_id": "${host}"},
            },
        },
        {
            "id": "win_account_deleted",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4726 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "account.deleted",
                "behavior_class": "identity_lifecycle",
                "risk": "Critical",
                "identity": {"actor_name": "${target_user}", "target_id": "${host}"},
            },
        },
        {
            "id": "win_logon_success",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4624 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+) .*IpAddress=(?P<src_ip>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "authentication.success",
                "behavior_class": "session",
                "risk": "Low",
                "identity": {
                    "actor_name": "${target_user}",
                    "target_id": "${host}",
                    "source_ip": "${src_ip}",
                },
            },
        },
        {
            "id": "win_logoff",
            "when": [
                {
                    "field": "message",
                    "matches": (
                        r"EventID=4634 Computer=(?P<host>\S+) "
                        r"TargetUserName=(?P<target_user>\S+)"
                    ),
                }
            ],
            "set": {
                "action": "session.end",
                "behavior_class": "session",
                "risk": "Low",
                "identity": {"actor_name": "${target_user}", "target_id": "${host}"},
            },
        },
    ],
    "behavior": [
        {
            "id": "win_brute_force",
            "trigger_action": "authentication.failure",
            "window_secs": 120,
            "threshold": 3,
            "escalate_to": {"behavior_class": "credential_attack", "risk": "Critical"},
        },
    ],
    "test_matrix": [
        {
            "input": "2026-08-15 03:20:44 SecurityEvent EventID=4625 Computer=DESK-SIAPE-042 TargetUserName=administrador LogonType=3 IpAddress=203.0.113.90 Status=0xC000006D",
            "expect_action": "authentication.failure",
        },
        {
            "input": "2026-08-15 03:20:01 SecurityEvent EventID=4624 Computer=DESK-SIAPE-042 TargetUserName=carlos.silva LogonType=2 IpAddress=10.2.3.44 Status=0x0",
            "expect_action": "authentication.success",
        },
        {
            "input": "2026-08-15 03:21:10 SecurityEvent EventID=4672 Computer=SRV-RH-01 TargetUserName=svc-folha LogonType=5 IpAddress=- Status=0x0",
            "expect_action": "privilege.granted",
        },
        {
            "input": "2026-08-15 03:21:33 SecurityEvent EventID=4720 Computer=SRV-RH-01 TargetUserName=usuario.novo LogonType=0 IpAddress=10.2.3.9 Status=0x0",
            "expect_action": "account.created",
        },
        {
            "input": "2026-08-15 03:22:02 SecurityEvent EventID=4726 Computer=SRV-RH-01 TargetUserName=ana.pereira LogonType=0 IpAddress=10.2.3.9 Status=0x0",
            "expect_action": "account.deleted",
        },
        {
            "input": "2026-08-15 03:22:40 SecurityEvent EventID=4634 Computer=DESK-SIAPE-042 TargetUserName=carlos.silva LogonType=2 IpAddress=10.2.3.44 Status=0x0",
            "expect_action": "session.end",
        },
    ],
    "benchmark": {"estimated_eps": 90_000, "avg_latency_ms": 1.1},
}

#: Nome do conector -> perfil. Usado pelo `compilar_sementes.py`.
SEEDS = {
    "nginx_access": NGINX_ACCESS,
    "windows_security": WINDOWS_SECURITY,
}
