"""Gerador explícito e seguro de carga sintética para o HeraclitusDB local.

Este arquivo não executa nada ao ser importado. A carga só começa com
`--confirm-demo-load` e é limitada por padrão para impedir milhões de escritas
acidentais no banco operacional.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

ACTIONS = [
    "authentication.success",
    "authentication.failure",
    "query.execute",
    "authorization.failure",
    "data.export",
]
CLASSES = ["session", "credential_attack", "data_access", "privilege_violation"]
RISKS = ["Low", "Medium", "High", "Critical"]
TARGETS = ["postgresql-demo", "directory-demo", "firewall-demo", "api-demo"]
USERS = ["demo-admin", "demo-root", "demo-guest", "demo-service", "demo-user"]


def _is_loopback(addr: str) -> bool:
    host = addr.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def _worker(db, worker_id: int, start: int, end: int, run_id: str, seed: int) -> int:
    rng = random.Random(seed + worker_id)
    written = 0
    for index in range(start, end):
        # RFC 5737 TEST-NET-1: nunca representa um endereço real de cliente.
        source_ip = f"192.0.2.{rng.randint(1, 254)}"
        user = rng.choice(USERS)
        action = rng.choice(ACTIONS)
        action_class = rng.choice(CLASSES)
        risk = rng.choice(RISKS)
        target = rng.choice(TARGETS)
        content = f"synthetic user={user} action={action} target={target} source={source_ip}"
        db.append(
            "OperationalFact",
            content,
            agent_id="forge-demo-load",
            session_id=run_id,
            attrs={
                "source_ip": source_ip,
                "actor_name": user,
                "target_id": target,
                "risk_level": risk,
                "action_class": action_class,
                "synthetic": "true",
                "generated_by": "forge_demo_load",
                "sequence_id": str(index),
            },
            idempotency_key=f"forge-demo:{run_id}:{index}",
        )
        written += 1
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-demo-load", action="store_true")
    parser.add_argument("--addr", default="127.0.0.1:7474")
    parser.add_argument("--count", type=int, default=1_000)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260814)
    parser.add_argument("--run-id", default="")
    parser.add_argument(
        "--allow-large",
        action="store_true",
        help="permite mais de 100.000 eventos sintéticos",
    )
    args = parser.parse_args()

    if not args.confirm_demo_load:
        parser.error("a carga só é permitida com --confirm-demo-load")
    if not _is_loopback(args.addr):
        parser.error("este gerador de demonstração é restrito ao loopback")
    if args.count < 1:
        parser.error("--count deve ser positivo")
    if args.count > 100_000 and not args.allow_large:
        parser.error("mais de 100.000 eventos exige --allow-large")
    if not 1 <= args.threads <= 64:
        parser.error("--threads deve estar entre 1 e 64")

    run_id = args.run_id or f"demo-{uuid.uuid4()}"
    chunk = (args.count + args.threads - 1) // args.threads
    import heraclitusdb

    db = heraclitusdb.connect(args.addr)
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for worker_id in range(args.threads):
                start = worker_id * chunk
                end = min(start + chunk, args.count)
                if start < end:
                    futures.append(
                        executor.submit(
                            _worker,
                            db,
                            worker_id,
                            start,
                            end,
                            run_id,
                            args.seed,
                        )
                    )
            written = sum(future.result() for future in futures)
    finally:
        db.close()

    elapsed = max(time.monotonic() - started, 1e-9)
    print(
        f"Carga sintética concluída: {written} eventos em {elapsed:.2f}s "
        f"({written / elapsed:.0f} ops/s); run_id={run_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
