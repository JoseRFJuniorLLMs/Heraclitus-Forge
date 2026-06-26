"""
Heraclitus Fabric — orquestracao de conectividade (Plug-and-Play / Drivers).

Conforme `Operational-Fact.md` (secao Fabric) e o "Ciclo de Vida de Segunda-Feira":
Discover -> Connect -> Compile -> Deploy -> Observe -> Learn. O Fabric descobre os
ativos, baixa (ou manda o Forge compilar) o `.hcx` correspondente, sobe um Runner
dedicado por fonte e monitora o stream procurando Schema Drift.
"""

import os
import time
from typing import Dict, List, Any

from forge_compiler import HeraclitusForgeCompiler
from runner_engine import ReconstitutiveRunner
from heraclitus_db import HeraclitusDB


class HeraclitusFabric:
    def __init__(self, registry_dir: str = "./registry", db_path: str = "storage.hdb"):
        self.registry_dir = registry_dir
        self.db_path = db_path
        self.active_runners = {}
        self.local_db = HeraclitusDB(db_path=self.db_path)

    def discover_assets(self, subnet: str) -> List[Dict[str, Any]]:
        """1. DISCOVERY ENGINE — varre a subrede (simulado) por emissores ativos."""
        print(f"=== [Heraclitus Fabric] Varredura Passiva na Subrede {subnet} ===")
        time.sleep(0.3)
        discovered = [
            {"ip": "10.0.4.12", "detected_fingerprint": "linux_sshd", "vendor": "Linux OS (OpenSSH)"},
            {"ip": "10.0.4.15", "detected_fingerprint": "postgresql", "vendor": "PostgreSQL Cluster"},
            {"ip": "10.0.4.88", "detected_fingerprint": "sigrh_custom", "vendor": "Proprietario (SIGRH)"},
        ]
        for asset in discovered:
            print(f"[+] Ativo -> IP: {asset['ip']:<12} | Assinatura: {asset['detected_fingerprint']}")
        return discovered

    def provision_asset(self, asset: Dict[str, Any], sample_data: str):
        """2-4. CONNECTIVITY + OKA ASSIGNMENT + RUNNER DEPLOYMENT."""
        fingerprint = asset["detected_fingerprint"]
        artifact_path = os.path.join(self.registry_dir, f"{fingerprint}.hcx")
        print(f"\n[*] Provisionando {asset['ip']} ({fingerprint})...")

        if not os.path.exists(artifact_path):
            print(f"[!] Artefato '{fingerprint}' ausente no Registry local.")
            print("[FORGE ACTIVE] Acionando esteira de IA para compilar conhecimento...")
            HeraclitusForgeCompiler(output_dir=self.registry_dir).compile_knowledge(
                artifact_id=fingerprint, vendor=asset["vendor"], sample_log=sample_data)

        print(f"[DEPLOY] Inicializando Runner dedicado para o IP {asset['ip']}...")
        runner = ReconstitutiveRunner(artifact_path=artifact_path)
        runner.compile_and_optimize()
        self.active_runners[asset["ip"]] = runner
        print(f"[OK] Ingestao ativada para {asset['ip']}.")

    def monitor_stream(self, asset_ip: str, raw_observation: str):
        """5-6. OBSERVE + SCHEMA DRIFT MONITOR."""
        runner = self.active_runners.get(asset_ip)
        if not runner:
            print(f"[!] Nenhum Runner ativo para {asset_ip}")
            return

        fact = runner.process_observation(raw_observation)
        if fact is None:
            print(f"[SCHEMA DRIFT] IP {asset_ip}: payload quebrou a validacao do "
                  f"artefato v{runner.manifest['version']}")
            print(f"   -> [QUARENTENA -> CKE] '{raw_observation[:60]}'")
            return

        lsn = self.local_db.write_fact(fact)
        b = fact["fact.behavior"]
        print(f"   -> {asset_ip} | LSN {lsn} | {b['action']} | class={b['class']} | risk={b['risk_level']}")


if __name__ == "__main__":
    for p in ("storage.hdb", "storage.hdb.anchor"):
        if os.path.exists(p):
            os.remove(p)

    fabric = HeraclitusFabric()
    assets = fabric.discover_assets(subnet="10.0.4.0/24")

    linux_sample = "<13> admin failed password for root from 187.4.5.1"
    pg_sample = '2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"'
    sigrh_sample = "USER=carlos_mgi ACTION=delete_record TARGET=table_benefits STATUS=failed"

    print("\n--- Provisionamento automatico (Segunda-Feira) ---")
    fabric.provision_asset(assets[0], sample_data=linux_sample)
    fabric.provision_asset(assets[1], sample_data=pg_sample)
    fabric.provision_asset(assets[2], sample_data=sigrh_sample)

    print("\n--- Trafego operacional: PostgreSQL sob brute force ---")
    for _ in range(6):
        fabric.monitor_stream("10.0.4.15", pg_sample)

    print("\n--- Teste de Schema Drift (fabricante mudou o formato do log) ---")
    fabric.monitor_stream("10.0.4.12",
                          "<13> TIME=2026-06-26 user=admin EVENT=auth_error platform_target=root")
