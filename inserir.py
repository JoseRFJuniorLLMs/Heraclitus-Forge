import heraclitusdb
import time
import random
from concurrent.futures import ThreadPoolExecutor

# Conecta globalmente (o canal gRPC do SDK é seguro para multi-threading)
db = heraclitusdb.connect("127.0.0.1:7474")

print("🚀 Conectado ao HeraclitusDB!")
print("Iniciando carga MULTI-THREAD de 2.000.000 de registos...")

TOTAL_REGISTOS = 20000000
NUM_THREADS = 16  # Número de tarefas paralelas (ajusta conforme os cores do teu CPU)
REGISTOS_POR_THREAD = TOTAL_REGISTOS // NUM_THREADS

# Listas para gerar dados simulados altamente realistas
acoes = ["authentication.success", "authentication.failure", "query.execute", "authorization.failure", "data.export"]
classes = ["session", "credential_attack", "data_access", "privilege_violation"]
riscos = ["Low", "Medium", "High", "Critical"]
alvos = ["postgresql-prod", "active-directory", "firewall-edge", "api-gateway"]
usuarios = ["admin", "root", "guest", "svc-backup", "user_test"]

# Função que cada Thread vai executar de forma independente e paralela
def carga_worker(worker_id, start_idx, end_idx):
    print(f"👷 Thread {worker_id} iniciada (Range: {start_idx:,} -> {end_idx:,})", flush=True)
    
    for i in range(start_idx, end_idx):
        ip_origem = f"187.54.12.{random.randint(1, 254)}"
        user = random.choice(usuarios)
        acao = random.choice(acoes)
        cls = random.choice(classes)
        risco = random.choice(riscos)
        alvo = random.choice(alvos)
        
        texto_log = f"User {user} triggered {acao} on target {alvo} from IP {ip_origem}"
        
        atributos = {
            "source_ip": ip_origem,
            "actor_name": user,
            "target_id": alvo,
            "risk_level": risco,
            "action_class": cls,
            "sequence_id": str(i),
            "system_timestamp": str(int(time.time() * 1000000))
        }
        
        # Envia para o banco de forma concorrente
        db.append("OperationalFact", texto_log, attrs=atributos)
        
        # Apenas a Thread 0 mostra progresso estimado para não poluir o ecrã
        if worker_id == 0 and i % 10000 == 0:
            progresso_thread = ((i - start_idx) / REGISTOS_POR_THREAD) * 100
            print(f"📊 Thread Mestra: {progresso_thread:.1f}% concluída...", flush=True)

start_time = time.time()

# Cria o pool de Threads para execução paralela real
with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
    for t_id in range(NUM_THREADS):
        inicio = (t_id * REGISTOS_POR_THREAD) + 1
        fim = inicio + REGISTOS_POR_THREAD
        
        # Dispara a thread de fundo
        executor.submit(carga_worker, t_id, inicio, fim)

duracao = time.time() - start_time
print(f"\n✅ CARGA PARALELA CONCLUÍDA!")
print(f"⚡ 2 milhões de registos processados em {duracao:.2f} segundos!")
print(f"🔥 Velocidade média: {TOTAL_REGISTOS / duracao:.0f} ops/sec")