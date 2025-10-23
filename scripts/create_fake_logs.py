import csv
import random
import sys
from datetime import datetime, timedelta
import os

"""Gerador de logs de teste para `SOC-Log-Analysis`.

Gera um CSV em `logs/security_logs.csv` contendo duas colunas: `Timestamp`
e `Event`. Permite controlar a quantidade total de eventos e a porcentagem
de eventos "maliciosos" para simular ruído e incidentes.

Documentação em Português (PT-BR). English: test log generator.

Uso: python scripts/create_fake_logs.py [count] [malicious_percent] [seed]
"""

# ---------------------------
# Configurações padrão
# ---------------------------
DEFAULT_COUNT = 50
DEFAULT_MALICIOUS_PERCENT = 5.0   # % de eventos maliciosos
OUTPUT_DIR = "logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "security_logs.csv")
ENCODING = "cp1252"

# Usuários fictícios
USERS = [
    "João", "Maria", "Carlos", "Ana", "Pedro", "Luiza", "Miguel",
    "Rafael", "Pedro", "Carol", "Matheus", "Natalia", "Roberto", "Thais"
]

# Templates benignos (ruído)
BENIGN_TEMPLATES = [
    "User {user} checked mailbox at {time}",
    "Scheduled backup completed on host {ip} at {time}",
    "Service apache started on {ip} at {time}",
    "User {user} opened file report.docx at {time}",
    "Connection established from {ip} to service port 80 at {time}",
    "User {user} logon successful at {time}",
    "User {user} logon successful from IP {ip} at {time}",
    "Sistema iniciou serviço de atualização às {time}",
    "Usuário {user} acessou a intranet às {time}",
    "Health check OK for service on {ip} at {time}"
]

# Templates maliciosos
MALICIOUS_TEMPLATES = [
    "User {user} failed login at {time}",
    "Failed login attempt detected from IP {ip}",
    "Failed login for {user} from {ip}",
    "Privilege escalation detected for user {user}",
    "Admin privilege change for user {user}",
    "Brute force detected: multiple failed logins from {ip}",
    "Login inválido do usuário {user} às {time}",
    "Tentativa de login falha detectada do IP {ip}",
    "Escalação de privilégio detectada para o usuário {user}",
    "Alteração de privilégio não autorizada para {user}"
]

# ---------------------------
# Funções utilitárias
# ---------------------------
def random_ip():
    """Gera IPs internos e externos misturados."""
    if random.random() < 0.6:
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return f"{random.randint(11,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_time(days_back=14):
    """Gera um horário aleatório nos últimos X dias."""
    now = datetime.now()
    delta = timedelta(seconds=random.randint(0, days_back * 24 * 3600))
    t = now - delta
    return t

def generate_one_event(is_malicious):
    """Gera um evento único com timestamp e texto."""
    tpl = random.choice(MALICIOUS_TEMPLATES if is_malicious else BENIGN_TEMPLATES)
    user = random.choice(USERS)
    ip = random_ip()
    timestamp = random_time(days_back=14)
    event_text = tpl.format(user=user, ip=ip, time=timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    return timestamp, event_text

def generate_events(total_count, malicious_percent):
    """Gera lista de (timestamp, evento) com mistura de benignos e maliciosos."""
    events = []
    malicious_count = int(total_count * (malicious_percent / 100.0))
    benign_count = total_count - malicious_count

    for _ in range(benign_count):
        events.append((False, *generate_one_event(False)))
    for _ in range(malicious_count):
        events.append((True, *generate_one_event(True)))

    random.shuffle(events)
    return events

# ---------------------------
# Entrada / validação
# ---------------------------
try:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_COUNT
    malicious_percent = float(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_MALICIOUS_PERCENT
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else None

    if count <= 0 or not (0 <= malicious_percent <= 100):
        raise ValueError
except ValueError:
    # Mensagem de uso corrigida para o nome do script correto
    print("Uso: python scripts/create_fake_logs.py [count:int>0] [malicious_percent:0-100] [seed:int]")
    sys.exit(1)

if seed is not None:
    random.seed(seed)

# Cria pasta logs
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------
# Gera e grava logs
# ---------------------------
events = generate_events(count, malicious_percent)
malicious_generated = sum(1 for e in events if e[0])

with open(OUTPUT_FILE, "w", newline="", encoding=ENCODING) as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Event"])  # agora tem duas colunas!
    for _, timestamp, event_text in events:
        writer.writerow([timestamp.strftime("%Y-%m-%d %H:%M:%S"), event_text])

# ---------------------------
# Resumo
# ---------------------------
print(f"✅ {count} eventos gerados em: {OUTPUT_FILE} (encoding={ENCODING})")
print(f"   • Maliciosos esperados: {malicious_generated} ({malicious_percent}%)")
print(f"   • Benignos esperados: {count - malicious_generated}")