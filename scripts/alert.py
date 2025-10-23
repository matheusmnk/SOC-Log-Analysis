import pandas as pd
import os
from datetime import datetime

"""Módulo de alertas simples para análise rápida de `logs/security_logs.csv`.

Este script lê o CSV de logs, procura por palavras-chave que indiquem
eventos relevantes (logins bem-sucedidos/falhos, alteração de privilégios)
e imprime um resumo na saída padrão. Também identifica eventos fora do
horário comercial configurado.

Documentação breve (PT-BR). English: simple alerting script for quick
analysis of the security_logs.csv file.

Uso: python scripts/alert.py

Saída: mensagens formatadas no console e arquivos de log gerados pelo
`analyze_logs.py` (se usado em conjunto).
"""

# ---------------------------
# Configurações
# ---------------------------
LOG_FILE = "logs/security_logs.csv"
WORK_START = 6   # 06h
WORK_END = 22    # 22h

# ---------------------------
# Verifica se o arquivo existe
# ---------------------------
if not os.path.exists(LOG_FILE):
    # Mensagem de ajuda ao usuário — indica o script correto para gerar logs de teste
    print(f"❌ Arquivo de logs não encontrado em {LOG_FILE}. Rode create_fake_logs.py primeiro.")
    exit(1)

# ---------------------------
# Lê CSV
# ---------------------------
logs = pd.read_csv(LOG_FILE, encoding='cp1252')

# Garante tipos corretos
logs['Event'] = logs['Event'].astype(str)

# Converte timestamp (ajuste o nome da coluna se necessário)
if 'Timestamp' in logs.columns:
    logs['Timestamp'] = pd.to_datetime(logs['Timestamp'], errors='coerce')
else:
    print("⚠️  Coluna 'Timestamp' não encontrada. Ignorando análise de horários.")
    logs['Timestamp'] = pd.NaT

# ---------------------------
# Palavras-chave para detectar alertas
# ---------------------------
keywords = {
    'successful_login': ['logon successful', 'login bem-sucedido'],
    'failed_login': ['failed login', 'tentativa de login', 'login inválido'],
    'privilege_change': ['privilege', 'privilégio', 'admin']
}

# ---------------------------
# Detecta e imprime alertas
# ---------------------------
print("\n================ ALERTAS AUTOMÁTICOS ================\n")

for category, words in keywords.items():
    # Filtra eventos da categoria
    mask = logs['Event'].str.contains('|'.join(words), case=False)
    filtered = logs[mask]

    if not filtered.empty:
        print(f"⚠️  Categoria: {category}")
        print(f"    Total de eventos: {len(filtered)}")
        # Exibe até 10 eventos
        for i, event in enumerate(filtered['Event'].head(10)):
            print(f"      - {event}")
        if len(filtered) > 10:
            print(f"      ... e mais {len(filtered) - 10} eventos\n")
        else:
            print("")
    else:
        print(f"✅ Categoria: {category} — nenhum evento suspeito encontrado.\n")

# ---------------------------
# Detecta eventos fora de horário
# ---------------------------
if 'Timestamp' in logs.columns and logs['Timestamp'].notna().any():
    logs['Hour'] = logs['Timestamp'].dt.hour
    suspicious_hours = logs[(logs['Hour'] < WORK_START) | (logs['Hour'] > WORK_END)]

    if not suspicious_hours.empty:
        print("⚠️  Categoria: atividade fora de horário")
        print(f"    Total de eventos fora do horário comercial: {len(suspicious_hours)}")
        for i, row in suspicious_hours.head(10).iterrows():
            ts = row['Timestamp'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['Timestamp']) else "sem horário"
            print(f"      - {ts} | {row['Event']}")
        if len(suspicious_hours) > 10:
            print(f"      ... e mais {len(suspicious_hours) - 10} eventos\n")
        else:
            print("")
    else:
        print("✅ Nenhuma atividade fora do horário comercial detectada.\n")

print("================ FIM DOS ALERTAS ===================\n")
