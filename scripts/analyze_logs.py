import pandas as pd
import os
import re
from datetime import datetime

"""Script principal de análise de logs.

Lê `logs/security_logs.csv`, tenta extrair timestamps embutidos nas mensagens
de evento, classifica eventos por palavras-chave (login bem-sucedido, falho,
alteração de privilégios) e gera relatórios CSV resumidos e por categoria.

Documentação em Português (PT-BR). English: main log analysis script.

Uso: python scripts/analyze_logs.py
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
    print(f"❌ Arquivo de logs não encontrado em {LOG_FILE}. Rode create_logs.py primeiro.")
    exit(1)

# ---------------------------
# Lê CSV
# ---------------------------
logs = pd.read_csv(LOG_FILE, encoding='cp1252')
logs['Event'] = logs['Event'].astype(str)

# ---------------------------
# Extrai timestamp do texto do evento
# ---------------------------
def extract_timestamp(event_str):
    """Tenta extrair um timestamp no formato YYYY-MM-DD HH:MM:SS do texto do evento.

    Retorna um pandas.Timestamp quando encontra correspondência, caso contrário
    retorna pd.NaT. Esta função é deliberadamente tolerante: usa `errors='coerce'`
    indiretamente (via pandas) quando a conversão falha.

    Args:
        event_str (str): Texto do evento que pode conter um timestamp.

    Returns:
        pandas.Timestamp | pandas.NaT
    """
    match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', event_str)
    if match:
        return pd.to_datetime(match.group(), format="%Y-%m-%d %H:%M:%S")
    else:
        return pd.NaT

logs['Timestamp'] = logs['Event'].apply(extract_timestamp)

# ---------------------------
# Palavras-chave para detectar alertas
# ---------------------------
keywords = {
    'successful_login': ['logon successful', 'login bem-sucedido'],
    'failed_login': ['failed login', 'tentativa de login', 'login inválido'],
    'privilege_change': ['privilege', 'privilégio', 'admin']
}

# ---------------------------
# Detecta alertas
# ---------------------------
alerts = {}
for category, words in keywords.items():
    mask = logs['Event'].str.contains('|'.join(words), case=False)
    alerts[category] = logs[mask]

# ---------------------------
# Criar relatório resumido
# ---------------------------
report_file = "logs/alerts_summary.csv"
with open(report_file, "w", encoding="utf-8") as f:
    f.write("Category,Count\n")
    for category, df in alerts.items():
        f.write(f"{category},{len(df)}\n")
print(f"📊 Resumo de alertas gerado em: {report_file}")

# Salvar arquivos detalhados por categoria
for category, df in alerts.items():
    if not df.empty:
        output_file = f"logs/alerts_{category}.csv"
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"{len(df)} eventos encontrados em {category}, salvos em {output_file}")
    else:
        print(f"✅ Nenhum evento encontrado em {category}")

# ---------------------------
# Detecta atividades fora de horário
# ---------------------------
if logs['Timestamp'].notna().any():
    logs['Hour'] = logs['Timestamp'].dt.hour
    suspicious_hours = logs[(logs['Hour'] < WORK_START) | (logs['Hour'] >= WORK_END)]
    
    if not suspicious_hours.empty:
        print(f"{len(suspicious_hours)} eventos fora do horário comercial (06h-22h) detectados:")
    else:
        print("\n✅ Nenhum evento fora do horário comercial detectado.")
