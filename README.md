# SOC-Log-Analysis

[English Version](#english) | [Versão em Português](#português)

# Português

Este é um projeto de análise de logs de segurança para SOC (Security Operations Center), desenvolvido para auxiliar na identificação e análise de diferentes tipos de eventos de segurança, como tentativas de login, alterações de privilégios e atividades suspeitas.

## 📊 Funcionalidades

- Análise detalhada de logs de segurança
- Detecção de tentativas de login (bem-sucedidas e falhas)
- Monitoramento de alterações de privilégios
- Geração de relatórios e alertas personalizados
- Análise de atividades dentro e fora do horário comercial

## 🔧 Estrutura do Projeto

```
SOC-Log-Analysis/
├── logs/                      # Diretório de logs
│   ├── alerts_failed_login.csv
│   ├── alerts_privilege_change.csv
│   ├── alerts_successful_login.csv
│   ├── alerts_summary.csv
│   └── security_logs.csv
├── scripts/                   # Scripts de análise
│   ├── alert.py              # Sistema de alertas
│   ├── analyze_logs.py       # Análise principal de logs
│   └── create_fake_logs.py   # Gerador de logs para testes
└── requirements.txt          # Dependências do projeto
```

## 📋 Pré-requisitos

- Python 3.x
- pandas

## ⚙️ Instalação

1. Clone o repositório:

```bash
git clone https://github.com/matheusmnk/SOC-Log-Analysis.git
cd SOC-Log-Analysis
```

2. Instale as dependências:

```bash
pip install -r requirements.txt
```

## 🚀 Como Usar

1. Para gerar logs de teste (se necessário):

```bash
python scripts/create_fake_logs.py
```

2. Para executar a análise dos logs:

```bash
python scripts/analyze_logs.py
```

3. Os resultados serão salvos na pasta `logs/` em diferentes arquivos CSV.

## 📈 Arquivos de Saída

- `alerts_failed_login.csv`: Registro de tentativas de login mal-sucedidas
- `alerts_privilege_change.csv`: Registro de alterações de privilégios
- `alerts_successful_login.csv`: Registro de logins bem-sucedidos
- `alerts_summary.csv`: Resumo geral dos alertas gerados

## ⚙️ Configurações

O script principal (`analyze_logs.py`) possui configurações para:

- Definição de horário comercial (padrão: 06h às 22h)
- Caminhos dos arquivos de log
- Parâmetros de análise personalizáveis

## 🤝 Como Contribuir

Sua contribuição é bem-vinda! Para contribuir:

1. Faça um Fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Faça commit das alterações (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abra um Pull Request

## ✨ Autor

Matheus da Rocha - [@matheusmnk](https://github.com/matheusmnk)

---

# English

This is a security log analysis tool for SOC (Security Operations Center), designed to help identify and analyze different types of security events, such as login attempts, privilege changes, and suspicious activities.

## 📊 Features

- Detailed security log analysis
- Detection of login attempts (successful and failed)
- Privilege change monitoring
- Custom reports and alerts generation
- Business hours and after-hours activity analysis

## 🔧 Project Structure

```
SOC-Log-Analysis/
├── logs/                      # Logs directory
│   ├── alerts_failed_login.csv
│   ├── alerts_privilege_change.csv
│   ├── alerts_successful_login.csv
│   ├── alerts_summary.csv
│   └── security_logs.csv
├── scripts/                   # Analysis scripts
│   ├── alert.py              # Alert system
│   ├── analyze_logs.py       # Main log analysis
│   └── create_fake_logs.py   # Test log generator
└── requirements.txt          # Project dependencies
```

## 📋 Prerequisites

- Python 3.x
- pandas

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/matheusmnk/SOC-Log-Analysis.git
cd SOC-Log-Analysis
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## 🚀 How to Use

1. To generate test logs (if needed):

```bash
python scripts/create_fake_logs.py
```

2. To run the log analysis:

```bash
python scripts/analyze_logs.py
```

3. Results will be saved in the `logs/` folder in different CSV files.

## 📈 Output Files

- `alerts_failed_login.csv`: Failed login attempt records
- `alerts_privilege_change.csv`: Privilege change records
- `alerts_successful_login.csv`: Successful login records
- `alerts_summary.csv`: General alert summary

## ⚙️ Configuration

The main script (`analyze_logs.py`) includes configurations for:

- Business hours definition (default: 06h to 22h)
- Log file paths
- Customizable analysis parameters

## 🤝 How to Contribute

Your contribution is welcome! To contribute:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

## ✨ Author

Matheus da Rocha - [@matheusmnk](https://github.com/matheusmnk)

---

⭐️ If this project helped you, please consider giving it a star!
