# DNS Threat Blocker & Sinkhole Telemetry

Solução integrada de **DNS Sinkhole** e **Threat Intelligence **, desenvolvida com **FastAPI**, **Unbound DNS** e **SQLite (WAL mode)** para intercetar tráfego malicioso na rede interna e fornecer telemetria em tempo real para analistas de SOC.

---

## 📋 Pré-requisitos

- **Sistema Operacional:** Linux (Ubuntu/Debian recomendado para Unbound) ou compatível
- **Python:** 3.9+
- **Serviços:** `unbound` (opcional em ambiente local de desenvolvimento, obrigatório em produção)
- **Ferramentas:** `openssl`, `git`

---

## 🚀 Instalação e Preparação

### 1. Clonar o repositório e aceder à pasta do projeto
```bash
cd /home/pserver/dnsthreat
```

### 2. Criar e ativar o ambiente virtual (venv)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar as dependências
```bash
pip install -r requirements.txt
```

---

## 💻 Consola Interativa de Gestão (CLI)

O projeto dispõe de uma consola interativa centralizada (`console.py`) com banner ASCII hacker e menu SecOps para gerir todas as operações num único ponto:

```bash
python3 console.py
```

**Menu de Opções Disponíveis:**
- **[1] Iniciar Servidor Web:** Arranca o Uvicorn com suporte interativo a **HTTPS (Porta 443 com SSL/TLS)** ou **HTTP (Porta 80)**, com auto-geração de certificados caso estejam em falta.
- **[2] Sincronizar Feeds de Ameaças:** Executa a ingestão de IoCs (`sudo python3 sync_iocs.py`).
- **[3] Reiniciar Unbound DNS:** Reinicia o serviço DNS do sistema (`sudo systemctl restart unbound`).
- **[4] Iniciar Agente de Machine Learning:** Alerta para módulo IA heurístico em desenvolvimento.
- **[5] Atualizar IP do Sinkhole:** Reescreve o IP atual no `threat_feed.conf` e reinicia o Unbound (`sudo python3 sync_iocs.py --refresh-ip`).
- **[6] Sair:** Encerramento seguro da consola e limpeza de processos.

---

## 🔒 Geração e Gestão Centralizada de Certificados SSL (HTTPS)

O projeto gere os caminhos SSL/TLS dinamicamente através de `app/config.py` (relativo à raiz do projeto em `certs/` ou configurável via variáveis de ambiente `SSL_KEYFILE` e `SSL_CERTFILE`):

```bash
# Geração manual via terminal:
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/sinkhole.key \
  -out certs/sinkhole.crt \
  -subj "/C=PT/ST=SecOps/L=SOC/O=DNS-Threat-Sinkhole/CN=sinkhole.local" \
  -addext "subjectAltName=DNS:*,DNS:sinkhole.local"
chmod 600 certs/sinkhole.key
chmod 644 certs/sinkhole.crt

# Ou geração automática em 1 clique via console.py (Opção 1) ou run_sinkhole.py:
sudo python3 run_sinkhole.py --generate-cert
```

---

## ⚙️ Sincronização de Threat Intelligence (IoCs)

O script `sync_iocs.py` descarrega feeds abertos de segurança (URLhaus, ThreatFox, AlienVault OTX, Feodo Tracker, etc.), popula a base de dados SQLite e gera o ficheiro de configuração do Unbound (`threat_feed.conf`).

```bash
# Execução padrão (descarrega IoCs, atualiza a BD e gera a config do Unbound)
sudo python3 sync_iocs.py

# Modo de simulação (não grava na BD nem altera o Unbound)
sudo python3 sync_iocs.py --dry-run

# Modo verboso para depuração
sudo python3 sync_iocs.py --verbose
```

---

## 🌐 Como Executar o Servidor Web (FastAPI / Uvicorn)

### Opção 1: Ambiente de Produção / Sinkhole Real (Portas Privilegiadas)

Como as portas `80` e `443` são privilégios de sistema no Linux, executa com `sudo` apontando para o binário do ambiente virtual:

#### Em HTTP (Porta 80):
```bash
sudo ./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 80
```

#### Em HTTPS (Porta 443 com SSL):
```bash
sudo ./venv/bin/uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile certs/sinkhole.key \
  --ssl-certfile certs/sinkhole.crt
```

---

### Opção 2: Ambiente de Desenvolvimento Local (Porta 8000, sem root)

Ideal para testar o painel administrativo, templates e rotas sem necessidade de privilégios de administrador:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🧪 Executar os Testes Automatizados

Para rodar a suite completa de testes de unidade e integração:

```bash
pytest
```

---

## 📍 Endpoints e Acessos

| Endpoint | Descrição |
| :--- | :--- |
| `http://<IP-SINKHOLE>/admin` | **SOC Telemetry Dashboard** (métricas de bloqueios, Top 5 IoCs e logs de auditoria). |
| `http://<IP-SINKHOLE>/api/stats` | **API JSON** com estatísticas em tempo real para automações e SIEM. |
| `http://<IP-SINKHOLE>/health` | Endpoint de verificação de integridade (*Health Check*). |
| `http://<IP-SINKHOLE>/*` | **Catch-All Sinkhole**: Qualquer rota/domínio intercetado apresenta a página de alerta `user_blocked.html` e grava o incidente. |

---

## 🔍 Como Testar o Sinkhole

### 1. Testar resolução DNS com Unbound ativo:
```bash
nslookup phish-banking-login.top 127.0.0.1
# Deve devolver o IP do Sinkhole (ex: 10.0.2.15)
```

### 2. Testar captura web simulando o cabeçalho `Host`:
```bash
# Teste via HTTP:
curl -H "Host: malicious-stealer.xyz" http://127.0.0.1:8000/login.php

# Teste via HTTPS:
curl -k -H "Host: malicious-stealer.xyz" https://127.0.0.1:443/payload.exe
```
