# DTBLOCKER — DNS Threat Blocker & Sinkhole

Solução integrada de **DNS Sinkhole**, **Threat Intelligence** e **Deteção de DGAs via Machine Learning**, concebida para intercetar tráfego malicioso em redes locais e fornecer telemetria em tempo real para analistas de segurança (SOC).


O sistema combina a resolução recursiva do **Unbound DNS** com uma camada web em **FastAPI** e base de dados **SQLite em modo WAL**  Consultas DNS para domínios maliciosos conhecidos ou gerados por algoritmos são redirecionadas para o IP da VM, apresentando uma página de bloqueio ao utilizador e registando auditoria detalhada no dashboard `/admin`.

---

## 🚀 Instalação Rápida

### Pré-requisitos
- **SO:** Linux (Ubuntu 22.04 / 24.04 recomendado)
- **Python:** 3.9 ou superior
- **Serviços:** `unbound` (`sudo apt install unbound`)

### Passos de Instalação

```bash
# 1. Aceder à diretoria do projeto
cd /home/pserver/dnsthreat

# 2. Criar e ativar o ambiente virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependências
pip install -r requirements.txt
```

---

## 💻 Como Usar a Ferramenta via Consola

Toda a gestão operacional é feita através do menu interativo `console.py`:

```bash
python3 console.py
```

```text
▀▀▀▀██▄ ███     ███     ███                     ███                    
███ ███ ███     ███     ███                     ███                    
███ ███ ███▄▄   ███     ███                     ███                    
███ ███ ███     ███▀██▄ ███     ▄██▀██▄ ▄██▀██▄ ███ ███ ▄██▀██▄ ▄██▀██▄
███ ███ ███     ███ ███ ███     ███ ███ ███ ███ ███ ███ ███ ███ ███ ███
███ ███ ███     ███ ███ ███     ███ ███ ███ ▀▀▀ ███▀██▄ ███▀▀▀▀ ███    
███ ███ ███ ▄▄▄ ███ ███ ███ ▄▄▄ ███ ███ ███ ███ ███ ███ ███ ███ ███    
███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███    
███▄██▀ ▀██▄██▀ ███▄██▀ ▀██▄██▀ ▀██▄██▀ ▀██▄██▀ ███ ███ ▀██▄██▀ ███    

╭────────────────────── ● DEFENSE ENGINE ACTIVE ● ──────────────────────╮
│ Host: pserver | Sinkhole IP: 192.168.1.102 | Data UTC: 2026-11-23 ... │
╰───────────────────────────────────────────────────────────────────────╯

                           MENU DE OPERAÇÕES                             
┌───────────┬───────────────────────────────────────────────────────────┐
│   Opção   │ Ação                                                      │
├───────────┼───────────────────────────────────────────────────────────┤
│    [1]    │ Iniciar servidor                                          │
│    [2]    │ Sincronizar Feeds de Ameaças                              │
│    [3]    │ Reiniciar Unbound DNS                                     │
│    [5]    │ Atualizar IP do Sinkhole                                  │
│    [6]    │ Sair da Consola                                           │
└───────────┴───────────────────────────────────────────────────────────┘
```

### Descrição das Opções

- **[1] Iniciar servidor:**
  Inicia a aplicação FastAPI via Uvicorn nas portas privilegiadas. Permite escolher entre:
  - **HTTPS (Porta 443):** Modo recomendado com suporte TLS (gera certificados autoassinados em `certs/` se não existirem).
  - **HTTP (Porta 80):** Modo de compatibilidade legado.
  - Aceder ao painel SOC: `http://<IP_DA_VM>/admin` ou `https://<IP_DA_VM>/admin`.

- **[2] Sincronizar Feeds de Ameaças:**
  Executa `sync_iocs.py` com privilégios `sudo`. Descarrega feeds públicos de Threat Intelligence (URLhaus, ThreatFox, AlienVault OTX, Feodo Tracker), normaliza os domínios, remove entradas da allowlist, atualiza a base SQLite e recarrega o Unbound.

- **[3] Reiniciar Unbound DNS:**
  Executa `sudo systemctl restart unbound` após validação sintática das regras (`unbound-checkconf`).

- **[4] Agente de Machine Learning / Extractor:**
  Módulo de triagem e inteligência artificial para análise de indicadores:
  1. *Analisar Texto / Indicadores:* Extrai domínios de relatórios desarmados (ex: `hxxps://evil[.]top`), filtra falsos positivos pela allowlist e calcula o score de risco DGA.
  2. *Processar Ficheiro:* Processa ficheiros de logs ou listas de domínios em lote.
  3. *Classificar Domínio Único:* Calcula a entropia de Shannon (bits), proporção de consoantes, padrões hexadecimais e emite veredito (`BENIGN`, `SUSPICIOUS`, `HIGH_RISK_DGA`).
  4. *Ver Allowlist:* Lista os domínios confiáveis carregados em memória (`data/allowlist.txt`).

- **[5] Atualizar IP do Sinkhole:**
  Modo rápido (`sync_iocs.py --refresh-ip`). Deteta dinamicamente o novo endereço IP da interface ativa (útil após troca de rede Wi-Fi/Ethernet), reescreve as entradas A e AAAA no Unbound e recarrega o serviço sem precisar de re-descarregar os feeds.

- **[6] Sair da Consola:**
  Encerra subprocessos ativos em segurança e liberta portas e recursos do sistema.

---

## 📖 Documentação Detalhada

Para uma visão aprofundada da arquitetura de rede, engenharia do classificador ML, esquemas de bases de dados SQLite e procedimentos de resposta a incidentes, consulta o documento:
👉 **[DOCUMENTATION.md](DOCUMENTATION.md)**

---

## 🧪 Execução de Testes Automatizados

```bash
# Executar todos os testes com pytest
pytest tests/ -v
```
