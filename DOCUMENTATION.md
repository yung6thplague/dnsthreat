# Documentação Técnica e Arquitetura do Sistema: dtblocker

Esta documentação descreve a arquitetura interna, o modelo de dados, o fluxo de rede, os algoritmos de machine learning e os procedimentos operacionais do projeto **dtblocker** (DNS Threat Blocker & Sinkhole).

---

## 1. Visão Geral da Arquitetura

O **dtblocker** é uma infraestrutura de defesa ativa em rede projetada para neutralizar comunicações maliciosas (Command & Control, phishing, distribuição de malware e domínios gerados por DGA) através de envenenamento controlado de DNS (*DNS Sinkholing*).

```
                      [ CLIENTE / VÍTIMA ]
                               │
            1. Consulta DNS    │ (ex: evil-c2-domain.top)
            ───────────────────┼───────────────────►
                               ▼
                       [ UNBOUND DNS ]
                        (Porta 53/UDP)
                               │
               ¿Domínio está em threat_feed.conf?
                    │                     │
                   SIM                   NÃO
                    ▼                     ▼
          2. Resposta Envenenada    2. Resolução Recursiva
             IP da VM Sinkhole         Servidores Raiz
             (192.168.1.102)                 │
                    │                        ▼
                    ▼                 IP Legítimo na Internet
          3. Tráfego HTTP/HTTPS
             Redirecionado para Sinkhole
                    │
                    ▼
          [ FASTAPI / UVICORN ]
          (Portas 80/TCP e 443/TCP)
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
  [ SQLite WAL ]       [ PÁGINA DE BLOQUEIO ]
 (access_logs &        (user_blocked.html com
   ioc_entries)         telemetria do incidente)
         │
         ▼
  [ SOC DASHBOARD ]
    (/admin Web UI)
```

### Componentes Principais

1. **DNS Engine (Unbound DNS):** Servidor DNS recursivo configurado com diretivas `local-zone` e `local-data` que forçam o encaminhamento de FQDNs maliciosos para a interface do Sinkhole.
2. **Camada Web (FastAPI + Uvicorn):** Servidor HTTP/HTTPS com suporte a portas privilegiadas (80 e 443) que interceta pedidos web, regista metadados forenses e apresenta uma página de aviso de bloqueio.
3. **Camada de Persistência (SQLite em modo WAL):** Base de dados otimizada para alta concorrência com registo de telemetria de acessos e tabela mestre de IoCs.
4. **Pipeline de Threat Intelligence (`sync_iocs.py`):** Ingestão, desofuscação e normalização automatizada de indicadores de compromisso de múltiplos feeds OSINT abertos.
5. **Módulo de Machine Learning & DGA Detection (`agent/`):** Motor de extração de características léxicas, cálculo de entropia de Shannon e classificação heurística de domínios pseudoaleatórios.
6. **Consola Central de Operações (`console.py`):** Interface CLI interativa para gestão unificada dos serviços, recarregamento de regras e triagem em linha de comandos.

---

## 2. Infraestrutura de Rede e DNS Sinkhole

### 2.1 Resolução Dual-Stack Dinâmica (IPv4 e IPv6)
Para evitar que o tráfego malicioso contorne o Sinkhole através de consultas AAAA (IPv6), o sistema implementa deteção dinâmica e gera registos para ambos os protocolos:

- **Deteção IPv4 (`get_local_ip`):** Cria um socket UDP não conexional apontado para `8.8.8.8:80`. Não transmite pacotes na rede; apenas força a tabela de encaminhamento do kernel a selecionar a interface primária ativa (Wi-Fi ou Ethernet), obtendo o IP local sem dependências de comandos externos ou interfaces fixas.
- **Deteção IPv6 (`get_local_ipv6`):** Efetua o mesmo procedimento com `2001:4860:4860::8888:80`, descartando endereços locais de ligação (`fe80::/10`) e loopback (`::1`), priorizando endereços globais roteáveis (GUA ou ULA).
- **Fallback Seguro:** Caso a interface ativa não disponha de IPv6 público, as consultas AAAA para domínios bloqueados são mapeadas para o endereço nulo `::` (*unspecified address*), impedindo a fuga de resolução para o IP real do atacante.

### 2.2 Estrutura de Regras no Unbound
O ficheiro gerado em `/etc/unbound/unbound.conf.d/threat_feed.conf` adota uma sintaxe rigorosa validada previamente com `unbound-checkconf`:

```text
server:
    # Domínio bloqueado redirecionado para o Sinkhole
    local-zone: "malware-traffic-dist.xyz" redirect
    local-data: "malware-traffic-dist.xyz A 192.168.1.102"
    local-data: "malware-traffic-dist.xyz AAAA 2001:db8::102"

    local-zone: "c2-beacon.darknet-command.ru" redirect
    local-data: "c2-beacon.darknet-command.ru A 192.168.1.102"
    local-data: "c2-beacon.darknet-command.ru AAAA ::"
```

A diretiva `redirect` garante que tanto o domínio exato como qualquer subdomínio não mapeado (ex: `gate.c2-beacon.darknet-command.ru`) sejam direcionados para o Sinkhole.

### 2.3 Atualização Rápida de IP (`--refresh-ip`)
Quando a máquina virtual muda de rede (por exemplo, transição entre diferentes pontos de acesso Wi-Fi ou sub-redes DHCP):
```bash
sudo python3 sync_iocs.py --refresh-ip
```
Este modo lê o ficheiro `threat_feed.conf` existente, substitui os endereços IP antigos pelos recém-detetados através de expressões regulares, valida a integridade com `unbound-checkconf` e executa o recarregamento do daemon com `unbound-control reload` em menos de 1 segundo, sem necessidade de transferir feeds externos.

---

## 3. Pipeline de Ingestão de Threat Intelligence

O script `sync_iocs.py` orquestra a recolha de inteligência sobre ameaças a partir de feeds reputados:

| Fonte | Tipo de Indicador | Formato |
| :--- | :--- | :--- |
| **URLhaus (Abuse.ch)** | URLs e domínios de distribuição de malware | CSV / Texto |
| **ThreatFox (Abuse.ch)** | Indicadores C2 e hashes | JSON / CSV |
| **AlienVault OTX** | Domínios maliciosos em campanhas ativas | API / Texto |
| **Feodo Tracker** | Botnets bancárias e nós C2 Dridex/Emotet | Lista de IPs/Domínios |

### 3.1 Normalização e Validação Sintática (`agent/extractor.py`)
Antes de serem considerados para bloqueio, os dados em bruto passam pelas seguintes fases:
1. **Desofuscação (*Defang*):** Converte formatos desarmados comuns em relatórios SOC (`hxxp://`, `hxxps://`, `[.]`, `(dot)`, `{dot}`) em URLs e FQDNs padrão.
2. **Validação de FQDN:** Valida se o candidato cumpre o RFC 1035 (comprimento de rótulo entre 1 e 63 carateres, carateres alfanuméricos e hífens não terminais, TLD válido, rejeitando endereços IP puros).
3. **Filtragem por Allowlist:** Compara cada domínio contra a lista branca local (`data/allowlist.txt`) e listas de tráfego popular (como o Top 10K Tranco/Umbrella). Se o domínio for legítimo (ex: `google.com`, `microsoft.com`, `gov.pt`), é descartado imediatamente, evitando a interrupção de serviços críticos na rede interna.

### 3.2 Persistência e Atualização Atómica
Os domínios válidos são inseridos na tabela `ioc_entries` da base de dados através de `INSERT OR IGNORE`, garantindo idempotência e preservando a data da primeira identificação.

---

## 4. Camada Web e Persistência de Dados (FastAPI & SQLite WAL)

### 4.1 Modelo de Dados e Concorrência SQLite WAL
O sistema utiliza SQLite nativo configurado para alto débito concorrente:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
```
O modo **WAL (Write-Ahead Logging)** permite que leituras (ex: consultas concorrentes do dashboard `/admin`) e escritas (ex: registo instantâneo de interceções via rota catch-all) ocorram em paralelo sem bloqueios de base de dados.

#### Esquema de Tabelas:
- **`access_logs`:**
  - `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
  - `domain_requested` (TEXT NOT NULL) — FQDN extraído do cabeçalho HTTP `Host`.
  - `client_ip` (TEXT NOT NULL) — Endereço IP do dispositivo comprometido na LAN.
  - `user_agent` (TEXT) — Assinatura da aplicação/browser que originou o pedido.
  - `timestamp` (DATETIME DEFAULT CURRENT_TIMESTAMP) — Data e hora UTC da tentativa.
- **`ioc_entries`:**
  - `domain` (TEXT PRIMARY KEY) — Indicador único bloqueado.
  - `status` (TEXT DEFAULT 'blocked') — Estado operacional (`blocked`, `whitelisted`).
  - `category` (TEXT) — Tipologia da ameaça (ex: `C2 Infrastructure`, `Phishing`).
  - `created_at` (DATETIME DEFAULT CURRENT_TIMESTAMP) — Data de ingestão.

### 4.2 Interceção Catch-All e Landing Page
Qualquer requisição HTTP/HTTPS direcionada para o Sinkhole é intercetada pela rota genérica `/{path:path}`:
1. Extrai o cabeçalho `Host` e o IP de origem (considerando cabeçalhos `X-Forwarded-For` ou ligação socket direta).
2. Regista o evento em `access_logs`.
3. Retorna a página visual `user_blocked.html` com código de estado `200 OK`, informando o utilizador sobre o bloqueio por razões de segurança corporativa e fornecendo o ID do incidente para suporte do SOC.

### 4.3 Endpoints da API REST
- `GET /health`: Monitorização de integridade para watchdogs.
- `GET /admin`: Dashboard web com métricas em tempo real, Top 5 IoCs mais acedidos e tabela de auditoria.
- `GET /api/stats`: Telemetria em formato JSON consumida assincronamente pelo frontend.
- `GET /api/iocs`: Listagem paginada e filtrável da base de ameaças.
- `POST /api/ioc/unblock`: Desbloqueio e rollback atómico de falsos positivos (remove de `ioc_entries` e insere na allowlist permanente).
- `POST /api/ml/analyze`: Submissão de domínios para inferência em tempo real pelo classificador de DGA.

---

## 5. Módulo de Inteligência Artificial: Classificador de DGA (`agent/classifier.py`)

Muitas estirpes de malware modernas utilizam **DGA (Domain Generation Algorithms)** para gerar centenas de nomes de domínio pseudoaleatórios diariamente para comunicação com os servidores C2, contornando listas de bloqueio estáticas.

O módulo `agent/classifier.py` implementa um motor heurístico e estatístico projetado para analisar nomes de domínio em tempo de execução sem dependências pesadas externas.

### 5.1 Vetor de Características Léxicas e Estatísticas (`DomainFeatures`)

Para cada domínio analisado, o extrator isola o rótulo principal (*Second-Level Domain* ou SLD) e calcula:

1. **Entropia de Informação de Shannon (\(H\)):**
   Calcula a aleatoriedade da distribuição de caracteres no rótulo:
   \[
   H(X) = -\sum_{i=1}^{k} P(x_i) \log_2 P(x_i)
   \]
   - Domínios benignos em linguagem natural (ex: `google`, `noticias`, `banco`) apresentam tipicamente valores de entropia entre **2.0 e 3.2 bits**.
   - Nomes gerados por DGA (ex: `xzkfplwq987123jfk`) apresentam entropia superior a **3.6 a 4.2 bits**, sinalizando ausência de estrutura semântica.

2. **Rácios de Caracteres:**
   - **Rácio de Vogais / Consoantes:** DGAs tendem a gerar cadeias com défice de vogais (< 15%) ou ausência total de vogais.
   - **Sequência Máxima de Consoantes Consecutivas:** Agrupamentos de 5 ou mais consoantes seguidas (ex: `...rtsdfg...`) constituem um forte indicador de aleatoriedade sintética.
   - **Rácio de Dígitos e Hexadecimal:** Identifica domínios construídos a partir de hashes MD5/SHA ou contadores numéricos (ex: `b3a8c7d9e1f2.xyz`).

3. **Heurísticas Estruturais e de Reputação:**
   - **Reputação de TLDs:** Avalia a terminação do domínio contra bases de TLDs historicamente correlacionados com atividade maliciosa e baixo custo de registo (`.xyz`, `.top`, `.online`, `.cc`, `.ru`, `.click`, `.live`, etc.).
   - **Profundidade de Subdomínios:** Deteção de técnicas de evasão e tunelamento baseadas em múltiplos níveis de delegação DNS.

### 5.2 Decisão e Veredito (`PredictionResult`)

O motor combina as características num **Score de Risco Normalizado** (entre `0.0` e `1.0`):

| Limiar de Risco | Veredito | Ação Recomendada |
| :---: | :---: | :--- |
| **0.00 – 0.39** | `BENIGN` | Tráfego permitido; perfil compatível com linguagem natural. |
| **0.40 – 0.69** | `SUSPICIOUS` | Alerta de triagem; anomalias parciais identificadas (ex: TLD de risco + comprimento moderado). |
| **0.70 – 1.00** | `HIGH_RISK_DGA` | Bloqueio automático; alta entropia combinada com sequências aleatórias e ausência de semântica. |

Para cada predição, o sistema gera uma lista explicativa de sinais para apoiar o analista de cibersegurança (ex: *"Entropia muito elevada (3.84 bits)"*, *"6 consoantes consecutivas"*, *"TLD de alto risco (.xyz)"*).

---

## 6. Suporte SSL/TLS e Comportamento em HTTPS

Para intercetar tráfego seguro na porta 443 (HTTPS), o projeto centraliza os certificados através de `app/config.py`:
- Chave Privada: `certs/sinkhole.key` (permissão `600`)
- Certificado X.509: `certs/sinkhole.crt` (permissão `644`)

### Comportamento em Navegadores Web Modernos
Como o Sinkhole responde a consultas de domínios maliciosos de terceiros utilizando um certificado autoassinado gerado para a autoridade local:
- O browser do cliente final apresenta legitimamente um aviso de segurança TLS (`SEC_ERROR_UNKNOWN_ISSUER` ou `ERR_CERT_AUTHORITY_INVALID`).
- Este comportamento é esperado num ambiente de Sinkhole em nível de rede corporativa e valida tecnicamente que a sessão maliciosa foi intercetada antes de atingir a infraestrutura real do atacante.
- Para ambientes laboratoriais ou de teste controlado, a autoridade emissora da VM pode ser importada no repositório de certificados de confiança dos clientes da rede.

---

## 7. Procedimentos de Resposta a Incidentes & Rollback

Caso um domínio legítimo seja bloqueado indevidamente (*Falso Positivo*):

1. **Desbloqueio via Dashboard SOC (`/admin`):**
   - Na tabela de auditoria recente, clicar no botão **Desbloquear** junto ao registo afetado.
   - Ou introduzir o FQDN no card **Desbloqueio / Rollback Rápido de IoC**.
2. **Efeito Imediato:**
   - O domínio é removido da tabela ativa `ioc_entries`.
   - É adicionado com marca de data ao ficheiro `data/allowlist.txt`.
   - Futuras sincronizações automáticas do `sync_iocs.py` descartam o domínio, impedindo re-bloqueios acidentais.

---

## 8. Verificação e Testes Automatizados

O repositório inclui testes unitários e de integração desenvolvidos com `pytest` e `fastapi.testclient`:

```bash
# Executar a suite completa com relatório detalhado
pytest tests/ -v
```

- `tests/test_classifier.py`: Valida a precisão matemática do cálculo de entropia de Shannon, testes com domínios benignos conhecidos, deteção de strings DGA, influência de TLDs e consistência de vetores de features.
- `tests/test_extractor.py`: Valida as rotinas de desofuscação regex, parsing de URLs com portas/caminhos e integridade da allowlist.
- `tests/test_sinkhole.py`: Valida a interceção na rota catch-all, o registo no SQLite WAL, o endpoint `/health`, a renderização do `/admin` e as rotas `/api/ioc/unblock` e `/api/ml/analyze`.
