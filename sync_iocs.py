#!/usr/bin/env python3
"""
sync_iocs.py — DNS Sinkhole Threat Intelligence Synchronization Engine
========================================================================
Engenheiro: SecOps / Python Sénior
Projeto:    DNS Sinkhole baseado em Unbound + Painel FastAPI/SQLite
Versão:     2.0.0

Descrição:
    Script autónomo de Threat Intelligence que descarrega, processa e
    unifica Indicadores de Compromisso (IoCs) de múltiplas fontes OSINT
    abertas, aplica-os na configuração do Unbound (DNS Sinkhole) e
    persiste os dados na base de dados de telemetria SQLite.

Fontes Implementadas (texto direto, sem API key):
    ✅  URLhaus          — abuse.ch: URLs de distribuição de malware
    ✅  Feodo Tracker    — abuse.ch: C2 de botnets (Emotet, TrickBot, etc.)
    ✅  OpenPhish        — Phishing URLs activos
    ✅  SpamHaus DROP    — Redes controladas por criminosos
    ✅  SpamHaus EDROP   — Redes secundárias de criminosos
    ✅  CINS Army List   — IPs/domínios de reputação negativa

Fontes Futuras (estrutura preparada, requer API key):
    🔲  ThreatFox        — abuse.ch IoC database
    🔲  AlienVault OTX   — Open Threat Exchange
    🔲  AbuseIPDB        — IP blacklist com contexto
    🔲  MalwareBazaar    — abuse.ch malware samples

Requisitos:
    - Python 3.9+
    - pip install requests
    - Execução com sudo (para escrita em /etc/unbound/ e systemctl)

Uso:
    sudo python3 /home/pserver/dnsthreat/sync_iocs.py
    sudo python3 /home/pserver/dnsthreat/sync_iocs.py --dry-run
    sudo python3 /home/pserver/dnsthreat/sync_iocs.py --verbose
"""

import argparse
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# CONFIGURAÇÃO GLOBAL
# ---------------------------------------------------------------------------

# Caminhos do sistema
UNBOUND_CONF_PATH = Path("/etc/unbound/unbound.conf.d/threat_feed.conf")
DATABASE_PATH = Path("/home/pserver/dnsthreat/data/telemetry.db")

# IP de sinkhole — endereço para onde os domínios bloqueados são redirecionados
SINKHOLE_IP = "10.0.2.15"

# Timeouts e comportamento de rede
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRY_ATTEMPTS = 3
REQUEST_RETRY_DELAY_SECONDS = 5

# Cabeçalho HTTP para identificar o script
HTTP_HEADERS = {
    "User-Agent": (
        "DNSThreat-SyncBot/2.0 (SecOps Threat Intelligence Sync; "
        "github.com/yung6thplague/dnsthreat)"
    )
}

# Expressão regular para validar um FQDN (Fully Qualified Domain Name)
# Extrai apenas domínios válidos; ignora IPs, comentários, linhas vazias
FQDN_REGEX = re.compile(
    r"""
    (?:https?://)?                          # Protocolo opcional (http/https)
    (?:[a-zA-Z0-9_\-]+\.)+                  # Sub-domínios + ponto separador
    (?:
        xn--[a-zA-Z0-9]+                    # IDN (internationalised domain)
        |[a-zA-Z]{2,63}                     # TLD standard (2-63 chars)
    )
    (?:/[^\s]*)?                            # Path opcional (descartado)
    """,
    re.VERBOSE,
)

# Regex para detectar endereços IPv4 (para exclusão explícita)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configura o sistema de logging com formatação profissional."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("sync_iocs")


# ---------------------------------------------------------------------------
# ESTRUTURAS DE DADOS
# ---------------------------------------------------------------------------

@dataclass
class IoCEntry:
    """Representa um único Indicador de Compromisso (IoC) extraído."""
    domain: str
    source_tag: str
    category: str = "Malware / C2"


@dataclass
class FeedResult:
    """Resultado do processamento de uma fonte de IoCs."""
    source_name: str
    domains_found: int = 0
    domains_valid: int = 0
    error: Optional[str] = None
    duration_seconds: float = 0.0
    iocs: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# CLASSES BASE — PADRÃO STRATEGY PARA FONTES DE IoCs
# ---------------------------------------------------------------------------

class BaseTextFeed(ABC):
    """
    Classe base abstracta para fontes de IoCs baseadas em texto plano.

    Todas as fontes de texto (sem API key) devem herdar desta classe
    e implementar os métodos `url`, `source_tag` e `category`.

    Para adicionar uma nova fonte de texto:
        1. Cria uma subclasse de BaseTextFeed
        2. Define `url`, `source_tag` e `category`
        3. (Opcional) Override de `parse_line` para lógica custom
        4. Adiciona a instância à lista ACTIVE_TEXT_FEEDS

    Para adicionar uma fonte baseada em API (ThreatFox, OTX, etc.):
        1. Cria uma subclasse de BaseApiFeed (ver secção abaixo)
        2. Implementa `fetch_raw` com a lógica de autenticação/paginação
        3. Adiciona a instância à lista ACTIVE_API_FEEDS
    """

    @property
    @abstractmethod
    def url(self) -> str:
        """URL pública da lista de IoCs em texto plano."""
        ...

    @property
    @abstractmethod
    def source_tag(self) -> str:
        """Tag identificadora da fonte (persiste na BD)."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Categoria de ameaça predominante nesta fonte."""
        ...

    def parse_line(self, line: str) -> Optional[str]:
        """
        Extrai um FQDN válido de uma linha de texto.

        Lógica padrão (pode ser sobrescrita por subclasses):
            - Ignora linhas vazias ou comentários (#)
            - Extrai o domínio via regex FQDN
            - Rejeita endereços IPv4

        Args:
            line: Linha de texto bruto da fonte

        Returns:
            FQDN em minúsculas se válido, None caso contrário
        """
        line = line.strip()

        # Ignora linhas vazias e comentários
        if not line or line.startswith("#"):
            return None

        # Tenta extrair um FQDN válido da linha
        match = FQDN_REGEX.search(line)
        if not match:
            return None

        raw = match.group(0)

        # Remove protocolo se presente
        raw = re.sub(r"^https?://", "", raw)

        # Extrai apenas o host (remove path)
        domain = raw.split("/")[0].strip().lower()

        # Rejeita se for um IP puro
        if IPV4_REGEX.match(domain):
            return None

        # Rejeita domínios com menos de 4 caracteres (inválidos)
        if len(domain) < 4 or "." not in domain:
            return None

        # Rejeita localhost e loopbacks
        if domain in ("localhost", "localhost.localdomain"):
            return None

        return domain

    def fetch(
        self,
        session: requests.Session,
        logger: logging.Logger,
    ) -> FeedResult:
        """
        Descarrega e processa a feed de IoCs com retry automático.

        Args:
            session: Sessão HTTP reutilizável (requests.Session)
            logger:  Logger do módulo principal

        Returns:
            FeedResult com os IoCs extraídos e estatísticas
        """
        result = FeedResult(source_name=self.source_tag)
        start_time = time.monotonic()

        for attempt in range(1, REQUEST_RETRY_ATTEMPTS + 1):
            try:
                logger.info(
                    "  [%s] A descarregar (tentativa %d/%d): %s",
                    self.source_tag, attempt, REQUEST_RETRY_ATTEMPTS, self.url,
                )
                response = session.get(
                    self.url,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    headers=HTTP_HEADERS,
                )
                response.raise_for_status()

                lines = response.text.splitlines()
                result.domains_found = len(lines)

                seen_in_feed: set = set()
                for line in lines:
                    domain = self.parse_line(line)
                    if domain and domain not in seen_in_feed:
                        seen_in_feed.add(domain)
                        result.iocs.append(
                            IoCEntry(
                                domain=domain,
                                source_tag=self.source_tag,
                                category=self.category,
                            )
                        )

                result.domains_valid = len(result.iocs)
                logger.info(
                    "[%s] Processado: %d linhas -> %d dominios validos",
                    self.source_tag, result.domains_found, result.domains_valid,
                )
                break  # Sucesso — sai do loop de retry

            except requests.exceptions.Timeout:
                result.error = f"Timeout apos {REQUEST_TIMEOUT_SECONDS}s"
                logger.warning(
                    "[%s] Timeout na tentativa %d/%d",
                    self.source_tag, attempt, REQUEST_RETRY_ATTEMPTS,
                )
                if attempt < REQUEST_RETRY_ATTEMPTS:
                    time.sleep(REQUEST_RETRY_DELAY_SECONDS)

            except requests.exceptions.ConnectionError as exc:
                result.error = f"Erro de ligacao: {exc}"
                logger.warning(
                    "[%s] Erro de ligacao na tentativa %d/%d: %s",
                    self.source_tag, attempt, REQUEST_RETRY_ATTEMPTS, exc,
                )
                if attempt < REQUEST_RETRY_ATTEMPTS:
                    time.sleep(REQUEST_RETRY_DELAY_SECONDS)

            except requests.exceptions.HTTPError as exc:
                result.error = f"HTTP {exc.response.status_code}: {exc}"
                logger.error(
                    "[%s] HTTP Error %s — fonte ignorada",
                    self.source_tag, exc.response.status_code,
                )
                break  # Erro HTTP permanente — não retry

            except requests.exceptions.RequestException as exc:
                result.error = str(exc)
                logger.error("[%s] Erro inesperado: %s", self.source_tag, exc)
                break

        result.duration_seconds = time.monotonic() - start_time
        return result


class BaseApiFeed(ABC):
    """
    Classe base abstracta para fontes de IoCs baseadas em API autenticada.

    Estrutura preparada para integração futura. Para implementar:
        1. Define `source_tag`, `category`, `api_key_env_var`
        2. Implementa `fetch_raw(session, api_key)` com a lógica da API
        3. Implementa `parse_response(raw)` para extrair domínios
        4. Adiciona a instância à lista ACTIVE_API_FEEDS no final do ficheiro

    Fontes previstas:
        - ThreatFoxFeed    (THREATFOX_API_KEY)
        - AlienVaultFeed   (OTX_API_KEY)
        - AbuseIPDBFeed    (ABUSEIPDB_API_KEY)
        - MalwareBazaarFeed(sem key, mas com endpoint JSON específico)
    """

    @property
    @abstractmethod
    def source_tag(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> str: ...

    @property
    @abstractmethod
    def api_key_env_var(self) -> str:
        """Nome da variável de ambiente que contém a API key."""
        ...

    @abstractmethod
    def fetch_raw(self, session: requests.Session, api_key: str) -> list:
        """Efectua o pedido à API e retorna lista de IoCs brutos."""
        ...

    @abstractmethod
    def parse_response(self, raw: list) -> list:
        """Converte a resposta bruta da API em IoCEntry normalizados."""
        ...

    def fetch(
        self,
        session: requests.Session,
        logger: logging.Logger,
    ) -> FeedResult:
        """Orchestrates API fetch with key validation and error handling."""
        result = FeedResult(source_name=self.source_tag)
        api_key = os.environ.get(self.api_key_env_var, "").strip()

        if not api_key:
            result.error = (
                f"API key em falta. Define a variavel de ambiente: "
                f"{self.api_key_env_var}"
            )
            logger.warning(
                "[%s] Ignorado — %s", self.source_tag, result.error
            )
            return result

        try:
            start_time = time.monotonic()
            raw = self.fetch_raw(session, api_key)
            result.iocs = self.parse_response(raw)
            result.domains_valid = len(result.iocs)
            result.duration_seconds = time.monotonic() - start_time
            logger.info(
                "[%s] API: %d dominios extraidos", self.source_tag, result.domains_valid
            )
        except Exception as exc:  # pylint: disable=broad-except
            result.error = str(exc)
            logger.error("[%s] Erro na API: %s", self.source_tag, exc)

        return result


# ---------------------------------------------------------------------------
# IMPLEMENTAÇÕES — FONTES DE TEXTO PLANO ACTIVAS
# ---------------------------------------------------------------------------

class URLhausFeed(BaseTextFeed):
    """
    URLhaus (abuse.ch) — Lista de URLs activas de distribuição de malware.
    Formato: Uma URL por linha, com comentários (#) no cabeçalho.
    URL: https://urlhaus.abuse.ch/downloads/text/
    """

    @property
    def url(self) -> str:
        return "https://urlhaus.abuse.ch/downloads/text/"

    @property
    def source_tag(self) -> str:
        return "URLhaus"

    @property
    def category(self) -> str:
        return "Malware Distribution"

    def parse_line(self, line: str) -> Optional[str]:
        """URLhaus emite linhas do tipo: http://malware.com/payload.exe"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        # Cada linha é uma URL completa — usa lógica base
        return super().parse_line(line)


class FeodoTrackerFeed(BaseTextFeed):
    """
    Feodo Tracker (abuse.ch) — C2 de botnets (Emotet, TrickBot, Dridex, QakBot).
    Nota: A lista oficial actual do Feodo Tracker emite IPs activos de C2
    (ipblocklist_recommended.txt / ipblocklist.txt).
    URL: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
    """

    @property
    def url(self) -> str:
        return "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

    @property
    def source_tag(self) -> str:
        return "Feodo Tracker"

    @property
    def category(self) -> str:
        return "Botnet C2"


class OpenPhishFeed(BaseTextFeed):
    """
    OpenPhish — Feed gratuita de URLs de phishing activos.
    Formato: Uma URL por linha.
    URL: https://openphish.com/feed.txt
    """

    @property
    def url(self) -> str:
        return "https://openphish.com/feed.txt"

    @property
    def source_tag(self) -> str:
        return "OpenPhish"

    @property
    def category(self) -> str:
        return "Credential Phishing"


class SpamHausDROPFeed(BaseTextFeed):
    """
    Spamhaus DROP (Don't Route Or Peer) — Redes controladas por criminosos.
    Nota: Lista maioritariamente de IPs/CIDRs. FQDNs serão extraídos se
    presentes; IPs e CIDRs são ignorados pelo regex FQDN.
    URL: https://www.spamhaus.org/drop/drop.txt
    """

    @property
    def url(self) -> str:
        return "https://www.spamhaus.org/drop/drop.txt"

    @property
    def source_tag(self) -> str:
        return "SpamHaus DROP"

    @property
    def category(self) -> str:
        return "Spam / Criminal Network"

    def parse_line(self, line: str) -> Optional[str]:
        """
        SpamHaus DROP emite CIDRs (ex: 1.2.3.0/24 ; SBL123).
        Ignora IPs/CIDRs; extrai apenas FQDNs se presentes.
        """
        line = line.strip()
        if not line or line.startswith(";"):
            return None
        # Remove anotações do tipo "; SBL123"
        line = line.split(";")[0].strip()
        return super().parse_line(line)


class SpamHausEDROPFeed(BaseTextFeed):
    """
    Spamhaus EDROP (Extended DROP) — Redes secundárias controladas por criminosos.
    URL: https://www.spamhaus.org/drop/edrop.txt
    """

    @property
    def url(self) -> str:
        return "https://www.spamhaus.org/drop/edrop.txt"

    @property
    def source_tag(self) -> str:
        return "SpamHaus EDROP"

    @property
    def category(self) -> str:
        return "Spam / Criminal Network"

    def parse_line(self, line: str) -> Optional[str]:
        """Mesmo formato que DROP — remove anotações '; SBL'."""
        line = line.strip()
        if not line or line.startswith(";"):
            return None
        line = line.split(";")[0].strip()
        return super().parse_line(line)


class CINSArmyFeed(BaseTextFeed):
    """
    CINS Army List (Sentinel IPS) — IPs/domínios de reputação negativa activa.
    URL: https://cinsscore.com/list/ci-badguys.txt
    """

    @property
    def url(self) -> str:
        return "https://cinsscore.com/list/ci-badguys.txt"

    @property
    def source_tag(self) -> str:
        return "CINS Army"

    @property
    def category(self) -> str:
        return "Malicious IP / Botnet"


# ---------------------------------------------------------------------------
# IMPLEMENTAÇÕES FUTURAS — FONTES BASEADAS EM API (ESQUELETOS COMENTADOS)
# ---------------------------------------------------------------------------
#
# NOTA PARA O PROGRAMADOR:
# Descomenta e preenche cada classe quando tiveres as respectivas API keys.
# Define as variáveis de ambiente antes de executar:
#   export THREATFOX_API_KEY="..."
#   export OTX_API_KEY="..."
#   export ABUSEIPDB_API_KEY="..."
#
# class ThreatFoxFeed(BaseApiFeed):
#     """ThreatFox (abuse.ch) — IoC database com contexto de malware."""
#     @property
#     def source_tag(self) -> str: return "ThreatFox"
#     @property
#     def category(self) -> str: return "Malware IoC"
#     @property
#     def api_key_env_var(self) -> str: return "THREATFOX_API_KEY"
#
#     def fetch_raw(self, session, api_key):
#         resp = session.post(
#             "https://threatfox-api.abuse.ch/api/v1/",
#             json={"query": "get_iocs", "days": 1},
#             headers={**HTTP_HEADERS, "Auth-Key": api_key},
#             timeout=REQUEST_TIMEOUT_SECONDS,
#         )
#         resp.raise_for_status()
#         return resp.json().get("data", [])
#
#     def parse_response(self, raw):
#         iocs = []
#         for item in raw:
#             ioc_value = item.get("ioc_value", "")
#             if item.get("ioc_type") == "domain" and ioc_value:
#                 iocs.append(IoCEntry(ioc_value.lower(), self.source_tag, self.category))
#         return iocs
#
#
# class AlienVaultOTXFeed(BaseApiFeed):
#     """AlienVault OTX — Open Threat Exchange com pulsos da comunidade."""
#     @property
#     def source_tag(self) -> str: return "AlienVault OTX"
#     @property
#     def category(self) -> str: return "Community Threat Intel"
#     @property
#     def api_key_env_var(self) -> str: return "OTX_API_KEY"
#
#     def fetch_raw(self, session, api_key):
#         resp = session.get(
#             "https://otx.alienvault.com/api/v1/indicators/export"
#             "?type=domain&modified_since=1d",
#             headers={**HTTP_HEADERS, "X-OTX-API-KEY": api_key},
#             timeout=REQUEST_TIMEOUT_SECONDS,
#         )
#         resp.raise_for_status()
#         return resp.text.splitlines()
#
#     def parse_response(self, raw):
#         iocs = []
#         for line in raw:
#             line = line.strip()
#             if line and not line.startswith("#"):
#                 iocs.append(IoCEntry(line.lower(), self.source_tag, self.category))
#         return iocs
#
#
# class AbuseIPDBFeed(BaseApiFeed):
#     """AbuseIPDB — Blacklist de IPs com histórico de comportamento abusivo."""
#     @property
#     def source_tag(self) -> str: return "AbuseIPDB"
#     @property
#     def category(self) -> str: return "Abusive IP"
#     @property
#     def api_key_env_var(self) -> str: return "ABUSEIPDB_API_KEY"
#
#     def fetch_raw(self, session, api_key):
#         resp = session.get(
#             "https://api.abuseipdb.com/api/v2/blacklist",
#             headers={**HTTP_HEADERS, "Key": api_key, "Accept": "text/plain"},
#             params={"confidenceMinimum": 90},
#             timeout=REQUEST_TIMEOUT_SECONDS,
#         )
#         resp.raise_for_status()
#         return resp.text.splitlines()
#
#     def parse_response(self, raw):
#         # AbuseIPDB emite IPs — nao aplicavel ao sinkhole DNS directamente.
#         # Implementa PTR lookup ou correlacao se necessario no futuro.
#         return []
#
#
# class MalwareBazaarFeed(BaseApiFeed):
#     """MalwareBazaar (abuse.ch) — Amostras de malware com C2 domains."""
#     @property
#     def source_tag(self) -> str: return "MalwareBazaar"
#     @property
#     def category(self) -> str: return "Malware Sample C2"
#     @property
#     def api_key_env_var(self) -> str: return "MALWAREBAZAAR_API_KEY"
#
#     def fetch_raw(self, session, api_key):
#         resp = session.post(
#             "https://mb-api.abuse.ch/api/v1/",
#             data={"query": "get_recent", "selector": "time"},
#             headers={**HTTP_HEADERS, "API-KEY": api_key},
#             timeout=REQUEST_TIMEOUT_SECONDS,
#         )
#         resp.raise_for_status()
#         return resp.json().get("data", [])
#
#     def parse_response(self, raw):
#         iocs = []
#         for sample in raw:
#             for domain in sample.get("domains", []):
#                 if domain:
#                     iocs.append(IoCEntry(domain.lower(), self.source_tag, self.category))
#         return iocs


# ---------------------------------------------------------------------------
# REGISTOS DE FONTES ACTIVAS
# ---------------------------------------------------------------------------

#: Fontes de texto activas — adiciona/remove instâncias conforme necessário
ACTIVE_TEXT_FEEDS: list = [
    URLhausFeed(),
    FeodoTrackerFeed(),
    OpenPhishFeed(),
    SpamHausDROPFeed(),
    SpamHausEDROPFeed(),
    CINSArmyFeed(),
]

#: Fontes de API activas — descomenta as classes acima e adiciona aqui
ACTIVE_API_FEEDS: list = [
    # ThreatFoxFeed(),
    # AlienVaultOTXFeed(),
    # AbuseIPDBFeed(),
    # MalwareBazaarFeed(),
]


# ---------------------------------------------------------------------------
# MOTOR DE DOWNLOAD — ORCHESTRATOR
# ---------------------------------------------------------------------------

def collect_all_iocs(logger: logging.Logger) -> tuple:
    """
    Executa todas as feeds activas e consolida os IoCs.

    Utiliza um requests.Session partilhado para reutilização de ligações TCP
    (connection pooling), melhorando performance em múltiplos downloads.

    Args:
        logger: Logger do módulo principal

    Returns:
        Tuple (unique_domains: set, all_iocs: list[IoCEntry])
        - unique_domains: set de FQDNs únicos para escrita no Unbound
        - all_iocs: lista completa de IoCEntry (com metadados de fonte)
    """
    all_iocs: list = []
    unique_domains: set = set()

    session = requests.Session()
    session.headers.update(HTTP_HEADERS)

    all_feeds = ACTIVE_TEXT_FEEDS + ACTIVE_API_FEEDS
    total_feeds = len(all_feeds)

    logger.info("=" * 65)
    logger.info("DNS Sinkhole — Threat Intelligence Sync Engine v2.0")
    logger.info("Fontes activas: %d | Sinkhole IP: %s", total_feeds, SINKHOLE_IP)
    logger.info("=" * 65)

    for idx, feed in enumerate(all_feeds, start=1):
        logger.info("-" * 65)
        logger.info("[%d/%d] Feed: %s", idx, total_feeds, feed.source_tag)
        result: FeedResult = feed.fetch(session, logger)

        if result.error and not result.iocs:
            logger.warning(
                "[%s] Ignorado com erro: %s", feed.source_tag, result.error
            )
            continue

        for ioc in result.iocs:
            if ioc.domain not in unique_domains:
                unique_domains.add(ioc.domain)
                all_iocs.append(ioc)
            # Domínios duplicados de fontes diferentes são descartados silenciosamente
            # (o primeiro a chegar fica registado com a sua fonte de origem)

    session.close()

    logger.info("=" * 65)
    logger.info("Total de dominios unicos consolidados: %d", len(unique_domains))

    return unique_domains, all_iocs


# ---------------------------------------------------------------------------
# GERAÇÃO DA CONFIGURAÇÃO UNBOUND
# ---------------------------------------------------------------------------

def generate_unbound_config(
    domains: set,
    sinkhole_ip: str,
    output_path: Path,
    logger: logging.Logger,
    dry_run: bool = False,
) -> None:
    """
    Gera e escreve o ficheiro de configuração do Unbound DNS Sinkhole.

    Formato gerado para cada domínio:
        local-zone: "dominio.com" redirect
        local-data: "dominio.com A 10.0.2.15"

    Args:
        domains:     Set de FQDNs únicos a bloquear
        sinkhole_ip: IP de destino do sinkhole (ex: 10.0.2.15)
        output_path: Caminho do ficheiro de configuração Unbound
        logger:      Logger do módulo principal
        dry_run:     Se True, imprime no stdout sem escrever no disco
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header = (
        f"# ============================================================\n"
        f"# DNS Sinkhole — Threat Intelligence Block List\n"
        f"# Gerado automaticamente por sync_iocs.py\n"
        f"# Data: {timestamp}\n"
        f"# Total de dominios: {len(domains)}\n"
        f"# Sinkhole IP: {sinkhole_ip}\n"
        f"# NAO EDITES ESTE FICHEIRO MANUALMENTE — Sera sobrescrito!\n"
        f"# ============================================================\n\n"
    )

    lines = [header]
    for domain in sorted(domains):
        lines.append(f'local-zone: "{domain}" redirect\n')
        lines.append(f'local-data: "{domain} A {sinkhole_ip}"\n')
        lines.append("\n")

    config_content = "".join(lines)

    if dry_run:
        logger.info(
            "[DRY-RUN] Configuracao Unbound (primeiras 40 linhas):\n%s",
            "\n".join(config_content.splitlines()[:40]),
        )
        logger.info("[DRY-RUN] Ficheiro NAO escrito. Caminho seria: %s", output_path)
        return

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(config_content, encoding="utf-8")
        logger.info(
            "Configuracao Unbound escrita: %s (%d dominios)",
            output_path, len(domains),
        )
    except PermissionError as exc:
        logger.critical(
            "PERMISSAO NEGADA ao escrever em %s\n"
            "Execute o script com: sudo python3 sync_iocs.py\n"
            "Detalhe: %s",
            output_path, exc,
        )
        sys.exit(1)
    except OSError as exc:
        logger.critical("Erro de I/O ao escrever configuracao: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# PERSISTÊNCIA NA BASE DE DADOS SQLITE
# ---------------------------------------------------------------------------

def persist_iocs_to_database(
    iocs: list,
    db_path: Path,
    logger: logging.Logger,
    dry_run: bool = False,
) -> None:
    """
    Persiste os IoCs na base de dados SQLite de telemetria.

    Operações executadas em transação atómica:
        1. Garante que a tabela `ioc_entries` existe (CREATE IF NOT EXISTS)
        2. Limpa todas as entradas anteriores (DELETE — sync completo)
        3. Insere todos os novos domínios com fonte e categoria em batch
        4. Em caso de erro, faz rollback completo

    A coluna `category` recebe o formato "SOURCE | CATEGORY" para preservar
    a rastreabilidade da fonte de origem, compatível com o schema existente.

    Args:
        iocs:     Lista de IoCEntry com metadados completos
        db_path:  Caminho absoluto para o ficheiro SQLite
        logger:   Logger do módulo principal
        dry_run:  Se True, simula sem escrever na BD
    """
    if dry_run:
        logger.info(
            "[DRY-RUN] Base de dados NAO modificada. "
            "Seriam inseridos %d registos em %s", len(iocs), db_path,
        )
        return

    if not db_path.exists():
        logger.warning(
            "Base de dados nao encontrada em %s\n"
            "Certifica-te que a aplicacao FastAPI foi iniciada pelo menos uma vez (init_db).",
            db_path,
        )

    try:
        conn = sqlite3.connect(
            str(db_path),
            timeout=15.0,
            check_same_thread=False,
        )

        # Configura WAL mode e parametros de concorrencia
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")

        with conn:  # Transacao atomica — commit ou rollback automatico
            cursor = conn.cursor()

            # 1. Garante que a tabela existe (idempotente)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ioc_entries (
                    domain     TEXT PRIMARY KEY,
                    status     TEXT NOT NULL DEFAULT 'blocked',
                    category   TEXT DEFAULT 'Malware / C2',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Limpa entradas anteriores (sync completo, nao incremental)
            cursor.execute("DELETE FROM ioc_entries;")
            deleted_count = cursor.rowcount
            logger.info("BD: %d entradas antigas removidas", deleted_count)

            # 3. Prepara dados — formata categoria como "Source | Category"
            utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            records = [
                (
                    ioc.domain,
                    "blocked",
                    f"{ioc.source_tag} | {ioc.category}",
                    utc_now,
                )
                for ioc in iocs
            ]

            # 4. Inserção em lote (batch insert) — eficiente para grandes volumes
            cursor.executemany(
                """
                INSERT OR REPLACE INTO ioc_entries
                    (domain, status, category, created_at)
                VALUES (?, ?, ?, ?);
                """,
                records,
            )
            logger.info("BD: %d IoCs inseridos em %s", len(records), db_path)

        conn.close()

    except sqlite3.OperationalError as exc:
        err_str = str(exc).lower()
        if "unable to open database" in err_str:
            logger.error(
                "BD: Nao foi possivel abrir a base de dados em %s\n"
                "Verifica permissoes e se o caminho existe.\n"
                "Detalhe: %s",
                db_path, exc,
            )
        elif "database is locked" in err_str:
            logger.error(
                "BD: Base de dados bloqueada (locked).\n"
                "Outro processo esta a usar o SQLite. Aguarda e tenta novamente.\n"
                "Detalhe: %s",
                exc,
            )
        else:
            logger.error("BD: Erro operacional SQLite: %s", exc)

    except sqlite3.DatabaseError as exc:
        logger.error(
            "BD: Erro critico na base de dados: %s\n"
            "Possivel corrupcao. Verifica com: sqlite3 %s 'PRAGMA integrity_check;'",
            exc, db_path,
        )

    except PermissionError as exc:
        logger.critical(
            "BD: PERMISSAO NEGADA ao aceder a %s\n"
            "Execute com sudo ou ajusta permissoes: chmod 664 %s\n"
            "Detalhe: %s",
            db_path, db_path, exc,
        )


# ---------------------------------------------------------------------------
# RESTART DO SERVIÇO UNBOUND
# ---------------------------------------------------------------------------

def restart_unbound(logger: logging.Logger, dry_run: bool = False) -> None:
    """
    Reinicia o serviço Unbound via systemctl para aplicar a nova configuração.

    Fluxo de segurança:
        1. Valida a configuração com `unbound-checkconf`
        2. Só reinicia se a configuração for válida
        3. Em caso de configuração inválida, termina com exit code 1

    Args:
        logger:  Logger do módulo principal
        dry_run: Se True, simula o comando sem executar
    """
    if dry_run:
        logger.info(
            "[DRY-RUN] Comandos NAO executados: "
            "unbound-checkconf + systemctl restart unbound"
        )
        return

    # 1. Valida a configuração antes de reiniciar
    logger.info("A validar configuracao Unbound (unbound-checkconf)...")
    try:
        check_result = subprocess.run(
            ["unbound-checkconf"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if check_result.returncode != 0:
            logger.critical(
                "Configuracao Unbound INVALIDA — Restart cancelado!\n"
                "Saida: %s\n"
                "Erros: %s",
                check_result.stdout.strip(),
                check_result.stderr.strip(),
            )
            sys.exit(1)
        logger.info(
            "Configuracao valida: %s",
            check_result.stdout.strip() or "OK",
        )
    except FileNotFoundError:
        logger.warning("`unbound-checkconf` nao encontrado — validacao ignorada.")
    except subprocess.TimeoutExpired:
        logger.warning("Timeout na validacao da configuracao — continuando...")

    # 2. Reinicia o serviço
    logger.info("A reiniciar servico Unbound...")
    try:
        result = subprocess.run(
            ["systemctl", "restart", "unbound"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("Unbound reiniciado com sucesso.")
        else:
            logger.error(
                "Falha ao reiniciar Unbound (exit code: %d)\n"
                "stdout: %s\n"
                "stderr: %s",
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
    except FileNotFoundError:
        logger.error(
            "`systemctl` nao encontrado. "
            "Este script requer um sistema Linux com systemd."
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "Timeout ao reiniciar Unbound (>30s). "
            "Verifica o estado com: sudo systemctl status unbound"
        )
    except PermissionError:
        logger.critical(
            "PERMISSAO NEGADA ao executar systemctl.\n"
            "Execute o script com: sudo python3 sync_iocs.py"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# VERIFICAÇÃO DE PRIVILÉGIOS
# ---------------------------------------------------------------------------

def check_root_privileges(logger: logging.Logger, dry_run: bool = False) -> None:
    """
    Verifica se o script está a ser executado com privilégios de root.

    Necessário para:
        - Escrever em /etc/unbound/unbound.conf.d/
        - Executar systemctl restart unbound

    Em modo dry-run ou Windows (dev), o aviso é emitido mas o script não termina.
    """
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = (os.geteuid() == 0)
    else:
        # Plataforma Windows (ambiente de desenvolvimento/teste)
        try:
            import ctypes
            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_root = False

    if not is_root:
        if dry_run or os.name == "nt":
            logger.warning(
                "Sem privilegios root/admin — Permitido em modo --dry-run ou desenvolvimento Windows.\n"
                "Em producao Ubuntu execute com: sudo python3 sync_iocs.py"
            )
        else:
            logger.critical(
                "Este script requer privilegios de root.\n"
                "Execute com: sudo python3 sync_iocs.py"
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# PONTO DE ENTRADA — MAIN
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Define e analisa os argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        prog="sync_iocs.py",
        description=(
            "DNS Sinkhole Threat Intelligence Sync Engine — "
            "Sincroniza IoCs OSINT com Unbound e SQLite"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 sync_iocs.py                # Execucao normal
  sudo python3 sync_iocs.py --dry-run      # Simula sem escrever nada
  sudo python3 sync_iocs.py --verbose      # Modo debug verboso
  sudo python3 sync_iocs.py --no-restart   # Sem reiniciar Unbound
        """,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simula toda a execucao sem escrever ficheiros, BD ou reiniciar servicos.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Activa logging de nivel DEBUG para diagnostico detalhado.",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Aplica a configuracao mas nao reinicia o Unbound.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=DATABASE_PATH,
        help=f"Caminho para o ficheiro SQLite. Default: {DATABASE_PATH}",
    )
    parser.add_argument(
        "--conf-path",
        type=Path,
        default=UNBOUND_CONF_PATH,
        help=f"Caminho para o ficheiro de configuracao Unbound. Default: {UNBOUND_CONF_PATH}",
    )
    parser.add_argument(
        "--sinkhole-ip",
        type=str,
        default=SINKHOLE_IP,
        help=f"IP de destino do sinkhole. Default: {SINKHOLE_IP}",
    )
    return parser.parse_args()


def main() -> None:
    """
    Ponto de entrada principal do script de sincronização de IoCs.

    Fluxo de execução:
        1. Parse de argumentos CLI
        2. Configuração do logger
        3. Verificação de privilégios root
        4. Download e processamento de todas as feeds OSINT
        5. Geração do ficheiro de configuração Unbound
        6. Persistência na base de dados SQLite
        7. Restart do serviço Unbound (opcional)
        8. Relatório final de execução
    """
    args = parse_arguments()
    logger = setup_logging(verbose=args.verbose)

    # --- Verificação de privilégios ---
    check_root_privileges(logger, dry_run=args.dry_run)

    if args.dry_run:
        logger.info("MODO DRY-RUN ACTIVADO — Nenhuma alteracao sera aplicada.")

    start_time = time.monotonic()

    # --- Fase 1: Recolha de IoCs ---
    unique_domains, all_iocs = collect_all_iocs(logger)

    if not unique_domains:
        logger.error(
            "Nenhum dominio valido encontrado em nenhuma fonte.\n"
            "Verifica conectividade a internet e tenta novamente."
        )
        sys.exit(1)

    # --- Fase 2: Geração da configuração Unbound ---
    logger.info("-" * 65)
    logger.info("A gerar configuracao Unbound...")
    generate_unbound_config(
        domains=unique_domains,
        sinkhole_ip=args.sinkhole_ip,
        output_path=args.conf_path,
        logger=logger,
        dry_run=args.dry_run,
    )

    # --- Fase 3: Persistência na BD SQLite ---
    logger.info("-" * 65)
    logger.info("A persistir IoCs na base de dados...")
    persist_iocs_to_database(
        iocs=all_iocs,
        db_path=args.db_path,
        logger=logger,
        dry_run=args.dry_run,
    )

    # --- Fase 4: Restart do Unbound ---
    if not args.no_restart:
        logger.info("-" * 65)
        restart_unbound(logger=logger, dry_run=args.dry_run)
    else:
        logger.info("Restart do Unbound ignorado (--no-restart).")

    # --- Relatório Final ---
    elapsed = time.monotonic() - start_time
    logger.info("=" * 65)
    logger.info("Sincronizacao concluida em %.2f segundos", elapsed)
    logger.info("  Dominios unicos processados : %d", len(unique_domains))
    logger.info("  Fontes activas              : %d", len(ACTIVE_TEXT_FEEDS + ACTIVE_API_FEEDS))
    logger.info("  Configuracao Unbound        : %s", args.conf_path)
    logger.info("  Base de dados               : %s", args.db_path)
    logger.info("=" * 65)


if __name__ == "__main__":
    main()
