#!/usr/bin/env python3
"""sync_iocs.py — DNS Threat Blocker & Threat Intelligence Ingestion Engine.

Requirements:
    - Python 3.9+
    - pip install requests
    - Root / sudo privileges (for writing to /etc/unbound/ and systemctl restart)

Usage:
    sudo python3 sync_iocs.py
    sudo python3 sync_iocs.py --dry-run
    sudo python3 sync_iocs.py --verbose
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

# Ensure project base directory is in sys.path for sudo execution from any cwd
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Import Machine Learning / Threat Intel domain extraction and normalization engine
try:
    from agent.extractor import DomainExtractor, normalize_domain_candidate
    HAS_ML_EXTRACTOR = True
except Exception as e:
    HAS_ML_EXTRACTOR = False

# ---------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ---------------------------------------------------------------------------

# System file paths
UNBOUND_CONF_PATH = Path("/etc/unbound/unbound.conf.d/threat_feed.conf")
DATABASE_PATH = Path("/home/pserver/dnsthreat/data/telemetry.db")

# Sinkhole IP — dynamic detection of active network interface IP
# Uses UDP socket to 8.8.8.8:80 (without sending traffic) to identify
# the local IP assigned to the active network interface.
def get_local_ip() -> str:
    """Dynamically detects the local IPv4 address of the active network interface."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except (OSError, socket.error):
        return "127.0.0.1"


SINKHOLE_IP = get_local_ip()

# Network behavior and timeouts
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRY_ATTEMPTS = 3
REQUEST_RETRY_DELAY_SECONDS = 5

# HTTP User-Agent header for OSINT feeds
HTTP_HEADERS = {
    "User-Agent": (
        "DNSThreat-SyncBot/2.0 (SecOps Threat Intelligence Sync; "
        "github.com/yung6thplague/dnsthreat)"
    )
}

# Regular expression to validate a Fully Qualified Domain Name (FQDN)
# Extracts valid domains while ignoring IPs, comments, and empty lines
FQDN_REGEX = re.compile(
    r"""
    (?:https?://)?                          # Optional protocol scheme
    (?:[a-zA-Z0-9_\-]+\.)+                  # Subdomains + dot separator
    (?:
        xn--[a-zA-Z0-9]+                    # IDN (internationalized domain)
        |[a-zA-Z]{2,63}                     # Standard TLD (2-63 chars)
    )
    (?:/[^\s]*)?                            # Optional URL path (discarded)
    """,
    re.VERBOSE,
)

# Regex to detect IPv4 addresses (for explicit exclusion)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configures structured logging with ISO timestamps and log levels."""
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
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class IoCEntry:
    """Represents a single extracted Indicator of Compromise (IoC)."""
    domain: str
    source_tag: str
    category: str = "Malware / C2"


@dataclass
class FeedResult:
    """Execution outcome from processing a threat intelligence feed."""
    source_name: str
    domains_found: int = 0
    domains_valid: int = 0
    error: Optional[str] = None
    duration_seconds: float = 0.0
    iocs: list = field(default_factory=list)
    source_name: str
    domains_found: int = 0
    domains_valid: int = 0
    error: Optional[str] = None
    duration_seconds: float = 0.0
    iocs: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# BASE CLASSES — STRATEGY PATTERN FOR THREAT INTELLIGENCE SOURCES
# ---------------------------------------------------------------------------

class BaseTextFeed(ABC):
    """Abstract base class for plain-text threat intelligence sources.

    All public text-based feeds (without API keys) inherit from this class
    and implement `url`, `source_tag`, and `category`.

    To add a new plain-text source:
        1. Subclass BaseTextFeed
        2. Define `url`, `source_tag`, and `category`
        3. (Optional) Override `parse_line` for custom parsing logic
        4. Append instance to ACTIVE_TEXT_FEEDS registry
    """

    @property
    @abstractmethod
    def url(self) -> str:
        """Public URL of the plain-text IoC feed."""
        ...

    @property
    @abstractmethod
    def source_tag(self) -> str:
        """Identifying tag for the source (persisted in SQLite)."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Primary threat category for this feed."""
        ...

    def parse_line(self, line: str) -> Optional[str]:
        """Extracts a valid FQDN from a line of feed text.

        Default parsing pipeline:
            - Discards empty lines and comment headers (#)
            - Extracts candidate domain via FQDN regex
            - Rejects IPv4 addresses and single-label hosts

        Args:
            line: Raw text line from feed payload

        Returns:
            Normalized lowercase FQDN if valid, None otherwise
        """
        line = line.strip()

        # Ignore empty lines and comment headers
        if not line or line.startswith("#"):
            return None

        # Attempt extracting valid FQDN match
        match = FQDN_REGEX.search(line)
        if not match:
            return None

        raw = match.group(0)

        # Strip protocol scheme if present
        raw = re.sub(r"^https?://", "", raw)

        # Extract hostname only (discard path/query)
        domain = raw.split("/")[0].strip().lower()

        # Reject pure IP addresses
        if IPV4_REGEX.match(domain):
            return None

        # Reject domains shorter than 4 characters or without dots
        if len(domain) < 4 or "." not in domain:
            return None

        # Reject localhost and loopback domains
        if domain in ("localhost", "localhost.localdomain"):
            return None

        return domain

    def fetch(
        self,
        session: requests.Session,
        logger: logging.Logger,
    ) -> FeedResult:
        """Downloads and processes threat feed with automated retries.

        Args:
            session: Reusable HTTP connection pool (requests.Session)
            logger:  Logger instance for structured tracing

        Returns:
            FeedResult populated with extracted IoC entries and performance metrics
        """
        result = FeedResult(source_name=self.source_tag)
        start_time = time.monotonic()

        for attempt in range(1, REQUEST_RETRY_ATTEMPTS + 1):
            try:
                logger.info(
                    "  [%s] Fetching (attempt %d/%d): %s",
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
                    if HAS_ML_EXTRACTOR:
                        domain = normalize_domain_candidate(line)
                    else:
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
                    "[%s] Processed: %d lines -> %d valid domains",
                    self.source_tag, result.domains_found, result.domains_valid,
                )
                break  # Successful fetch, exit retry loop

            except requests.exceptions.Timeout:
                result.error = f"Timeout after {REQUEST_TIMEOUT_SECONDS}s"
                logger.warning(
                    "[%s] Timeout on attempt %d/%d",
                    self.source_tag, attempt, REQUEST_RETRY_ATTEMPTS,
                )
                if attempt < REQUEST_RETRY_ATTEMPTS:
                    time.sleep(REQUEST_RETRY_DELAY_SECONDS)

            except requests.exceptions.ConnectionError as exc:
                result.error = f"Connection error: {exc}"
                logger.warning(
                    "[%s] Connection error on attempt %d/%d: %s",
                    self.source_tag, attempt, REQUEST_RETRY_ATTEMPTS, exc,
                )
                if attempt < REQUEST_RETRY_ATTEMPTS:
                    time.sleep(REQUEST_RETRY_DELAY_SECONDS)

            except requests.exceptions.HTTPError as exc:
                result.error = f"HTTP {exc.response.status_code}: {exc}"
                logger.error(
                    "[%s] HTTP Error %s — skipping feed",
                    self.source_tag, exc.response.status_code,
                )
                break  # Permanent HTTP error, do not retry

            except requests.exceptions.RequestException as exc:
                result.error = str(exc)
                logger.error("[%s] Unexpected request error: %s", self.source_tag, exc)
                break

        result.duration_seconds = time.monotonic() - start_time
        return result


class BaseApiFeed(ABC):
    """Abstract base class for authenticated API-based threat feeds.

    Provides a template for authenticated endpoints (ThreatFox, AlienVault, AbuseIPDB).
    To implement:
        1. Define `source_tag`, `category`, and `api_key_env_var`
        2. Implement `fetch_raw(session, api_key)` with endpoint logic
        3. Implement `parse_response(raw)` returning normalized IoCEntry objects
        4. Append instance to ACTIVE_API_FEEDS registry
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
        """Environment variable name containing the authentication API key."""
        ...

    @abstractmethod
    def fetch_raw(self, session: requests.Session, api_key: str) -> list:
        """Performs authenticated HTTP request returning raw feed payload."""
        ...

    @abstractmethod
    def parse_response(self, raw: list) -> list:
        """Parses raw API response payload into normalized IoCEntry items."""
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
# IMPLEMENTATIONS — ACTIVE PLAIN-TEXT THREAT FEEDS
# ---------------------------------------------------------------------------

class URLhausFeed(BaseTextFeed):
    """URLhaus (abuse.ch) — Active malware distribution URL feed.

    Format: One URL per line with comment headers (#).
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
        """URLhaus emits lines formatted as: http://malware.com/payload.exe"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        return super().parse_line(line)


class FeodoTrackerFeed(BaseTextFeed):
    """Feodo Tracker (abuse.ch) — Botnet C2 servers (Emotet, TrickBot, QakBot).

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
    """OpenPhish — Free community feed of active phishing URLs.

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
    """Spamhaus DROP (Don't Route Or Peer) — Criminal-controlled IP/domain ranges.

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
        """SpamHaus DROP emits CIDRs and domains (e.g. 1.2.3.0/24 ; SBL123)."""
        line = line.strip()
        if not line or line.startswith(";"):
            return None
        line = line.split(";")[0].strip()
        return super().parse_line(line)


class SpamHausEDROPFeed(BaseTextFeed):
    """Spamhaus EDROP (Extended DROP) — Secondary criminal-controlled ranges.

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
        line = line.strip()
        if not line or line.startswith(";"):
            return None
        line = line.split(";")[0].strip()
        return super().parse_line(line)


class CINSArmyFeed(BaseTextFeed):
    """CINS Army List (Sentinel IPS) — Active malicious reputation IPs and hosts.

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
# FUTURE IMPLEMENTATIONS — API-BASED THREAT FEEDS (COMMENTED SKELETONS)
# ---------------------------------------------------------------------------
#
# DEVELOPER NOTE:
# Uncomment and implement each class when API keys are available.
# Export corresponding environment variables prior to execution:
#   export THREATFOX_API_KEY="..."
#   export OTX_API_KEY="..."
#   export ABUSEIPDB_API_KEY="..."


# ---------------------------------------------------------------------------
# ACTIVE FEED REGISTRIES
# ---------------------------------------------------------------------------

#: Active text feeds — append/remove instances as needed
ACTIVE_TEXT_FEEDS: list = [
    URLhausFeed(),
    FeodoTrackerFeed(),
    OpenPhishFeed(),
    SpamHausDROPFeed(),
    SpamHausEDROPFeed(),
    CINSArmyFeed(),
]

#: Active API feeds — uncomment classes above and add here
ACTIVE_API_FEEDS: list = [
    # ThreatFoxFeed(),
    # AlienVaultOTXFeed(),
    # AbuseIPDBFeed(),
    # MalwareBazaarFeed(),
]


# ---------------------------------------------------------------------------
# DOWNLOAD ENGINE — ORCHESTRATOR
# ---------------------------------------------------------------------------

def collect_all_iocs(logger: logging.Logger) -> tuple:
    """Executes all active feeds and consolidates unique threat IoCs.

    Uses a shared requests.Session for TCP connection pooling, improving
    performance across multiple remote feed downloads.

    Args:
        logger: Main logger instance

    Returns:
        Tuple (unique_domains: set, all_iocs: list[IoCEntry])
    """
    all_iocs: list = []
    unique_domains: set = set()

    session = requests.Session()
    session.headers.update(HTTP_HEADERS)

    all_feeds = ACTIVE_TEXT_FEEDS + ACTIVE_API_FEEDS
    total_feeds = len(all_feeds)

    logger.info("=" * 65)
    logger.info("DNS Sinkhole — Threat Intelligence Sync Engine v2.0")
    logger.info("Active feeds: %d | Sinkhole IP: %s", total_feeds, SINKHOLE_IP)
    logger.info("=" * 65)

    for idx, feed in enumerate(all_feeds, start=1):
        logger.info("-" * 65)
        logger.info("[%d/%d] Feed: %s", idx, total_feeds, feed.source_tag)
        result: FeedResult = feed.fetch(session, logger)

        if result.error and not result.iocs:
            logger.warning(
                "[%s] Skipped with error: %s", feed.source_tag, result.error
            )
            continue

        for ioc in result.iocs:
            if ioc.domain not in unique_domains:
                unique_domains.add(ioc.domain)
                all_iocs.append(ioc)

    session.close()

    # Apply allowlist filtering (ML/Threat Intel) to avoid false positives
    if HAS_ML_EXTRACTOR:
        logger.info("-" * 65)
        logger.info("Applying Machine Learning / Threat Intel Allowlist...")
        try:
            data_dir = DATABASE_PATH.parent
            extractor = DomainExtractor(auto_load_data_dir=True, data_dir=data_dir)
            filtered_iocs = []
            allowed_count = 0
            for ioc in all_iocs:
                is_allowed, rule = extractor.allowlist.is_allowed(ioc.domain)
                if is_allowed:
                    allowed_count += 1
                    logger.debug("Allowlist excluded: %s (rule: %s)", ioc.domain, rule)
                else:
                    filtered_iocs.append(ioc)

            all_iocs = filtered_iocs
            unique_domains = {ioc.domain for ioc in all_iocs}
            logger.info("Allowlist filtered out %d legitimate/false-positive domains.", allowed_count)
        except Exception as exc:
            logger.warning("Failed to apply allowlist: %s — proceeding with raw data.", exc)

    logger.info("=" * 65)
    logger.info("Total consolidated unique domains: %d", len(unique_domains))

    return unique_domains, all_iocs


# ---------------------------------------------------------------------------
# UNBOUND CONFIGURATION GENERATOR
# ---------------------------------------------------------------------------

def generate_unbound_config(
    domains: set,
    sinkhole_ip: str,
    output_path: Path,
    logger: logging.Logger,
    dry_run: bool = False,
) -> None:
    """Generates and writes Unbound DNS sinkhole configuration file.

    Format required by Unbound:
        server:
            local-zone: "domain.com" redirect
            local-data: "domain.com A 10.0.2.15"

    Args:
        domains:     Set of unique FQDNs to block
        sinkhole_ip: Destination IP for sinkhole redirection
        output_path: Destination path for Unbound configuration
        logger:      Logger instance
        dry_run:     If True, prints preview without writing to disk
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header = (
        f"# ============================================================\n"
        f"# DNS Sinkhole — Threat Intelligence Block List\n"
        f"# Automatically generated by sync_iocs.py\n"
        f"# Timestamp: {timestamp}\n"
        f"# Total domains: {len(domains)}\n"
        f"# Sinkhole IP: {sinkhole_ip}\n"
        f"# DO NOT EDIT MANUALLY — Overwritten on each sync cycle!\n"
        f"# ============================================================\n\n"
        f"server:\n"
    )

    lines = [header]
    for domain in sorted(domains):
        lines.append(f'    local-zone: "{domain}" redirect\n')
        lines.append(f'    local-data: "{domain} A {sinkhole_ip}"\n')

    config_content = "".join(lines)

    if dry_run:
        logger.info(
            "[DRY-RUN] Unbound configuration preview (first 40 lines):\n%s",
            "\n".join(config_content.splitlines()[:40]),
        )
        logger.info("[DRY-RUN] File NOT written. Target path would be: %s", output_path)
        return

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(config_content, encoding="utf-8")
        logger.info(
            "Unbound configuration written: %s (%d domains)",
            output_path, len(domains),
        )
    except PermissionError as exc:
        logger.critical(
            "PERMISSION DENIED writing to %s\n"
            "Run script with: sudo python3 sync_iocs.py\n"
            "Detail: %s",
            output_path, exc,
        )
        sys.exit(1)
    except OSError as exc:
        logger.critical("I/O error writing configuration: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# SQLITE DATABASE PERSISTENCE
# ---------------------------------------------------------------------------

def persist_iocs_to_database(
    iocs: list,
    db_path: Path,
    logger: logging.Logger,
    dry_run: bool = False,
) -> None:
    """Persists threat IoCs to SQLite database in atomic transaction.

    Operations:
        1. Ensures `ioc_entries` table exists
        2. Clears previous entries (full synchronization)
        3. Inserts all newly extracted domains in batch
        4. Rolls back on error

    Args:
        iocs:     List of IoCEntry items with metadata
        db_path:  Absolute path to SQLite database file
        logger:   Logger instance
        dry_run:  If True, simulates without modifying database
    """
    if dry_run:
        logger.info(
            "[DRY-RUN] Database NOT modified. "
            "Would insert %d records in %s", len(iocs), db_path,
        )
        return

    if not db_path.exists():
        logger.warning(
            "Database file not found at %s. Ensure FastAPI was initialized at least once.",
            db_path,
        )

    try:
        conn = sqlite3.connect(
            str(db_path),
            timeout=15.0,
            check_same_thread=False,
        )

        # Configure WAL mode and concurrency pragmas
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")

        with conn:  # Atomic transaction — auto commit or rollback
            cursor = conn.cursor()

            # 1. Ensure table exists (idempotent)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ioc_entries (
                    domain     TEXT PRIMARY KEY,
                    status     TEXT NOT NULL DEFAULT 'blocked',
                    category   TEXT DEFAULT 'Malware / C2',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Clear old entries (full sync)
            cursor.execute("DELETE FROM ioc_entries;")
            deleted_count = cursor.rowcount
            logger.info("DB: %d old entries removed", deleted_count)

            # 3. Format category as 'Source | Category'
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

            # 4. Batch insert for optimal performance
            cursor.executemany(
                """
                INSERT OR REPLACE INTO ioc_entries
                    (domain, status, category, created_at)
                VALUES (?, ?, ?, ?);
                """,
                records,
            )
            logger.info("DB: %d IoCs inserted into %s", len(records), db_path)

        conn.close()

    except sqlite3.OperationalError as exc:
        err_str = str(exc).lower()
        if "unable to open database" in err_str:
            logger.error(
                "DB: Unable to open database at %s. Verify permissions. Detail: %s",
                db_path, exc,
            )
        elif "database is locked" in err_str:
            logger.error(
                "DB: Database is locked by another process. Detail: %s", exc
            )
        else:
            logger.error("DB: SQLite operational error: %s", exc)

    except sqlite3.DatabaseError as exc:
        logger.error("DB: Database integrity error: %s", exc)

    except PermissionError as exc:
        logger.critical(
            "DB: PERMISSION DENIED accessing %s. Run with sudo: %s",
            db_path, exc,
        )


# ---------------------------------------------------------------------------
# UNBOUND SERVICE RESTART
# ---------------------------------------------------------------------------

def restart_unbound(logger: logging.Logger, dry_run: bool = False) -> bool:
    """Restarts Unbound service via systemctl to apply updated zone rules.

    Safety workflow:
        1. Validates configuration syntax using `sudo unbound-checkconf`
        2. Only restarts if exit code is 0 (syntax valid)
        3. Prints exact error without disrupting running DNS resolver on failure

    Args:
        logger:  Logger instance
        dry_run: If True, simulates without executing command

    Returns:
        True if restart succeeded, False otherwise
    """
    if dry_run:
        logger.info(
            "[DRY-RUN] Commands NOT executed: "
            "unbound-checkconf + systemctl restart unbound"
        )
        return True

    # 1. Validate configuration BEFORE restarting (safety gate)
    logger.info("Validating Unbound configuration (sudo unbound-checkconf)...")
    try:
        check_result = subprocess.run(
            ["sudo", "unbound-checkconf"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if check_result.returncode != 0:
            logger.critical(
                "Unbound configuration INVALID — Restart CANCELLED!\n"
                "DNS service unaffected (active protection).\n"
                "Output: %s\n"
                "Errors: %s",
                check_result.stdout.strip(),
                check_result.stderr.strip(),
            )
            return False
        logger.info(
            "Valid configuration: %s",
            check_result.stdout.strip() or "OK",
        )
    except FileNotFoundError:
        logger.warning("`unbound-checkconf` not found — syntax validation skipped.")
    except subprocess.TimeoutExpired:
        logger.warning("Timeout validating configuration — continuing...")

    # 2. Restart service (only if validation passed)
    logger.info("Restarting Unbound service...")
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "unbound"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("Unbound restarted successfully.")
            return True
        else:
            logger.error(
                "Failed to restart Unbound (exit code: %d)\n"
                "stdout: %s\n"
                "stderr: %s",
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
            return False
    except FileNotFoundError:
        logger.error(
            "`systemctl` not found. "
            "This script requires a Linux system with systemd."
        )
        return False
    except subprocess.TimeoutExpired:
        logger.error(
            "Timeout restarting Unbound (>30s). "
            "Check status with: sudo systemctl status unbound"
        )
        return False
    except PermissionError:
        logger.critical(
            "PERMISSION DENIED executing systemctl.\n"
            "Run script with: sudo python3 sync_iocs.py"
        )
        return False


# ---------------------------------------------------------------------------
# PRIVILEGE VERIFICATION
# ---------------------------------------------------------------------------

def check_root_privileges(logger: logging.Logger, dry_run: bool = False) -> None:
    """Verifies that script is running with root / administrative privileges.

    Required for:
        - Writing to /etc/unbound/unbound.conf.d/
        - Executing systemctl restart unbound

    In dry-run mode or Windows (dev environment), a warning is logged instead.
    """
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = (os.geteuid() == 0)
    else:
        # Windows platform (development/testing environment)
        try:
            import ctypes
            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_root = False

    if not is_root:
        if dry_run or os.name == "nt":
            logger.warning(
                "Running without root/admin privileges — Allowed in --dry-run or Windows development mode.\n"
                "In Ubuntu production, run with: sudo python3 sync_iocs.py"
            )
        else:
            logger.critical(
                "This script requires root privileges.\n"
                "Run with: sudo python3 sync_iocs.py"
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# ENTRYPOINT — MAIN
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Defines and parses command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="sync_iocs.py",
        description=(
            "DNS Sinkhole Threat Intelligence Sync Engine — "
            "Synchronizes OSINT IoCs with Unbound and SQLite"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 sync_iocs.py                # Standard sync
  sudo python3 sync_iocs.py --dry-run      # Dry-run simulation
  sudo python3 sync_iocs.py --verbose      # Verbose debug logging
  sudo python3 sync_iocs.py --no-restart   # Update configs without restarting Unbound
  sudo python3 sync_iocs.py --refresh-ip   # Fast-path IP update in threat_feed.conf
        """,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulates execution without writing files, database records, or restarting services.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enables DEBUG logging for detailed diagnostics.",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Applies configuration but skips restarting Unbound DNS.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=DATABASE_PATH,
        help=f"Path to SQLite database file. Default: {DATABASE_PATH}",
    )
    parser.add_argument(
        "--conf-path",
        type=Path,
        default=UNBOUND_CONF_PATH,
        help=f"Path to Unbound configuration file. Default: {UNBOUND_CONF_PATH}",
    )
    parser.add_argument(
        "--sinkhole-ip",
        type=str,
        default=SINKHOLE_IP,
        help=f"Sinkhole destination IP. Default: auto-detected ({SINKHOLE_IP})",
    )
    parser.add_argument(
        "--refresh-ip",
        action="store_true",
        help=(
            "Fast mode: rewrites threat_feed.conf with current active IP "
            "without re-downloading OSINT threat feeds from the internet. "
            "Ideal when switching Wi-Fi or DHCP leases."
        ),
    )
    return parser.parse_args()


def refresh_sinkhole_ip(
    conf_path: Path,
    new_ip: str,
    logger: logging.Logger,
    dry_run: bool = False,
) -> bool:
    """Quickly rewrites sinkhole IP in existing threat_feed.conf without re-downloading feeds.

    Reads existing file, replaces previous IP occurrences with the new IP,
    validates with unbound-checkconf, and reloads Unbound.

    Args:
        conf_path: Path to threat_feed.conf
        new_ip:    Newly detected local IP
        logger:    Logger instance
        dry_run:   If True, simulates without writing to disk

    Returns:
        True if successfully completed, False otherwise
    """
    if not conf_path.exists():
        logger.error(
            "File %s not found. Perform full initial sync: sudo python3 sync_iocs.py",
            conf_path,
        )
        return False

    content = conf_path.read_text(encoding="utf-8")

    # Extract old IP from header comment ('# Sinkhole IP: x.x.x.x')
    old_ip_match = re.search(r"# Sinkhole IP:\s*(\d+\.\d+\.\d+\.\d+)", content)
    if old_ip_match:
        old_ip = old_ip_match.group(1)
    else:
        # Fallback: extract IP from first local-data entry
        data_match = re.search(r'local-data:.*?A\s+(\d+\.\d+\.\d+\.\d+)', content)
        if data_match:
            old_ip = data_match.group(1)
        else:
            logger.error("Unable to detect previous IP in %s", conf_path)
            return False

    if old_ip == new_ip:
        logger.info(
            "IP already up-to-date (%s). No changes needed.", new_ip
        )
        return True

    logger.info("Updating Sinkhole IP: %s -> %s", old_ip, new_ip)

    # Replace old IP with new IP
    new_content = content.replace(old_ip, new_ip)

    # Update timestamp header
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    new_content = re.sub(
        r"# Timestamp:.*",
        f"# Timestamp: {timestamp}",
        new_content,
    )

    if dry_run:
        logger.info("[DRY-RUN] IP would be updated from %s to %s in %s", old_ip, new_ip, conf_path)
        return True

    try:
        conf_path.write_text(new_content, encoding="utf-8")
        logger.info("Configuration %s updated with IP %s", conf_path, new_ip)
    except (PermissionError, OSError) as exc:
        logger.critical("Error writing to %s: %s", conf_path, exc)
        return False

    # Validate and reload Unbound
    return restart_unbound(logger=logger, dry_run=dry_run)


def main() -> None:
    """Main execution entrypoint for threat intelligence synchronization.

    Execution lifecycle:
        1. Parse CLI arguments
        2. Configure logging
        3. Check root / administrator privileges
        4. If --refresh-ip: fast-path IP update and restart
        5. Fetch and normalize OSINT threat feeds
        6. Apply allowlist filtering (false positive prevention)
        7. Generate Unbound sinkhole configuration file
        8. Persist IoCs into SQLite database (WAL mode)
        9. Restart Unbound DNS service
        10. Output execution telemetry summary
    """
    args = parse_arguments()
    logger = setup_logging(verbose=args.verbose)

    # --- Privilege check ---
    check_root_privileges(logger, dry_run=args.dry_run)

    if args.dry_run:
        logger.info("DRY-RUN MODE ACTIVE — No persistent changes will be made.")

    # --- Fast-path: Update IP only ---
    if args.refresh_ip:
        logger.info("=" * 65)
        logger.info("REFRESH-IP MODE — Fast Sinkhole IP Update")
        logger.info("Detected IP: %s", args.sinkhole_ip)
        logger.info("=" * 65)
        success = refresh_sinkhole_ip(
            conf_path=args.conf_path,
            new_ip=args.sinkhole_ip,
            logger=logger,
            dry_run=args.dry_run,
        )
        sys.exit(0 if success else 1)

    start_time = time.monotonic()

    # --- Phase 1: Threat feed ingestion ---
    unique_domains, all_iocs = collect_all_iocs(logger)

    if not unique_domains:
        logger.error(
            "No valid threat domains retrieved from active sources.\n"
            "Verify network connectivity and retry."
        )
        sys.exit(1)

    # --- Phase 2: Unbound configuration generation ---
    logger.info("-" * 65)
    logger.info("Generating Unbound configuration...")
    generate_unbound_config(
        domains=unique_domains,
        sinkhole_ip=args.sinkhole_ip,
        output_path=args.conf_path,
        logger=logger,
        dry_run=args.dry_run,
    )

    # --- Phase 3: SQLite persistence ---
    logger.info("-" * 65)
    logger.info("Persisting IoCs to SQLite database...")
    persist_iocs_to_database(
        iocs=all_iocs,
        db_path=args.db_path,
        logger=logger,
        dry_run=args.dry_run,
    )

    # --- Phase 4: Unbound reload ---
    if not args.no_restart:
        logger.info("-" * 65)
        restart_unbound(logger=logger, dry_run=args.dry_run)
    else:
        logger.info("Unbound reload skipped (--no-restart).")

    # --- Telemetry Summary ---
    elapsed = time.monotonic() - start_time
    logger.info("=" * 65)
    logger.info("Synchronization completed in %.2f seconds", elapsed)
    logger.info("  Unique domains processed : %d", len(unique_domains))
    logger.info("  Active feeds             : %d", len(ACTIVE_TEXT_FEEDS + ACTIVE_API_FEEDS))
    logger.info("  Unbound configuration    : %s", args.conf_path)
    logger.info("  Database path            : %s", args.db_path)
    logger.info("=" * 65)


if __name__ == "__main__":
    main()
