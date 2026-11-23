"""Database module for DNS Threat Blocker.

Uses native SQLite with WAL (Write-Ahead Logging) mode enabled for high concurrency
and robust multi-client logging during DNS sinkhole operations.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple
from app.config import ALLOWLIST_PATH, DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    """Creates and configures a SQLite connection with WAL mode and row factory."""
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=10.0,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    # Configure SQLite for high concurrency and performance
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database access, committing transactions or rolling back on error."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initializes SQLite tables and indexes.

    Creates:
    - access_logs: records intercepted requests (id, domain_requested, client_ip, user_agent, timestamp)
    - ioc_entries: threat intelligence database (domain, status, category, added_at)
    """
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Access Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_requested TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. IoC Entries Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_entries (
                domain TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'blocked',
                category TEXT DEFAULT 'Malware / C2',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. High-performance Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON access_logs(domain_requested);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_client ON access_logs(client_ip);")

        # 4. Populate default IoCs if empty (Threat Intelligence seeds)
        cursor.execute("SELECT COUNT(*) as count FROM ioc_entries;")
        if cursor.fetchone()["count"] == 0:
            seed_iocs = [
                ("malware-traffic-dist.xyz", "blocked", "Trojan / Dropper"),
                ("c2-beacon.darknet-command.ru", "blocked", "C2 Infrastructure"),
                ("phish-banking-login.top", "blocked", "Credential Phishing"),
                ("crypto-drainer-secure.online", "blocked", "Crypto Stealer"),
                ("botnet-update-sync.cc", "blocked", "Botnet Node"),
                ("ransom-payment-portal.onion.pet", "blocked", "Ransomware Exfil"),
                ("spyware-telemetry-cdn.info", "blocked", "Data Exfiltration")
            ]
            cursor.executemany(
                "INSERT OR IGNORE INTO ioc_entries (domain, status, category) VALUES (?, ?, ?);",
                seed_iocs
            )


def log_intercepted_access(domain_requested: str, client_ip: str, user_agent: Optional[str]) -> int:
    """Logs an intercepted DNS request attempt into access_logs and returns the generated incident ID."""
    clean_domain = (domain_requested or "unknown-domain").strip().lower()
    clean_ip = (client_ip or "0.0.0.0").strip()
    clean_ua = (user_agent or "Unknown Client").strip()
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO access_logs (domain_requested, client_ip, user_agent, timestamp)
            VALUES (?, ?, ?, ?);
            """,
            (clean_domain, clean_ip, clean_ua, utc_now)
        )
        return cursor.lastrowid


def get_admin_metrics() -> Dict[str, Any]:
    """Calculates all key metrics for the SOC Admin Telemetry Dashboard:

    - Total absolute blocks
    - Top 5 most requested blocked domains
    - Last 10 audit logs
    - Additional SOC health stats (unique domains, unique victims, active IoCs)
    """
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Total absolute blocks
        cursor.execute("SELECT COUNT(*) as total FROM access_logs;")
        total_blocks: int = cursor.fetchone()["total"]

        # 2. Unique blocked domains intercepted
        cursor.execute("SELECT COUNT(DISTINCT domain_requested) as total FROM access_logs;")
        unique_domains: int = cursor.fetchone()["total"]

        # 3. Unique client IPs intercepted
        cursor.execute("SELECT COUNT(DISTINCT client_ip) as total FROM access_logs;")
        unique_clients: int = cursor.fetchone()["total"]

        # 4. Total active IoC entries
        cursor.execute("SELECT COUNT(*) as total FROM ioc_entries;")
        total_iocs: int = cursor.fetchone()["total"]

        # 5. Top 5 most accessed blocked domains
        cursor.execute("""
            SELECT domain_requested, COUNT(*) as hit_count
            FROM access_logs
            GROUP BY domain_requested
            ORDER BY hit_count DESC
            LIMIT 5;
        """)
        top_domains_rows = cursor.fetchall()
        top_domains = [
            {
                "domain": row["domain_requested"],
                "count": row["hit_count"],
                "percentage": round((row["hit_count"] / total_blocks * 100), 1) if total_blocks > 0 else 0
            }
            for row in top_domains_rows
        ]

        # 6. Last 10 audit logs
        cursor.execute("""
            SELECT id, domain_requested, client_ip, user_agent, timestamp
            FROM access_logs
            ORDER BY id DESC
            LIMIT 10;
        """)
        recent_logs_rows = cursor.fetchall()
        recent_logs = [dict(row) for row in recent_logs_rows]

        return {
            "total_blocks": total_blocks,
            "unique_domains": unique_domains,
            "unique_clients": unique_clients,
            "total_iocs": total_iocs,
            "top_domains": top_domains,
            "recent_logs": recent_logs,
        }


def unblock_ioc(domain: str, add_to_allowlist: bool = True) -> Dict[str, Any]:
    """Unblocks an IoC domain (Rollback mechanism for False Positives).

    Operations:
    1. Removes domain from the active `ioc_entries` table in SQLite.
    2. Appends the domain to `data/allowlist.txt` to prevent automated re-ingestion
       by threat feeds during subsequent sync cycles.
    3. Returns operation details and count of affected records.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return {"success": False, "domain": domain, "error": "Domínio inválido ou vazio."}

    deleted_count = 0
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ioc_entries WHERE domain = ?;", (clean_domain,))
        deleted_count = cursor.rowcount

    added_to_allowlist = False
    if add_to_allowlist:
        try:
            # Ensure allowlist file exists
            if not ALLOWLIST_PATH.exists():
                ALLOWLIST_PATH.touch()

            existing_lines = ALLOWLIST_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
            cleaned_existing = {line.strip().lower() for line in existing_lines if line.strip() and not line.startswith("#")}

            if clean_domain not in cleaned_existing:
                with ALLOWLIST_PATH.open("a", encoding="utf-8") as f:
                    f.write(f"{clean_domain}  # Unblocked via SOC Console/Dashboard\n")
                added_to_allowlist = True
        except Exception as e:
            # Non-blocking error for allowlist file write
            pass

    return {
        "success": True,
        "domain": clean_domain,
        "deleted_count": deleted_count,
        "added_to_allowlist": added_to_allowlist,
        "message": f"Domínio '{clean_domain}' desbloqueado com sucesso."
    }


def get_ioc_entries(limit: int = 50, offset: int = 0, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves paginated and filtered list of active IoC threat entries."""
    with get_db() as conn:
        cursor = conn.cursor()
        if search and search.strip():
            query_str = f"%{search.strip().lower()}%"
            cursor.execute(
                """
                SELECT domain, status, category, created_at
                FROM ioc_entries
                WHERE domain LIKE ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (query_str, limit, offset)
            )
        else:
            cursor.execute(
                """
                SELECT domain, status, category, created_at
                FROM ioc_entries
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset)
            )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def add_ioc_entry(domain: str, category: str = "Manual / SOC") -> bool:
    """Manually registers an IoC into the database."""
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return False
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO ioc_entries (domain, status, category)
            VALUES (?, 'blocked', ?);
            """,
            (clean_domain, category)
        )
        return cursor.rowcount > 0

