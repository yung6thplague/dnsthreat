"""Configuration module for DNS Threat Blocker & Sinkhole Web Layer.

Handles absolute path resolutions via pathlib, dynamic IP detection,
centralized SSL/TLS certificate management, and data directory initialization.
"""

import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

# Base directory (/dns_threat_blocker root)
BASE_DIR: Path = Path(__file__).resolve().parent.parent

# Application directories
APP_DIR: Path = BASE_DIR / "app"
TEMPLATES_DIR: Path = APP_DIR / "templates"
DATA_DIR: Path = BASE_DIR / "data"

# Guarantee data directory exists (dynamically generated if missing)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database and allowlist file paths
DATABASE_PATH: Path = DATA_DIR / "telemetry.db"
ALLOWLIST_PATH: Path = DATA_DIR / "allowlist.txt"

# -----------------------------------------------------------------------------
# SSL / TLS Centralized Configuration
# Supports environment variables (CERTS_DIR, SSL_KEYFILE, SSL_CERTFILE) with
# automatic fallback relative to BASE_DIR / "certs".
# -----------------------------------------------------------------------------
CERTS_DIR: Path = Path(os.getenv("CERTS_DIR", str(BASE_DIR / "certs")))
SSL_KEY_PATH: Path = Path(os.getenv("SSL_KEYFILE", str(CERTS_DIR / "sinkhole.key")))
SSL_CERT_PATH: Path = Path(os.getenv("SSL_CERTFILE", str(CERTS_DIR / "sinkhole.crt")))

# Server & Application metadata
APP_TITLE: str = "DNS Threat Blocker & Sinkhole Telemetry"
APP_DESCRIPTION: str = "Unbound DNS Sinkhole Web Interception & SOC Telemetry Layer"
APP_VERSION: str = "1.2.0"


def get_local_ip() -> str:
    """Dynamically detects the local IPv4 address of the active network interface.

    Uses the native socket module to open a UDP socket towards 8.8.8.8:80.
    The socket does NOT transmit real traffic (UDP is connectionless); it merely
    prompts the kernel to select the network interface routing outbound traffic,
    retrieving the local IP assigned by the current network interface.

    Returns:
        The IPv4 address of the active interface (e.g., '192.168.1.102').
        Falls back safely to '127.0.0.1' on error (no network connectivity).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Does not send packets; connect() on UDP only binds routing path
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except (OSError, socket.error):
        return "127.0.0.1"


def get_local_ipv6() -> Optional[str]:
    """Dynamically detects the global/ULA IPv6 address of the active interface.

    Uses a connectionless UDP socket pointing towards 2001:4860:4860::8888.
    Discards loopback (::1) and non-routable link-local addresses (fe80::/10).

    Returns:
        Global IPv6 address or None if IPv6 connectivity is unavailable.
    """
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 80))
            ip = s.getsockname()[0]
            if ip.startswith("fe80:") or ip == "::1":
                return None
            return ip
    except (OSError, socket.error):
        return None


def is_ssl_configured() -> bool:
    """Checks whether SSL/TLS private key and certificate files exist and are non-empty."""
    try:
        return (
            SSL_KEY_PATH.is_file()
            and SSL_CERT_PATH.is_file()
            and SSL_KEY_PATH.stat().st_size > 0
            and SSL_CERT_PATH.stat().st_size > 0
        )
    except OSError:
        return False


def get_ssl_uvicorn_args() -> List[str]:
    """Returns Uvicorn CLI arguments for SSL if certificates are configured."""
    if is_ssl_configured():
        return [
            "--ssl-keyfile", str(SSL_KEY_PATH),
            "--ssl-certfile", str(SSL_CERT_PATH)
        ]
    return []


def generate_self_signed_cert(
    domain: Optional[str] = None,
    days: int = 365,
    force: bool = False
) -> Tuple[bool, str]:
    """Generates a self-signed SSL/TLS certificate (RSA 2048) in non-interactive batch mode.
    
    Automatically creates the certificates directory if missing and enforces
    secure permissions (chmod 600 key / 644 crt on POSIX systems).
    """
    if is_ssl_configured() and not force:
        return True, f"Certificates already configured in {CERTS_DIR}"

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        return False, "The 'openssl' binary was not found in system PATH."

    current_ip = get_local_ip()
    cn_domain = domain or current_ip

    cmd = [
        openssl_bin, "req", "-x509", "-nodes", "-days", str(days),
        "-newkey", "rsa:2048",
        "-keyout", str(SSL_KEY_PATH),
        "-out", str(SSL_CERT_PATH),
        "-subj", f"/C=PT/ST=SecOps/L=SOC/O=DNS-Threat-Sinkhole/CN={cn_domain}",
        "-addext", f"subjectAltName=DNS:*,IP:{current_ip},DNS:sinkhole.local"
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            if os.name != "nt":
                try:
                    os.chmod(SSL_KEY_PATH, 0o600)
                    os.chmod(SSL_CERT_PATH, 0o644)
                except OSError:
                    pass
            return True, f"Certificate successfully generated in {CERTS_DIR} (CN: {cn_domain})"
        else:
            return False, f"OpenSSL error ({res.returncode}): {res.stderr.strip()}"
    except Exception as exc:
        return False, f"Error generating certificates: {exc}"
