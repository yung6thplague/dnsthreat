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
# Suporta variáveis de ambiente (CERTS_DIR, SSL_KEYFILE, SSL_CERTFILE) com
# fallback automático relativo a BASE_DIR / "certs".
# -----------------------------------------------------------------------------
CERTS_DIR: Path = Path(os.getenv("CERTS_DIR", str(BASE_DIR / "certs")))
SSL_KEY_PATH: Path = Path(os.getenv("SSL_KEYFILE", str(CERTS_DIR / "sinkhole.key")))
SSL_CERT_PATH: Path = Path(os.getenv("SSL_CERTFILE", str(CERTS_DIR / "sinkhole.crt")))

# Server & Application metadata
APP_TITLE: str = "DNS Threat Blocker & Sinkhole Telemetry"
APP_DESCRIPTION: str = "Unbound DNS Sinkhole Web Interception & SOC Telemetry Layer"
APP_VERSION: str = "1.2.0"


def get_local_ip() -> str:
    """Deteta dinamicamente o IP IPv4 local da interface de rede ativa.

    Utiliza o módulo nativo socket para abrir um socket UDP para 8.8.8.8:80.
    O socket NÃO envia tráfego real (UDP é connectionless); apenas força o
    kernel a selecionar a interface de rede com rota para o exterior,
    revelando o IP local atribuído pela rede Wi-Fi/Ethernet atual.

    Returns:
        O endereço IPv4 da interface ativa (ex: '192.168.1.102').
        Em caso de falha (sem rede), retorna '127.0.0.1' como fallback seguro.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Não envia dados; connect() em UDP apenas define a rota
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except (OSError, socket.error):
        return "127.0.0.1"


def is_ssl_configured() -> bool:
    """Verifica se os ficheiros de chave privada e certificado SSL/TLS existem e são válidos."""
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
    """Retorna os argumentos CLI do Uvicorn para SSL se os certificados existirem."""
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
    """Gera um certificado SSL auto-assinado (RSA 2048) em modo batch/não interativo.
    
    Cria automaticamente o diretório de certificados caso não exista e define
    as permissões seguras recomendadas (chmod 600 key / 644 crt em sistemas POSIX).
    """
    if is_ssl_configured() and not force:
        return True, f"Certificados já configurados em {CERTS_DIR}"

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        return False, "O utilitário 'openssl' não foi encontrado no PATH do sistema."

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
            return True, f"Certificado gerado com sucesso em {CERTS_DIR} (CN: {cn_domain})"
        else:
            return False, f"Falha no openssl ({res.returncode}): {res.stderr.strip()}"
    except Exception as exc:
        return False, f"Erro ao gerar certificados: {exc}"
