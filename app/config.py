"""Configuration module for DNS Threat Blocker & Sinkhole Web Layer.

Handles absolute path resolutions via pathlib, dynamic IP detection,
and guarantees data directories exist.
"""

import socket
from pathlib import Path

# Base directory (/dns_threat_blocker root)
BASE_DIR: Path = Path(__file__).resolve().parent.parent

# Application directories
APP_DIR: Path = BASE_DIR / "app"
TEMPLATES_DIR: Path = APP_DIR / "templates"
DATA_DIR: Path = BASE_DIR / "data"

# Guarantee data directory exists (dynamically generated if missing)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database file path
DATABASE_PATH: Path = DATA_DIR / "telemetry.db"

# Server & Application metadata
APP_TITLE: str = "DNS Threat Blocker & Sinkhole Telemetry"
APP_DESCRIPTION: str = "Unbound DNS Sinkhole Web Interception & SOC Telemetry Layer"
APP_VERSION: str = "1.1.0"


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
