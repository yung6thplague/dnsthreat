"""Configuration module for DNS Threat Blocker & Sinkhole Web Layer.

Handles absolute path resolutions via pathlib and guarantees data directories exist.
"""

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
APP_VERSION: str = "1.0.0"
