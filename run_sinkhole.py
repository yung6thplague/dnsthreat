#!/usr/bin/env python3
"""run_sinkhole.py — DNS Threat Blocker Server Runner.

Starts the Uvicorn web server with centralized support for:
- HTTPS (Port 443 with SSL/TLS)
- HTTP (Port 80 legacy mode)
- Dual Mode (Port 80 and 443 running in parallel processes)
- Automatic generation of self-signed SSL/TLS certificates
"""

import argparse
import multiprocessing
import os
import sys
from pathlib import Path

# Add project base directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import uvicorn
from app.config import (
    APP_TITLE,
    APP_VERSION,
    SSL_CERT_PATH,
    SSL_KEY_PATH,
    generate_self_signed_cert,
    get_local_ip,
    is_ssl_configured,
)
from app.database import init_db


def run_https(host: str = "0.0.0.0", port: int = 443):
    """Starts the web server in secure HTTPS mode."""
    if not is_ssl_configured():
        print(f"[!] SSL certificates not found in {SSL_KEY_PATH.parent}. Generating automatically...")
        ok, msg = generate_self_signed_cert()
        if not ok:
            print(f"[✗] Failed to generate certificates: {msg}")
            sys.exit(1)
        print(f"[✓] {msg}")

    print(f"[▶] Starting {APP_TITLE} v{APP_VERSION} on HTTPS ({host}:{port})...")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        ssl_keyfile=str(SSL_KEY_PATH),
        ssl_certfile=str(SSL_CERT_PATH),
        log_level="info",
    )


def run_http(host: str = "0.0.0.0", port: int = 80):
    """Starts the web server in legacy HTTP mode."""
    print(f"[▶] Starting {APP_TITLE} v{APP_VERSION} on HTTP ({host}:{port})...")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        log_level="info",
    )


def run_dual(host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443):
    """Starts parallel instances on port 80 (HTTP) and port 443 (HTTPS)."""
    if not is_ssl_configured():
        ok, msg = generate_self_signed_cert()
        if not ok:
            print(f"[✗] {msg}")
            sys.exit(1)

    print(f"[▶] Starting Dual Mode (HTTP :{http_port} and HTTPS :{https_port})...")
    p_https = multiprocessing.Process(
        target=run_https, args=(host, https_port), name="Sinkhole-HTTPS"
    )
    p_http = multiprocessing.Process(
        target=run_http, args=(host, http_port), name="Sinkhole-HTTP"
    )

    p_https.start()
    p_http.start()

    try:
        p_https.join()
        p_http.join()
    except KeyboardInterrupt:
        print("\n[!] Shutting down parallel servers...")
        p_https.terminate()
        p_http.terminate()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="DNS Sinkhole Web Application Runner"
    )
    parser.add_argument(
        "--mode",
        choices=["https", "http", "dual"],
        default="https" if is_ssl_configured() else "http",
        help="Execution mode (https, http, or dual). Default: https if certificates exist",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Listening address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Custom port (default: 443 for HTTPS, 80 for HTTP)",
    )
    parser.add_argument(
        "--generate-cert",
        action="store_true",
        help="Forces regeneration of self-signed SSL certificates",
    )

    args = parser.parse_args()

    # Initialize SQLite database schema if not already present
    init_db()

    if args.generate_cert:
        ok, msg = generate_self_signed_cert(force=True)
        print(f"[{'✓' if ok else '✗'}] {msg}")
        if not ok:
            sys.exit(1)

    if args.mode == "https":
        run_https(host=args.host, port=args.port or 443)
    elif args.mode == "http":
        run_http(host=args.host, port=args.port or 80)
    elif args.mode == "dual":
        run_dual(host=args.host)


if __name__ == "__main__":
    main()
