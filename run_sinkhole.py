#!/usr/bin/env python3
"""
run_sinkhole.py — DNS Threat Blocker Server Runner

Inicia o servidor Uvicorn com suporte centralizado para:
- HTTPS (Porta 443 com SSL/TLS)
- HTTP (Porta 80)
- Modo Dual (Porta 80 e 443 em processos paralelos)
- Geração automática de certificados SSL auto-assinados
"""

import argparse
import multiprocessing
import os
import sys
from pathlib import Path

# Adiciona o diretório base ao sys.path
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
    """Inicia o servidor em modo HTTPS seguro."""
    if not is_ssl_configured():
        print(f"[!] Certificados SSL não encontrados em {SSL_KEY_PATH.parent}. A gerar automaticamente...")
        ok, msg = generate_self_signed_cert()
        if not ok:
            print(f"[✗] Falha ao gerar certificados: {msg}")
            sys.exit(1)
        print(f"[✓] {msg}")

    print(f"[▶] A iniciar {APP_TITLE} v{APP_VERSION} em HTTPS ({host}:{port})...")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        ssl_keyfile=str(SSL_KEY_PATH),
        ssl_certfile=str(SSL_CERT_PATH),
        log_level="info",
    )


def run_http(host: str = "0.0.0.0", port: int = 80):
    """Inicia o servidor em modo HTTP legado."""
    print(f"[▶] A iniciar {APP_TITLE} v{APP_VERSION} em HTTP ({host}:{port})...")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        log_level="info",
    )


def run_dual(host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443):
    """Inicia instâncias em paralelo nas portas 80 (HTTP) e 443 (HTTPS)."""
    if not is_ssl_configured():
        ok, msg = generate_self_signed_cert()
        if not ok:
            print(f"[✗] {msg}")
            sys.exit(1)

    print(f"[▶] A iniciar Modo Dual (HTTP :{http_port} e HTTPS :{https_port})...")
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
        print("\n[!] A encerrar servidores paralelos...")
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
        help="Modo de execução (https, http ou dual). Padrão: https se certificados existirem",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Endereço de escuta (padrão: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Porta personalizada (padrão: 443 para HTTPS, 80 para HTTP)",
    )
    parser.add_argument(
        "--generate-cert",
        action="store_true",
        help="Força a regeneração de certificados SSL auto-assinados",
    )

    args = parser.parse_args()

    # Inicializa tabelas SQLite caso ainda não existam
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
