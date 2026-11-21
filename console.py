#!/usr/bin/env python3
"""
console.py — DTBlocker Interactive Security Operations CLI

Ponto de entrada de linha de comandos (CLI) para gestão centralizada do DNS Sinkhole:
1. Iniciar o Servidor Web / Dashboard (FastAPI/Uvicorn)
2. Sincronizar Feeds de Ameaças (Threat Intelligence Ingestion)
3. Reiniciar Unbound DNS (systemctl)
4. Iniciar Agente de Machine Learning (Módulo IA em desenvolvimento)
5. Sair com encerramento gracioso e limpeza de processos
"""

import atexit
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Diretório base do projeto (/home/pserver/dnsthreat ou raiz onde está console.py)
PROJECT_DIR: Path = Path(__file__).resolve().parent

# Importa a função de deteção dinâmica de IP e utilitários de SSL/TLS
sys.path.insert(0, str(PROJECT_DIR))
try:
    from app.config import (
        get_local_ip,
        is_ssl_configured,
        generate_self_signed_cert,
        SSL_KEY_PATH,
        SSL_CERT_PATH,
        CERTS_DIR
    )
except ImportError:
    # Fallback inline caso o import falhe (ex: venv não ativado)
    import socket
    def get_local_ip() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except (OSError, socket.error):
            return "127.0.0.1"

    CERTS_DIR = PROJECT_DIR / "certs"
    SSL_KEY_PATH = CERTS_DIR / "sinkhole.key"
    SSL_CERT_PATH = CERTS_DIR / "sinkhole.crt"

    def is_ssl_configured() -> bool:
        return SSL_KEY_PATH.is_file() and SSL_CERT_PATH.is_file()

    def generate_self_signed_cert(domain=None, days=365, force=False):
        return False, "app.config não disponível para geração automática"

# Referência global ao processo filho ativo para limpeza
active_process: Optional[subprocess.Popen] = None

# -----------------------------------------------------------------------------
# Tentativa de importação de bibliotecas visuais (Rich, PyFiglet, Termcolor)
# Caso não estejam instaladas, o script utiliza um motor ANSI nativo integrado.
# -----------------------------------------------------------------------------
try:
    import pyfiglet
    from termcolor import colored
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    rich_console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    rich_console = None

# Códigos ANSI para estilização nativa de fallback
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_MAGENTA = "\033[95m"
ANSI_CYAN = "\033[96m"
ANSI_WHITE = "\033[97m"
ANSI_GRAY = "\033[90m"


def clear_screen() -> None:
    """Limpa o ecrã do terminal de forma compatível com Linux e Windows."""
    os.system("cls" if os.name == "nt" else "clear")


def cleanup_processes() -> None:
    """Termina quaisquer subprocessos ativos para evitar processos órfãos."""
    global active_process
    if active_process and active_process.poll() is None:
        try:
            print(f"\n{ANSI_YELLOW}[!] A encerrar processo filho ativo (PID: {active_process.pid})...{ANSI_RESET}")
            active_process.terminate()
            active_process.wait(timeout=2)
        except (subprocess.TimeoutExpired, Exception):
            try:
                active_process.kill()
            except Exception:
                pass
        active_process = None


# Regista a limpeza automática ao sair
atexit.register(cleanup_processes)


def signal_handler(signum, frame) -> None:
    """Manipulador para SIGINT (Ctrl+C) ao nível do interpretador."""
    cleanup_processes()
    print(f"\n\n{ANSI_RED}[!] Operação interrompida pelo utilizador (Ctrl+C). A sair...{ANSI_RESET}")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def render_banner() -> None:
    """Renderiza o banner ASCII de Dtblocker"""
    clear_screen()

    banner_text = ""
    if HAS_PYFIGLET:
        try:
            raw_figlet = pyfiglet.figlet_format("Dtblocker", font="slant")
            banner_text = colored(raw_figlet, "cyan", attrs=["bold"])
        except Exception:
            banner_text = ""

    if not banner_text:
        # Fallback de alta fidelidade em ASCII nativo (estilo Slant/Cyberpunk)
        banner_text = f"""{ANSI_CYAN}{ANSI_BOLD}
[0;37m                                                                       [0m
[0;37m▀▀▀▀██▄ ░░░     ░░░     ░░░                     ░░░                    [0m
[0;37m░░░ ███ ▒▒▒     ▒▒▒     ▒▒▒                     ▒▒▒                    [0m
[0;37m▒▒▒ ███ ▓▓▓▄▄   ▓▓▓     ▓▓▓                     ▓▓▓                    [0m
[0;37m▓▓▓ ███ ███     ███▀██▄ ███     ▄██▀██▄ ▄██▀██▄ ███ ███ ▄██▀██▄ ▄██▀██▄[0m
[0;37m███ ███ ███     ███ ███ ███     ███ ███ ███ ███ ███ ███ ███ ███ ███ ███[0m
[0;37m███ ███ ███     ███ ███ ███     ███ ███ ███ ▀▀▀ ███▀██▄ ███▀▀▀▀ ███    [0m
[0;37m███ ███ ███ ▄▄▄ ███ ███ ███ ▄▄▄ ███ ███ ███ ███ ███ ███ ███ ███ ███    [0m
[0;37m███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███ ███    [0m
[0;37m███▄██▀ ▀██▄██▀ ███▄██▀ ▀██▄██▀ ▀██▄██▀ ▀██▄██▀ ███ ███ ▀██▄██▀ ███    [0m
[0;37m          ▀█    █▀        ▀█      █▀      █▀        █▀    █▀     ▀█    [0m
[0;37m           ▄    ▄          ▄      ▄       ▄         ▄     ▄       ▄    [0m
   
{ANSI_RESET}"""

    ssl_status_rich = "[bold green]Ativo (:443)[/bold green]" if is_ssl_configured() else "[yellow]Inativo[/yellow]"
    ssl_status_ansi = f"{ANSI_GREEN}Ativo (:443){ANSI_RESET}" if is_ssl_configured() else f"{ANSI_YELLOW}Inativo{ANSI_RESET}"

    if HAS_RICH and rich_console:
        rich_console.print(banner_text)
        info_panel = Panel(
            Text.from_markup(
                f"[bold green]DNS Threat Blocker & SOC Sinkhole Control Center[/bold green]\n"
                f"[dim white]Host:[/] [cyan]{platform.node()}[/] | "
                f"[dim white]OS:[/] [cyan]{platform.system()} {platform.release()}[/] | "
                f"[dim white]Sinkhole IP:[/] [bold yellow]{get_local_ip()}[/bold yellow] | "
                f"[dim white]SSL/TLS:[/] {ssl_status_rich} | "
                f"[dim white]Data UTC:[/] [yellow]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}[/]"
            ),
            border_style="green",
            title="[bold red]● SOC DEFENSE ENGINE ACTIVE ●[/bold red]",
            title_align="center"
        )
        rich_console.print(info_panel)
    else:
        print(banner_text)
        print(f"{ANSI_GREEN}{ANSI_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ANSI_RESET}")
        print(f" {ANSI_BOLD}DNS Threat Blocker {ANSI_RESET}")
        print(f" {ANSI_GRAY}Host:{ANSI_RESET} {ANSI_CYAN}{platform.node()}{ANSI_RESET} | {ANSI_GRAY}OS:{ANSI_RESET} {ANSI_CYAN}{platform.system()}{ANSI_RESET} | {ANSI_GRAY}Sinkhole IP:{ANSI_RESET} {ANSI_YELLOW}{ANSI_BOLD}{get_local_ip()}{ANSI_RESET} | {ANSI_GRAY}SSL/TLS:{ANSI_RESET} {ssl_status_ansi} | {ANSI_GRAY}Data UTC:{ANSI_RESET} {ANSI_YELLOW}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}{ANSI_RESET}")
        print(f"{ANSI_GREEN}{ANSI_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ANSI_RESET}\n")


def display_menu() -> None:
    """Apresenta o menu de seleção de opções formatado."""
    ssl_desc = "HTTPS :443" if is_ssl_configured() else "HTTP :80"
    if HAS_RICH and rich_console:
        table = Table(title="[bold white]MENU DE OPERAÇÕES [/bold white]", show_header=True, header_style="bold magenta", border_style="cyan")
        table.add_column("Opção", justify="center", style="bold green", width=8)
        table.add_column("Ação", style="bold white", width=38)
        table.add_column("Comando Associado", style="dim yellow")

        table.add_row("[1]", f"Iniciar Servidor Web ({ssl_desc})", f"sudo ./venv/bin/uvicorn app.main:app ({ssl_desc})")
        table.add_row("[2]", "Sincronizar Feeds de Ameaças", "sudo python3 sync_iocs.py")
        table.add_row("[3]", "Reiniciar Unbound DNS", "sudo systemctl restart unbound")
        table.add_row("[4]", "Iniciar Agente de Machine Learning", "[Módulo IA - Analisador Heurístico]")
        table.add_row("[5]", f"Atualizar IP do Sinkhole ({get_local_ip()})", "sudo python3 sync_iocs.py --refresh-ip")
        table.add_row("[6]", "Sair da Consola", "Encerramento seguro do CLI")

        rich_console.print(table)
    else:
        current_ip = get_local_ip()
        print(f" {ANSI_MAGENTA}{ANSI_BOLD}--- MENU DE OPERAÇÕES SECOPS ---{ANSI_RESET}")
        print(f"  {ANSI_GREEN}[1]{ANSI_RESET} {ANSI_BOLD}Iniciar Servidor Web ({ssl_desc}){ANSI_RESET}   {ANSI_GRAY}(sudo ./venv/bin/uvicorn ... {ssl_desc}){ANSI_RESET}")
        print(f"  {ANSI_GREEN}[2]{ANSI_RESET} {ANSI_BOLD}Sincronizar Feeds de Ameaças{ANSI_RESET}       {ANSI_GRAY}(sudo python3 sync_iocs.py){ANSI_RESET}")
        print(f"  {ANSI_GREEN}[3]{ANSI_RESET} {ANSI_BOLD}Reiniciar Unbound DNS{ANSI_RESET}              {ANSI_GRAY}(sudo systemctl restart unbound){ANSI_RESET}")
        print(f"  {ANSI_GREEN}[4]{ANSI_RESET} {ANSI_BOLD}Iniciar Agente de Machine Learning{ANSI_RESET} {ANSI_YELLOW}[Módulo IA em desenvolvimento]{ANSI_RESET}")
        print(f"  {ANSI_GREEN}[5]{ANSI_RESET} {ANSI_BOLD}Atualizar IP do Sinkhole{ANSI_RESET}          {ANSI_CYAN}[IP atual: {current_ip}]{ANSI_RESET}")
        print(f"  {ANSI_RED}[6]{ANSI_RESET} {ANSI_BOLD}Sair{ANSI_RESET}\n")


def run_command_interactive(cmd_list: List[str], description: str) -> None:
    """
    Executa comandos do sistema operativo de forma controlada via subprocess.
    Interceta Ctrl+C para regressar ao menu sem quebrar a execução da consola principal.
    """
    global active_process
    print(f"\n{ANSI_CYAN}{ANSI_BOLD}[▶] A executar:{ANSI_RESET} {' '.join(cmd_list)}")
    print(f"{ANSI_GRAY}{description}{ANSI_RESET}\n")

    try:
        # Executa no diretório base do projeto
        active_process = subprocess.Popen(
            cmd_list,
            cwd=str(PROJECT_DIR),
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        active_process.wait()
    except KeyboardInterrupt:
        print(f"\n\n{ANSI_YELLOW}[!] Interrupção (Ctrl+C) intercetada. A terminar processo...{ANSI_RESET}")
        cleanup_processes()
    except FileNotFoundError:
        print(f"\n{ANSI_RED}[✗] Erro: Comando ou executável não encontrado:{ANSI_RESET} {cmd_list[0]}")
    except Exception as e:
        print(f"\n{ANSI_RED}[✗] Erro inesperado durante a execução:{ANSI_RESET} {e}")
    finally:
        active_process = None


def resolve_uvicorn_path() -> str:
    """Localiza o binário do uvicorn (prioriza ./venv/bin/uvicorn, com fallback para PATH)."""
    venv_uvicorn = PROJECT_DIR / "venv" / "bin" / "uvicorn"
    if venv_uvicorn.is_file() and os.access(venv_uvicorn, os.X_OK):
        return str(venv_uvicorn)
    
    # Fallback caso o uvicorn esteja no PATH global
    system_uvicorn = shutil.which("uvicorn")
    if system_uvicorn:
        return system_uvicorn
    
    # Retorna o caminho padrão exigido
    return "./venv/bin/uvicorn"


def handle_option_1() -> None:
    """Opção 1: Iniciar o Servidor Web / Dashboard (com suporte dinâmico a HTTPS :443 e HTTP :80)."""
    uvicorn_bin = resolve_uvicorn_path()
    ssl_ready = is_ssl_configured()

    print(f"\n{ANSI_CYAN}{ANSI_BOLD}--- SELEÇÃO DE MODO DO SERVIDOR WEB ---{ANSI_RESET}")
    if ssl_ready:
        print(f"  {ANSI_GREEN}[1]{ANSI_RESET} {ANSI_BOLD}HTTPS (Porta 443 - Recomendado para navegadores HTTPS-First){ANSI_RESET} {ANSI_CYAN}[Certificados OK]{ANSI_RESET}")
        print(f"  {ANSI_GREEN}[2]{ANSI_RESET} {ANSI_BOLD}HTTP (Porta 80 - Modo Legado){ANSI_RESET}")
        print(f"  {ANSI_GREEN}[3]{ANSI_RESET} {ANSI_BOLD}Regenerar Certificados SSL/TLS Auto-assinados{ANSI_RESET}")
        print(f"  {ANSI_GRAY}[0] Voltar ao menu principal{ANSI_RESET}")
        sub_choice = input(f"\n{ANSI_BOLD}Escolha o modo [padrão: 1]: {ANSI_RESET}").strip() or "1"
    else:
        print(f"  {ANSI_YELLOW}[!] Certificados SSL/TLS não encontrados em {CERTS_DIR}.{ANSI_RESET}")
        print(f"  {ANSI_GREEN}[1]{ANSI_RESET} {ANSI_BOLD}Gerar Certificado SSL Auto-assinado e Iniciar em HTTPS (:443){ANSI_RESET}")
        print(f"  {ANSI_GREEN}[2]{ANSI_RESET} {ANSI_BOLD}Iniciar apenas em HTTP (Porta 80){ANSI_RESET}")
        print(f"  {ANSI_GRAY}[0] Voltar ao menu principal{ANSI_RESET}")
        sub_choice = input(f"\n{ANSI_BOLD}Escolha o modo [padrão: 1]: {ANSI_RESET}").strip() or "1"
        if sub_choice == "1":
            print(f"\n{ANSI_CYAN}[▶] A gerar certificados SSL/TLS auto-assinados...{ANSI_RESET}")
            ok, msg = generate_self_signed_cert()
            if ok:
                print(f"{ANSI_GREEN}[✓] {msg}{ANSI_RESET}")
                ssl_ready = True
            else:
                print(f"{ANSI_RED}[✗] {msg}{ANSI_RESET}")
                input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")
                return

    if sub_choice == "0":
        return
    elif sub_choice == "3" and ssl_ready:
        print(f"\n{ANSI_CYAN}[▶] A regenerar certificados SSL/TLS para o IP {get_local_ip()}...{ANSI_RESET}")
        ok, msg = generate_self_signed_cert(force=True)
        if ok:
            print(f"{ANSI_GREEN}[✓] {msg}{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}[✗] {msg}{ANSI_RESET}")
        input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")
        return
    elif sub_choice == "1" and ssl_ready:
        cmd = [
            "sudo", uvicorn_bin, "app.main:app",
            "--host", "0.0.0.0",
            "--port", "443",
            "--ssl-keyfile", str(SSL_KEY_PATH),
            "--ssl-certfile", str(SSL_CERT_PATH)
        ]
        run_command_interactive(cmd, "Servidor HTTPS ativo na porta 443 com TLS. Prime Ctrl+C para parar.")
    else:
        cmd = [
            "sudo", uvicorn_bin, "app.main:app",
            "--host", "0.0.0.0",
            "--port", "80"
        ]
        run_command_interactive(cmd, "Servidor HTTP ativo na porta 80. Prime Ctrl+C para parar.")

    input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")


def handle_option_2() -> None:
    """Opção 2: Sincronizar Feeds de Ameaças (sync_iocs.py)."""
    sync_script = PROJECT_DIR / "sync_iocs.py"
    # sync_iocs.py necessita de privilégios sudo para escrever em /etc/unbound/
    cmd = ["sudo", "python3", str(sync_script)]
    run_command_interactive(cmd, "A descarregar IoCs, atualizar SQLite e recarregar configuração do Unbound...")
    input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")


def handle_option_3() -> None:
    """Opção 3: Reiniciar Unbound DNS (sudo systemctl restart unbound)."""
    cmd = ["sudo", "systemctl", "restart", "unbound"]
    print(f"\n{ANSI_CYAN}[▶] A reiniciar o serviço Unbound DNS...{ANSI_RESET}")
    try:
        res = subprocess.run(cmd, cwd=str(PROJECT_DIR))
        if res.returncode == 0:
            print(f"{ANSI_GREEN}{ANSI_BOLD}[✓] Serviço Unbound reiniciado com sucesso!{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}{ANSI_BOLD}[✗] Falha ao reiniciar o Unbound (Código de saída: {res.returncode}){ANSI_RESET}")
    except Exception as e:
        print(f"{ANSI_RED}[✗] Erro ao comunicar com o systemctl: {e}{ANSI_RESET}")
    input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")


def handle_option_4() -> None:
    """Opção 4: Iniciar Agente de Machine Learning."""
    warning_msg = "Módulo IA em desenvolvimento..."
    if HAS_RICH and rich_console:
        rich_console.print(f"\n[bold yellow][!] {warning_msg}[/bold yellow]\n")
    else:
        print(f"\n{ANSI_YELLOW}{ANSI_BOLD}[!] {warning_msg}{ANSI_RESET}\n")
    time.sleep(1.5)
    input(f"{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")


def handle_option_5() -> None:
    """Opção 5: Atualizar IP do Sinkhole (--refresh-ip)."""
    current_ip = get_local_ip()
    print(f"\n{ANSI_CYAN}{ANSI_BOLD}[▶] IP detetado na rede atual:{ANSI_RESET} {ANSI_GREEN}{current_ip}{ANSI_RESET}")
    print(f"{ANSI_GRAY}A reescrever o IP no threat_feed.conf e a reiniciar o Unbound...{ANSI_RESET}\n")

    sync_script = PROJECT_DIR / "sync_iocs.py"
    cmd = ["sudo", "python3", str(sync_script), "--refresh-ip"]
    run_command_interactive(cmd, "Modo rápido: apenas atualiza o IP sem re-descarregar feeds OSINT.")
    input(f"\n{ANSI_GRAY}[Prime ENTER para continuar...]{ANSI_RESET}")


def main_loop() -> None:
    """Ciclo principal de execução interativa do CLI."""
    while True:
        render_banner()
        display_menu()

        # Obter escolha do utilizador
        choice = ""
        try:
            if HAS_RICH and rich_console:
                choice = Prompt.ask("[bold green]dtblocker[/bold green][bold white]@[/bold white][bold cyan]secops[/bold cyan] [bold white]❯[/bold white]", choices=["1", "2", "3", "4", "5", "6"], default="1")
            else:
                prompt_str = f"{ANSI_GREEN}{ANSI_BOLD}dtblocker{ANSI_RESET}@{ANSI_CYAN}secops{ANSI_RESET} {ANSI_BOLD}❯{ANSI_RESET} "
                choice = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            cleanup_processes()
            print(f"{ANSI_YELLOW}[!] Sessão interrompida. Até à próxima!{ANSI_RESET}")
            sys.exit(0)

        # Tratar seleção
        if choice == "1":
            handle_option_1()
        elif choice == "2":
            handle_option_2()
        elif choice == "3":
            handle_option_3()
        elif choice == "4":
            handle_option_4()
        elif choice == "5":
            handle_option_5()
        elif choice == "6":
            print(f"\n{ANSI_CYAN}{ANSI_BOLD}[✓] A encerrar o DTBlocker Console de forma segura... Até logo!{ANSI_RESET}\n")
            cleanup_processes()
            sys.exit(0)
        else:
            print(f"\n{ANSI_RED}[!] Opção inválida. Por favor escolhe um número entre 1 e 6.{ANSI_RESET}")
            time.sleep(1.2)


if __name__ == "__main__":
    main_loop()

