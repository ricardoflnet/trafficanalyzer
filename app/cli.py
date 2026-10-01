"""Modo terminal: pergunta a interface, captura e mostra as estatísticas ao vivo.

Uso (dentro do container):
    docker compose run --rm traffic-analyzer python -m app.cli
    docker compose run --rm traffic-analyzer python -m app.cli --interface eth0 --filter "tcp"
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .capture import CaptureManager, list_interfaces
from .database import Database


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def ask_interface() -> str:
    interfaces = list_interfaces()
    print("Interfaces disponíveis:")
    for i, name in enumerate(interfaces, 1):
        print(f"  {i}. {name}")
    while True:
        answer = input("Escolha a interface (número ou nome): ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(interfaces):
            return interfaces[int(answer) - 1]
        if answer in interfaces:
            return answer
        print("Interface inválida, tente novamente.")


def render(stats: dict, status: dict) -> str:
    lines = [
        f"Interface: {status['interface']}   Sessão: {stats['session_id']}   "
        f"Filtro: {status['bpf_filter'] or '(nenhum)'}",
        f"Total de pacotes: {stats['total_packets']}   Volume: {human_bytes(stats['total_bytes'])}   "
        f"Descartados: {status['dropped']}",
        "",
        "Pacotes por protocolo:",
    ]
    for p in stats["protocols"]:
        lines.append(f"  {p['protocol']:<12} {p['packets']:>10}  {human_bytes(p['bytes']):>10}")
    for title, key in (("Top 5 IPs de origem", "top_sources"), ("Top 5 IPs de destino", "top_destinations")):
        lines += ["", f"{title} (por bytes):"]
        for i, row in enumerate(stats[key], 1):
            lines.append(f"  {i}. {row['ip']:<40} {row['packets']:>8} pct  {human_bytes(row['bytes']):>10}")
    lines += ["", "Ctrl+C para encerrar."]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analisador de tráfego (modo terminal)")
    parser.add_argument("--interface", "-i", help="interface de rede (se omitida, será perguntada)")
    parser.add_argument("--filter", "-f", default=None, help='filtro BPF opcional, ex.: "tcp port 443"')
    parser.add_argument("--refresh", type=float, default=2.0, help="intervalo de atualização em segundos")
    args = parser.parse_args()

    interface = args.interface or os.getenv("CAPTURE_INTERFACE") or ask_interface()
    db = Database()
    capture = CaptureManager(db)
    try:
        capture.start(interface, args.filter)
    except (ValueError, RuntimeError, PermissionError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1

    try:
        while True:
            time.sleep(args.refresh)
            print("\033[2J\033[H" + render(db.stats(capture.session_id), capture.status()), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        session_id = capture.stop()
        print(f"\nCaptura encerrada. Dados salvos na sessão {session_id} ({db.path}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
