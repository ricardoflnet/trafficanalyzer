"""Captura de pacotes com Scapy.

Fluxo:
    AsyncSniffer (thread do Scapy)  ->  parse_packet()  ->  fila em memória
    thread de escrita               ->  lê a fila em lotes  ->  SQLite

O callback do sniffer só extrai os campos e enfileira, sem tocar no banco.
Assim a captura não fica bloqueada esperando I/O de disco, e os INSERTs são
feitos em lote (uma transação a cada N pacotes ou a cada intervalo de tempo).
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Optional

from scapy.all import ARP, IP, IPv6, AsyncSniffer, get_if_list  # type: ignore
from scapy.arch.common import compile_filter  # type: ignore
from scapy.error import Scapy_Exception  # type: ignore

from .database import Database

log = logging.getLogger(__name__)

# Números de protocolo IANA mais comuns -> nome legível.
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

# Cabeçalhos de extensão IPv6 que precisam ser "pulados" para achar o protocolo real.
IPV6_EXTENSION_HEADERS = {0, 43, 44, 60}  # Hop-by-Hop, Routing, Fragment, Destination


def protocol_name(number: Optional[int]) -> str:
    if number is None:
        return "OTHER"
    return IP_PROTOCOLS.get(int(number), f"IP-{int(number)}")


def _ipv6_upper_protocol(ip6) -> Optional[int]:
    """Percorre os cabeçalhos de extensão IPv6 até o protocolo de transporte."""
    layer, nh = ip6, ip6.nh
    while nh in IPV6_EXTENSION_HEADERS:
        layer = layer.payload
        nh = getattr(layer, "nh", None)
        if nh is None:
            break
    return nh


def parse_packet(pkt) -> tuple:
    """Extrai (timestamp, ip_origem, ip_destino, protocolo, tamanho) de um pacote."""
    timestamp = float(getattr(pkt, "time", 0) or time.time())
    # wirelen é o tamanho real no fio; len(pkt) é o que foi capturado (iguais
    # salvo quando o snaplen corta o pacote).
    length = int(getattr(pkt, "wirelen", None) or len(pkt))

    if IP in pkt:
        ip = pkt[IP]
        return timestamp, ip.src, ip.dst, protocol_name(ip.proto), length
    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        return timestamp, ip6.src, ip6.dst, protocol_name(_ipv6_upper_protocol(ip6)), length
    if ARP in pkt:
        arp = pkt[ARP]
        return timestamp, arp.psrc, arp.pdst, "ARP", length
    return timestamp, None, None, "OTHER", length


def list_interfaces() -> list[str]:
    return sorted(get_if_list())


def validate_filter(bpf_filter: Optional[str], interface: str) -> None:
    """Compila o filtro BPF antes de iniciar, para devolver um erro claro."""
    if not bpf_filter:
        return
    try:
        compile_filter(bpf_filter, iface=interface)
    except Scapy_Exception as exc:
        raise ValueError(f"Filtro BPF inválido: {bpf_filter!r}") from exc


class CaptureManager:
    """Controla uma captura por vez e a thread que grava no banco."""

    def __init__(
        self,
        db: Database,
        batch_size: int = 500,
        flush_interval: float = 1.0,
        max_queue: int = 100_000,
    ) -> None:
        self.db = db
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._queue: "queue.Queue[tuple]" = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sniffer: Optional[AsyncSniffer] = None
        self._writer: Optional[threading.Thread] = None
        self.session_id: Optional[int] = None
        self.interface: Optional[str] = None
        self.bpf_filter: Optional[str] = None
        self.started_at: Optional[float] = None
        self.captured = 0
        self.stored = 0
        self.dropped = 0

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    # ---------------------------------------------------------------- controle
    def start(self, interface: str, bpf_filter: Optional[str] = None) -> int:
        with self._lock:
            if self.running:
                raise RuntimeError("Já existe uma captura em andamento.")
            if interface not in get_if_list():
                raise ValueError(f"Interface desconhecida: {interface!r}")
            bpf_filter = (bpf_filter or "").strip() or None
            validate_filter(bpf_filter, interface)

            self.session_id = self.db.create_session(interface, bpf_filter)
            self.interface, self.bpf_filter = interface, bpf_filter
            self.started_at = time.time()
            self.captured = self.stored = self.dropped = 0
            self._stop_event.clear()

            self._writer = threading.Thread(target=self._writer_loop, name="db-writer", daemon=True)
            self._writer.start()

            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=bpf_filter,
                prn=self._on_packet,
                store=False,  # não guarda pacotes em memória; já vão para a fila
            )
            self._sniffer.start()
            log.info("Captura iniciada (sessão %s) em %s, filtro=%s", self.session_id, interface, bpf_filter)
            return self.session_id

    def stop(self) -> Optional[int]:
        with self._lock:
            if not self.running:
                return None
            try:
                self._sniffer.stop()
            except Scapy_Exception as exc:  # sniffer já tinha parado sozinho
                log.warning("Erro ao parar o sniffer: %s", exc)
            self._sniffer = None
            self._stop_event.set()
            if self._writer:
                self._writer.join(timeout=10)
            self._writer = None
            session_id = self.session_id
            self.db.close_session(session_id)
            log.info("Captura encerrada (sessão %s): %s pacotes gravados", session_id, self.stored)
            return session_id

    def status(self) -> dict:
        return {
            "running": self.running,
            "session_id": self.session_id,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "started_at": self.started_at,
            "captured": self.captured,
            "stored": self.stored,
            "dropped": self.dropped,
            "queued": self._queue.qsize(),
        }

    # --------------------------------------------------------------- internos
    def _on_packet(self, pkt) -> None:
        try:
            row = parse_packet(pkt)
        except Exception:  # um pacote malformado não pode derrubar a captura
            log.debug("Falha ao interpretar pacote", exc_info=True)
            return
        self.captured += 1
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            self.dropped += 1

    def _writer_loop(self) -> None:
        session_id = self.session_id
        while not (self._stop_event.is_set() and self._queue.empty()):
            batch = []
            deadline = time.monotonic() + self.flush_interval
            while len(batch) < self.batch_size:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=timeout))
                except queue.Empty:
                    break
            if batch:
                try:
                    self.stored += self.db.insert_packets(session_id, batch)
                except Exception:
                    log.exception("Falha ao gravar lote de %s pacotes", len(batch))
