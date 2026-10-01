"""Camada de persistência (SQLite).

Cada operação abre sua própria conexão curta. Isso evita compartilhar uma
conexão entre threads (a thread de escrita da captura e as threads do servidor
web) e, com o modo WAL, permite que leituras aconteçam enquanto a captura grava.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterable, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS capture_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    interface   TEXT    NOT NULL,
    bpf_filter  TEXT,
    started_at  REAL    NOT NULL,          -- epoch (segundos, UTC)
    stopped_at  REAL                       -- NULL enquanto a captura estiver ativa
);

CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    captured_at REAL    NOT NULL,          -- timestamp do pacote (epoch)
    src_ip      TEXT,                      -- NULL para quadros sem camada IP/ARP
    dst_ip      TEXT,
    protocol    TEXT    NOT NULL,          -- TCP, UDP, ICMP, ICMPv6, ARP, ...
    length      INTEGER NOT NULL           -- tamanho do quadro em bytes
);

-- Índices compostos começando por session_id: todas as consultas de
-- estatística filtram por sessão e depois agrupam pela segunda coluna.
CREATE INDEX IF NOT EXISTS idx_packets_session_protocol ON packets(session_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packets_session_src      ON packets(session_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_session_dst      ON packets(session_id, dst_ip);
"""

# Colunas permitidas para ordenar o top 5 (lista branca contra SQL injection).
ORDER_COLUMNS = {"bytes": "bytes", "packets": "packets"}

PacketRow = tuple  # (captured_at, src_ip, dst_ip, protocol, length)


class Database:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.getenv("DB_PATH", "/data/traffic.db")
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(SCHEMA)
            # Sessões que ficaram abertas por queda do container são encerradas.
            conn.execute(
                "UPDATE capture_sessions SET stopped_at = ? WHERE stopped_at IS NULL",
                (time.time(),),
            )

    # ------------------------------------------------------------------ sessões
    def create_session(self, interface: str, bpf_filter: Optional[str]) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO capture_sessions (interface, bpf_filter, started_at) VALUES (?, ?, ?)",
                (interface, bpf_filter or None, time.time()),
            )
            return int(cur.lastrowid)

    def close_session(self, session_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE capture_sessions SET stopped_at = ? WHERE id = ? AND stopped_at IS NULL",
                (time.time(), session_id),
            )

    def list_sessions(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.interface, s.bpf_filter, s.started_at, s.stopped_at,
                       (SELECT COUNT(*) FROM packets p WHERE p.session_id = s.id) AS packets
                FROM capture_sessions s
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def latest_session_id(self) -> Optional[int]:
        with self.connect() as conn:
            row = conn.execute("SELECT MAX(id) AS id FROM capture_sessions").fetchone()
        return row["id"] if row else None

    def delete_session(self, session_id: int) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM capture_sessions WHERE id = ?", (session_id,))

    # ----------------------------------------------------------------- pacotes
    def insert_packets(self, session_id: int, rows: Iterable[PacketRow]) -> int:
        data = [(session_id, *row) for row in rows]
        if not data:
            return 0
        with self.connect() as conn:
            conn.executemany(
                "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, protocol, length) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                data,
            )
        return len(data)

    def recent_packets(self, session_id: int, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT captured_at, src_ip, dst_ip, protocol, length FROM packets "
                "WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ estatísticas
    def stats(self, session_id: int, order_by: str = "bytes", top: int = 5) -> dict:
        order = ORDER_COLUMNS.get(order_by, "bytes")
        with self.connect() as conn:
            totals = conn.execute(
                "SELECT COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes, "
                "MIN(captured_at) AS first_at, MAX(captured_at) AS last_at "
                "FROM packets WHERE session_id = ?",
                (session_id,),
            ).fetchone()

            protocols = conn.execute(
                "SELECT protocol, COUNT(*) AS packets, SUM(length) AS bytes "
                "FROM packets WHERE session_id = ? "
                "GROUP BY protocol ORDER BY packets DESC",
                (session_id,),
            ).fetchall()

            def top_ips(column: str) -> list[dict]:
                rows = conn.execute(
                    f"SELECT {column} AS ip, COUNT(*) AS packets, SUM(length) AS bytes "
                    f"FROM packets WHERE session_id = ? AND {column} IS NOT NULL "
                    f"GROUP BY {column} ORDER BY {order} DESC, ip ASC LIMIT ?",
                    (session_id, top),
                ).fetchall()
                return [dict(r) for r in rows]

            top_src = top_ips("src_ip")
            top_dst = top_ips("dst_ip")

        return {
            "session_id": session_id,
            "total_packets": totals["packets"],
            "total_bytes": totals["bytes"],
            "first_at": totals["first_at"],
            "last_at": totals["last_at"],
            "protocols": [dict(r) for r in protocols],
            "top_sources": top_src,
            "top_destinations": top_dst,
            "ordered_by": order,
        }
