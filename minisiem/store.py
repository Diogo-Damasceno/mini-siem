"""Armazenamento de eventos + regras de correlação/detecção."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass

from .parsers import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT, timestamp TEXT, host TEXT, event_type TEXT,
    src_ip TEXT, user TEXT, message TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_ev_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_ev_type ON events(event_type);
"""


@dataclass
class Detection:
    rule: str
    severity: str
    src_ip: str
    count: int
    detail: str


class EventStore:
    def __init__(self, path: str = "siem.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    def ingest(self, events: list[Event]) -> int:
        self.conn.executemany(
            "INSERT INTO events (source,timestamp,host,event_type,src_ip,user,message,raw)"
            " VALUES (?,?,?,?,?,?,?,?)",
            [(e.source, e.timestamp, e.host, e.event_type, e.src_ip, e.user,
              e.message, e.raw) for e in events],
        )
        self.conn.commit()
        return len(events)

    def query(self, *, event_type=None, src_ip=None, limit=100) -> list[dict]:
        q = "SELECT * FROM events WHERE 1=1"
        p = []
        if event_type:
            q += " AND event_type=?"; p.append(event_type)
        if src_ip:
            q += " AND src_ip=?"; p.append(src_ip)
        q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
        return [dict(r) for r in self.conn.execute(q, p).fetchall()]

    def stats(self) -> dict:
        cur = self.conn.cursor()
        return {
            "total": cur.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "by_type": dict(cur.execute(
                "SELECT event_type,COUNT(*) FROM events WHERE event_type!='' "
                "GROUP BY event_type").fetchall()),
            "top_ips": cur.execute(
                "SELECT src_ip,COUNT(*) c FROM events WHERE src_ip!='' "
                "GROUP BY src_ip ORDER BY c DESC LIMIT 10").fetchall(),
        }

    def close(self):
        self.conn.close()


def detect_bruteforce(events: list[Event], threshold: int = 5) -> list[Detection]:
    """Regra: N falhas de autenticação do mesmo IP => brute-force."""
    fails: dict[str, int] = defaultdict(int)
    for e in events:
        if e.event_type in ("auth_failure", "invalid_user") and e.src_ip:
            fails[e.src_ip] += 1
    out = []
    for ip, c in fails.items():
        if c >= threshold:
            out.append(Detection("ssh_bruteforce", "critical", ip, c,
                                  f"{c} tentativas de autenticação falhas de {ip}"))
    return out


def detect_web_scan(events: list[Event], threshold: int = 10) -> list[Detection]:
    """Regra: muitos 404 do mesmo IP => varredura web."""
    hits: dict[str, int] = defaultdict(int)
    for e in events:
        if e.event_type == "http_404" and e.src_ip:
            hits[e.src_ip] += 1
    return [Detection("web_scan", "warning", ip, c,
                      f"{c} respostas 404 de {ip} (possível varredura)")
            for ip, c in hits.items() if c >= threshold]


def run_all_rules(events: list[Event]) -> list[Detection]:
    return detect_bruteforce(events) + detect_web_scan(events)
