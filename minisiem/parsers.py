"""Parsers que normalizam linhas de log em eventos estruturados."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    source: str            # ssh | syslog | nginx | generic
    timestamp: str
    host: str = ""
    event_type: str = ""   # auth_failure, auth_success, etc.
    src_ip: str = ""
    user: str = ""
    message: str = ""
    raw: str = ""
    fields: dict = field(default_factory=dict)


# sshd: "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
_SSH_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_SSH_OK = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")

# syslog prefix: "Jan 10 12:00:00 hostname process[pid]:"
_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+)\s(?P<proc>\S+?)(?:\[\d+\])?:\s(?P<msg>.*)$")

# nginx access: '1.2.3.4 - - [10/Jan/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 ...'
_NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d+)')


def parse_line(line: str) -> Event | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = _NGINX.match(line)
    if m:
        return Event(source="nginx", timestamp=m["ts"], src_ip=m["ip"],
                     event_type=f"http_{m['status']}", message=f"{m['method']} {m['path']}",
                     raw=line, fields={"status": m["status"], "path": m["path"]})

    sm = _SYSLOG.match(line)
    if sm:
        host, proc, msg, ts = sm["host"], sm["proc"], sm["msg"], sm["ts"]
        if "ssh" in proc.lower():
            return _parse_ssh(ts, host, msg, line)
        return Event(source="syslog", timestamp=ts, host=host,
                     event_type=proc, message=msg, raw=line)

    # tenta ssh direto (sem prefixo syslog)
    ssh = _parse_ssh("", "", line, line)
    if ssh.event_type:
        return ssh
    return Event(source="generic", timestamp="", message=line, raw=line)


def _parse_ssh(ts: str, host: str, msg: str, raw: str) -> Event:
    m = _SSH_FAIL.search(msg)
    if m:
        return Event("ssh", ts, host, "auth_failure", m["ip"], m["user"], msg, raw)
    m = _SSH_OK.search(msg)
    if m:
        return Event("ssh", ts, host, "auth_success", m["ip"], m["user"], msg, raw)
    m = _SSH_INVALID.search(msg)
    if m:
        return Event("ssh", ts, host, "invalid_user", m["ip"], m["user"], msg, raw)
    return Event("ssh", ts, host, "", "", "", msg, raw)


def parse_stream(lines) -> list[Event]:
    events = []
    for line in lines:
        ev = parse_line(line)
        if ev:
            events.append(ev)
    return events
