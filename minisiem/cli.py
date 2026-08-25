"""CLI do Mini-SIEM."""

from __future__ import annotations

import argparse
import json
import sys

from .parsers import parse_stream
from .store import EventStore, run_all_rules


def main(argv=None):
    p = argparse.ArgumentParser(description="Mini-SIEM: ingestão e correlação de logs.")
    p.add_argument("--db", default="siem.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="ingere um arquivo de log (ou stdin)")
    ing.add_argument("file", nargs="?", help="arquivo de log; omita para stdin")

    q = sub.add_parser("query", help="consulta eventos")
    q.add_argument("--type")
    q.add_argument("--ip")
    q.add_argument("--limit", type=int, default=50)

    sub.add_parser("stats", help="estatísticas")
    sub.add_parser("detect", help="roda regras de detecção sobre o log ingerido")

    args = p.parse_args(argv)
    store = EventStore(args.db)

    if args.cmd == "ingest":
        lines = open(args.file) if args.file else sys.stdin
        events = parse_stream(lines)
        n = store.ingest(events)
        dets = run_all_rules(events)
        print(f"[*] {n} eventos ingeridos.")
        for d in dets:
            print(f"  [!] {d.severity.upper()} {d.rule}: {d.detail}")
    elif args.cmd == "query":
        res = store.query(event_type=args.type, src_ip=args.ip, limit=args.limit)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.cmd == "stats":
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
    elif args.cmd == "detect":

        from .parsers import Event
        rows = store.query(limit=100000)
        events = [Event(source=r["source"], timestamp=r["timestamp"],
                        host=r["host"], event_type=r["event_type"],
                        src_ip=r["src_ip"], user=r["user"], message=r["message"],
                        raw=r["raw"]) for r in rows]
        dets = run_all_rules(events)
        if not dets:
            print("Nenhuma detecção.")
        for d in dets:
            print(f"[!] {d.severity.upper()} {d.rule}: {d.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
