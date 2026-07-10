from minisiem.parsers import parse_line, parse_stream
from minisiem.store import EventStore, detect_bruteforce, detect_web_scan, run_all_rules


def test_parse_ssh_failure():
    line = ("Jan 10 12:00:00 srv sshd[123]: Failed password for invalid user "
            "admin from 1.2.3.4 port 22 ssh2")
    ev = parse_line(line)
    assert ev.source == "ssh"
    assert ev.event_type == "auth_failure"
    assert ev.src_ip == "1.2.3.4"
    assert ev.user == "admin"


def test_parse_ssh_success():
    line = "Jan 10 12:00:00 srv sshd[123]: Accepted password for diogo from 10.0.0.2 port 22 ssh2"
    ev = parse_line(line)
    assert ev.event_type == "auth_success"
    assert ev.user == "diogo"


def test_parse_nginx():
    line = '1.2.3.4 - - [10/Jan/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 404 200'
    ev = parse_line(line)
    assert ev.source == "nginx"
    assert ev.event_type == "http_404"
    assert ev.src_ip == "1.2.3.4"


def test_bruteforce_detection():
    lines = [f"Jan 10 12:00:0{i} s sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2"
             for i in range(6)]
    events = parse_stream(lines)
    dets = detect_bruteforce(events, threshold=5)
    assert len(dets) == 1
    assert dets[0].src_ip == "9.9.9.9"
    assert dets[0].severity == "critical"


def test_web_scan_detection():
    lines = [f'8.8.8.8 - - [x] "GET /p{i} HTTP/1.1" 404 1' for i in range(12)]
    events = parse_stream(lines)
    dets = detect_web_scan(events, threshold=10)
    assert len(dets) == 1
    assert dets[0].src_ip == "8.8.8.8"


def test_store_ingest_and_query():
    store = EventStore(":memory:")
    lines = ["Jan 10 12:00:00 s sshd[1]: Failed password for x from 1.1.1.1 port 22 ssh2"]
    events = parse_stream(lines)
    n = store.ingest(events)
    assert n == 1
    res = store.query(event_type="auth_failure")
    assert len(res) == 1
    assert res[0]["src_ip"] == "1.1.1.1"


def test_stats():
    store = EventStore(":memory:")
    lines = [f"Jan 10 12:00:0{i} s sshd[1]: Failed password for x from 1.1.1.1 port 22 ssh2"
             for i in range(3)]
    store.ingest(parse_stream(lines))
    st = store.stats()
    assert st["total"] == 3
    assert st["by_type"]["auth_failure"] == 3
