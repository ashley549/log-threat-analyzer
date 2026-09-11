"""Phase 1 verification: cross-check SQLite rows against ground truth."""
import json
import sqlite3

conn = sqlite3.connect("db/logsec.db")
gt = json.load(open("data/synthetic/ground_truth.json", encoding="utf-8"))

print("=== rows by event_type/status ===")
for r in conn.execute("SELECT event_type, status, COUNT(*) FROM events GROUP BY 1,2 ORDER BY 3 DESC"):
    print(f"  {r[0]:<16} {str(r[1]):<8} {r[2]}")

q = lambda s, *a: conn.execute(s, a).fetchone()[0]
print("\n=== ground-truth cross-checks ===")
checks = [
    ("S1 brute force: failed ssh from 203.0.113.45", q("SELECT COUNT(*) FROM events WHERE source_ip='203.0.113.45' AND status='fail'"), "expect 88 (2 lines/failed login kept)"),
    ("S1 compromise: root success from attacker IP", q("SELECT COUNT(*) FROM events WHERE source_ip='203.0.113.45' AND user='root' AND status='success'"), "expect >=1"),
    ("S2 stuffing: distinct users failed from botnet", q("SELECT COUNT(DISTINCT user) FROM events WHERE status='fail' AND source_ip LIKE '198.51.100.%'"), "expect ~20"),
    ("S2 compromise: alice success from botnet IP", q("SELECT COUNT(*) FROM events WHERE user='alice' AND status='success' AND source_ip LIKE '198.51.100.%'"), "expect 1"),
    ("S3 privesc: sudo_fail events", q("SELECT COUNT(*) FROM events WHERE event_type='sudo_fail'"), "expect 2"),
    ("S3 backdoor: user_added + user_modified", q("SELECT COUNT(*) FROM events WHERE event_type IN ('user_added','user_modified')"), "expect 2"),
    ("S4 impossible travel: alice success IPs", [r[0] for r in conn.execute("SELECT DISTINCT source_ip FROM events WHERE user='alice' AND event_type='ssh_login' AND status='success'")], "expect 2 distinct IPs"),
]
for name, got, note in checks:
    print(f"  {name:<45} -> {got}  ({note})")

total_db = q("SELECT COUNT(*) FROM events")
print(f"\nDB rows: {total_db} / log lines: {gt['meta']['total_lines']} (5 unparseable skipped -> {total_db + 5} expected)")
