"""Phase 1 perf check: build a ~500k-line auth.log and ingest it."""
import time
from pathlib import Path

from app.ingest import ingest_file
from db.schema import init_db

SRC = Path("data/synthetic/auth.log")
BIG = Path("data/synthetic/big_auth.log")
TARGET = 500_000

lines = SRC.read_text(encoding="utf-8").splitlines()
reps = TARGET // len(lines) + 1
BIG.write_text("\n".join((lines * reps)[:TARGET]) + "\n", encoding="utf-8")
print(f"built {BIG} with {TARGET} lines")

init_db()
import sqlite3
conn = sqlite3.connect("db/logsec.db")
conn.execute("DELETE FROM events")  # clean slate for the perf run
conn.commit()
stats = ingest_file(BIG, conn, fmt="auth", year=2026)
print(stats)
n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
print(f"rows in SQLite: {n}")
