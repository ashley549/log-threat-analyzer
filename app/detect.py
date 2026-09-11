"""Phase 2 runner: load events from SQLite, run all rules, store detections."""
from __future__ import annotations

import sqlite3
from contextlib import closing
import time
from pathlib import Path

import pandas as pd

from app.rules import RULES
from db.schema import init_db, DB_PATH

INSERT_SQL = "INSERT INTO detections (rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)"


def load_events(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status, host FROM events", conn)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def run_rules(df: pd.DataFrame) -> list:
    all_dets = []
    for rule_id, (fn, _doc) in RULES.items():
        t0 = time.perf_counter()
        try:
            dets = fn(df)
        except Exception as e:  # a broken rule must never kill the engine
            print(f"  [rule-error] {rule_id}: {e}")
            dets = []
        ms = (time.perf_counter() - t0) * 1000
        print(f"  {rule_id:<26} {len(dets)} detection(s)  [{ms:.0f} ms]")
        all_dets.extend(dets)
    return all_dets


def detect(db_path: str | Path = DB_PATH) -> dict:
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("DELETE FROM detections WHERE rule_id NOT LIKE 'ML_%'")  # keep ML detections
        df = load_events(conn)
        if df.empty:
            print("No events in DB — run `python -m app.ingest` first.")
            return {"detections": 0}
        dets = run_rules(df)
        conn.executemany(INSERT_SQL, [d.to_row() for d in dets])
        conn.commit()
    dets.sort(key=lambda d: (d.severity_weight, d.first_seen), reverse=True)
    print(f"\n{len(dets)} detection(s) written to SQLite")
    for d in dets:
        print(f"  [{d.severity_weight:.1f}] {d.rule_id:<26} {d.entity:<28} {d.first_seen}  ({len(d.matched_event_ids)} events)")
    return {"detections": len(dets)}


if __name__ == "__main__":
    detect()
