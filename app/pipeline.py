"""Staged pipeline runner: file -> incidents, with per-stage progress callbacks.

Used by the Streamlit dashboard (narrates the architecture stage-by-stage)
and available to the FastAPI layer. Runs against a caller-owned SQLite path
so the dashboard can process uploads without clobbering the main DB.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

import pandas as pd

from app.ingest import ingest_file
from app.detect import load_events, run_rules
from app.detect_ml import build_features, train_and_flag
from app.correlate import correlate as correlate_fn
from app.rules import Detection
from app.recommend import recommend_all
from app.score import score_incident, COMPONENTS_ORDER
from db.schema import init_db

STAGES = [
    ("Parsing & normalizing logs", "ingest"),
    ("Rule-based detection", "rules"),
    ("ML anomaly detection", "ml"),
    ("Incident correlation", "correlate"),
    ("Risk scoring", "score"),
    ("AI recommendations", "recommend"),
]

ProgressFn = Callable[[str, int, str], None]  # (stage_name, pct, detail)


def run_pipeline(log_path: str | Path, db_path: str | Path, fmt: str = "auto",
                 year: int = 2026, progress: ProgressFn | None = None) -> dict:
    """Execute the full pipeline; returns a summary dict for the UI."""
    t_start = time.perf_counter()
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()  # fresh run each time (upload replaces previous)

    def report(stage: str, pct: int, detail: str = "") -> None:
        if progress:
            progress(stage, pct, detail)

    import sqlite3
    from contextlib import closing
    import json as _json

    # format auto-detection from file contents
    if fmt == "auto":
        with open(log_path, encoding="utf-8", errors="replace") as f:
            sample = [next(f, "") for _ in range(200)]
        from app.parsers import detect_format
        fmt = detect_format(sample) or "auth"
    result: dict = {"file": str(log_path), "db": str(db_path), "format": fmt, "stages": {}}

    # ---- 1) ingest ---------------------------------------------------------
    report("Parsing & normalizing logs", 5, "reading file")
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        stats = ingest_file(log_path, conn, fmt, year)
        n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    result["stages"]["ingest"] = {"events": n_events, **stats}
    report("Parsing & normalizing logs", 15, f"{n_events} events normalized")
    if n_events == 0:
        raise ValueError(
            f"No parseable events found in '{Path(log_path).name}' with format '{fmt}'. "
            f"Supported: Linux auth syslog (sshd/sudo), Apache/nginx access logs, "
            f"JSON lines. If this is a different format, the file may be empty, "
            f"truncated, or in an unsupported layout.")

    # ---- 2) rules -----------------------------------------------------------
    report("Rule-based detection", 25, "running 8 rules")
    with closing(sqlite3.connect(db_path)) as conn:
        df = load_events(conn)
        dets = run_rules(df)
        conn.executemany(
            "INSERT INTO detections (rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            [d.to_row() for d in dets])
        conn.commit()
    result["stages"]["rules"] = {"detections": len(dets)}
    report("Rule-based detection", 35, f"{len(dets)} rule detection(s)")

    # ---- 3) ML ---------------------------------------------------------------
    report("ML anomaly detection", 45, "training IsolationForest")
    with closing(sqlite3.connect(db_path)) as conn:
        agg = build_features(df)
        flagged, _ = train_and_flag(agg)
        rows = []
        for _, r in flagged.iterrows():
            w_start = pd.Timestamp(r["win"])
            w_end = w_start + pd.Timedelta(hours=1)
            if r["entity_user"] == "*":
                ev = df[(df["source_ip"] == r["entity_ip"]) & (df["timestamp"] >= w_start) & (df["timestamp"] < w_end)]
                entity = f"{r['entity_ip']} (source)"
            else:
                ev = df[(df["user"] == r["entity_user"]) & (df["source_ip"] == r["entity_ip"]) & (df["timestamp"] >= w_start) & (df["timestamp"] < w_end)]
                entity = f"{r['entity_user']}@{r['entity_ip']}"
            ids = sorted(int(i) for i in ev["id"].tolist())
            if not ids:
                continue
            import numpy as np
            sev = float(np.clip(1.5 - r["anomaly_score"] * 3, 1.0, 3.0))
            d = Detection("ML_ANOMALY",
                          f"Anomalous behavior ({int(r['n_fail'])} fail / {int(r['n_logins'])} logins, driven by: {', '.join(r['drivers'])})",
                          sev, ids, entity,
                          ev["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                          ev["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"))
            rows.append(d.to_row())
        conn.executemany(
            "INSERT INTO detections (rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            rows)
        conn.commit()
    result["stages"]["ml"] = {"detections": len(rows)}
    report("ML anomaly detection", 55, f"{len(rows)} anomaly window(s)")

    # ---- 4) correlate ---------------------------------------------------------
    report("Incident correlation", 65, "grouping detections")
    with closing(sqlite3.connect(db_path)) as conn:
        correlate_fn(db_path)
        n_inc = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    result["stages"]["correlate"] = {"incidents": n_inc}
    report("Incident correlation", 72, f"{n_inc} incident(s)")

    # ---- 5) score ----------------------------------------------------------------
    report("Risk scoring", 80, "computing risk breakdowns")
    with closing(sqlite3.connect(db_path)) as conn:
        inc = pd.read_sql("SELECT * FROM incidents", conn)
        dets_all = pd.read_sql("SELECT id, rule_id, description, severity_weight, entity, incident_id FROM detections", conn)
        ev_all = pd.read_sql("SELECT id, timestamp, user, source_ip, event_type, status, host FROM events", conn)
        ev_all["timestamp"] = pd.to_datetime(ev_all["timestamp"])
        for _, i in inc.iterrows():
            sub = dets_all[dets_all["incident_id"] == i["incident_id"]]
            ev = ev_all[ev_all["id"].isin(_json.loads(i["event_ids"]))]
            total, level, bd = score_incident(i, sub, ev)
            conn.execute("UPDATE incidents SET risk_score=?, risk_level=?, risk_breakdown=? WHERE incident_id=?",
                         (total, level, _json.dumps(bd, ensure_ascii=False), i["incident_id"]))
        conn.commit()
    report("Risk scoring", 88, f"{n_inc} incident(s) scored")

    # ---- 6) recommend ------------------------------------------------------------------
    report("AI recommendations", 92, "generating guidance")
    with closing(sqlite3.connect(db_path)) as conn:
        rec = recommend_all(db_path)
    result["stages"]["recommend"] = rec

    result["seconds"] = round(time.perf_counter() - t_start, 1)
    result["incidents"] = n_inc
    report("AI recommendations", 100, f"done in {result['seconds']}s")
    return result
