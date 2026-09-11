"""Phase 9 benchmark: stage-by-stage pipeline timing on a big log + cProfile of the worst stage.

Usage: python -m app.bench [log_path] [--profile]
"""
from __future__ import annotations

import cProfile
import io
import pstats
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LOG = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "data/perf/auth.log"
PROFILE = "--profile" in sys.argv
DB = ROOT / "data" / "perf" / "bench.db"

import pandas as pd

from app.ingest import ingest_file
from app.detect import load_events, run_rules
from app.detect_ml import build_features, train_and_flag
from app.correlate import correlate
from app.score import score_incident
from app.recommend import recommend_all
from db.schema import init_db

DB.unlink(missing_ok=True)
init_db(DB)

print(f"=== J-001 pipeline benchmark on {LOG} ===\n")

def stage(name, fn, *a, **k):
    t0 = time.perf_counter()
    out = fn(*a, **k)
    dt = time.perf_counter() - t0
    rows = out if isinstance(out, int) else (len(out) if hasattr(out, "__len__") else "")
    print(f"  {name:<28} {dt:>7.2f}s   {rows}")
    return out, dt

# 1) ingest
with sqlite3.connect(DB) as conn:
    stats, t_ing = stage("1. ingest", ingest_file, LOG, conn, "auth", 2026)

# 2) rules
with sqlite3.connect(DB) as conn:
    df, t_ld = stage("2a. load events", load_events, conn)
    dets, t_rules = stage("2b. run rules", run_rules, df)
    with conn:
        conn.executemany(
            "INSERT INTO detections (rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            [d.to_row() for d in dets])

# 3) ML — the suspected bottleneck: build_features is O(n·win)
def ml_fn():
    agg = build_features(df)
    flagged, _ = train_and_flag(agg)
    return agg, flagged

if PROFILE:
    pr = cProfile.Profile()
    pr.enable()
    (agg, flagged), t_ml = stage("3. ML (features+forest)", ml_fn)
    pr.disable()
else:
    (agg, flagged), t_ml = stage("3. ML (features+forest)", ml_fn)

with sqlite3.connect(DB) as conn:
    import numpy as np
    from app.rules import Detection
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
        sev = float(np.clip(1.5 - r["anomaly_score"] * 3, 1.0, 3.0))
        d = Detection("ML_ANOMALY",
                       f"Anomalous behavior ({int(r['n_fail'])} fail / {int(r['n_logins'])} logins, driven by: {', '.join(r['drivers'])})",
                       sev, ids, entity,
                       ev["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                       ev["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"))
        rows.append(d.to_row())
    with conn:
        conn.executemany(
            "INSERT INTO detections (rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)", rows)
    print(f"  {'  (ml detections stored)':<28} {len(rows)}")

# 4) correlate
_, t_cor = stage("4. correlate", correlate, DB)

# 5) score
def score_fn():
    with sqlite3.connect(DB) as conn:
        inc = pd.read_sql("SELECT * FROM incidents", conn)
        dets_all = pd.read_sql("SELECT id, rule_id, description, severity_weight, entity, incident_id FROM detections", conn)
        ev_all = pd.read_sql("SELECT id, timestamp, user, source_ip, event_type, status, host FROM events", conn)
        ev_all["timestamp"] = pd.to_datetime(ev_all["timestamp"])
        import json as _json
        for _, i in inc.iterrows():
            sub = dets_all[dets_all["incident_id"] == i["incident_id"]]
            ev = ev_all[ev_all["id"].isin(_json.loads(i["event_ids"]))]
            total, level, bd = score_incident(i, sub, ev)
            conn.execute("UPDATE incidents SET risk_score=?, risk_level=?, risk_breakdown=? WHERE incident_id=?",
                         (total, level, _json.dumps(bd, ensure_ascii=False), i["incident_id"]))
        conn.commit()
        return len(inc)

_, t_score = stage("5. score", score_fn)

# 6) recommend
_, t_rec = stage("6. recommend", recommend_all, DB)

total_t = t_ing + t_ld + t_rules + t_ml + t_cor + t_score + t_rec
print(f"\n  {'TOTAL':<28} {total_t:>7.2f}s   ({int(stats['total_lines'])} lines -> "
      f"{total_t/stats['total_lines']*1e6:.0f} us/line)")
print(f"  stage shares: ingest {t_ing/total_t:.0%} | rules {t_rules/total_t:.0%} | "
      f"ml {t_ml/total_t:.0%} | correlate {t_cor/total_t:.0%} | score {t_score/total_t:.0%} | rec {t_rec/total_t:.0%}")

if PROFILE:
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(15)
    print("\n=== cProfile top 15 (ML stage) ===")
    print("\n".join(s.getvalue().splitlines()[:28]))
