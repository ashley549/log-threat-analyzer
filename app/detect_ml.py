"""ML anomaly detection (Phase 3): IsolationForest over per-entity windows.

Pipeline:
  1. Slice events into 1-hour windows.
  2. Build TWO feature views:
       - user@ip windows  (individual behavior: fail ratio, new-IP flag, ...)
       - ip-only windows  (source behavior: how many distinct users it hit —
         invisible per-user, obvious per-IP, e.g. password spraying)
  3. Train one unsupervised IsolationForest on the combined matrix.
  4. Flag the most anomalous entity-windows; attribute drivers by comparing
     each flagged row's features to the population (z-scores).
  5. Write to the same `detections` table with rule_id 'ML_ANOMALY'.

Catches subtler planted anomalies the rules missed, e.g. a single success
after 1-3 fails from a never-seen IP (below RULE_SUCCESS_AFTER_FAILS's
threshold of 5) or off-hours spraying that never trips a discrete rule.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.rules import Detection
from db.schema import init_db, DB_PATH

WINDOW = "1h"
CONTAMINATION = 0.08          # expected anomalous fraction (planted data is attack-heavy)
MAX_FLAGS = 40
Z_DRIVER = 2.0                # |z| above this => feature "drove" the anomaly
# machine accounts behave "weirdly" by design (night cron, fixed patterns) —
# and their activity is near-identical every run, so they pollute training
SERVICE_ACCOUNT_PAT = ("svc.", ".job", "backup", "cron", "deploy", "monitor")

FEATURES = [
    "n_events", "n_logins", "n_success", "n_fail",
    "fail_ratio", "distinct_users_seen", "distinct_hosts",
    "offhours_ratio", "is_night", "success_after_fail", "pair_first_time",
]

INSERT_SQL = ("INSERT INTO detections (rule_id, description, severity_weight, "
              "matched_event_ids, entity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)")


def load_events(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status, host FROM events", conn)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def _offhours(ts: pd.Series) -> pd.Series:
    h = ts.dt.hour
    return ((h >= 22) | (h < 5)).astype(float)


def _first_time_flags(logins: pd.DataFrame) -> dict:
    """(user, ip) and ip first-ever appearance timestamps."""
    pair_first = logins.groupby(["user", "source_ip"])["timestamp"].min().to_dict()
    ip_first = logins.groupby("source_ip")["timestamp"].min().to_dict()
    return pair_first, ip_first


def build_features(df: pd.DataFrame, window: str = WINDOW) -> pd.DataFrame:
    """Return feature rows for both user@ip and ip-only ('*') entity windows.

    Vectorized: single groupby pass per view, no per-row rescans.
    """
    logins = df[df["event_type"] == "ssh_login"].copy()
    if logins.empty:
        return pd.DataFrame(columns=["entity_user", "entity_ip", "win"] + FEATURES)
    logins["offhours"] = _offhours(logins["timestamp"])
    logins["win"] = logins["timestamp"].dt.floor(window)
    pair_first, ip_first = _first_time_flags(logins)

    def _is_service(u):
        return isinstance(u, str) and any(p in u for p in SERVICE_ACCOUNT_PAT)

    svc_mask = logins["user"].map(_is_service)
    # service-only IPs excluded from ip-level view
    ip_service_all = (logins.assign(svc=svc_mask).groupby("source_ip")["svc"].all())
    service_ips = set(ip_service_all[ip_service_all].index)
    keep = ~svc_mask
    logins_h = logins[keep]

    rows = []

    # ---- per user@ip windows (vectorized) -----------------------------------
    g = logins_h.groupby(["user", "source_ip", "win"], sort=True)
    agg = g.agg(
        n_logins=("id", "count"),
        n_success=("status", lambda s: int((s == "success").sum())),
        n_fail=("status", lambda s: int((s == "fail").sum())),
        distinct_hosts=("host", "nunique"),
        offhours_mean=("offhours", "mean"),
        first_id=("id", "min"),
        last_id=("id", "max"),
    ).reset_index()
    # per (ip, win): how many distinct users that IP touched
    ip_win_users = logins.groupby(["source_ip", "win"])["user"].nunique().rename("distinct_users_seen")
    agg = agg.merge(ip_win_users, on=["source_ip", "win"], how="left")

    # success-after-fail per (user, ip, win): statuses ordered by time within group
    logins_h_sorted = logins_h.sort_values(["user", "source_ip", "win", "timestamp"])
    seq = logins_h_sorted.groupby(["user", "source_ip", "win"])["status"].transform(lambda s: (s == "fail").cumsum())
    # a success whose preceding-fail count >= 1 and group has any fail
    saf_hit = (logins_h_sorted["status"] == "success") & (seq >= 1)
    saf = (logins_h_sorted.assign(_saf=saf_hit)
           .groupby(["user", "source_ip", "win"])["_saf"].any().rename("success_after_fail"))
    agg = agg.merge(saf, on=["user", "source_ip", "win"], how="left")

    # first-time (user, ip) pair
    pf = pd.Series(pair_first).rename("pair_first_ts")
    pf.index.names = ["user", "source_ip"]
    pf = pf.reset_index()
    pf["pair_first_win"] = pf["pair_first_ts"].dt.floor(window)
    agg = agg.merge(pf, on=["user", "source_ip"], how="left")
    agg["pair_first_time"] = (agg["win"] == agg["pair_first_win"]).astype(float)

    for _, r in agg.iterrows():
        rows.append({
            "entity_user": r["user"], "entity_ip": r["source_ip"], "win": r["win"],
            "n_events": int(r["n_logins"]), "n_logins": int(r["n_logins"]),
            "n_success": int(r["n_success"]), "n_fail": int(r["n_fail"]),
            "fail_ratio": float(r["n_fail"] / max(r["n_logins"], 1)),
            "distinct_users_seen": float(r["distinct_users_seen"]),
            "distinct_hosts": float(r["distinct_hosts"]),
            "offhours_ratio": float(r["offhours_mean"]),
            "is_night": float(r["win"].hour >= 22 or r["win"].hour < 5),
            "success_after_fail": float(bool(r["success_after_fail"])),
            "pair_first_time": float(r["pair_first_time"]),
        })

    # ---- per ip-only windows ('*' = the source itself) ------------------------
    gi = logins[~logins["source_ip"].isin(service_ips)].groupby(["source_ip", "win"], sort=True)
    aggi = gi.agg(
        n_logins=("id", "count"),
        n_success=("status", lambda s: int((s == "success").sum())),
        n_fail=("status", lambda s: int((s == "fail").sum())),
        distinct_hosts=("host", "nunique"),
        offhours_mean=("offhours", "mean"),
    ).reset_index()
    aggi["distinct_users_seen"] = gi["user"].nunique().values
    # any user in this ip+win had a success preceded by >=1 fail
    saf_i = (logins_h_sorted.assign(_saf=saf_hit)
             .groupby(["source_ip", "win"])["_saf"].any().rename("saf_any"))
    aggi = aggi.merge(saf_i, on=["source_ip", "win"], how="left")
    ipf = pd.Series(ip_first).rename("ts").reset_index()
    ipf.columns = ["source_ip", "ts"]
    ipf["win0"] = ipf["ts"].dt.floor(window)
    aggi = aggi.merge(ipf, on=["source_ip"], how="left")
    aggi["pair_first_time"] = (aggi["win"] == aggi["win0"]).astype(float)

    for _, r in aggi.iterrows():
        rows.append({
            "entity_user": "*", "entity_ip": r["source_ip"], "win": r["win"],
            "n_events": int(r["n_logins"]), "n_logins": int(r["n_logins"]),
            "n_success": int(r["n_success"]), "n_fail": int(r["n_fail"]),
            "fail_ratio": float(r["n_fail"] / max(r["n_logins"], 1)),
            "distinct_users_seen": float(r["distinct_users_seen"]),
            "distinct_hosts": float(r["distinct_hosts"]),
            "offhours_ratio": float(r["offhours_mean"]),
            "is_night": float(r["win"].hour >= 22 or r["win"].hour < 5),
            "success_after_fail": float(bool(r["saf_any"])),
            "pair_first_time": float(r["pair_first_time"]),
        })

    return pd.DataFrame(rows)


def train_and_flag(agg: pd.DataFrame, features: list[str] = FEATURES,
                   contamination: float = CONTAMINATION,
                   max_flags: int = MAX_FLAGS) -> pd.DataFrame:
    if agg.empty:
        return agg.assign(anomaly_score=[], is_anomaly=[], drivers=[]).head(0), agg
    X = agg[features].to_numpy(dtype=float)
    Xc = np.log1p(X)  # heavy-tailed counts -> compress

    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    scores = iso.fit(Xc).score_samples(Xc)
    labels = iso.fit_predict(Xc)

    agg = agg.copy()
    agg["anomaly_score"] = scores      # lower = more anomalous
    agg["is_anomaly"] = labels == -1

    flagged = agg[agg["is_anomaly"]].sort_values("anomaly_score").head(max_flags).copy()

    # z-score driver attribution vs population
    mu, sigma = Xc.mean(axis=0), Xc.std(axis=0).clip(min=1e-9)
    z = (np.log1p(flagged[features].to_numpy(dtype=float)) - mu) / sigma
    drivers = []
    for row in z:
        order = np.argsort(-np.abs(row))
        top = [features[i] for i in order[:3] if abs(row[i]) >= Z_DRIVER]
        if not top:
            i0 = int(order[0])
            top = [features[i0]]
        drivers.append(top)
    flagged["drivers"] = drivers
    return flagged, agg


def detect_ml(db_path=DB_PATH) -> dict:
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        df = load_events(conn)
        if df.empty:
            print("No events — run app.ingest first.")
            return {"ml_detections": 0}
        agg = build_features(df)
        flagged, _ = train_and_flag(agg)
        conn.execute("DELETE FROM detections WHERE rule_id = 'ML_ANOMALY'")
        rows = []
        for _, r in flagged.iterrows():
            w_start = pd.Timestamp(r["win"])
            w_end = w_start + pd.Timedelta(hours=1)
            if r["entity_user"] == "*":
                ev = df[(df["source_ip"] == r["entity_ip"])
                        & (df["timestamp"] >= w_start) & (df["timestamp"] < w_end)]
                entity = r["entity_ip"] + " (source)"
                who = f"source {r['entity_ip']}"
            else:
                ev = df[(df["user"] == r["entity_user"]) & (df["source_ip"] == r["entity_ip"])
                        & (df["timestamp"] >= w_start) & (df["timestamp"] < w_end)]
                entity = f"{r['entity_user']}@{r['entity_ip']}"
                who = f"user '{r['entity_user']}' from {r['entity_ip']}"
            ids = sorted(int(i) for i in ev["id"].tolist())
            if not ids:
                continue
            sev = float(np.clip(1.5 - r["anomaly_score"] * 3, 1.0, 3.0))
            drv = ", ".join(r["drivers"])
            desc = (f"Anomalous behavior for {who}: {int(r['n_logins'])} logins, "
                    f"{int(r['n_fail'])} fail, fail_ratio={r['fail_ratio']:.2f}, "
                    f"distinct_users_seen={int(r['distinct_users_seen'])}, offhours={r['offhours_ratio']:.2f} "
                    f"— driven by: {drv}")
            d = Detection(
                rule_id="ML_ANOMALY", description=desc, severity_weight=sev,
                matched_event_ids=ids, entity=entity,
                first_seen=ev["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                last_seen=ev["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"),
            )
            rows.append(d.to_row())
        conn.executemany(INSERT_SQL, rows)
        conn.commit()
    print(f"ML anomaly detection: {len(rows)} entity-window(s) flagged")
    for r in rows:
        print(f"  [{r[2]:.1f}] {r[4]:<32} {r[5]}  ({len(json.loads(r[3]))} events)")
    return {"ml_detections": len(rows)}


if __name__ == "__main__":
    detect_ml()
