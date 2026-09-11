"""FastAPI backend for SENTINEL — serves the SPA frontend + JSON API.

Endpoints:
    POST /api/analyze                upload a log file; runs the whole pipeline
    GET  /api/overview               KPIs, posture, timeline, distribution, entities, feed
    GET  /api/incidents              list incidents (optional q / severity filters)
    GET  /api/incidents/{id}         one incident: breakdown, detections, evidence, response
    GET  /api/entities               risk-profile aggregates per entity + behavior bins
    GET  /api/intel                  per-source-IP reputation from local evidence
    GET  /api/reports/run            executive run report (Markdown)
    GET  /api/reports/incident/{id}  per-incident Markdown report
    GET  /api/exports/{kind}         incidents.csv / detections.csv / analysis.json
    GET  /api/settings               engine configuration + LLM key status
    GET  /api/demo-info              what the built-in security demo contains
    GET  /*                          static SPA (frontend/)

Legacy (unchanged, used by app/test_api.py):
    POST /ingest, GET /incidents, GET /incidents/{id},
    GET /incidents/{id}/report, GET /dashboard/summary

Run: uvicorn app.main:app --reload
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.pipeline import run_pipeline
from app.report import build_incident_report, build_run_report

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"

app = FastAPI(title="SENTINEL — Log Security Analyzer", version="1.0.0")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}

# The web app's own analysis store — user uploads and demo runs land here.
# A fresh server starts empty (the UI shows the upload/demo CTA).
# db/logsec.db is the internal CLI/test-fixture DB and is never served here.
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", str(ROOT / "db")))
API_DB = DATA_DIR / "webapp.db"


def _db() -> Path:
    return Path(API_DB)


def _run_analysis(log_path: str, fmt: str) -> dict:
    """Run the pipeline into a scratch DB, then promote it on success.

    The scratch-first dance means a failed/garbage upload never wipes the
    previous analysis. Runs in a worker thread so the event loop stays free.
    """
    # Work DB must live NEXT TO the real store: os.replace() is atomic but
    # cannot cross drives on Windows (WinError 17), and temp/ may be on C:
    # while the project is on D:.
    API_DB.parent.mkdir(parents=True, exist_ok=True)
    work = API_DB.parent / f"sentinel_work_{uuid4().hex}.db"
    try:
        result = run_pipeline(log_path, work, fmt=fmt)
        last_err: Exception | None = None
        for _ in range(10):                # Windows: AV/indexer may briefly hold the file
            try:
                work.replace(API_DB)       # atomic overwrite of the previous analysis
                return result
            except PermissionError as e:
                last_err = e
                time.sleep(0.2)
        raise RuntimeError(
            f"Could not update the analysis store {API_DB.name}: {last_err}")
    finally:
        try:
            work.unlink(missing_ok=True)
        except PermissionError:
            pass


def _connect() -> sqlite3.Connection:
    db = _db()
    if not db.exists():
        raise HTTPException(503, "No analysis yet — POST /api/analyze first (or run the demo).")
    return sqlite3.connect(db)


def _has_data(db: Path) -> bool:
    if not db.exists():
        return False
    with closing(sqlite3.connect(db)) as conn:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'").fetchone()
    return row is not None


# ===========================================================================
# shared loaders
# ===========================================================================

ATTACK_NAMES = {
    "RULE_BRUTE_FORCE": "Brute Force Attack", "RULE_WEB_BRUTEFORCE": "Brute Force Attack",
    "RULE_SUCCESS_AFTER_FAILS": "Compromise After Failures", "RULE_CRED_STUFFING": "Credential Stuffing",
    "RULE_SQLI_ATTEMPT": "SQL Injection", "RULE_XSS_ATTEMPT": "Cross-Site Scripting",
    "RULE_TRAVERSAL_ATTEMPT": "Path Traversal", "RULE_WEB_RECON": "Recon Scanning",
    "RULE_BACKDOOR_USER": "Backdoor Account", "RULE_IMPOSSIBLE_TRAVEL": "Impossible Travel",
    "RULE_OFFHOURS_LOGIN": "Off-Hours Login", "ML_ANOMALY": "Behavioral Anomaly",
}

CATEGORY = {
    "RULE_BRUTE_FORCE": "Brute Force", "RULE_WEB_BRUTEFORCE": "Brute Force",
    "RULE_SUCCESS_AFTER_FAILS": "Credential Abuse", "RULE_CRED_STUFFING": "Credential Abuse",
    "RULE_SQLI_ATTEMPT": "SQL Injection", "RULE_XSS_ATTEMPT": "XSS",
    "RULE_TRAVERSAL_ATTEMPT": "Path Traversal", "RULE_WEB_RECON": "Scanning",
    "RULE_BACKDOOR_USER": "Privilege Escalation", "RULE_IMPOSSIBLE_TRAVEL": "Account Takeover",
    "RULE_OFFHOURS_LOGIN": "Anomalous Traffic", "ML_ANOMALY": "Anomalous Traffic",
}

SEVERITIES = ["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"]


def _short_summary(rec: str | None, limit: int = 130) -> str | None:
    if not rec:
        return None
    s = re.split(r"RECOMMENDED ACTIONS:?", rec, flags=re.I, maxsplit=1)[0].replace("SUMMARY:", "")
    return " ".join(s.split())[:limit]


def _parse_actions(rec: str | None) -> list[str]:
    """Extract action bullets from an LLM/playbook recommendation.
    Tolerant of LLM formatting drift: '- ', '* ', '• ' and '1.'/'1)' styles."""
    if not rec:
        return []
    m = re.search(r"RECOMMENDED ACTIONS:?", rec, flags=re.I)
    body = rec[m.end():] if m else rec
    actions: list[str] = []
    for line in body.splitlines():
        mm = re.match(r"^\s*(?:[-*•\u2022]|\d+[.)])\s+(.+)$", line)
        if mm:
            a = mm.group(1).strip()
            if a and a not in actions:
                actions.append(a)
    return actions[:6]


def _load_core(db: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if not _has_data(db):
        raise HTTPException(503, "No analysis yet")
    with closing(sqlite3.connect(db)) as conn:
        inc = pd.read_sql("SELECT * FROM incidents ORDER BY risk_score DESC", conn)
        ev = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status, host, source_file FROM events", conn)
        dets = pd.read_sql("SELECT id, rule_id, severity_weight, entity, incident_id FROM detections", conn)
    if not ev.empty:
        ev["timestamp"] = pd.to_datetime(ev["timestamp"], errors="coerce")
    return inc, ev, dets


# ===========================================================================
# new JSON API (consumed by frontend/)
# ===========================================================================

@app.post("/api/analyze")
async def api_analyze(file: UploadFile | None = File(None), fmt: str = Query("auto", pattern="^(auto|auth|json|apache)$"),
                      demo: str = Query("none", pattern="^(none|web|ssh)$")):
    """Upload a log file — or demo=web/ssh to run a bundled sample — then run the pipeline."""
    if demo != "none" and file is None:
        src = ROOT / ("data/demo/demo.log" if demo == "web" else "data/synthetic/auth.log")
        if not src.exists():
            if demo == "web":
                import subprocess, sys
                try:
                    subprocess.run([sys.executable, "-m", "generator.demo"], check=True, cwd=str(ROOT))
                except subprocess.CalledProcessError as e:
                    raise HTTPException(500, "Could not generate the demo sample.") from e
            else:
                raise HTTPException(500, "SSH sample missing — run generator first.")
        tmp_path, name = str(src), src.name
    else:
        if file is None:
            raise HTTPException(400, "Provide a file or demo=web|ssh.")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            while chunk := await file.read(1 << 20):   # stream to disk, don't buffer in RAM
                tmp.write(chunk)
            tmp_path, name = tmp.name, (file.filename or "upload.log")
    try:
        result = await run_in_threadpool(_run_analysis, tmp_path, fmt)
        result["file_name"] = name
        return result
    except HTTPException:
        raise
    except ValueError as e:                # parser: no parseable events / unknown format
        raise HTTPException(400, str(e)) from None
    except Exception as e:                 # readable message instead of a raw HTML 500
        logging.getLogger("uvicorn.error").exception("analyze failed")
        raise HTTPException(500, f"Analysis failed: {e}") from None
    finally:
        if demo == "none":
            Path(tmp_path).unlink(missing_ok=True)


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
def chrome_devtools_probe():
    """Chrome DevTools probes every page for this project-config file;
    answer with empty JSON so the requests stop retrying (log noise)."""
    return {}


@app.post("/api/reset")
def api_reset():
    """Delete the current analysis — back to the clean 'no data' state."""
    try:
        API_DB.unlink()
        return {"ok": True, "message": "Analysis cleared. Upload a new log to start over."}
    except FileNotFoundError:
        return {"ok": True, "message": "Nothing to clear — no analysis loaded."}
    except PermissionError as e:
        raise HTTPException(
            503, "The analysis database is busy — stop any other analysis, wait a "
                 "moment and try Reset again.") from e


@app.get("/api/overview")
def api_overview():
    inc, ev, dets = _load_core(_db())
    if inc.empty:
        raise HTTPException(503, "No analysis yet")

    n_crit = int((inc["risk_level"] == "🔴 Critical").sum())
    n_high = int((inc["risk_level"] == "🟠 High").sum())
    n_med = int((inc["risk_level"] == "🟡 Medium").sum())
    n_low = int((inc["risk_level"] == "🟢 Low").sum())
    n_ml = int((dets["rule_id"] == "ML_ANOMALY").sum()) if not dets.empty else 0
    n_rules = int((dets["rule_id"] != "ML_ANOMALY").sum()) if not dets.empty else 0
    fails = int((ev["status"] == "fail").sum())

    worst = float(inc["risk_score"].max())
    posture = int(round(worst * 10))
    label = "HIGH RISK" if posture >= 80 else "ELEVATED" if posture >= 60 else "GUARDED" if posture >= 30 else "SECURE"

    # timeline: incidents per hour by severity
    tl = inc.copy()
    tl["start"] = pd.to_datetime(tl["first_seen"], errors="coerce")
    tl = tl.dropna(subset=["start"])
    tl["bucket"] = tl["start"].dt.floor("h")
    chart = []
    if not tl.empty:
        g = tl.groupby(["bucket", "risk_level"]).size().reset_index(name="n")
        for _, r in g.iterrows():
            chart.append({"t": r["bucket"].isoformat(), "level": r["risk_level"], "n": int(r["n"])})

    # distribution by attack category
    dist = []
    if not dets.empty:
        sub = dets[dets["rule_id"] != "ML_ANOMALY"].copy()
        sub["cat"] = sub["rule_id"].map(CATEGORY).fillna("Other")
        vc = sub["cat"].value_counts()
        dist = [{"category": k, "count": int(v)} for k, v in vc.items()]

    # top entities
    entities = []
    for _, i in inc.iterrows():
        ids = set(json.loads(i["event_ids"]))
        sub = ev[ev["id"].isin(ids)]
        ip = str(i["entity"]).split("@")[-1].replace(" (source)", "")
        entities.append({
            "entity": i["entity"], "ip": ip, "risk": round(float(i["risk_score"]), 2),
            "level": i["risk_level"], "detections": int(i["n_detections"]),
            "events": int(i["n_events"]), "last": i["last_seen"],
            "fails": int((sub["status"] == "fail").sum()),
        })

    feed = []
    for _, i in inc.head(7).iterrows():
        feed.append({
            "incident_id": i["incident_id"], "entity": i["entity"],
            "level": i["risk_level"], "risk": round(float(i["risk_score"]), 2),
            "summary": _short_summary(i["recommendation"], 110) or i["first_seen"],
            "window": f'{i["first_seen"]} → {i["last_seen"]}',
        })

    return {
        "events": int(len(ev)),
        "detections_rule": n_rules,
        "detections_ml": n_ml,
        "incidents_total": int(len(inc)),
        "severity": {"critical": n_crit, "high": n_high, "medium": n_med, "low": n_low},
        "failed_auth": fails,
        "posture": {"score": posture, "label": label},
        "avg_risk": round(float(inc["risk_score"].mean()), 2),
        "timeline": chart,
        "distribution": dist,
        "top_entities": entities[:8],
        "feed": feed,
    }


@app.get("/api/incidents")
def api_incidents(q: str = "", severity: str = ""):
    inc, ev, dets = _load_core(_db())
    if inc.empty:
        raise HTTPException(503, "No analysis yet")

    rows = []
    for _, i in inc.iterrows():
        sub = dets[dets["incident_id"] == i["incident_id"]]
        attack = next((ATTACK_NAMES.get(r) for r in sub["rule_id"] if r in ATTACK_NAMES), "Suspicious Activity")
        rows.append({
            "incident_id": i["incident_id"], "entity": i["entity"], "attack": attack,
            "level": i["risk_level"], "risk": round(float(i["risk_score"]), 2),
            "summary": _short_summary(i["recommendation"]),
            "first_seen": i["first_seen"], "last_seen": i["last_seen"],
            "n_detections": int(i["n_detections"]), "n_events": int(i["n_events"]),
        })

    if severity:
        want = [s.strip() for s in severity.split(",") if s.strip()]
        rows = [r for r in rows if r["level"] in want]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["incident_id"].lower() or ql in r["entity"].lower()
                or ql in (r["summary"] or "").lower() or ql in r["attack"].lower()]
    return rows


@app.get("/api/incidents/{incident_id}")
def api_incident_detail(incident_id: str):
    if "/" in incident_id or "\\" in incident_id:
        raise HTTPException(400, "bad id")
    db = _db()
    with closing(sqlite3.connect(db)) as conn:
        row = conn.execute(
            "SELECT incident_id, entity, first_seen, last_seen, risk_score, risk_level, "
            "risk_breakdown, n_detections, n_events, recommendation, detection_ids, event_ids "
            "FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(404, f"incident {incident_id} not found")
        det_ids = json.loads(row[10])
        ev_ids = json.loads(row[11])
        dets = pd.read_sql(f"SELECT * FROM detections WHERE id IN ({','.join(map(str, det_ids))})", conn)
        ev = pd.read_sql(f"SELECT * FROM events WHERE id IN ({','.join(map(str, ev_ids))}) ORDER BY timestamp", conn)
        # NaN (from NULL columns, e.g. web-log users) -> None so JSON stays valid
        ev = ev.astype(object).where(pd.notna(ev), None)

    bd = json.loads(row[6]) if row[6] else {}
    breakdown = [{"factor": k, "label": lbl, "value": v["value"], "max": v["max"], "reason": v["reason"]}
                 for k, lbl, v in (("entity_sensitivity", "Entity Sensitivity", bd.get("entity_sensitivity", {})),
                                   ("rule_severity", "Rule Severity", bd.get("rule_severity", {})),
                                   ("ml_anomaly", "ML Anomaly", bd.get("ml_anomaly", {})),
                                   ("corroboration", "Corroboration", bd.get("corroboration", {})),
                                   ("outcome", "Outcome", bd.get("outcome", {})),
                                   ("volume", "Evidence Volume", bd.get("volume", {})))
                 if isinstance(v, dict) and "value" in v]

    # timeline buckets
    evs = ev.copy()
    timeline = []
    if not evs.empty:
        evs["ts"] = pd.to_datetime(evs["timestamp"], errors="coerce")
        evs = evs.dropna(subset=["ts"])
        bins = min(len(evs), 12)
        if bins and bins > 0:
            evs["bucket"] = pd.cut(evs["ts"], bins=bins)
            for b, g in evs.groupby("bucket", observed=True):
                timeline.append({
                    "t": g["ts"].iloc[0].strftime("%H:%M"),
                    "events": int(len(g)),
                    "fails": int((g["status"] == "fail").sum()),
                    "success": int((g["status"] == "success").sum()),
                })

    rec = row[9] or ""
    actions = _parse_actions(rec)
    fallback = "[generated by built-in" in rec

    return {
        "incident_id": row[0], "entity": row[1],
        "first_seen": row[2], "last_seen": row[3],
        "risk": round(float(row[4]), 2), "level": row[5],
        "risk_total_reason": bd.get("total", {}).get("reason", ""),
        "n_detections": row[7], "n_events": row[8],
        "breakdown": breakdown,
        "summary": _short_summary(rec, 100000),
        "actions": actions,
        "llm_fallback": fallback,
        "timeline": timeline,
        "detections": [
            {"rule_id": d["rule_id"], "name": ATTACK_NAMES.get(d["rule_id"], d["rule_id"]),
             "kind": "ml" if d["rule_id"] == "ML_ANOMALY" else "rule",
             "description": d["description"], "severity": float(d["severity_weight"]),
             "first_seen": d["first_seen"], "last_seen": d["last_seen"]}
            for _, d in dets.iterrows()],
        "evidence": [
            {"timestamp": e[0], "source_ip": e[1], "user": e[2], "event_type": e[3],
             "status": e[4], "host": e[5], "raw_line": e[6]}
            for e in ev[["timestamp", "source_ip", "user", "event_type", "status", "host", "raw_line"]]
            .itertuples(index=False, name=None)],
    }


@app.get("/api/entities")
def api_entities():
    inc, ev, dets = _load_core(_db())
    if inc.empty:
        raise HTTPException(503, "No analysis yet")
    out = []
    for _, i in inc.iterrows():
        ids = set(json.loads(i["event_ids"]))
        sub = ev[ev["id"].isin(ids)].sort_values("timestamp")
        ip = str(i["entity"]).split("@")[-1].replace(" (source)", "")
        user = str(i["entity"]).split("@")[0] if "@" in str(i["entity"]) else None
        ent_ev = sub[(sub["source_ip"] == ip) | (sub["user"] == user)] if user else sub[sub["source_ip"] == ip]
        sub_dets = dets[dets["incident_id"] == i["incident_id"]]
        # behavior bins: risk signal per 10-min bucket
        bins = []
        if not ent_ev.empty:
            e = ent_ev.copy()
            e["min"] = e["timestamp"].dt.floor("10min")
            for b, g in e.groupby("min"):
                fails = int((g["status"] == "fail").sum())
                atk = int(g["event_type"].isin(["sqli_attempt", "xss_attempt", "traversal_attempt",
                                                "sensitive_probe", "ssh_login"]).sum())
                score = min(10.0, (fails + atk) / 3 + (10 if "success" in set(g["status"]) and fails > 3 else 0))
                bins.append({"t": str(b), "risk": round(score, 2), "events": int(len(g))})
        out.append({
            "entity": i["entity"], "incident_id": i["incident_id"], "ip": ip,
            "user": user if user and user != "*" else None,
            "level": i["risk_level"], "risk": round(float(i["risk_score"]), 2),
            "first_seen": i["first_seen"], "last_seen": i["last_seen"],
            "n_events": int(len(ent_ev)),
            "n_fail": int((ent_ev["status"] == "fail").sum()),
            "n_anomalies": int((sub_dets["rule_id"] == "ML_ANOMALY").sum()),
            "n_detections": int(i["n_detections"]),
            "recommendation": _short_summary(i["recommendation"], 260),
            "behavior": bins,
        })
    return out


@app.get("/api/intel")
def api_intel():
    inc, ev, _ = _load_core(_db())
    if inc.empty:
        raise HTTPException(503, "No analysis yet")

    def zone(ip: str) -> str:
        if not isinstance(ip, str):
            return "?"
        return "internal" if ip.startswith(("10.", "192.168.", "172.")) else "external"

    rows = []
    for _, i in inc.iterrows():
        ids = set(json.loads(i["event_ids"]))
        sub = ev[ev["id"].isin(ids)]
        ip = str(i["entity"]).split("@")[-1].replace(" (source)", "")
        rows.append({"ip": ip, "zone": zone(ip), "risk": float(i["risk_score"]),
                     "events": len(sub), "fails": int((sub["status"] == "fail").sum()),
                     "first": i["first_seen"], "last": i["last_seen"]})
    if not rows:
        return []
    rep = (pd.DataFrame(rows).groupby("ip")
           .agg(zone=("zone", "first"), risk=("risk", "max"), events=("events", "sum"),
                fails=("fails", "sum"), first=("first", "min"), last=("last", "max"))
           .reset_index().sort_values("risk", ascending=False))
    return rep.to_dict("records")


@app.get("/api/reports/run", response_class=PlainTextResponse)
def api_run_report():
    return build_run_report(_db(), run=None)


@app.get("/api/reports/incident/{incident_id}", response_class=PlainTextResponse)
def api_incident_report(incident_id: str):
    if "/" in incident_id or "\\" in incident_id:
        raise HTTPException(400, "bad id")
    return build_incident_report(incident_id, str(_db()))


@app.get("/api/exports/{kind}")
def api_exports(kind: str):
    db = _db()
    with closing(sqlite3.connect(db)) as conn:
        inc = pd.read_sql("SELECT incident_id, entity, first_seen, last_seen, risk_score, risk_level, "
                          "n_detections, n_events FROM incidents", conn)
        dets = pd.read_sql("SELECT rule_id, description, severity_weight, entity, first_seen, last_seen, "
                           "incident_id FROM detections", conn)
    if kind == "incidents.csv":
        return PlainTextResponse(inc.to_csv(index=False), media_type="text/csv")
    if kind == "detections.csv":
        return PlainTextResponse(dets.to_csv(index=False), media_type="text/csv")
    if kind == "analysis.json":
        return PlainTextResponse(json.dumps({"incidents": inc.to_dict("records"),
                                             "detections": dets.to_dict("records")}, indent=2, default=str),
                                 media_type="application/json")
    raise HTTPException(404, f"unknown export {kind}")


@app.get("/api/settings")
def api_settings():
    import os
    import sys as _sys
    return {
        "rules": {
            "ssh": ["brute force", "success-after-fails", "credential stuffing",
                    "impossible travel", "backdoor user", "off-hours login"],
            "web": ["login brute force", "recon scanning", "SQL injection", "XSS", "path traversal"],
            "count": 11,
        },
        "ml": {"model": "IsolationForest", "trees": 200, "contamination": 0.08,
               "features": 11, "windows": "1h per user@ip and per source IP"},
        "scoring": {"components": ["entity sensitivity", "rule severity", "ML corroboration",
                                   "multi-source agreement", "outcome", "volume"], "range": "0-10"},
        "recommendation": {
            "mode": "AI (Gemini)" if os.environ.get("GEMINI_API_KEY") else "Built-in playbook (fallback)",
            "gemini_key": bool(os.environ.get("GEMINI_API_KEY")),
        },
        "runtime": {"python": _sys.version.split()[0], "storage": "SQLite",
                    "parsers": "syslog-auth / Apache-Nginx-combined / JSON-lines (auto-detect)"},
    }


@app.get("/api/demo-info")
def api_demo_info():
    return {
        "web": {"features": ["Web brute force (401s → successful login)", "Recon scan of sensitive paths",
                             "SQL injection campaign", "XSS probes", "Path traversal", "140 lines of normal traffic"]},
        "ssh": {"features": ["Brute force on root", "Credential stuffing from a 5-IP botnet",
                             "Privilege escalation → backdoor user", "Impossible travel"]},
    }


# ===========================================================================
# legacy endpoints (kept for app/test_api.py + CLI consumers)
# ===========================================================================

@app.post("/ingest")
async def ingest(file: UploadFile = File(...), fmt: str = Query("auto", pattern="^(auto|auth|json|apache)$")):
    """Upload a log file; runs the whole pipeline and returns the summary."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        return await run_in_threadpool(_run_analysis, tmp_path, fmt)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@app.get("/incidents")
def list_incidents():
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT incident_id, entity, first_seen, last_seen, risk_score, risk_level, "
            "n_detections, n_events, recommendation FROM incidents ORDER BY risk_score DESC").fetchall()
    return [
        {"incident_id": r[0], "entity": r[1], "first_seen": r[2], "last_seen": r[3],
         "risk_score": r[4], "risk_level": r[5], "n_detections": r[6], "n_events": r[7],
         "summary": _short_summary(r[8])}
        for r in rows
    ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT incident_id, entity, first_seen, last_seen, risk_score, risk_level, "
            "risk_breakdown, n_detections, n_events, recommendation, detection_ids, event_ids "
            "FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(404, f"incident {incident_id} not found")
        det_ids = json.loads(row[10])
        ev_ids = json.loads(row[11])
        dets = conn.execute(
            f"SELECT rule_id, description, severity_weight, first_seen, last_seen FROM detections WHERE id IN ({','.join(map(str, det_ids))})").fetchall()
        ev = conn.execute(
            f"SELECT timestamp, user, source_ip, event_type, status, host, raw_line FROM events WHERE id IN ({','.join(map(str, ev_ids))}) ORDER BY timestamp").fetchall()
    return {
        "incident_id": row[0], "entity": row[1], "first_seen": row[2], "last_seen": row[3],
        "risk_score": row[4], "risk_level": row[5],
        "risk_breakdown": json.loads(row[6]) if row[6] else None,
        "n_detections": row[7], "n_events": row[8], "recommendation": row[9],
        "detections": [
            {"rule_id": d[0], "description": d[1], "severity": d[2], "first_seen": d[3], "last_seen": d[4]}
            for d in dets],
        "evidence": [
            {"timestamp": e[0], "user": e[1], "source_ip": e[2], "event_type": e[3],
             "status": e[4], "host": e[5], "raw_line": e[6]}
            for e in ev],
    }


@app.get("/incidents/{incident_id}/report", response_class=PlainTextResponse)
def incident_report(incident_id: str):
    if "/" in incident_id or "\\" in incident_id:
        raise HTTPException(400, "bad id")
    return build_incident_report(incident_id, str(_db()))


@app.get("/dashboard/summary")
def dashboard_summary():
    with closing(_connect()) as conn:
        levels = dict(conn.execute(
            "SELECT risk_level, COUNT(*) FROM incidents GROUP BY risk_level").fetchall())
        inc = pd.read_sql("SELECT incident_id, entity, first_seen, risk_score, risk_level, event_ids FROM incidents", conn)
        ev = pd.read_sql("SELECT id, timestamp, source_ip, user FROM events", conn)
    timeline = sorted(inc["first_seen"].tolist())
    top = []
    for _, i in inc.iterrows():
        ids = set(json.loads(i["event_ids"]))
        sub = ev[ev["id"].isin(ids)]
        for ip, cnt in sub["source_ip"].value_counts().items():
            top.append({"ip": ip, "events": int(cnt), "incident_id": i["incident_id"]})
    seen, offenders = set(), []
    for t in sorted(top, key=lambda x: -x["events"]):
        if t["ip"] not in seen:
            seen.add(t["ip"])
            offenders.append(t)
        if len(offenders) >= 5:
            break
    return {
        "n_incidents": len(inc),
        "severity_counts": {"critical": levels.get("🔴 Critical", 0),
                            "high": levels.get("🟠 High", 0),
                            "medium": levels.get("🟡 Medium", 0),
                            "low": levels.get("🟢 Low", 0)},
        "incidents_over_time": timeline,
        "top_offenders": offenders,
    }


# ===========================================================================
# favicons & PWA icons (generated by scripts/make_icons.py -> frontend/icons/)
# ===========================================================================

ICONS_DIR = FRONTEND_DIR / "icons"


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico():
    return FileResponse(ICONS_DIR / "favicon.ico", media_type="image/x-icon")


@app.get("/favicon.svg", include_in_schema=False)
def favicon_svg():
    return FileResponse(ICONS_DIR / "favicon.svg", media_type="image/svg+xml")


@app.get("/apple-touch-icon.png", include_in_schema=False)
def apple_touch_icon():
    return FileResponse(ICONS_DIR / "apple-touch-icon.png", media_type="image/png")


@app.get("/site.webmanifest", include_in_schema=False)
def webmanifest():
    return FileResponse(FRONTEND_DIR / "site.webmanifest", media_type="application/manifest+json")


# ===========================================================================
# static SPA (must be mounted last)
# ===========================================================================

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
