"""Audit & report generation (Phase 8) — template-driven (Jinja2) Markdown reports.

- build_incident_report(incident_id)   -> per-incident Markdown
- build_run_report()                   -> per-run executive report (all incidents)
- export_reports()                    -> one command: writes both to reports/ (+PDF if weasyprint)

All reports render from the same structured data the dashboard uses
(incidents, detections, risk breakdowns, recommendations) — never raw
pipelines — and carry a generation timestamp.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from db.schema import DB_PATH

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR),
                   autoescape=select_autoescape([]),  # markdown: no escaping
                   trim_blocks=True, lstrip_blocks=True,
                   keep_trailing_newline=True)

RULE_LABELS = {"RULE_BRUTE_FORCE": "Brute force",
               "RULE_SUCCESS_AFTER_FAILS": "Compromise after failures",
               "RULE_CRED_STUFFING": "Credential stuffing",
               "RULE_IMPOSSIBLE_TRAVEL": "Impossible travel",
               "RULE_BACKDOOR_USER": "Backdoor account",
               "RULE_OFFHOURS_LOGIN": "Off-hours login",
               "ML_ANOMALY": "ML anomaly"}

COMPONENT_NAMES = [("entity_sensitivity", "Entity sensitivity"),
                   ("rule_severity", "Rule severity"),
                   ("ml_anomaly", "ML anomaly"),
                   ("corroboration", "Corroboration"),
                   ("outcome", "Outcome"),
                   ("volume", "Volume")]

LEVELS = ["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"]


def _load(incident_id: str | None, db_path: str | Path,
          since: str | None = None, until: str | None = None):
    """Shared data loading for both report types (with optional time range)."""
    conn = sqlite3.connect(db_path)
    q = "SELECT * FROM incidents"
    conds, params = [], []
    if incident_id:
        conds.append("incident_id = ?"); params.append(incident_id)
    if since:
        conds.append("first_seen >= ?"); params.append(since)
    if until:
        conds.append("last_seen <= ?"); params.append(until)
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY risk_score DESC"
    inc = pd.read_sql(q, conn, params=params)
    dets = pd.read_sql("SELECT * FROM detections", conn)
    ev = pd.read_sql("SELECT * FROM events", conn)
    conn.close()
    if not ev.empty:
        ev["timestamp_dt"] = pd.to_datetime(ev["timestamp"])
    return inc, dets, ev


def build_incident_report(incident_id: str, db_path: str | Path = DB_PATH) -> str:
    """Per-incident Markdown report (dashboard detail page + API use this)."""
    inc, dets, ev = _load(incident_id, db_path)
    if inc.empty:
        return f"# Incident {incident_id} not found"
    i = inc.iloc[0]
    det_ids = json.loads(i["detection_ids"])
    ev_ids = json.loads(i["event_ids"])
    sub_dets = dets[dets["id"].isin(det_ids)]
    sub_ev = ev[ev["id"].isin(ev_ids)].sort_values("timestamp")
    # NaN (from pandas) -> None so Jinja's 'or' fallback renders '-'
    sub_ev = sub_ev.astype(object).where(pd.notna(sub_ev), None)

    bd = json.loads(i["risk_breakdown"]) if i["risk_breakdown"] else {}
    components = [{"name": name, "value": bd[key]["value"], "max": bd[key]["max"],
                    "reason": bd[key]["reason"]}
                   for key, name in COMPONENT_NAMES if isinstance(bd.get(key), dict)]
    total = bd.get("total", {"value": i["risk_score"], "reason": i["risk_level"]})

    return ENV.get_template("incident_report.md.j2").render(
        inc=i,
        components=components,
        total=total,
        detections=[{"label": RULE_LABELS.get(d["rule_id"], d["rule_id"]),
                     "description": d["description"], "severity": d["severity_weight"],
                     "first_seen": d["first_seen"], "last_seen": d["last_seen"]}
                    for _, d in sub_dets.iterrows()],
        evidence=sub_ev.to_dict("records"),
        recommendation=i["recommendation"] or "(no recommendation cached)",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def build_run_report(db_path: str | Path = DB_PATH, run: dict | None = None,
                     since: str | None = None, until: str | None = None) -> str:
    """Per-run executive report: every incident + pipeline stats.

    `run` = pipeline result dict (dashboard session state); synthesised from
    the DB when not provided (CLI use)."""
    inc, dets, ev = _load(None, db_path, since, until)
    if inc.empty:
        return f"# No incidents found{' in range' if since or until else ''}"

    if run is None:
        run = {
            "file": str(db_path), "seconds": 0.0,
            "stages": {
                "ingest": {"events": len(ev), "parsed": len(ev), "total_lines": len(ev),
                           "malformed_kept": 0},
                "rules": {"detections": int((dets["rule_id"] != "ML_ANOMALY").sum())},
                "ml": {"detections": int((dets["rule_id"] == "ML_ANOMALY").sum())},
                "correlate": {"incidents": len(inc)},
                "recommend": {"recommended": int(inc["recommendation"].notna().sum()),
                              "total": len(inc)},
            },
        }

    # one-line findings for the executive summary
    findings = []
    for _, i in inc.iterrows():
        short = ""
        if i["recommendation"]:
            short = re.split(r"RECOMMENDED ACTIONS:?", i["recommendation"], flags=re.I, maxsplit=1)[0].replace("SUMMARY:", "")
            short = " ".join(short.split())[:170]
        findings.append(f"**{i['incident_id']} ({i['risk_level']})** {i['entity']}: {short or '—'}")

    window = {"start": inc["first_seen"].min(), "end": inc["last_seen"].max()}
    levels = [{"label": lvl, "count": int((inc["risk_level"] == lvl).sum())} for lvl in LEVELS]

    return ENV.get_template("run_report.md.j2").render(
        run=run, window=window, levels=levels, findings=findings,
        incidents=inc.to_dict("records"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def to_pdf(markdown_text: str, out_path: Path) -> bool:
    """Optional Markdown->PDF. Returns True on success, False if unavailable
    (missing deps or native GTK libs — PDF is a nice-to-have, never a blocker)."""
    import contextlib, io, sys
    try:
        with contextlib.redirect_stderr(io.StringIO()):  # silence weasyprint's banner
            from weasyprint import HTML  # noqa: optional dep
        import markdown as md  # noqa: optional dep
        html = md.markdown(markdown_text, extensions=["tables"])
        HTML(string=f"<meta charset='utf-8'><style>body{{font-family:sans-serif}}</style>{html}").write_pdf(out_path)
        return True
    except Exception:
        return False


def export_reports(db_path: str | Path = DB_PATH, out_dir: str | Path = REPORTS_DIR,
                   with_pdf: bool = True) -> dict:
    """One command: write per-incident reports + the run report to reports/."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.md"):        # one command -> one clean set of reports
        old.unlink()
    for old in out.glob("*.pdf"):
        old.unlink()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    written = {"incidents": [], "run": None, "pdfs": []}

    inc_ids = [r[0] for r in sqlite3.connect(db_path).execute(
        "SELECT incident_id FROM incidents ORDER BY risk_score DESC")]
    for iid in inc_ids:
        text = build_incident_report(iid, db_path)
        p = out / f"{iid}_report.md"
        p.write_text(text, encoding="utf-8")
        written["incidents"].append(str(p))
        if with_pdf:
            pdf = out / f"{iid}_report.pdf"
            if to_pdf(text, pdf):
                written["pdfs"].append(str(pdf))

    run_text = build_run_report(db_path)
    p = out / f"run_report_{ts}.md"
    p.write_text(run_text, encoding="utf-8")
    written["run"] = str(p)
    if with_pdf:
        pdf = out / f"run_report_{ts}.pdf"
        if to_pdf(run_text, pdf):
            written["pdfs"].append(str(pdf))

    print(f"Reports written to {out}\\")
    for k, v in written.items():
        for f in (v if isinstance(v, list) else [v]):
            if f:
                print(f"  {k:<10} {f}")
    if with_pdf and not written["pdfs"]:
        print("  (PDF skipped — weasyprint/markdown not installed)")
    return written


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Export Markdown(/PDF) audit reports")
    ap.add_argument("--db", default=str(DB_PATH))
    ap.add_argument("--incident", default=None, help="export a single incident")
    ap.add_argument("--since", default=None, help="time range start (YYYY-MM-DD HH:MM:SS)")
    ap.add_argument("--until", default=None, help="time range end")
    ap.add_argument("--no-pdf", action="store_true")
    a = ap.parse_args()
    if a.incident:
        print(build_incident_report(a.incident, a.db))
    elif a.since or a.until:
        print(build_run_report(a.db, since=a.since, until=a.until))
    else:
        export_reports(a.db, with_pdf=not a.no_pdf)
