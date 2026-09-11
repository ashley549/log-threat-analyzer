"""E2E: SENTINEL web frontend + API journey (replaces the old Streamlit test).

Journey: overview (empty) -> analyze (run web demo) -> overview (populated)
       -> incidents -> incident detail -> risk profiles -> threat intel
       -> reports -> settings. Exercises the real HTTP endpoints (TestClient)
       and the SPA files served as static assets.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import app.main as main

ok = True


def check(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(f"  {name:<56} {'PASS' if cond else 'FAIL'} {extra if not cond else ''}")


client = TestClient(main.app)

# --- 1) frontend assets served ------------------------------------------------
r = client.get("/")
check("GET / serves the SPA", r.status_code == 200 and "SENTINEL" in r.text)
r = client.get("/css/theme.css")
check("GET /css/theme.css", r.status_code == 200 and "emerald" in r.text.lower() or r.status_code == 200)
r = client.get("/js/app.js")
check("GET /js/app.js", r.status_code == 200 and "SENTINEL" in r.text)

# --- 2) overview: empty state (fresh temp DB) -----------------------------------
import os
import tempfile
main.API_DB = Path(tempfile.gettempdir()) / "j001_web_test.db"
if main.API_DB.exists():
    main.API_DB.unlink()
r = client.get("/api/overview")
check("overview empty -> 503", r.status_code == 503)
r = client.get("/api/incidents")
check("incidents empty -> 503", r.status_code == 503)

# --- 3) run the web security demo through /api/analyze --------------------------
r = client.post("/api/analyze?demo=web")
check("POST /api/analyze?demo=web", r.status_code == 200, r.text[:200])
res = r.json()
check("demo pipeline returns incidents", res.get("incidents") == 5, f"got {res.get('incidents')}")
check("apache format auto-detected", res.get("format") == "apache", res.get("format"))
check("0 rejected lines", res["stages"]["ingest"]["n_rejected"] == 0)

# --- 4) overview populated ------------------------------------------------------
r = client.get("/api/overview")
check("GET /api/overview", r.status_code == 200)
ov = r.json()
check("overview has 5 incidents", ov["incidents_total"] == 5, str(ov["incidents_total"]))
check("severity counts sum to incidents", sum(ov["severity"].values()) == 5)
check("timeline present", isinstance(ov["timeline"], list))
check("distribution present", len(ov["distribution"]) >= 1)
check("top entities present", len(ov["top_entities"]) >= 1)
check("feed present", len(ov["feed"]) >= 1)
check("posture score 0-100", 0 <= ov["posture"]["score"] <= 100)

# --- 5) incidents + detail --------------------------------------------------------
r = client.get("/api/incidents")
check("GET /api/incidents", r.status_code == 200)
rows = r.json()
check("5 incidents listed", len(rows) == 5)
check("sorted by risk desc", all(rows[i]["risk"] >= rows[i + 1]["risk"] for i in range(len(rows) - 1)))
check("attack names resolved", rows[0]["attack"] != "")

r = client.get("/api/incidents?q=INC-001")
check("filter q=INC-001", r.status_code == 200 and len(r.json()) == 1)
r = client.get("/api/incidents", params={"severity": "🟠 High"})
high_rows = r.json()
check("filter severity=High", r.status_code == 200 and len(high_rows) >= 1
      and all(row["level"] == "🟠 High" for row in high_rows))

r = client.get("/api/incidents/INC-001")
check("GET /api/incidents/INC-001", r.status_code == 200)
d = r.json()
check("detail has breakdown", len(d["breakdown"]) == 6)
check("detail has timeline", len(d["timeline"]) >= 1)
check("detail has detections", len(d["detections"]) >= 1)
check("detail has evidence", len(d["evidence"]) >= 1)
check("detail has actions", len(d["actions"]) >= 1)
r = client.get("/api/incidents/INC-999")
check("missing incident -> 404", r.status_code == 404)

# --- 6) risk profiles --------------------------------------------------------------
r = client.get("/api/entities")
check("GET /api/entities", r.status_code == 200)
ents = r.json()
check("entities have behavior bins", all("behavior" in e for e in ents))
check("entities have risk + level", all("risk" in e and "level" in e for e in ents))

# --- 7) threat intel ------------------------------------------------------------------
r = client.get("/api/intel")
check("GET /api/intel", r.status_code == 200)
intel = r.json()
check("intel has zone classification", all("zone" in x for x in intel))

# --- 8) reports + exports ----------------------------------------------------------
r = client.get("/api/reports/run")
check("GET /api/reports/run", r.status_code == 200 and len(r.text) > 500)
r = client.get("/api/reports/incident/INC-001")
check("GET /api/reports/incident/INC-001", r.status_code == 200 and len(r.text) > 300)
r = client.get("/api/exports/incidents.csv")
check("GET /api/exports/incidents.csv", r.status_code == 200 and "incident_id" in r.text)
r = client.get("/api/exports/detections.csv")
check("GET /api/exports/detections.csv", r.status_code == 200)
r = client.get("/api/exports/analysis.json")
check("GET /api/exports/analysis.json", r.status_code == 200)

# --- 9) settings + demo-info ---------------------------------------------------------
r = client.get("/api/settings")
check("GET /api/settings", r.status_code == 200)
check("settings has rules+ml", "rules" in r.json() and "ml" in r.json())
r = client.get("/api/demo-info")
check("GET /api/demo-info", r.status_code == 200)

# --- 9b) reset round-trip --------------------------------------------------------------
r = client.post("/api/reset")
check("POST /api/reset", r.status_code == 200 and r.json().get("ok") is True)
r = client.get("/api/overview")
check("overview empty after reset -> 503", r.status_code == 503)
r = client.post("/api/analyze?demo=web")
check("re-analyze after reset", r.status_code == 200)
r = client.get("/api/overview")
check("overview repopulated after reset", r.status_code == 200)

# --- 10) SSH sample regression (full pipeline via API) --------------------------------
r = client.post("/api/analyze?demo=ssh")
check("POST /api/analyze?demo=ssh", r.status_code == 200, r.text[:200])
res = r.json()
check("ssh pipeline -> 5 incidents", res.get("incidents") == 5, f"got {res.get('incidents')}")
check("ssh format detected", res.get("format") == "auth", res.get("format"))

# legacy endpoint contract still intact
r = client.get("/dashboard/summary")
check("legacy /dashboard/summary", r.status_code == 200)
r = client.get("/incidents")
check("legacy /incidents", r.status_code == 200 and len(r.json()) == 5)

# --- 11) pipeline verifiers still PASS (ground truth) -----------------------------------
import subprocess
r_ = subprocess.run([sys.executable, "-m", "app.verify_detect"], capture_output=True, text=True, cwd=str(ROOT))
ssh_ok = all(f"{sid} " in r_.stdout and "PASS" in r_.stdout for sid in ["S1", "S2", "S3", "S4"]) \
    and "MISS" not in r_.stdout and "FAIL" not in r_.stdout
check("SSH sample verifiers still PASS", ssh_ok, r_.stdout[-200:] if not ssh_ok else "")

print("\n" + ("JOURNEY COMPLETE — ALL PASS" if ok else "ISSUES FOUND"))
sys.exit(0 if ok else 1)
