"""Test FastAPI endpoints with TestClient against the existing main DB."""
import shutil
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main

# make the API serve a copy of the already-built main DB (repo db/ stays untouched)
main.API_DB = Path(tempfile.gettempdir()) / "j001_api_test.db"
shutil.copy("db/logsec.db", main.API_DB)
client = TestClient(main.app)

def check(name, resp, expect=200):
    ok = resp.status_code == expect
    print(f"  {name:<42} {resp.status_code} {'OK' if ok else 'FAIL: ' + resp.text[:200]}")
    return ok

all_ok = True
r = client.get("/dashboard/summary")
all_ok &= check("GET /dashboard/summary", r)
s = r.json()
print(f"    -> incidents={s['n_incidents']}, severity={s['severity_counts']}, offenders={[o['ip'] for o in s['top_offenders'][:3]]}")

r = client.get("/incidents")
all_ok &= check("GET /incidents", r)
incs = r.json()
print(f"    -> {[i['incident_id'] for i in incs]} sorted by risk: {[i['risk_score'] for i in incs]}")
print(f"    -> first summary: {incs[0]['summary'][:90]}...")

r = client.get("/incidents/INC-005")
all_ok &= check("GET /incidents/INC-005", r)
d = r.json()
print(f"    -> {d['entity']} {d['risk_level']} {d['risk_score']}, {len(d['detections'])} detections, {len(d['evidence'])} evidence rows")
print(f"    -> breakdown factors: {list(d['risk_breakdown'].keys())}")

r = client.get("/incidents/INC-999")
all_ok &= check("GET /incidents/INC-999 (missing)", r, 404)

r = client.get("/incidents/INC-005/report")
all_ok &= check("GET /incidents/INC-005/report", r)
print(f"    -> report chars: {len(r.text)}, starts: {r.text.splitlines()[0]!r}")

# upload path: run pipeline on sample via API
r = client.post("/ingest", files={"file": ("auth.log", open("data/synthetic/auth.log", "rb"), "text/plain")})
all_ok &= check("POST /ingest (full pipeline)", r)
print(f"    -> pipeline result: incidents={r.json().get('incidents')}, seconds={r.json().get('seconds')}, stages={list(r.json().get('stages', {}).keys())}")

r = client.get("/incidents")
all_ok &= check("GET /incidents after ingest", r)
print(f"    -> {len(r.json())} incidents from uploaded file")

print("\nALL PASS" if all_ok else "\nISSUES FOUND")
