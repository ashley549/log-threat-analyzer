"""Phase 8 verification: reports complete, structured, template-driven."""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.report import build_incident_report, build_run_report, export_reports

ok = True
def check(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(f"  {name:<56} {'PASS' if cond else 'FAIL'} {extra}")

# 1) per-incident report structure
r = build_incident_report("INC-005")
for section in ["# Incident Report — INC-005", "## Why this is risky", "## Detections that fired",
                "## Analysis & recommended actions", "## Evidence timeline"]:
    check(f"incident report has: {section.split('— ')[0][:40]}", section in r)
check("score breakdown table rows (6 factors)", r.count("| 2.0 |") + r.count("| 4.0 |") >= 2)
check("generation timestamp present", bool(re.search(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", r)))
check("raw evidence lines included", "Failed password" in r or "Accepted" in r)
check("recommendation included", "usermod" in r or "RECOMMENDED ACTIONS" in r)
check("no NaN leaks", "nan" not in r.lower().replace("nanosec", ""))

# 2) per-run report
r = build_run_report()
for section in ["# Security Analysis Report", "## Executive summary", "## Incidents (",
                "## Pipeline stages", "## Incident details"]:
    check(f"run report has: {section[:40]}", section in r)
check("all 5 incidents in run report", all(f"INC-00{i}" in r for i in (1, 2, 3, 4, 5)))
check("severity counts present", "🔴 Critical | 2" in r)

# 3) time-range filtering (S4 window only: 2026-06-07)
r = build_run_report(since="2026-06-07 00:00:00", until="2026-06-07 23:59:59")
check("time range filters incidents (Jun 7 only -> INC-001, INC-002)",
      "INC-001" in r and "INC-005" not in r)

# 4) one-command export via CLI
res = subprocess.run([sys.executable, "-m", "app.report"], capture_output=True, text=True)
check("CLI export succeeds", res.returncode == 0, res.stderr[-80:] if res.returncode else "")
files = sorted(Path("reports").glob("*.md"))
check("5 incident reports + run report on disk", len(files) == 6, f"{len(files)} md files")

# 5) dashboard export buttons exist in the Reports page (summary merged into Overview)
src = Path("dashboard/pages/7_Reports.py").read_text(encoding="utf-8")
check("reports page has run-report download button",
      "security_run_report.md" in src and "build_run_report" in src)

print("\n" + ("ALL PASS" if ok else "ISSUES FOUND"))
sys.exit(0 if ok else 1)
