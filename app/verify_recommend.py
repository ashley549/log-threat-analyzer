"""Phase 6 verification: every incident has an explanation + concrete action."""
import json
import re
import sqlite3

conn = sqlite3.connect("db/logsec.db")
inc = conn.execute("SELECT incident_id, entity, risk_level, recommendation FROM incidents ORDER BY incident_id").fetchall()

print("=== Phase 6: recommendation quality gate ===")
ok = True
CONCRETE_PAT = re.compile(r"(`|usermod|firewall|fail2ban|MFA|password|ssh|session|key|cron|sudoers|IP|block|reset|disable|review|verify)", re.I)
for inc_id, entity, level, rec in inc:
    if not rec:
        print(f"  {inc_id}  MISSING"); ok = False; continue
    has_summary = "SUMMARY:" in rec
    has_actions = "RECOMMENDED ACTIONS:" in rec
    n_actions = len(re.findall(r"^\s*-\s+\S", rec, re.M))
    concrete = bool(CONCRETE_PAT.search(rec))
    mentions_entity = entity.split("@")[0] in rec
    flags = []
    if not has_summary: flags.append("no SUMMARY")
    if not has_actions: flags.append("no ACTIONS")
    if n_actions < 2: flags.append(f"only {n_actions} action(s)")
    if not concrete: flags.append("no concrete step")
    if not mentions_entity: flags.append("doesn't mention entity")
    status = "OK" if not flags else flags
    ok &= not flags
    print(f"  {inc_id}  {level}  {entity:<28} actions={n_actions}  {status}")

# cache behavior: text is stored in DB (non-null after first run)
cached = conn.execute("SELECT COUNT(*) FROM incidents WHERE recommendation IS NOT NULL AND recommendation != ''").fetchone()[0]
print(f"\n  cached in DB: {cached}/{len(inc)}")
print(f"ALL {'PASS' if ok and cached == len(inc) else 'ISSUES FOUND'}")
