"""Phase 5 verification: score breakdown integrity + level mapping + sanity."""
import json
import sqlite3

conn = sqlite3.connect("db/logsec.db")
inc = conn.execute("SELECT incident_id, entity, risk_score, risk_level, risk_breakdown FROM incidents ORDER BY risk_score DESC").fetchall()

LEVELS = ["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"]

def level_for(s):
    return "🔴 Critical" if s >= 8 else "🟠 High" if s >= 6 else "🟡 Medium" if s >= 3 else "🟢 Low"

print("=== Phase 5: score + level + breakdown per incident ===")
ok = True
components = {"entity_sensitivity", "rule_severity", "ml_anomaly", "corroboration", "outcome", "volume"}
for inc_id, entity, score, level, bd_json in inc:
    bd = json.loads(bd_json)
    # integrity: all components present, values match, total = sum (or clamped sum)
    missing = components - set(bd)
    ssum = round(sum(bd[c]["value"] for c in components), 2)
    total_ok = abs(ssum - score) < 0.06 or (ssum > 10 and score == 10.0)
    level_ok = level == level_for(score)
    flags = []
    if missing: flags.append(f"missing {missing}"); ok = False
    if not total_ok: flags.append(f"sum {ssum} != score {score}"); ok = False
    if not level_ok: flags.append(f"level mismatch"); ok = False
    print(f"  {inc_id}  {level}  {score:>4}  {entity:<28} {'OK' if not flags else flags}")
    for c in sorted(components):
        v = bd[c]
        print(f"      {c:<18} {v['value']:>4} /{v['max']:<4} {v['reason']}")

# sanity: attack incidents outrank the benign one
scores = {i: s for i, _, s, _, _ in inc}
benign, attacks = scores["INC-002"], [scores[i] for i in ("INC-001", "INC-003", "INC-004", "INC-005")]
sanity = all(a > benign for a in attacks)
print(f"\n  all attack incidents outrank benign off-hours: {'PASS' if sanity else 'FAIL'}")
print(f"  root-compromise incident is the top risk:    {'PASS' if inc[0][0] == 'INC-005' else 'FAIL'}")
print(f"  levels used: {sorted({l for _,_,_,l,_ in inc}, key=LEVELS.index)}")
print(f"\nALL {'PASS' if ok and sanity and inc[0][0]=='INC-005' else 'ISSUES FOUND'}")
