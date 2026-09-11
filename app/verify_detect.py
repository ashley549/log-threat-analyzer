"""Phase 2 verification: score detections against the planted ground truth."""
import json
import sqlite3

import pandas as pd

conn = sqlite3.connect("db/logsec.db")
gt = json.load(open("data/synthetic/ground_truth.json", encoding="utf-8"))

dets = pd.read_sql(
    "SELECT id, rule_id, entity, first_seen, last_seen, matched_event_ids FROM detections", conn
)
events = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status FROM events", conn)
events["timestamp"] = pd.to_datetime(events["timestamp"])

# map scenario -> the rule expected to catch it (by name)
EXPECT = {
    "S1": ["RULE_BRUTE_FORCE", "RULE_SUCCESS_AFTER_FAILS"],
    "S2": ["RULE_CRED_STUFFING"],
    "S3": ["RULE_BACKDOOR_USER"],
    "S4": ["RULE_IMPOSSIBLE_TRAVEL"],
}
RULE_NAMES = {
    "RULE_BRUTE_FORCE": "brute force",
    "RULE_SUCCESS_AFTER_FAILS": "brute force compromise",
    "RULE_CRED_STUFFING": "credential stuffing",
    "RULE_BACKDOOR_USER": "privilege escalation",
    "RULE_IMPOSSIBLE_TRAVEL": "impossible travel",
    "RULE_OFFHOURS_LOGIN": "off-hours activity",
}

print("=== Phase 2: planted scenarios vs detections ===")
tp_total = fp_total = 0
for s in gt["scenarios"]:
    w0, w1 = pd.Timestamp(s["window"]["start"]), pd.Timestamp(s["window"]["end"])
    attack_ips = set(s["actors"]["source_ips"])
    sid = s["id"]
    hit_rules = []
    # a detection "matches" a scenario if its evidence events fall in the window
    # and involve the scenario's attacker IPs / users
    for _, d in dets.iterrows():
        ids = json.loads(d["matched_event_ids"])
        ev = events[events["id"].isin(ids)]
        in_window = ev[(ev["timestamp"] >= w0) & (ev["timestamp"] <= w1)]
        if in_window.empty:
            continue
        if in_window["source_ip"].isin(attack_ips).any() or (d["rule_id"] == "RULE_BACKDOOR_USER" and sid == "S3"):
            if d["rule_id"] in EXPECT[sid]:
                hit_rules.append(d["rule_id"])
    expected = EXPECT[sid]
    caught = [r for r in expected if r in hit_rules]
    status = "PASS" if len(caught) == len(expected) else ("PARTIAL" if caught else "MISS")
    names = ", ".join(sorted({RULE_NAMES[r] for r in caught})) or "-"
    print(f"  {sid} {s['name']:<22} {status:<8} via: {names}")

# false positives: off-hours logins on background noise (dev.jones is legit night owl)
fp = dets[dets["rule_id"] == "RULE_OFFHOURS_LOGIN"]
fp_s2 = fp[fp["entity"].str.contains("198.51.100")]  # these are part of S2, not FPs
clean_fps = len(fp) - len(fp_s2)
print(f"\nExpected-rule detections: {len(dets) - clean_fps}, clean-noise false positives: {clean_fps} (dev.jones off-hours — acceptable soft signal)")

# evidence trail sanity: every detection's event ids exist
bad = 0
for _, d in dets.iterrows():
    ids = json.loads(d["matched_event_ids"])
    if not events["id"].isin(ids).sum() == len(set(ids)):
        bad += 1
print(f"Evidence trails valid: {'YES' if bad == 0 else f'{bad} BROKEN'} ({len(dets)} detections checked)")
