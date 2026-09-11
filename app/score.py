"""Dynamic risk scoring (Phase 5).

score = clamp( base(entity sensitivity)                     0..2
             + rule_severity(max rule weight, scaled)      0..4
             + ml_anomaly(mean ML weight)                   0..2
             + corroboration(distinct detection kinds)      0..1.5
             + outcome(compromise/persistence achieved)     0..2.5
             + volume(spread of evidence events)            0..1
             , 0, 10)

Levels: >=8 Critical / >=6 High / >=3 Medium / else Low.
The full per-component value + reason is stored as JSON in
incidents.risk_breakdown — the score is explainable by construction.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pandas as pd

from db.schema import init_db, DB_PATH

# entity sensitivity: what the principal is worth to an attacker
SENSITIVE_USERS = {"root", "admin", "svc_bkp"}           # privileged / backdoor accounts
ADMIN_PREFIXES = ("svc.", "backup", "deploy")
SENSITIVE_WEIGHTS = {
    "root": 2.0, "admin": 1.8, "svc_bkp": 1.8,           # direct privilege
}
DEFAULT_USER_BASE = 0.5
IP_BASE = 0.5

RULE_MAX = 4.0     # cap for rule_severity component
ML_MAX = 2.0
CORROB_MAX = 1.5
OUTCOME_MAX = 2.5
VOLUME_MAX = 1.0

# rules that mean the attacker actually GOT something
COMPROMISE_RULES = {"RULE_SUCCESS_AFTER_FAILS"}
PERSISTENCE_RULES = {"RULE_BACKDOOR_USER"}
OFFHOURS_ONLY = {"RULE_OFFHOURS_LOGIN"}
# rules that signal active exploitation (not just scanning)
EXPLOIT_RULES = {"RULE_SQLI_ATTEMPT", "RULE_WEB_RECON"}


def _level(score: float) -> str:
    if score >= 8: return "🔴 Critical"
    if score >= 6: return "🟠 High"
    if score >= 3: return "🟡 Medium"
    return "🟢 Low"


def score_incident(inc: pd.Series, dets: pd.DataFrame,
                   ev: pd.DataFrame | None = None) -> tuple[float, str, dict]:
    """Compute (score, level, breakdown) for one incident row.

    `ev` = the incident's raw evidence events (used to detect outcomes that
    no rule fired on, e.g. a quiet success-after-few-fails compromise).
    """
    bd: dict[str, dict] = {}

    # ---- 1) entity sensitivity -------------------------------------------
    ent = str(inc["entity"])
    user = ent.split("@")[0]
    if user in SENSITIVE_WEIGHTS:
        base = SENSITIVE_WEIGHTS[user]
        why = f"'{user}' is a privileged/sensitive account"
    elif any(user.startswith(p) for p in ADMIN_PREFIXES):
        base = 1.2
        why = f"'{user}' looks like a service account"
    elif "@" in ent:  # named human account
        base = DEFAULT_USER_BASE
        why = f"named user account '{user}'"
    else:
        # ip-labeled incident: external attacker IPs are higher-stakes
        rules_present_ = set(dets["rule_id"]) if not dets.empty else set()
        if rules_present_ & {"RULE_WEB_BRUTEFORCE", "RULE_SQLI_ATTEMPT", "RULE_TRAVERSAL_ATTEMPT", "RULE_XSS_ATTEMPT"}:
            base = 1.2
            why = "external source IP executing web attacks"
        else:
            base = IP_BASE
            why = "source-IP incident"
    bd["entity_sensitivity"] = {"value": round(base, 2), "max": 2.0, "reason": why}

    # ---- 2) rule severity ---------------------------------------------------
    rule_dets = dets[dets["rule_id"].str.startswith("RULE_")]
    if len(rule_dets):
        max_w = float(rule_dets["severity_weight"].max())
        rs = min(max_w / 3.0 * RULE_MAX, RULE_MAX)      # weight 3.0 (max) -> 4.0
        top = rule_dets.loc[rule_dets["severity_weight"].idxmax()]
        why = (f"{len(rule_dets)} rule hit(s), top: {top['rule_id']} "
               f"(weight {max_w:.1f})")
    else:
        rs, why = 0.0, "no rule detections"
    bd["rule_severity"] = {"value": round(rs, 2), "max": RULE_MAX, "reason": why}

    # ---- 3) ML anomaly ------------------------------------------------------
    ml_dets = dets[dets["rule_id"] == "ML_ANOMALY"]
    if len(ml_dets):
        ml = min(float(ml_dets["severity_weight"].mean()) / 3.0 * ML_MAX, ML_MAX)
        why = f"{len(ml_dets)} ML anomaly window(s) corroborate (avg weight {ml_dets['severity_weight'].mean():.1f})"
    else:
        ml, why = 0.0, "no ML corroboration"
    bd["ml_anomaly"] = {"value": round(ml, 2), "max": ML_MAX, "reason": why}

    # ---- 4) corroboration ---------------------------------------------------
    kinds = dets["rule_id"].nunique()
    cor = min((kinds - 1) * 0.5, CORROB_MAX) if kinds > 1 else 0.0
    bd["corroboration"] = {
        "value": round(cor, 2), "max": CORROB_MAX,
        "reason": f"{kinds} distinct detection type(s) agree"
                  + (" (single-source)" if kinds == 1 else ""),
    }

    # ---- 5) outcome -----------------------------------------------------------
    rules_present = set(dets["rule_id"])
    oc = 0.0
    whys = []
    if rules_present & COMPROMISE_RULES:
        oc += OUTCOME_MAX * 0.8
        whys.append("successful login after failures (compromise)")
    if rules_present & PERSISTENCE_RULES:
        oc += OUTCOME_MAX * 0.7
        whys.append("new account created (persistence)")
    if rules_present & EXPLOIT_RULES and rules_present & {"RULE_SQLI_ATTEMPT"}:
        oc += OUTCOME_MAX * 0.8
        whys.append("active exploitation attempts (SQL injection) against the application")
    if rules_present & {"RULE_WEB_BRUTEFORCE"} and "followed by a SUCCESSFUL login" in " ".join(dets["description"].tolist()):
        oc += OUTCOME_MAX * 0.8
        whys.append("web login brute force ended in a successful login (compromise)")
    oc = min(oc, OUTCOME_MAX)
    # raw-evidence scan: quiet compromises the rules missed — a success login
    # from an IP that also failed against the same user in this incident
    if ev is not None and not ev.empty:
        logins = ev[ev["event_type"] == "ssh_login"]
        fails = logins[logins["status"] == "fail"]
        succs = logins[logins["status"] == "success"]
        quiet = 0
        for _, s in succs.iterrows():
            prior = fails[(fails["user"] == s["user"])
                          & (fails["source_ip"] == s["source_ip"])
                          & (fails["timestamp"] < s["timestamp"])]
            if len(prior) >= 1 and "RULE_SUCCESS_AFTER_FAILS" not in rules_present:
                quiet += 1
        if quiet and "successful login after failures (compromise)" not in whys:
            oc += OUTCOME_MAX * (0.8 if quiet > 1 else 0.6)
            whys.append(f"{quiet} successful login(s) preceded by failures on same user@ip "
                         f"(compromise — below rule threshold, found in raw evidence)")
    oc = min(oc, OUTCOME_MAX)
    if whys:
        why = "; ".join(whys)
    else:
        why = "no compromise/persistence achieved (attempt only)"
    bd["outcome"] = {"value": round(oc, 2), "max": OUTCOME_MAX, "reason": why}

    # ---- 6) volume -------------------------------------------------------------
    n_ev = int(inc["n_events"])
    vol = min(n_ev / 100.0, VOLUME_MAX)
    bd["volume"] = {"value": round(vol, 2), "max": VOLUME_MAX,
                    "reason": f"{n_ev} evidence events"}

    total = round(sum(bd[c]["value"] for c in COMPONENTS_ORDER), 2)
    raw = total
    total = max(0.0, min(total, 10.0))
    bd["total"] = {"value": total, "max": 10.0,
                   "reason": (f"sum of components = {raw:.2f}"
                              + (f", clamped to 10.0" if raw > 10 else "")
                              + f" -> {_level(total)}")}
    return total, _level(total), bd


COMPONENTS_ORDER = ["entity_sensitivity", "rule_severity", "ml_anomaly",
                   "corroboration", "outcome", "volume"]


def score_all(db_path=DB_PATH) -> dict:
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        inc = pd.read_sql("SELECT * FROM incidents", conn)
        if inc.empty:
            print("No incidents — run app.correlate first.")
            return {"scored": 0}
        dets = pd.read_sql("SELECT id, rule_id, description, severity_weight, entity, incident_id FROM detections", conn)
        ev_all = pd.read_sql("SELECT id, timestamp, user, source_ip, event_type, status FROM events", conn)
        ev_all["timestamp"] = pd.to_datetime(ev_all["timestamp"])
        updates = []
        for _, i in inc.iterrows():
            sub = dets[dets["incident_id"] == i["incident_id"]]
            ids = json.loads(i["event_ids"])
            ev = ev_all[ev_all["id"].isin(ids)]
            total, level, bd = score_incident(i, sub, ev)
            updates.append((total, level, json.dumps(bd, ensure_ascii=False), i["incident_id"]))
        conn.executemany("UPDATE incidents SET risk_score=?, risk_level=?, risk_breakdown=? WHERE incident_id=?", updates)

    print(f"Scored {len(updates)} incidents:")
    for total, level, _bd, inc_id in sorted(updates, reverse=True):
        row = inc[inc["incident_id"] == inc_id].iloc[0]
        print(f"  {inc_id}  {level}  score={total:.1f}  {row['entity']}")
    return {"scored": len(updates)}


if __name__ == "__main__":
    score_all()
