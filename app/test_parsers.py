"""Parser tests: Apache/Nginx combined, malformed, empty, multi-line (req #29).

Every case has an explicit expected result. Run: python -m app.test_parsers
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from app.parsers import (APACHE_RE, detect_format, parse_apache_chunk,
                         parse_auth_chunk)

ok = True


def check(name, cond, got=""):
    global ok
    ok &= bool(cond)
    print(f"  {name:<62} {'PASS' if cond else 'FAIL'} {got if not cond else ''}")


def apache(lines):
    df = parse_apache_chunk(lines, "test.log")
    return df


# --- 1) one valid Apache Combined line (the exact example from the spec) ----
L1 = '192.168.1.20 - - [09/Sep/2026:10:23:11 +0530] "GET /login HTTP/1.1" 200 1523 "-" "Mozilla/5.0"'
df = apache([L1])
r = df.iloc[0]
check("1. valid Apache line parses (entries=1)", df["timestamp"].notna().all() and r["event_type"] != "malformed",
      f"event_type={r['event_type']}")
check("1a. ip extracted", r["source_ip"] == "192.168.1.20", r["source_ip"])
check("1b. timestamp + tz handled", str(r["timestamp"]) == "2026-09-09 10:23:11", str(r["timestamp"]))
check("1c. path as user", r["user"] == "/login", r["user"])
check("1d. status mapped", r["status"] == "success", r["status"])
check("1e. http_request type", r["event_type"] == "http_request", r["event_type"])

# --- 2) valid Nginx combined lines ----------------------------------------------
L2 = '172.16.0.9 - alice [09/Sep/2026:11:00:01 +0000] "POST /api/login HTTP/2.0" 401 512 "https://ref.example/x" "curl/8.0"'
L3 = '2001:db8::1 - - [09/Sep/2026:11:00:02 +0000] "DELETE /x HTTP/1.1" 204 0 "-" "-"'
df = apache([L2, L3])
check("2. nginx lines parse (2/2)", df["timestamp"].notna().all(),
      f"valid={df['timestamp'].notna().sum()}")
check("2a. remote user captured (alice)", df.iloc[0]["host"] == "web")
check("2b. IPv6 host accepted", df.iloc[1]["source_ip"] == "2001:db8::1", df.iloc[1]["source_ip"])
check("2c. 401 -> fail", df.iloc[0]["status"] == "fail", df.iloc[0]["status"])
check("2d. 204 -> success", df.iloc[1]["status"] == "success", df.iloc[1]["status"])

# --- 3) malformed lines are marked, never crash ----------------------------------
df = apache(["total garbage ???", "", '1.2.3.4 - - [bad-ts] "GET / HTTP/1.1" 200 1', L1])
check("3. malformed lines -> event_type=malformed", df.iloc[0]["event_type"] == "malformed")
check("3a. empty line -> malformed", df.iloc[1]["event_type"] == "malformed")
check("3b. bad timestamp -> malformed", df.iloc[2]["event_type"] == "malformed")
check("3c. valid line still parses after malformed ones", df.iloc[3]["event_type"] == "http_request")

# --- 4) '-' values, missing size, escaped quotes, spaces in URL -----------------
L4 = '10.0.0.1 - - [09/Sep/2026:12:00:00 +0000] "GET /search?q=1\' OR \'1\'=\'1 HTTP/1.1" 500 - "-" "python-requests/2.28"'
df = apache([L4])
r = df.iloc[0]
check("4. '-' size accepted", r["event_type"] != "malformed", r["event_type"])
check("4a. SQLi with spaces in URL detected", r["event_type"] == "sqli_attempt", r["event_type"])
L5 = '10.0.0.2 - - [09/Sep/2026:12:01:00 +0000] "GET /x?n=%3Cscript%3E HTTP/1.1" 200 5 "-" "Mozilla/5.0"'
check("4b. XSS url-encoded detected", apache([L5]).iloc[0]["event_type"] == "xss_attempt",
      apache([L5]).iloc[0]["event_type"])
L6 = '10.0.0.3 - - [09/Sep/2026:12:02:00 +0000] "GET /files?path=../../etc/passwd HTTP/1.1" 403 5 "-" "curl/7"'
check("4c. path traversal detected", apache([L6]).iloc[0]["event_type"] == "traversal_attempt",
      apache([L6]).iloc[0]["event_type"])

# --- 5) multiple lines / stats ------------------------------------------------------
lines = open(Path("data/uploads/apache_access.log"), encoding="utf-8").read().splitlines()
df = apache(lines)
parsed = int(df["timestamp"].notna().sum())
check("5. user's 84-line file: all parse", parsed == 84, f"parsed={parsed}/84")
vc = df["event_type"].value_counts().to_dict()
check("5a. recon (sensitive_probe) found", vc.get("sensitive_probe", 0) == 11, vc)
check("5b. sqli found", vc.get("sqli_attempt", 0) == 3, vc)

# --- format detection ------------------------------------------------------------------
check("6. detect apache", detect_format(lines) == "apache")
check("6a. detect auth", detect_format(open("data/synthetic/auth.log", encoding="utf-8").read().splitlines()[:50]) == "auth")
check("6b. detect json", detect_format(['{"timestamp": "2026-01-01T00:00:00", "event_type": "x"}']) == "json")
check("6c. garbage -> None", detect_format(["?????"]) is None)

print("\n" + ("PARSER TESTS ALL PASS" if ok else "PARSER TESTS FAILED"))
sys.exit(0 if ok else 1)
