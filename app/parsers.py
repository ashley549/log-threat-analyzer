"""Log parsers -> normalized event schema.

Every parser takes raw text chunks (list[str]) and returns a pandas DataFrame
with the normalized columns:
    timestamp, source_ip, user, event_type, status, host, raw_line, source_file

Malformed lines are never fatal: they yield event_type='malformed' rows
(status=None, best-effort other fields) so ingestion can proceed and we can
report skip counts.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

import numpy as np
import pandas as pd

COLUMNS = ["timestamp", "source_ip", "user", "event_type", "status",
           "host", "raw_line", "source_file"]

# ---------------------------------------------------------------------------
# auth syslog parser (Linux auth.log / sshd / sudo / su / cron)
# ---------------------------------------------------------------------------

# "Jun  7 09:00:04 srv-app01 sshd[17311]: Accepted password for alice from ..."
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?):\s+(?P<msg>.*)$"
)

SSHD_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]"
)
# Accepted publickey for alice from 10.0.1.22 port 40532 ssh2
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?:(?P<invalid>invalid user )?(?P<user>\S+)) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
# Failed password for invalid user admin from 203.0.113.45 port 123 ssh2
FAILED_RE = re.compile(
    r"Failed password for (?:(?P<invalid>invalid user )?(?P<user>\S+)) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
# Invalid user admin from 203.0.113.45 port 123
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SESSION_OPENED_RE = re.compile(r"session opened for user (?P<user>\S+)")
SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)")
PAM_AUTH_FAIL_RE = re.compile(
    r"pam_unix\((?P<svc>\w+):auth\): authentication failure.*(?:user=(?P<user>\S*))?"
)
SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*(?P<rest>command not allowed|incorrect password attempts|TTY=.*|.*COMMAND=\S+.*)"
)
SUDO_CMD_RE = re.compile(r"USER=(?P<target>\S+)\s+COMMAND=(?P<cmd>.+)$")
SUDO_FAIL_RE = re.compile(r"(?P<n>\d+) incorrect password attempts|command not allowed")
USERADD_RE = re.compile(r"new user: name=(?P<user>\S+),")
USERMOD_RE = re.compile(r"add '(?P<user>\S+)' to group '(?P<group>\S+)'")
DISCONNECT_RE = re.compile(r"Received disconnect from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
CRON_RE = re.compile(r"CRON\[\d+\]:\s*(?P<cmd>.*)")

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _year_for(mon: str, day: int, default_year: int) -> int:
    """syslog has no year; assume default_year. (Dec 31 -> Jan 1 wraparound
    is out of scope for hackathon data.)"""
    return default_year


def parse_auth_chunk(lines: list[str], source_file: str, year: int) -> pd.DataFrame:
    """Parse one chunk of auth.log lines into normalized events (vectorized)."""
    n = len(lines)
    # output arrays
    ts: np.ndarray = np.full(n, "NaT", dtype="datetime64[s]")
    host = np.full(n, None, dtype=object)
    user = np.full(n, None, dtype=object)
    ip = np.full(n, None, dtype=object)
    etype = np.full(n, "malformed", dtype=object)
    status = np.full(n, None, dtype=object)

    for i, line in enumerate(lines):
        m = SYSLOG_RE.match(line)
        if not m:
            continue  # stays 'malformed'
        d = m.groupdict()
        mon = MONTHS.get(d["mon"])
        if mon is None:
            continue
        try:
            h, mi, s = d["time"].split(":")
            ts[i] = np.datetime64(datetime(_year_for(mon, int(d["day"]), year),
                                           mon, int(d["day"]),
                                           int(h), int(mi), int(s)))
        except ValueError:
            continue
        host[i] = d["host"]
        proc, msg = d["proc"], d["msg"]

        if proc.startswith("sshd["):
            if (mm := ACCEPTED_RE.search(msg)):
                user[i], ip[i] = mm["user"], mm["ip"]
                etype[i], status[i] = "ssh_login", "success"
            elif (mm := FAILED_RE.search(msg)):
                user[i], ip[i] = mm["user"], mm["ip"]
                etype[i], status[i] = "ssh_login", "fail"
            elif INVALID_USER_RE.search(msg):
                mm = INVALID_USER_RE.search(msg)
                user[i], ip[i] = mm["user"], mm["ip"]
                etype[i], status[i] = "ssh_login", "fail"  # probe of nonexistent user
            elif (mm := SESSION_OPENED_RE.search(msg)):
                user[i], etype[i] = mm["user"], "session_opened"
            elif (mm := SESSION_CLOSED_RE.search(msg)):
                user[i], etype[i] = mm["user"], "session_closed"
            elif (mm := DISCONNECT_RE.search(msg)):
                ip[i], etype[i] = mm["ip"], "disconnect"
            else:
                etype[i] = "ssh_other"
        elif proc == "sudo":
            if "command not allowed" in msg or "incorrect password attempts" in msg:
                etype[i], status[i] = "sudo_fail", "fail"
                if (mm := re.match(r"\s*(\S+)", msg)):
                    user[i] = mm.group(1)
            elif SUDO_CMD_RE.search(msg):
                etype[i], status[i] = "sudo_success", "success"
                if (mm := re.match(r"\s*(\S+)", msg)):
                    user[i] = mm.group(1)
            else:
                etype[i] = "sudo_other"
        elif proc.startswith("su["):
            if (mm := SESSION_OPENED_RE.search(msg)):
                u = mm["user"]
                if "(" in u:  # 'svc_bkp(uid=0)' style
                    u = u.split("(")[0]
                user[i], etype[i], status[i] = u, "su_session", "success"
            elif PAM_AUTH_FAIL_RE.search(msg):
                mm = re.search(r"ruser=(\S+)", msg)
                user[i], etype[i], status[i] = (mm.group(1) if mm else None), "su_auth_fail", "fail"
            else:
                etype[i] = "su_other"
        elif proc.startswith("useradd["):
            if (mm := USERADD_RE.search(msg)):
                user[i], etype[i] = mm["user"], "user_added"
        elif proc.startswith("usermod["):
            if (mm := USERMOD_RE.search(msg)):
                user[i], etype[i] = mm["user"], "user_modified"
        elif proc.startswith("CRON[") or proc == "CRON":
            etype[i] = "cron"
        else:
            etype[i] = "other"

    return pd.DataFrame({
        "timestamp": ts,
        "source_ip": ip,
        "user": user,
        "event_type": etype,
        "status": status,
        "host": host,
        "raw_line": lines,
        "source_file": [source_file] * n,
    })


# ---------------------------------------------------------------------------
# JSON app-log parser
# ---------------------------------------------------------------------------

_JSON_FIELDS = {"timestamp", "source_ip", "user", "event_type", "status", "host"}

def parse_json_chunk(lines: list[str], source_file: str) -> pd.DataFrame:
    n = len(lines)
    ts = np.full(n, np.datetime64("NaT"), dtype="datetime64[s]")
    host = np.full(n, None, dtype=object)
    user = np.full(n, None, dtype=object)
    ip = np.full(n, None, dtype=object)
    etype = np.full(n, "malformed", dtype=object)
    status = np.full(n, None, dtype=object)

    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or "timestamp" not in rec:
            continue
        try:
            ts[i] = np.datetime64(rec["timestamp"], "s")
        except (ValueError, TypeError):
            continue
        etype[i] = str(rec.get("event_type", "app_event"))
        host[i] = rec.get("host")
        user[i] = rec.get("user")
        ip[i] = rec.get("source_ip")
        st = rec.get("status")
        status[i] = str(st).lower() if st is not None else None

    return pd.DataFrame({
        "timestamp": ts,
        "source_ip": ip,
        "user": user,
        "event_type": etype,
        "status": status,
        "host": host,
        "raw_line": lines,
        "source_file": [source_file] * n,
    })


# ---------------------------------------------------------------------------
# Apache / nginx access-log parser (Combined Log Format)
#   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
# Handles: "-" values, escaped quotes (\") inside quoted fields, IPv6 hosts,
# missing response size, Common format (no referer/UA), spaces inside URLs,
# arbitrary HTTP methods/protocols, and timezone offsets.
# ---------------------------------------------------------------------------

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<ref>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?\s*$'
)

SQLI_RE = re.compile(
    r"(union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|drop\s+table|;\s*delete|"
    r";\s*insert|information_schema|sleep\s*\(|benchmark\s*\(|xp_cmdshell)", re.I)
XSS_RE = re.compile(
    r"(<\s*script|%3c\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|%3c\s*img|"
    r"<\s*svg|document\.cookie|alert\s*\()", re.I)
TRAVERSAL_RE = re.compile(
    r"(\.\.[/\\]|%2e%2e[/\\%5c]|/etc/passwd|/etc/shadow|/proc/self|"
    r"win\.ini|boot\.ini|%2fetc%2f)", re.I)
SENSITIVE_PATH_RE = re.compile(
    r"(/admin|wp-admin|wp-login|phpmyadmin|administrator|/manager/html|/console|"
    r"/actuator|\.env|\.git|\.bak|\.sql|/config|\.php\b|/backup|/shell|/cgi-bin|"
    r"/\.aws|/\.ssh|/etc/passwd)", re.I)


def _split_request(req: str) -> tuple[str, str]:
    """'GET /a?q=1 2 HTTP/1.1' -> ('GET', '/a?q=1 2'); tolerant of no protocol."""
    if req in ("", "-"):
        return "-", "-"
    parts = req.split(" ", 1)
    method = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    if " http/" in rest.lower() and rest.rstrip().lower().endswith("http/0.9") is False and rest.lower().rstrip().split(" ")[-1].startswith("http/"):
        target = rest.rsplit(" ", 1)[0]
    else:
        target = rest
    return method, target.replace('\\"', '"')


def parse_apache_chunk(lines: list[str], source_file: str) -> pd.DataFrame:
    """Combined-format access log -> normalized events.

    Mapping (web logs carry no account; the path plays that analytical role):
      user       = requested path (query string stripped)
      status     = success (<400) / fail (>=400)
      event_type = http_request | sensitive_probe | sensitive_access |
                   sqli_attempt | xss_attempt | traversal_attempt
    """
    n = len(lines)
    ts = np.full(n, "NaT", dtype="datetime64[s]")
    host = np.full(n, None, dtype=object)
    user = np.full(n, None, dtype=object)
    ip = np.full(n, None, dtype=object)
    etype = np.full(n, "malformed", dtype=object)
    status = np.full(n, None, dtype=object)

    for i, line in enumerate(lines):
        m = APACHE_RE.match(line)
        if not m:
            continue
        try:
            dt = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            ts[i] = np.datetime64(dt.replace(tzinfo=None))
        except ValueError:
            continue
        code = int(m["status"])
        _, target = _split_request(m["req"])
        path = target.split("?")[0]
        query = target[len(path):]
        ip[i] = m["ip"]
        user[i] = path or "-"
        host[i] = "web"
        status[i] = "success" if code < 400 else "fail"
        if SQLI_RE.search(target):
            etype[i] = "sqli_attempt"
        elif XSS_RE.search(target):
            etype[i] = "xss_attempt"
        elif TRAVERSAL_RE.search(target):
            etype[i] = "traversal_attempt"
        elif SENSITIVE_PATH_RE.search(path):
            etype[i] = "sensitive_probe" if code >= 400 else "sensitive_access"
        else:
            etype[i] = "http_request"

    return pd.DataFrame({
        "timestamp": ts,
        "source_ip": ip,
        "user": user,
        "event_type": etype,
        "status": status,
        "host": host,
        "raw_line": lines,
        "source_file": [source_file] * n,
    })


# ---------------------------------------------------------------------------
# format auto-detection
# ---------------------------------------------------------------------------

def detect_format(lines: list[str], max_check: int = 200) -> str | None:
    """Sniff the log format from sample lines. Returns 'auth' | 'apache' | 'json' | None."""
    counts = {"auth": 0, "apache": 0, "json": 0}
    for line in lines[:max_check]:
        if not line.strip():
            continue
        if SYSLOG_RE.match(line):
            counts["auth"] += 1
        elif APACHE_RE.match(line):
            counts["apache"] += 1
        elif line.lstrip().startswith("{"):
            counts["json"] += 1
    fmt, hits = max(counts.items(), key=lambda kv: kv[1])
    return fmt if hits > 0 else None


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

PARSERS = {
    "auth": parse_auth_chunk,
    "json": parse_json_chunk,
    "apache": parse_apache_chunk,
}
