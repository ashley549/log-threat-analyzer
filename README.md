# SENTINEL — Log Security Analyzer & Dynamic Risk Profiler

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Frontend](https://img.shields.io/badge/Frontend-vanilla%20JS-38BDF8)
![License](https://img.shields.io/badge/License-MIT-38BDF8)

Ingests raw auth logs, flags suspicious events (rules + ML), correlates them
into incidents, scores each incident's risk **with a visible breakdown**,
explains _why_ it's risky, and recommends what to do about it — with AI-written
summaries via the **Google Gemini API** (free tier).

```
logs → parse/normalize → detect (rules + ML) → correlate into incidents
     → score risk → explain (evidence + AI) → web app → report
```

## Highlights

- **Explainable risk scoring** — every incident's 0–10 score is itemized into
  6 factors (entity sensitivity, rule severity, ML corroboration, multi-source
  agreement, outcome, volume). No black boxes.
- **Rules + ML detection** — 11 deterministic rules plus IsolationForest
  anomaly windows with z-score driver attribution.
- **AI incident narratives** — Gemini turns each incident into a SUMMARY +
  RECOMMENDED ACTIONS, built from structured data only (never raw log dumps).
  Falls back to a deterministic playbook when no key/quota — demo-day safe.
- **Zero-dependency frontend** — hand-rolled SPA: hash router, SVG charts,
  cohesive blue design system. No build step, no npm.
- **Honest about false positives** — ships with a benign-behavior incident the
  engine correctly scores Low.

## Screenshots

> Add 2–3 screenshots here before pushing (Overview, incident detail, Reports).
> Suggested: `docs/screenshot-overview.png` etc.

## Frontend

**SENTINEL** — a dependency-free single-page app (vanilla HTML/CSS/JS) served
by FastAPI from `frontend/`. Hash-routed views, hand-rolled SVG charts, and a
blue-centered dark theme (every chrome surface is a shade of one blue sky
ramp; warm hues are reserved for severity only).

| View            | Route                 | What it shows                                                                              |
| --------------- | --------------------- | ------------------------------------------------------------------------------------------ |
| Overview        | `/#/overview`         | KPIs, posture ring, threat timeline, distribution, live feed                               |
| Analyze         | `/#/analyze`          | Drag-&-drop upload, one-click security demos, staged pipeline progress, parser diagnostics |
| Incidents       | `/#/incidents`        | Filterable, risk-sorted incident cards                                                     |
| Incident detail | `/#/incident/INC-001` | Explainable score breakdown, attack timeline, AI response, raw evidence                    |
| Risk Profiles   | `/#/profiles`         | Per-entity behavior-over-time line, stats, full incident link                              |
| Threat Intel    | `/#/intel`            | Evidence-based source reputation (internal vs external)                                    |
| Reports         | `/#/reports`          | Markdown run/incident report downloads + CSV/JSON exports                                  |
| Settings        | `/#/settings`         | Engine configuration + LLM key status                                                      |

The JSON API lives under `/api/*` (see `app/main.py`); the same server also
keeps the legacy contract (`/ingest`, `/incidents`, `/dashboard/summary`) and
auto-documents everything at `/docs`.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                   ┌──────────────┐                        │
│  data/synthetic/auth.log ─────────▶│ app/ingest.py│  regex parsers          │
│  (+ ground_truth.json)             │  (pandas/re) │  (syslog auth + JSON)  │
│                                    └──────┬───────┘  chunked 50k, NaN-safe │
│                                           ▼                                │
│                                    ┌──────────────┐                        │
│                    ┌───────────────▶│  SQLite      │  events(id, ts, ip,  │
│                    │                │  db/logsec.db│  user, type, status…)│
│                    │                └──────┬───────┘                        │
│                    │                       ▼                                │
│                    │     ┌─────────────────────────────────┐              │
│                    │     │ app/rules.py   6 rule functions  │ RULE_*        │
│                    │     │ app/detect_ml.py IsolationForest│ ML_ANOMALY    │
│                    │     │  (per user@ip / per-IP 1h windows,│              │
│                    │     │   z-score driver attribution)    │              │
│                    │     └───────────────┬─────────────────┘              │
│                    │                     ▼   detections(rule_id, matched_event_ids) │
│                    │     ┌─────────────────────────────────┐              │
│                    │     │ app/correlate.py                │ union-find on │
│                    │     │  entity tokens + time windows + │ evidence      │
│                    │     │  evidence overlap (+span split) │               │
│                    │     └───────────────┬─────────────────┘              │
│                    │                     ▼   incidents(INC-xxx)            │
│                    │     ┌─────────────────────────────────┐              │
│                    │     │ app/score.py    6-component risk│ score, level, │
│                    │     │                 breakdown (JSON)│ 🔴🟠🟡🟢     │
│                    │     └───────────────┬─────────────────┘              │
│                    │                     ▼                                │
│                    │     ┌─────────────────────────────────┐              │
│                    │     │ app/recommend.py                │ Gemini →      │
│                    │     │  generate_recommendation()      │ playbook     │
│                    │     │  (swappable, cached per-incident)│              │
│                    │     └───────────────┬─────────────────┘              │
│                    │                     ▼                                │
│  dashboard/ (Streamlit multipage)   app/main.py (FastAPI)  app/report.py  │
│  Upload→Summary→Incidents→Detail   /ingest /incidents/{id} (Jinja2 →      │
│  staged progress, evidence, export /report  /dashboard/    Markdown (+PDF)│
└──────────────────────────────────────────────────────────────────────────┘
```

Each phase of the build maps to one module; verification scripts
(`app/verify_*.py`, `app/test_*.py`) score the pipeline against the
planted ground truth (`data/synthetic/ground_truth.json`).

## Setup

```powershell
python -m venv venv
venv\Scripts\activate            # or: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure the Gemini API key (optional but recommended)

Incident summaries are AI-written through the Google Gemini API. Grab a free
key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey), then:

```powershell
copy .env.example .env           # then paste your key inside
```

`.env` is gitignored — never commit real keys. Without a key the app still
works fully: recommendations fall back to a built-in deterministic playbook.

> The web app reads `.env` at startup — restart uvicorn after changing it.

## Run — one command per layer

| Goal                                  | Command                                                                                                                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Generate demo data (log + answer key) | `python -m generator.run`                                                                                                                              |
| Run the full analysis (CLI)           | `python -m app.ingest && python -m app.detect && python -m app.detect_ml && python -m app.correlate && python -m app.score && python -m app.recommend` |
| **Web app (SENTINEL)**                | `venv\Scripts\uvicorn.exe app.main:app --reload` → open http://localhost:8000                                                                          |
| REST API (+ auto docs at `/docs`)     | same server — `/api/*` + legacy endpoints                                                                                                              |
| Export all reports to `reports/`      | `python -m app.report`                                                                                                                                 |
| Benchmark on 100k-line log            | `python -m app.bench`                                                                                                                                  |

## Deploy on Render

This repository includes a Render Blueprint in `render.yaml`. Create a new
Blueprint Instance in Render and select this repository. Render will install
`requirements.txt`, start Uvicorn on the injected `$PORT`, and use `/healthz`
for health checks.

The Blueprint uses a 1 GB persistent disk mounted at `/var/data`; the web
SQLite database is stored there through `SENTINEL_DATA_DIR`. Add
`GEMINI_API_KEY` as a secret environment variable if Gemini recommendations
are desired. Without it, the built-in playbook remains active.

The persistent disk requires Render's Starter plan and is attached to a single
web instance. Without persistent storage, the app still runs, but uploaded
analyses are lost whenever the service is redeployed or restarted.

## The demo dataset

`data/synthetic/auth.log` (806 lines, 3 days) — realistic SSH/sudo/su/cron
traffic with **4 planted attacks** and a ground-truth answer key the detector
never sees:

| ID  | Attack                                               | Result after pipeline                                                                                |
| --- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| S1  | SSH brute force on root (88 attempts)                | INC-005, 🔴 Critical 10.0 — compromise included                                                      |
| S2  | Credential stuffing from 5-IP botnet                 | INC-003, 🔴 Critical 9.3 — alice + m.chen compromised (found in raw evidence, below rule thresholds) |
| S3  | Privilege escalation → backdoor user `svc_bkp`       | INC-004, 🟠 High 7.6                                                                                 |
| S4  | Impossible travel (alice, office → abroad in 12 min) | INC-001, 🟠 High 6.4                                                                                 |
| —   | _(benign)_ dev.jones works nights                    | INC-002, 🟢 Low 1.9 — keeps the system honest                                                        |

## Sample output

Incident detail (Streamlit) for the worst incident:

```
INC-005 · root@203.0.113.45        Risk 10.0/10  🔴 Critical
────────────────────────────────────────────────────────────
Why this score
  entity_sensitivity  2.0/2.0   'root' is a privileged account
  rule_severity       4.0/4.0   top: RULE_SUCCESS_AFTER_FAILS (3.0)
  ml_anomaly          2.0/2.0   2 ML windows corroborate
  outcome             2.0/2.5   successful login after failures
  volume              0.86/1.0  86 evidence events

Analysis: 84 failed logins for 'root' from 203.0.113.45 within 10 min…
Actions:
  - Block the source IP at the edge firewall and add it to fail2ban
  - Disable password auth for SSH (public key only)
  - Assume compromise: reset password, revoke sessions, rotate keys
Evidence timeline: 86 raw log lines (Jun 9 14:05:00 → 14:16:37)
```

## Detection & scoring internals

- **Rules** (`app/rules.py`): brute force (N fails/user@ip/window),
  success-after-fails, credential stuffing (≥8 users sprayed from ≥2 IPs in
  one /24), impossible travel (corp↔external zone flip), backdoor user
  (useradd+usermod after sudo failures), off-hours login.
- **ML** (`app/detect_ml.py`): per-entity 1h windows (user@ip and ip-only
  views), 11 features, IsolationForest (200 trees, contamination 0.08),
  top-3 z-score drivers named in every detection. Service accounts excluded.
- **Risk** (`app/score.py`): entity sensitivity + rule severity + ML
  corroboration + multi-source agreement + outcome (raw-evidence compromise
  scan) + volume → 0–10, fully itemized in `incidents.risk_breakdown`.
- **Recommendations** (`app/recommend.py`): `generate_recommendation()`
  builds a structured prompt (no raw logs) → Google Gemini
  (`gemini-3.5-flash-lite`, free tier) → built-in playbook fallback
  (demo-day safe), cached per incident.

## Performance

100,748-line synthetic log (`data/perf/`), full pipeline:

| Stage                  | Time                         |
| ---------------------- | ---------------------------- |
| Ingest                 | 1.7s                         |
| Rules (all 6)          | 0.4s                         |
| ML (features + forest) | 10.2s                        |
| Correlate              | 0.1s                         |
| Score + recommend      | 1.0s                         |
| **Total**              | **13.5s** (~7,500 lines/sec) |

Optimizations: rules 9.3s→0.4s (two-pointer + bisect),
ML 24.9s→10.2s (vectorized feature engineering, no per-row rescans),
correlation gained span-discipline so recurring activity clusters into
bursts instead of one mega-incident.

## Verifiers

```powershell
python -m app.verify_ingest        # rows vs ground truth
python -m app.verify_detect        # 4 attacks flagged by name
python -m app.verify_ml            # ML-only catches, FP count
python -m app.verify_correlate    # multi-stage collapse
python -m app.verify_score         # breakdown integrity + ranking
python -m app.verify_recommend     # every incident explained
python -m app.verify_report        # report structure
python -m app.test_api             # FastAPI endpoints
python -m app.test_web             # SPA + API end-to-end journey
```

## Known limitations

- LLM recommendations are written by Gemini from structured incident data —
  always sanity-check actions against your own environment before executing.
- The Gemini integration uses REST directly; no SDK dependency, but the model
  name (`gemini-3.5-flash-lite`) may need bumping as Google rotates free-tier
  models.

- Syslog timestamps carry no year (assumed 2026); no cross-year wrap handling.
- Impossible travel uses corp/external zones, not GeoIP distances.
- At 100k+ line scale, recurring benign activity (e.g. nightly admin logins)
  can chain into a few long-span incidents; span-splitting keeps each burst
  separate but a handful of multi-month "pattern" incidents remain.
- PDF export requires WeasyPrint's native GTK libs; it degrades to
  Markdown-only where unavailable.
