# Demo Script — J-001 Log Security Analyzer

**Target: under 3 minutes.** Rehearse the click path top to bottom before demo day.
Dataset: `data/synthetic/auth.log` (4 planted attacks + 1 benign night owl).

## Setup (before the demo, never live)

```powershell
venv\Scripts\uvicorn.exe app.main:app --port 8000
```

Open http://localhost:8000 — the SENTINEL web app. Sanity check: the
Overview shows the empty state ("Run the security demo →") and the sidebar
badge reads AWAITING DATA — clean slate for the audience.

## The 3 demo scenarios

| # | Scenario | What you say | What you show |
|---|---|---|---|
| 1 | **"Feed it a log"** | "Upload any SSH auth log — or press one button for the sample." | Analyze page → "▶ Run" on the SSH sample |
| 2 | **"It finds and explains attacks"** | "The pipeline narrates itself: parse, rules, ML, correlation, scoring, recommendations. Then the overview gives severity counts, trends, top offenders." | Staged progress → Overview |
| 3 | **"Risk is explainable, not a black box"** | "Here's a Critical: root brute-forced and compromised — 86 events, every factor itemized. And here's a Low: dev.jones just works nights. The system doesn't cry wolf." | INC-005 detail → INC-002 detail → export report |

## Timed click path (rehearse to < 3:00)

```
0:00  Overview (empty state) — one line: "raw logs in, explained incidents out."
      Click "Run the security demo →", then "▶ Run" on the SSH sample.   (Analyze)
0:05  Processing: six stages check off with a live progress bar.
      Say: "Parsing, eleven detection rules, IsolationForest, correlation,
      scoring with full breakdowns, AI recommendations."
0:30  OVERVIEW.
      "Two Critical, two High, one Low — five incidents from 800 log lines."
      Point at: KPI strip → posture ring → threat activity timeline →
      top risk entities (203.0.113.45 leads).
1:00  INCIDENTS. "Sorted by risk. Read the one-line AI summaries."
      Open INC-005.
1:10  INC-005 DETAIL (spend the most time here).
      - Score 10.0 CRITICAL — "clamped from 11.9, every point itemized below."
      - Walk the breakdown rows: entity=root, rules maxed, ML corroborates,
        OUTCOME=compromise ("that's why it's Critical, not High").
      - Read the AI summary aloud: 84 fails → 1 success.
      - Recommended actions: block IP/fail2ban, key-only SSH, revoke sessions.
      - Scroll evidence: real raw log lines, failures then the fatal success.
      - "Everything traces back to raw log lines — nothing is magic."
2:10  Back to Incidents. Open INC-002 (LOW, dev.jones).
      "Same pipeline, opposite verdict: score 1.9, single off-hours rule,
      recommendation is *verify with the user*, not page someone at 3am.
      Risk triage only works if Low exists."
2:35  Export. Reports view → "⬇ Markdown" — executive summary, all incidents,
      pipeline stats, per-incident detail. CSV/JSON exports one click away.
      "Shareable Markdown per incident or per run, one click, timestamped."
2:50  Done. Land the line: "From raw logs to explained, evidenced,
      prioritized incidents — in under a minute of compute."
```

## The Low-vs-Critical contrast (don't skip this)

Judges' #1 question for security tools is false positives. INC-002
(dev.jones, 🟠→🟢 Low 1.9) exists precisely to answer it:

- **INC-005 (Critical 10.0)**: privileged account + compromise achieved +
  86-event evidence + multi-source agreement.
- **INC-002 (Low 1.9)**: named human + single soft rule + 2 events +
  recommendation is "verify with the user".
- Same engine, same data — the *breakdown table* is the proof that the
  scores aren't arbitrary.

## Fallbacks (demo-day insurance)

| Risk | Fallback |
|---|---|
| No internet / Gemini quota out / flaky API | Recommendations auto-fall back to the built-in playbook (concrete actions per rule type) — output stays high-quality; the detail view notes which generator ran |
| Server won't start | `python -m app.ingest && … && python -m app.report` — show `reports/*.md` + terminal output |
| Web app dies mid-demo | `/docs` walks the same journey through the REST API |
| Question: "what about scale?" | `python -m app.bench` — 100k lines in ~13.5s; run it live, it's fast enough to wait for |
| Question: "how do you know it's right?" | `python -m app.verify_detect` etc. — verifiers score the pipeline against the planted answer key |

## Numbers to memorize

- 806-line demo log → 5 incidents (4 attacks, 1 benign), 0 clean-noise FPs
- 100,748-line perf log → full pipeline 13.5s (~7,500 lines/sec)
- Worst incident: root@203.0.113.45, 84 failed logins in 11 minutes,
  then a success — Critical 10.0
- Subtle catch: alice & m.chen compromises (1–3 fails then success each)
  — too quiet for any rule, caught by ML + the outcome scan in scoring
