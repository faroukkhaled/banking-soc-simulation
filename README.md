# Bank SOC Platform (simulation)

A miniature bank security operations platform written in Python (standard library only, 3.10+): a seeded activity simulator with injected attacks, streaming detectors, alert-to-incident correlation with risk scoring, an SQLite case store with triage workflow and SLA tracking, a JSON API, and a web console.

Portfolio and learning project. All customers, IPs, payees and amounts are synthetic.

## Pipeline
```
simulator -> detectors (stateful, streaming) -> correlation (union-find on entities) -> store (SQLite) -> API + console
```

## Attack scenarios injected into the simulation
| Scenario | Detector | ATT&CK |
|----------|----------|--------|
| Credential stuffing then a successful login | `credential-stuffing` (distinct failures per IP in a window, escalates on success) | T1110.004 |
| Account takeover: foreign login, password reset, new payee, large transfer | `new-payee-large-transfer` (scaled to the customer's own history) | T1657 |
| Login from two countries too fast | `impossible-travel` (haversine distance / elapsed time, with cooldown) | T1078 |
| Transfers just under the reporting threshold | `structuring` | T1657 |
| Many customers paying one payee | `mule-fan-in` | T1657 |
| Teller browsing many accounts, especially out of hours | `insider-browsing` | T1213 |
| Click on a reported phishing URL | `phishing-click` | T1566.002 |

The simulator also produces benign near-misses (a legitimate trip to the UAE, repeated rent payments, ordinary staff lookups, mistyped passwords). The tests require zero false positives on them.

## Run it
```bash
python3 -m banksoc evaluate              # scenarios caught / missed / false positives, exits 1 on a problem
python3 -m banksoc detect                # incidents with their alerts
python3 -m banksoc report 2              # Markdown report for incident 2
python3 -m banksoc simulate --out data/sample_logs.jsonl
python3 -m banksoc serve --port 8080     # console at http://127.0.0.1:8080
python3 -m unittest discover -s tests
```
Options `--seed`, `--customers` and `--days` go before the command (for example `python3 -m banksoc --days 3 detect`).

## Console and API
| Endpoint | Purpose |
|----------|---------|
| `GET /` | Single-page console: incident queue, alert details, status buttons, notes |
| `GET /api/incidents[?status=]` | Incidents, highest score first |
| `GET /api/incidents/<id>` | Detail with alerts, entities, notes |
| `POST /api/incidents/<id>/status` | `new`, `triaging`, `true_positive`, `false_positive`, `closed` |
| `POST /api/incidents/<id>/notes` | Add an analyst note |
| `GET /api/metrics` | Counts by severity and status, mean minutes to acknowledge |
| `GET /api/sla` | Incidents still `new` past their SLA (critical 15 min, high 60, medium 4 h, low 24 h) |

The server binds to localhost by default, validates input, limits body size, escapes everything it renders and sends CSP and nosniff headers. It has no authentication: do not expose it.

## Correlation and scoring
Alerts that share an entity (`user:`, `ip:`, `payee:`, `staff:`) within two hours merge into one incident. Score = sum of severity weights (critical 70, high 40, medium 15) plus 10 per extra kill-chain tactic, capped at 100. Severity bands: critical 70+, high 40+, medium 15+.

## Layout
- `banksoc/` simulator, detectors, correlate, store, api, dashboard, report, evaluate, cli
- `runbooks/alert-triage.md` response steps per alert type
- `reports/sample-incident-report.md` generated report
- `data/sample_logs.jsonl` sample simulated events
- `tests/` 22 tests: detector edge cases, window expiry, reproducibility, correlation, API behaviour including error paths

## Limitations
Single-process, in-memory sliding windows. Detectors flag once per entity. Thresholds are examples, not tuned to real bank data.
