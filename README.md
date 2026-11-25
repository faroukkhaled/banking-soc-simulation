# Banking SOC Simulation

A simulation of a bank SOC workflow: generate realistic-looking synthetic logs, detect attacks with rules, triage alerts, and write incident reports. All data is fake.

## Scenarios injected into the logs
1. Credential stuffing against many customer accounts
2. Account takeover with a high-value transfer to a new payee
3. Insider mass viewing of customer accounts out of hours
4. Phishing link clicked by a teller

## Run
```
python3 simulator/generate_logs.py > sample_logs.jsonl
python3 detections/detect.py sample_logs.jsonl
```
Python 3 standard library only. Expected: 5 alerts.

## Layout
- `simulator/` log generator (seeded, reproducible)
- `detections/` rules with MITRE ATT&CK mapping and severity
- `runbooks/` triage steps and severity levels per alert type
- `reports/` sample incident report
