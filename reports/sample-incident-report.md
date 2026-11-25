# Incident #2: ip:185.220.101.61: credential-stuffing, impossible-travel

- Severity: critical (score 100)
- Status: new
- Window: 2026-03-02T09:10:42 to 2026-03-02T09:13:00
- Entities: ip:185.220.101.61, user:cust015
- Tactics: Credential Access, Initial Access

## Alerts

- 2026-03-02T09:10:42 **credential-stuffing** [high] 8 accounts failed to log in from 185.220.101.61 in 600s (T1110.004)
- 2026-03-02T09:13:00 **credential-stuffing** [critical] Successful login for cust015 from credential stuffing source 185.220.101.61 (T1110.004)
- 2026-03-02T09:13:00 **impossible-travel** [high] cust015 logged in from QA then RU 12 min later (3570 km, 17850 km/h) (T1078)

## Actions

See `runbooks/alert-triage.md` for the response steps for each alert type.

