# Alert triage runbook

For every alert: 1) validate (true/false positive), 2) scope, 3) classify severity, 4) act or escalate, 5) document.

## Credential stuffing
Validate: many accounts, one source, short time. Check if any success followed. Act: block source IP, force reset on any account with a success, notify fraud team. FP: shared corporate NAT or load testing.

## Possible account takeover / high-value transfer
Validate: new country, prior failures, new payee, amount vs customer history. Act: hold transfer, lock online access, call customer on the number on file, escalate to fraud (critical, 15 min SLA). Preserve logs.

## Mass account viewing (insider)
Validate: role, ticket or business reason, hours. Act: notify line manager and compliance quietly, preserve access logs, restrict access if no reason. Treat as confidential.

## Phishing link clicked
Validate: sender domain, URL reputation, whether credentials were entered. Act: reset password, check mailbox rules and other recipients, block domain and URL, search proxy logs for other clicks.

## Severity
Critical: money moving or confirmed compromise. High: probable attack in progress. Medium: needs review same day. Low: informational.
