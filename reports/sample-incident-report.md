# Incident report: account takeover, cust007 (simulation)

- Severity: Critical
- Detected: 2026-03-02 12:00:40 by rule "Possible account takeover"

## Summary
After 6 failed logins, cust007 logged in from Nigeria (never seen before) and 80 seconds later sent 48,000 to a new payee acct9999.

## Timeline
| Time | Event |
|---|---|
| 12:00:00 to 12:00:25 | 6 failed logins from 203.0.113.99 |
| 12:00:40 | Successful login from the same IP |
| 12:02:00 | Transfer of 48,000 to acct9999 |

## Actions (simulated)
Transfer held, online access locked, customer contacted by phone, IP blocked, fraud team engaged.

## Recommendations
Step-up authentication for new payees and new countries, transfer limits for new payees, customer alerting by SMS.
