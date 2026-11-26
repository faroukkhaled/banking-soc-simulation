# banking-soc-simulation: Detections

Detectors in `banksoc/detectors.py`. ATT&CK ids are the ones the tool attaches to its alerts.

| Detector | Scenario | Notes | ATT&CK |
|---|---|---|---|
| credential-stuffing | Many failed logins from one IP, then a success | Escalates to critical on success | T1110.004 |
| new-payee-large-transfer | Account takeover: new payee after reset, then a large transfer | Scaled to the customer's own history; critical | T1657 |
| impossible-travel | Two countries too fast | Haversine distance over elapsed time, with cooldown | T1078 |
| structuring | Transfers just under the reporting threshold | 3 transfers between 9000 and 10000 in a day | T1657 |
| mule-fan-in | Many customers paying one payee | 4 customers within 60 minutes in the sample | T1657 |
| insider-browsing | Staff viewing many accounts out of hours | 10 accounts in 15 minutes in the sample | T1213 |
| phishing-click | Click on a reported phishing URL | Matches the reported URL list | T1566.002 |

Limits: rules are teaching-grade and untuned for any real environment. See the Scope and limits section of the README.
