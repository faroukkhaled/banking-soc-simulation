"""Score detectors against the simulator's ground truth."""
from . import detectors, simulator

# which scenario labels each detector is allowed to fire on (stuffing victims really do travel "impossibly")
EXPECTED = {
    "credential-stuffing": {"stuffing"},
    "impossible-travel": {"travel", "stuffing", "ato"},
    "new-payee-large-transfer": {"ato"},
    "structuring": {"structuring"},
    "mule-fan-in": {"mule"},
    "insider-browsing": {"insider"},
    "phishing-click": {"phishing"},
}
SCENARIOS = {"stuffing", "ato", "travel", "structuring", "mule", "insider", "phishing"}


def evaluate(seed=5, customers=60, days=1):
    events = simulator.generate(seed, customers, days)
    alerts = detectors.run(events)
    label = {e["id"]: e["_scenario"] for e in events}

    def labels(a):
        # an alert is explained by the label of any event that triggered it
        return {label[i] for i in a.evidence} | {a.scenario}

    ok = lambda a: bool(labels(a) & EXPECTED.get(a.detector, set()))
    caught = set()
    for a in alerts:
        if ok(a):
            caught |= labels(a) & EXPECTED[a.detector]
    false_pos = [a for a in alerts if not ok(a)]
    return {"events": len(events), "alerts": len(alerts), "scenarios": len(SCENARIOS),
            "caught": sorted(caught), "missed": sorted(SCENARIOS - caught), "false_positives": [a.as_dict() for a in false_pos]}
