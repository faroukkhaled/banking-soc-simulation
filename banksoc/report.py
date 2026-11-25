def incident_markdown(inc):
    out = ["# Incident #%d: %s" % (inc["id"], inc["title"]), "",
           "- Severity: %s (score %d)" % (inc["severity"], inc["score"]),
           "- Status: %s" % inc["status"],
           "- Window: %s to %s" % (inc["start"], inc["end"]),
           "- Entities: %s" % ", ".join(inc["entities"]),
           "- Tactics: %s" % ", ".join(inc["tactics"]), "", "## Alerts", ""]
    for a in inc["alerts"]:
        out.append("- %s **%s** [%s] %s (%s)" % (a["time"], a["detector"], a["severity"], a["summary"], a["technique"]))
    if inc.get("notes"):
        out += ["", "## Analyst notes", ""] + ["- %s %s: %s" % (n["ts"], n["author"], n["text"]) for n in inc["notes"]]
    out += ["", "## Actions", "", "See `runbooks/alert-triage.md` for the response steps for each alert type.", ""]
    return "\n".join(out)
