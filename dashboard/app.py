"""
SDP Live Monitoring Dashboard — Backend

A lightweight Flask app that reads:
  - results/sdp_events.log   (line-delimited JSON event log)
  - results/audit_chain.json (hash-chained audit ledger)

...and exposes them as JSON APIs, plus serves a single-page dashboard
(dashboard/templates/index.html) that polls those APIs every 2 seconds
to show live SDP activity: access grants/denials, SPA rejections
(simulated attacks), anomaly scores, and audit chain integrity status.

Run:
  python -m dashboard.app
Then open http://127.0.0.1:9000 in a browser while the Controller and
at least one Gateway are running (see README) to watch events stream in
live as you run client requests / attack simulations in other terminals.
"""
import json
import os
import sys

from flask import Flask, jsonify, render_template

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.utils.audit_chain import AuditChain

BASE_DIR = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
LOG_FILE = os.path.join(RESULTS_DIR, "sdp_events.log")

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
audit_chain = AuditChain()


def read_events(limit: int = 200):
    if not os.path.exists(LOG_FILE):
        return []
    events = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events[-limit:][::-1]  # most recent first


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    events = read_events()
    summary = {
        "total": len(events),
        "granted": sum(1 for e in events if e.get("event") == "access_granted"),
        "denied": sum(1 for e in events if e.get("event") in
                      ("access_denied", "auth_failed", "step_up_required")),
        "spa_rejected": sum(1 for e in events if e.get("event") == "spa_rejected"),
        "anomalies": sum(1 for e in events if e.get("event") == "anomaly_detected"),
    }
    return jsonify({"events": events, "summary": summary})


@app.route("/api/audit-chain")
def api_audit_chain():
    report = audit_chain.verify_chain()
    chain = audit_chain.get_chain()
    return jsonify({"integrity": report, "blocks": chain[-50:][::-1]})


def main():
    print("SDP Dashboard running at http://127.0.0.1:9000")
    app.run(host="127.0.0.1", port=9000, debug=False)


if __name__ == "__main__":
    main()
