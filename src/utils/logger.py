"""Lightweight structured event logger shared by all SDP components."""
import datetime
import json
import os

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "results")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "sdp_events.log")


def log_event(component: str, event: str, **details):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "component": component,
        "event": event,
        **details,
    }
    line = json.dumps(entry)
    print(f"[{component}] {event} :: {details}")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
