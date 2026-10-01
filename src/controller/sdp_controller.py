"""
SDP Controller

Listens for client authentication requests over TCP (JSON messages, one
per line). On success, evaluates policy + trust, issues a signed,
short-lived session token, and returns the SPA target (gateway host/port
and shared secret) the client needs to reach that resource.

In a production system the control channel would be mTLS; here it is a
plain local TCP socket for demonstration clarity — swapping in `ssl`
context is a documented extension point (see docs/architecture.md).
"""
import argparse
import json
import socketserver
import sys
import os
import yaml

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from src.controller.policy_engine import PolicyEngine
from src.controller.trust_evaluator import TrustEvaluator
from src.controller.anomaly_detector import AnomalyDetector
from src.utils.crypto_utils import build_session_token
from src.utils.logger import log_event
from src.utils.audit_chain import AuditChain

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")


class ControllerState:
    """Holds shared engine instances for the request handler."""
    def __init__(self, config_path: str = CONFIG_PATH):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.policy = PolicyEngine(config_path)
        self.trust = TrustEvaluator()
        self.anomaly = AnomalyDetector()
        self.audit = AuditChain()
        self.secret = self.config["hmac_secret"]
        self.ttl = self.config["controller"]["session_token_ttl_seconds"]


STATE = ControllerState()


class ControllerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline().strip()
        if not raw:
            return
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            log_event("controller", "malformed_request", peer=str(self.client_address))
            self._respond({"status": "error", "reason": "malformed_request"})
            return

        client_id = request.get("client_id")
        resource = request.get("resource")
        password = request.get("password")  # demo-only; use certs/SSO in production

        STATE.trust.record_request(client_id or "unknown")

        # --- Step 1: basic authentication (demo: any non-empty password) ---
        if not client_id or not password:
            log_event("controller", "auth_failed", client_id=client_id, reason="missing_credentials")
            STATE.audit.add_block({
                "event": "access_denied", "client_id": client_id,
                "resource": resource, "reason": "missing_credentials",
            })
            self._respond({"status": "denied", "reason": "authentication_failed"})
            return

        # --- Step 2: risk-adaptive check ---
        if STATE.trust.should_step_up_auth(client_id):
            risk = STATE.trust.risk_score(client_id)
            log_event("controller", "step_up_required", client_id=client_id, risk_score=risk)
            STATE.audit.add_block({
                "event": "access_denied", "client_id": client_id, "resource": resource,
                "reason": "step_up_authentication_required", "risk_score": risk,
            })
            self._respond({"status": "denied", "reason": "step_up_authentication_required"})
            return

        # --- Step 3: policy / least-privilege authorization ---
        if not STATE.policy.is_authorized(client_id, resource):
            log_event("controller", "access_denied", client_id=client_id, resource=resource,
                       reason="not_authorized_by_policy")
            STATE.audit.add_block({
                "event": "access_denied", "client_id": client_id,
                "resource": resource, "reason": "not_authorized_by_policy",
            })
            self._respond({"status": "denied", "reason": "not_authorized"})
            return

        gateway = STATE.policy.resolve_gateway(resource)
        if not gateway:
            self._respond({"status": "denied", "reason": "unknown_resource"})
            return

        # --- Step 4: ML-based anomaly check (Isolation Forest) ---
        # Design choice: flag-and-log rather than hard-deny. A single ML
        # signal alone is prone to false positives (e.g., a user's very
        # first legitimate access to a resource looks "new" and can score
        # as anomalous). In this project the anomaly score is surfaced to
        # the audit chain and live dashboard for analyst review / further
        # policy tuning, while the actual allow/deny decision stays with
        # the deterministic policy engine + rate-based trust evaluator.
        # See docs/architecture.md for the documented rationale and how a
        # production system might instead trigger step-up auth here.
        sensitivity = STATE.policy.resource_sensitivity(resource) or "medium"
        anomaly_result = STATE.anomaly.score(client_id, resource, sensitivity)
        if anomaly_result["is_anomaly"]:
            log_event("controller", "anomaly_detected", client_id=client_id, resource=resource,
                       anomaly_score=anomaly_result["anomaly_score"])

        # --- Step 5: issue session token + SPA target ---
        token = build_session_token(client_id, resource, gateway["cloud"], STATE.secret, STATE.ttl)
        log_event("controller", "access_granted", client_id=client_id, resource=resource,
                   gateway=gateway["cloud"], anomaly_score=anomaly_result["anomaly_score"])
        STATE.audit.add_block({
            "event": "access_granted", "client_id": client_id, "resource": resource,
            "gateway": gateway["cloud"], "anomaly_score": anomaly_result["anomaly_score"],
        })

        self._respond({
            "status": "granted",
            "token": token,
            "anomaly_score": anomaly_result["anomaly_score"],
            "gateway": {
                "host": gateway["host"],
                "spa_port": gateway["spa_port"],
                "tcp_port": gateway["tcp_port"],
            },
        })

    def _respond(self, data: dict):
        self.wfile.write((json.dumps(data) + "\n").encode())


def main():
    parser = argparse.ArgumentParser(description="SDP Controller")
    parser.add_argument("--host", default=STATE.config["controller"]["host"])
    parser.add_argument("--port", type=int, default=STATE.config["controller"]["port"])
    args = parser.parse_args()

    server = socketserver.ThreadingTCPServer((args.host, args.port), ControllerHandler)
    log_event("controller", "started", host=args.host, port=args.port)
    print(f"SDP Controller listening on {args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
