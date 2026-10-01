"""
Trust Evaluator: computes a lightweight risk score for each access
request, used by the Controller to support risk-adaptive authorization
(a Zero-Trust "continuous verification" principle).

This is intentionally simple for demonstration; a real deployment would
also incorporate device posture (patch level, EDR status), geo-velocity
checks, and behavioral baselining.
"""
import time
from collections import defaultdict
from typing import Dict


class TrustEvaluator:
    def __init__(self, request_rate_limit: int = 5, rate_window_seconds: int = 60):
        self._request_log: Dict[str, list] = defaultdict(list)
        self.request_rate_limit = request_rate_limit
        self.rate_window_seconds = rate_window_seconds
        self.blocklist = set()  # e.g., known-bad client IDs / IPs

    def record_request(self, client_id: str):
        now = time.time()
        self._request_log[client_id].append(now)
        # prune old entries outside the rate window
        window_start = now - self.rate_window_seconds
        self._request_log[client_id] = [
            t for t in self._request_log[client_id] if t >= window_start
        ]

    def risk_score(self, client_id: str) -> float:
        """Returns a risk score in [0.0, 1.0]; higher = riskier."""
        if client_id in self.blocklist:
            return 1.0

        request_count = len(self._request_log.get(client_id, []))
        rate_risk = min(request_count / self.request_rate_limit, 1.0)

        hour = time.localtime().tm_hour
        off_hours_risk = 0.3 if (hour < 6 or hour > 22) else 0.0

        score = min(1.0, 0.7 * rate_risk + off_hours_risk)
        return round(score, 2)

    def should_step_up_auth(self, client_id: str, threshold: float = 0.6) -> bool:
        return self.risk_score(client_id) >= threshold

    def block(self, client_id: str):
        self.blocklist.add(client_id)
