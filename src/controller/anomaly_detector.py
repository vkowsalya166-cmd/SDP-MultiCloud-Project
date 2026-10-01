"""
ML-Based Anomaly Detection for SDP Access Requests

Uses scikit-learn's IsolationForest — an unsupervised anomaly detection
algorithm well suited to this problem because we don't have labeled
"attack" examples in advance; we only know what *normal* legitimate
access behavior looks like, and want to flag requests that deviate from
it (the same principle used in production UEBA/SIEM anomaly engines).

Feature vector per request:
    [hour_of_day, request_rate_last_60s, resource_sensitivity_score,
     is_new_client_resource_pair]

The model is trained on a synthetic baseline of "normal" access patterns
at startup (see `_generate_baseline_traffic`), then used to score live
requests in `score()`. In a real deployment you would replace the
synthetic baseline with several days/weeks of real historical access
logs before going live — this is documented as a required step in
docs/methodology.md.
"""
import time
from collections import defaultdict
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest

SENSITIVITY_SCORE = {"low": 0.2, "medium": 0.5, "high": 0.9}


class AnomalyDetector:
    def __init__(self, contamination: float = 0.03, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            random_state=random_state,
        )
        self._request_history: Dict[str, List[float]] = defaultdict(list)
        self._known_pairs = set()
        self._fit_baseline()

    # ---------- baseline training ----------
    def _generate_baseline_traffic(self, n_samples: int = 400) -> np.ndarray:
        """
        Synthesize plausible 'normal' business-hours access patterns to
        train the model on, since a fresh deployment has no history yet.
        Columns: [hour_of_day, request_rate, sensitivity_score, is_new_pair]
        """
        rng = np.random.default_rng(42)
        hours = rng.normal(loc=13, scale=3, size=n_samples).clip(0, 23)          # mostly daytime
        rates = rng.poisson(lam=1.5, size=n_samples).clip(0, 8)                  # low, steady request rate
        sensitivities = rng.choice([0.2, 0.5, 0.9], size=n_samples, p=[0.3, 0.5, 0.2])
        # ~35% "new" client/resource pairings reflects that first-time
        # access to a resource is a routine, not rare, event in normal
        # traffic -- calibrated up from an earlier 10% that caused
        # legitimate first-time requests to be false-flagged.
        is_new_pair = rng.choice([0, 1], size=n_samples, p=[0.65, 0.35])
        return np.column_stack([hours, rates, sensitivities, is_new_pair])

    def _fit_baseline(self):
        baseline = self._generate_baseline_traffic()
        self.model.fit(baseline)

    # ---------- live feature extraction ----------
    def _record_and_get_rate(self, client_id: str, window_seconds: int = 60) -> int:
        now = time.time()
        history = self._request_history[client_id]
        history.append(now)
        window_start = now - window_seconds
        self._request_history[client_id] = [t for t in history if t >= window_start]
        return len(self._request_history[client_id])

    def _build_feature_vector(self, client_id: str, resource: str, sensitivity: str) -> np.ndarray:
        hour = time.localtime().tm_hour
        rate = self._record_and_get_rate(client_id)
        sens_score = SENSITIVITY_SCORE.get(sensitivity, 0.5)

        pair_key = f"{client_id}:{resource}"
        is_new_pair = 0 if pair_key in self._known_pairs else 1
        self._known_pairs.add(pair_key)

        return np.array([[hour, rate, sens_score, is_new_pair]])

    # ---------- public scoring API ----------
    def score(self, client_id: str, resource: str, sensitivity: str) -> Dict[str, float]:
        """
        Returns {"anomaly_score": float in ~[-0.5, 0.5] (lower = more anomalous),
                 "is_anomaly": bool}
        IsolationForest's decision_function: negative scores => more anomalous.
        """
        features = self._build_feature_vector(client_id, resource, sensitivity)
        raw_score = float(self.model.decision_function(features)[0])
        prediction = int(self.model.predict(features)[0])  # -1 = anomaly, 1 = normal
        return {
            "anomaly_score": round(raw_score, 4),
            "is_anomaly": prediction == -1,
        }
