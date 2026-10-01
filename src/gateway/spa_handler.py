"""
Single Packet Authorization (SPA) verification logic used by the SDP
Gateway. Implements the "dark port" behavior: invalid packets receive
absolutely no response, so an unauthenticated scanner cannot even tell
the port is open.
"""
import time
from typing import Dict, Any, Set

from src.utils.crypto_utils import hmac_verify, is_fresh


class SPAHandler:
    def __init__(self, secret: str, freshness_window: int = 30):
        self.secret = secret
        self.freshness_window = freshness_window
        self._seen_nonces: Set[str] = set()
        self._nonce_expiry: Dict[str, float] = {}

    def _prune_nonces(self):
        now = time.time()
        expired = [n for n, t in self._nonce_expiry.items() if t < now]
        for n in expired:
            self._seen_nonces.discard(n)
            self._nonce_expiry.pop(n, None)

    def verify(self, spa_packet: Dict[str, Any], expected_resource: str) -> Dict[str, Any]:
        """
        Returns {"valid": bool, "reason": str, "client_id": str|None}.
        Never raises — malformed input must fail closed silently.
        """
        self._prune_nonces()
        try:
            payload = spa_packet["payload"]
            signature = spa_packet["signature"]
        except (KeyError, TypeError):
            return {"valid": False, "reason": "malformed_packet", "client_id": None}

        # 1. Signature check
        if not hmac_verify(payload, signature, self.secret):
            return {"valid": False, "reason": "bad_signature", "client_id": None}

        # 2. Freshness / anti-replay (timestamp window)
        if not is_fresh(payload.get("timestamp", 0), self.freshness_window):
            return {"valid": False, "reason": "stale_timestamp", "client_id": payload.get("client_id")}

        # 3. Nonce replay check
        nonce = payload.get("nonce")
        if not nonce or nonce in self._seen_nonces:
            return {"valid": False, "reason": "replayed_nonce", "client_id": payload.get("client_id")}

        # 4. Resource match
        if payload.get("resource") != expected_resource:
            return {"valid": False, "reason": "resource_mismatch", "client_id": payload.get("client_id")}

        # Passed all checks — record nonce to prevent reuse
        self._seen_nonces.add(nonce)
        self._nonce_expiry[nonce] = time.time() + self.freshness_window + 5

        return {"valid": True, "reason": "ok", "client_id": payload.get("client_id")}
