"""
Cryptographic helper functions for the SDP framework.

NOTE: This uses a pre-shared HMAC key for simplicity/demonstration in an
academic project. A production SDP implementation would use per-device
X.509 certificates + mutual TLS for the control channel, and could layer
HMAC-based SPA on top of that for the pre-connect authorization packet.
"""
import hashlib
import hmac
import json
import time
import uuid
from typing import Dict, Any


def hmac_sign(payload: Dict[str, Any], secret: str) -> str:
    """Return a hex HMAC-SHA256 signature over a canonical JSON payload."""
    message = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def hmac_verify(payload: Dict[str, Any], signature: str, secret: str) -> bool:
    expected = hmac_sign(payload, secret)
    return hmac.compare_digest(expected, signature)


def new_nonce() -> str:
    return uuid.uuid4().hex


def build_spa_packet(client_id: str, resource: str, secret: str) -> Dict[str, Any]:
    """Build a signed Single Packet Authorization payload."""
    payload = {
        "client_id": client_id,
        "resource": resource,
        "timestamp": time.time(),
        "nonce": new_nonce(),
    }
    signature = hmac_sign(payload, secret)
    return {"payload": payload, "signature": signature}


def is_fresh(timestamp: float, window_seconds: int = 30) -> bool:
    """Anti-replay: reject packets outside the freshness window."""
    return abs(time.time() - timestamp) <= window_seconds


def build_session_token(client_id: str, resource: str, gateway: str,
                         secret: str, ttl_seconds: int = 60) -> Dict[str, Any]:
    payload = {
        "client_id": client_id,
        "resource": resource,
        "gateway": gateway,
        "issued_at": time.time(),
        "expires_at": time.time() + ttl_seconds,
    }
    signature = hmac_sign(payload, secret)
    return {"payload": payload, "signature": signature}


def verify_session_token(token: Dict[str, Any], secret: str) -> bool:
    payload, signature = token.get("payload", {}), token.get("signature", "")
    if not hmac_verify(payload, signature, secret):
        return False
    return time.time() <= payload.get("expires_at", 0)
