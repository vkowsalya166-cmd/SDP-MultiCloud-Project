"""
Blockchain-Style Tamper-Proof Audit Log

Implements a minimal, single-node hash-chained ledger (the same core
idea as a blockchain, without consensus/mining, which is unnecessary for
a single trusted logging authority like an SDP Controller). Every
access-control decision (granted/denied) is appended as a "block" that
cryptographically commits to the previous block's hash, so any retroactive
edit, deletion, or reordering of history is detectable.

Block structure:
    {
        "index": int,
        "timestamp": float,
        "event": {...},          # the SDP event being recorded
        "previous_hash": str,    # SHA-256 hash of the previous block
        "hash": str              # SHA-256 hash of this block's own contents
    }

This is intentionally simple/auditable for an academic project: it
demonstrates the *integrity* property blockchains provide (tamper
evidence via hash chaining), which is directly useful for SDP access
logs that may later be needed as forensic evidence.
"""
import hashlib
import json
import os
import threading
import time
from typing import Dict, Any, List, Optional

LEDGER_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "results", "audit_chain.json")


def _hash_block(index: int, timestamp: float, event: Dict[str, Any], previous_hash: str) -> str:
    block_content = json.dumps(
        {"index": index, "timestamp": timestamp, "event": event, "previous_hash": previous_hash},
        sort_keys=True,
    )
    return hashlib.sha256(block_content.encode()).hexdigest()


class AuditChain:
    """A minimal append-only, hash-chained audit ledger with a genesis block."""

    GENESIS_HASH = "0" * 64

    def __init__(self, path: str = LEDGER_PATH):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self._write_chain([])

    # ---------- persistence ----------
    def _read_chain(self) -> List[Dict[str, Any]]:
        try:
            with open(self.path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write_chain(self, chain: List[Dict[str, Any]]):
        with open(self.path, "w") as f:
            json.dump(chain, f, indent=2)

    # ---------- core operations ----------
    def add_block(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append a new event as a block, chained to the previous block's hash."""
        with self._lock:
            chain = self._read_chain()
            index = len(chain)
            previous_hash = chain[-1]["hash"] if chain else self.GENESIS_HASH
            timestamp = time.time()
            block_hash = _hash_block(index, timestamp, event, previous_hash)
            block = {
                "index": index,
                "timestamp": timestamp,
                "event": event,
                "previous_hash": previous_hash,
                "hash": block_hash,
            }
            chain.append(block)
            self._write_chain(chain)
            return block

    def verify_chain(self) -> Dict[str, Any]:
        """
        Recompute every block's hash and confirm the chain of
        previous_hash references is unbroken. Returns a report:
        {"valid": bool, "blocks_checked": int, "first_invalid_index": int|None}
        """
        chain = self._read_chain()
        expected_previous = self.GENESIS_HASH

        for block in chain:
            recomputed = _hash_block(
                block["index"], block["timestamp"], block["event"], block["previous_hash"]
            )
            if recomputed != block["hash"] or block["previous_hash"] != expected_previous:
                return {
                    "valid": False,
                    "blocks_checked": len(chain),
                    "first_invalid_index": block["index"],
                }
            expected_previous = block["hash"]

        return {"valid": True, "blocks_checked": len(chain), "first_invalid_index": None}

    def get_chain(self) -> List[Dict[str, Any]]:
        return self._read_chain()

    def tamper_demo(self, index: int, new_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        FOR DEMONSTRATION/TESTING ONLY: directly edits a historical block's
        event data WITHOUT recomputing hashes, to simulate an attacker
        tampering with the log file. Use this to show verify_chain()
        catching the tamper in your viva/demo. Never call this in normal
        operation.
        """
        with self._lock:
            chain = self._read_chain()
            if index >= len(chain):
                return None
            chain[index]["event"] = new_event  # hash now stale -> detectable
            self._write_chain(chain)
            return chain[index]
