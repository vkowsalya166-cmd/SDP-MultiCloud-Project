"""
Audit Chain Verification Tool

Run this any time to check whether the SDP access log's hash chain is
intact (i.e., no historical block has been edited or deleted).

Usage:
  python -m evaluation.verify_audit_chain                 # just verify
  python -m evaluation.verify_audit_chain --demo-tamper    # verify, then
      tamper with block 0 and verify again, to DEMONSTRATE detection
      (use only for your viva/demo — do not run this against a real log
      you want to keep intact)
"""
import argparse
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.utils.audit_chain import AuditChain


def main():
    parser = argparse.ArgumentParser(description="Verify SDP audit chain integrity")
    parser.add_argument("--demo-tamper", action="store_true",
                         help="After verifying, tamper with block 0 and verify again "
                              "to demonstrate tamper detection (for demo purposes only)")
    args = parser.parse_args()

    chain = AuditChain()

    print("=== Audit Chain Verification ===")
    report = chain.verify_chain()
    print(json.dumps(report, indent=2))
    if report["valid"]:
        print(f"✔ Chain is INTACT across {report['blocks_checked']} blocks.")
    else:
        print(f"✘ TAMPERING DETECTED at block index {report['first_invalid_index']}.")

    if args.demo_tamper:
        print("\n=== Simulating tampering with block 0 (for demonstration) ===")
        tampered = chain.tamper_demo(0, {"event": "access_granted", "client_id": "mallory",
                                          "resource": "aws-db-01", "note": "maliciously edited"})
        if tampered is None:
            print("No block 0 exists yet — run the controller and make at least one "
                  "request first, then re-run this demo.")
            return
        print("Block 0 was directly edited on disk (bypassing the chain-safe API).")

        print("\n=== Re-verifying after tamper ===")
        report2 = chain.verify_chain()
        print(json.dumps(report2, indent=2))
        if not report2["valid"]:
            print(f"✔ As expected, tampering was DETECTED at block index "
                  f"{report2['first_invalid_index']} — the hash chain caught it.")
        else:
            print("Unexpected: tampering was not detected — check the chain length.")


if __name__ == "__main__":
    main()
