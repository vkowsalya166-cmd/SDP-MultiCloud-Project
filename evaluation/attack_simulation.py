"""
Attack Simulation Harness

Run against a live gateway (see README "How to Run") to evaluate:
  1. Port-scan stealth: send raw connection attempts / garbage UDP
     packets to the gateway's SPA port and TCP port WITHOUT a valid SPA
     "knock" first, and confirm zero responses (dark port behavior).
  2. Replay attack: capture a valid SPA packet and resend it, confirming
     the gateway rejects the replay.

Usage:
  python -m evaluation.attack_simulation --target 127.0.0.1 --spa-port 6000 --tcp-port 6001
  python -m evaluation.attack_simulation --target 127.0.0.1 --spa-port 6000 --tcp-port 6001 --baseline
      (--baseline treats the target as a normal open TCP port with no SDP,
       for contrast/comparison purposes)
"""
import argparse
import json
import socket
import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.utils.crypto_utils import build_spa_packet
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")


def port_scan_test(target: str, tcp_port: int, attempts: int = 10, timeout: float = 1.0) -> dict:
    """Attempt raw TCP connects without any SPA knock. Under SDP, all
    attempts should be refused/time out (no dynamic allow-list entry)."""
    responses = 0
    for _ in range(attempts):
        try:
            with socket.create_connection((target, tcp_port), timeout=timeout):
                responses += 1
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
    return {
        "test": "port_scan",
        "attempts": attempts,
        "successful_connections": responses,
        "stealth_effective": responses == 0,
    }


def garbage_spa_test(target: str, spa_port: int, attempts: int = 10) -> dict:
    """Send malformed UDP packets to the SPA port; gateway should log
    them as dropped and never respond (we simply confirm no crash /
    no reply on a bound listening socket, since UDP has no handshake)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    for i in range(attempts):
        sock.sendto(f"garbage-packet-{i}".encode(), (target, spa_port))
    responses = 0
    try:
        while True:
            sock.recvfrom(4096)
            responses += 1
    except socket.timeout:
        pass
    sock.close()
    return {"test": "garbage_spa_flood", "attempts": attempts, "responses_received": responses}


def replay_attack_test(target: str, spa_port: int, tcp_port: int, secret: str,
                        client_id: str = "alice", resource: str = "aws-db-01") -> dict:
    """Send one valid SPA packet, then immediately resend the SAME packet
    (replay). First should succeed in opening the allow-list window;
    the second (replay) must be rejected by the gateway's nonce cache."""
    packet = build_spa_packet(client_id, resource, secret)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(json.dumps(packet).encode(), (target, spa_port))
    time.sleep(0.3)
    sock.sendto(json.dumps(packet).encode(), (target, spa_port))  # replay
    sock.close()

    return {
        "test": "spa_replay",
        "note": "Check results/sdp_events.log on the gateway for 'spa_rejected' "
                "with reason 'replayed_nonce' to confirm this was blocked.",
    }


def main():
    parser = argparse.ArgumentParser(description="SDP Attack Simulation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--spa-port", type=int, required=True)
    parser.add_argument("--tcp-port", type=int, required=True)
    parser.add_argument("--baseline", action="store_true",
                         help="Skip SPA-specific tests; just port-scan (for comparison)")
    args = parser.parse_args()

    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    secret = config["hmac_secret"]

    print("Running port scan test (no SPA knock)...")
    scan_result = port_scan_test(args.target, args.tcp_port)
    print(json.dumps(scan_result, indent=2))

    if not args.baseline:
        print("\nRunning garbage SPA packet flood test...")
        garbage_result = garbage_spa_test(args.target, args.spa_port)
        print(json.dumps(garbage_result, indent=2))

        print("\nRunning SPA replay attack test...")
        replay_result = replay_attack_test(args.target, args.spa_port, args.tcp_port, secret)
        print(json.dumps(replay_result, indent=2))


if __name__ == "__main__":
    main()
