"""
Performance Benchmark

Measures end-to-end connection setup latency for the full SDP flow
(Controller auth -> SPA knock -> TCP connect) across N legitimate
requests, and prints summary statistics. Compare this against a plain
open-TCP-port baseline (implement your own trivial echo server for the
baseline case) to quantify SDP's performance overhead for your report.

Usage:
  python -m evaluation.performance_metrics --user alice --resource aws-db-01 --runs 20
"""
import argparse
import json
import os
import socket
import statistics
import sys
import time
import yaml

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from src.utils.crypto_utils import build_spa_packet

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")


def authenticate(controller_host, controller_port, client_id, password, resource):
    with socket.create_connection((controller_host, controller_port), timeout=5) as sock:
        request = {"client_id": client_id, "password": password, "resource": resource}
        sock.sendall((json.dumps(request) + "\n").encode())
        return json.loads(sock.makefile().readline())


def single_run(config, user, resource, password="demo-pass"):
    controller = config["controller"]
    secret = config["hmac_secret"]

    start = time.perf_counter()

    auth_response = authenticate(controller["host"], controller["port"], user, password, resource)
    if auth_response.get("status") != "granted":
        return None

    token = auth_response["token"]
    gateway = auth_response["gateway"]

    packet = build_spa_packet(user, resource, secret)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.sendto(json.dumps(packet).encode(), (gateway["host"], gateway["spa_port"]))
    udp_sock.close()
    time.sleep(0.3)

    with socket.create_connection((gateway["host"], gateway["tcp_port"]), timeout=5) as sock:
        sock.sendall(json.dumps({"token": token}).encode())
        sock.recv(4096)

    elapsed = time.perf_counter() - start
    return elapsed


def main():
    parser = argparse.ArgumentParser(description="SDP Performance Benchmark")
    parser.add_argument("--user", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()

    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    latencies = []
    for i in range(args.runs):
        elapsed = single_run(config, args.user, args.resource)
        if elapsed is not None:
            latencies.append(elapsed)
            print(f"Run {i+1}/{args.runs}: {elapsed*1000:.1f} ms")
        else:
            print(f"Run {i+1}/{args.runs}: DENIED (excluded from stats)")

    if latencies:
        print("\n--- Summary (SDP full flow: auth + SPA knock + TCP connect) ---")
        print(f"  Runs counted : {len(latencies)}")
        print(f"  Mean latency : {statistics.mean(latencies)*1000:.1f} ms")
        print(f"  Median       : {statistics.median(latencies)*1000:.1f} ms")
        if len(latencies) > 1:
            print(f"  Std dev      : {statistics.stdev(latencies)*1000:.1f} ms")
        print(f"  Min / Max    : {min(latencies)*1000:.1f} / {max(latencies)*1000:.1f} ms")
        print("\nNote: ~300ms of this is the deliberate SPA settle delay "
              "(time.sleep before TCP connect) — reduce/tune this in "
              "sdp_client.py and sdp_gateway.py for tighter latency numbers, "
              "and document the trade-off in your report.")
    else:
        print("No successful runs — check controller/gateway are running and policy allows this user/resource.")


if __name__ == "__main__":
    main()
