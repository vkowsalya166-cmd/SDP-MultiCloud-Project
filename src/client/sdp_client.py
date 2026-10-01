"""
SDP Client (Initiating Host)

Flow:
  1. Authenticate to the SDP Controller (user_id + password) and request
     access to a named resource.
  2. If granted: receive a signed session token + the target gateway's
     SPA/TCP endpoints.
  3. Send a signed SPA packet (UDP) to "knock" on the gateway's dark
     port, then attempt the TCP connection presenting the session token.
"""
import argparse
import json
import socket
import time
import sys
import os
import yaml
import getpass

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from src.utils.crypto_utils import build_spa_packet
from src.utils.logger import log_event

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")


def authenticate(controller_host: str, controller_port: int, client_id: str,
                  password: str, resource: str) -> dict:
    with socket.create_connection((controller_host, controller_port), timeout=5) as sock:
        request = {"client_id": client_id, "password": password, "resource": resource}
        sock.sendall((json.dumps(request) + "\n").encode())
        response_raw = sock.makefile().readline()
        return json.loads(response_raw)


def send_spa(gateway_host: str, spa_port: int, client_id: str, resource: str, secret: str):
    packet = build_spa_packet(client_id, resource, secret)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(json.dumps(packet).encode(), (gateway_host, spa_port))
    sock.close()


def connect_to_gateway(gateway_host: str, tcp_port: int, token: dict, timeout: int = 5) -> dict:
    with socket.create_connection((gateway_host, tcp_port), timeout=timeout) as sock:
        sock.sendall(json.dumps({"token": token}).encode())
        response_raw = sock.recv(4096)
        return json.loads(response_raw.decode())


def main():
    parser = argparse.ArgumentParser(description="SDP Client (Initiating Host)")
    parser.add_argument("--user", required=True, help="client/user id, e.g. alice")
    parser.add_argument("--resource", required=True, help="resource to access, e.g. aws-db-01")
    parser.add_argument("--password", default=None, help="omit to be prompted securely")
    args = parser.parse_args()

    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    controller = config["controller"]
    secret = config["hmac_secret"]
    password = args.password or getpass.getpass(f"Password for {args.user}: ") or "demo-pass"

    print(f"[1/3] Authenticating '{args.user}' to Controller for resource '{args.resource}'...")
    auth_response = authenticate(controller["host"], controller["port"], args.user, password, args.resource)

    if auth_response.get("status") != "granted":
        print(f"ACCESS DENIED: {auth_response.get('reason')}")
        log_event("client", "access_denied", client_id=args.user, resource=args.resource,
                   reason=auth_response.get("reason"))
        return

    token = auth_response["token"]
    gateway = auth_response["gateway"]
    print(f"[2/3] Access granted by Controller. Target gateway: {gateway}")

    print(f"[3/3] Sending SPA 'knock' + attempting connection...")
    send_spa(gateway["host"], gateway["spa_port"], args.user, args.resource, secret)
    time.sleep(0.5)  # brief pause to let the gateway open its dynamic allow-list

    try:
        result = connect_to_gateway(gateway["host"], gateway["tcp_port"], token)
        print(f"RESULT: {result}")
        log_event("client", "connection_result", client_id=args.user, resource=args.resource, result=result)
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"Connection failed: {e} (this is expected if SPA was not sent/accepted)")
        log_event("client", "connection_failed", client_id=args.user, resource=args.resource, error=str(e))


if __name__ == "__main__":
    main()
