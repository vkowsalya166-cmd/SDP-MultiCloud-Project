"""
SDP Gateway (Accepting Host)

Simulates a per-cloud enforcement point:
  1. UDP "dark port" listener receives SPA packets. Invalid packets get
     NO response (default-deny / stealth). Valid packets dynamically
     open a short-lived allow-list entry for that client IP.
  2. TCP listener only accepts connections from IPs currently on the
     allow-list, and additionally validates the Controller-issued
     session token before proxying to the simulated backend resource.
"""
import argparse
import json
import os
import socket
import sys
import threading
import time
import yaml

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from src.gateway.spa_handler import SPAHandler
from src.utils.crypto_utils import verify_session_token
from src.utils.logger import log_event

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml")
ALLOW_WINDOW_SECONDS = 15  # how long a client IP stays allow-listed after valid SPA


class SDPGateway:
    def __init__(self, cloud: str, config_path: str = CONFIG_PATH):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.cloud = cloud
        gw_cfg = self.config["gateways"][cloud]
        self.host = gw_cfg["host"]
        self.spa_port = gw_cfg["spa_port"]
        self.tcp_port = gw_cfg["tcp_port"]
        self.resource = gw_cfg["resource"]
        self.secret = self.config["hmac_secret"]

        self.spa_handler = SPAHandler(
            secret=self.secret,
            freshness_window=self.config["controller"]["spa_freshness_window_seconds"],
        )
        self._allow_list = {}  # ip -> expiry_timestamp
        self._lock = threading.Lock()

    # ---------- SPA (UDP) listener: the "dark" port ----------
    def _spa_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.spa_port))
        log_event("gateway", "spa_listener_started", cloud=self.cloud,
                   host=self.host, port=self.spa_port)
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                spa_packet = json.loads(data.decode())
            except Exception:
                # Malformed packet -> silently drop, NO response (stealth)
                log_event("gateway", "spa_dropped_malformed", cloud=self.cloud, source=str(addr))
                continue

            result = self.spa_handler.verify(spa_packet, self.resource)
            if result["valid"]:
                with self._lock:
                    self._allow_list[addr[0]] = time.time() + ALLOW_WINDOW_SECONDS
                log_event("gateway", "spa_accepted", cloud=self.cloud, source=str(addr),
                           client_id=result["client_id"])
                # Deliberately still send NO response — SDP does not
                # acknowledge SPA over the network; the client proceeds
                # to attempt the TCP connection directly.
            else:
                log_event("gateway", "spa_rejected", cloud=self.cloud, source=str(addr),
                           reason=result["reason"])
                # No response sent -> indistinguishable from closed port.

    # ---------- TCP listener: only reachable after valid SPA ----------
    def _is_allowed(self, ip: str) -> bool:
        with self._lock:
            self._prune_allow_list()
            return ip in self._allow_list

    def _prune_allow_list(self):
        now = time.time()
        expired = [ip for ip, exp in self._allow_list.items() if exp < now]
        for ip in expired:
            del self._allow_list[ip]

    def _tcp_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.tcp_port))
        server.listen(5)
        log_event("gateway", "tcp_listener_started", cloud=self.cloud,
                   host=self.host, port=self.tcp_port)
        while True:
            conn, addr = server.accept()
            threading.Thread(target=self._handle_tcp, args=(conn, addr), daemon=True).start()

    def _handle_tcp(self, conn: socket.socket, addr):
        ip = addr[0]
        if not self._is_allowed(ip):
            log_event("gateway", "tcp_connection_rejected", cloud=self.cloud,
                       source=str(addr), reason="no_prior_valid_spa")
            conn.close()
            return

        try:
            raw = conn.recv(4096)
            request = json.loads(raw.decode())
            token = request.get("token")
            if not token or not verify_session_token(token, self.secret):
                log_event("gateway", "tcp_connection_rejected", cloud=self.cloud,
                           source=str(addr), reason="invalid_or_expired_token")
                conn.sendall(json.dumps({"status": "denied", "reason": "invalid_token"}).encode())
                conn.close()
                return

            if token["payload"]["resource"] != self.resource:
                log_event("gateway", "tcp_connection_rejected", cloud=self.cloud,
                           source=str(addr), reason="resource_mismatch")
                conn.sendall(json.dumps({"status": "denied", "reason": "resource_mismatch"}).encode())
                conn.close()
                return

            # Access granted -> simulate proxying to the backend resource
            log_event("gateway", "access_granted", cloud=self.cloud, source=str(addr),
                       resource=self.resource, client_id=token["payload"]["client_id"])
            response = {
                "status": "granted",
                "resource": self.resource,
                "message": f"Connected to simulated {self.cloud} resource '{self.resource}'",
            }
            conn.sendall(json.dumps(response).encode())
        except Exception as e:
            log_event("gateway", "tcp_handling_error", cloud=self.cloud, error=str(e))
        finally:
            conn.close()

    def run(self):
        threading.Thread(target=self._spa_listener, daemon=True).start()
        threading.Thread(target=self._tcp_listener, daemon=True).start()
        log_event("gateway", "running", cloud=self.cloud, resource=self.resource)
        while True:
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="SDP Gateway")
    parser.add_argument("--cloud", required=True, choices=["aws", "azure", "gcp"])
    args = parser.parse_args()
    gateway = SDPGateway(cloud=args.cloud)
    print(f"SDP Gateway [{args.cloud}] guarding resource '{gateway.resource}' "
          f"| SPA(UDP):{gateway.spa_port} TCP:{gateway.tcp_port}")
    gateway.run()


if __name__ == "__main__":
    main()
