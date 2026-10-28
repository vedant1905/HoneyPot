import os
import sys
import json
import threading
import time
from core.logger import HoneypotLogger
from core.services.ssh_honeypot import SSHHoneypot
from core.services.http_honeypot import HTTPHoneypot
from core.services.ftp_honeypot import FTPHoneypot

BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║                CYBER DEFENSE HONEYPOT LAB                    ║
  ║             [ Safe Local Simulation Sandbox ]                ║
  ╚══════════════════════════════════════════════════════════════╝
"""

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    print(BANNER)
    config = load_config()
    host = config.get("host", "127.0.0.1")

    # Safety Guard: Ensure strictly bound to loopback/local
    if host not in ("127.0.0.1", "localhost"):
        print("[!] SAFETY WARNING: Project is configured strictly for local simulation.")
        print(f"[!] Overriding host {host} -> 127.0.0.1")
        host = "127.0.0.1"

    logger = HoneypotLogger(log_dir=config.get("log_dir", "logs"), log_file=config.get("log_file", "honeypot_events.json"))

    threads = []
    service_instances = []

    print(f"[*] Initializing Honeypot Decoy Services on {host}...")

    # SSH Decoy
    if config["services"]["ssh"].get("enabled", True):
        ssh_cfg = config["services"]["ssh"]
        ssh = SSHHoneypot(host, ssh_cfg["port"], ssh_cfg["banner"], logger)
        t = threading.Thread(target=ssh.start, name="SSH-Service", daemon=True)
        threads.append(t)
        service_instances.append(ssh)
        print(f"    [+] SSH Decoy Active  -> Port {ssh_cfg['port']}")

    # HTTP Decoy
    if config["services"]["http"].get("enabled", True):
        http_cfg = config["services"]["http"]
        http = HTTPHoneypot(host, http_cfg["port"], http_cfg["server_header"], http_cfg["app_name"], logger)
        t = threading.Thread(target=http.start, name="HTTP-Service", daemon=True)
        threads.append(t)
        service_instances.append(http)
        print(f"    [+] HTTP Portal Decoy -> Port {http_cfg['port']} (http://{host}:{http_cfg['port']})")

    # FTP Decoy
    if config["services"]["ftp"].get("enabled", True):
        ftp_cfg = config["services"]["ftp"]
        ftp = FTPHoneypot(host, ftp_cfg["port"], ftp_cfg["banner"], logger)
        t = threading.Thread(target=ftp.start, name="FTP-Service", daemon=True)
        threads.append(t)
        service_instances.append(ftp)
        print(f"    [+] FTP Decoy Active  -> Port {ftp_cfg['port']}")

    print("\n[*] Starting listeners. Press Ctrl+C to shut down.")
    print("[*] To test, run the attack simulator in another terminal:")
    print("    python simulator/simulate_attacks.py\n")

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot services safely...")
        for s in service_instances:
            s.stop()
        print("[+] All services stopped. Logs preserved in logs/honeypot_events.json")

if __name__ == "__main__":
    main()
