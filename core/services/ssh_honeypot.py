import socket
import threading
import time

class SSHHoneypot:
    """Simulates an interactive SSH/Telnet terminal service to log reconnaissance & credentials."""

    FAKE_RESPONSES = {
        "whoami": "root\r\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
        "uname -a": "Linux ubuntu-srv 5.15.0-72-generic #79-Ubuntu SMP Wed Apr 19 16:49:10 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n",
        "ls": "backup.tar.gz  config.py  database.db  notes.txt\r\n",
        "ls -la": "total 48\r\ndrwx------ 4 root root  4096 Oct 28 10:00 .\r\ndrwxr-xr-x 19 root root  4096 Oct 28 09:30 ..\r\n-rw-r--r-- 1 root root 12040 Oct 28 10:05 backup.tar.gz\r\n-rw-r--r-- 1 root root   450 Oct 28 09:45 config.py\r\n-rw-r--r-- 1 root root  8192 Oct 28 10:01 database.db\r\n-rw-r--r-- 1 root root   120 Oct 28 10:15 notes.txt\r\n",
        "cat notes.txt": "TODO: Change default root password before Friday audit.\r\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\r\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\r\n",
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied\r\n",
        "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.1 169308 12820 ?        Ss   09:30   0:01 /sbin/init\r\nroot       612  0.0  0.1  14280  7120 ?        Ss   09:30   0:00 /usr/sbin/sshd -D\r\nroot      1420  0.0  0.0   9820  3210 pts/0    S    10:20   0:00 -bash\r\n",
        "ip a": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\r\n    inet 192.168.1.150/24 brd 192.168.1.255 scope global eth0\r\n",
        "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255\r\n",
        "pwd": "/root\r\n",
        "help": "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\nThese shell commands are defined internally.\r\n"
    }

    def __init__(self, host: str, port: int, banner: str, logger):
        self.host = host
        self.port = port
        self.banner = banner
        self.logger = logger
        self.server_socket = None
        self.running = False

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _readline(self, sock):
        buffer = ""
        while True:
            chunk = sock.recv(1)
            if not chunk:
                return None
            char = chunk.decode("utf-8", errors="ignore")
            if char in ("\r", "\n"):
                # Clean up any trailing newline bytes
                sock.settimeout(0.1)
                try:
                    peek = sock.recv(1)
                    if peek not in (b"\r", b"\n"):
                        # If it wasn't a newline, put it back or handle
                        pass
                except Exception:
                    pass
                sock.settimeout(30.0)
                return buffer.strip()
            buffer += char
            if len(buffer) > 1024:
                return buffer.strip()

    def _handle_client(self, sock, addr):
        src_ip, src_port = addr[0], addr[1]
        sock.settimeout(30.0)

        self.logger.log_event(
            protocol="SSH",
            event_type="CONNECTION_ESTABLISHED",
            src_ip=src_ip,
            src_port=src_port,
            details={"action": "Client connected to SSH decoy port"}
        )

        try:
            # Send SSH banner
            sock.sendall(self.banner.encode("utf-8"))

            # Emulate login prompt
            sock.sendall(b"login: ")
            username = self._readline(sock)
            if username is None:
                return

            sock.sendall(b"Password: ")
            password = self._readline(sock)
            if password is None:
                password = ""

            self.logger.log_event(
                protocol="SSH",
                event_type="AUTH_ATTEMPT",
                src_ip=src_ip,
                src_port=src_port,
                details={
                    "username": username,
                    "password": password,
                    "auth_status": "ACCEPTED_DECOY"
                }
            )

            # Present fake Linux MOTD and root shell
            motd = (
                "\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\r\n\r\n"
                " * Documentation:  https://help.ubuntu.com\r\n"
                " * Management:     https://landscape.canonical.com\r\n\r\n"
                "Last login: Sun Oct 25 14:12:08 2026 from 10.0.0.15\r\n"
            )
            sock.sendall(motd.encode("utf-8"))

            prompt = "root@ubuntu-srv:~# "
            while True:
                sock.sendall(prompt.encode("utf-8"))
                cmd = self._readline(sock)
                if cmd is None or cmd.lower() in ("exit", "quit", "logout"):
                    break

                if not cmd.strip():
                    continue

                # Log the command execution attempt
                self.logger.log_event(
                    protocol="SSH",
                    event_type="COMMAND_EXECUTION",
                    src_ip=src_ip,
                    src_port=src_port,
                    details={
                        "username": username,
                        "command": cmd
                    }
                )

                # Simulated response
                clean_cmd = cmd.strip()
                if clean_cmd in self.FAKE_RESPONSES:
                    sock.sendall(self.FAKE_RESPONSES[clean_cmd].encode("utf-8"))
                elif clean_cmd.startswith("wget ") or clean_cmd.startswith("curl "):
                    # Attacker trying to drop payload
                    sock.sendall(b"Connecting to remote host... 404 Not Found.\r\n")
                elif clean_cmd.startswith("rm ") or clean_cmd.startswith("chmod "):
                    sock.sendall(b"\r\n")
                else:
                    sock.sendall(f"bash: {clean_cmd.split()[0]}: command not found\r\n".encode("utf-8"))

        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self.logger.log_event(
                protocol="SSH",
                event_type="SESSION_CLOSED",
                src_ip=src_ip,
                src_port=src_port,
                details={"action": "Connection closed"}
            )
