import socket
import threading

class FTPHoneypot:
    """Simulates an FTP service to trap automated FTP scanners and credential brute-force bots."""

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

    def _handle_client(self, sock, addr):
        src_ip, src_port = addr[0], addr[1]
        sock.settimeout(20.0)

        self.logger.log_event("FTP", "CONNECTION_ESTABLISHED", src_ip, src_port, {"action": "Client connected to FTP decoy"})

        current_user = ""
        try:
            sock.sendall(self.banner.encode("utf-8"))
            while True:
                data = sock.recv(1024)
                if not data:
                    break

                line = data.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    current_user = arg
                    sock.sendall(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    self.logger.log_event("FTP", "AUTH_ATTEMPT", src_ip, src_port, {
                        "username": current_user,
                        "password": arg,
                        "auth_status": "FAILED"
                    })
                    sock.sendall(b"530 Login incorrect.\r\n")
                elif cmd == "SYST":
                    sock.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == "QUIT":
                    sock.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    sock.sendall(b"500 Unknown command.\r\n")
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
