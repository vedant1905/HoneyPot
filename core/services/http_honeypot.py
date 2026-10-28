from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import json

class HTTPHoneypot:
    """Simulates a corporate web portal to detect web scans, directory bruteforcing & credential stuffing."""

    def __init__(self, host: str, port: int, server_header: str, app_name: str, logger):
        self.host = host
        self.port = port
        self.server_header = server_header
        self.app_name = app_name
        self.logger = logger
        self.server = None

    def start(self):
        logger = self.logger
        server_header = self.server_header
        app_name = self.app_name

        class HoneypotHTTPHandler(BaseHTTPRequestHandler):
            def version_string(self):
                return server_header

            def log_message(self, format, *args):
                # Suppress default stdout printing; logger handles it
                pass

            def do_GET(self):
                src_ip, src_port = self.client_address[0], self.client_address[1]
                path = self.path
                user_agent = self.headers.get("User-Agent", "Unknown")

                # Detect sensitive probe targets
                details = {
                    "method": "GET",
                    "path": path,
                    "user_agent": user_agent,
                    "headers": dict(self.headers)
                }

                if any(k in path.lower() for k in [".env", "wp-", "phpmyadmin", "api", "config", "backup", "actuator"]):
                    logger.log_event("HTTP", "SENSITIVE_PATH_PROBE", src_ip, src_port, details)
                else:
                    logger.log_event("HTTP", "WEB_REQUEST", src_ip, src_port, details)

                # Return fake responses
                if path == "/.env":
                    body = "APP_NAME=EnterpriseGateway\nAPP_ENV=production\nAPP_KEY=base64:FakeSecretKeyForTarpitOnly==\nDB_PASSWORD=SuperSecretPass123\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body.encode())
                    return

                if path == "/robots.txt":
                    body = "User-agent: *\nDisallow: /admin\nDisallow: /internal-backup\nDisallow: /.env\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body.encode())
                    return

                # Default Decoy Admin Portal Page
                html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{app_name} - Login</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .card {{ background: #1e293b; border: 1px solid #334155; padding: 2.5rem; border-radius: 12px; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h2 {{ margin-top: 0; color: #38bdf8; font-size: 1.4rem; }}
        p {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }}
        input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; margin-bottom: 1rem; border: 1px solid #475569; border-radius: 6px; background: #0f172a; color: #f8fafc; }}
        button {{ width: 100%; padding: 10px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }}
        button:hover {{ background: #0369a1; }}
        .badge {{ font-size: 0.75rem; background: #0369a1; padding: 3px 8px; border-radius: 4px; display: inline-block; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">SECURE ACCESS</span>
        <h2>{app_name}</h2>
        <p>Authorized personnel only. All access attempts are recorded.</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username / Corp ID" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html.encode())

            def do_POST(self):
                src_ip, src_port = self.client_address[0], self.client_address[1]
                path = self.path
                user_agent = self.headers.get("User-Agent", "Unknown")
                content_length = int(self.headers.get("Content-Length", 0))
                post_body = self.rfile.read(content_length).decode("utf-8", errors="ignore")

                # Parse form credentials or JSON payload
                creds = {}
                try:
                    parsed = urllib.parse.parse_qs(post_body)
                    for k, v in parsed.items():
                        creds[k] = v[0] if v else ""
                except Exception:
                    creds = {"raw_payload": post_body[:500]}

                logger.log_event("HTTP", "CREDENTIAL_SUBMISSION", src_ip, src_port, {
                    "path": path,
                    "user_agent": user_agent,
                    "submitted_data": creds
                })

                # Respond with fake invalid credential error
                error_html = """<!DOCTYPE html><html><body style="background:#0f172a;color:#ef4444;font-family:sans-serif;text-align:center;padding:50px;">
                <h3>Access Denied: Invalid Credentials</h3><p style="color:#94a3b8;">Incident recorded and reported to Security Operations Center.</p>
                <a href="/" style="color:#38bdf8;">Return</a></body></html>"""
                self.send_response(401)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(error_html)))
                self.end_headers()
                self.wfile.write(error_html.encode())

        self.server = HTTPServer((self.host, self.port), HoneypotHTTPHandler)
        self.server.serve_forever()

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
            except Exception:
                pass
