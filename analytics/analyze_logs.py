import os
import json
import collections
import webbrowser
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "honeypot_events.json")
DASHBOARD_FILE = os.path.join(os.path.dirname(__file__), "dashboard.html")

def load_events():
    if not os.path.exists(LOG_FILE):
        return []
    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
    return events

def analyze():
    events = load_events()
    if not events:
        print("[!] No log events found in logs/honeypot_events.json.")
        print("[!] Please run the honeypot and simulator first:")
        print("    1. python honeypot.py")
        print("    2. python simulator/simulate_attacks.py (in another terminal)")
        return

    total = len(events)
    protocols = collections.Counter(e.get("protocol") for e in events)
    event_types = collections.Counter(e.get("event_type") for e in events)
    usernames = collections.Counter()
    passwords = collections.Counter()
    paths = collections.Counter()
    commands = collections.Counter()
    ips = collections.Counter(e.get("src_ip") for e in events)

    for e in events:
        d = e.get("details", {})
        # Usernames / Passwords from SSH, FTP, or HTTP
        u = d.get("username")
        p = d.get("password")
        if not u and "submitted_data" in d:
            u = d["submitted_data"].get("username")
            p = d["submitted_data"].get("password")
        if u:
            usernames[u] += 1
        if p:
            passwords[p] += 1

        if "path" in d:
            paths[d["path"]] += 1

        if "command" in d:
            commands[d["command"]] += 1

    print("\n" + "=" * 60)
    print("        HONEYPOT THREAT INTELLIGENCE SUMMARY REPORT")
    print("=" * 60)
    print(f"Total Captured Events : {total}")
    print(f"Unique Sources (IPs)  : {len(ips)}")
    print("\n[+] Activity by Protocol:")
    for proto, cnt in protocols.most_common():
        print(f"    - {proto:6} : {cnt:4} events ({cnt/total*100:.1f}%)")

    print("\n[+] Top Targeted Usernames:")
    for u, cnt in usernames.most_common(5):
        print(f"    - {u:20} : {cnt} attempts")

    print("\n[+] Top Targeted Passwords:")
    for p, cnt in passwords.most_common(5):
        print(f"    - {p:20} : {cnt} attempts")

    if commands:
        print("\n[+] Attacker Shell Commands Captured:")
        for cmd, cnt in commands.most_common(5):
            print(f"    - {cmd:30} : {cnt} times")

    if paths:
        print("\n[+] Top Web Paths Scanned:")
        for path, cnt in paths.most_common(5):
            print(f"    - {path:30} : {cnt} hits")

    generate_html_dashboard(total, protocols, event_types, usernames, passwords, paths, commands, events)
    print(f"\n\033[92m[✓] Interactive HTML Dashboard generated at:\033[0m")
    print(f"    {os.path.abspath(DASHBOARD_FILE)}")
    
    # Try to open in local browser
    try:
        webbrowser.open("file://" + os.path.abspath(DASHBOARD_FILE))
    except Exception:
        pass

def generate_html_dashboard(total, protocols, event_types, usernames, passwords, paths, commands, events):
    proto_labels = list(protocols.keys())
    proto_counts = list(protocols.values())

    user_labels = [u[0] for u in usernames.most_common(7)]
    user_counts = [u[1] for u in usernames.most_common(7)]

    recent_events = events[-15:]
    recent_events.reverse()

    rows = ""
    for ev in recent_events:
        ts = ev.get("timestamp", "")[:19].replace("T", " ")
        proto = ev.get("protocol", "")
        etype = ev.get("event_type", "")
        src = f"{ev.get('src_ip')}:{ev.get('src_port')}"
        dt = ev.get("details", {})
        summary = ", ".join(f"{k}: {v}" for k, v in dt.items() if k not in ("headers", "submitted_data"))
        if "submitted_data" in dt:
            summary += f" creds={dt['submitted_data']}"
        rows += f"""<tr>
            <td style="color:#94a3b8; font-family:monospace;">{ts}</td>
            <td><span class="badge badge-{proto.lower()}">{proto}</span></td>
            <td><code>{etype}</code></td>
            <td style="color:#38bdf8;">{src}</td>
            <td style="color:#cbd5e1; font-size:0.85rem;">{summary}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Defense Honeypot SOC Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #090d16;
            --card: #131b2e;
            --border: #202b46;
            --text: #e2e8f0;
            --accent: #38bdf8;
            --danger: #ef4444;
            --success: #10b981;
            --warn: #f59e0b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ margin: 0; font-size: 1.6rem; color: #f8fafc; display: flex; align-items: center; gap: 10px; }}
        .badge-live {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        .stat-value {{ font-size: 2.2rem; font-weight: 700; color: #fff; margin-top: 5px; }}
        .stat-label {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
        .grid-charts {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media(max-width: 900px) {{ .grid-charts {{ grid-template-columns: 1fr; }} }}
        h3 {{ margin-top: 0; font-size: 1.1rem; color: #cbd5e1; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .badge-ssh {{ background: #1e3a8a; color: #60a5fa; }}
        .badge-http {{ background: #064e3b; color: #34d399; }}
        .badge-ftp {{ background: #78350f; color: #fbbf24; }}
        .mitre-badge {{ background: #312e81; color: #a5b4fc; border: 1px solid #4338ca; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; display: inline-block; margin-right: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ SOC Honeypot Telemetry Dashboard</h1>
            <p style="color:#94a3b8; margin: 5px 0 0 0; font-size: 0.9rem;">Simulated Threat Intelligence & Adversary Deception Analysis</p>
        </div>
        <div>
            <span class="badge-live">● Local Sandbox Mode</span>
        </div>
    </div>

    <div class="grid-stats">
        <div class="card">
            <div class="stat-label">Total Threat Events</div>
            <div class="stat-value" style="color:var(--accent);">{total}</div>
        </div>
        <div class="card">
            <div class="stat-label">Protocols Monitored</div>
            <div class="stat-value" style="color:var(--warn);">{len(protocols)}</div>
        </div>
        <div class="card">
            <div class="stat-label">Credential Attempts</div>
            <div class="stat-value" style="color:var(--danger);">{sum(usernames.values())}</div>
        </div>
        <div class="card">
            <div class="stat-label">Unique Attack Vectors</div>
            <div class="stat-value" style="color:var(--success);">{len(event_types)}</div>
        </div>
    </div>

    <div class="grid-charts">
        <div class="card">
            <h3>Events by Decoy Protocol</h3>
            <canvas id="protoChart" height="200"></canvas>
        </div>
        <div class="card">
            <h3>Top Targeted Usernames</h3>
            <canvas id="userChart" height="200"></canvas>
        </div>
    </div>

    <div class="card" style="margin-bottom: 2rem;">
        <h3>Observed MITRE ATT&CK Techniques</h3>
        <p style="color: #94a3b8; font-size: 0.85rem; margin-top: -5px;">Mapped behaviors detected across active sessions:</p>
        <div style="margin-top: 10px; line-height: 2;">
            <span class="mitre-badge">T1110.001 - Password Guessing</span>
            <span class="mitre-badge">T1110.004 - Credential Stuffing</span>
            <span class="mitre-badge">T1082 - System Information Discovery</span>
            <span class="mitre-badge">T1033 - System Owner/User Discovery</span>
            <span class="mitre-badge">T1105 - Ingress Tool Transfer</span>
            <span class="mitre-badge">T1595.002 - Vulnerability Scanning</span>
        </div>
    </div>

    <div class="card">
        <h3>Live Event Feed (Latest 15 Events)</h3>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Protocol</th>
                    <th>Event Type</th>
                    <th>Source</th>
                    <th>Telemetry Summary</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <script>
        // Protocol Chart
        new Chart(document.getElementById('protoChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(proto_labels)},
                datasets: [{{
                    data: {json.dumps(proto_counts)},
                    backgroundColor: ['#38bdf8', '#34d399', '#fbbf24', '#f87171']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ labels: {{ color: '#cbd5e1' }} }} }}
            }}
        }});

        // Username Chart
        new Chart(document.getElementById('userChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(user_labels)},
                datasets: [{{
                    label: 'Attempts',
                    data: {json.dumps(user_counts)},
                    backgroundColor: '#ef4444'
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }},
                    y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e293b' }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
    </script>
</body>
</html>"""

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    analyze()
