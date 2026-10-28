# 🛡️ Cyber Defense Honeypot & Threat Intelligence Sandbox

> **Safety Notice:** This honeypot is designed **strictly for local experimentation, education, and portfolio demonstration**. It is hardcoded to listen only on loopback (`127.0.0.1`) and must **never** be deployed to public or production networks.

A lightweight, zero-external-dependency honeypot system with built-in adversary traffic simulation, structured JSON telemetry logging, an automated analytics dashboard, and SigmaHQ detection rules.

---

## 📐 Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │    Adversary Simulator / Local Test    │
                      │       (simulator/simulate_attacks.py)  │
                      └──────────────────┬─────────────────────┘
                                         │ Loopback Traffic (127.0.0.1)
                                         ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                        HONEYPOT ENGINE (honeypot.py)                   │
   │                                                                        │
   │   [ Port 2222 ] SSH Decoy        -> Captures credentials & shell cmds  │
   │   [ Port 8080 ] HTTP Web Portal  -> Captures web probes & POST logins  │
   │   [ Port 2121 ] FTP Decoy        -> Captures scanner probes & creds    │
   └─────────────────────────────────────┬──────────────────────────────────┘
                                         │ Structured JSONL
                                         ▼
                      ┌────────────────────────────────────────┐
                      │      logs/honeypot_events.json         │
                      └──────────────────┬─────────────────────┘
                                         │
                ┌────────────────────────┴────────────────────────┐
                ▼                                                 ▼
   ┌───────────────────────────┐                     ┌───────────────────────────┐
   │     Analytics Engine      │                     │     SigmaHQ Detections    │
   │ (analytics/analyze_logs)  │                     │       (rules/*.yml)       │
   │             │             │                     │             │             │
   │   Generates SOC Web UI    │                     │  Convertible to Splunk /  │
   │  (analytics/dashboard.html)                     │  Sentinel KQL via pySigma │
   └───────────────────────────┘                     └───────────────────────────┘
```

---

## ✨ Features

- **Multi-Service Decoys:**
  - **SSH / Interactive Shell (Port 2222):** Simulates an Ubuntu server, logs login attempts, and provides a sandboxed shell simulating Linux reconnaissance commands (`whoami`, `id`, `uname -a`, `cat /etc/passwd`, `wget`).
  - **HTTP Admin Gateway (Port 8080):** Serves a fake corporate authentication portal; traps directory fuzzing (`/.env`, `/wp-login.php`, `/phpmyadmin`, `/robots.txt`) and records credential stuffing.
  - **FTP Decoy (Port 2121):** Emulates vsFTPd 3.0.3 banner and records anonymous and brute-force logins.
- **Built-in Attack Simulator (`simulator/simulate_attacks.py`):**
  - Generates realistic adversarial traffic locally against `127.0.0.1` without needing external attacker tools.
- **Structured JSON Telemetry:**
  - Standardized log schema with timestamps, protocols, event types, source IPs, and detailed event metadata.
- **Automated Analytics & SOC Dashboard:**
  - Summarizes top targeted usernames, passwords, commands, and attack vectors.
  - Generates an offline HTML dashboard with Chart.js visualizations.
- **SigmaHQ Detection Rules:**
  - Production-ready Sigma rules mapped to **MITRE ATT&CK** techniques.

---

## 🚀 Quick Start Guide

### Requirements
- Python 3.8+ (No external pip libraries required; uses Python standard library!)

### 1. Launch the Honeypot
Open a terminal and start the listeners:
```bash
python honeypot.py
```
*Output will confirm all three decoy listeners (SSH: 2222, HTTP: 8080, FTP: 2121) are active on `127.0.0.1`.*

### 2. Generate Simulated Adversary Traffic
Open a second terminal and trigger the local attack simulation:
```bash
python simulator/simulate_attacks.py
```
*You will see real-time alerts appear on the honeypot console as attacks are intercepted.*

### 3. Generate Analytics & Open the SOC Dashboard
In your terminal, run:
```bash
python analytics/analyze_logs.py
```
*This parses all captured events and opens an interactive HTML dashboard (`analytics/dashboard.html`) in your browser.*

---

## 🎯 MITRE ATT&CK Coverage

| Technique ID | Technique Name | Decoy Component |
| :--- | :--- | :--- |
| **T1110.001** | Password Guessing | SSH & FTP Decoy Login Handlers |
| **T1110.004** | Credential Stuffing | HTTP `/login` Form Handler |
| **T1082** | System Information Discovery | Sandboxed SSH Shell (`uname -a`) |
| **T1033** | System Owner/User Discovery | Sandboxed SSH Shell (`whoami`, `id`) |
| **T1105** | Ingress Tool Transfer | Sandboxed SSH Shell (`wget`, `curl`) |
| **T1595.002** | Vulnerability / Sensitive Path Scanning | HTTP Request Handler (`/.env`, `/phpmyadmin`) |

---

## 📁 Repository Structure

```text
D:\project\honeypot\
├── config.json                     # Honeypot listener & banner configurations
├── honeypot.py                     # Main server entry point
├── core/
│   ├── logger.py                   # Thread-safe JSON event logger
│   └── services/
│       ├── ssh_honeypot.py         # SSH terminal decoy & fake shell
│       ├── http_honeypot.py        # Web portal & directory trap
│       └── ftp_honeypot.py         # FTP banner & auth decoy
├── simulator/
│   └── simulate_attacks.py         # Local adversary traffic generator
├── analytics/
│   ├── analyze_logs.py             # Telemetry aggregator & report generator
│   └── dashboard.html              # Generated interactive SOC dashboard
├── rules/
│   ├── honeypot_unauthorized_port_access.yml
│   ├── honeypot_credential_bruteforce.yml
│   └── honeypot_web_reconnaissance.yml
└── README.md
```

---

