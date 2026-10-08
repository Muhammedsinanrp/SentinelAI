# 🛡️ CYBERSHIELD X — AI-Assisted SOC & Attack Surface Management

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/Threat%20Intel-MITRE%20ATT%26CK-E65100)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Enterprise-grade, AI-powered Security Operations Center (SOC) & Attack Surface Management (ASM) Platform.**  
> Fuses continuous attack surface discovery, unified vulnerability intelligence, real-time SIEM log correlation, and an autonomous AI Tier-3 Incident Response Commander.

---

## 📐 Architecture Blueprint

```
                         CYBERSHIELD X
                               │
                   ┌───────────▼───────────┐
                   │   Security Dashboard  │
                   └───────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
         Asset Discovery   Vulnerability     SIEM / SOC
              │             Management          │
              │                │                │
         ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
         │Subdomain│      │ Nuclei  │      │  Logs   │
         │DNS      │      │ Nmap    │      │ Syslog  │
         │Cloud    │      │ CVEs    │      │ Wazuh   │
         │Web      │      │ OWASP   │      │ Windows │
         └─────────┘      └─────────┘      └─────────┘
                               │                │
                               └───────┬────────┘
                                       ▼
                               ┌──────────────┐
                               │  AI ANALYST  │
                               │              │
                               │ Correlation  │
                               │ Risk scoring │
                               │ Investigation│
                               │ Remediation  │
                               └──────┬───────┘
                                      ▼
                               ┌──────────────┐
                               │ Reports      │
                               │ Alerts       │
                               │ Tickets      │
                               └──────────────┘
```

---

## 🔥 Core Modules

### 1. 🌐 Attack Surface Management (ASM)
- **Authorized Domain Discovery**: Enter an authorized company domain (`example.com`).
- Discovers subdomains (`api.example.com`, `dev.example.com`, `vpn.example.com`, `mail.example.com`) via DNS, CRT.sh Certificate Transparency, and async brute-force.
- Probes and maps:
  - IP addresses & reverse DNS
  - Full DNS record matrix (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`)
  - Open port discovery & banner grabbing
  - Technology stack identification (Server, Framework, CMS, CDN)
  - TLS / SSL Certificate health & expiration
  - Security headers audit (HSTS, CSP, X-Frame-Options, etc.)

### 2. 🛡️ Unified Vulnerability Management
- Normalizes findings from **Nuclei**, **Nmap NSE**, **OWASP Top 10**, and custom audit rules into a single database schema.
- Automatic **CVSS v3.1** calculation and organizational risk scoring.
- Comprehensive finding cards:
  - **Asset Target**: `api.example.com`
  - **Finding**: SQL Injection in Authentication Endpoint
  - **CVSS**: `9.8` (CRITICAL)
  - **Evidence**: Payload reproduction and response proof
  - **Business Impact**: Unauthorized database access, tenant data exfiltration
  - **Remediation**: Use parameterized queries and ORM prepared statements

### 3. 🚨 Real SOC / SIEM Telemetry & Correlation
- Collects and normalizes logs from:
  - **Linux** (`/var/log/auth.log`, `secure`, `sudo`)
  - **Windows** Security Events (Event ID 4625 Failed Logon, 4624 Successful Logon, 4672 Special Privileges, 4688 Process Creation)
  - **Web Servers** (Nginx / Apache access logs with SQLi & Path Traversal detection)
  - **Wazuh** EDR & Syslog RFC 5424
- Built-in multi-stage correlation engine detects attack chains:
  ```
  Brute Force  ──>  Multiple Failed Logins  ──>  Same Source IP
        │
        └──>  Successful Login  ──>  Privilege Escalation  ──>  CRITICAL ALERT
  ```

### 4. 🧠 Autonomous AI Security Analyst
- Cross-correlates asset context, known vulnerabilities, and live SIEM logs.
- Produces a complete Incident Response Dossier:
  - **Root Cause Analysis**
  - **MITRE ATT&CK Technique Mapping**
  - **Immediate Containment Actions** (firewall blocks, session kills, account freezes)
  - **Eradication & Long-Term Hardening Playbook**
- **Offline Resilient**: Works out-of-the-box using the built-in Heuristic SOC Reasoning Engine, and seamlessly connects to any OpenAI / DeepSeek / Anthropic / Ollama endpoint when `AI_API_KEY` is provided!

### ⏱️ The Signature Feature: Attack Timeline
Reconstructs the full chronological kill-chain step-by-step:
```
12:01:04  Failed SSH login
12:01:08  Failed SSH login
12:01:14  Failed SSH login
12:02:01  Successful login
12:03:22  Privilege escalation
12:04:10  Suspicious command execution
12:05:32  Outbound C2 connection
          ──> AI Incident Summary & Remediation Dossier
```

---

## 📊 Interactive Web Dashboard

Launch the sleek, glassmorphic dark-mode cybersecurity command center:
```bash
python cli.py serve --port 8888
```
Then navigate to: **[http://localhost:8888](http://localhost:8888)**

Features:
- **Executive Overview**: Calculated Org Risk Score (0-100), metric cards, severity meters, and recent incident feed.
- **Attack Surface Explorer**: Scope check input, one-click asset discovery, and service matrix.
- **Vulnerability Tracker**: Filterable vulnerability findings with CVSS scores, proof, and remediation.
- **SIEM / SOC Console**: Live log streaming terminal, correlation alert feed, and log injection simulator.
- **AI Analyst Hub**: Interactive attack timeline builder and executive incident dossiers.

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.10+
- (Optional) Docker & Docker Compose

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Muhammedsinanrp/SentinelAI.git
cd SentinelAI

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
```bash
# Linux / macOS
export AI_API_KEY="your-api-key"
export AI_BASE_URL="https://api.openai.com/v1"   # or local Ollama / vLLM
export AI_MODEL="gpt-4o-mini"

# Windows PowerShell
$env:AI_API_KEY = "your-api-key"
$env:AI_BASE_URL = "https://api.openai.com/v1"
$env:AI_MODEL = "gpt-4o-mini"
```

---

## 💻 CLI Usage

```bash
# Display program scope, rate limits, and system status
python cli.py status

# Verify if a target is authorized under scope policy
python cli.py check-scope httpbin.org
python cli.py check-scope status.example.com

# Execute full Attack Surface discovery & vulnerability probes
python cli.py scan httpbin.org

# Start the Web Command Center
python cli.py serve --port 8888
```

---

## 🐳 Docker Deployment

Run CYBERSHIELD X anywhere with Docker:

```bash
# Build and run with Docker Compose
docker compose up -d

# Access the dashboard at http://localhost:8000
```

---

## 📁 Project Structure

```
.
├── cli.py                             # Root CLI entry point
├── scope.yaml                         # Scope policy & program config
├── requirements.txt                   # Core Python dependencies
├── Dockerfile                         # Container definition
├── docker-compose.yml                 # Multi-container orchestration
└── cybershield/
    ├── app/
    │   ├── main.py                    # FastAPI server & static mounting
    │   ├── config.py                  # Pydantic configuration & env loader
    │   ├── database.py                # Async SQLite/PostgreSQL engine
    │   ├── models/                    # Asset, Vulnerability, Log, Alert models
    │   ├── schemas/                   # Pydantic API schemas
    │   ├── api/                       # REST endpoints (dashboard, asm, vulns, siem, ai)
    │   ├── modules/
    │   │   ├── asm/                   # Subdomain, DNS, TLS, Ports, Scope Gate
    │   │   ├── vuln/                  # OWASP probes, Nuclei/Nmap normalizer, CVSS
    │   │   ├── siem/                  # Ingestion, Sigma-like rules, Correlation engine
    │   │   └── ai_analyst/            # Incident timeline, Context aggregator, LLM analyst
    │   └── static/                    # Glassmorphism dark-mode Web UI
    └── cli.py                         # Rich console CLI commands
```

---

## ⚖️ Authorized Testing & Ethics

CYBERSHIELD X enforces strict target authorization via `scope.yaml` to prevent unauthorized activity. This platform is strictly designed for authorized security assessments, defensive monitoring, and SOC training.

---

## 📄 License

MIT License © 2026 CYBERSHIELD X
