# 🚀 AI Recon Agent

> AI-powered reconnaissance and OSINT automation framework built using CrewAI, LangChain, and LangGraph.

---

## 👨‍💻 Author
**Yaswanth B**  
AI & Cybersecurity Enthusiast  

---

## 📌 Overview

AI Recon Agent is a modular, agent-orchestrated reconnaissance framework designed to automate intelligence gathering on domains and IP addresses.

The system leverages:
- Multi-agent collaboration (CrewAI)
- Structured execution graph (LangGraph)
- LLM reasoning (LangChain + OpenAI)

It generates structured findings in **JSON format** and professional **PDF reports**.

---

## 🕵️‍♂️ Web Reconnaissance Methodology

This project aligns with a structured methodology to identify potential attack surfaces effectively:

1️⃣ **Subdomain Enumeration & Live Host Checking**
**What is present?**
- Active servers
- Dead/parked domains
- Redirected hosts
- CDN-protected services

2️⃣ **Port Scanning**
**What is present?**
- Open ports (80, 443, 22, 21, 8080, etc.)
- Running services (SSH, FTP, MySQL)
- Service versions
- Misconfigured services

3️⃣ **Technology Detection**
**What is present?**
- Web server (Apache, Nginx, IIS)
- Backend language (PHP, Python, Node, Java)
- Framework (Django, Laravel, Spring)
- CMS (WordPress)
- JS libraries
- Version numbers

4️⃣ **Directory & File Enumeration**
**What is present?**

Hidden endpoints:
- `/admin`
- `/backup`
- `/.git`
- `/config`
- `/api`
- `/dashboard`
- Exposed configuration files
- Old backup files
- Debug endpoints

👉 Direct access to sensitive areas.

5️⃣ **JavaScript Recon**
**What is present?**
- Hidden API endpoints
- Internal routes
- Hardcoded API keys
- Access tokens
- Secret parameters
- Business logic
- WebSocket endpoints

👉 Modern apps expose most logic in JS.

6️⃣ **Parameter Discovery**
**What is present?**
- GET parameters (`?id=`)
- POST parameters
- Hidden parameters
- JSON request fields
- Cookie-based parameters

👉 These may lead to:
- SQL Injection
- IDOR
- LFI
- Open Redirect
- SSRF

7️⃣ **Authentication & Access Control Testing**
Verifying authorization mechanisms to detect broken access control and privilege escalation vulnerabilities.

---

## 🧠 Architecture

- **Web Recon Agent** → Scraping, headers, directory discovery, SSL info  
- **OSINT Agent** → WHOIS, DNS, historical snapshots  
- **Subdomain Agent** → Comprehensive subdomain enumeration  
- **Live Host Agent** → ICMP/Ping checks, WAF/CDN detection, active services  
- **Vulnerability Agent** → Nmap scanning, port analysis, threat exposure checks  
- **JavaScript Recon Agent** → API key hunting, hidden endpoint exposure  
- **Parameter Discovery Agent** → Fuzzing GET/POST variables for IDOR/SQLi  
- **Report Engine** → Structured JSON + PDF generation  
- **LangGraph Orchestrator** → Controls parallel execution workflow  

---

## ✨ Features

✔ Parallel Agent orchestration (LangGraph)  
✔ Web content scraping  
✔ HTTP header analysis  
✔ Subdomain enumeration  
✔ WHOIS & DNS records  
✔ Wayback historical data  
✔ Open port scanning (Nmap)  
✔ Technology fingerprinting  
✔ Structured JSON output  
✔ Automated PDF reporting  

---

## 🛠 Tech Stack

- Python 3.10+
- CrewAI
- LangChain
- LangGraph
- Requests
- BeautifulSoup
- Python-WHOIS
- Nmap
- ReportLab
- OpenAI API

---

## 📦 Installation

```bash
git clone https://github.com/Yaswanthbhathrasamy/Recon_Agent.git
cd Recon_Agents

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt


## Usage

Simply run `main.py` pointing to a target domain or URL.

```bash
python main.py example.com
```

### Options
- `--format`: Set to `json`, `pdf`, or `both` (default is `both`).
- `--verbose`: Enable verbose logging to see agent actions.

Example:
```bash
python main.py example.com --format pdf --verbose
```

### Reports
Results will be saved in the `src/reports/` directory with a timestamp.
