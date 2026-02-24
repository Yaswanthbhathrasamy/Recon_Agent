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

## 🧠 Architecture

- **Web Recon Agent** → Scraping, headers, directory discovery  
- **OSINT Agent** → WHOIS, DNS, subdomains, historical snapshots  
- **Network Agent** → Nmap scanning, port analysis  
- **Vulnerability Agent** → Tech stack fingerprinting, exposure checks  
- **Report Engine** → Structured JSON + PDF generation  
- **LangGraph Orchestrator** → Controls execution workflow  

---

## ✨ Features

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
git clone https://github.com/Yaswanthbhathrasamy/Recon_Agent-.git
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
