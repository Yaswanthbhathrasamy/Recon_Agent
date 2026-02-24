# AI Recon Agent

**Developed by Yaswanth**

AI Recon Agent is an orchestrator-based reconnaissance tool that uses CrewAI, LangChain, and LangGraph to perform automated intelligence gathering and vulnerability assessment on target domains and IP addresses. 

It provides structured execution steps, allowing individual specialized agents (like Web Recon Specialists, OSINT Analysts, and Vulnerability Scanners) to fetch, process, and combine findings. The results are finally exported as structured JSON and a professional PDF report.

## Features
- **Web Reconnaissance**: Scrape content, retrieve HTTP headers, scan for exposed directories, harvest emails.
- **OSINT Gathering**: Fetch WHOIS data, enumerate subdomains asynchronously, retrieve DNS records, and explore Wayback Machine snapshots.
- **Vulnerability Assessment**: Identify open ports using Nmap, map tech stacks via Wappalyzer, and cross-reference Shodan for known exposures.
- **Automated Workflow**: Orchestrated by LangGraph to dictate an execution flow where agents iteratively gather context.
- **Rich Reporting**: Outputs structured JSON and compiled PDF reports.

## Prerequisites
- Python 3.10+
- `nmap` installed on your system (`sudo apt-get install nmap`)
- OpenAI API Key
- Shodan API Key (optional but recommended for CVE/exposure searches)

## Installation

1. Clone this repository.
2. Initialize a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and fill out your API credentials:
   ```bash
   cp .env.example .env
   ```

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
