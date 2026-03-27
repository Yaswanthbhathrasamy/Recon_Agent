<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Framework-LangGraph-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/Agents-14-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/LLM-OpenAI%20%7C%20Ollama-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />
</p>

<h1 align="center">☠ RECON AGENTS</h1>
<h3 align="center">Autonomous Offensive Reconnaissance Engine</h3>
<p align="center"><em>dev by yashh</em></p>

---

## 🔍 What Is This?

**Recon Agents** is a **14-agent autonomous security reconnaissance framework** that performs end-to-end attack surface mapping, vulnerability pattern detection, and intelligence validation against any target domain.

It operates as a **deterministic, evidence-based validation engine** — not a chatbot. Every finding is backed by structured evidence, deduplicated, classified by severity, and correlated across multiple signals before being reported.

### Key Capabilities

| Capability | Description |
|---|---|
| 🌐 **Subdomain Discovery** | Multi-source enumeration via CT logs (crt.sh), DNS brute-force (80+ prefixes), and subfinder |
| 🔎 **DNS Resolution** | Async resolution of discovered subdomains to IP addresses |
| 🏓 **Live Host Detection** | HTTP/HTTPS probing with status codes and server fingerprinting |
| 🔌 **Port Scanning** | Fast/deep Nmap scans for open ports and services |
| 🛠 **Technology Fingerprinting** | Server headers, X-Powered-By, and tech stack detection |
| 🕷 **URL Crawling** | Depth-2 recursive crawler extracting all endpoints |
| 📜 **JavaScript Analysis** | JS file discovery, API endpoint extraction, secret/token detection |
| 🔑 **Parameter Discovery** | Query/body parameter fuzzing from crawled URLs |
| 🛡 **Header Analysis** | 6 security headers checked (CSP, HSTS, XFO, XCTO, RP, PP) |
| 📂 **Sensitive File Detection** | Probes 15+ paths (.git, .env, .htaccess, wp-config, backups, etc.) |
| ⚡ **Vulnerability Pattern Detection** | Nuclei template matching for known patterns |
| ✅ **Finding Validation** | Reclassifies, prunes false positives, enforces evidence requirements |
| 🔗 **Correlation Analysis** | Multi-signal risk correlation across all agent outputs |
| 🧠 **Final Intelligence** | LLM-powered severity assessment and attack path generation |

---

## 🏗 Architecture

The system has a **dual-layer architecture**:

### Layer 1 — LangGraph Workflow (CrewAI Agents)

Located in `src/workflow/graph.py` and `src/agents/recon_agents.py`. This layer uses **LangGraph** with **CrewAI** agents for LLM-driven reconnaissance:

```
                    ┌─────────────┐
                    │   START     │
                    └──────┬──────┘
         ┌────────────┬────┴────┬────────────┐
         ▼            ▼         ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
   │Web Recon │ │  OSINT   │ │Vuln Scan │ │Subdomain │ ...
   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
        └─────────────┴────────────┴─────────────┘
                          │
                    ┌─────▼─────┐
                    │  Compile  │
                    │  Report   │
                    └─────┬─────┘
                          │
                    ┌─────▼─────┐
                    │    END    │
                    └───────────┘
```

### Layer 2 — Distributed Engine (14 Specialized Agents)

Located in `src/distributed/`. This is the **production pipeline** with phased execution:

```
══════════════════════════════════════════════════════════════════
  PHASE 1 — Parallel Execution (11 agents)
══════════════════════════════════════════════════════════════════
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │ 1. Subdomain    │  │ 2. DNS Resolve  │  │ 3. Live Hosts   │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │ 4. Port Scan    │  │ 5. Tech FP      │  │ 6. URL Crawl    │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │ 7. JS Analysis  │  │ 8. Param Disc.  │  │ 9. Header Check │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
  ┌─────────────────┐  ┌─────────────────┐
  │10. File Detect   │  │11. Vuln Pattern │
  └─────────────────┘  └─────────────────┘
                          │
══════════════════════════════════════════════════════════════════
  PHASE 2 — Sequential Execution (with aggregated metadata)
══════════════════════════════════════════════════════════════════
  ┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐
  │12. Validation   │ ──▶ │13. Correlation  │ ──▶ │14. Final     │
  │   Agent         │     │    Agent        │     │   Intel      │
  └─────────────────┘     └─────────────────┘     └──────────────┘
```

---

## 📁 Project Structure

```
Recon_Agents/
├── main.py                          # Entry point with OpenClaw TUI
├── requirements.txt                 # Python dependencies
├── src/
│   ├── agents/
│   │   └── recon_agents.py          # 7 CrewAI agent definitions
│   ├── core/
│   │   ├── schemas.py               # Pydantic models (16 TaskTypes, findings, reports)
│   │   ├── logging_utils.py         # Structured JSON logging
│   │   ├── cache.py                 # Result caching layer
│   │   └── progress.py              # Progress tracking
│   ├── distributed/
│   │   ├── controller.py            # Orchestrator (phased execution, metadata piping)
│   │   ├── worker_engine.py         # 14 agent handler implementations
│   │   ├── worker_api.py            # FastAPI worker node
│   │   ├── remote_client.py         # Remote worker HTTP client
│   │   └── task_queue.py            # Task distribution queue
│   ├── intel/
│   │   ├── final_analysis.py        # Intelligence engine (dedup, scoring, reporting)
│   │   └── correlation.py           # Multi-signal risk correlation
│   ├── tooling/
│   │   ├── recon_wrappers.py        # CLI tool wrappers (subfinder, httpx, nmap, nuclei)
│   │   └── command_runner.py        # Async subprocess executor
│   ├── tools/
│   │   ├── web_tools.py             # Web scraper, header analyzer
│   │   ├── osint_tools.py           # WHOIS, DNS, Shodan
│   │   ├── network_tools.py         # Nmap, live host checker
│   │   ├── advanced_web_tools.py    # Wappalyzer, subdomain enum, dir brute
│   │   └── misc_recon_tools.py      # SSL info, Wayback Machine
│   ├── workflow/
│   │   ├── graph.py                 # LangGraph state machine
│   │   └── reporting.py             # JSON + PDF report generation
│   └── reports/                     # Generated reports output
└── .env                             # API keys configuration
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure LLM

**OpenAI:**
```bash
echo "OPENAI_API_KEY=sk-your-key" > .env
```

**Ollama (local):**
```bash
ollama pull llama3
```

### 3. Run Interactive Mode

```bash
python main.py
```

This launches the OpenClaw-themed TUI:

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ...
  ◤ Autonomous Offensive Reconnaissance Engine ◢
                                dev by yashh
```

### 4. CLI Mode (Non-Interactive)

```bash
# Full recon+attack pipeline
python main.py example.com --mode recon_attack --scan-type fast \
  --llm-provider ollama --llm-model codeguru:latest --yes

# Recon only
python main.py example.com --mode recon --scan-type deep --yes

# JSON-only output (for piping)
python main.py example.com --mode recon_attack --yes --json-only
```

---

## ⚙️ CLI Flags

| Flag | Values | Default | Description |
|---|---|---|---|
| `--mode` | `recon`, `recon_attack`, `attack` | interactive | Execution mode |
| `--scan-type` | `fast`, `deep` | `fast` | Timeout: 120s (fast) / 300s (deep) |
| `--llm-provider` | `openai`, `ollama` | interactive | LLM backend |
| `--llm-model` | any model name | `gpt-4o` / `llama3` | Model selection |
| `--format` | `json`, `pdf`, `both` | `both` | Report format |
| `--yes` | flag | — | Non-interactive mode |
| `--json-only` | flag | — | Pure JSON output (no TUI) |
| `--run-worker` | flag | — | Start as FastAPI worker node |
| `--verbose` | flag | — | Debug logging |

---

## 🧠 Intelligence Engine

The **Final Intelligence Engine** (`src/intel/final_analysis.py`) is not a simple aggregator. It enforces strict classification logic:

### Classification Rules

| Signal | Classification | Severity |
|---|---|---|
| Missing security headers | **Misconfiguration** (NOT XSS) | Low |
| Exposed `.git` / `.env` | **Misconfiguration** | High |
| Admin endpoint without auth | **Access Control** | High |
| No parameters discovered | Injection claims **dropped** | — |
| No payload executed | Status → **suspected** | — |
| Confidence < 0.55 | Finding **pruned** | — |
| Surface-only signal | **Misconfiguration** | Medium/Low |

### Finding Status

| Status | Meaning |
|---|---|
| `confirmed` | Tested with strong evidence (payload executed, response verified) |
| `suspected` | Strong pattern match but no active exploitation proof |
| `weak_signal` | Incomplete evidence — may be pruned |

### Risk Score Calculation

```
critical  →  any critical finding exists
high      →  ≥2 high OR (≥1 high + ≥3 medium)
medium    →  ≥1 medium finding
low       →  all others
```

---

## 🔗 Correlation Engine

The **Correlation Agent** (`src/intel/correlation.py`) detects multi-signal attack chains:

- **Admin + Exposed Ports**: Admin endpoint + sensitive ports (3306, 6379, etc.) = critical
- **Sensitive Files**: `.git`, `.env`, `debug`, `graphql`, `backup` exposure = high
- **Legacy Tech + Ports**: PHP stack + sensitive ports = elevated injection risk
- **Header Gaps**: Missing CSP + XFO + HSTS combined = medium

---

## 📊 Output Format

Every scan produces a structured `FullScanOutput`:

```json
{
  "meta": { "scan_id", "timestamp", "target", "mode", "scan_type", "llm" },
  "recon": { "subdomains", "alive_hosts", "technologies", "ports" },
  "attack_surface": { "endpoints", "parameters", "files", "headers" },
  "findings": [
    {
      "id": "FIND-A816C7FE",
      "category": "Misconfig",
      "type": "Misconfiguration",
      "severity": "high",
      "confidence": 0.88,
      "status": "suspected",
      "evidence": { "endpoint", "parameter", "payload", "response_snippet" },
      "impact": "...",
      "recommendation": "..."
    }
  ],
  "correlation": [ { "title", "severity", "description", "related_findings" } ],
  "summary": { "total_subdomains", "total_alive", "total_findings", "severity_count", "risk_score" }
}
```

Reports are saved to `src/reports/` in JSON and/or PDF format.

---

## 🖥 Terminal UI

The OpenClaw-themed TUI provides:

- **ASCII banner** with neon green/cyan coloring
- **6-stage interactive wizard** (provider → model → target → mode → vectors → depth)
- **Mission Brief** config summary with skull icons
- **Real-time progress** with animated spinner during agent execution
- **Threat Matrix** table with severity-colored findings
- **Raw Intelligence Dump** for full JSON output
- **`dev by yashh`** branding throughout

---

## 🌐 Distributed Mode

Run as a multi-node scanning cluster:

```bash
# Start worker node
python main.py --run-worker --worker-host 0.0.0.0 --worker-port 8000

# Connect controller to remote worker
python main.py example.com --mode recon_attack --yes \
  --remote-worker-url http://192.168.1.50:8000 \
  --remote-api-key your-secret-key
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `langgraph` | State machine orchestration |
| `crewai` | LLM agent framework |
| `langchain-openai` | OpenAI LLM provider |
| `pydantic` | Data validation and schemas |
| `rich` | Terminal UI rendering |
| `requests` | HTTP client |
| `beautifulsoup4` | HTML parsing for crawling |
| `python-nmap` | Port scanning integration |
| `fpdf2` | PDF report generation |
| `fastapi` / `uvicorn` | Distributed worker API |
| `dnspython` | DNS resolution |
| `shodan` | Shodan threat intelligence |

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>☠ RECON AGENTS</strong><br>
  <em>Autonomous Offensive Reconnaissance Engine</em><br>
  <code>dev by yashh</code>
</p>
