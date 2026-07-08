<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Agents-18-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Orchestration-Autonomous%20%7C%20Pipeline-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/LLM-Claude%20%7C%20GPT%20%7C%20Gemini%20%7C%20Ollama%20%2B-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />
</p>

<h1 align="center">☠ RECON AGENTS</h1>
<h3 align="center">Autonomous Offensive Reconnaissance & VAPT Engine</h3>
<p align="center"><em>dev by yashh</em></p>

---

## 🔍 What Is This?

**Recon Agents** is an **18-agent autonomous security engine** that performs end-to-end attack surface mapping, **active surface-level exploitation testing (SQLi, XSS, open redirect)**, **API reconnaissance and attacking**, and LLM-driven intelligence against a single authorized target.

It runs in one of two orchestration modes:

- **🤖 Autonomous agent** — an LLM drives a perceive → decide → act loop, choosing which tools to run next based on what it has found, until it decides the assessment is complete.
- **⚙️ Deterministic pipeline** — a fixed recon → attack → post-processing flow (the fallback when no LLM is configured).

Every finding is backed by structured evidence, deduplicated, classified by severity, correlated across signals, and — when an LLM is configured — reviewed and narrated with attack-path synthesis.

> ⚠️ **Authorized use only.** The active testing agents send real payloads (SQLi/XSS probes, API requests). They are single-target, non-destructive (detection, not exploitation), and request-budgeted — but you must only run them against systems you are authorized to test.

### Key Capabilities

| Capability | Description |
|---|---|
| 🌐 **Subdomain Discovery** | CT logs (crt.sh), DNS brute-force (110+ prefixes), subfinder |
| 🔎 **DNS & Live Hosts** | Async resolution + HTTP/HTTPS probing with fingerprinting |
| 🔌 **Port Scanning** | Fast/deep Nmap scans for open ports and services |
| 🛠 **Tech Fingerprinting** | Server headers, X-Powered-By, tech-stack detection |
| 🕷 **Crawling & JS Analysis** | Depth-2 crawler, JS endpoint/secret extraction |
| 🔑 **Parameter Discovery** | Query/body parameter fuzzing from response differentials |
| 🛡 **Header & File Checks** | 6 security headers + 15+ sensitive path probes (.git, .env…) |
| ⚡ **Vulnerability Patterns** | Nuclei template matching |
| 💉 **SQL Injection Testing** | Active error-based + boolean-based detection |
| 🧬 **XSS & Open Redirect** | Reflected-XSS (unencoded reflection) + redirect probing |
| 🔗 **API Reconnaissance** | OpenAPI/Swagger discovery, REST roots, GraphQL introspection |
| 🎯 **API Attacking** | Broken-auth, BOLA/IDOR indicators, API path-parameter injection |
| ✅ **Validation & Correlation** | Reclassify, prune false positives, multi-signal attack chains |
| 🧠 **LLM Intelligence** | Executive summary, attack-path synthesis, severity review |
| 🤖 **Autonomous Planning** | LLM decides which tools to run and when |

---

## 🤖 LLM Providers

The engine is **provider-agnostic** — a single registry (`src/llm/registry.py`) drives the wizard's `provider → API key → model` selection. Adding a backend is one entry.

| Provider | Backend | Notes |
|---|---|---|
| **Anthropic (Claude)** | Official `anthropic` SDK | Default `claude-opus-4-8`; strongest reasoning for severity & attack paths |
| **OpenAI (GPT)** | Chat Completions API | `gpt-4o` and family |
| **Google (Gemini)** | Generative Language REST | `gemini-2.0-flash`, `1.5-pro/flash` |
| **Groq** | OpenAI-compatible | Fast OSS models (Llama, Mixtral) |
| **OpenRouter** | OpenAI-compatible | Access to many hosted models |
| **Ollama** | Local HTTP, no key | Auto-lists your pulled models; runs offline |
| **None** | Deterministic rules | No LLM — rule engine only |

The LLM is used for three things: **attack focus planning**, **autonomous tool selection**, and the **final intelligence brief** (executive summary + attack paths). With `None`, all three fall back to deterministic behaviour and scans still run fully.

---

## 🏗 Architecture

The production engine lives in `src/distributed/` and executes in three logical phases. In **autonomous mode** the LLM sequences the recon + attack tools itself; in **pipeline mode** they run in the fixed order below.

```
══════════════════════════════════════════════════════════════════
  PHASE 1 — Recon  (parallel)
══════════════════════════════════════════════════════════════════
  subdomain · dns · live-hosts · ports · tech · crawl · js ·
  params · headers · sensitive-files · nuclei
                          │
        ┌─────────────────┴─────────────────┐
        │   🤖 LLM attack-focus planner      │   (picks high-value targets)
        └─────────────────┬─────────────────┘
══════════════════════════════════════════════════════════════════
  PHASE 2 — Active Testing  (sequential)
══════════════════════════════════════════════════════════════════
  api_discovery → sqli_testing → xss_testing → api_attack_surface
                          │
══════════════════════════════════════════════════════════════════
  PHASE 3 — Post-processing  (sequential)
══════════════════════════════════════════════════════════════════
  finding_validation → correlation_analysis → final_intelligence
                          │
                    ┌─────▼─────┐
                    │  Report   │  JSON + PDF
                    └───────────┘
```

**Autonomous mode** replaces phases 1–2 with an agent loop: each step the LLM sees the current findings/surface and the remaining tools, then chooses the next tool(s) to run (with reasoning) or finishes. Phase 3 always runs at the end. Every decision is recorded in `agent_trace` and shown live in the TUI.

---

## 📁 Project Structure

```
Recon_Agents/
├── main.py                          # Entry point + OpenClaw TUI
├── src/
│   ├── core/schemas.py              # Pydantic models (task types, findings, agent trace)
│   ├── distributed/
│   │   ├── controller.py            # Orchestrator (pipeline + autonomous loop)
│   │   ├── worker_engine.py         # 18 agent handler implementations
│   │   └── worker_api.py            # FastAPI worker node
│   ├── attacks/                     # Active surface + API testing
│   │   ├── http_probe.py            # Budgeted, injected-fetch HTTP primitive
│   │   ├── injection.py             # SQLi / XSS / open-redirect testers
│   │   ├── api_recon.py             # OpenAPI/Swagger + GraphQL discovery
│   │   └── api_attack.py            # Broken-auth, BOLA/IDOR, API injection
│   ├── llm/                         # Provider-agnostic LLM layer
│   │   ├── registry.py              # Provider catalog (wizard-driven)
│   │   ├── clients.py               # Anthropic / OpenAI-compat / Gemini / Ollama
│   │   ├── agent.py                 # Autonomous decision loop
│   │   ├── planner.py               # Attack-focus planning
│   │   └── enrich.py                # Final intelligence brief
│   ├── intel/final_analysis.py      # Intelligence engine (dedup, scoring, enrichment)
│   ├── intel/correlation.py         # Multi-signal risk correlation
│   └── reports/                     # Generated reports output (gitignored)
└── .recon_llm_config.json           # LLM config (gitignored — holds keys)
```

---

## 🚀 Quick Start

### 1. Install
```bash
pip install -r requirements.txt
```
External CLIs used by some agents (optional but recommended): `subfinder`, `httpx`, `nmap`, `nuclei`.

### 2. Configure an LLM (optional)
Run `python main.py` and pick a provider in the wizard, or pass it on the CLI. Keys are stored in `.recon_llm_config.json` (gitignored). With no LLM, use `--llm-provider none`.

### 3. Run — interactive
```bash
python main.py
```
The OpenClaw wizard walks you through: **provider → API key → model → target → mode → vectors → depth → autonomy**.

### 4. Run — non-interactive
```bash
# Autonomous agent, full recon + attack, Claude
python main.py example.com --mode recon_attack --agentic \
  --llm-provider anthropic --llm-model claude-opus-4-8 --api-key sk-ant-... --yes

# Deterministic pipeline, deep scan, local Ollama
python main.py example.com --mode recon_attack --scan-type deep \
  --llm-provider ollama --llm-model llama3 --yes

# Recon only, no LLM
python main.py example.com --mode recon --llm-provider none --yes
```

---

## ⚙️ CLI Flags

| Flag | Values | Default | Description |
|---|---|---|---|
| `--mode` | `recon`, `recon_attack`, `attack` | interactive | Execution mode |
| `--agentic` | flag | off | Autonomous LLM-driven tool selection |
| `--scan-type` | `fast`, `deep` | `fast` | Timeout: 120s / 300s |
| `--llm-provider` | `anthropic`, `openai`, `gemini`, `groq`, `openrouter`, `ollama`, `none` | interactive | LLM backend |
| `--llm-model` | any model id | provider default | Model selection |
| `--api-key` | string | — | API key for the chosen provider |
| `--categories` | `Injection,XSS,Auth,...` | all | Attack vector filter |
| `--format` | `json`, `pdf`, `both` | `both` | Report format |
| `--yes` | flag | — | Non-interactive |
| `--json-only` | flag | — | Pure JSON output (no TUI) |
| `--run-worker` | flag | — | Start as a FastAPI worker node |

---

## 🧠 Intelligence Engine

`src/intel/final_analysis.py` is a deterministic classifier **augmented** by the LLM — the rule engine always owns the findings; the LLM adds narrative and attack-path synthesis on top.

### Classification rules
| Signal | Classification | Severity |
|---|---|---|
| Missing security headers | Misconfiguration (not XSS) | Low |
| Exposed `.git` / `.env` | Misconfiguration | High |
| SQL error on quote payload | Injection (error-based) | High |
| Unencoded payload reflection | XSS (reflected) | High |
| GraphQL introspection enabled | Advanced | High |
| Sibling object IDs differ | Access Control (BOLA/IDOR) | Medium |
| Confidence < 0.55 & unconfirmed | Finding pruned | — |

### LLM output (`intelligence` block)
- **Executive summary** — factual, evidence-grounded
- **Attack paths** — multi-step chains across observed signals
- **Severity reviews** — advisory re-rating with reasons

`engine` records which model produced it (e.g. `anthropic:claude-opus-4-8`) or `deterministic`.

---

## 📊 Output Format

```json
{
  "meta":         { "scan_id", "timestamp", "target", "mode", "scan_type", "llm" },
  "recon":        { "subdomains", "alive_hosts", "technologies", "ports" },
  "attack_surface": { "endpoints", "parameters", "files", "headers" },
  "findings":     [ { "id", "category", "type", "severity", "confidence", "status",
                      "evidence": { "endpoint", "parameter", "payload", "response_snippet" },
                      "impact", "recommendation" } ],
  "correlation":  [ { "title", "severity", "description", "related_findings" } ],
  "intelligence": { "engine", "executive_summary", "attack_paths", "severity_reviews" },
  "agent_trace":  [ { "step", "thought", "action", "tasks", "reason" } ],
  "summary":      { "total_findings", "severity_count", "risk_score" }
}
```

Reports are written to `src/reports/` (gitignored) as JSON and/or PDF.

---

## 🖥 Terminal UI (OpenClaw)

- ASCII banner with neon green/cyan theming
- 8-stage wizard: provider → key → model → target → mode → vectors → depth → autonomy
- **Autonomous Agent Log** — live per-step decisions (thought → tools → reason)
- **Threat Matrix** — severity-colored findings table
- **Intelligence Brief** — LLM executive summary + attack paths
- Raw JSON intelligence dump

---

## 🌐 Distributed Mode

```bash
# Worker node
python main.py --run-worker --worker-host 0.0.0.0 --worker-port 8000

# Controller → remote worker
python main.py example.com --mode recon_attack --yes \
  --remote-worker-url http://192.168.1.50:8000 --remote-api-key your-secret-key
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `anthropic` | Claude LLM provider |
| `pydantic` | Data validation and schemas |
| `rich` | Terminal UI rendering |
| `requests` / `httpx` | HTTP clients (recon + active testing) |
| `beautifulsoup4` | HTML parsing for crawling |
| `python-nmap` | Port scanning |
| `dnspython` | DNS resolution |
| `fpdf2` | PDF report generation |
| `fastapi` / `uvicorn` | Distributed worker API |
| `shodan` | Threat intelligence (optional) |

The `src/attacks/` and `src/llm/` modules use only the standard library plus `requests` / the `anthropic` SDK, and every attack tester takes an injected `fetch`, so the logic is unit-testable offline.

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>☠ RECON AGENTS</strong><br>
  <em>Autonomous Offensive Reconnaissance & VAPT Engine</em><br>
  <code>dev by yashh</code>
</p>
