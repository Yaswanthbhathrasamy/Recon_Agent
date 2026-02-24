# 🚀 AI Recon Agent

> An AI-powered, multi-agent reconnaissance and OSINT automation framework built using CrewAI, LangChain, and LangGraph.

---

## 📖 Overview

**AI Recon Agent** is a modular, agent-orchestrated reconnaissance framework designed to automate attack surface discovery and intelligence gathering for web assets.

It combines:

- 🤖 Multi-Agent Collaboration (CrewAI)
- 🧠 LLM-Driven Reasoning (LangChain + OpenAI)
- 🔄 Parallel Workflow Orchestration (LangGraph)
- 📊 Structured Reporting (JSON + PDF)

The system performs structured reconnaissance across network, application, and client-side layers and generates professional security reports.

---

## 🎯 Objectives

- Automate structured web reconnaissance
- Reduce manual enumeration effort
- Map attack surfaces efficiently
- Provide machine-readable and human-readable outputs
- Enable future AI-driven vulnerability prioritization

---

# 🕵️ Reconnaissance Methodology

The framework follows a layered methodology aligned with real-world security assessment workflows.

---

## 1️⃣ Subdomain Enumeration & Live Host Verification

**Purpose:** Expand and validate attack surface.

**Identifies:**
- Discovered subdomains
- Active vs inactive hosts
- Redirected infrastructure
- CDN/WAF-protected services

---

## 2️⃣ Port Scanning & Service Detection

**Purpose:** Detect exposed network services.

**Identifies:**
- Open ports (80, 443, 22, 21, 8080, etc.)
- Running services (SSH, FTP, MySQL, HTTP)
- Service versions
- Potential misconfigurations

---

## 3️⃣ Technology Fingerprinting

**Purpose:** Identify underlying tech stack.

**Detects:**
- Web servers (Apache, Nginx, IIS)
- Backend frameworks (Django, Laravel, Spring)
- CMS platforms
- JavaScript libraries
- Version disclosures

---

## 4️⃣ Directory & File Enumeration

**Purpose:** Discover hidden or sensitive endpoints.

**Common Findings:**
- `/admin`
- `/backup`
- `/.git`
- `/config`
- `/api`
- `/dashboard`
- Debug endpoints
- Exposed configuration files

---

## 5️⃣ JavaScript Reconnaissance

**Purpose:** Analyze client-side logic for hidden attack surface.

**Extracts:**
- Hidden API endpoints
- Internal routes
- Hardcoded API keys
- Access tokens
- Business logic exposure
- WebSocket endpoints

Modern applications often expose critical logic within JavaScript — this stage is essential.

---

## 6️⃣ Parameter Discovery

**Purpose:** Identify input vectors for injection testing.

**Discovers:**
- GET parameters (`?id=`, `?user=`)
- POST body fields
- Hidden parameters
- JSON keys
- Cookie-based inputs

These inputs may lead to:
- SQL Injection
- IDOR
- LFI
- Open Redirect
- SSRF

---

## 7️⃣ Authentication & Access Control Analysis

**Purpose:** Evaluate authorization mechanisms.

**Checks:**
- Admin panel exposure
- Role-based access enforcement
- JWT token structure
- Rate limiting
- Privilege escalation paths

---

# 🧠 Architecture

## 🔹 Agent-Based Design

| Agent | Responsibility |
|-------|---------------|
| Web Recon Agent | Scraping, headers, directory discovery |
| OSINT Agent | WHOIS, DNS, historical data |
| Subdomain Agent | Asset expansion |
| Live Host Agent | Active host verification |
| Vulnerability Agent | Port & service scanning |
| JavaScript Recon Agent | JS endpoint & secret extraction |
| Parameter Discovery Agent | Input surface mapping |
| Report Engine | JSON & PDF generation |
| LangGraph Orchestrator | Parallel workflow execution |

---

## 🔄 Parallel Execution Flow

The system uses **LangGraph** to execute reconnaissance stages concurrently, improving efficiency and fault isolation.
