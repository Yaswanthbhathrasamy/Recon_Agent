import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import List

import uvicorn
from dotenv import load_dotenv

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.table import Table
from rich.theme import Theme
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align

# ── OpenClaw Dark Theme ──────────────────────────────────────────────
_THEME = Theme({
    "accent": "bold bright_green",
    "accent2": "bold bright_cyan",
    "danger": "bold bright_red",
    "muted": "dim white",
    "skull": "bold red",
    "circuit": "dim green",
    "highlight": "bold yellow",
    "brand": "bold bright_magenta",
})
console = Console(theme=_THEME)

_BANNER = r"""
[bright_green]  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bright_green]
  [bright_cyan]█████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗
  ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝
  ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗
  ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
  ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝[/bright_cyan] [dim bright_red]v2.0[/dim bright_red]
  [dim bright_red]◤ Autonomous Offensive Reconnaissance Engine ◢[/dim bright_red]
  [dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
  [bright_magenta]                              dev by yashh[/bright_magenta]
"""


load_dotenv()

from src.core.logging_utils import configure_logging
from src.core.schemas import AttackCategory, DecisionEngineOutput, DecisionFinding, ModeType, ScanType
from src.distributed.controller import ReconController
from src.intel.final_analysis import finalize_security_insights
from src.llm import PROVIDERS, build_client, get_provider, list_providers
from src.llm.base import LLMError
from src.workflow.reporting import generate_json_report, generate_pdf_report

import requests as _requests


COLOR_ENABLED = False
CONFIG_PATH = Path(".recon_llm_config.json")

CATEGORY_OPTIONS: list[AttackCategory] = [
    "Injection",
    "XSS",
    "Auth",
    "Access Control",
    "Misconfiguration",
    "Web Attacks",
    "Advanced",
]


def _panel_title(title: str) -> None:
    console.print(Panel(
        f"[accent]{title}[/accent]",
        expand=False,
        border_style="bright_green",
        padding=(0, 2),
    ))


def _step_title(step_no: int, title: str) -> None:
    console.print(f"\n  [bright_red]▸[/bright_red] [accent]STAGE {step_no:02d}[/accent] [dim]│[/dim] [bold white]{title}[/bold white]")


def _kv(label: str, value: str) -> None:
    console.print(f"    [dim]{label:<16}[/dim] [bright_green]→[/bright_green] [bright_cyan]{value}[/bright_cyan]")


def _print_header(target: str):
    console.print(_BANNER)
    inner = (
        f"  [bright_red]☠[/bright_red]  [accent]TARGET ACQUIRED[/accent]  [bright_red]☠[/bright_red]\n"
        f"  [dim]┌─────────────────────────────────────┐[/dim]\n"
        f"  [dim]│[/dim] [bright_cyan]{target:^35}[/bright_cyan] [dim]│[/dim]\n"
        f"  [dim]└─────────────────────────────────────┘[/dim]\n"
        f"  [dim bright_green]▸ Initializing Reconnaissance & Vulnerability Engine...[/dim bright_green]"
    )
    console.print(Panel(
        inner,
        border_style="bright_red",
        title="[bold bright_green][ SYSTEM ONLINE ][/bold bright_green]",
        subtitle="[dim]encrypted channel ● active[/dim]",
        expand=False,
        padding=(0, 1),
    ))

def _safe_scan_id(value: str | None) -> str:
    if value:
        return value
    return datetime.now(timezone.utc).strftime("scan_%Y%m%d_%H%M%S")


def _export_json_if_requested(path_arg: str | None, report_data: dict) -> None:
    if not path_arg:
        return
    output_path = Path(path_arg)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(__import__("json").dumps(report_data, indent=2), encoding="utf-8")


def _result_by_task(final_report: dict, task_name: str) -> dict:
    for item in final_report.get("task_results", []):
        if item.get("task_type") == task_name:
            return item
    return {}


def _extract_ports_from_task(task_result: dict) -> list[int]:
    data = task_result.get("data", {})
    return sorted(item.get("port") for item in data.get("open_ports", []) if isinstance(item.get("port"), int))


def _extract_ports_detailed(task_result: dict, target: str) -> list[dict]:
    data = task_result.get("data", {})
    out: list[dict] = []
    for item in data.get("open_ports", []):
        if not isinstance(item, dict) or not isinstance(item.get("port"), int):
            continue
        out.append(
            {
                "host": str(item.get("host", target)),
                "port": int(item["port"]),
                "service": str(item.get("service", "")),
            }
        )
    return sorted(out, key=lambda x: x["port"])


def _extract_tech_from_task(task_result: dict) -> list[str]:
    data = task_result.get("data", {})
    values = [data.get("server"), data.get("x_powered_by")]
    return [v for v in values if v and str(v).lower() != "unknown"]


def _extract_subdomains(task_result: dict) -> list[str]:
    return list(task_result.get("data", {}).get("subdomains", []) or [])


def _extract_live_hosts(task_result: dict) -> list[str]:
    hosts = []
    for item in task_result.get("data", {}).get("live_hosts", []):
        if isinstance(item, dict) and item.get("url"):
            hosts.append(item["url"])
    return hosts


def _is_valid_domain_or_url(value: str) -> bool:
    if not value or not value.strip():
        return False
    raw = value.strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    if len(raw) > 253:
        return False
    pattern = r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$"
    return bool(re.match(pattern, raw))


def _validate_openai_key(api_key: str) -> bool:
    return bool(api_key) and api_key.startswith("sk-")


def _select(prompt_text: str, options: list[str], default: int = 1) -> str:
    if prompt_text:
        console.print(f"    [accent2]{prompt_text}[/accent2]")

    for idx, option in enumerate(options, start=1):
        if idx == default:
            console.print(f"    [bright_green] ❯ [{idx}][/bright_green] [bold white]{option}[/bold white]")
        else:
            console.print(f"    [dim]   [{idx}][/dim] [dim]{option}[/dim]")

    choices = [str(i) for i in range(1, len(options) + 1)]
    raw = Prompt.ask("    [bright_red]⟫[/bright_red] [dim]select[/dim]", choices=choices, default=str(default), show_choices=False)

    idx = int(raw)
    return options[idx - 1]


def _parse_categories(raw: str) -> List[AttackCategory]:
    if not raw.strip():
        return CATEGORY_OPTIONS.copy()
    selected: list[AttackCategory] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            idx = int(token)
            if 1 <= idx <= len(CATEGORY_OPTIONS):
                selected.append(CATEGORY_OPTIONS[idx - 1])
        except ValueError:
            if token in CATEGORY_OPTIONS:
                selected.append(token)
    return selected or CATEGORY_OPTIONS.copy()


def _persist_llm_config(provider: str, model: str, api_key: str | None = None) -> None:
    payload = {
        "provider": provider,
        "model": model,
        "api_key": api_key or "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _list_ollama_models() -> list[str]:
    # Try HTTP API first (http://localhost:11434/api/tags)
    try:
        resp = _requests.get("http://localhost:11434/api/tags", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = [m["name"] for m in data.get("models", []) if m.get("name")]
            if models:
                return models
    except Exception:
        pass

    # Fallback to CLI
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0:
        return []

    models = []
    for line in result.stdout.splitlines()[1:]:
        row = line.strip()
        if not row:
            continue
        model_name = row.split()[0]
        if model_name:
            models.append(model_name)
    return models


def _category_from_type(finding_type: str) -> AttackCategory:
    mapping = {
        "Injection": "Injection",
        "XSS": "XSS",
        "Auth": "Auth",
        "Access Control": "Access Control",
        "Misconfiguration": "Misconfiguration",
        "Web Attacks": "Web Attacks",
        "Advanced": "Advanced",
    }
    return mapping.get(finding_type, "Advanced")


def _build_decision_output(final_report: dict, categories: List[AttackCategory]) -> DecisionEngineOutput:
    subdomains = _extract_subdomains(_result_by_task(final_report, "subdomain_enumeration"))
    alive_hosts = _extract_live_hosts(_result_by_task(final_report, "live_host_detection"))

    attack_surface = []
    tech = _result_by_task(final_report, "technology_fingerprinting")
    attack_surface.extend(tech.get("data", {}).get("interesting_paths", []))
    endpoints = _result_by_task(final_report, "endpoint_discovery")
    attack_surface.extend(endpoints.get("data", {}).get("suspicious_endpoints", []))
    ports = _extract_ports_from_task(_result_by_task(final_report, "port_scan"))
    attack_surface.extend([f"port:{p}" for p in ports])

    findings: list[DecisionFinding] = []
    mode = str(final_report.get("mode", "recon"))
    attack_focus_types = {"Injection", "XSS", "Auth", "Access Control", "Web Attacks", "Advanced", "Misconfiguration"}

    for task_item in final_report.get("task_results", []):
        for finding in task_item.get("findings", []):
            finding_type = str(finding.get("type", "Unknown"))
            cat = _category_from_type(finding_type)

            if mode != "recon" and categories and cat not in categories:
                continue

            if mode == "attack" and finding_type not in attack_focus_types:
                continue

            status = str(finding.get("state", "suspected")).lower()
            if mode == "recon_attack":
                status = "suspected"

            findings.append(
                DecisionFinding(
                    type=finding_type,
                    endpoint=str(finding.get("endpoint", "")),
                    severity=str(finding.get("severity", "low")).lower(),
                    confidence=float(finding.get("confidence", 0.5)),
                    status=status,
                    description=str(finding.get("description", "")),
                )
            )

    if mode != "attack":
        for insight in final_report.get("insights", []):
            findings.append(
                DecisionFinding(
                    type="Correlated Risk",
                    endpoint="multi-signal",
                    severity=str(insight.get("severity", "medium")).lower(),
                    confidence=0.9,
                    status="suspected",
                    description=str(insight.get("rationale", "")),
                )
            )

    if mode == "recon":
        findings = []

    return DecisionEngineOutput(
        target=str(final_report.get("target", "")),
        mode=str(final_report.get("mode", "recon")),
        subdomains=sorted(set(subdomains)),
        alive_hosts=sorted(set(alive_hosts)),
        attack_surface=sorted(set(str(x) for x in attack_surface if x)),
        findings=findings,
    )


def _collect_preliminary_findings(final_report: dict, categories: List[AttackCategory]) -> list[dict]:
    mode = str(final_report.get("mode", "recon"))
    attack_focus_types = {"Injection", "XSS", "Auth", "Access Control", "Web Attacks", "Advanced", "Misconfiguration"}
    out: list[dict] = []

    for task_item in final_report.get("task_results", []):
        for finding in task_item.get("findings", []):
            finding_type = str(finding.get("type", "Unknown"))
            cat = _category_from_type(finding_type)

            if mode != "recon" and categories and cat not in categories:
                continue
            if mode == "attack" and finding_type not in attack_focus_types:
                continue

            status = str(finding.get("state", "suspected")).lower()
            if mode == "recon_attack":
                status = "suspected"

            out.append(
                {
                    "type": finding_type,
                    "endpoint": str(finding.get("endpoint", "")),
                    "severity": str(finding.get("severity", "low")).lower(),
                    "confidence": float(finding.get("confidence", 0.5)),
                    "status": status,
                    "description": str(finding.get("description", "")),
                    "evidence": finding.get("evidence", {}),
                }
            )

    if mode == "recon":
        return []

    return out


def _choose_llm(args) -> tuple[str, str, str | None]:
    """Registry-driven backend selection: provider -> API key -> model.

    Every provider in ``src.llm.PROVIDERS`` is offered; adding a backend there
    makes it appear here automatically.
    """
    # ── STAGE 01: LLM Provider ───────────────────────────────────────
    _step_title(1, "Intelligence Backend")
    specs = list_providers()
    labels = [s.label for s in specs]
    default_idx = 1
    if args.llm_provider:
        for i, s in enumerate(specs, start=1):
            if s.id == args.llm_provider:
                default_idx = i
                break
    chosen_label = _select("select an LLM provider:", labels, default=default_idx)
    spec = specs[labels.index(chosen_label)]

    # API key (only if the provider needs one)
    api_key: str | None = None
    if spec.requires_api_key:
        _step_title(2, f"{spec.label.strip()} — API Key")
        env_key = os.environ.get(spec.api_key_env or "", "") if spec.api_key_env else ""
        api_key = args.api_key or env_key or Prompt.ask(
            f"    [bright_red]⟫[/bright_red] [dim]api key [{spec.api_key_hint}][/dim]",
            password=True,
        )
        if not api_key or not api_key.strip():
            console.print("    [bright_red]✘ FATAL:[/bright_red] An API key is required for this provider.")
            sys.exit(1)
        if spec.api_key_env:
            os.environ[spec.api_key_env] = api_key

    # Model
    _step_title(3, f"{spec.label.strip()} — Model")
    models = spec.available_models(api_key)
    if args.llm_model:
        model = args.llm_model
        console.print(f"    [dim]model →[/dim] [bright_cyan]{model}[/bright_cyan]")
    elif models:
        default_model_idx = models.index(spec.default_model) + 1 if spec.default_model in models else 1
        model = _select("select model:", models, default=default_model_idx)
    else:
        model = spec.default_model

    _persist_llm_config(provider=spec.id, model=model, api_key=api_key)
    return spec.id, model, api_key


def _interactive_flow(args) -> tuple[str, ModeType, List[AttackCategory], ScanType, str, str, str | None]:
    console.clear()
    console.print(_BANNER)
    console.print(Panel(
        "[accent]SYSTEM INITIALIZATION[/accent]  [dim]●  secure channel established[/dim]",
        border_style="bright_green",
        expand=False,
        padding=(0, 2),
    ))

    # ── STAGES 01-03: LLM backend (provider -> API key -> model) ─────
    provider_id, model, api_key = _choose_llm(args)

    # ── STAGE 04: Target ─────────────────────────────────────────────
    _step_title(4, "Target Acquisition")
    target = args.target or Prompt.ask("    [bright_red]⟫[/bright_red] [dim]target[/dim]")
    if not _is_valid_domain_or_url(target):
        console.print("    [bright_red]✘ FATAL:[/bright_red] Invalid target domain format.")
        sys.exit(1)
    console.print(f"    [dim]locked on →[/dim] [bright_cyan]{target}[/bright_cyan]")

    # ── STAGE 05: Mode ───────────────────────────────────────────────
    _step_title(5, "Operation Mode")
    mode_label = _select(
        "",
        [
            "Recon Only        ⟨surface mapping⟩",
            "Recon + Attack    ⟨full pipeline⟩",
            "Attack Only       ⟨vuln analysis⟩",
        ],
    )
    mode_map = {
        "Recon Only        ⟨surface mapping⟩": "recon",
        "Recon + Attack    ⟨full pipeline⟩": "recon_attack",
        "Attack Only       ⟨vuln analysis⟩": "attack",
    }
    mode: ModeType = mode_map[mode_label]

    # ── STAGE 05: Categories ─────────────────────────────────────────
    categories: List[AttackCategory] = []
    if mode != "recon":
        _step_title(6, "Attack Vector Selection")
        console.print("    [dim]comma-separated indexes · blank = all vectors[/dim]")
        for idx, name in enumerate(CATEGORY_OPTIONS, start=1):
            console.print(f"    [dim]  [{idx}][/dim] [bright_green]{name}[/bright_green]")
        raw = Prompt.ask("    [bright_red]⟫[/bright_red] [dim]vectors[/dim]", default="")
        categories = _parse_categories(raw)

    # ── STAGE 07: Scan Type ──────────────────────────────────────────
    _step_title(7, "Scan Depth")
    scan_choice = _select("", ["Fast  ⟨120s timeout⟩", "Deep  ⟨300s timeout⟩"])
    scan_type: ScanType = "deep" if scan_choice.startswith("Deep") else "fast"

    # ── STAGE 08: Autonomy ───────────────────────────────────────────
    _step_title(8, "Orchestration")
    if provider_id == "none":
        args.agentic = False
        console.print("    [dim]autonomous mode needs an LLM · using deterministic pipeline[/dim]")
    else:
        args.agentic = Confirm.ask(
            "    [bright_red]⟫[/bright_red] [accent]Autonomous agent?[/accent] [dim](LLM chooses tools dynamically)[/dim]",
            default=False,
        )

    # ── Config Summary ───────────────────────────────────────────────
    console.print()
    table = Table(
        title="[bright_red]☠[/bright_red] [accent]MISSION BRIEF[/accent] [bright_red]☠[/bright_red]",
        border_style="bright_green",
        show_header=False,
        padding=(0, 2),
        title_style="bold",
    )
    table.add_column("Key", style="dim", min_width=14)
    table.add_column("Value", style="bright_cyan bold")
    table.add_row("[bright_green]BACKEND[/bright_green]", f"{provider_id} ⟨{model}⟩")
    table.add_row("[bright_green]TARGET[/bright_green]", target)
    table.add_row("[bright_green]MODE[/bright_green]", mode)
    table.add_row("[bright_green]VECTORS[/bright_green]", ", ".join(categories) if categories else "ALL")
    table.add_row("[bright_green]DEPTH[/bright_green]", scan_type.upper())
    table.add_row("[bright_green]ORCHESTRATION[/bright_green]", "AUTONOMOUS AGENT" if args.agentic else "DETERMINISTIC PIPELINE")
    console.print(table)
    console.print()

    if not Confirm.ask("  [bright_red]⟫[/bright_red] [accent]Deploy agents?[/accent]"):
        console.print("  [bright_red]✘ ABORTED[/bright_red] [dim]— no agents deployed[/dim]")
        sys.exit(0)

    return target, mode, categories, scan_type, provider_id, model, api_key


def main():
    parser = argparse.ArgumentParser(
        description="AI Recon Agent - Distributed Recon & VAPT Pipeline"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target domain or URL (e.g., example.com or https://example.com)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "pdf", "both"],
        default="both",
        help="Output format for generated reports (default: both)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output"
    )
    parser.add_argument("--scan-id", help="Optional scan identifier for distributed tracking")
    parser.add_argument("--export-json", help="Optional path to export strict structured JSON report")
    parser.add_argument("--remote-worker-url", help="Remote worker FastAPI URL (e.g., http://192.168.1.50:8000)")
    parser.add_argument("--remote-api-key", help="Remote worker API key")
    parser.add_argument("--mode", choices=["recon", "recon_attack", "attack"], help="Execution mode")
    parser.add_argument("--categories", help="Comma-separated categories, e.g. Injection,XSS,Auth")
    parser.add_argument("--scan-type", choices=["fast", "deep"], help="Scan depth")
    parser.add_argument("--llm-provider", choices=list(PROVIDERS.keys()), help="LLM provider")
    parser.add_argument("--llm-model", help="LLM model name")
    parser.add_argument("--api-key", help="API key for OpenAI provider")
    parser.add_argument("--agentic", action="store_true", help="Autonomous LLM-driven agent loop (dynamically chooses which tools to run)")
    parser.add_argument("--yes", action="store_true", help="Run non-interactively with provided flags")
    parser.add_argument("--json-only", action="store_true", help="Print strict JSON output only")
    parser.add_argument("--run-worker", action="store_true", help="Run this node as a FastAPI worker")
    parser.add_argument("--worker-host", default="0.0.0.0", help="FastAPI worker bind host")
    parser.add_argument("--worker-port", default=8000, type=int, help="FastAPI worker port")

    args = parser.parse_args()

    global COLOR_ENABLED
    COLOR_ENABLED = sys.stdout.isatty() and not args.no_color

    configure_logging(verbose=(args.verbose and not args.json_only), json_logs=True)
    logger = logging.getLogger("recon.main")

    if args.run_worker:
        console.print("  [accent]▸ Starting worker API...[/accent]")
        uvicorn.run("src.distributed.worker_api:app", host=args.worker_host, port=args.worker_port)
        return

    if args.yes:
        if not args.target or not args.mode:
            parser.error("--yes requires --target and --mode")
        target = args.target
        if not _is_valid_domain_or_url(target):
            parser.error("Invalid target domain format")
        mode: ModeType = args.mode
        scan_type: ScanType = args.scan_type or "fast"
        if mode == "recon":
            categories = []
        else:
            categories = _parse_categories(args.categories or "")
        provider_id = args.llm_provider or "openai"
        spec = get_provider(provider_id)
        model = args.llm_model or spec.default_model
        env_key = os.environ.get(spec.api_key_env, "") if spec.api_key_env else ""
        api_key = args.api_key or env_key or None
        if spec.requires_api_key and not (api_key and api_key.strip()):
            parser.error(
                f"Provider '{provider_id}' requires --api-key"
                + (f" (or {spec.api_key_env})" if spec.api_key_env else "")
            )
        if spec.api_key_env and api_key:
            os.environ[spec.api_key_env] = api_key
        _persist_llm_config(provider=provider_id, model=model, api_key=api_key)
    else:
        target, mode, categories, scan_type, provider_id, model, api_key = _interactive_flow(args)

    scan_id = _safe_scan_id(args.scan_id)

    if not args.json_only:
        _print_header(target)
        console.print(f"  [bright_green]▸ SCAN ID[/bright_green]   [dim]│[/dim] [bright_cyan]{scan_id}[/bright_cyan]")
        console.print(f"  [bright_green]▸ MODE[/bright_green]      [dim]│[/dim] [bright_cyan]{mode}[/bright_cyan]")
        console.print(f"  [bright_green]▸ DEPTH[/bright_green]     [dim]│[/dim] [bright_cyan]{scan_type}[/bright_cyan]")
        console.print()
        console.print("  [bright_red]◤[/bright_red] [accent]DEPLOYING 14 AUTONOMOUS AGENTS[/accent] [bright_red]◢[/bright_red]")
        console.print("  [dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]\n")

    try:
        controller = ReconController(
            remote_worker_url=args.remote_worker_url,
            remote_api_key=args.remote_api_key,
        )
        
        # Setup rich progress — OpenClaw style
        if not args.json_only:
            progress = Progress(
                SpinnerColumn(spinner_name="dots12", style="bright_red"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(complete_style="bright_green", finished_style="bright_cyan", bar_width=40),
                TaskProgressColumn(),
                console=console,
            )
            task_id = progress.add_task("  [bright_green]⟫ agents scanning...[/bright_green]", total=100)
            progress.start()
        
        # We would ideally update progress dynamically inside controller.run_scan
        # For now we simulate it or just let run_scan run holding the spinner.
        
        report, progress_state = asyncio.run(
            controller.run_scan(
                target=target,
                scan_id=scan_id,
                mode=mode,
                categories=categories,
                scan_type=scan_type,
                agentic=bool(args.agentic),
            )
        )
        
        if not args.json_only:
            progress.update(task_id, completed=100)
            progress.stop()
            
        final_report = report.model_dump()

        if args.verbose and not args.json_only:
            logger.info(
                "scan_completed",
                extra={"extra": {"scan_id": scan_id, "target": target, "mode": mode, "scan_type": scan_type}},
            )

        if not final_report:
            console.print("[bold red][x] No final report data generated.[/bold red]")
            if final_report.get("errors"):
                console.print("\n[bold red]Errors:[/bold red]")
                for err in final_report["errors"]:
                    console.print(f"[red] - {err}[/red]")
            sys.exit(1)

        decision_output = _build_decision_output(final_report, categories)

        if not args.json_only:
            console.print(f"\n  [bright_red]☠[/bright_red] [accent]ALL AGENTS RETURNED[/accent] [bright_red]☠[/bright_red]")
            console.print("  [dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]")

            if decision_output.findings:
                console.print("\n  [bright_red]▸[/bright_red] [accent]THREAT MATRIX[/accent]")
                ptable = Table(
                    show_header=True,
                    header_style="bold bright_green",
                    border_style="bright_green",
                    padding=(0, 1),
                )
                ptable.add_column("THREAT", min_width=10)
                ptable.add_column("CLASS", min_width=16)
                ptable.add_column("VECTOR", min_width=20)

                for finding in decision_output.findings[:8]:
                    sev = finding.severity.upper()
                    if sev in {"HIGH", "CRITICAL"}:
                        color = "bright_red"
                        icon = "◉"
                    elif sev == "MEDIUM":
                        color = "yellow"
                        icon = "◎"
                    else:
                        color = "dim"
                        icon = "○"
                    ptable.add_row(
                        f"[{color}]{icon} {sev}[/{color}]",
                        f"[bright_cyan]{finding.type}[/bright_cyan]",
                        f"[dim]{finding.endpoint or 'N/A'}[/dim]",
                    )

                console.print(ptable)
            else:
                console.print("  [dim]○ no actionable threats in selected mode[/dim]")

        # Build endpoints from url_crawling (new) or endpoint_discovery (legacy)
        ep_task = _result_by_task(final_report, "url_crawling") or _result_by_task(final_report, "endpoint_discovery")
        file_task = _result_by_task(final_report, "sensitive_file_detection") or _result_by_task(final_report, "technology_fingerprinting")
        header_task = _result_by_task(final_report, "header_analysis") or _result_by_task(final_report, "auth_analysis")

        analysis_input = {
            "recon": {
                "subdomains": decision_output.subdomains,
                "alive_hosts": decision_output.alive_hosts,
                "ports": _extract_ports_detailed(_result_by_task(final_report, "port_scan"), target),
                "technologies": _extract_tech_from_task(_result_by_task(final_report, "technology_fingerprinting")),
            },
            "attack_surface": {
                "endpoints": sorted(set(
                    ep_task.get("data", {}).get("endpoints", [])
                    + _result_by_task(final_report, "api_discovery").get("data", {}).get("endpoints", [])
                )),
                "parameters": _result_by_task(final_report, "parameter_discovery").get("data", {}).get("parameters", []),
                "files": file_task.get("data", {}).get("files", file_task.get("data", {}).get("interesting_paths", [])),
                "headers": list(header_task.get("data", {}).get("security_headers", {}).keys()) or [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                ],
            },
            "preliminary_findings": _collect_preliminary_findings(final_report, categories),
        }
        try:
            llm_client = build_client(provider_id, model, api_key)
        except LLMError as exc:
            llm_client = None
            if not args.json_only:
                console.print(f"  [highlight][!] LLM disabled:[/highlight] [dim]{exc}[/dim]")

        final_output = finalize_security_insights(
            analysis_input,
            errors=final_report.get("errors", []),
            scan_id=scan_id,
            target=target,
            mode=mode,
            scan_type=scan_type,
            provider=provider_id,
            model=model,
            llm_client=llm_client,
            agent_trace=final_report.get("agent_trace", []),
        )

        if not args.json_only and final_output.get("summary", {}).get("total_findings", 0) == 0:
            console.print("[dim][-] No results found[/dim]")

        if not args.json_only:
            trace = final_output.get("agent_trace", []) or []
            if trace:
                console.print("\n  [bright_red]▸[/bright_red] [accent]AUTONOMOUS AGENT LOG[/accent] [dim]· LLM-driven tool selection[/dim]")
                for st in trace:
                    tasks = ", ".join(st.get("tasks", [])) or "—"
                    action = str(st.get("action", "")).upper()
                    console.print(f"    [dim]step {st.get('step')}[/dim] [bright_cyan]{action}[/bright_cyan] [bright_green]→[/bright_green] {tasks}")
                    if st.get("reason"):
                        console.print(f"      [dim]{st['reason']}[/dim]")

        if not args.json_only:
            intel = final_output.get("intelligence", {})
            summary_text = str(intel.get("executive_summary", "")).strip()
            if summary_text:
                console.print(
                    f"\n  [bright_red]▸[/bright_red] [accent]INTELLIGENCE BRIEF[/accent] "
                    f"[dim]· engine: {intel.get('engine', 'deterministic')}[/dim]"
                )
                console.print(Panel(summary_text, border_style="bright_green", expand=False, padding=(0, 2)))
            paths = intel.get("attack_paths", []) or []
            if paths:
                console.print("  [bright_red]▸[/bright_red] [accent]ATTACK PATHS[/accent]")
                for p in paths[:5]:
                    sev = str(p.get("severity", "")).upper()
                    console.print(f"    [bright_cyan]◈ {p.get('title', '')}[/bright_cyan] [dim]({sev})[/dim]")
                    for i, step in enumerate(p.get("steps", [])[:6], start=1):
                        console.print(f"      [dim]{i}.[/dim] {step}")

        if args.format in ["json", "both"]:
            try:
                generate_json_report(target, final_output)
            except Exception:
                if not args.json_only:
                    console.print("[bold yellow][!] Tool execution failed (json report)[/bold yellow]")

        if args.format in ["pdf", "both"]:
            try:
                generate_pdf_report(target, final_output)
            except Exception:
                if not args.json_only:
                    console.print("[bold yellow][!] Tool execution failed (pdf report)[/bold yellow]")

        _export_json_if_requested(args.export_json, final_output)

        if args.json_only:
            print(json.dumps(final_output, indent=2))
        else:
            console.print("\n  [dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]")
            console.print("  [bright_red]▸[/bright_red] [accent]RAW INTELLIGENCE DUMP[/accent]")
            console.print("  [dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]")
            console.print_json(data=final_output)
            console.print(f"\n  [dim]━━ scan complete ━━ [/dim][bright_magenta]dev by yashh[/bright_magenta][dim] ━━[/dim]\n")

    except KeyboardInterrupt:
        console.print("\n  [bright_red]✘ SIGNAL INTERRUPT[/bright_red] [dim]— extraction complete[/dim]")
        sys.exit(1)

    except Exception as e:
        logger.exception("critical_failure")
        console.print(f"\n  [bright_red]☠ CRITICAL FAILURE:[/bright_red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
