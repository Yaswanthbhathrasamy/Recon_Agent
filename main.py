import argparse
import logging
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Validate required environment variables
if not os.environ.get("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY environment variable is not set. Please configure it in your .env file.")

# Import workflow and reporting
from src.workflow.graph import app
from src.workflow.reporting import generate_json_report, generate_pdf_report


# ==============================
# UI Helpers
# ==============================

def print_banner():
    banner = r"""
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

    AI Recon Agent | Multi-Agent OSINT Framework (v1.0)
    Developed by Yaswanth
    Powered by LangGraph + OpenAI
    """
    print(banner)


def print_section(title):
    print("\n" + "=" * 60)
    print(f"[+] {title}")
    print("=" * 60)


def print_success(message):
    print(f"[SUCCESS] {message}")


def print_error(message):
    print(f"[ERROR] {message}")


# ==============================
# Main Execution
# ==============================

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="AI Recon Agent - Multi-Agent Reconnaissance Framework"
    )
    parser.add_argument(
        "target",
        help="Target domain or URL (e.g., example.com or https://example.com)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "pdf", "both"],
        default="both",
        help="Output format (default: both)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Logging configuration
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)

    target = args.target

    print_section("Recon Execution Started")
    print(f"Target      : {target}")
    print(f"Timestamp   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Agents      : Web | OSINT | Network | Vulnerability")

    inputs = {
        "target": target,
        "errors": []
    }

    try:
        print_section("LangGraph Orchestration Initiated")

        # Execute workflow
        result = app.invoke(inputs)

        final_report = result.get("final_report", {})

        if not final_report:
            print_error("No final report data generated.")
            if result.get("errors"):
                print("\nErrors:")
                for err in result["errors"]:
                    print(f" - {err}")
            sys.exit(1)

        print_section("Reconnaissance Complete")
        print_success("Intelligence gathering finished successfully.")

        # Generate reports
        print_section("Generating Reports")

        if args.format in ["json", "both"]:
            json_file = generate_json_report(target, final_report)
            print_success(f"JSON Report: {json_file}")

        if args.format in ["pdf", "both"]:
            pdf_file = generate_pdf_report(target, final_report)
            print_success(f"PDF Report : {pdf_file}")

        print_section("Operation Completed Successfully")

    except KeyboardInterrupt:
        print_error("Operation cancelled by user.")
        sys.exit(1)

    except Exception as e:
        print_error(f"Critical orchestration failure: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()