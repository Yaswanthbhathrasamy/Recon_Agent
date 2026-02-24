import argparse
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Basic validation before importing heavy things
if not os.environ.get("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY environment variable is not set. Please set it in your .env file.")

# Import workflow and reporting
from src.workflow.graph import app
from src.workflow.reporting import generate_json_report, generate_pdf_report

def main():
    parser = argparse.ArgumentParser(description="Multi-Agent AI Reconnaissance System")
    parser.add_argument("target", help="The target domain or URL (e.g., example.com or https://example.com)")
    parser.add_argument("--format", choices=['json', 'pdf', 'both'], default='both', help="Output format for the report (default: both)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)

    target = args.target

    print(f"[*] Starting AI Recon on target: {target}")
    print("[*] Tracking enabled on LangSmith (if LANGCHAIN_TRACING_V2 is true in .env)...")

    # Initial state
    inputs = {
        "target": target,
        "errors": []
    }

    try:
        print("[*] Initiating LangGraph Orchestration Workflow...")
        # Run workflow
        result = app.invoke(inputs)
        
        # Extract the final structured report
        final_report = result.get("final_report", {})
        
        print("\n[*] Reconnaissance Complete! Generating reports...")
        
        # Generate requested formats
        if final_report:
            if args.format in ['json', 'both']:
                 json_file = generate_json_report(target, final_report)
                 print(f"[+] JSON Report generated at: {json_file}")
                 
            if args.format in ['pdf', 'both']:
                 pdf_file = generate_pdf_report(target, final_report)
                 print(f"[+] PDF Report generated at: {pdf_file}")
        else:
            print("[-] No final report data was generated.")
            if result.get("errors"):
                 print("\nErrors Array:")
                 for e in result["errors"]:
                      print(f"- {e}")

    except Exception as e:
        print(f"\n[-] A critical error occurred during orchestration: {e}")

if __name__ == "__main__":
    main()
