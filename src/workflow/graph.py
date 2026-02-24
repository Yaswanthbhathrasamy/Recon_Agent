from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, START, END
from crewai import Task, Crew
from src.agents.recon_agents import web_recon_specialist, osint_analyst, vulnerability_analyst, subdomain_analyst, live_host_analyst, js_recon_analyst, parameter_discovery_analyst
import logging

# Set up simple logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 1. Define the State
class ReconState(TypedDict):
    target: str
    web_recon_results: str
    osint_results: str
    vulnerability_results: str
    subdomain_results: str
    live_host_results: str
    js_recon_results: str
    parameter_results: str
    final_report: dict
    errors: Annotated[list[str], operator.add]

# 2. Node Functions
def run_web_recon(state: ReconState):
    logging.info(f"Starting Web Recon on {state['target']}")
    try:
        task = Task(
            description=f"Perform comprehensive web reconnaissance on {state['target']}. Use your tools to gather technologies, directories, headers, emails, and SSL info.",
            expected_output="A detailed summary of web-related findings.",
            agent=web_recon_specialist
        )
        crew = Crew(agents=[web_recon_specialist], tasks=[task], verbose=False)
        result = crew.kickoff()
        return {"web_recon_results": str(result.raw)}
    except Exception as e:
        error_msg = f"Web Recon Error: {e}"
        logging.error(error_msg)
        return {"errors": [error_msg]}

def run_osint(state: ReconState):
    logging.info(f"Starting OSINT on {state['target']}")
    try:
        task = Task(
            description=f"Perform OSINT on {state['target']}. Extract WHOIS, DNS records, subdomains, and historical data.",
            expected_output="A detailed summary of infrastructure and OSINT findings.",
            agent=osint_analyst
        )
        crew = Crew(agents=[osint_analyst], tasks=[task], verbose=False)
        result = crew.kickoff()
        return {"osint_results": str(result.raw)}
    except Exception as e:
        error_msg = f"OSINT Error: {e}"
        logging.error(error_msg)
        return {"errors": [error_msg]}

def run_vulnerability_scan(state: ReconState):
     logging.info(f"Starting Vulnerability Scan on {state['target']}")
     try:
          task = Task(
               description=f"Perform vulnerability scanning on {state['target']}. Check for open ports and known vulnerabilities via Shodan.",
               expected_output="A summary of potential vulnerabilities and open ports.",
               agent=vulnerability_analyst
          )
          crew = Crew(agents=[vulnerability_analyst], tasks=[task], verbose=False)
          result = crew.kickoff()
          return {"vulnerability_results": str(result.raw)}
     except Exception as e:
          error_msg = f"Vulnerability Scan Error: {e}"
          logging.error(error_msg)
          return {"errors": [error_msg]}

def run_subdomain_recon(state: ReconState):
     logging.info(f"Starting Subdomain Recon on {state['target']}")
     try:
          task = Task(
               description=f"Perform subdomain enumeration on {state['target']} to uncover expanded attack surface.",
               expected_output="A detailed list of subdomains and related context.",
               agent=subdomain_analyst
          )
          crew = Crew(agents=[subdomain_analyst], tasks=[task], verbose=False)
          result = crew.kickoff()
          return {"subdomain_results": str(result.raw)}
     except Exception as e:
          error_msg = f"Subdomain Recon Error: {e}"
          logging.error(error_msg)
          return {"errors": [error_msg]}

def run_compile_report_placeholder():
     pass

def run_live_host(state: ReconState):
     logging.info(f"Starting Live Host Check on {state['target']}")
     try:
          task = Task(
               description=f"Perform live host checking on {state['target']} to see if services respond directly.",
               expected_output="A summary of live services.",
               agent=live_host_analyst
          )
          crew = Crew(agents=[live_host_analyst], tasks=[task], verbose=False)
          result = crew.kickoff()
          return {"live_host_results": str(result.raw)}
     except Exception as e:
          error_msg = f"Live Host Check Error: {e}"
          logging.error(error_msg)
          return {"errors": [error_msg]}

def run_js_recon(state: ReconState):
     logging.info(f"Starting JS Recon on {state['target']}")
     try:
          task = Task(
               description=f"Analyze JavaScript files on {state['target']} to uncover hidden endpoints and API keys.",
               expected_output="A summary of JavaScript reconnaissance findings.",
               agent=js_recon_analyst
          )
          crew = Crew(agents=[js_recon_analyst], tasks=[task], verbose=False)
          result = crew.kickoff()
          return {"js_recon_results": str(result.raw)}
     except Exception as e:
          error_msg = f"JS Recon Error: {e}"
          logging.error(error_msg)
          return {"errors": [error_msg]}

def run_parameter_discovery(state: ReconState):
     logging.info(f"Starting Parameter Discovery on {state['target']}")
     try:
          task = Task(
               description=f"Discover hidden GET/POST parameters on {state['target']} that could lead to injection or IDOR.",
               expected_output="A summary of discovered parameters.",
               agent=parameter_discovery_analyst
          )
          crew = Crew(agents=[parameter_discovery_analyst], tasks=[task], verbose=False)
          result = crew.kickoff()
          return {"parameter_results": str(result.raw)}
     except Exception as e:
          error_msg = f"Parameter Discovery Error: {e}"
          logging.error(error_msg)
          return {"errors": [error_msg]}

def compile_report(state: ReconState):
    logging.info("Compiling final report...")
    report = {
        "Target": state["target"],
        "Live_Host_Checking": state.get("live_host_results", "Data not available or errored out."),
        "Web_Reconnaissance": state.get("web_recon_results", "Data not available or errored out."),
        "OSINT_Intelligence": state.get("osint_results", "Data not available or errored out."),
        "Subdomain_Reconnaissance": state.get("subdomain_results", "Data not available or errored out."),
        "Vulnerability_Assessment": state.get("vulnerability_results", "Data not available or errored out."),
        "JavaScript_Reconnaissance": state.get("js_recon_results", "Data not available or errored out."),
        "Parameter_Discovery": state.get("parameter_results", "Data not available or errored out."),
        "Errors": state.get("errors", [])
    }
    return {"final_report": report}
# 3. Build Graph
workflow = StateGraph(ReconState)

# Add nodes
workflow.add_node("web_recon", run_web_recon)
workflow.add_node("osint", run_osint)
workflow.add_node("vuln_scan", run_vulnerability_scan)
workflow.add_node("subdomain_recon", run_subdomain_recon)
workflow.add_node("live_host", run_live_host)
workflow.add_node("js_recon", run_js_recon)
workflow.add_node("parameter_recon", run_parameter_discovery)
workflow.add_node("compile_report", compile_report)

# Define edges (Parallel flow)
workflow.add_edge(START, "web_recon")
workflow.add_edge(START, "osint")
workflow.add_edge(START, "vuln_scan")
workflow.add_edge(START, "subdomain_recon")
workflow.add_edge(START, "live_host")
workflow.add_edge(START, "js_recon")
workflow.add_edge(START, "parameter_recon")

workflow.add_edge(["web_recon", "osint", "vuln_scan", "subdomain_recon", "live_host", "js_recon", "parameter_recon"], "compile_report")
workflow.add_edge("compile_report", END)

# Compile
app = workflow.compile()
