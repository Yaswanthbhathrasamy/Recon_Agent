from crewai import Agent
from langchain_openai import ChatOpenAI
from src.tools.web_tools import web_scraper, http_header_analyzer
from src.tools.osint_tools import whois_lookup, dns_lookup, shodan_lookup
from src.tools.network_tools import nmap_port_scanner, live_host_checker
from src.tools.advanced_web_tools import wappalyzer_detection, subdomain_enumeration, directory_brute_force, email_harvester, js_recon, parameter_discovery
from src.tools.misc_recon_tools import ssl_certificate_info, wayback_machine_osint
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize LLM
llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ.get("OPENAI_API_KEY"))

# 1. Web Recon Specialist
web_recon_specialist = Agent(
    role='Web Reconnaissance Specialist',
    goal='Gather comprehensive technical and architectural data from the target website.',
    backstory='An expert in web technologies, you excel at identifying tech stacks, finding hidden directories, and parsing web content for sensitive information.',
    verbose=True,
    allow_delegation=False,
    tools=[
        web_scraper, 
        http_header_analyzer, 
        wappalyzer_detection, 
        directory_brute_force, 
        email_harvester,
        ssl_certificate_info
    ],
    llm=llm
)

# 2. OSINT Analyst
osint_analyst = Agent(
    role='OSINT Analyst',
    goal='Collect public and infrastructure data about the target domain including domains, DNS, and historical records.',
    backstory='A seasoned intelligence operative who specializes in connecting the dots using public records, DNS registries, and internet archives.',
    verbose=True,
    allow_delegation=False,
    tools=[
        whois_lookup, 
        dns_lookup, 
        wayback_machine_osint
    ],
    llm=llm
)

# 4. Subdomain Analyst
subdomain_analyst = Agent(
    role='Subdomain Analyst',
    goal='Identify all active and historical subdomains for the target to expand the attack surface area.',
    backstory='An expert in attack surface management, relying on certificate transparency and enumeration to find forgotten or hidden subdomains.',
    verbose=True,
    allow_delegation=False,
    tools=[
        subdomain_enumeration
    ],
    llm=llm
)

# 3. Vulnerability Analyst
vulnerability_analyst = Agent(
    role='Vulnerability Analyst',
    goal='Identify potential open ports, services, and known vulnerabilities associated with the target infrastructure.',
    backstory='A cybersecurity veteran focused on discovering network exposures, utilizing port scanning and threat intelligence databases to evaluate risk.',
    verbose=True,
    allow_delegation=False,
    tools=[
        nmap_port_scanner, 
        shodan_lookup
    ],
    llm=llm
)

# 5. Live Host Analyst
live_host_analyst = Agent(
    role='Live Host Analyst',
    goal='Verify which target infrastructure assets and subdomains are actively responding to requests.',
    backstory='A network specialist focused on verifying up-time and pinging servers to map out actual live endpoints.',
    verbose=True,
    allow_delegation=False,
    tools=[
        live_host_checker
    ],
    llm=llm
)

# 6. JavaScript Recon Analyst
js_recon_analyst = Agent(
    role='JavaScript Recon Analyst',
    goal='Analyze JavaScript files on the target to uncover hidden API endpoints, internal routes, and hardcoded secrets.',
    backstory='An application security expert who dissects client-side code to find vulnerabilities hiding in plain sight within JS files.',
    verbose=True,
    allow_delegation=False,
    tools=[
        js_recon
    ],
    llm=llm
)

# 7. Parameter Discovery Analyst
parameter_discovery_analyst = Agent(
    role='Parameter Discovery Analyst',
    goal='Fuzz and discover hidden GET/POST parameters on target endpoints to expand potential injection vectors.',
    backstory='A meticulous fuzzer who understands how hidden parameters lead to IDOR, SQLi, and open redirect vulnerabilities.',
    verbose=True,
    allow_delegation=False,
    tools=[
        parameter_discovery
    ],
    llm=llm
)
