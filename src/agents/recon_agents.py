from crewai import Agent
from langchain_openai import ChatOpenAI
from src.tools.web_tools import web_scraper, http_header_analyzer
from src.tools.osint_tools import whois_lookup, dns_lookup, shodan_lookup
from src.tools.network_tools import nmap_port_scanner
from src.tools.advanced_web_tools import wappalyzer_detection, subdomain_enumeration, directory_brute_force, email_harvester
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
