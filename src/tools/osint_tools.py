import whois
import dns.resolver
from crewai.tools import tool
import os
import shodan

@tool
def whois_lookup(domain: str) -> str:
    """Performs a WHOIS lookup for a given domain name to retrieve registration details."""
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error retrieving WHOIS data for {domain}: {e}"

@tool
def dns_lookup(domain: str) -> str:
    """Performs a DNS lookup for A, AAAA, MX, NS, and TXT records for a given domain."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except Exception:
            pass # Ignore if record type doesn't exist
            
    if not records:
         return f"No common DNS records found for {domain} or an error occurred."
         
    output = f"DNS Records for {domain}:\n"
    for r_type, r_data in records.items():
        output += f"- {r_type}: {', '.join(r_data)}\n"
        
    return output

@tool
def shodan_lookup(ip_address: str) -> str:
    """Uses the Shodan API to retrieve information about an IP address. Requires SHODAN_API_KEY environment variable."""
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
         return "SHODAN_API_KEY environment variable not set."
         
    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip_address)
        
        output = f"Shodan Info for {ip_address}:\n"
        output += f"Organization: {host.get('org', 'N/A')}\n"
        output += f"OS: {host.get('os', 'N/A')}\n"
        output += "Ports: " + ", ".join(str(p) for p in host.get('ports', [])) + "\n"
        
        return output
    except Exception as e:
        return f"Error connecting to Shodan for {ip_address}: {e}"
