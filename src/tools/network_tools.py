import nmap
from crewai.tools import tool
import socket
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
@tool
def nmap_port_scanner(target: str) -> str:
    """Scans top 100 common ports using Nmap for a given IP address or hostname."""
    try:
        nm = nmap.PortScanner()
        # Scan top 100 ports using -F (fast scan)
        nm.scan(target, arguments='-F') 
        
        output = f"Nmap Scan Results for {target}:\n"
        for host in nm.all_hosts():
            output += f"Host: {host} ({nm[host].hostname()})\n"
            output += f"State: {nm[host].state()}\n"
            
            for proto in nm[host].all_protocols():
                output += f"Protocol: {proto}\n"
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port]['name']
                    output += f"  - Port {port}: {state} ({name})\n"
                    
        if not nm.all_hosts():
             return f"Nmap found no open ports on {target} in top 100 or host is down."
             
        return output
    except Exception as e:
        return f"Error running Nmap scan on {target}. Please ensure nmap is installed on the system (e.g., sudo apt-get install nmap). Error: {e}"

@tool
def live_host_checker(target: str) -> str:
    """Checks if a given domain or IP is a live host by pinging it and trying HTTP/HTTPS."""
    output = f"Live Host Check for {target}:\n"
    
    # 1. DNS Resolution Check
    try:
        ip = socket.gethostbyname(target)
        output += f"- DNS Resolution: SUCCESS (IP: {ip})\n"
    except socket.gaierror:
        return f"Live Host Check for {target}:\n- DNS Resolution: FAILED. Host is likely dead or parked."
        
    # 2. HTTP/HTTPS Check
    live_services = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    for protocol in ['http', 'https']:
        url = f"{protocol}://{target}"
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            status = response.status_code
            
            # Check for CDN or WAF headers briefly
            server = response.headers.get('Server', 'Unknown')
            cdn = "Detected" if any(x in server.lower() for x in ['cloudflare', 'akamai', 'fastly', 'cloudfront']) else "Not Detected"
            
            live_services.append(f"{protocol.upper()} ({status}) - Server: {server} | CDN/WAF: {cdn}")
        except requests.exceptions.RequestException:
            pass
            
    if live_services:
        output += "- Active Services:\n"
        for srv in live_services:
            output += f"  - {srv}\n"
    else:
        output += "- Active Services: NONE (Ports 80/443 do not respond)\n"
        
    return output
