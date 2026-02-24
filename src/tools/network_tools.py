import nmap
from crewai.tools import tool

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
