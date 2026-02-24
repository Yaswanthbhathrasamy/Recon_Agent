import ssl
import socket
from datetime import datetime
from crewai.tools import tool
import requests

@tool
def ssl_certificate_info(domain: str) -> str:
    """Retrieves and analyzes the SSL/TLS certificate information for a given domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        output = f"SSL Certificate Info for {domain}:\n"
        output += f"Issuer: {dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')}\n"
        output += f"Subject: {dict(x[0] for x in cert['subject']).get('commonName', 'Unknown')}\n"
        output += f"Version: {cert.get('version')}\n"
        output += f"Serial Number: {cert.get('serialNumber')}\n"
        
        # Date parsing
        date_fmt = '%b %d %H:%M:%S %Y %Z'
        not_before = datetime.strptime(cert['notBefore'], date_fmt)
        not_after = datetime.strptime(cert['notAfter'], date_fmt)
        
        output += f"Valid From: {not_before.strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += f"Valid Until: {not_after.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        days_left = (not_after - datetime.utcnow()).days
        output += f"Days Remaining: {days_left}\n"
        
        return output
    except Exception as e:
        return f"Error connecting or retrieving SSL cert for {domain}: {e}"
        
@tool
def wayback_machine_osint(url: str) -> str:
     """Fetches the latest archived snapshot of a URL from the Internet Archive Wayback Machine."""
     try:
          api_url = f"http://archive.org/wayback/available?url={url}"
          response = requests.get(api_url, timeout=10)
          response.raise_for_status()
          data = response.json()
          
          archived_snapshots = data.get('archived_snapshots', {})
          closest = archived_snapshots.get('closest')
          
          if not closest:
               return f"No archived snapshots found for {url} in the Wayback Machine."
               
          output = f"Wayback Machine Data for {url}:\n"
          output += f"Found latest snapshot: {closest.get('available')}\n"
          output += f"Snapshot URL: {closest.get('url')}\n"
          output += f"Timestamp: {closest.get('timestamp')}\n"
          
          return output
     except Exception as e:
          return f"Error retrieving Wayback Machine data for {url}: {e}"
