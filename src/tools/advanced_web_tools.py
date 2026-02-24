from crewai.tools import tool
import requests
import re
from urllib.parse import urlparse

@tool
def wappalyzer_detection(url: str) -> str:
    """Detects technologies used on a website using Wappalyzer. Requires a full URL."""
    try:
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
        
        output = f"Technologies detected on {url}:\n"
        for tech, details in technologies.items():
             versions = ', '.join(details.get('versions', [])) or 'Unknown'
             cats = ', '.join(c for c in details.get('categories', []))
             output += f"- {tech} (Version: {versions}) [Categories: {cats}]\n"
             
        return output
    except Exception as e:
        return f"Error detecting technologies on {url}: {e}"

@tool
def subdomain_enumeration(domain: str) -> str:
    """Enumerates subdomains for a given domain using the crt.sh certificate transparency database API."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value')
            if name_value:
                # Some entries have multiple subdomains separated by newlines
                for sub in name_value.split('\n'):
                     if sub.endswith(domain) and not sub.startswith('*'):
                          subdomains.add(sub.strip())
                          
        if not subdomains:
             return f"No subdomains found for {domain} on crt.sh."
             
        output = f"Subdomains for {domain}:\n"
        for sub in sorted(list(subdomains))[:50]: # Limit to 50 for context size
             output += f"- {sub}\n"
             
        if len(subdomains) > 50:
             output += f"... and {len(subdomains) - 50} more."
             
        return output
    except Exception as e:
         return f"Error enumerating subdomains for {domain}: {e}"
         
@tool
def directory_brute_force(url: str) -> str:
    """Performs a lightweight dictionary attack to find common exposed directories (e.g., /admin, /api). Requires a full URL."""
    common_dirs = ['admin', 'login', 'api', 'dashboard', 'config', 'backup', 'robots.txt', '.git/', 'wp-admin']
    found_dirs = []
    
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    try:
        for directory in common_dirs:
             test_url = f"{base_url}/{directory}"
             try:
                 # Use HEAD request for speed and less noise
                 response = requests.head(test_url, timeout=5)
                 if response.status_code in [200, 301, 302, 401, 403]: # 401/403 indicate it exists but is restricted
                      found_dirs.append(f"{test_url} (HTTP {response.status_code})")
             except requests.RequestException:
                 continue
                 
        if not found_dirs:
             return f"No common directories found on {base_url}."
             
        output = f"Discovered Directories on {base_url}:\n"
        for d in found_dirs:
             output += f"- {d}\n"
             
        return output
    except Exception as e:
         return f"Error brute-forcing directories on {base_url}: {e}"

@tool
def email_harvester(url: str) -> str:
     """Scrapes a webpage and extracts any visible email addresses using regular expressions. Requires full URL."""
     try:
         headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
         response = requests.get(url, headers=headers, timeout=10)
         response.raise_for_status()
         
         # Regex for email extraction
         email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
         emails = set(re.findall(email_pattern, response.text))
         
         if not emails:
              return f"No emails found on {url}."
              
         output = f"Emails found on {url}:\n"
         for email in emails:
              output += f"- {email}\n"
              
         return output
     except Exception as e:
          return f"Error harvesting emails from {url}: {e}"

@tool
def js_recon(url: str) -> str:
    """Scrapes a webpage for linked JavaScript files and extracts hidden endpoints, API keys, and routes."""
    try:
        from bs4 import BeautifulSoup
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        js_files = []
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                # Handle relative URLs
                if src.startswith('/'):
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    src = base_url + src
                elif not src.startswith('http'):
                    src = url.rstrip('/') + '/' + src
                js_files.append(src)
                
        if not js_files:
            return f"No external JavaScript files found on {url}."
            
        output = f"JavaScript Recon for {url}:\nFound {len(js_files)} JS files.\n"
        
        # We only analyze the first 3 files to avoid context limits and long execution
        for js_url in js_files[:3]:
            try:
                js_resp = requests.get(js_url, headers=headers, timeout=5)
                if js_resp.status_code == 200:
                    content = js_resp.text
                    
                    # Search for endpoints /api/...
                    endpoints = set(re.findall(r'[\'"](/api/[^\'"]+)[\'"]', content) + re.findall(r'[\'"](https?://[^\'"]+)[\'"]', content))
                    
                    # Search for potential keys
                    keys = set(re.findall(r'(?i)(?:api_key|apikey|secret|token)[\s:=]+[\'"]([a-zA-Z0-9_\-]{16,})[\'"]', content))
                    
                    output += f"\nFile: {js_url}\n"
                    if endpoints:
                        output += f"  - Potential Endpoints found: {len(endpoints)} (e.g., {list(endpoints)[:3]})\n"
                    if keys:
                        output += f"  - Potential Secrets found: {len(keys)}\n"
                    if not endpoints and not keys:
                         output += "  - No immediate secrets or endpoints found via regex.\n"
            except Exception:
                output += f"\nFile: {js_url} (Failed to load)\n"
                
        if len(js_files) > 3:
             output += f"\n...and {len(js_files) - 3} more files not analyzed deeply."
             
        return output
    except Exception as e:
        return f"Error performing JS Recon on {url}: {e}"

@tool
def parameter_discovery(url: str) -> str:
    """Discovers potential hidden parameters for a URL by fuzzing common GET parameters."""
    common_params = ['id', 'user', 'admin', 'redirect', 'file', 'dir', 'page', 'token', 'debug', 'test']
    found_params = []
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        # Baseline response length
        baseline_resp = requests.get(url, headers=headers, timeout=5)
        baseline_len = len(baseline_resp.text)
        
        # Fuzz standard parameters with a dummy value
        for param in common_params:
            test_url = f"{url}?{param}=1"
            try:
                test_resp = requests.get(test_url, headers=headers, timeout=3)
                # If the length of the response changes significantly, the parameter might be reflected or processed
                if abs(len(test_resp.text) - baseline_len) > 50 or test_resp.status_code != baseline_resp.status_code:
                    found_params.append(f"{param} (Changes response length or status: {test_resp.status_code})")
            except requests.RequestException:
                continue
                
        output = f"Parameter Discovery for {url}:\n"
        if found_params:
             output += "Potential active parameters discovered (response changed):\n"
             for p in found_params:
                  output += f"- {p}\n"
             output += "\nThese may lead to SQLi, XSS, or IDOR vulnerabilities.\n"
        else:
             output += "No obvious active parameters found from the quick scan list.\n"
             
        # Find parameters already in the DOM (forms)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(baseline_resp.text, 'html.parser')
        form_params = set()
        for form in soup.find_all('input'):
             name = form.get('name')
             if name:
                  form_params.add(name)
                  
        if form_params:
             output += f"Parameters found in HTML forms: {', '.join(form_params)}\n"
             
        return output
    except Exception as e:
        return f"Error performing parameter discovery on {url}: {e}"
