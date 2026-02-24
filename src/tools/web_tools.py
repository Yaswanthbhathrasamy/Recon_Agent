import requests
from bs4 import BeautifulSoup
from crewai.tools import tool

@tool
def web_scraper(url: str) -> str:
    """Useful for scraping the text content of a website. Requires the full URL including http/https."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
            
        text = soup.get_text(separator=' ', strip=True)
        return text[:5000] # Return the first 5000 characters to prevent context window overflow
    except Exception as e:
        return f"Error scraping {url}: {e}"

@tool
def http_header_analyzer(url: str) -> str:
    """Extracts and analyzes the HTTP headers from a given URL."""
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers
        
        analysis = "HTTP Headers:\n"
        for key, value in headers.items():
            analysis += f"- {key}: {value}\n"
            
        return analysis
    except Exception as e:
        return f"Error extracting headers from {url}: {e}"
