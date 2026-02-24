import json
import os
from fpdf import FPDF
from datetime import datetime

def generate_json_report(target: str, data: dict, output_dir: str = "src/reports"):
    """Saves the reconnaissance data to a JSON file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"{output_dir}/recon_{sanitized_target}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
        
    return filename

def generate_pdf_report(target: str, data: dict, output_dir: str = "src/reports"):
    """Generates a professional PDF report from the reconnaissance data."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"{output_dir}/recon_{sanitized_target}_{timestamp}.pdf"
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"AI Reconnaissance Report: {target}", ln=True, align='C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)
    
    # Content Sections
    for section, content in data.items():
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, section.replace("_", " ").title(), ln=True)
        pdf.set_font("Arial", '', 11)
        
        # Handle string content or dictionary (for structured tool outputs if any)
        if isinstance(content, str):
            # Encode to latin-1 and replace chars causing issues
            safe_text = content.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 8, safe_text)
        elif isinstance(content, dict):
             for k, v in content.items():
                 safe_k = str(k).encode('latin-1', 'replace').decode('latin-1')
                 safe_v = str(v).encode('latin-1', 'replace').decode('latin-1')
                 pdf.multi_cell(0, 8, f"{safe_k}: {safe_v}")
        else:
             safe_content = str(content).encode('latin-1', 'replace').decode('latin-1')
             pdf.multi_cell(0, 8, safe_content)
             
        pdf.ln(5)
        
    pdf.output(filename)
    return filename
