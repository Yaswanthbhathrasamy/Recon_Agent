import json
import os
import textwrap
from fpdf import FPDF
from datetime import datetime


def _pdf_safe_text(value: str, hard_wrap: int = 70) -> str:
    """Normalize text for FPDF and force-wrap long tokens to avoid rendering errors."""
    safe = str(value).replace("\t", "    ").encode("latin-1", "replace").decode("latin-1")
    lines = []
    for line in safe.splitlines() or [safe]:
        # break_long_words=True prevents "Not enough horizontal space" on long tokens
        wrapped = textwrap.wrap(
            line,
            width=hard_wrap,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        if wrapped:
            lines.extend(wrapped)
        else:
            lines.append("")
    return "\n".join(lines)


def _pdf_write_multiline(pdf: FPDF, value: str) -> None:
    # Use an explicit positive width and left margin x position to avoid
    # fpdf "Not enough horizontal space" errors on wrapped content.
    usable_width = max(10.0, pdf.w - pdf.l_margin - pdf.r_margin)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(usable_width, 8, _pdf_safe_text(value))


def generate_json_report(target: str, data: dict, output_dir: str = "src/reports"):
    """Saves the reconnaissance data to a JSON file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"{output_dir}/recon_{sanitized_target}_{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
        
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
        pdf.cell(0, 10, _pdf_safe_text(section.replace("_", " ").title()), ln=True)
        pdf.set_font("Arial", '', 11)
        
        # Handle string content or dictionary (for structured tool outputs if any)
        if isinstance(content, str):
            _pdf_write_multiline(pdf, content)
        elif isinstance(content, dict):
             for k, v in content.items():
                 if isinstance(v, (dict, list)):
                     safe_v = json.dumps(v, ensure_ascii=True, indent=2)
                 else:
                     safe_v = str(v)
                 _pdf_write_multiline(pdf, f"{k}: {safe_v}")
        elif isinstance(content, list):
             _pdf_write_multiline(pdf, json.dumps(content, ensure_ascii=True, indent=2))
        else:
             _pdf_write_multiline(pdf, str(content))
             
        pdf.ln(5)
        
    pdf.output(filename)
    return filename
