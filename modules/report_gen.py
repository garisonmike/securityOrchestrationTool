"""
Incident Response Report Generator Module
"""
import os
import shutil
import subprocess
from typing import Dict, Any

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    raise ImportError("Jinja2 is required for report generation. Run: pip install jinja2")

def generate_report(findings: Dict[str, Any], report_format: str, output_dir: str = "reports") -> str:
    """
    Compiles the findings dictionary into a professional Markdown or HTML report using Jinja2.
    Optionally, if HTML is selected and wkhtmltopdf is installed, converts the HTML to PDF.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    target = findings.get("configuration", {}).get("target", "Unknown Target")
    cleaned_target = target.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "_")
    
    # Establish Jinja2 environment referencing the templates directory relative to project root
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, "templates")
    env = Environment(loader=FileSystemLoader(template_dir))

    # Determine template and output file extensions
    ext = report_format.lower()
    if ext not in ["markdown", "html"]:
        ext = "markdown" # Fallback

    template_file = "report.md.j2" if ext == "markdown" else "report.html.j2"
    file_ext = ".md" if ext == "markdown" else ".html"
    
    output_filename = f"report_{cleaned_target}{file_ext}"
    output_path = os.path.join(output_dir, output_filename)

    try:
        template = env.get_template(template_file)
    except Exception as e:
        return f"failed_to_load_template: {str(e)}"

    # Provide safe fallbacks if modules were skipped
    template_vars = {
        "target": target,
        "recon": findings.get("recon", {}),
        "fuzzer": findings.get("fuzzer", {}),
        "privesc": findings.get("privesc", {}),
        "log_analysis": findings.get("log_analysis", {})
    }

    try:
        rendered_content = template.render(**template_vars)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_content)
    except Exception as e:
        return f"failed_to_write_report: {str(e)}"

    pdf_output_path = None
    # Special Dependency Check: HTML to PDF conversion using wkhtmltopdf
    if ext == "html":
        wkhtmltopdf_path = shutil.which("wkhtmltopdf")
        if wkhtmltopdf_path:
            pdf_output_path = os.path.join(output_dir, f"report_{cleaned_target}.pdf")
            try:
                subprocess.run(
                    [wkhtmltopdf_path, "--quiet", output_path, pdf_output_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as e:
                # Log the error but don't fail the HTML generation
                pdf_error_msg = e.stderr.decode('utf-8', errors='replace').strip() if e.stderr else str(e)
                print(f"[!] Warning: PDF generation failed during wkhtmltopdf execution. Output: {pdf_error_msg}")
                pdf_output_path = None
            except Exception as e:
                print(f"[!] Warning: Unexpected error during PDF generation: {str(e)}")
                pdf_output_path = None
        else:
            # Tool not found; we gracefully skip PDF conversion
            pass

    return pdf_output_path if pdf_output_path and os.path.exists(pdf_output_path) else output_path
