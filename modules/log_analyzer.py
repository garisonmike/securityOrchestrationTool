"""
Blue Team Log Correlation Engine
"""
import os
import re
from typing import Dict, Any, List

def analyze_logs(log_path: str) -> Dict[str, Any]:
    """
    Parses a given server log file to identify traces of the tool's attacks.
    Matches against known signatures like Nmap UAs, Nuclei tags, and polyglots.
    Calculates a Detection Score based on matches.
    """
    results: Dict[str, Any] = {
        "status": "pending",
        "log_file": log_path,
        "total_lines_analyzed": 0,
        "detection_score": 0,
        "matches": {
            "nmap": [],
            "nuclei": [],
            "polyglot": []
        },
        "errors": []
    }

    if not log_path or not os.path.exists(log_path):
        results["status"] = "error"
        results["errors"].append(f"Log file not found at: {log_path}")
        return results

    if not os.path.isfile(log_path):
        results["status"] = "error"
        results["errors"].append(f"Path is not a regular file: {log_path}")
        return results

    # Signatures to hunt for in the logs
    # Nmap often leaves 'Nmap Scripting Engine' or just 'nmap' in the User-Agent
    # Nuclei typically includes 'nuclei' in the User-Agent
    # Polyglots matching our web fuzzer (e.g., SLEEP(5), script tags, union select)
    signatures = {
        "nmap": re.compile(r'(?i)nmap\b'),
        "nuclei": re.compile(r'(?i)nuclei'),
        "polyglot": re.compile(r'(?i)(SLEEP\(\d+\)|<script>|<svg/onload|NCI_HACKATHON|UNION\s+SELECT|OR\s+1=1|/etc/passwd)')
    }

    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as lf:
            for line_num, line in enumerate(lf, start=1):
                results["total_lines_analyzed"] += 1
                line = line.strip()

                if signatures["nmap"].search(line):
                    results["matches"]["nmap"].append({"line": line_num, "content": line})
                    results["detection_score"] += 1
                
                if signatures["nuclei"].search(line):
                    results["matches"]["nuclei"].append({"line": line_num, "content": line})
                    results["detection_score"] += 1
                
                if signatures["polyglot"].search(line):
                    results["matches"]["polyglot"].append({"line": line_num, "content": line})
                    results["detection_score"] += 1

        results["status"] = "completed"

    except PermissionError:
        results["status"] = "error"
        results["errors"].append(f"Permission denied to read log file: {log_path}. Try running with elevated privileges.")
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(f"An unexpected error occurred while reading the log file: {str(e)}")

    return results
