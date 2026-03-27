"""
Blue Team Log Correlation Engine
"""
import os
import re
from typing import Dict, Any, List, Optional

def analyze_logs_from_ssh(ssh_session, target_hostname: str, log_paths: List[str] = None) -> Dict[str, Any]:
    """
    Issue #27, #25, #26, #34: Fetch and analyze logs from a remote host via SSH.
    
    Args:
        ssh_session: Active paramiko.SSHClient connection
        target_hostname: Target hostname (for reporting)
        log_paths: List of log file paths to fetch. Defaults to common locations.
    
    Returns:
        Dict containing analysis results from all fetched logs
    """
    if log_paths is None:
        log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/auth.log",
            "/var/log/syslog"
        ]
    
    combined_results: Dict[str, Any] = {
        "status": "pending",
        "target": target_hostname,
        "logs_analyzed": [],
        "total_lines_analyzed": 0,
        "detection_score": 0,
        "matches": {
            "nmap": [],
            "nuclei": [],
            "polyglot": []
        },
        "errors": []
    }
    
    # Signatures to hunt for in the logs
    signatures = {
        "nmap": re.compile(r'(?i)nmap\b'),
        "nuclei": re.compile(r'(?i)nuclei'),
        "polyglot": re.compile(r'(?i)(SLEEP\(\d+\)|<script>|<svg/onload|NCI_HACKATHON|UNION\s+SELECT|OR\s+1=1|/etc/passwd)')
    }
    
    for remote_path in log_paths:
        try:
            # Execute remote cat command and capture output
            _, stdout, stderr = ssh_session.exec_command(f"cat {remote_path}", timeout=30)
            lines = stdout.readlines()
            error_output = stderr.read().decode('utf-8', errors='replace').strip()
            
            if error_output and ("No such file" in error_output or "Permission denied" in error_output):
                combined_results["errors"].append(f"{remote_path}: {error_output}")
                continue
            
            if not lines:
                combined_results["errors"].append(f"{remote_path}: File is empty or unreadable")
                continue
            
            # Analyze this log file
            log_matches = 0
            for line_num, line in enumerate(lines, start=1):
                combined_results["total_lines_analyzed"] += 1
                line = line.strip()

                if signatures["nmap"].search(line):
                    combined_results["matches"]["nmap"].append({
                        "file": remote_path,
                        "line": line_num,
                        "content": line
                    })
                    combined_results["detection_score"] += 1
                    log_matches += 1
                
                if signatures["nuclei"].search(line):
                    combined_results["matches"]["nuclei"].append({
                        "file": remote_path,
                        "line": line_num,
                        "content": line
                    })
                    combined_results["detection_score"] += 1
                    log_matches += 1
                
                if signatures["polyglot"].search(line):
                    combined_results["matches"]["polyglot"].append({
                        "file": remote_path,
                        "line": line_num,
                        "content": line
                    })
                    combined_results["detection_score"] += 1
                    log_matches += 1
            
            combined_results["logs_analyzed"].append({
                "path": remote_path,
                "lines": len(lines),
                "matches": log_matches
            })
            
        except Exception as e:
            combined_results["errors"].append(f"{remote_path}: {type(e).__name__}: {str(e)}")
    
    if combined_results["logs_analyzed"]:
        combined_results["status"] = "completed"
    else:
        combined_results["status"] = "error"
        combined_results["errors"].append("No logs could be analyzed")
    
    return combined_results


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
