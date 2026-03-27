#!/usr/bin/env python3
"""
Automated Security Orchestration and Correlation Engine
Main Entry Point
"""

import sys
import argparse
import shutil
import subprocess
from typing import Dict, Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    import questionary
except ImportError:
    print("Error: Missing required libraries. Please run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize Rich console
console = Console()

def display_banner() -> None:
    """Displays the stylized application banner."""
    banner_text = (
        "[bold cyan]Automated Security Orchestration Engine[/bold cyan]\n"
        "[blue]DevSecOps CLI Tool v1.0[/blue]\n"
        "[italic deep_sky_blue1]Identify, Exploit, and Correlate.[/italic deep_sky_blue1]"
    )
    console.print(Panel(banner_text, expand=False, border_style="cyan"))

def get_user_configuration() -> Optional[Dict[str, Any]]:
    """
    Displays an interactive menu to gather scan configuration from the user.
    Uses Questionary for interactive prompts.
    
    Returns:
        Dict[str, Any]: A configuration dictionary containing target, profile, modules, and report format.
        None: If the user interrupts or cancels the prompt.
    """
    config: Dict[str, Any] = {}
    
    try:
        # Prompt for target
        target = questionary.text(
            "Enter the Target URL/IP:",
            validate=lambda text: True if len(text.strip()) > 0 else "Target cannot be empty"
        ).ask()
        
        # questionary returns None on user interrupt (Ctrl+C)
        if target is None:
            return None
        config['target'] = target.strip()

        # Prompt for Fingerprinting OPSEC Level
        opsec_level = questionary.select(
            "Select Fingerprinting OPSEC Level:",
            choices=[
                questionary.Choice("Stealth (Passive headers, meta tags)", "stealth"),
                questionary.Choice("Noisy (Active probing, error triggering, loud scripts)", "noisy")
            ]
        ).ask()
        
        if opsec_level is None:
            return None
            
        if opsec_level == "noisy":
            console.print("\n[bold orange3][!] WARNING: Noisy mode will aggressively probe the target (error triggering, path brute-forcing) and will leave a significant footprint in server logs.[/bold orange3]\n")
            
        config['opsec_level'] = opsec_level

        # Prompt for scan profile (General aggressiveness)
        profile = questionary.select(
            "Select General Scan Profile (determines aggressiveness for other tools):",
            choices=["Stealth", "Noisy"]
        ).ask()
        
        if profile is None:
            return None
        config['profile'] = profile

        # Prompt for modules
        modules = questionary.checkbox(
            "Select Modules to Execute:",
            choices=[
                "Reconnaissance & Enumeration",
                "Web Vulnerability Fuzzer",
                "Privilege Escalation Simulator",
                "Blue Team Log Correlation Engine"
            ],
            validate=lambda answers: True if len(answers) > 0 else "You must select at least one module."
        ).ask()
        
        if modules is None:
            return None
        config['modules'] = modules

        # Prompt for report format
        report_format = questionary.select(
            "Select Output Report Format:",
            choices=["Markdown", "HTML"]
        ).ask()
        
        if report_format is None:
            return None
        config['report_format'] = report_format

        return config

    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during configuration: {e}[/bold red]")
        sys.exit(1)

def check_and_install_missing_tools(config: Dict[str, Any]) -> None:
    """
    Checks for required native tools based on selected modules and 
    prompts the user to install them if they are missing.
    """
    required_tools = set()
    selected_modules = config.get("modules", [])
    
    if "Reconnaissance & Enumeration" in selected_modules:
        required_tools.update(["nmap", "gobuster", "whatweb", "searchsploit"])
    if "Web Vulnerability Fuzzer" in selected_modules:
        required_tools.add("nuclei")
        
    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
    
    for tool in missing_tools:
        # Prompt user using Questionary
        choice = questionary.confirm(
            f"Required tool '{tool}' is missing from your PATH. Would you like to attempt to install it via 'apt'?"
        ).ask()
        
        if choice:
            console.print(f"[bold yellow][*] Attempting to install {tool} (may require sudo password)...[/bold yellow]")
            try:
                # Assuming a Debian/Ubuntu/Kali based Linux system
                subprocess.run(['sudo', 'apt-get', 'install', '-y', tool], check=True)
                
                if shutil.which(tool):
                    console.print(f"[bold green][+] {tool} installed successfully![/bold green]")
                else:
                    console.print(f"[bold red][!] {tool} installation appeared to succeed, but it's still not in PATH. It will be skipped.[/bold red]")
            except subprocess.CalledProcessError:
                console.print(f"[bold red][!] APT failed to install {tool}. It will be skipped.[/bold red]")
            except Exception as e:
                console.print(f"[bold red][!] Unexpected error installing {tool}: {e}[/bold red]")
        else:
            console.print(f"[bold yellow][!] Skipping installation of {tool}. Modules relying on it will bypass those scans.[/bold yellow]")

def main() -> None:
    """Main program execution loop."""
    display_banner()
    
    console.print("\n[bold green]Initializing Configuration...[/bold green]\n")
    
    config = get_user_configuration()
    
    if config is None:
        console.print("\n[red]Configuration aborted by user. Exiting...[/red]")
        sys.exit(0)
        
    console.print("\n[bold green]Configuration Saved Successfully:[/bold green]")
    
    # Display the configuration cleanly
    for key, value in config.items():
        if isinstance(value, list):
            value_str = ", ".join(value)
        else:
            value_str = str(value)
        console.print(f"  [cyan]{key.capitalize()}[/cyan]: [yellow]{value_str}[/yellow]")
    
    console.print("\n[bold yellow]Checking dependencies...[/bold yellow]\n")
    check_and_install_missing_tools(config)

    console.print("\n[bold yellow]System readiness achieved. Initiating Module Execution...[/bold yellow]\n")

    # Master findings dictionary
    session_findings: Dict[str, Any] = {"config": config}

    if "Reconnaissance & Enumeration" in config.get("modules", []):
        from modules.recon import run_recon
        console.print("[bold cyan][*] Launching Reconnaissance & Enumeration Module...[/bold cyan]")
        with console.status("[bold blue]Running Recon scans (this could take a moment)...[/bold blue]"):
            recon_results = run_recon(config)
        session_findings["recon"] = recon_results
        
        console.print("[bold green][+] Reconnaissance complete. Findings summary:[/bold green]")
        
        # Issue #20: Check for authentication requirements and prompt for session cookie
        web_headers = recon_results.get("web_headers", {})
        if web_headers.get("requires_auth"):
            auth_info = web_headers.get("auth_detection", {})
            console.print(f"\n[bold orange3]⚠ WARNING: {auth_info.get('message', 'Target requires authentication')}[/bold orange3]")
            if auth_info.get("redirect_to"):
                console.print(f"[yellow]Redirects to: {auth_info['redirect_to']}[/yellow]")
            console.print("[yellow]Unauthenticated scanning will produce limited/useless results.[/yellow]\n")
            
            # Prompt user for session cookie
            provide_cookie = questionary.confirm(
                "Would you like to provide a session cookie for authenticated scanning?",
                default=True
            ).ask()
            
            if provide_cookie:
                cookie_value = questionary.text(
                    "Enter the Cookie header value (e.g., PHPSESSID=abc123; security=low):"
                ).ask()
                if cookie_value:
                    config['cookie'] = cookie_value
                    console.print("[bold green][+] Session cookie configured. All modules will use authenticated requests.[/bold green]")
                else:
                    console.print("[bold yellow][!] No cookie provided. Continuing with unauthenticated scanning.[/bold yellow]")
            else:
                console.print("[bold yellow][!] Continuing with unauthenticated scanning.[/bold yellow]")
        
        # Pretty print the Tech Stack
        stack = recon_results.get("hierarchical_stack", {})
        if stack:
            console.print("\n[bold cyan]Target Tech Stack Discovered:[/bold cyan]")
            for cat, items in stack.items():
                if items:
                    console.print(f"  [bold yellow]{cat.replace('_', ' ').title()}[/bold yellow]: [white]{', '.join(items)}[/white]")
        
        # Pretty print Searchsploit Results
        sploits = recon_results.get("searchsploit_results", {})
        if sploits:
            console.print("\n[bold red]Searchsploit Vectors Identified:[/bold red]")
            for query, vectors in sploits.items():
                if isinstance(vectors, list) and len(vectors) > 0:
                    console.print(f"  [bold magenta]Query:[/bold magenta] {query}")
                    for v in vectors:
                        title = v.get('Title', 'Unknown')
                        edb = v.get('EDB_ID', 'N/A')
                        console.print(f"    - {title} (EDB: {edb})")
                        
        console.print("\n[bold]Raw Findings JSON:[/bold]")
        console.print(recon_results)

    if "Web Vulnerability Fuzzer" in config.get("modules", []):
        from modules.web_fuzzer import run_fuzzer
        console.print("\n[bold magenta][*] Launching Web Vulnerability Fuzzer Module...[/bold magenta]")
        
        # Issue #20: Only prompt for cookie if not already provided during recon
        if 'cookie' not in config:
            # Prompt for optional cookie for authenticated scanning
            use_cookie = questionary.confirm(
                "Do you want to provide a session cookie for authenticated scanning?"
            ).ask()
            
            if use_cookie:
                cookie_value = questionary.text(
                    "Enter the Cookie header value (e.g., PHPSESSID=abc123; security=low):"
                ).ask()
                if cookie_value:
                    config['cookie'] = cookie_value
                    console.print("[bold green][+] Cookie configured for authenticated scanning.[/bold green]")
        else:
            console.print(f"[bold cyan][*] Using session cookie from earlier configuration.[/bold cyan]")
        
        with console.status("[bold blue]Running Nuclei and Custom Polyglot Injectors...[/bold blue]"):
            fuzzer_results = run_fuzzer(config)
        session_findings["fuzzer"] = fuzzer_results
        
        console.print("[bold green][+] Web Vulnerability Fuzzer complete. Findings summary:[/bold green]")
        console.print(fuzzer_results)

    # Issue #13: Make SSH credentials prompt optional
    # Issue #17: Conditional module execution - track SSH session success
    ssh_session_established = False
    
    if "Privilege Escalation Simulator" in config.get("modules", []):
        from modules.privesc import run_privesc
        console.print("\n[bold magenta][*] Launching Privilege Escalation Simulator...[/bold magenta]")
        
        # Issue #13: Add option to skip SSH prompt
        console.print("[yellow]SSH Credentials required for post-exploitation simulation.[/yellow]")
        skip_privesc = questionary.confirm(
            "Do you want to run PrivEsc simulation? (requires SSH access)",
            default=True
        ).ask()
        
        if skip_privesc:
            ssh_user = questionary.text(
                "Enter SSH Username (or press Enter to skip):",
                default=""
            ).ask()
            
            # Allow skipping by leaving username empty
            if ssh_user and ssh_user.strip():
                ssh_pass = questionary.password("Enter SSH Password:").ask()
                
                if ssh_pass:
                    ssh_creds = {"username": ssh_user, "password": ssh_pass}
                    with console.status("[bold blue]Connecting via SSH and simulating privesc vectors...[/bold blue]"):
                        privesc_results = run_privesc(config, ssh_creds)
                    session_findings["privesc"] = privesc_results
                    
                    # Issue #17: Track whether SSH actually succeeded
                    if privesc_results.get("status") == "connected":
                        ssh_session_established = True
                        console.print("[bold green][+] PrivEsc Simulation complete. SSH session established successfully.[/bold green]")
                        console.print(privesc_results)
                    else:
                        console.print(f"[bold red][!] PrivEsc Simulation failed: {privesc_results.get('error_msg', 'Unknown error')}[/bold red]")
                else:
                    console.print("[bold yellow][!] PrivEsc simulation skipped by user (no password provided).[/bold yellow]")
                    session_findings["privesc"] = {"status": "skipped", "reason": "User skipped password entry"}
            else:
                console.print("[bold yellow][!] PrivEsc simulation skipped by user (no username provided).[/bold yellow]")
                session_findings["privesc"] = {"status": "skipped", "reason": "User skipped username entry"}
        else:
            console.print("[bold yellow][!] PrivEsc simulation skipped by user.[/bold yellow]")
            session_findings["privesc"] = {"status": "skipped", "reason": "User chose to skip"}

    # Issue #16: Skip Log Correlation entirely if no SSH session was established
    # Issue #17: Conditional module execution based on SSH success
    if "Blue Team Log Correlation Engine" in config.get("modules", []):
        from modules.log_analyzer import analyze_logs
        console.print("\n[bold magenta][*] Launching Blue Team Log Correlation Engine...[/bold magenta]")
        
        if not ssh_session_established:
            console.print("[bold yellow][!] Log Correlation skipped: No SSH session was established.[/bold yellow]")
            console.print("[yellow]Note: Log correlation requires an active SSH connection from the PrivEsc module.[/yellow]")
            session_findings["log_analysis"] = {
                "status": "skipped", 
                "reason": "No shell access obtained",
                "note": "Log Correlation skipped: no shell access obtained"
            }
        else:
            log_file = questionary.path("Enter path to the log file to analyze (e.g., /var/log/apache2/access.log):").ask()
            
            if log_file:
                with console.status(f"[bold blue]Analyzing {log_file} for tool signatures...[/bold blue]"):
                    log_results = analyze_logs(log_file)
                session_findings["log_analysis"] = log_results
                
                if log_results.get("status") == "error":
                    for err in log_results.get("errors", []):
                        console.print(f"[bold red][!] {err}[/bold red]")
                else:
                    score = log_results.get("detection_score", 0)
                    console.print(f"[bold green][+] Log Analysis complete. Detection Score: {score}[/bold green]")
                    console.print(log_results)
            else:
                console.print("[bold yellow][!] Log Correlation skipped: No file provided.[/bold yellow]")
                session_findings["log_analysis"] = {"status": "skipped", "reason": "No file path provided"}

    # ==========================
    # Final Stage: Generate IR Report
    # ==========================
    console.print("\n[bold magenta][*] Compiling Execution Findings into Report...[/bold magenta]")
    
    try:
        from modules.report_gen import generate_report
        session_findings["configuration"] = config
        
        with console.status("[bold blue]Generating final report...[/bold blue]"):
            report_path = generate_report(session_findings, config.get("report_format", "Markdown"))
            
        if report_path.startswith("failed"):
            console.print(f"[bold red][!] Report generation failed: {report_path}[/bold red]")
        else:
            console.print(f"[bold green][+] Beautiful report saved successfully at: {report_path}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Critical error during report generation: {str(e)}[/bold red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Execution interrupted by user. Exiting...[/red]")
        sys.exit(0)
