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

        # Prompt for scan profile
        profile = questionary.select(
            "Select Scan Profile (determines aggressiveness):",
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
        required_tools.update(["nmap", "gobuster"])
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
        # Provide a stylized output of the dictionary using rich
        console.print(recon_results)

    if "Web Vulnerability Fuzzer" in config.get("modules", []):
        from modules.web_fuzzer import run_fuzzer
        console.print("\n[bold magenta][*] Launching Web Vulnerability Fuzzer Module...[/bold magenta]")
        with console.status("[bold blue]Running Nuclei and Custom Polyglot Injectors...[/bold blue]"):
            fuzzer_results = run_fuzzer(config)
        session_findings["fuzzer"] = fuzzer_results
        
        console.print("[bold green][+] Web Vulnerability Fuzzer complete. Findings summary:[/bold green]")
        console.print(fuzzer_results)

    if "Privilege Escalation Simulator" in config.get("modules", []):
        from modules.privesc import run_privesc
        console.print("\n[bold magenta][*] Launching Privilege Escalation Simulator...[/bold magenta]")
        
        # We need credentials to proceed
        console.print("[yellow]SSH Credentials required for post-exploitation simulation.[/yellow]")
        ssh_user = questionary.text("Enter SSH Username:").ask()
        ssh_pass = questionary.password("Enter SSH Password:").ask()
        
        if ssh_user and ssh_pass:
            ssh_creds = {"username": ssh_user, "password": ssh_pass}
            with console.status("[bold blue]Connecting via SSH and simulating privesc vectors...[/bold blue]"):
                privesc_results = run_privesc(config, ssh_creds)
            session_findings["privesc"] = privesc_results
            
            console.print("[bold green][+] PrivEsc Simulation complete. Findings summary:[/bold green]")
            console.print(privesc_results)
        else:
            console.print("[bold red][!] PrivEsc Simulation aborted: Missing credentials.[/bold red]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Execution interrupted by user. Exiting...[/red]")
        sys.exit(0)
