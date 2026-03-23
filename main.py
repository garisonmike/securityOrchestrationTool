#!/usr/bin/env python3
"""
Automated Security Orchestration and Correlation Engine
Main Entry Point
"""

import sys
import argparse
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
    
    console.print("\n[bold yellow]System readiness achieved. Module execution pending...[/bold yellow]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Execution interrupted by user. Exiting...[/red]")
        sys.exit(0)
