"""
Privilege Escalation Simulator Module
"""
import paramiko
from typing import Dict, Any

def execute_remote_command(ssh_client: paramiko.SSHClient, command: str) -> Dict[str, str]:
    """Execute a single command via SSH and parse the streams."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=15)
        # Wait for the command to finish and get exit status
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()
        return {"command": command, "stdout": out, "stderr": err, "exit_status": exit_status}
    except Exception as e:
        return {"command": command, "error": str(e)}

def run_privesc(config: Dict[str, Any], ssh_creds: Dict[str, str]) -> Dict[str, Any]:
    """
    Main entry point for the Privilege Escalation Simulator.
    Establishes an SSH connection and runs automated enumeration vectors.
    """
    target = config.get('target', '').split(":")[0]  # strip port if attached 
    target = target.replace('http://', '').replace('https://', '')
    
    results: Dict[str, Any] = {
        "status": "pending",
        "target": target,
        "auth_used": ssh_creds.get('username'),
        "findings": {}
    }

    # Initialize SSH Client
    ssh = paramiko.SSHClient()
    # Automatically add unknown host keys
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect
        ssh.connect(
            hostname=target,
            username=ssh_creds.get('username'),
            password=ssh_creds.get('password'),
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        results["status"] = "connected"

        # Enumeration Commands Dictionary
        enum_commands = {
            "sudo_privileges": "sudo -n -l 2>/dev/null",
            "suid_binaries": "find / -type f -perm -4000 2>/dev/null | grep -v 'snap\\|docker' | head -n 20",
            "shadow_writable": "ls -l /etc/shadow | awk '{print $1}'",
            "cron_jobs": "cat /etc/crontab 2>/dev/null",
            "os_release": "cat /etc/os-release | grep PRETTY_NAME"
        }

        # Execute and store results
        for key, cmd in enum_commands.items():
            run_result = execute_remote_command(ssh, cmd)
            results["findings"][key] = run_result

    except paramiko.AuthenticationException:
        results["status"] = "error"
        results["error_msg"] = "Authentication failed. Invalid username or password."
    except paramiko.SSHException as e:
        results["status"] = "error"
        results["error_msg"] = f"SSH error occurred: {e}"
    except Exception as e:
        results["status"] = "error"
        results["error_msg"] = f"Unexpected connection error: {e}"
    finally:
        # Always ensure the connection is closed
        ssh.close()

    return results
