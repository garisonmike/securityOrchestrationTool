"""
Privilege Escalation Simulator Module
"""
import paramiko
import time
from typing import Dict, Any, Tuple
from urllib.parse import urlparse

def detect_ssh_rate_limiting(hostname: str, port: int = 22) -> Tuple[bool, str]:
    """
    Issue #22: Detect SSH rate limiting before attempting credential brute-force.
    
    Performs 3 rapid intentionally-failed auth probes and measures:
    - Response delay patterns
    - Connection drop behavior
    - Exponential backoff indicators
    
    Returns:
        (is_rate_limited: bool, message: str)
    """
    delays = []
    connection_failures = 0
    
    for attempt in range(3):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        start_time = time.time()
        try:
            # Intentionally fail with invalid credentials
            ssh.connect(
                hostname=hostname,
                username="__rate_limit_test__",
                password="__invalid__",
                port=port,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=10
            )
        except paramiko.AuthenticationException:
            # Expected - authentication failed as intended
            elapsed = time.time() - start_time
            delays.append(elapsed)
        except (paramiko.SSHException, OSError, EOFError) as e:
            # Connection was dropped/reset - strong indicator of rate limiting
            connection_failures += 1
            elapsed = time.time() - start_time
            delays.append(elapsed)
        except Exception as e:
            # Unexpected error
            return (False, f"Rate limit detection inconclusive: {str(e)}")
        finally:
            ssh.close()
        
        # Small delay between probes (100ms)
        if attempt < 2:
            time.sleep(0.1)
    
    # Analysis
    # 1. Check for connection drops
    if connection_failures >= 2:
        return (True, f"SSH rate limiting detected: {connection_failures}/3 connections dropped/reset")
    
    # 2. Check for exponential delay pattern
    if len(delays) == 3:
        # If each delay is significantly longer than the previous (>50% increase)
        if delays[1] > delays[0] * 1.5 and delays[2] > delays[1] * 1.5:
            return (True, f"SSH rate limiting detected: exponential delay pattern ({delays[0]:.2f}s → {delays[1]:.2f}s → {delays[2]:.2f}s)")
        
        # If any single auth attempt takes >5 seconds (artificial delay)
        if any(d > 5.0 for d in delays):
            return (True, f"SSH rate limiting detected: artificial delay (max {max(delays):.2f}s)")
    
    # No rate limiting detected
    avg_delay = sum(delays) / len(delays) if delays else 0
    return (False, f"No rate limiting detected (avg delay: {avg_delay:.2f}s)")


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
    target_url = config.get('target', '')
    parsed = urlparse(target_url if '://' in target_url else f'http://{target_url}')
    target = parsed.hostname or target_url.split(':')[0]
    
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
