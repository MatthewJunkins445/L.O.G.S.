"""
L.O.G.S. — Linux Firewall Analyzer
Uses iptables via subprocess to query, analyze, and manage firewall rules.
Uses pkexec for GUI password prompt when elevated privileges are needed.
"""

import json
import logging
import subprocess
import re
import os
import shlex
from typing import Dict, List, Optional, Union

logger = logging.getLogger("logs.firewall")


class FirewallAnalyzer:
    """
    Queries and analyzes Linux iptables firewall rules.

    Detects:
    - Rules without specific source restrictions (0.0.0.0/0)
    - Duplicate rules (same port/protocol/action)
    - Overly permissive ACCEPT rules on all interfaces
    
    Uses pkexec for GUI password prompts when root access is needed.
    """

    def __init__(self):
        """Initialize and check for privilege escalation tools."""
        self.privilege_tool = self._detect_privilege_tool()
        logger.info(f"Using privilege escalation: {self.privilege_tool}")

    def _detect_privilege_tool(self) -> str:
        """
        Detect which privilege escalation tool is available.
        
        Priority:
        1. pkexec (GUI prompt, best for desktop apps)
        2. sudo (terminal prompt)
        3. none (already root or no tools available)
        """
        # Check if already root
        if os.geteuid() == 0:
            logger.info("Running as root, no privilege escalation needed")
            return "none"
        
        # Check for pkexec (GUI password prompt)
        try:
            subprocess.run(["which", "pkexec"], 
                          capture_output=True, 
                          check=True)
            return "pkexec"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Check for sudo
        try:
            subprocess.run(["which", "sudo"], 
                          capture_output=True, 
                          check=True)
            return "sudo"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        logger.warning("No privilege escalation tool found")
        return "none"

    def _run_iptables(
        self,
        command: Union[str, List[str]],
        timeout: int = 30,
        needs_root: bool = True,
    ) -> Optional[str]:
        """
        Run an iptables command with privilege escalation.
        
        Args:
            command: iptables command to run
            timeout: Command timeout in seconds
            needs_root: Whether this command requires root privileges
        
        Returns:
            Command output or None on failure
        """
        try:
            cmd_list = command[:] if isinstance(command, list) else shlex.split(command)
            
            # Add privilege escalation if needed
            if needs_root and self.privilege_tool != "none":
                if self.privilege_tool == "pkexec":
                    # pkexec shows GUI password prompt
                    cmd_list = ["pkexec"] + cmd_list
                elif self.privilege_tool == "sudo":
                    # Try non-interactive sudo first, fall back to interactive
                    try:
                        cmd_list = ["sudo", "-n"] + cmd_list  # -n = non-interactive
                        proc = subprocess.run(
                            cmd_list,
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                        )
                        if proc.returncode != 0:
                            # Non-interactive failed, try interactive sudo
                            raise subprocess.CalledProcessError(proc.returncode, cmd_list)
                    except subprocess.CalledProcessError:
                        # Fall back to interactive sudo (terminal prompt)
                        base_cmd = command[:] if isinstance(command, list) else shlex.split(command)
                        cmd_list = ["sudo"] + base_cmd
            
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            
            if proc.returncode != 0:
                if proc.stderr.strip():
                    logger.warning(f"iptables stderr: {proc.stderr.strip()[:200]}")
                    
                    # Check for common errors
                    if "not authorized" in proc.stderr.lower():
                        raise RuntimeError(
                            "Not authorized to run iptables.\n"
                            "Install PolicyKit: sudo apt install policykit-1"
                        )
                    elif "authentication" in proc.stderr.lower():
                        raise RuntimeError(
                            "Authentication failed. Please try again."
                        )
                
                return None
            
            return proc.stdout.strip() if proc.stdout else ""
        
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out.")
            return None
        except FileNotFoundError:
            raise RuntimeError(
                "iptables not found. This tool requires Linux with iptables installed.\n"
                "Install: sudo apt install iptables"
            )
        except Exception as exc:
            logger.error(f"iptables error: {exc}")
            raise

    def get_firewall_rules(self) -> List[Dict]:
        """Retrieve all iptables firewall rules as a list of dicts."""
        # List rules doesn't need root on most systems, but some require it
        cmd = "iptables -L INPUT -n -v --line-numbers"
        
        try:
            output = self._run_iptables(cmd, needs_root=True)
        except RuntimeError:
            # If pkexec/sudo fails, try without privileges (read-only might work)
            logger.warning("Failed with privileges, trying without...")
            output = self._run_iptables(cmd, needs_root=False)
        
        if not output:
            return []
        
        rules = []
        lines = output.split('\n')
        
        # Skip header lines (first 2 lines)
        for line in lines[2:]:
            if not line.strip():
                continue
            
            # Parse iptables output format:
            # num  pkts bytes target     prot opt in     out     source               destination
            # 1    0     0    ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
            
            parts = line.split()
            if len(parts) < 9:
                continue
            
            rule_num = parts[0]
            target = parts[3]  # ACCEPT, DROP, REJECT
            protocol = parts[4]  # tcp, udp, icmp, all
            in_interface = parts[6]
            out_interface = parts[7]
            source = parts[8]
            destination = parts[9] if len(parts) > 9 else "0.0.0.0/0"
            
            # Extract port from the rest of the line if present
            port = None
            rest = ' '.join(parts[10:]) if len(parts) > 10 else ""
            port_match = re.search(r'dpt:(\d+)', rest)
            if port_match:
                port = port_match.group(1)
            
            # Build rule name similar to Windows format
            rule_name = f"{target} {protocol}"
            if port:
                rule_name += f" port {port}"
            if source != "0.0.0.0/0":
                rule_name += f" from {source}"
            
            rules.append({
                "DisplayName": rule_name,
                "RuleNumber": rule_num,
                "Enabled": True,  # iptables rules are always enabled if they exist
                "Direction": "Inbound",  # INPUT chain is inbound
                "Action": target,
                "Protocol": protocol,
                "Profile": "Any",  # iptables doesn't have profile concept
                "Source": source,
                "Destination": destination,
                "Port": port,
                "Interface": in_interface,
                "Description": rest,
            })
        
        logger.info(f"Retrieved {len(rules)} firewall rules.")
        return rules

    def analyze(self) -> Dict:
        """
        Detect firewall misconfigurations.

        Returns:
            Dict with 'rules', 'issues', and 'total_rules'.
        """
        logger.info("Starting firewall analysis")
        rules = self.get_firewall_rules()
        issues: List[Dict] = []
        seen_signatures: Dict[str, int] = {}

        for rule in rules:
            name = rule.get("DisplayName", "Unknown")
            action = rule.get("Action", "")
            source = rule.get("Source", "0.0.0.0/0")
            port = rule.get("Port")
            protocol = rule.get("Protocol", "")
            
            # Create signature for duplicate detection
            signature = f"{action}_{protocol}_{port}_{source}"
            
            # Check 1: Duplicate rules
            if signature in seen_signatures:
                seen_signatures[signature] += 1
                issues.append({
                    "rule_name": name,
                    "issue_type": "Duplicate Rule",
                    "severity": "Medium",
                    "suggested_fix": f"Remove duplicate entry for '{name}' to avoid confusion.",
                })
            else:
                seen_signatures[signature] = 1
            
            # Check 2: Overly permissive ACCEPT rules from anywhere
            if action == "ACCEPT" and source == "0.0.0.0/0":
                # Exception: loopback and established connections are OK
                if port and int(port) not in [22]:  # SSH is common, don't flag it as high
                    issues.append({
                        "rule_name": name,
                        "issue_type": "Overly Permissive (Accept from Anywhere)",
                        "severity": "High",
                        "suggested_fix": f"Restrict '{name}' to specific source IPs instead of 0.0.0.0/0.",
                    })
            
            # Check 3: Critical ports exposed
            critical_ports = {21, 23, 445, 3389, 5900}
            if port and int(port) in critical_ports and action == "ACCEPT":
                issues.append({
                    "rule_name": name,
                    "issue_type": "Critical Port Exposed",
                    "severity": "High",
                    "suggested_fix": f"Port {port} is a high-risk service. Consider blocking or restricting access.",
                })
            
            # Check 4: Default policy check (too permissive)
            if name.startswith("ACCEPT all") and source == "0.0.0.0/0":
                issues.append({
                    "rule_name": name,
                    "issue_type": "Default Accept All",
                    "severity": "Medium",
                    "suggested_fix": "Default ACCEPT policy is permissive. Consider DROP with explicit allow rules.",
                })

        logger.info(f"Analysis complete. {len(issues)} issue(s) in {len(rules)} rule(s).")
        return {"rules": rules, "issues": issues, "total_rules": len(rules)}

    def disable_rule(self, rule_name: str) -> bool:
        """
        Disable (delete) a firewall rule by rule number or name.
        Note: iptables doesn't have "disable", only delete.
        Shows GUI password prompt via pkexec if available.
        """
        # Extract rule number from name if it's in format "Rule #N: ..."
        # Or try to find matching rule and delete it
        rules = self.get_firewall_rules()
        
        for rule in rules:
            if rule["DisplayName"] == rule_name:
                rule_num = rule["RuleNumber"]
                cmd = f"iptables -D INPUT {rule_num}"
                result = self._run_iptables(cmd, needs_root=True)
                if result is None:
                    logger.error(f"Failed to delete rule '{rule_name}'")
                    return False
                logger.info(f"Deleted rule: '{rule_name}' (rule #{rule_num})")
                return True
        
        logger.error(f"Rule '{rule_name}' not found")
        return False

    def remove_rule(self, rule_name: str) -> bool:
        """Permanently remove a firewall rule (same as disable for iptables)."""
        return self.disable_rule(rule_name)

    def enable_rule(self, rule_name: str) -> bool:
        """
        Enable a firewall rule.
        Note: iptables doesn't have enable/disable - rules are active or deleted.
        This is a no-op for compatibility with Windows version.
        """
        logger.warning("iptables rules cannot be 'enabled' - they are always active.")
        return True

    def create_rule(
        self,
        name: str,
        direction: str = "Inbound",
        action: str = "DROP",
        protocol: str = "tcp",
        port: str = "Any",
        source_ip: str = "",
        profile: str = "Any",
        description: str = "",
    ) -> bool:
        """
        Create a new iptables firewall rule.
        Shows GUI password prompt via pkexec if available.
        """
        
        # Build iptables command
        # Example: iptables -A INPUT -p tcp --dport 8080 -j DROP
        
        cmd_parts = ["iptables", "-A", "INPUT"]
        
        if protocol.lower() != "any":
            cmd_parts.extend(["-p", protocol.lower()])
            
            if port.lower() not in ("any", ""):
                cmd_parts.extend(["--dport", port])

        if source_ip.strip():
            cmd_parts.extend(["-s", source_ip.strip()])
        
        # Action mapping
        action_map = {
            "Block": "DROP",
            "Allow": "ACCEPT",
            "DROP": "DROP",
            "ACCEPT": "ACCEPT",
        }
        target = action_map.get(action, "DROP")
        cmd_parts.extend(["-j", target])
        
        # Add comment if description provided (requires iptables comment module)
        if description:
            cmd_parts.extend(["-m", "comment", "--comment", description])
        
        result = self._run_iptables(cmd_parts, needs_root=True)
        
        if result is None:
            logger.error(f"Failed to create rule '{name}'")
            return False
        
        logger.info(f"Created rule: '{name}' - {' '.join(shlex.quote(part) for part in cmd_parts)}")
        return True

