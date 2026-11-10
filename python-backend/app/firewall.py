"""
L.O.G.S. — Windows Firewall Analyzer
Uses PowerShell via subprocess to query, analyze, and manage firewall rules.
Requires Administrator privileges for full functionality.
"""

import json
import logging
import subprocess
import sys
import time
from typing import Dict, List, Optional

logger = logging.getLogger("logs.firewall")

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_VALID_DIRECTIONS = {"Inbound", "Outbound"}
_VALID_ACTIONS = {"Allow", "Block"}
_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "Any"}
_VALID_PROFILES = {"Domain", "Private", "Public", "Any"}

# PowerShell 5.1 ConvertTo-Json serialises enum fields as integers.
# Normalise them to strings so the frontend never receives raw numbers.
_DIRECTION_MAP = {"1": "Inbound", "2": "Outbound"}
_ACTION_MAP    = {"2": "Allow", "4": "Block"}
_PROFILE_MAP   = {
    "1": "Domain", "2": "Private", "4": "Public",
    "2147483647": "Any", "4294967295": "Any", "-1": "Any",
}


def _normalise_rule(rule: Dict) -> Dict:
    """Coerce PowerShell enum integers to their string names in-place."""
    for key, mapping in (
        ("Direction", _DIRECTION_MAP),
        ("Action",    _ACTION_MAP),
        ("Profile",   _PROFILE_MAP),
    ):
        val = rule.get(key)
        if val is not None:
            rule[key] = mapping.get(str(val), str(val))

    # PowerShell 5.1 serialises the `enabled` enum as integer 1 (True) or 2 (False).
    # Normalise to a proper Python bool so the frontend always receives true/false.
    enabled_val = rule.get("Enabled")
    if enabled_val is not None:
        rule["Enabled"] = str(enabled_val).lower() in ("1", "true")

    return rule


def _choice(value: str, allowed: set[str], default: str) -> str:
    value = str(value or default)
    for allowed_value in allowed:
        if value.lower() == allowed_value.lower():
            return allowed_value
    raise ValueError(f"Invalid value '{value}'. Expected one of: {', '.join(sorted(allowed))}")


def _ps_quote(value: str) -> str:
    return str(value).replace("'", "''")


class FirewallAnalyzer:
    """
    Queries and analyzes Windows Firewall rules via PowerShell.

    Detects:
    - Disabled rules that should be reviewed
    - Duplicate rules (same display name)
    - Overly permissive inbound Allow/Any rules
    """

    _CACHE_TTL = 60  # seconds

    def __init__(self):
        self._rules_cache: Optional[List[Dict]] = None
        self._rules_cache_time: float = 0.0

    def _invalidate_cache(self):
        self._rules_cache = None
        self._rules_cache_time = 0.0

    def _run_powershell(self, command: str, timeout: int = 45) -> str:
        """Run a PowerShell command and return stdout. Raises on failure."""
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", command,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )
            if proc.returncode != 0:
                stderr = proc.stderr.strip()
                logger.warning(f"PowerShell stderr: {stderr[:300]}")
                if "access is denied" in stderr.lower() or "permissiondenied" in stderr.lower():
                    raise PermissionError(
                        "Access denied — restart L.O.G.S. as Administrator to modify firewall rules."
                    )
                raise RuntimeError(stderr[:300] if stderr else f"PowerShell exited with code {proc.returncode}")
            return proc.stdout.strip() if proc.stdout else ""
        except (PermissionError, RuntimeError):
            raise
        except subprocess.TimeoutExpired:
            raise RuntimeError("PowerShell command timed out.")
        except FileNotFoundError:
            raise RuntimeError(
                "PowerShell not found. This tool requires Windows with PowerShell."
            )
        except Exception as exc:
            raise RuntimeError(f"PowerShell error: {exc}")

    def get_firewall_rules(self) -> List[Dict]:
        """Retrieve all Windows Firewall rules as a list of dicts."""
        now = time.monotonic()
        if self._rules_cache is not None and (now - self._rules_cache_time) < self._CACHE_TTL:
            logger.debug("Returning cached firewall rules.")
            return self._rules_cache

        cmd = (
            "Get-NetFirewallRule | "
            "Select-Object DisplayName, Enabled, Direction, Action, Profile, "
            "DisplayGroup, Description, PolicyStoreSourceType | "
            "ConvertTo-Json -Depth 2 -Compress"
        )
        try:
            output = self._run_powershell(cmd)
        except Exception as exc:
            logger.error(f"Failed to retrieve firewall rules: {exc}")
            return []
        if not output:
            return []
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            data = [_normalise_rule(r) for r in data]
            logger.info(f"Retrieved {len(data)} firewall rules.")
            self._rules_cache = data
            self._rules_cache_time = time.monotonic()
            return data
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse firewall JSON: {exc}")
            return []

    def analyze(self) -> Dict:
        """
        Detect firewall misconfigurations.

        Returns:
            Dict with 'rules', 'issues', and 'total_rules'.
        """
        logger.info("Starting firewall analysis")
        rules = self.get_firewall_rules()
        issues: List[Dict] = []
        seen_names: Dict[str, int] = {}

        for rule in rules:
            name      = rule.get("DisplayName", "Unknown")
            enabled   = rule.get("Enabled", True)
            action    = str(rule.get("Action", ""))
            direction = str(rule.get("Direction", ""))
            profile   = str(rule.get("Profile", ""))

            # Check 1: Disabled rules
            if str(enabled).lower() in ("false", "0"):
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Disabled Rule",
                    "severity":      "Low",
                    "suggested_fix": f"Review and remove '{name}' if no longer needed.",
                })

            # Check 2: Duplicate names
            if name in seen_names:
                seen_names[name] += 1
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Duplicate Rule",
                    "severity":      "Medium",
                    "suggested_fix": f"Remove duplicate entry for '{name}' to avoid rule shadowing.",
                })
            else:
                seen_names[name] = 1

            # Check 3: Overly permissive inbound Allow on Any profile
            is_allow    = action == "Allow"
            is_inbound  = direction == "Inbound"
            is_any_prof = profile == "Any"

            if is_allow and is_inbound and is_any_prof:
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Overly Permissive (Any Profile)",
                    "severity":      "High",
                    "suggested_fix": f"Restrict '{name}' to Domain or Private profile only.",
                })

        logger.info(f"Analysis complete. {len(issues)} issue(s) in {len(rules)} rule(s).")
        return {"rules": rules, "issues": issues, "total_rules": len(rules)}

    def disable_rule(self, rule_name: str) -> bool:
        """Disable a firewall rule by display name."""
        safe_name = _ps_quote(rule_name)
        self._run_powershell(f"Disable-NetFirewallRule -DisplayName '{safe_name}'")
        self._invalidate_cache()
        logger.info(f"Disabled rule: '{rule_name}'")
        return True

    def remove_rule(self, rule_name: str) -> bool:
        """Permanently remove a firewall rule by display name."""
        safe_name = _ps_quote(rule_name)
        self._run_powershell(f"Remove-NetFirewallRule -DisplayName '{safe_name}'")
        self._invalidate_cache()
        logger.info(f"Removed rule: '{rule_name}'")
        return True

    def enable_rule(self, rule_name: str) -> bool:
        """Enable a firewall rule by display name."""
        safe_name = _ps_quote(rule_name)
        self._run_powershell(f"Enable-NetFirewallRule -DisplayName '{safe_name}'")
        self._invalidate_cache()
        logger.info(f"Enabled rule: '{rule_name}'")
        return True

    def create_rule(
        self,
        name: str,
        direction: str = "Inbound",
        action: str = "Block",
        protocol: str = "TCP",
        port: str = "Any",
        source_ip: str = "",
        profile: str = "Any",
        description: str = "",
    ) -> bool:
        """Create a new Windows Firewall rule via New-NetFirewallRule."""
        direction = _choice(direction, _VALID_DIRECTIONS, "Inbound")
        action = _choice(action, _VALID_ACTIONS, "Block")
        protocol = _choice(protocol, _VALID_PROTOCOLS, "TCP")
        profile = _choice(profile, _VALID_PROFILES, "Any")

        safe_name = _ps_quote(name)
        parts = [
            "New-NetFirewallRule",
            f"-DisplayName '{safe_name}'",
            f"-Direction {direction}",
            f"-Action {action}",
            "-Enabled True",
            f"-Profile {profile}",
        ]
        if protocol.lower() != "any":
            parts.append(f"-Protocol {protocol}")
            if port.lower() not in ("any", ""):
                parts.append(f"-LocalPort '{_ps_quote(port)}'")
        if source_ip.strip():
            parts.append(f"-RemoteAddress '{_ps_quote(source_ip.strip())}'")
        if description:
            safe_desc = _ps_quote(description)
            parts.append(f"-Description '{safe_desc}'")
        cmd = " ".join(parts)
        self._run_powershell(cmd)
        self._invalidate_cache()
        logger.info(f"Created rule: '{name}'")
        return True
