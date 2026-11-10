"""
L.O.G.S. — Risk Scoring Engine
Calculates a 0-100% risk score from scan and firewall results.

Scoring weights:
  - Critical port open (21, 22, 23, 445, 3389): +20 each
  - Risky port open (HTTP, DB, VNC, etc.):       +15 each
  - Firewall High severity issue:                +15 each
  - Firewall Medium severity issue:              +10 each
  - Firewall Low severity issue:                 + 2 each
  - Score is capped at 100.
"""

import logging
from typing import Dict

from app.constants import CRITICAL_PORTS, RISKY_PORTS

logger = logging.getLogger("logs.risk_engine")


class RiskEngine:
    """
    Calculates a composite risk percentage from port and firewall scan data.

    Usage:
        engine = RiskEngine()
        percent = engine.calculate_risk(scan_results, firewall_results)
    """

    CRITICAL_PORT_SCORE  = 20
    RISKY_PORT_SCORE     = 15

    FIREWALL_SEVERITY_SCORES = {
        "Critical": 15,
        "High":     10,
        "Medium":    7,
        "Low":       2,
    }

    def calculate_risk(self, scan_results: Dict, firewall_results: Dict) -> int:
        """
        Calculate overall risk percentage.

        Args:
            scan_results:     Output from NetworkScanner.scan_localhost()
            firewall_results: Output from FirewallAnalyzer.analyze()

        Returns:
            Integer risk percentage in range [0, 100].
        """
        score = 0
        breakdown = []

        # --- Port-based scoring ---
        for port_info in scan_results.get("ports", []):
            if port_info.get("state") != "open":
                continue

            port = port_info.get("port", 0)

            if port in CRITICAL_PORTS:
                score += self.CRITICAL_PORT_SCORE
                breakdown.append(f"+{self.CRITICAL_PORT_SCORE} critical port {port}")
            elif port in RISKY_PORTS or port_info.get("is_risky", False):
                score += self.RISKY_PORT_SCORE
                breakdown.append(f"+{self.RISKY_PORT_SCORE} risky port {port}")

        # --- Firewall issue scoring ---
        for issue in firewall_results.get("issues", []):
            severity = issue.get("severity", "Low")
            issue_score = self.FIREWALL_SEVERITY_SCORES.get(
                severity, self.FIREWALL_SEVERITY_SCORES["Low"]
            )
            score += issue_score
            breakdown.append(f"+{issue_score} firewall {severity}: {issue.get('rule_name', '')[:30]}")

        final = min(score, 100)

        logger.info(f"Risk score: {final}%  (raw={score})")
        for item in breakdown[:10]:
            logger.debug(f"  {item}")
        if len(breakdown) > 10:
            logger.debug(f"  ... and {len(breakdown) - 10} more")

        return final

    def get_risk_level(self, percent: int) -> str:
        """Map percentage to a human-readable risk level."""
        if percent <= 30:
            return "Low"
        elif percent <= 70:
            return "Medium"
        return "High"

    def get_remediation_hints(self, scan_results: Dict, firewall_results: Dict) -> list:
        """Generate a list of actionable remediation suggestions."""
        hints = []
        open_ports = {
            p["port"] for p in scan_results.get("ports", []) if p.get("state") == "open"
        }

        suggestions = {
            3389: "Disable RDP (port 3389) or restrict to VPN/specific IPs via firewall.",
            445:  "Block SMB (port 445) from external access - critical WannaCry/EternalBlue vector.",
            22:   "Restrict SSH (port 22) to key-based auth and specific source IPs.",
            21:   "Disable FTP (port 21) and use SFTP instead - FTP transmits credentials in plaintext.",
            23:   "Disable Telnet (port 23) immediately - completely unencrypted protocol.",
            5900: "Restrict or disable VNC (port 5900) - use encrypted remote access instead.",
        }

        for port, hint in suggestions.items():
            if port in open_ports:
                hints.append(hint)

        for issue in firewall_results.get("issues", []):
            if issue.get("severity") in ("High", "Critical"):
                fix = issue.get("suggested_fix", "").strip()
                if fix:
                    hints.append(f"Firewall: {fix}")

        return hints
