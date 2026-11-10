"""
L.O.G.S. — Network Scanner Module
Scans localhost using python-nmap for open ports and services.
Only defensive, non-aggressive scans are performed.
"""

import json
import logging
import os
from typing import Dict

from app.constants import CRITICAL_PORTS, RISKY_PORTS

logger = logging.getLogger("logs.scanner")


# ---------------------------------------------------------------------------
# Scan Profile Definitions
# ---------------------------------------------------------------------------

SCAN_PROFILES = {
    "quick": {
        "label":       "Quick Scan",
        "description": "Top 100 common ports — fast (~5–10 sec)",
        "args":        "-sV --version-intensity 2 -T4 --max-retries 1 --open --top-ports 100",
        "port_desc":   "top 100",
    },
    "standard": {
        "label":       "Standard Scan",
        "description": "Ports 1–10 000 with version detection (~30–60 sec)",
        "args":        "-sV --version-intensity 2 -T4 --max-retries 1 --open -p 1-10000",
        "port_desc":   "1–10 000",
    },
    "full": {
        "label":       "Full Scan",
        "description": "All 65 535 ports — thorough (~2–5 min)",
        "args":        "-sV --version-intensity 2 -T4 --max-retries 1 --open -p 1-65535",
        "port_desc":   "1–65 535",
    },
}

DEFAULT_PROFILE = "standard"

_BASELINE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "baseline.json"
)


class NetworkScanner:
    """
    Handles localhost network scanning using python-nmap.

    Security policy:
    - Only scans 127.0.0.1 (localhost)
    - No aggressive scan flags (-A, --script, etc.)
    - Uses service version detection only

    Supports three scan profiles: quick, standard, full.
    """

    # Friendly descriptions for well-known ports
    PORT_DESCRIPTIONS = {
        21:   "FTP - File Transfer",
        22:   "SSH - Secure Shell",
        23:   "Telnet (unencrypted)",
        25:   "SMTP - Email",
        80:   "HTTP - Web",
        110:  "POP3 - Email",
        143:  "IMAP - Email",
        443:  "HTTPS - Secure Web",
        445:  "SMB - File Sharing (WannaCry vector)",
        3306: "MySQL Database",
        3389: "RDP - Remote Desktop",
        5432: "PostgreSQL Database",
        5900: "VNC - Remote Desktop",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
    }

    def __init__(self):
        """Initialize the scanner, loading nmap with error handling."""
        self.nm = None
        self._init_nmap()

    def _init_nmap(self):
        """
        Initialize the nmap PortScanner.

        Raises:
            RuntimeError: If python-nmap or nmap binary is missing.
        """
        try:
            import nmap
            self.nm = nmap.PortScanner()
            logger.info("nmap PortScanner initialized successfully")
        except ImportError:
            raise RuntimeError(
                "python-nmap is not installed.\n"
                "Fix: pip install python-nmap"
            )
        except nmap.PortScannerError:
            raise RuntimeError(
                "nmap binary not found on PATH.\n"
                "Download from: https://nmap.org/download.html\n"
                "Add nmap to your system PATH after installing."
            )

    def scan_localhost(self, profile: str = DEFAULT_PROFILE) -> Dict:
        """
        Perform a non-aggressive service scan on localhost.

        Args:
            profile: One of 'quick', 'standard', or 'full'.
                     Defaults to DEFAULT_PROFILE ('standard').

        Returns:
            Dict with keys:
                target (str):      Always '127.0.0.1'
                ports (list):      List of port detail dicts
                os_guess (str):    Best OS guess or 'Unknown'
                scan_args (str):   nmap arguments used
                profile (str):     Profile key that was used
                profile_label (str): Human-readable profile name
        """
        target = "127.0.0.1"

        # Resolve the profile — fall back to standard if invalid
        prof = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
        scan_args    = prof["args"]
        profile_key  = profile if profile in SCAN_PROFILES else DEFAULT_PROFILE

        logger.info(
            f"Starting scan on {target} | profile={profile_key} "
            f"({prof['label']}) | args: {scan_args}"
        )

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
        except Exception as exc:
            raise RuntimeError(
                f"nmap scan failed: {exc}\n"
                "Ensure nmap is installed and the application is run as Administrator."
            )

        results: Dict = {
            "target":        target,
            "ports":         [],
            "os_guess":      "Unknown",
            "scan_args":     scan_args,
            "profile":       profile_key,
            "profile_label": prof["label"],
        }

        if target not in self.nm.all_hosts():
            logger.warning("Localhost not found in scan results - no open ports detected.")
            return results

        host_data = self.nm[target]

        # OS guess (best effort - requires elevated privileges)
        try:
            if host_data.get("osmatch"):
                results["os_guess"] = host_data["osmatch"][0].get("name", "Unknown")
        except Exception:
            pass

        # Collect port information
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                info = host_data[proto][port]

                service_name = info.get("name", "unknown")
                product     = info.get("product", "")
                version     = info.get("version", "")
                service_full = " ".join(filter(None, [service_name, product, version]))

                # Override with friendly description if known
                friendly = self.PORT_DESCRIPTIONS.get(port, "")
                display_service = friendly if friendly else service_full

                results["ports"].append({
                    "port":        port,
                    "proto":       proto,
                    "state":       info.get("state", "unknown"),
                    "service":     display_service or service_name,
                    "version":     service_full,   # product + version from nmap -sV
                    "is_risky":    port in RISKY_PORTS,
                    "is_critical": port in CRITICAL_PORTS,
                })

        open_count = sum(1 for p in results["ports"] if p["state"] == "open")
        logger.info(f"Scan complete. {open_count} open port(s) found.")

        self._save_initial_baseline(results)
        return results

    def _save_initial_baseline(self, results: Dict):
        """
        Save scan results as baseline ONLY if no baseline exists yet.

        Args:
            results: Scan results to potentially save.
        """
        try:
            os.makedirs(os.path.dirname(_BASELINE_PATH), exist_ok=True)

            if not os.path.exists(_BASELINE_PATH) or os.path.getsize(_BASELINE_PATH) < 5:
                with open(_BASELINE_PATH, "w", encoding="utf-8") as fh:
                    json.dump(results, fh, indent=2)
                logger.info("Initial baseline saved.")
        except Exception as exc:
            logger.warning(f"Could not save baseline: {exc}")
