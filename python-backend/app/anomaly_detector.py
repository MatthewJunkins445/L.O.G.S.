"""
L.O.G.S. — Anomaly Detector Module
Compares current scan results against a saved baseline.

Rule-based checks:
  - New open ports not in baseline
  - Ports that closed since baseline

Statistical ML checks (requires >= 5 scan history entries):
  - Z-score deviation on per-feature rolling history
  - Flags features > 2.5 standard deviations above historical mean
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger("logs.anomaly_detector")

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_BASELINE_PATH     = os.path.join(_DATA_DIR, "baseline.json")
_SCAN_HISTORY_PATH = os.path.join(_DATA_DIR, "scan_history.json")

_FEATURE_NAMES = ["open ports", "risky ports", "critical ports", "protocol types"]
_ML_MIN_HISTORY = 5      # scans needed before statistical detection activates
_MAX_HISTORY    = 20     # rolling window cap
_Z_THRESHOLD    = 2.5    # standard deviations to flag


class AnomalyDetector:
    """
    Detects network anomalies by comparing the current scan to a saved baseline.

    The baseline is frozen at first scan and only cleared on explicit reset —
    it is NOT auto-updated on every scan, which would cause drift and suppress
    legitimate anomaly alerts after the first occurrence.

    A separate rolling history (last 20 scans) is used for statistical
    z-score detection, which activates once >= 5 scans are recorded.
    """

    def detect(self, current_scan: Dict) -> List[str]:
        """
        Run anomaly detection against the baseline.

        Returns:
            List of human-readable anomaly strings. Empty if none or no baseline.
        """
        anomalies: List[str] = []

        baseline = self._load_baseline()
        if not baseline:
            logger.info("No baseline — saving current scan as initial baseline.")
            self._save_baseline(current_scan)
            return []

        # ── Rule-based port comparison ──────────────────────────────────────
        baseline_open = {
            p["port"] for p in baseline.get("ports", []) if p.get("state") == "open"
        }
        current_open = {
            p["port"] for p in current_scan.get("ports", []) if p.get("state") == "open"
        }

        for port in sorted(current_open - baseline_open):
            msg = f"New open port detected: {port}"
            anomalies.append(msg)
            logger.warning(f"ANOMALY: {msg}")

        for port in sorted(baseline_open - current_open):
            msg = f"Port no longer open (was in baseline): {port}"
            anomalies.append(msg)
            logger.info(f"Change: {msg}")

        # ── Statistical ML detection ────────────────────────────────────────
        anomalies.extend(self._statistical_detect(current_scan))

        # Append to rolling history (does NOT modify the frozen baseline)
        self._append_scan_history(current_scan)

        return anomalies

    # ── Feature extraction ──────────────────────────────────────────────────

    def _build_feature_vector(self, scan: Dict) -> List[float]:
        ports       = scan.get("ports", [])
        open_ports  = [p for p in ports if p.get("state") == "open"]
        risky       = [p for p in open_ports if p.get("is_risky", False)]
        critical    = [p for p in open_ports if p.get("is_critical", False)]
        protocols   = {p.get("proto", "tcp") for p in open_ports}
        return [
            float(len(open_ports)),
            float(len(risky)),
            float(len(critical)),
            float(len(protocols)),
        ]

    # ── Statistical detection ────────────────────────────────────────────────

    def _statistical_detect(self, current_scan: Dict) -> List[str]:
        """
        Z-score check: flag features that are > _Z_THRESHOLD std devs above
        the historical mean. Requires at least _ML_MIN_HISTORY prior scans.
        """
        history = self._load_scan_history()
        if len(history) < _ML_MIN_HISTORY:
            logger.debug(
                f"Statistical detection skipped: {len(history)}/{_ML_MIN_HISTORY} scans in history"
            )
            return []

        try:
            import numpy as np

            curr_vec = self._build_feature_vector(current_scan)
            X    = np.array(history)
            mean = X.mean(axis=0)
            std  = X.std(axis=0)

            results = []
            for val, m, s, name in zip(curr_vec, mean, std, _FEATURE_NAMES):
                if s < 0.5:
                    continue  # not enough variance — skip this feature
                z = (val - m) / s
                if z > _Z_THRESHOLD:
                    results.append(
                        f"Statistical anomaly: {name} ({int(val)}) is significantly "
                        f"above your recent average ({m:.1f})"
                    )

            if results:
                logger.warning(f"Statistical anomalies: {results}")
            return results

        except Exception as exc:
            logger.warning(f"Statistical anomaly detection failed: {exc}")
            return []

    # ── Scan history (rolling, used for ML only) ─────────────────────────────

    def _load_scan_history(self) -> List[List[float]]:
        try:
            if os.path.exists(_SCAN_HISTORY_PATH):
                with open(_SCAN_HISTORY_PATH, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception as exc:
            logger.error(f"Could not load scan history: {exc}")
        return []

    def _append_scan_history(self, scan: Dict) -> None:
        history = self._load_scan_history()
        history.append(self._build_feature_vector(scan))
        if len(history) > _MAX_HISTORY:
            history = history[-_MAX_HISTORY:]
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with open(_SCAN_HISTORY_PATH, "w", encoding="utf-8") as fh:
                json.dump(history, fh)
        except Exception as exc:
            logger.error(f"Could not save scan history: {exc}")

    # ── Frozen baseline (rule-based reference) ────────────────────────────────

    def _load_baseline(self) -> Optional[Dict]:
        try:
            if os.path.exists(_BASELINE_PATH) and os.path.getsize(_BASELINE_PATH) > 5:
                with open(_BASELINE_PATH, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception as exc:
            logger.error(f"Could not load baseline: {exc}")
        return None

    def _save_baseline(self, scan: Dict) -> None:
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with open(_BASELINE_PATH, "w", encoding="utf-8") as fh:
                json.dump(scan, fh, indent=2)
            logger.info("Baseline saved.")
        except Exception as exc:
            logger.error(f"Could not save baseline: {exc}")

    def reset_baseline(self) -> None:
        """Delete the baseline and scan history so the next scan starts fresh."""
        for path in (_BASELINE_PATH, _SCAN_HISTORY_PATH):
            try:
                if os.path.exists(path):
                    os.remove(path)
                    logger.info(f"Removed: {path}")
            except Exception as exc:
                logger.error(f"Could not remove {path}: {exc}")
