"""
Background threads for live monitoring and initial baseline collection.

Status lifecycle:
  needs_baseline  → no model on disk; user must run setup
  collecting_baseline → baseline capture in progress
  stopped         → model exists, monitor idle
  starting        → monitor thread spinning up
  running         → monitor actively analyzing traffic
  error           → unrecoverable failure
"""
import threading
import time
import logging
import os
from collections import deque

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from app.ml_config import (
    WINDOW_SIZE, CONTAMINATION, SETUP_BASELINE_WINDOWS,
    MODEL_PATH, USER_BASELINE_PATH,
    NEW_BATCH_OUTLIER_FRACTION, COMBINED_OUTLIER_FRACTION,
    MAX_BASELINE_WINDOWS, BEST_WINDOW_COUNT, RECENT_WINDOW_COUNT, MODELS_DIR,
)
from app.ml_model import AnomalyModel, FEATURE_NAMES
from app.capture import get_interface, capture_window, get_local_ip
from app.features import extract_features
from app.notifier import send_monitor_alert_notification

logger = logging.getLogger("logs.monitor")

FEATURE_LABELS = {
    "syn_count": "SYN Packets",
    "syn_ratio": "SYN Ratio",
    "connection_count": "Connection Attempts",
    "unique_destination_ports": "Targeted Ports",
    "bytes_per_sec": "Traffic Rate",
    "protocol_diversity": "Protocol Variety",
    "tcp_ratio": "TCP Ratio",
    "udp_ratio": "UDP Ratio",
    "total_packets": "Total Packets",
    "total_bytes": "Total Bytes",
    "mean_len": "Avg Packet Size",
    "packets_per_sec": "Packets/sec",
    "avg_packets_per_connection": "Pkts/Connection",
    "avg_bytes_per_connection": "Bytes/Connection",
    "avg_packets_per_port": "Pkts/Port",
}

PORT_WEIGHTS = {
    5353: 0.03, 443: 0.40, 80: 0.50,
    67: 0.30, 68: 0.30, 138: 0.30, 137: 0.30,
}

BRUTE_FORCE_PORTS = {21, 22, 23, 25, 110, 143, 445}
CLIENT_PORT_START = 32768
COMMON_SERVICE_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375,
    2376, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 8000,
    8080, 8443, 8888, 9000, 9200, 9300, 27017,
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _is_likely_service_port(port):
    if port is None:
        return False
    return port in COMMON_SERVICE_PORTS or 0 < port < CLIENT_PORT_START


def _select_service_port(packet, local_ip):
    src = packet.get("src")
    dst = packet.get("dst")
    sport = packet.get("sport")
    dport = packet.get("dport")

    if sport is None and dport is None:
        return None

    if local_ip:
        if dst == local_ip:
            candidates = (dport, sport)
        elif src == local_ip:
            candidates = (dport, sport)
        else:
            return None
    else:
        candidates = (dport, sport)

    for port in candidates:
        if _is_likely_service_port(port):
            return port
    return None


def _get_scanner_ips(packets, local_ip, min_syns=5):
    """
    Return source IPs that sent >= min_syns SYN packets to this machine,
    sorted by SYN count descending. Catches both port scans (many ports,
    few SYNs each) and brute-force (one port, many SYNs).
    Skips loopback, link-local, and the machine's own IP.
    """
    ip_syns = {}
    ip_ports = {}
    for packet in packets:
        if packet.get("syn", 0) != 1:
            continue
        dst = packet.get("dst")
        if local_ip and dst != local_ip:
            continue
        src = packet.get("src")
        if not src:
            continue
        if (src.startswith("127.") or src.startswith("169.254.")
                or src == local_ip):
            continue
        ip_syns[src] = ip_syns.get(src, 0) + 1
        dport = packet.get("dport")
        if dport:
            ip_ports.setdefault(src, set()).add(dport)

    results = [
        {"ip": ip, "syn_count": count, "port_count": len(ip_ports.get(ip, set()))}
        for ip, count in ip_syns.items()
        if count >= min_syns
    ]
    results.sort(key=lambda x: x["syn_count"], reverse=True)
    return results[:3]


def _get_targeted_ports(packets, local_ip):
    port_counts = {}
    syn_port_counts = {}
    for packet in packets:
        service_port = _select_service_port(packet, local_ip)
        if service_port is None:
            continue
        port_counts[service_port] = port_counts.get(service_port, 0) + 1
        if packet.get("syn", 0) == 1:
            syn_port_counts[service_port] = syn_port_counts.get(service_port, 0) + 1

    port_scores = []
    for service_port, count in port_counts.items():
        syn_c = syn_port_counts.get(service_port, 0)
        weight = PORT_WEIGHTS.get(service_port, 1.0)
        port_scores.append((service_port, (count + syn_c * 2) * weight))
    port_scores.sort(key=lambda x: x[1], reverse=True)
    return port_scores[:5]


_F = {name: idx for idx, name in enumerate(FEATURE_NAMES)}


def _detect_attack_type(features, targeted_ports):
    if not features or len(features) < 15:
        return ""
    syn_count                = features[_F["syn_count"]]
    connection_count         = features[_F["connection_count"]]
    unique_destination_ports = features[_F["unique_destination_ports"]]
    syn_ratio                = features[_F["syn_ratio"]]
    avg_packets_per_port     = features[_F["avg_packets_per_port"]]
    top3 = sum(s for _, s in targeted_ports[:3])
    top1 = targeted_ports[0][1] if targeted_ports else 0

    if syn_count >= 100 and syn_ratio >= 0.60 and (top1 >= 100 or top3 >= 150):
        return "POSSIBLE SYN FLOOD"
    for port, score in targeted_ports:
        if (port in BRUTE_FORCE_PORTS
                and (syn_count >= 40 or connection_count >= 30)
                and unique_destination_ports <= 10 and top3 >= 50):
            return "POSSIBLE BRUTE FORCE"
    if unique_destination_ports >= 15 and avg_packets_per_port <= 3 and syn_ratio >= 0.30 and top3 < 150:
        return "POSSIBLE PORT SCAN"
    return ""


def _clean_windows(windows, outlier_fraction):
    X = np.array(windows)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    clf = IsolationForest(contamination=outlier_fraction, n_estimators=100, random_state=42)
    clf.fit(X_scaled)
    preds = clf.predict(X_scaled)
    scores = clf.decision_function(X_scaled)
    scored = [(w, s) for w, p, s in zip(windows, preds, scores) if p == 1]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def _build_hybrid_baseline(scored_combined, cleaned_new):
    baseline = []
    seen = set()
    recent_tuples = {tuple(w) for w in cleaned_new}

    for w, _ in scored_combined:
        if len(baseline) >= BEST_WINDOW_COUNT:
            break
        key = tuple(w)
        if key not in seen:
            baseline.append(w)
            seen.add(key)

    recent_added = 0
    for w, _ in scored_combined:
        if recent_added >= RECENT_WINDOW_COUNT:
            break
        key = tuple(w)
        if key in recent_tuples and key not in seen:
            baseline.append(w)
            seen.add(key)
            recent_added += 1

    for w, _ in scored_combined:
        if len(baseline) >= MAX_BASELINE_WINDOWS:
            break
        key = tuple(w)
        if key not in seen:
            baseline.append(w)
            seen.add(key)

    return baseline


def _model_exists():
    return os.path.exists(MODEL_PATH) and os.path.exists(USER_BASELINE_PATH)


# ---------------------------------------------------------------------------
# Main state object — single instance shared by all endpoints
# ---------------------------------------------------------------------------

class MonitorState:
    """
    Holds all runtime state for both baseline collection and live monitoring.
    Thread-safe via self._lock.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_event = threading.Event()

        # Derived from disk on startup
        self.status = "needs_baseline" if not _model_exists() else "stopped"
        self.windows_analyzed = 0
        self.alerts = deque(maxlen=50)
        self.error_message = ""

        # Baseline collection progress
        self.baseline_current = 0
        self.baseline_total = SETUP_BASELINE_WINDOWS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_state(self):
        with self._lock:
            return {
                "status": self.status,
                "windows_analyzed": self.windows_analyzed,
                "alerts": list(self.alerts),
                "error": self.error_message,
                "baseline_progress": {
                    "current": self.baseline_current,
                    "total": self.baseline_total,
                },
            }

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()
        return {"success": True}

    def _thread_alive(self):
        return self._thread is not None and self._thread.is_alive()

    # --- Baseline collection ---

    def start_baseline(self):
        with self._lock:
            if self.status == "collecting_baseline":
                return {"success": False, "message": "Baseline collection already running"}
            if self.status in ("running", "starting"):
                return {"success": False, "message": "Stop the monitor before re-collecting baseline"}
            if self._thread_alive():
                return {"success": False, "message": "Previous monitoring task is still stopping"}

        os.makedirs(MODELS_DIR, exist_ok=True)
        self._stop_event.clear()
        with self._lock:
            self.baseline_current = 0
            self.status = "collecting_baseline"
            self.error_message = ""

        self._thread = threading.Thread(target=self._collect_baseline, daemon=True)
        self._thread.start()
        return {"success": True, "message": "Baseline collection started"}

    def reset_baseline(self):
        """Delete saved model so the user can redo the setup scan."""
        self._stop_event.set()
        for path in (MODEL_PATH, USER_BASELINE_PATH):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                logger.warning(f"Could not remove {path}: {e}")
        with self._lock:
            self.status = "needs_baseline"
            self.alerts.clear()
            self.windows_analyzed = 0
            self.baseline_current = 0
            self.error_message = ""
        return {"success": True, "message": "Baseline reset. Please run setup again."}

    # --- Live monitoring ---

    def start_monitor(self):
        with self._lock:
            if self.status == "running":
                return {"success": False, "message": "Monitor is already running"}
            if self.status == "needs_baseline":
                return {"success": False, "message": "Run baseline setup first"}
            if self.status == "collecting_baseline":
                return {"success": False, "message": "Baseline collection in progress"}
            if self._thread_alive():
                return {"success": False, "message": "Previous monitoring task is still stopping"}

        self._stop_event.clear()
        with self._lock:
            self.status = "starting"
            self.error_message = ""

        self._thread = threading.Thread(target=self._run_monitor, daemon=True)
        self._thread.start()
        return {"success": True, "message": "Monitor started"}

    def stop_monitor(self):
        self._stop_event.set()
        with self._lock:
            if self.status in ("running", "starting"):
                self.status = "stopping"
        return {"success": True, "message": "Monitor stopping"}

    # ------------------------------------------------------------------
    # Background threads
    # ------------------------------------------------------------------

    def _collect_baseline(self):
        try:
            interface = get_interface()
        except Exception as exc:
            logger.error(f"Could not get network interface for baseline: {exc}")
            with self._lock:
                self.status = "error"
                self.error_message = str(exc)
            return
        logger.info(f"Collecting baseline on {interface} ({SETUP_BASELINE_WINDOWS} windows)")

        raw_windows = []
        consecutive_empty = 0
        MAX_CONSECUTIVE_EMPTY = 3

        while len(raw_windows) < SETUP_BASELINE_WINDOWS and not self._stop_event.is_set():
            try:
                packets = capture_window(interface, WINDOW_SIZE)
                features = extract_features(packets, WINDOW_SIZE)
                if not features:
                    consecutive_empty += 1
                    logger.warning(f"Empty capture window ({consecutive_empty}/{MAX_CONSECUTIVE_EMPTY})")
                    if consecutive_empty >= MAX_CONSECUTIVE_EMPTY:
                        with self._lock:
                            self.status = "error"
                            self.error_message = (
                                f"No network traffic captured on interface '{interface}'. "
                                "Ensure the app is running as Administrator and your "
                                "network adapter is active."
                            )
                        return
                    continue
                consecutive_empty = 0
                raw_windows.append(features)
                with self._lock:
                    self.baseline_current = len(raw_windows)
                logger.info(f"Baseline window {len(raw_windows)}/{SETUP_BASELINE_WINDOWS}")
            except Exception as e:
                logger.error(f"Baseline capture error: {e}")
                if self._stop_event.is_set():
                    break

        if self._stop_event.is_set():
            with self._lock:
                self.status = "needs_baseline"
            return

        # Need at least 3 windows to filter; skip filter if too few survive
        try:
            if len(raw_windows) >= 4:
                scored = _clean_windows(raw_windows, 0.10)
                baseline_data = [w for w, _ in scored] or raw_windows
            else:
                baseline_data = raw_windows

            logger.info(f"Training model on {len(baseline_data)} clean windows…")
            model = AnomalyModel(CONTAMINATION, MODEL_PATH)
            model.train(baseline_data)
            joblib.dump(baseline_data, USER_BASELINE_PATH)
            logger.info("Baseline model saved.")

            with self._lock:
                self.status = "stopped"
        except Exception as e:
            logger.error(f"Baseline training failed: {e}")
            with self._lock:
                self.status = "error"
                self.error_message = str(e)

    def _run_monitor(self):
        try:
            model = AnomalyModel(CONTAMINATION, MODEL_PATH)
            model.load()
            baseline_data = joblib.load(USER_BASELINE_PATH)
            logger.info(f"Monitor loaded model ({len(baseline_data)} baseline windows)")
        except Exception as e:
            with self._lock:
                self.status = "error"
                self.error_message = str(e)
            return

        try:
            interface = get_interface()
        except Exception as exc:
            logger.error(f"Could not get network interface for monitor: {exc}")
            with self._lock:
                self.status = "error"
                self.error_message = str(exc)
            return
        local_ip = get_local_ip()
        normal_buffer = []

        with self._lock:
            self.status = "running"

        logger.info(f"Monitor running on {interface} (local IP: {local_ip})")

        while not self._stop_event.is_set():
            try:
                packets = capture_window(interface, WINDOW_SIZE)
                features = extract_features(packets, WINDOW_SIZE)
                if not features:
                    continue

                with self._lock:
                    self.windows_analyzed += 1

                prediction = model.predict(features)

                if prediction == -1:
                    score = model.score(features)
                    severity = model.get_severity(score)
                    explanation = model.explain(features)
                    targeted_ports = _get_targeted_ports(packets, local_ip)
                    attack_type = _detect_attack_type(features, targeted_ports)
                    scanner_ips = _get_scanner_ips(packets, local_ip)

                    alert = {
                        "timestamp": time.ctime(),
                        "severity": severity,
                        "score": round(score, 4),
                        "attack_type": attack_type,
                        "scanner_ips": scanner_ips,
                        "top_reasons": [
                            {
                                "name": FEATURE_LABELS.get(n, n),
                                "value": round(v, 4),
                                "impact": "High" if abs(v) > 0.7 else "Medium" if abs(v) > 0.4 else "Low",
                            }
                            for n, v in explanation[:5]
                        ],
                        "targeted_ports": [
                            {"port": p, "score": round(s, 2)}
                            for p, s in targeted_ports
                        ],
                    }
                    with self._lock:
                        self.alerts.appendleft(alert)
                    send_monitor_alert_notification(alert)
                    logger.warning(f"ANOMALY [{severity}] score={score:.4f} type={attack_type}")
                else:
                    normal_buffer.append(features)

                if len(normal_buffer) >= 50:
                    scored_new = _clean_windows(normal_buffer, NEW_BATCH_OUTLIER_FRACTION)
                    cleaned_new = [w for w, _ in scored_new]
                    if len(cleaned_new) >= 10:
                        combined = baseline_data + cleaned_new
                        scored_combined = _clean_windows(combined, COMBINED_OUTLIER_FRACTION)
                        baseline_data = _build_hybrid_baseline(scored_combined, cleaned_new)
                        model.train(baseline_data)
                        joblib.dump(baseline_data, USER_BASELINE_PATH)
                        logger.info(f"Retrained — baseline size: {len(baseline_data)}")
                    normal_buffer = []

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                if self._stop_event.is_set():
                    break

        with self._lock:
            self.status = "stopped"
        logger.info("Monitor stopped")


monitor = MonitorState()
