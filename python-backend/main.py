# python-backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging
import os
import platform
import subprocess
from typing import Optional

from app.monitor import monitor
from app.scanner import NetworkScanner
from app.risk_engine import RiskEngine
from app.anomaly_detector import AnomalyDetector

if platform.system() == "Windows":
    from app.firewall import FirewallAnalyzer
    logger_platform = "Windows (PowerShell)"
else:
    from app.firewall_linux import FirewallAnalyzer
    logger_platform = "Linux (iptables)"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("logs.api")

app = FastAPI(title="L.O.G.S. Security API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:1420", "tauri://localhost", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall = FirewallAnalyzer()
risk_engine = RiskEngine()
anomaly_detector = AnomalyDetector()
scanner: Optional[NetworkScanner] = None

logger.info(f"Initialized firewall module for {logger_platform}")


# ── Request models ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    profile: str = "quick"

class RiskRequest(BaseModel):
    scan_results: dict
    firewall_results: dict

class AnomalyRequest(BaseModel):
    current_scan: dict

class CreateRuleRequest(BaseModel):
    name: str
    port: str
    protocol: str = "tcp"
    action: str = "Block"
    direction: str = "Inbound"
    source_ip: str = ""
    description: str = ""


# ── Scanner ─────────────────────────────────────────────────────────────────

def get_scanner() -> NetworkScanner:
    global scanner
    if scanner is None:
        scanner = NetworkScanner()
    return scanner


@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    try:
        logger.info(f"Starting scan with profile: {request.profile}")
        return get_scanner().scan_localhost(profile=request.profile)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Firewall ─────────────────────────────────────────────────────────────────

@app.get("/api/firewall/analyze")
async def analyze_firewall():
    try:
        logger.info(f"Analyzing firewall rules on {platform.system()}")
        return firewall.analyze()
    except Exception as e:
        logger.error(f"Firewall analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/firewall/rules")
async def get_firewall_rules():
    try:
        return {"rules": firewall.get_firewall_rules()}
    except Exception as e:
        logger.error(f"Failed to get firewall rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/firewall/disable/{rule_name}")
async def disable_rule(rule_name: str):
    try:
        return {"success": firewall.disable_rule(rule_name)}
    except Exception as e:
        logger.error(f"Failed to disable rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/firewall/enable/{rule_name}")
async def enable_rule(rule_name: str):
    try:
        return {"success": firewall.enable_rule(rule_name)}
    except Exception as e:
        logger.error(f"Failed to enable rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/firewall/remove/{rule_name}")
async def remove_rule(rule_name: str):
    try:
        return {"success": firewall.remove_rule(rule_name)}
    except Exception as e:
        logger.error(f"Failed to remove rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/firewall/create")
async def create_firewall_rule(request: CreateRuleRequest):
    try:
        logger.info(f"Creating firewall rule: {request.name}")
        success = firewall.create_rule(
            name=request.name,
            direction=request.direction,
            action=request.action,
            protocol=request.protocol,
            port=request.port,
            source_ip=request.source_ip,
            description=request.description,
        )
        return {"success": success}
    except Exception as e:
        logger.error(f"Failed to create rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Risk engine ──────────────────────────────────────────────────────────────

@app.post("/api/risk/calculate")
async def calculate_risk(request: RiskRequest):
    try:
        logger.info("Calculating risk score")
        percent = risk_engine.calculate_risk(request.scan_results, request.firewall_results)
        return {
            "percent": percent,
            "level": risk_engine.get_risk_level(percent),
            "remediation_hints": risk_engine.get_remediation_hints(
                request.scan_results, request.firewall_results
            ),
        }
    except Exception as e:
        logger.error(f"Risk calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Anomaly detection ────────────────────────────────────────────────────────

@app.post("/api/anomaly/detect")
async def detect_anomalies(request: AnomalyRequest):
    try:
        logger.info("Running anomaly detection")
        return {"anomalies": anomaly_detector.detect(request.current_scan)}
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/anomaly/reset-baseline")
async def reset_anomaly_baseline():
    try:
        anomaly_detector.reset_baseline()
        return {"success": True, "message": "Baseline reset"}
    except Exception as e:
        logger.error(f"Baseline reset failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Live monitor ─────────────────────────────────────────────────────────────

@app.post("/api/monitor/baseline/start")
async def start_baseline():
    return monitor.start_baseline()

@app.post("/api/monitor/baseline/reset")
async def reset_monitor_baseline():
    return monitor.reset_baseline()

@app.post("/api/monitor/start")
async def start_monitor():
    return monitor.start_monitor()

@app.post("/api/monitor/stop")
async def stop_monitor():
    return monitor.stop_monitor()

@app.get("/api/monitor/status")
async def monitor_status():
    return monitor.get_state()

@app.post("/api/monitor/alerts/clear")
async def clear_alerts():
    return monitor.clear_alerts()


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "L.O.G.S. Security API",
        "version": "1.0.0",
        "platform": platform.system(),
        "firewall_backend": logger_platform,
    }

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "ready",
        "firewall": "ready",
        "risk_engine": "ready",
        "anomaly_detector": "ready",
        "platform": platform.system(),
    }


def _free_port(port: int) -> None:
    """Kill any process currently holding the given port before we try to bind it."""
    my_pid = os.getpid()
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if f":{port} " in line and "LISTENING" in line:
                    parts = line.split()
                    pid_str = parts[-1] if parts else ""
                    if pid_str.isdigit() and int(pid_str) != my_pid:
                        subprocess.run(
                            ["taskkill", "/F", "/PID", pid_str],
                            capture_output=True, timeout=3,
                        )
                        logger.info(f"Freed port {port}: killed stale PID {pid_str}")
        else:
            result = subprocess.run(
                ["fuser", f"{port}/tcp"],
                capture_output=True, text=True, timeout=5,
            )
            for pid_str in result.stdout.split():
                if pid_str.isdigit() and int(pid_str) != my_pid:
                    subprocess.run(["kill", "-9", pid_str], timeout=3)
                    logger.info(f"Freed port {port}: killed stale PID {pid_str}")
    except Exception as exc:
        logger.warning(f"Could not free port {port}: {exc}")


if __name__ == "__main__":
    _free_port(8080)
    logger.info(f"Starting L.O.G.S. Security API on http://127.0.0.1:8080")
    logger.info(f"Platform: {platform.system()}")
    logger.info(f"Firewall backend: {logger_platform}")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")
