# L.O.G.S. 

L.O.G.S. is a desktop security monitoring application built with Tauri, React, and a Python FastAPI backend. It provides a local dashboard for scanning network exposure, reviewing firewall rules, calculating risk, and monitoring live traffic for anomaly alerts.

## Features

- Dashboard: summary view for risk score, open ports, firewall issues, anomaly count, and latest scan status.
- Scanner: local network port scan profiles for quick, standard, and full scans.
- Firewall: Windows Firewall or Linux iptables rule analysis, rule filtering, and rule management actions.
- Monitor: live packet capture, baseline learning, ML-based anomaly detection, alert cards, targeted service ports, and Windows toast notifications.
- Risk engine: combines scan and firewall findings into a user-facing risk level.
- Tauri sidecar backend: the desktop app starts and supervises the Python API process.

## Project Structure

```text
L.O.G.S/
  src/                  React frontend
  src/pages/            Dashboard, Scanner, Firewall, and Monitor tabs
  src/components/       Shared UI components
  src-tauri/            Tauri desktop shell and Rust sidecar launcher
  python-backend/       Backend and security logic
  python-backend/app/   Scanner, firewall, risk, anomaly, monitor, and notification modules
  scripts/              Linux/macOS helper scripts for backend build/copy
  build-windows.bat     Windows build script for backend and Tauri app
```

## Requirements

- Node.js and npm
- Rust and Cargo
- Python 3.12 recommended
- Nmap for scan functionality
- Npcap on Windows for live packet capture
- Administrator privileges on Windows for packet capture and firewall management

## Install Dependencies

Install frontend dependencies:

```powershell
npm install
```

Create and install the Python backend environment:

```powershell
cd python-backend
py -3.12 -m venv venv
.\venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
cd ..
```

## Run In Development

Run the full Tauri desktop app:

```powershell
npm run tauri dev
```

For frontend-only development:

```powershell
npm run dev
```

If running the frontend separately, start the Python API from another terminal:

```powershell
cd python-backend
.\venv\Scripts\python.exe main.py
```

## Build

Build the React frontend:

```powershell
npm run build
```

Build the Windows desktop application:

```powershell
.\build-windows.bat
```

## Monitor Alerts

The Monitor tab first requires a baseline setup scan. After the baseline is trained, the monitor captures live traffic windows and compares them against the learned model.

When an anomaly is detected, the app displays:

- Severity: Mild, Moderate, or Strong
- Score: anomaly model score
- Top Indicators: features that differed most from baseline traffic
- Targeted Ports: likely service ports involved in the alert, such as 22, 80, 443, 445, or 3389

On Windows, monitor alerts also trigger a desktop notification using `win10toast`.
