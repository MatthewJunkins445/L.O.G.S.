# L.O.G.S. — Architecture

## High-Level Stack

```
┌─────────────────────────────────────────────────────┐
│                  Tauri Desktop Shell                │
│   (Rust — window management, sidecar launcher)      │
│                                                     │
│   ┌─────────────────┐   ┌───────────────────────┐   │
│   │  React Frontend │   │   Python FastAPI       │   │
│   │  (Vite + JSX)   │◄──►  Backend (sidecar)    │   │
│   │                 │   │                       │   │
│   │  Dashboard      │   │  /api/scan            │   │
│   │  Scanner        │   │  /api/firewall/*      │   │
│   │  Firewall       │   │  /api/risk/calculate  │   │
│   │  Monitor        │   │  /api/monitor/*       │   │
│   └─────────────────┘   │  /api/anomaly/*       │   │
│                         └───────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Frontend — React + Vite

The UI is a single-page React application with four tab pages:

- [src/pages/Dashboard.jsx](../src/pages/Dashboard.jsx) — summary cards and risk gauge
- [src/pages/Scanner.jsx](../src/pages/Scanner.jsx) — port scan controls and results table
- [src/pages/Firewall.jsx](../src/pages/Firewall.jsx) — rule browser, issue cards, rule management
- [src/pages/Monitor.jsx](../src/pages/Monitor.jsx) — live monitor controls and anomaly alerts

State that needs to persist across tabs (scan results, firewall results) is lifted into
`App.jsx` and passed as props. Tab-local state (pagination, filter, change log) stays inside
each page component.

The frontend communicates with the backend through a thin `apiFetch` wrapper
([src/useBackend.js](../src/useBackend.js)) that handles timeouts, JSON parsing, and
surfaces error messages from the API into the UI.

---

## Backend — Python FastAPI

The Python backend runs as a sidecar process launched and supervised by Tauri. It exposes
a REST API on `http://127.0.0.1:8080` and never accepts connections from outside the machine.

### Modules

| File | Responsibility |
|---|---|
| `main.py` | FastAPI app, route definitions, CORS, port management |
| `app/scanner.py` | Nmap wrapper — runs port scans and parses results |
| `app/firewall.py` | PowerShell wrapper — queries, creates, enables, disables, and removes Windows Firewall rules |
| `app/firewall_linux.py` | iptables equivalent for Linux |
| `app/risk_engine.py` | Combines scan and firewall findings into a 0–100 risk score |
| `app/monitor.py` | Background threads for baseline collection and live ML monitoring |
| `app/ml_model.py` | Isolation Forest wrapper — training, scoring, and feature explanation |
| `app/capture.py` | Scapy-based packet capture — selects the best network interface and sniffs 15-second windows |
| `app/features.py` | Converts raw packets into a 15-feature numeric vector for the ML model |
| `app/anomaly_detector.py` | Rule-based anomaly detection using a frozen baseline comparison |
| `app/notifier.py` | Windows toast notification for anomaly alerts |

---

## Tauri Sidecar

Rather than requiring users to install Python separately, the Python backend is compiled into
a standalone executable (`secureshield-backend.exe`) using **PyInstaller**. Tauri bundles this
binary and launches it automatically when the app starts.

**Rebuild process (when Python source changes):**

```powershell
# Step 1 — recompile the Python backend
cd python-backend
pyinstaller secureshield-backend.spec --noconfirm

# Step 2 — copy into the Tauri binaries folder
copy dist\secureshield-backend.exe ..\src-tauri\binaries\secureshield-backend-x86_64-pc-windows-msvc.exe

# Step 3 — relaunch
cd ..
npm run tauri dev
```

React frontend changes hot-reload instantly via Vite and do not require a rebuild.

---

## ML Pipeline

```
Live traffic
     │
     ▼
capture_window()          ← Scapy sniffs packets for 15 seconds
     │
     ▼
extract_features()        ← Converts packets to 15 numeric features
     │                       (SYN count, connection count, bytes/sec, etc.)
     ▼
AnomalyModel.predict()    ← Isolation Forest trained on user's own baseline
     │
     ├── Normal (1)  → added to rolling normal buffer
     │                  every 50 windows, model retrains on updated baseline
     │
     └── Anomaly (-1) → score()     → anomaly intensity (-0.05 mild, -0.09 strong)
                         explain()  → top features by z-score deviation
                         _detect_attack_type() → port scan / brute force / SYN flood
                         _get_scanner_ips()    → source IPs sending suspicious SYNs
                         → alert appended to deque, toast notification sent
```

---

## Data Flow — Firewall Block IP (demo path)

```
Monitor detects port scan
        │
        ▼
alert.scanner_ips = [{ ip: "192.168.1.50", syn_count: 87, port_count: 23 }]
        │
        ▼
User clicks "Block IP" in Monitor tab
        │
        ▼
apiFetch POST /api/firewall/create
  { name: "L.O.G.S. Block 192.168.1.50",
    direction: "Inbound", action: "Block",
    protocol: "any", source_ip: "192.168.1.50" }
        │
        ▼
firewall.py → PowerShell New-NetFirewallRule
        │
        ▼
Rule written to Windows Firewall
Button turns green ✓ Blocked
Rule appears in Firewall tab → "Created via L.O.G.S."
```
