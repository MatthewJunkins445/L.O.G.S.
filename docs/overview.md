# L.O.G.S. — Project Overview

**L.O.G.S.** (Local Operations & Guardian Shield) is a desktop security monitoring application
designed to give non-expert users a clear, actionable view of their machine's security posture
without relying on cloud services or external subscriptions.

---

## The Problem

Most security tools fall into one of two categories:

- **Enterprise tools** (Splunk, CrowdStrike, Wireshark) — powerful but require expert knowledge,
  expensive licenses, and send data to external servers.
- **Basic built-in tools** (Windows Defender, Task Manager) — easy to use but give no insight
  into what is actually happening on the network, and offer no guidance when something looks wrong.

The gap between these two is where most home users and small organizations live. They have no
reliable way to answer questions like:

- Is anyone scanning my machine right now?
- Which firewall rules are a security risk?
- Has my network traffic changed in a way that suggests an attack?
- What should I do if something looks suspicious?

---

## What L.O.G.S. Does

L.O.G.S. runs entirely on the local machine and provides four core capabilities:

| Capability | What it answers |
|---|---|
| **Network Scan** | Which ports are open and how risky are they? |
| **Firewall Analysis** | Which firewall rules are misconfigured or dangerous? |
| **Risk Score** | How exposed is this machine overall, right now? |
| **Live Monitor** | Is traffic behaving abnormally compared to my normal baseline? |

When the monitor detects an anomaly, L.O.G.S. explains what the score means in plain English,
identifies the likely attack type (port scan, brute force, SYN flood), surfaces the source IP
of the attacker, and lets the user block that IP with a single button — all without leaving the app.

---

## Design Goals

1. **Local-first** — no data leaves the machine. The ML model is trained on the user's own traffic.
2. **Actionable** — every alert tells the user what to do, not just that something happened.
3. **Self-contained** — ships as a single installer with the Python backend bundled inside.
4. **No expertise required** — severity labels, plain-English descriptions, and one-click remediation
   are designed for users who are not security professionals.
