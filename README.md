# RealVulnScan — Live Network Vulnerability Scanner

A **real** network scanner that performs actual live checks against target IPs/domains.

---

## ⚠️ LEGAL DISCLAIMER
Only scan systems **you own or have explicit written permission to test**.
Unauthorised scanning is illegal under computer misuse laws in most countries.

---

## What It Actually Scans

| Module | What It Does |
|---|---|
| **DNS Recon** | Real DNS lookups — A records, reverse DNS, MX, SPF/DMARC |
| **Port Scan** | TCP connect scan on 55 common ports using Node.js `net` module |
| **HTTP Probe** | Live HTTP/HTTPS requests — detects open web servers, redirect issues |
| **Headers** | Real HTTP response header analysis — CSP, HSTS, cookies, CORS, server info |
| **SSL/TLS** | Live TLS handshake — checks protocol version, cert expiry, self-signed |
| **Path Discovery** | Probes 35+ sensitive paths — `.git/`, `.env`, `phpmyadmin`, `actuator`, etc. |
| **Banner Grabbing** | Grabs service banners, checks for outdated software versions |

---

## Quick Start

### Step 1 — Install Node.js
Download from: https://nodejs.org (version 16 or higher)

### Step 2 — Install dependencies
Open terminal/command prompt in this folder:
```bash
npm install
```

### Step 3 — Start the server
```bash
npm start
```
Or double-click **start.bat** (Windows) / run **./start.sh** (Linux/Mac)

### Step 4 — Open in browser
Go to: **http://localhost:3000**

### Step 5 — Scan your target
- Enter IP: `192.168.29.119`
- Select modules
- Click **▶ SCAN NOW**

---

## Scan Results

Each finding shows:
- **Severity** (Critical / High / Medium / Low / Info)
- **CVSS Score** (0–10)
- **Category** (e.g. Network Exposure, Information Disclosure)
- **Endpoint** (exact URL/port affected)
- **Evidence** (actual banner, response, header value)
- **Remediation** (how to fix it)

Export to: TXT · HTML · JSON · CSV

---

## Project Structure
```
realvulnscan/
├── server.js          ← Node.js backend (scanning engine + WebSocket)
├── package.json       ← Dependencies
├── public/
│   ├── index.html     ← Frontend UI
│   ├── css/style.css  ← Styles
│   └── js/app.js      ← Frontend WebSocket client + UI logic
├── start.bat          ← Windows launcher
├── start.sh           ← Linux/Mac launcher
└── README.md
```

---

## How It Works

```
Browser ──WebSocket──► Node.js Server
                           │
                    ┌──────┼──────────┐
                    │      │          │
                  DNS    net.connect  https.get
                lookup   (port scan)  (HTTP checks)
                    │      │          │
                    └──────┴──────────┘
                           │
                     Results stream back
                     via WebSocket in real-time
```

The browser sends a scan request via WebSocket. The Node.js server performs all actual network operations (DNS, TCP, HTTP, TLS) and streams findings back to the browser in real time.

---

*Built for authorised security testing and educational use.*
