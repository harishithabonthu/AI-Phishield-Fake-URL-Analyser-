# PhishShield AI - Enterprise URL Threat Intelligence Platform

PhishShield is a premium, high-fidelity mock Single-Page Application (SPA) for AI-powered URL scanning, security telemetry, whitelist/blacklist rules management, and airgapped browser sandbox quarantines. Designed with a sleek, futuristic, dark cybersecurity aesthetic, it demonstrates production-ready UI/UX paradigms for modern security operations centers (SOC).

---

## 🚀 Quick Start (Local Run)

The application is completely serverless and dependency-free at the frontend layer, meaning it runs instantly in any modern web browser.

### Option A: Standard Dev Server (Recommended)
If you have **Node.js** installed, run the following commands in the project directory:
```bash
# Start the local security node server on port 3000
npm run dev
```
Then visit `http://localhost:3000` in your browser.

### Option B: Python Simple Server
If you prefer Python:
```bash
python -m http.server 3000
```
Then visit `http://localhost:3000` in your browser.

---

## 🛡️ Core Features Implemented

1. **AI progressive URL threat engine**: Normalizes inputs, triggers terminal logging animations, queries mock registrar authorities, resolves SSL/IP configurations, and maps threat coordinates.
2. **Heuristic Hazard Logic**: Matches URLs against custom lists, spot-checks brand spoofing keywords (`paypal`, `chase`, `netflix`, etc.), checks for HTTP plaintext connections, and parses top-level domains (.ru, .cc, .xyz).
3. **Smart Quarantine Sandbox**:
   - Safe domains load clean, mock layouts.
   - Suspicious domains load preview frames complete with warning banners warning user input.
   - Blocked domains (Hazard >= 60) terminate preview entirely, loading an access denied screen with logs and pulsing siren alarms.
4. **Interactive Dashboard**:
   - Tally stats for Scans, Safe domains, Blocked threats, and Alerts.
   - Custom-drawn, reactive SVG charts tracking threat timeline curves and category breakdowns.
   - Automated global threat signals feed feeding real-time network reports.
5. **SOC Access Sheets (CRUD Settings)**:
   - Dynamic lists to add or delete Whitelisted/Blacklisted domains with direct `localStorage` saves.
   - Core API key generators and sensitivity threshold metrics.

---

## 📊 Risk Score Classifications

Heuristic outputs evaluate domains using the designated risk ranges:
* **`0 - 30` (Normal / Safe)**: Emerald green display. Trusted domains with proper certificates.
* **`31 - 59` (Suspicious)**: Amber orange display. Triggers warnings banners inside isolated previews.
* **`60 - 90` (Fraud / Dangerous)**: Crimson red display. Auto-blocked by firewall policy and isolated.
* **`91 - 100` (Critical Threat)**: Glowing violet/red display. Triggers automatic blocking, denial cards, and dispatches slide-in admin warning alerts.

---

## 🧬 Suggested Production Architecture

For deployment to high-traffic, real-world operational scopes, deploy as follows:
* **API Ingress**: AWS API Gateway + Cognito JWT auth checking limits.
* **Workers**: Go-based microservices executing WHOIS registers and domain checks concurrently.
* **Deep Classifier**: Fast FastAPI/Python endpoints running neural analysis (e.g., DistilBERT) on domain characters under 10ms.
* **Airgapped Browsing**: Isolated Playwright/headless Chrome containers running within gVisor sandboxes to screenshot sites safely.
