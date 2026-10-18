<p align="center">
  <img src="assets/logo.png" alt="BreachSieve - AI-Augmented Vulnerability Assessment" width="720">
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/Frontend-React%20(Vite)-61DAFB?logo=react&logoColor=white">
  <img alt="ZAP" src="https://img.shields.io/badge/Scanner-OWASP%20ZAP-FF6600">
  <img alt="Gemini" src="https://img.shields.io/badge/AI-Gemini%202.5%20Flash-8E75B2">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="Series" src="https://img.shields.io/badge/52%20Weeks%20of%20Security-Week%204--6-blueviolet">
</p>

<p align="center">
  <b>Scope it, scan it, and get a report with the noise already filtered out.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-why-breachsieve-exists">Why this exists</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-api-keys">API keys</a> ·
  <a href="#-security-notes-and-honest-limitations">Limitations</a>
</p>

---

## 📌 Table of contents
- [Why BreachSieve exists](#-why-breachsieve-exists)
- [Who this is built for](#-who-this-is-built-for)
- [Why this is different from running ZAP alone](#-why-this-is-different-from-running-zap-alone)
- [Features](#-features)
- [How it works](#-how-it-works)
- [Architecture](#-architecture)
- [API keys](#-api-keys)
- [Quick start](#-quick-start)
- [Usage](#-usage)
- [Example output](#-example-output)
- [Project structure](#-project-structure)
- [Testing](#-testing)
- [Non-negotiable safety rules](#-non-negotiable-safety-rules)
- [Security notes and honest limitations](#-security-notes-and-honest-limitations)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Why BreachSieve exists

A vulnerability scanner on its own produces two problems: it fires real attack payloads at whatever it can reach, and it drowns you in findings that are mostly noise. DAST tools are well known for over-reporting, missing headers, informational alerts, and pattern matches that don't actually apply to the endpoint being tested.

**BreachSieve fixes both problems at the same time.** It wraps OWASP ZAP in a scope allow-list that a scan can never step outside of, and it sends every raw ZAP alert to Gemini for evidence-based triage before a human ever sees it. The result is a report with a confirmed finding, a quoted piece of evidence, a standard severity score, and a specific fix, not a wall of maybe.

---

## 👥 Who this is built for

| Audience | What BreachSieve gives them |
|---|---|
| **Ethical hackers / white-hat testers** | A scope allow-list enforced in code, not just agreed on in an email, so a test stays inside the boundary of what was authorized. The dual confirmation before active scanning and the immutable audit log give you a clean, defensible record of exactly what you tested, when, and under what authorization, evidence you can hand to a client if a target ever questions your testing |
| **Bug bounty hunters** | Less time wasted triaging noise. Gemini's evidence-quoted verdicts and CWE/OWASP/MITRE mapping get you close to submission-ready faster, and the specific remediation text is easy to adapt into a report a program will accept on the first pass |
| **Corporate VA teams** | Risk-adjusted scoring (CVSS × business impact × exposure) that reflects the asset, not just the raw technical severity, a full audit trail for compliance evidence, and PDF/HTML reports ready to hand to stakeholders who don't read raw scanner output |
| **Security researchers** | The `novel_pattern_flag` surfaces alerts that don't match a familiar pattern for closer study, the AI's reasoning is written and quoted against real evidence rather than a black-box score, and every verdict is logged for later analysis |

**The one thing all four have in common**: a scanner's raw output is not the deliverable, a filtered, evidence-backed, properly scoped set of findings is. That's what BreachSieve produces.

---

## 🛡️ Why this is different from running ZAP alone

| Running ZAP by itself | **BreachSieve** |
|---|---|
| Scans whatever the spider discovers, with no enforced boundary | A parsed allow-list blocks any out-of-scope URL from ever being queued, in code, not just in a settings screen |
| Active scanning can start with one command | Active scanning needs a **second, explicit confirmation**, separate from the scan authorization itself |
| Every alert is shown, confidence and all | Every alert is sent to Gemini with its evidence and comes back labeled `confirmed`, `false_positive`, or `needs_review`, with a written reason quoting the evidence |
| Severity is raw CVSS only | Severity is CVSS **adjusted** for the asset's business impact and exposure, so two findings with the same CVSS score don't always carry the same real-world risk |
| Findings are a rule ID and a description | Every finding carries its CWE ID, its OWASP Top 10:2021 category, and its MITRE ATT&CK technique ID where one applies |
| Remediation is generic ("fix this header") | Remediation is the specific header, value, or query pattern to use |
| No record of who ran what, or why | Every scan, scope, authorization statement, and AI verdict is logged, immutably |

> **Honest note:** BreachSieve does not discover genuinely new vulnerability classes no one has seen before, no scanner does. What it does is keep triage fast and evidence-based, and flag findings that don't match a familiar pattern (`novel_pattern_flag`) for a closer look. See [Security notes and honest limitations](#-security-notes-and-honest-limitations).

---

## ✨ Features

- 📝 **Single input form**: target URL, in-scope rules, out-of-scope exclusions, business impact multiplier, exposure context, and legal authorization, all in one place
- 🚧 **Strict allow-list enforcement**: host wildcards (`*.example.com`), path prefixes (`/api/*`), and CIDR ranges (`192.168.1.0/24`). Out-of-scope rules always win over in-scope ones, and an out-of-scope URL is never queued
- 🔐 **Dual confirmation for active scans**: a second, explicit warning dialog before any intrusive payload is sent
- 🤖 **Gemini AI triage**: evidence-based verdicts (`confirmed` / `false_positive` / `needs_review`) with the reasoning quoting the actual request/response, plus a flag for unfamiliar patterns
- 🧹 **False-positive reduction**: scanner noise and uncorroborated low-confidence alerts are dropped or clearly marked, not mixed in with real findings
- 📊 **Risk-adjusted scoring**: `min(10.0, round(CVSS_base × business_multiplier × exposure_factor, 1))`, mapped to Critical / High / Medium / Low
- 🗂️ **Standard mapping on every finding**: CWE ID, OWASP Top 10:2021 category, MITRE ATT&CK technique ID
- 🔧 **Specific remediation**: exact headers, values, and patterns, not generic advice
- 📄 **PDF and HTML reports**: a styled standalone report, downloadable straight from the dashboard
- 🧾 **Immutable audit log**: every scan parameter, authorization statement, timestamp, and AI verdict, permanently recorded
- 🧪 **Works without a Gemini key**: an offline deterministic triage mode activates automatically if `GEMINI_API_KEY` is not set, so you can test locally with no external API

---

## 🔬 How it works

```
 1. Submit the form
    target URL · in-scope rules · out-of-scope rules · business impact · exposure · authorization
         │
         ▼
 2. Scope engine builds an allow-list and blocks the request if authorization is missing
         │
         ▼
 3. OWASP ZAP spiders and scans, bounded to the allow-list only
    (active scanning needs the second confirmation)
         │
         ▼
 4. Every raw alert + its evidence goes to Gemini
    verdict: confirmed | false_positive | needs_review   (+ novel_pattern_flag)
         │
         ▼
 5. Confirmed findings are scored, mapped to CWE / OWASP / MITRE ATT&CK,
    and given specific remediation
         │
         ▼
 6. Dashboard + downloadable PDF/HTML report + audit log entry
```

---

## 🗺️ Architecture

```
                          ┌─────────────────────────────────────┐
                          │     React Frontend (Vite, :3000)    │
                          │   Single Form + Command Dashboard   │
                          └──────────────────┬──────────────────┘
                                             │ HTTP / JSON
                                             ▼
                          ┌─────────────────────────────────────┐
                          │     FastAPI Backend (:8000)         │
                          │  Scope Enforcement & Orchestrator   │
                          └──────────┬───────────────┬──────────┘
                                     │               │
                 REST API Telemetry  │               │ google-genai SDK
                                     ▼               ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │   OWASP ZAP Daemon   │   │  Google Gemini API   │
                      │   (:8080) in Docker  │   │   (gemini-2.5-flash) │
                      │  Spider & DAST Scan  │   │  Triage & Novel Flag │
                      └──────────────────────┘   └──────────────────────┘
                                     │               │
                                     └───────┬───────┘
                                             ▼
                          ┌─────────────────────────────────────┐
                          │    SQLite Audit Database & Storage  │
                          │     PDF / HTML Report Generator     │
                          └─────────────────────────────────────┘
```

---

## 🔑 API keys

| Key | Required? | How to get it |
|---|---|---|
| `GEMINI_API_KEY` | Optional. Without it, an offline deterministic triage mode runs instead | Free key from Google AI Studio: **https://aistudio.google.com/apikey** |
| `ZAP_API_KEY` | Required | ZAP is not a cloud service, there is no sign-up page. You **set this value yourself** when you start ZAP, then use the same value in `.env`. In the ZAP desktop app: **Tools → Options → API**. In Docker/daemon mode: `zap.sh -daemon -config api.key=your-own-secret` |

Copy `.env.example` to `.env` and fill in both values. Never commit `.env`, it is already in `.gitignore`.

```bash
# .env
GEMINI_API_KEY=your_gemini_api_key_here
ZAP_API_KEY=breachsieve_secret_key
ZAP_BASE_URL=http://zap:8080
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_PORT=3000
```

---

## 🚀 Quick start

### With Docker (recommended)

```bash
git clone https://github.com/RavinduChamika1/breachsieve.git
cd breachsieve
cp .env.example .env    # fill in GEMINI_API_KEY and ZAP_API_KEY
docker-compose up --build
```

- Dashboard: **http://localhost:3000**
- API docs (Swagger): **http://localhost:8000/docs**
- ZAP daemon: **http://localhost:8080**

### Without Docker

**Backend**
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```
Visit **http://localhost:3000**.

---

## 💻 Usage

1. Open the dashboard and fill in the single form: target URL, in-scope rules, out-of-scope rules, business impact multiplier, exposure context.
2. Confirm authorization: *"I own this target, or I have written permission to test it."* The scan will not start without this.
3. Choose passive-only (default, safe) or full active scanning. Active scanning asks for a **second** confirmation before it sends any payload.
4. Watch ZAP spider and scan, bounded to your scope.
5. Gemini triages every alert in the background; confirmed findings appear on the dashboard with severity, evidence, and remediation.
6. Download the PDF or HTML report, or review everything later from the audit log.

**Test safely first**: point BreachSieve at OWASP's own intentionally vulnerable practice apps, such as `testphp.vulnweb.com`, Juice Shop, or WebGoat, before ever scanning anything else.

---

## 📺 Example output

```json
{
  "finding_id": "BS-FIND-001",
  "title": "Anti-clickjacking Header (X-Frame-Options) Not Set",
  "severity": "Medium",
  "cvss_score": 5.2,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
  "cwe_id": "CWE-1021",
  "owasp_category": "A05:2021-Security Misconfiguration",
  "mitre_attack_technique": "T1190",
  "affected_url": "https://testphp.vulnweb.com",
  "description": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or an X-Frame-Options header.",
  "evidence": {
    "request": "GET / HTTP/1.1\nHost: testphp.vulnweb.com",
    "response": "HTTP/1.1 200 OK\nContent-Type: text/html"
  },
  "ai_verdict": "confirmed",
  "ai_reasoning": "Confirmed: HTTP response headers omit both 'X-Frame-Options' and CSP 'frame-ancestors'. The target page can be rendered inside an unauthorized <iframe> layer.",
  "novel_pattern_flag": false,
  "remediation": "Add the following HTTP response headers: Content-Security-Policy: frame-ancestors 'self'; X-Frame-Options: SAMEORIGIN",
  "references": [
    "https://cwe.mitre.org/data/definitions/1021.html",
    "https://attack.mitre.org/techniques/T1190/"
  ]
}
```

*(Add a dashboard screenshot or demo GIF here, for example `assets/demo.gif`.)*

---

## 🗂️ Project structure

```
breachsieve/
├── assets/
│   ├── logo.svg, logo.png
│   └── icon.svg, icon.png
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── requirements.txt
│   └── tests/
│       ├── test_scope_manager.py
│       ├── test_scoring_and_mapping.py
│       ├── test_report_service.py
│       ├── test_api_endpoints.py
│       └── test_e2e_workflow.py
├── frontend/
│   ├── package.json
│   └── src/                 # React (Vite) dashboard
├── docker-compose.yml        # zap + backend + frontend
├── .env.example
├── LICENSE
└── README.md
```

---

## 🧪 Testing

```bash
backend\venv\Scripts\pytest backend/tests/ -v
```

| Test file | What it covers |
|---|---|
| `test_scope_manager.py` | Subdomain wildcards, CIDR blocks, path prefixes, and that out-of-scope rules override in-scope ones |
| `test_scoring_and_mapping.py` | CVSS v3.1 base scores, business impact multipliers, exposure factors, severity bands, and MITRE ATT&CK mapping |
| `test_report_service.py` | Standalone HTML generation and PDF document compilation |
| `test_api_endpoints.py` | Authorization enforcement, scope rejection, active-scan confirmation checks, and scan submission |
| `test_e2e_workflow.py` | The complete 12-step pipeline, from target input through false-positive filtering to finished report artifacts |

---

## 🔒 Non-negotiable safety rules

1. **Strict allow-list.** A URL outside scope is never queued for a scan. Out-of-scope rules always override in-scope ones.
2. **Mandatory authorization.** A scan is rejected immediately if `authorization_confirmation` is false.
3. **Active-scan guardrail.** The active scanner never runs without both the authorization confirmation and a separate, explicit active-scan confirmation.
4. **Keys stay in the environment.** `GEMINI_API_KEY` and `ZAP_API_KEY` are read only from environment variables, never committed.
5. **A clear in-app disclaimer** states this tool is for authorized security testing only.

---

## 🛡️ Security notes and honest limitations

- **For authorized testing only.** Scanning a system you do not own or do not have written permission to test may be illegal in your jurisdiction. Confirm authorization before every scan.
- **Not zero-day discovery.** `novel_pattern_flag` means Gemini saw an alert that doesn't closely match a pattern already seen in this scan, an unfamiliar instance of a known weakness class. It is not a claim of discovering a previously unknown vulnerability class.
- **AI triage reduces false positives, it does not eliminate them.** Review `needs_review` findings yourself; don't treat Gemini's verdict as final for anything high-severity.
- **The risk score is CVSS adjusted for context, not a full FAIR analysis.** A true FAIR model needs real financial loss and incident-history data this tool cannot observe. Treat the adjusted score as decision support, not ground truth.
- **The offline deterministic mode (no Gemini key) is a fallback, not the full experience.** It quotes evidence and applies rule-based labels, but it does not reason about context the way the AI triage does.
- **Scope enforcement is the one component that deserves the most scrutiny.** A bug there undermines the legal-safety argument for the whole tool; test it thoroughly before pointing BreachSieve at anything beyond a practice target.
- **This augments, it does not replace, manual penetration testing.** It will not find business-logic flaws or multi-step attack chains that require human creativity.

---

## 🗺️ Roadmap

Part of **52 Weeks of Security**: one new cybersecurity project every week, with major builds spanning 2-3 weeks.

- [x] **Week 1:** [PassVigil](https://github.com/RavinduChamika1/passvigil), password strength and breach checker
- [x] **Week 2:** [HashKiln](https://github.com/RavinduChamika1/hashkiln), password hashing lab
- [x] **Week 3:** [MimicLens](https://github.com/RavinduChamika1/mimiclens), phishing URL detector
- [x] **Weeks 4-6:** BreachSieve, AI-augmented vulnerability assessment platform
- [ ] More coming every week

Ideas for this project: scope import directly from bug bounty platform program pages, a trend view across repeated scans, Jira/ServiceNow ticketing integration, a real FAIR mode for organizations that can supply their own loss data.

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-idea`
3. Make your changes and run `pytest backend/tests/ -v`
4. Commit and push, then open a Pull Request

Found a bug or have an idea? [Open an issue](https://github.com/RavinduChamika1/breachsieve/issues).

---

## 👤 Author

**Ravindu Chamika**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ravindu-chamika/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?logo=github&logoColor=white)](https://github.com/RavinduChamika1)

If this helped you learn something, please ⭐ the repo and follow the series.

---

## 📄 License

Copyright © 2026 **Ravindu Chamika**. Released under the [MIT License](LICENSE).

This project orchestrates OWASP ZAP (Apache 2.0) and the Google Gemini API; it does not modify or redistribute either, and inherits no capability beyond what those services already provide.

<p align="center"><sub>Built for authorized security testing · 52 Weeks of Security · Weeks 4-6</sub></p>
