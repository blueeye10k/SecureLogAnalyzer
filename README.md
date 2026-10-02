# SecureLogAnalyzer 🛡️

A lightweight, terminal-based **Security Information and Event Management (SIEM)** and log analytics engine built in Python. This tool ingests raw system authentication logs, correlates Indicators of Compromise (IoCs), evaluates brute-force thresholds, and triages active web exploitation attempts into a real-time SOC dashboard.

---

## 🚀 Core Security Features

* **Threshold-Based Brute-Force Detection:** Utilizes stateful in-memory dictionaries to track failed SSH login frequencies per IP. Automatically flags sources crossing the correlation threshold (>5 failures) as malicious.
* **Signature-Based Exploitation Triage:** Inspects URL request strings for Path Traversal payloads (`../../`) specifically targeting critical Linux system configuration structures (`/etc/passwd`, `/etc/shadow`).
* **Identity & Access Auditing:** Parses successful authenticated sessions (`Accepted password/publickey`), isolating administrative user profiles (`alice`, `deploy`) to trace legitimate entry vectors.
* **Compliance Automated Reporting:** Converts multi-vector threat assessments into an industry-standard Markdown Security Incident Report (`security_incident_report.md`) for SOC handlers.

---

## 🛠️ Architecture & Technical Logic

The script functions via a three-tier pipeline:
1. **Ingestion & Regular Expressions:** Utilizes optimized regex signatures to extract IPv4 addresses, timestamps, HTTP indicators, and access flags from unstructured log entries.
2. **Correlation Engine:** Computes risk matrix metrics based on event severity. Web directory traversal targeting system assets automatically forces an **Overall Threat Level escalation to CRITICAL**.
3. **UI Layout Layer:** Implements structural data modeling via the `Rich` framework to display cross-platform terminal diagnostics without relying on web interfaces.

---

## 💻 Installation & Usage

### Prerequisites
* Linux / WSL2 Environment (Ubuntu/Debian preferred)
* Python 3.10+
* `python3-venv` package installed

### 1. Clone & Set Up the Sandbox Environment
Navigate into your target directory, initialize an isolated virtual environment, and activate it:
```bash
cd my-omnirush-project
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Project Dependencies
Install the required text formatting dependencies securely inside the sandbox:
```bash
pip3 install -r requirements.txt
```

### 3. Execute the Threat Assessment Tool
Run the core analyzer tool against the included mock network authentication files:
```bash
python3 analyzer.py
```

---

## 📊 Incident Output Sample

```text
┌──────────────────────────────────────────────────────────┐
│                 SecureLogAnalyzer Dashboard              │
├──────────────────────────────────────────────────────────┤
│ Successful SSH: 2 | Failed SSH: 11 | Brute-force: 1      │
│ Exploitation Attempts: 3          | Threat Level: CRITICAL│
└──────────────────────────────────────────────────────────┘
```
*Note: A standardized compliance report detailing exact request timestamps and attacking source IPs is automatically compiled into the workspace root as `security_incident_report.md` on every execution cycle.*
