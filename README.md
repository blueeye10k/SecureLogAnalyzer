# SecureLogAnalyzer

A small Python CLI that parses SSH authentication and web access logs, detects brute-force and exploitation activity, renders a color-coded Rich dashboard, and exports a Markdown incident report.

## Usage

From this directory:

```bash
python3 -m pip install -r requirements.txt
python3 analyzer.py
```

The default command reads `mock_auth.log` and writes `security_incident_report.md`. A different input and report path can be supplied:

```bash
python3 analyzer.py /path/to/auth.log --report /path/to/report.md
```

Detection rules:

- **Brute force:** more than five failed SSH logins from the same source IP.
- **Exploitation:** directory traversal and probes for sensitive paths such as `/etc/passwd`, `/etc/shadow`, and `/proc/self/` (including URL-encoded traversal).
- **Threat level:** `CRITICAL` when both brute force and exploitation are present, `HIGH` for either one, `MEDIUM` for failed logins without a threshold breach, and `LOW` otherwise.

The included IP addresses use documentation-only ranges (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`) so the fixture cannot identify real hosts.

## Tests

```bash
python3 -m unittest -v
```
