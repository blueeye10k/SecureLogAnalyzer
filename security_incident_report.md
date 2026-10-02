# SecureLogAnalyzer Security Incident Report

## Executive summary

- **Source log:** `mock_auth.log`
- **Overall threat level:** 🔴 **CRITICAL**
- **Successful SSH logins:** 2
- **Failed SSH logins:** 11
- **Brute-force sources:** 1
- **Exploitation attempts:** 3

Brute force is flagged when one source IP produces **more than 5 failed SSH logins**.

## Brute-force detections

| Source IP | Failed attempts | Threat |
|---|---:|---|
| `203.0.113.77` | 8 | HIGH |

## Exploitation attempts

| Timestamp | Source IP | Request | HTTP status | Indicator |
|---|---|---|---:|---|
| `02/Oct/2026:10:10:00 +0000` | `203.0.113.66` | `GET /../../etc/passwd` | 400 | Directory traversal targeting a sensitive system file |
| `02/Oct/2026:10:10:01 +0000` | `203.0.113.66` | `GET /static/../../etc/shadow` | 404 | Directory traversal targeting a sensitive system file |
| `02/Oct/2026:10:10:04 +0000` | `203.0.113.66` | `GET /%2e%2e/%2e%2e/etc/passwd` | 400 | Directory traversal targeting a sensitive system file |

## Successful SSH logins

| Timestamp | User | Source IP |
|---|---|---|
| `Oct  2 09:14:02` | `alice` | `192.0.2.44` |
| `Oct  2 09:15:19` | `deploy` | `198.51.100.12` |

## Analyst recommendations

1. Investigate and block confirmed brute-force source IPs at the perimeter or host firewall.
2. Review authentication logs and rotate credentials for targeted accounts, especially `root`.
3. Inspect web-server and application logs around each traversal request for follow-on activity.
4. Prefer key-based SSH authentication, disable direct root login, and apply rate limiting.
