# soc-incident-response-playbook

Tier 1 SOC analyst playbooks built from Security+ curriculum and hands-on SIEM lab work. Covers phishing triage, failed authentication investigation, false positive classification, Splunk SPL queries, and CVSS reference.

---

## Contents

| File | Purpose |
|------|---------|
| `playbooks/01-phishing-triage.md` | End-to-end phishing response from report to quarantine |
| `playbooks/02-malware-alert-response.md` | Endpoint malware detection and containment |
| `playbooks/03-failed-auth-investigation.md` | Auth failure patterns, Splunk queries, brute force detection |
| `playbooks/04-false-positive-classification.md` | FP decision matrix and documentation standard |
| `splunk/useful-spl-queries.md` | Production-ready SPL queries for auth, network, and process events |
| `splunk/dashboard-design-notes.md` | Security overview dashboard structure for Splunk Free |
| `reference/cvss-quick-reference.md` | CVSS scoring, severity mapping, Nessus alignment |
| `reference/mfa-enforcement-checklist.md` | MFA rollout verification and gap remediation |
| `reference/iam-access-review-procedure.md` | Periodic access review steps and documentation |

---

## Skills Demonstrated

- **Phishing Triage:** Header analysis, SPF/DKIM/DMARC interpretation, URL sandboxing, quarantine
- **SIEM:** Splunk SPL queries for authentication, network, and process events; dashboard creation
- **Vulnerability Management:** CVSS scoring, Nessus severity alignment, remediation prioritisation
- **ITIL 4:** P1–P4 incident classification, escalation criteria, documentation standards
- **Security+:** Incident response lifecycle, identity security, IAM, MFA enforcement

---

## Lab Environment

- Splunk Free (local instance) with Windows Event Log forwarding from Server 2022
- Nessus Essentials — vulnerability scans against home lab VMs
- OWASP Juice Shop — authorised pen testing target for SQL injection and XSS identification
- Kali Linux — Burp Suite for web application testing

---

## Outcome

These playbooks mirror the workflow of a real Tier 1 SOC analyst. The phishing playbook alone covers the full cycle: user report → header analysis → sandboxing → classification → quarantine → user education → escalation. The Splunk queries are production-ready and tested in a real SIEM environment.