# soc-incident-response-playbook

Tier 1 SOC analyst playbooks built from CompTIA Security+ curriculum and hands-on
Splunk SIEM lab work. Covers phishing triage, malware alert response, failed
authentication investigation, and false positive classification - with every scenario
mapped to MITRE ATT&CK tactics and technique IDs, production-ready Splunk SPL queries
tested in a live home lab SIEM instance, a comprehensive MFA enforcement checklist,
and a complete IAM access review procedure.

Built to be used, not just read. Every playbook documents what you do when an alert
fires - not just what the terms mean. The MITRE ATT&CK mapping shows the attacker's
next move, not just the defensive checklist. The Splunk queries are tested. The
compliance checklists reflect real-world requirements.

---

## What this repo contains and why it matters

| File | Purpose | Who it helps |
|------|---------|-------------|
| `playbooks/01-phishing-triage.md` | Complete phishing cycle: user contact script → header analysis → SPF/DKIM/DMARC → URL sandboxing → classification → P1 vs P2 response → quarantine → user education → ITIL 4 documentation | Any SOC L1 analyst triaging phishing daily |
| `playbooks/02-malware-alert-response.md` | Malware scope assessment → P1/P2/P3 classification → containment (why not to power off) → Splunk evidence collection → PowerShell investigation commands → remediation → verification → malware family quick reference | SOC L1 analysts, IT security analysts |
| `playbooks/03-failed-auth-investigation.md` | Authentication pattern recognition (user error vs brute force vs spray vs stuffing vs PtH) → ATT&CK mapping for each → Splunk detection queries for each → Pass-the-Hash investigation | SOC L1, analysts reviewing authentication alerts |
| `playbooks/04-false-positive-classification.md` | FP vs TP decision matrix for 10 common alert types → complete classification checklist → FP documentation standard → alert tuning recommendations with approval controls | SOC L1 managing alert quality and fatigue |
| `splunk/useful-spl-queries.md` | 20+ production-ready SPL queries across: auth events, brute force/spray/stuffing detection, process execution (Sysmon), persistence mechanisms, lateral movement, network exfiltration, alert quality management | Any Splunk user doing L1 security monitoring |
| `splunk/dashboard-design-notes.md` | Three complete Splunk dashboard designs with full SPL, layout specifications, threshold colouring XML, performance guidance for Splunk Free, and drill-down token design | SOC analysts building monitoring dashboards |
| `reference/mitre-attack-mapping.md` | Every playbook scenario mapped to ATT&CK tactic + technique + ID with explanation of why the mapping matters for triage; full detection coverage heatmap | Anyone learning ATT&CK or building detection coverage |
| `reference/cvss-quick-reference.md` | CVSS v3.1 score ranges, metric explanations (AV/AC/PR/UI/CIA), CVE to ticket action mapping, Nessus severity alignment, real CVE examples with triage interpretation | Any analyst working with vulnerability scan output |
| `reference/mfa-enforcement-checklist.md` | Complete MFA rollout verification: scope definition, IdP config review, phishing-resistant method comparison, coverage verification checklists, monitoring requirements, gap tracking table, sign-off | IAM teams, security teams running compliance reviews |
| `reference/iam-access-review-procedure.md` | Full access review cycle: scoping, data collection quality checks, reviewer briefing, decision criteria, chase schedule, revocation SLAs, evidence retention, campaign metrics, special account handling, Splunk pre-review queries | IAM teams, security engineers, compliance officers |

---

## Skills demonstrated

**Incident response:**
Phishing triage lifecycle (report → investigation → classification → containment →
remediation → documentation), malware response (scope → classify → contain → collect →
remediate → verify), authentication anomaly investigation (user error vs credential attack)

**MITRE ATT&CK:**
Tactic-to-technique mapping for all playbook scenarios; understanding of attacker next
move after initial access (what happens after credentials are stolen); detection coverage
heatmap across 14 ATT&CK tactics; family-to-technique mapping for major malware types

**SIEM — Splunk:**
SPL queries for authentication anomalies (brute force, spray, stuffing, PtH detection),
process execution analysis (T1059.001 PowerShell dropper detection), persistence
mechanism detection (T1053.005, T1543.003, T1547.001), lateral movement detection
(T1550.002 NTLM pattern); three dashboard designs with full SPL, threshold colouring,
and Splunk Free performance optimisation

**Vulnerability management:**
CVSS v3.1 metric interpretation, severity-to-priority mapping, CVE to patch action
workflow, Nessus severity alignment

**Identity and compliance:**
MFA enforcement verification (phishing-resistant vs standard methods, fatigue attack
detection, legacy auth blocking), IAM access review procedure aligned to ISO 27001,
SOC 2, Kenya Data Protection Act 2019, and CBK guidelines

**ITIL 4:**
P1–P4 incident priority classification, Incident vs Problem vs Change application
to security events, escalation criteria and urgency guide, complete documentation
requirements per playbook

---

## Lab environment

```
Hypervisor      : Proxmox VE 8.x
SIEM            : Splunk Free (Ubuntu 22.04) — VLAN 99 (management segment)
Event forwarding: Splunk Universal Forwarder on Windows Server 2022 DC
Sysmon          : Deployed on Windows VMs for process and network event collection
Windows DC      : Windows Server 2022 — domain contoso.local
Windows Clients : Windows 10 22H2, Windows 11 23H2 — domain-joined
Kali Linux      : VLAN 20 (isolated) — attack simulation for detection validation
Nessus          : Nessus Essentials — vulnerability scans against lab VMs
OWASP Juice Shop: Authorised web app pen test target for XSS/SQLi practice
pfSense         : Firewall with VLAN segmentation and log forwarding
```

---

## Why this repo is different from a typical Security+ project

Most candidates who have passed Security+ can explain the difference between a
virus and a worm, or name the stages of the incident response lifecycle from a
textbook. This repository demonstrates operational security thinking:

The phishing playbook documents the exact initial user call script, the specific
headers that matter and what each result means, the exact tools for URL analysis
and why VirusTotal is used for hash lookup rather than file upload, and the exact
PowerShell commands to disable an account and revoke M365 sessions simultaneously.

The malware playbook explains why you never power off a machine during active
compromise (volatile memory), distinguishes between P1/P2/P3 based on execution
status rather than just detection, and maps each malware family to the ATT&CK
techniques it employs so the analyst knows what to look for next.

The MITRE ATT&CK mappings show that understanding a phishing email as T1566.002
means the attacker's goal is T1078 (Valid Accounts) - and that the post-click P1
response disables the account AND revokes sessions because disabling without
revoking leaves an active browser session that the attacker continues to use.

That is the gap between someone who studied for an exam and someone who has
thought through what they would actually do in a real incident.

---

## How to use this repo

```bash
# Clone
git clone https://github.com/YOUR-USERNAME/soc-incident-response-playbook.git
cd soc-incident-response-playbook

# Start with the phishing playbook — most common daily ticket type
cat playbooks/01-phishing-triage.md

# Reference MITRE ATT&CK mappings while reading any playbook
cat reference/mitre-attack-mapping.md

# Copy SPL queries directly into Splunk Search & Reporting
cat splunk/useful-spl-queries.md

# Use checklists for compliance work
cat reference/mfa-enforcement-checklist.md
cat reference/iam-access-review-procedure.md
