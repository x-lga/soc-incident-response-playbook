# CVSS Quick Reference - SOC Triage

CVSS (Common Vulnerability Scoring System) v3.1 is used to prioritise vulnerabilities.

---

## Score Ranges

| Score | Severity | SOC Response |
|-------|---------|-------------|
| 0.0 | None | Informational - no action |
| 0.1–3.9 | Low | Log and schedule - no urgency |
| 4.0–6.9 | Medium | Patch within 30 days - monitor |
| 7.0–8.9 | High | Patch within 7 days - escalate |
| 9.0–10.0 | Critical | Patch immediately - P1 treatment |

---

## Key CVSS Metrics to Understand at L1

| Metric | What It Means for Triage |
|--------|------------------------|
| **Attack Vector (AV)** | Network = remotely exploitable (worse). Local = attacker needs physical access (better). |
| **Attack Complexity (AC)** | Low = easy to exploit. High = complex conditions required. |
| **Privileges Required (PR)** | None = no account needed (worse). High = admin rights needed (better). |
| **User Interaction (UI)** | None = exploit without user action. Required = user must click something. |
| **Confidentiality/Integrity/Availability (CIA)** | High impact = data loss / service down / corruption. |

---
