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

## CVE to Action Mapping (L1 Scope)

```
Receive CVE alert from scanner (Nessus / Qualys):

1. Note CVSS score
2. Confirm affected system is in your environment
3. Check if a patch is available: nvd.nist.gov → search CVE ID
4. Critical/High: Create incident ticket → escalate to Patch Management L2
5. Medium/Low: Add to next patching cycle → log in Change Management
6. Document: CVE ID, CVSS score, affected hosts, patch availability, action taken
```

---

## Nessus Severity Mapping

| Nessus | CVSS Equivalent | Action |
|--------|----------------|--------|
| Critical | 9.0-10.0 | Immediate escalation |
| High | 7.0-8.9 | Patch within 7 days |
| Medium | 4.0-6.9 | Patch within 30 days |
| Low | 0.1-3.9 | Schedule next cycle |
| Info | 0.0 | No action - informational |


---