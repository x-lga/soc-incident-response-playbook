### `playbooks/04-false-positive-classification.md`

```markdown
# Playbook 04 — False Positive Classification

**Category:** SOC Process  
**ITIL 4 Alignment:** Problem Management — systematic FP classification reduces alert noise

---

## What is a False Positive?

A security alert triggered by legitimate activity that matches a detection rule pattern.

**Risk of incorrect FP classification:** If you mark a real threat as FP, it goes uninvestigated. When in doubt → escalate.

---

## FP Classification Matrix

| Alert Type | Legitimate Trigger (FP) | Malicious Trigger (True Positive) |
|-----------|------------------------|----------------------------------|
| Port scan detected | Vulnerability scanner (Nessus, Qualys) run by IT | External probe from unknown IP |
| Admin tool usage | IT admin using PsExec for remote support | PsExec from non-admin account after-hours |
| Large data transfer | Scheduled backup job | Exfiltration (unusual destination, unusual time) |
| Failed auth spike | Password expiry wave | Credential stuffing from multiple IPs |
| PowerShell download | Software deployment script (SCCM, Intune) | Malware dropper downloading payload |

---

## FP Decision Criteria

Before marking an alert as FP, ALL of the following must be confirmed:

- [ ] Source account is a known IT service account or admin
- [ ] Activity matches a scheduled or documented job
- [ ] Source IP is internal or a known IT management IP
- [ ] Activity occurred during expected business hours (or known maintenance window)
- [ ] Volume is consistent with normal baseline (check last 30 days in Splunk)
- [ ] No lateral movement indicators present
- [ ] No data exfiltration indicators present

If ANY box is unchecked → do NOT classify as FP. Escalate to L2 for review.

---

## FP Documentation Standard

When closing an alert as FP: