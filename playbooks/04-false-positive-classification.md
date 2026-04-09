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