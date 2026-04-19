# Playbook 04 - False Positive Classification

**Category:** SOC Process - Alert Quality Management  
**ITIL 4 Alignment:** Problem Management - systematic FP classification and tuning
                       reduces alert fatigue and improves analyst capacity  
**Cert alignment:** CompTIA Security+  
**Last reviewed:** 2026-07

---

## What Is a False Positive and Why Getting It Wrong Matters

A false positive (FP) is a security alert triggered by legitimate activity that
matches the pattern of a detection rule. FPs are a normal part of operating a SIEM.
No detection rule is perfect - any rule broad enough to catch real attacks will
occasionally trigger on legitimate activity.

**The risk of over-classifying as FP (saying it is FP when it is real):**
The alert goes uninvestigated. The attacker continues their operation. Detection
fails. The average attacker dwell time before detection is 16 days - many of those
breaches involved analysts dismissing real alerts as false positives.

**The risk of under-classifying as FP (saying it is real when it is benign):**
Alert fatigue. Analysts spend time investigating legitimate activity. The noise
drowns out real signals. Eventually, analysts start dismissing alerts without
properly investigating them - which leads back to the first problem.

**The principle:** When in doubt, escalate. Never classify as FP because you
cannot quickly find evidence of malicious intent - that absence of evidence is not
evidence of absence. Escalate and let L2 make the determination with more time.

---

## FP Classification Matrix

| Alert Type | Legitimate Trigger → True FP | Malicious Trigger → True Positive |
|-----------|------------------------------|----------------------------------|
| Port scan / sweep detected | Nessus, Qualys, or Tenable scheduled scan by IT (verify against scan schedule) | External probe from unknown IP - network reconnaissance (T1595) |
| PsExec / admin tool usage | IT admin using PsExec for authorised remote management | PsExec from a non-admin account, from an unexpected source machine, outside business hours |
| Large data transfer outbound | Scheduled backup to cloud storage, large approved file migration | Unusual destination, unusual volume, data staged before transfer (T1041) |
| Failed auth spike on one account | Password policy expiry, cached credentials on old device | Brute force or credential stuffing - see Playbook 03 |
| PowerShell DownloadString / IEX | SCCM deployment script, approved automation, software packaging | Malware dropper downloading secondary payload (T1059.001) |
| New scheduled task created | Software update installer, approved IT deployment task | Malware persistence mechanism (T1053.005) |
| New Windows service installed | Software installation, Windows Update component | Malware persistence mechanism (T1543.003) |
| Outbound traffic to unusual port | Developer testing a new application endpoint | C2 communication on non-standard port (T1071) |
| NTLM auth, LogonType=3 to many hosts | Administrator mapping network shares, running inventory | Pass-the-Hash lateral movement (T1550.002) |
| Admin account used from new IP | Admin working from home on a new IP, VPN exit node changed | Compromised admin credentials being used from attacker infrastructure |
| DNS queries to unusual domains | Browser cached a redirect, software checking for updates | C2 communication using DNS (T1071.004), domain generation algorithm (DGA) |
| Process injection detected | Security software (AV, EDR, DLP) doing legitimate in-process inspection | Attacker process injection for privilege escalation or AV evasion |

---

## FP Classification Checklist

**Before marking any alert as false positive, ALL of the following must be confirmed.**
If ANY box cannot be checked, do NOT classify as FP. Escalate to L2.

**Identity checks:**
- [ ] The source account is a known IT service account, named admin, or scheduled task
- [ ] The source account has documented authorisation for this type of activity
- [ ] The source IP is internal or a known and documented IT management IP

**Activity checks:**
- [ ] The activity matches a scheduled or documented job (check change calendar)
- [ ] The activity volume is consistent with baseline for this account/machine
  (check last 30 days in Splunk - is this a normal Tuesday or a spike?)
- [ ] The activity occurred during expected business hours or a known maintenance window

**Threat indicator checks:**
- [ ] No lateral movement indicators present
  (same account authenticating to multiple machines in a short window)
- [ ] No data exfiltration indicators present
  (unusual volume of data leaving the network to an unusual destination)
- [ ] No concurrent suspicious activity on the same machine
  (process injection + outbound connection + new persistence = not FP)

**The harder check - intent:**
Even if all boxes above are checked, ask: is it possible this legitimate account
was compromised and is being used by an attacker who happens to be doing the right
things? If the account does not normally do this activity at this time and the
operator cannot be reached for confirmation - escalate.

---

## FP Documentation Standard

When closing an alert as false positive, the ticket must include:

```
FALSE POSITIVE CLASSIFICATION RECORD
──────────────────────────────────────────────────────
Alert name / rule  :
Alert triggered at :
Reviewed by        : [Your name and role]
Decision           : FALSE POSITIVE
──────────────────────────────────────────────────────
EVIDENCE FOR FP CLASSIFICATION:

1. Source account:
   [e.g., "Source account is svc_nessus - documented Nessus scanner service account"]

2. Source IP:
   [e.g., "10.10.10.50 is the Nessus scanner IP confirmed in IT asset register"]

3. Activity match:
   [e.g., "Scan ran at 02:00 Tuesday - matches scheduled scan in change calendar
            entry CHG-2026-0047"]

4. Volume check:
   [e.g., "Splunk query shows identical scan pattern every Tuesday for 6 weeks -
            this week's pattern is consistent with baseline"]

5. Lateral movement check: None detected
6. Exfiltration check: None detected

──────────────────────────────────────────────────────
RECOMMENDATION:
[e.g., "Add Nessus scanner IP 10.10.10.50 to exception list for port scan rule.
        Review with L2 before adding - exception list whitelist must be approved."]
──────────────────────────────────────────────────────
```

---

## Alert Tuning Recommendations

A properly documented FP is not just a closed ticket - it is a signal that the
detection rule needs tuning. FP documentation should include a tuning recommendation
that L2 can evaluate.

| FP Type | Tuning Recommendation |
|---------|----------------------|
| Scanner triggering port scan alert | Add scanner IP to exclusion list for port scan rule |
| SCCM/Intune triggering PowerShell download alert | Add known SCCM/Intune IPs to exclusion - or add CommandLine patterns to allow list |
| Backup job triggering large data transfer alert | Add backup destination IP/domain to exclusion with volume threshold increase |
| Legitimate scheduled task matching malware persistence rule | Add task name and source to exception - document the approved task |
| Admin account triggering lateral movement rule | Add the admin service account to an exception with an hourly volume cap |

**Do not add exceptions without L2 approval.** Exceptions reduce detection coverage.
Every exception must be documented with a justification, a review date, and an owner.
An undocumented exception list is a security gap waiting to be exploited.


---