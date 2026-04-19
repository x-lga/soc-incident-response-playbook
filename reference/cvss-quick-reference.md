# CVSS Quick Reference - SOC Triage and Vulnerability Prioritisation

CVSS (Common Vulnerability Scoring System) v3.1 is the industry standard for
measuring the severity of security vulnerabilities. Understanding CVSS enables
a Tier 1 analyst to prioritise vulnerability findings from Nessus scans and
communicate remediation urgency to system owners and management.

Reference: `nvd.nist.gov` (National Vulnerability Database)

---

## CVSS Score Ranges and SOC Response

| Score | Severity | Expected Response | Patch Target |
|-------|---------|-----------------|-------------|
| 0.0 | None | Informational - no action required | N/A |
| 0.1–3.9 | Low | Log and schedule for next patch cycle | 90 days |
| 4.0–6.9 | Medium | Patch within 30 days - monitor affected systems | 30 days |
| 7.0–8.9 | High | Patch within 7 days - escalate if unpatched after 48 hours | 7 days |
| 9.0–10.0 | Critical | Immediate action - treat as P1 until patched or mitigated | 24–48 hours |

---

## Key CVSS v3.1 Metrics: What They Mean for Triage

The CVSS score is composed of several metrics. Understanding each helps you
interpret the severity and communicate it to non-technical stakeholders.

### Attack Vector (AV) - How the attacker reaches the target
| Value | Meaning | Risk Level |
|-------|---------|-----------|
| Network (N) | Exploitable remotely over the internet | Highest |
| Adjacent (A) | Requires access to the same network segment | High |
| Local (L) | Requires local access to the system | Medium |
| Physical (P) | Requires physical access to hardware | Lowest |

**Triage impact:** Network-exploitable vulnerabilities (AV:N) should be patched fastest -
they can be exploited by any attacker on the internet without needing prior access.

### Attack Complexity (AC) - How easy it is to exploit
| Value | Meaning |
|-------|---------|
| Low (L) | No special conditions required - reliably exploitable |
| High (H) | Specific conditions must exist or attacker must overcome defences |

**Triage impact:** AC:L means exploit tools likely exist and are widely available.

### Privileges Required (PR) - What access the attacker needs before exploiting
| Value | Meaning |
|-------|---------|
| None (N) | No account or authentication required |
| Low (L) | Standard user account required |
| High (H) | Administrator account required |

**Triage impact:** PR:N is most dangerous - any unauthenticated attacker can exploit it.

### User Interaction (UI) - Does the victim need to do something?
| Value | Meaning |
|-------|---------|
| None (N) | Exploit works without user action |
| Required (R) | User must click, open, or perform some action |

**Triage impact:** UI:N (no user interaction required) is a silent exploit — no phishing
needed. UI:R requires social engineering (phishing, malicious link), which reduces
the attack surface but does not eliminate the risk.

### Impact Metrics (Confidentiality, Integrity, Availability)
| Value | Meaning |
|-------|---------|
| High (H) | Complete compromise of that property |
| Low (L) | Limited impact |
| None (N) | No impact on this property |

**Triage impact:** C:H means the attacker can read all data on the system (data breach risk).
I:H means they can modify data. A:H means they can make the system unavailable (outage risk).

---

## CVE to Action Mapping - L1 Scope

When a vulnerability scan (Nessus, Qualys, or Microsoft Secure Score) produces
a CVE finding, the L1 analyst's job is:

```
1. Record the CVE ID and CVSS score
2. Confirm the affected system is in your environment:
   nvd.nist.gov → search CVE ID → read "Affected Systems" section
3. Check whether a patch is available:
   nvd.nist.gov → CVE entry → "References" section
   Or: vendor security advisory (Microsoft, Cisco, etc.)
4. Create a ticket based on CVSS score:
   Critical (9.0–10.0) → Create P1 Incident → escalate to Patch Management L2 immediately
   High (7.0–8.9)      → Create P2 Incident → assign to L2, patch within 7 days
   Medium (4.0–6.9)    → Log in next patch cycle → P3
   Low (0.1–3.9)       → Schedule for quarterly patch cycle → P4
5. Document in ticket:
   - CVE ID
   - CVSS score and severity
   - Affected host(s) and OS version
   - Patch availability (yes/no, patch KB number if Microsoft)
   - Escalation action taken
```

---

## Nessus Essentials - Severity Mapping

Nessus uses its own severity rating alongside CVSS. The mapping is:

| Nessus Rating | CVSS Equivalent | L1 Response |
|--------------|----------------|------------|
| Critical | 9.0–10.0 | Immediate escalation to L2 - P1 treatment |
| High | 7.0–8.9 | Escalate to L2 — patch within 7 days - P2 |
| Medium | 4.0–6.9 | Schedule for next patch cycle - P3 |
| Low | 0.1–3.9 | Add to quarterly patch planning - P4 |
| Informational | 0.0 | No vulnerability - configuration finding or information only |

---

## CVE Examples with Triage Interpretation

| CVE | CVSS | Severity | Why It Matters | Priority |
|-----|------|---------|----------------|---------|
| ProxyLogon (CVE-2021-26855) | 9.8 | Critical | RCE on Exchange - AV:N/AC:L/PR:N/UI:N - no auth, remote, trivial. Exploited widely within days of disclosure. | Patch immediately - hours, not days |
| Log4Shell (CVE-2021-44228) | 10.0 | Critical | RCE in Log4j library - AV:N/AC:L/PR:N/UI:N - any system using Log4j remotely exploitable. | Identify affected systems first - patch or mitigate immediately |
| EternalBlue (CVE-2017-0144) | 9.3 | Critical | SMB RCE - used by WannaCry. AV:N/AC:L/PR:N/UI:N. Still unpatched on many systems. | Critical - but if unpatched in 2026, investigate why |
| BlueKeep (CVE-2019-0708) | 9.8 | Critical | RDP RCE - AV:N/AC:L/PR:N/UI:N. RDP exposed to internet = immediate exploitation risk. | Critical - disable RDP to internet or patch immediately |
| PrintNightmare (CVE-2021-34527) | 8.8 | High | Windows Print Spooler privilege escalation - local authenticated user can escalate to SYSTEM. | High - patch within 7 days |


---
