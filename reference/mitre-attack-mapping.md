# MITRE ATT&CK Mapping - All Playbook Scenarios

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is the
industry-standard framework for classifying adversary behaviour at the tactic
and technique level. Every corporate security team uses it for threat intelligence,
detection engineering, red team scoping, and incident response.

Mapping your playbook scenarios to ATT&CK demonstrates that you understand the
attacker's perspective - not just the defensive checklist.

Reference: `attack.mitre.org`

---

## ATT&CK Tactics Overview (The "Why")

| Tactic | ID | Description | Relevance to L1 SOC |
|--------|-----|-------------|-------------------|
| Reconnaissance | TA0043 | Gather information about the target before attacking | Port scans, OSINT gathering - pre-attack visibility |
| Resource Development | TA0042 | Prepare attacker infrastructure | Newly registered domains, attacker-controlled email servers |
| Initial Access | TA0001 | Gain initial foothold | Phishing, drive-by, public-facing exploits |
| Execution | TA0002 | Run attacker-controlled code | PowerShell, macro, script execution |
| Persistence | TA0003 | Maintain foothold across reboots | Registry Run keys, scheduled tasks, services |
| Privilege Escalation | TA0004 | Gain higher privileges | Token impersonation, UAC bypass |
| Defense Evasion | TA0005 | Avoid detection | Obfuscation, signed binary proxy execution |
| Credential Access | TA0006 | Steal credentials | LSASS dumping, brute force, phishing for credentials |
| Discovery | TA0007 | Learn the environment | Account enumeration, network scanning |
| Lateral Movement | TA0008 | Move through the network | Pass-the-Hash, RDP, SMB shares |
| Collection | TA0009 | Gather data for exfiltration | File access, email collection |
| Command and Control | TA0011 | Communicate with compromised systems | C2 beaconing, DNS tunnelling |
| Exfiltration | TA0010 | Remove data from the network | Upload to attacker infrastructure |
| Impact | TA0040 | Disrupt or destroy | Ransomware, data destruction, defacement |

---

## Playbook 01 - Phishing Triage ATT&CK Mapping

| Scenario Component | Tactic | Technique | ID |
|-------------------|--------|-----------|-----|
| Phishing email with malicious link | Initial Access | Phishing - Spearphishing Link | T1566.002 |
| Phishing email with malicious attachment | Initial Access | Phishing - Spearphishing Attachment | T1566.001 |
| Fake credential harvesting login page | Credential Access | Phishing for Information | T1598 |
| User clicks the link | Execution | User Execution - Malicious Link | T1204.001 |
| User opens the attachment | Execution | User Execution - Malicious File | T1204.002 |
| Sender domain spoofing (display name vs From) | Defense Evasion | Masquerading | T1036 |
| Attacker uses newly registered domain | Resource Development | Acquire Infrastructure - Domains | T1583.001 |

**Why the ATT&CK mapping matters for triage:**

When a user clicks a link (T1204.001) to a credential harvesting page (T1598), the
attacker's next move is T1078 (Valid Accounts) - they will attempt to use the stolen
credentials immediately. In Microsoft 365, attackers typically:
1. Log in within 5–15 minutes of credential entry
2. Navigate to email to search for sensitive data (Collection - T1114)
3. Set up forwarding rules to maintain access after password change (Persistence - T1098)
4. Look for Azure admin portals or other high-value services using the same password

This is why the P1 response disables the account AND revokes sessions AND notifies
L2 Security simultaneously. Disabling the account without revoking sessions means
the attacker's existing browser session remains active. Revoking without disabling
allows them to re-authenticate. Both must be done together.

---

## Playbook 02 - Malware Alert Response ATT&CK Mapping

| Scenario Component | Tactic | Technique | ID |
|-------------------|--------|-----------|-----|
| Malware delivered via phishing email | Initial Access | Phishing | T1566 |
| Malware delivered via malicious website | Initial Access | Drive-by Compromise | T1189 |
| User executes malware from downloads | Execution | User Execution | T1204 |
| PowerShell download cradle executing payload | Execution | Command and Scripting Interpreter - PowerShell | T1059.001 |
| Macro-enabled Office document running VBA | Execution | Command and Scripting Interpreter - Visual Basic | T1059.005 |
| Registry Run key created for persistence | Persistence | Boot/Logon Autostart - Registry Run Keys | T1547.001 |
| Scheduled task created for persistence | Persistence | Scheduled Task/Job | T1053.005 |
| New Windows service created | Persistence | Create/Modify System Process - Windows Service | T1543.003 |
| LSASS memory dump (Mimikatz) | Credential Access | OS Credential Dumping - LSASS Memory | T1003.001 |
| Pass-the-Hash lateral movement | Lateral Movement | Use Alternate Authentication Material - Pass the Hash | T1550.002 |
| Attacker communicating back to C2 server | Command and Control | Application Layer Protocol | T1071 |
| C2 using DNS queries (DNS tunnelling) | Command and Control | Application Layer Protocol - DNS | T1071.004 |
| Data staged before exfiltration | Collection | Data Staged | T1074 |
| Exfiltration over existing C2 channel | Exfiltration | Exfiltration over C2 Channel | T1041 |

**Malware family to ATT&CK mapping:**

| Malware Family | Primary ATT&CK Techniques to Investigate |
|----------------|------------------------------------------|
| Trojan | T1071 (C2), T1547.001 (Registry persistence), T1003.001 (Credential dumping) |
| Ransomware | T1490 (Inhibit System Recovery - VSS deletion), T1486 (Data Encrypted for Impact) |
| RAT | T1071 (C2), T1113 (Screen Capture), T1056.001 (Keylogging), T1021 (Remote Services) |
| Dropper | T1204 (Execution), T1059 (Scripting), look for T1071 from the secondary payload |
| Worm | T1210 (Exploitation of Remote Services), T1021.002 (SMB/Windows Admin Shares) |
| Fileless | T1059.001 (PowerShell in memory), T1055 (Process Injection), T1140 (Deobfuscate/Decode) |

**Detection coverage - what Splunk detects for each technique:**

| Technique | ID | Splunk Detection Approach |
|-----------|-----|--------------------------|
| PowerShell execution | T1059.001 | Sysmon EventCode=1, CommandLine contains IEX/DownloadString/EncodedCommand |
| Scheduled task creation | T1053.005 | Windows Security EventCode=4698 |
| Registry Run key modification | T1547.001 | Sysmon EventCode=13 (Registry Value Set) on Run key paths |
| New service created | T1543.003 | Windows Security EventCode=7045 |
| LSASS access | T1003.001 | Sysmon EventCode=10, TargetImage=lsass.exe |
| Pass-the-Hash | T1550.002 | EventCode=4624, LogonType=3, AuthPackage=NTLM, dc(host) > 3 |
| C2 communication | T1071 | Firewall logs showing unusual outbound connections, DNS logs |

---

## Playbook 03 - Failed Auth ATT&CK Mapping

| Attack Pattern | Tactic | Technique | ID |
|----------------|--------|-----------|-----|
| Traditional brute force (many passwords, one account) | Credential Access | Brute Force | T1110 |
| Password spraying (common passwords across many accounts) | Credential Access | Brute Force - Password Spraying | T1110.003 |
| Credential stuffing (leaked credentials against live systems) | Credential Access | Brute Force - Credential Stuffing | T1110.004 |
| Attacker enumerating valid usernames (0xC0000064 errors) | Discovery | Account Discovery | T1087 |
| Using successfully compromised account | Persistence / Lateral Movement | Valid Accounts | T1078 |
| Pass-the-Hash after credential dumping | Lateral Movement | Use Alternate Auth Material - Pass the Hash | T1550.002 |

**Password spray vs credential stuffing - detection difference and response:**

| Attack | ATT&CK ID | Splunk Indicator | Response |
|--------|----------|-----------------|---------|
| Spray | T1110.003 | dc(Account_Name) > 10 per source IP in 1h window | P1 - block source IP, check all targeted accounts for success |
| Stuffing | T1110.004 | dc(src_ip) > 5 per Account_Name in 24h window | P1 - check for success, disable if compromised, advise password change on other services |
| Brute force | T1110 | count > 50 per Account_Name per source IP in 1h | P2 - block IP, reset account password |
| User error | None | count < 20, single source IP = user's workstation, during business hours | P3 - unlock, advise |

---

## Detection Coverage Heatmap

This table shows which tactics and techniques are covered by the playbooks in this
repository and the Splunk queries in `splunk/useful-spl-queries.md`.

| ATT&CK Tactic | Covered | Playbook | Primary Detection |
|---------------|---------|---------|-----------------|
| Initial Access (TA0001) | ✅ | Playbook 01 | Email gateway, user report |
| Execution (TA0002) | ✅ | Playbook 02 | Sysmon EventCode=1 CommandLine analysis |
| Persistence (TA0003) | ✅ | Playbook 02 | EventCode 7045, 4698, registry Sysmon events |
| Privilege Escalation (TA0004) | ⚠ Partial | - | Token impersonation - Sysmon EventCode 4672 |
| Defense Evasion (TA0005) | ⚠ Partial | Playbook 04 | Obfuscation detection in CommandLine |
| Credential Access (TA0006) | ✅ | Playbook 01, 03 | EventCode 4625/4740, Sysmon EventCode 10 |
| Discovery (TA0007) | ⚠ Partial | - | Port scan alerts, EventCode 4688 execution |
| Lateral Movement (TA0008) | ✅ | Playbook 02, 03 | EventCode 4624 LogonType=3 NTLM pattern |
| Collection (TA0009) | ⚠ Partial | - | File access auditing required |
| C2 (TA0011) | ⚠ Partial | Playbook 02 | Firewall outbound logs, DNS logs |
| Exfiltration (TA0010) | ⚠ Partial | - | Firewall bytes_out anomaly |
| Impact (TA0040) | ⚠ Partial | - | VSS deletion detection, file extension changes |

✅ = Covered with playbook and Splunk detection
⚠ Partial = Some detection capability but no dedicated playbook yet


---