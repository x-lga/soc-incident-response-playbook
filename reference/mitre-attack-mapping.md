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

## Playbook 04 - False Positive Classification ATT&CK Mapping

At first glance, false positive classification does not seem to have an ATT&CK
mapping - it is a defensive process, not an attack technique. That framing misses
the point. Understanding why something is a false positive requires understanding
what the attacker's real technique looks like, so you can recognise the difference
between a legitimate tool doing legitimate work and a legitimate tool being abused
by an attacker. Every row in the FP decision matrix is grounded in a specific
ATT&CK technique. If you do not know the technique, you cannot classify the alert.

---

### Why Attackers Deliberately Mimic False Positives (Living-off-the-Land)

The most sophisticated attacks do not use custom malware or exotic tools.
They use the tools already present on every Windows machine - PowerShell, WMI,
PsExec, scheduled tasks, Windows services. This is the MITRE ATT&CK category
known as **Living off the Land (LotL)**, and it is the primary reason FP
classification is difficult and high-stakes.

The attacker's goal is to be indistinguishable from normal administrative activity.
A Tier 1 analyst who does not understand the attacker perspective will see a
PsExec execution and think "that looks like the admin doing something" and dismiss
it. An analyst who understands ATT&CK will ask: "Is this PsExec execution consistent
with a known admin task on a known schedule? Or is it a new source, new target,
unusual time, or unexpected CommandLine?" The ATT&CK mapping is what tells you
which questions to ask.

---

### ATT&CK Mapping - FP Decision Matrix Row by Row

| Alert Type | Legitimate (True FP) | Malicious (True TP) | Technique if Malicious | Tactic |
|-----------|---------------------|---------------------|----------------------|--------|
| Port scan detected | Nessus/Qualys/Tenable scheduled scan by IT (verify scan schedule and scanner IP) | External or internal probe from unexpected source | T1595 - Active Scanning | Reconnaissance (TA0043) |
| PsExec / admin tool usage | IT admin using PsExec for authorised remote support (expected source, expected target, business hours) | PsExec from non-admin account, unexpected workstation, after hours, or targeting a DC | T1569.002 - System Services: Service Execution | Execution (TA0002) |
| Large outbound data transfer | Scheduled backup to cloud, approved file migration, software update download | Data staged internally then exfiltrated to attacker infrastructure | T1041 - Exfiltration Over C2 Channel / T1567 - Exfiltration Over Web Service | Exfiltration (TA0010) |
| Failed auth spike on one account | Password expiry, cached credentials on old device, user forgot password | Brute force (T1110) or credential stuffing (T1110.004) | T1110 - Brute Force | Credential Access (TA0006) |
| PowerShell DownloadString / IEX | SCCM deployment script, approved automation, software packaging tool | Malware dropper downloading secondary payload in memory | T1059.001 - Command and Scripting Interpreter: PowerShell | Execution (TA0002) |
| New scheduled task created | Software update installer, approved IT deployment task | Malware establishing persistence - survives reboot without a running process | T1053.005 - Scheduled Task/Job: Scheduled Task | Persistence (TA0003) |
| New Windows service installed | Software installation, Windows Update component | Malware registering itself as a service for persistence and auto-start | T1543.003 - Create or Modify System Process: Windows Service | Persistence (TA0003) |
| Outbound traffic on unusual port | Developer testing a new API, application using non-standard port | C2 communication using a non-standard port to evade firewall rules that allow standard ports | T1571 - Non-Standard Port | Command and Control (TA0011) |
| NTLM auth, LogonType=3 to many hosts | Admin mapping network shares, SCCM inventory, legitimate admin scripting | Pass-the-Hash lateral movement - attacker reusing captured hash to authenticate across hosts | T1550.002 - Use Alternate Authentication Material: Pass the Hash | Lateral Movement (TA0008) |
| Admin account used from new IP | Admin working from home, VPN exit node changed, new machine | Compromised admin credentials used from attacker infrastructure in a different geography | T1078 - Valid Accounts | Initial Access (TA0001) / Lateral Movement (TA0008) |

---

### The Core ATT&CK Insight Behind FP Classification

Every row in this table has the same underlying structure:

```
Attacker technique:    Use a legitimate tool or behaviour pattern
Why it works:          It looks like normal administrative activity
How to distinguish:    Context - source, destination, time, frequency, baseline
What ATT&CK provides:  The exact technique name and ID, so you know
                       which contextual questions to ask
```

**Worked example - PsExec (T1569.002):**

PsExec is a legitimate Sysinternals tool used by IT admins for remote command
execution. It is also one of the most commonly abused tools by attackers after
gaining initial access - used for lateral movement to deploy ransomware, exfiltrate
data, or establish footholds on additional machines.

Without ATT&CK knowledge: "PsExec execution detected - that is probably an admin."

With ATT&CK knowledge (T1569.002 - System Services: Service Execution):
- Is the source machine a known admin workstation? (If no → investigate)
- Is the target machine a normal target for this admin? (If no → investigate)
- Is the CommandLine argument a known admin task? (If no → investigate)
- Did this happen during business hours? (If outside hours → investigate)
- Is this consistent with the last 30 days of baseline? (If not → investigate)

The technique ID gives you the exact behavioural fingerprint to compare against.
Classifying this as FP without answering all five questions is how breaches
go undetected for 16+ days.

**Worked example - PowerShell DownloadString (T1059.001):**

PowerShell with DownloadString is used by SCCM to deploy software packages,
by Intune to run configuration scripts, and by developers for legitimate automation.
It is also the most common malware dropper technique - the first stage of a
multi-stage payload downloads the second stage entirely in memory using IEX
(Invoke-Expression) so no file is written to disk.

The FP vs TP distinction is entirely in the context:
- FP: source is the SCCM server IP, CommandLine matches a known deployment script,
  time matches the deployment schedule
- TP: source is a user workstation, CommandLine contains an obfuscated or
  Base64-encoded string, time is outside business hours, no matching change record

Without understanding T1059.001 and why IEX + DownloadString in memory is a
standard evasion technique (no file = no AV scan), you will dismiss the TP as
a noisy deployment script.

---

### ATT&CK Detection Coverage - Playbook 04 Contribution

Adding Playbook 04 to the coverage heatmap extends detection into techniques
that produce FP-like signals - the hardest category to detect correctly:

| Technique | ID | Detection Challenge | Playbook 04 Guidance |
|-----------|-----|--------------------|--------------------|
| Active Scanning | T1595 | Scanner IP may be internal | Verify scanner IP against known scanners list before classifying FP |
| System Services: Service Execution | T1569.002 | PsExec is a legitimate admin tool | Source, target, CommandLine, and time all must match known admin pattern |
| PowerShell | T1059.001 | Deployment scripts look identical to droppers | DownloadString from SCCM IP vs from user workstation are entirely different risks |
| Scheduled Task | T1053.005 | Many legitimate tasks exist | New tasks created outside maintenance windows without a change record = TP |
| Windows Service | T1543.003 | Many legitimate services exist | New services not matching known software installs = TP |
| Non-Standard Port | T1571 | Developer testing looks identical to C2 | Developer testing is temporary; C2 is persistent and beacons on a schedule |
| Pass-the-Hash | T1550.002 | NTLM LogonType=3 is common | Volume (many hosts) + unusual source + NTLM (not Kerberos) = TP pattern |
| Valid Accounts | T1078 | Legitimate admin logons from home | New geography + new device + unusual hours + no VPN = TP pattern |

---

### Why This Mapping Makes the Playbook More Valuable

The FP classification playbook without ATT&CK context is a checklist:
"check the source IP, check the time, check the baseline." Useful, but mechanical.

The FP classification playbook with ATT&CK context is a threat model:
"I know exactly what T1569.002 looks like when an attacker uses it, I know
what questions distinguish attacker from admin, and I know which details to
document in the FP record so the tuning recommendation does not accidentally
whitelist the real attack technique."

That is the difference between a Tier 1 analyst who runs through steps and one
who understands why the steps exist - and who therefore cannot be fooled by an
attacker who has read the same checklist.

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