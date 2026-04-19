# Playbook 03 - Failed Authentication Investigation

**Category:** Security Event - Authentication Anomaly  
**ITIL 4 Priority:** P3 (single user, low volume, expected source) |
                     P2 (unusual source IP, moderate volume) |
                     P1 (password spray, credential stuffing, confirmed brute force)  
**SLA - P1 Response:** 15 minutes | **P1 Resolution:** 4 hours  
**SLA - P2 Response:** 1 hour | **P2 Resolution:** 8 hours  
**MITRE ATT&CK coverage:** T1110 (Brute Force), T1110.001 (Password Guessing),
T1110.002 (Password Cracking), T1110.003 (Password Spraying),
T1110.004 (Credential Stuffing), T1078 (Valid Accounts),
T1550.002 (Pass-the-Hash), T1556 (Modify Authentication Process)  
**Last reviewed:** 2026-07

---

## Understanding Authentication Attack Patterns: Why They Look Different in Logs

Failed authentication events are high-volume in any domain environment. Users forget
their passwords, lock themselves out, or type into the wrong field. The skill is
distinguishing the statistically normal noise from the signal of an active credential
attack. The distinction lives in the pattern — not in the individual event.

---

### Pattern 1: Benign User Error

**What it looks like in logs:**
Single account, low failure count (5-20), single source IP consistent with the user's
normal workstation IP, failures occurring during the user's normal working hours, user
calls the help desk reporting they cannot log in.

**ATT&CK:** Not applicable - no attacker activity.

**L1 Response:** Standard account unlock and/or password reset. P3.

---

### Pattern 2: Traditional Brute Force (T1110)

**What it looks like in logs:**
Single account, very high failure count (50-10,000+ in a short window), single or few
source IPs, often outside business hours, often originating from an external IP.

```spl
-- Detect brute force: one account, high failure count, single source IP
index=windows_security EventCode=4625 earliest=-1h
| stats count as failures by Account_Name, src_ip
| where failures > 50
| sort -failures
```

**ATT&CK:** T1110 (Brute Force) - attacker trying many passwords against one account.

**L1 Response:**
- Lock out or change password on the targeted account
- Block the source IP at the perimeter firewall or via Entra ID Conditional Access
- Escalate to L2 to review whether the account is still secure

---

### Pattern 3: Password Spray (T1110.003)

**What it looks like in logs:**
Many accounts (potentially all accounts in the directory), very low failure count per
account (1-5 attempts each), single or few source IPs, concentrated time window.

The attacker has a list of valid usernames (obtained through OSINT or prior enumeration)
and is trying a small number of common passwords against each account - staying below
the lockout threshold to avoid triggering automated detection per-account.

This is the most dangerous and most common enterprise credential attack technique.
It bypasses per-account lockout monitoring entirely. It only becomes visible when
you aggregate failures across accounts.

```spl
-- Detect password spray: many accounts, low count per account, same source IP
-- High unique accounts + low total failures per account = spray pattern
index=windows_security EventCode=4625 earliest=-1h
| stats
    dc(Account_Name) as unique_accounts_targeted,
    count as total_failures,
    values(Account_Name) as targeted_accounts
  by src_ip
| where unique_accounts_targeted > 10
| eval failures_per_account = round(total_failures / unique_accounts_targeted, 1)
| sort -unique_accounts_targeted
```

**ATT&CK:** T1110.003 (Password Spraying).

**L1 Response:** P1. Escalate immediately by phone. Block the source IP.
Do NOT unlock individual accounts (they will re-lock immediately). Document the
full list of targeted accounts - the attacker may have succeeded on one of them.

---

### Pattern 4: Credential Stuffing (T1110.004)

**What it looks like in logs:**
Single account, moderate failure count, many different source IPs. The attacker
has credential pairs (username + password) from a breach of a different service and
is trying them against your systems. The spread across many IPs is designed to evade
per-IP rate limiting.

```spl
-- Detect credential stuffing: one account, failures from many different IPs
index=windows_security EventCode=4625 earliest=-24h
| stats
    dc(src_ip) as unique_source_ips,
    count as total_failures
  by Account_Name
| where unique_source_ips > 5
| sort -unique_source_ips
```

**ATT&CK:** T1110.004 (Credential Stuffing).

**L1 Response:**
- Check whether any authentication from any of those IPs succeeded (EventCode=4624)
- If a success is present after the failures: treat as active account compromise — P1
- Block the targeted account if the user can be reached and credentials changed
- Escalate to L2

---

## Windows Event IDs for Authentication Investigation

| Event ID | Description | Key Fields to Review |
|---------|-------------|---------------------|
| 4624 | Successful logon | Account_Name, Logon_Type, IpAddress, Authentication_Package |
| 4625 | Failed logon | Account_Name, Failure_Reason, Sub_Status, IpAddress, Logon_Type |
| 4634 | Account logoff | Account_Name, Logon_ID (correlate with 4624) |
| 4648 | Logon with explicit credentials (RunAs / mapped drive) | Account_Name, Target_Server, IpAddress |
| 4672 | Special privileges assigned (admin logon) | Account_Name, Privileges |
| 4720 | User account created | New_Account_Name, Subject_Account (who created it) |
| 4740 | Account locked out | Target_Account, Caller_Machine |
| 4767 | Account unlocked | Target_Account, Subject_Account |
| 4776 | NTLM credential validation | Account_Name, Workstation, Error_Code |

**4625 Sub-Status Codes - exact reason for failure:**

| Sub-Status | Meaning | Investigation Direction |
|-----------|---------|------------------------|
| 0xC000006A | Wrong password - account exists | Normal user error, or brute force in progress |
| 0xC0000064 | Username does not exist | Attacker guessing usernames (enumeration) |
| 0xC000006D | Generic auth failure | Check Logon_Type for additional context |
| 0xC0000234 | Account locked out | Check what caused the lockout - brute force? |
| 0xC000006F | Outside permitted logon hours | Account has time restrictions |
| 0xC000015B | Logon type not granted | Account trying an unauthorised logon method |
| 0xC0000193 | Account expired | Contractor or temp account past expiry |
| 0xC0000224 | Must change password | User must change but is using old password |

---

## Investigation Procedure

### Step 1 - Determine scope and initial classification

```spl
-- Starting point: all accounts with 10+ failures in last hour
index=windows_security EventCode=4625 earliest=-1h
| stats count as failures by Account_Name, src_ip, Failure_Reason
| where failures >= 10
| sort -failures

-- Check time distribution - was this a burst or sustained?
index=windows_security EventCode=4625 Account_Name="TARGET-ACCOUNT" earliest=-24h
| timechart span=15m count
```

---

### Step 2 - Profile the source IPs

```spl
-- All source IPs targeting a specific account in the last 24 hours
index=windows_security EventCode=4625 Account_Name="TARGET-ACCOUNT" earliest=-24h
| stats count as failures by src_ip
| sort -failures

-- Check if the source IP is internal (corporate network) or external
-- Internal IPs (10.x.x.x, 172.16.x.x, 192.168.x.x) suggest:
-- - User is on the wrong machine
-- - Cached credentials on a device with old password
-- - Legitimate brute force from a compromised internal machine
-- External IPs suggest: external attack
```

Geolocate external IPs:
```powershell
# Quick geolocation check from PowerShell
$IP = "203.0.113.45"
try {
    $GeoData = Invoke-RestMethod "https://ip-api.com/json/$IP" -ErrorAction Stop
    Write-Host "IP      : $IP"
    Write-Host "Country : $($GeoData.country)"
    Write-Host "City    : $($GeoData.city)"
    Write-Host "ISP     : $($GeoData.isp)"
    Write-Host "Mobile  : $($GeoData.mobile)"
    Write-Host "Hosting : $($GeoData.hosting)"
} catch {
    Write-Host "Geolocation unavailable for $IP"
}
```

Red flags: Country where no employees are located. IP from a cloud hosting provider
or VPN service. IP on a known spam or attack IP blocklist.

---

### Step 3 - Check for successful logon after failures

This is the most critical query in any brute force investigation. A successful logon
after a series of failures may indicate the attacker eventually guessed the correct password.

```spl
-- Was there a successful logon for this account in the same window?
index=windows_security EventCode=4624 Account_Name="TARGET-ACCOUNT" earliest=-24h
| table _time, IpAddress, Workstation_Name, Logon_Type, Authentication_Package
| sort -_time

-- Cross-reference: failures AND successes for the same account
-- from the SAME source IP (indicates attacker succeeded after failed attempts)
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-24h
    Account_Name="TARGET-ACCOUNT"
| eval event_type = if(EventCode=4624, "SUCCESS", "FAILURE")
| stats count by IpAddress, event_type
| xyseries IpAddress event_type count
| fillnull value=0
| where SUCCESS > 0 AND FAILURE > 0
```

If the same source IP has both failures and a success: treat as confirmed credential
compromise. Escalate to P1 immediately.

---

### Step 4 - Assess account lockout status

```powershell
# Check current lockout status for the targeted account
Get-ADUser -Identity "TARGET-SAMACCOUNTNAME" `
    -Properties LockedOut, BadLogonCount, LastBadPasswordAttempt,
                Enabled, LastLogonDate, PasswordLastSet |
    Select-Object Name, LockedOut, BadLogonCount,
                  LastBadPasswordAttempt, Enabled, LastLogonDate
```

---

### Step 5 - Response based on confirmed pattern

**P3 - Benign user error:**
- Unlock account (Unlock-ADUserAccount.ps1)
- Reset password if expired or if user has forgotten it
- Advise user to check for saved credentials on other devices
- Close as P3 Incident with documentation

**P2 - Brute force (single account, high count, external IP):**
- Unlock account and reset password to a strong passphrase
- Block the source IP at the perimeter or via Entra ID Conditional Access
  named location policy
- Document source IP, failure volume, and time window
- Escalate to L2 for review: Is this account targeted because the username is guessable?
  Should MFA be enforced on this account?

**P1 - Password spray (many accounts, low count per account):**
- Phone call to L2 Security immediately - this is an active attack
- Block the source IP(s) at the perimeter
- Do NOT unlock individual accounts while the attack is ongoing
- Document the complete list of targeted accounts
- Check whether any targeted account has also had a successful logon
  (use the cross-reference query from Step 3)

**P1 - Credential stuffing (one account, many source IPs):**
- Phone call to L2 Security immediately
- Check all source IPs for any successful logon (Step 3 query)
- If any success found: P1 active compromise - disable account and revoke sessions
- Escalate with full source IP list and success/failure timeline
- Recommend the user change this password on all services where they may
  have reused it (the breach that provided the credential pair likely affects
  other services too)

---

## Pass-the-Hash Investigation (T1550.002)

Pass-the-Hash (PtH) is a lateral movement technique where an attacker uses a
captured NTLM password hash - not the plaintext password - to authenticate as a
user to other systems on the network. The hash is obtained by dumping LSASS memory
on a previously compromised machine (Mimikatz, Sekurlsa::logonpasswords).

PtH does not require cracking the password. The hash itself is sufficient for
NTLM authentication. It appears in logs as apparently legitimate network authentication.

**Detection in Splunk:**
```spl
-- Pass-the-Hash indicators:
-- NTLM authentication (not Kerberos), LogonType=3 (network logon), not anonymous
-- Multiple destination computers from same source in short window
index=windows_security EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
    earliest=-24h
| where Account_Name != "ANONYMOUS LOGON"
| stats
    dc(host) as destinations_reached,
    values(host) as destination_list,
    count as total_logons
  by Account_Name, IpAddress
| where destinations_reached > 3
| sort -destinations_reached

-- Correlate with LSASS access (Sysmon EventCode 10 - Process Access to LSASS)
-- This indicates a credential dumping tool may have been used on the source machine
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe" earliest=-24h
| table _time, host, SourceImage, SourceCommandLine, GrantedAccess
| sort -_time
```

**Why PtH is significant:**
PtH requires that the attacker has already compromised at least one machine and has
obtained admin privileges on it (to dump LSASS). Detecting PtH means an attacker
is inside the network, has admin credentials, and is actively moving laterally.
This is a P1 incident requiring immediate escalation.

**Indicators that differentiate PtH from legitimate NTLM:**
- Source workstation is not the user's usual machine
- Authentication is to many different destination servers in a short time window
- Authentication occurs outside the user's normal working hours
- The user is authenticated from two different machines simultaneously
  (the original legitimate session + the attacker's PtH session)


---