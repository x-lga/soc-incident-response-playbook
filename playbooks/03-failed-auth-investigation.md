# Playbook 03 - Failed Authentication Investigation

**Category:** Security Event - Authentication  
**ITIL 4 Priority:** P2 (single user / low volume) / P1 (account lockout wave or brute force) 

---

## Symptom Patterns

| Pattern | Likely Cause | Priority |
|---------|-------------|---------|
| Single user, multiple failures, same time | User forgot password / fat fingers | P3 |
| Single user, failures from multiple IPs | Credential stuffing attack | P2 |
| Many users, failures in short window | Password spray attack | P1 |
| Failures outside business hours | Potential brute force / stolen credentials | P2 |

---

## Splunk Investigation (see splunk/ folder for full SPL)

```spl
# High-level: count failed logins per user in last 24 hours
index=windows_security EventCode=4625
| stats count by Account_Name, src_ip, failure_reason
| sort -count
| where count > 10

# Identify if failures come from multiple source IPs (stuffing indicator)
index=windows_security EventCode=4625 Account_Name="jsmith"
| stats dc(src_ip) as unique_ips, count by Account_Name
| where unique_ips > 3
```

---

## Windows Event IDs for Authentication

| Event ID | Description |
|---------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon — includes failure reason code |
| 4740 | Account locked out |
| 4767 | Account unlocked |
| 4648 | Logon attempt with explicit credentials |

**4625 Failure Reason Codes:**

| Code | Meaning |
|------|---------|
| 0xC000006A | Wrong password |
| 0xC0000064 | Username does not exist |
| 0xC000006D | Bad username or auth info |
| 0xC0000234 | Account locked out |
| 0xC000006F | Outside permitted logon hours |

---

## Response Procedure

1. Identify the account(s) involved and volume of failures
2. Pull Splunk query (above) for source IPs
3. Geolocate unusual source IPs (ipinfo.io or similar)
4. Check if account is currently locked: `Get-ADUser -Identity <user> -Properties LockedOut`
5. If single user, failures from expected location → password reset (see AD playbook)
6. If failures from unusual/foreign IPs → escalate to L2 Security immediately
7. Document IP addresses and country of origin in ticket
```

---