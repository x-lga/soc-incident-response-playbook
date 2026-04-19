# Splunk SPL Queries - L1 SOC Reference

All queries in this file were developed and tested in a Splunk Free instance
with Windows Security Event Logs forwarded from a Windows Server 2022 domain
controller via the Splunk Universal Forwarder.

Index names used throughout: `windows_security` (Windows Security events),
`windows_sysmon` (Sysmon events), `firewall_logs` (pfSense firewall logs).
Adjust index names to match your Splunk deployment.

---

## Authentication and Access Events

### Failed logon summary - last 24 hours
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name, src_ip, Failure_Reason
| sort -count
| rename count as failures
```

### Account lockouts - last 7 days
```spl
index=windows_security EventCode=4740 earliest=-7d
| stats count as lockout_count by TargetUserName, src_ip
| sort -lockout_count
```

### Successful logons outside business hours (before 07:00 or after 19:00)
```spl
index=windows_security EventCode=4624 earliest=-7d
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| stats count by Account_Name, src_ip, hour
| sort -count
```

### Users logging in from multiple different source IPs - potential account sharing or compromise
```spl
index=windows_security EventCode=4624 earliest=-24h
| stats dc(src_ip) as unique_ips, values(src_ip) as ip_list
    by Account_Name
| where unique_ips > 3
| sort -unique_ips
```

### Password spray detection - many accounts, low failures per account
```spl
index=windows_security EventCode=4625 earliest=-1h
| stats
    dc(Account_Name) as unique_accounts,
    count as total_failures
  by src_ip
| where unique_accounts > 10
| eval failures_per_account = round(total_failures / unique_accounts, 1)
| sort -unique_accounts
```

### Credential stuffing detection - one account, many source IPs
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats dc(src_ip) as unique_ips, count as failures by Account_Name
| where unique_ips > 5
| sort -unique_ips
```

### Successful logon after multiple failures (possible successful brute force)
```spl
-- Step 1: Find accounts with both failures and successes from the same IP
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-24h
| eval event_type = if(EventCode=4624, "SUCCESS", "FAILURE")
| stats count by Account_Name, src_ip, event_type
| xyseries Account_Name src_ip event_type count
| fillnull value=0
| where SUCCESS > 0 AND FAILURE > 3
```

### Admin accounts logging in after hours
```spl
index=windows_security EventCode=4624 earliest=-7d
| eval hour=strftime(_time, "%H")
| where (hour < 7 OR hour > 19)
| search Account_Name IN ("Administrator", "*admin*", "*Admin*", "*svc*")
| stats count by Account_Name, src_ip, hour
| sort -count
```

---

## Process Execution and Endpoint Events (Sysmon)

### PowerShell with download/execution indicators - dropper detection (T1059.001)
```spl
index=windows_sysmon EventCode=1 earliest=-24h
| where Image like "%powershell%" AND (
    CommandLine like "%DownloadString%" OR
    CommandLine like "%IEX%" OR
    CommandLine like "%Invoke-Expression%" OR
    CommandLine like "%DownloadFile%" OR
    CommandLine like "%WebClient%" OR
    CommandLine like "%EncodedCommand%" OR
    CommandLine like "%-enc%" OR
    CommandLine like "%FromBase64String%"
  )
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time
```

### Processes executing from suspicious locations
```spl
index=windows_sysmon EventCode=1 earliest=-24h
| where (
    Image like "%AppData%" OR
    Image like "%Temp%" OR
    Image like "%Downloads%" OR
    Image like "%Public%"
  ) AND Image like "%.exe%"
| stats count by Image, User, host
| sort -count
```

### New Windows services created - persistence check (T1543.003)
```spl
index=windows_security EventCode=7045 earliest=-24h
| table _time, host, ServiceName, ServiceFileName, ServiceAccount
| sort -_time
```

### Scheduled tasks created - persistence check (T1053.005)
```spl
index=windows_security EventCode=4698 earliest=-24h
| table _time, host, SubjectUserName, TaskName, TaskContent
| sort -_time
```

### Process accessing LSASS memory - credential dumping (T1003.001)
```spl
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe" earliest=-24h
| table _time, host, SourceImage, SourceCommandLine, GrantedAccess
| sort -_time
```

### Lateral movement via Pass-the-Hash (T1550.002)
```spl
index=windows_security EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
    earliest=-24h
| where Account_Name != "ANONYMOUS LOGON"
| stats
    dc(host) as destinations,
    values(host) as destination_list,
    count as logons
  by Account_Name, IpAddress
| where destinations > 3
| sort -destinations
```

---

## Network and Firewall Events

### Top outbound talkers by bytes - potential data exfiltration detection
```spl
index=firewall_logs action=allowed earliest=-24h
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval total_MB = round(total_bytes/1024/1024, 2)
| sort -total_MB
| head 20
| fields src_ip, dest_ip, total_MB
```

### Outbound connections to unusual ports (not standard web or email)
```spl
index=firewall_logs action=allowed earliest=-24h
| where dest_port NOT IN (80, 443, 53, 25, 587, 993, 995, 22, 123, 3389, 5985)
| stats count by src_ip, dest_ip, dest_port, protocol
| sort -count
| head 50
```

### Connections to known-malicious IPs (requires threat intel feed or lookup table)
```spl
-- Assumes a lookup table named "malicious_ips.csv" with field "ip"
index=firewall_logs earliest=-24h
| lookup malicious_ips ip as dest_ip OUTPUT threat_category, confidence
| where isnotnull(threat_category)
| table _time, src_ip, dest_ip, dest_port, threat_category, confidence
| sort -confidence
```

### DNS queries to newly registered or unusual domains
```spl
index=dns_logs earliest=-24h
| stats count by query, src_ip
| sort -_time
| head 100
```

---

## Alert Volume and Quality Management

### Alert count by type over last 7 days - identify noisy rules
```spl
index=alerts earliest=-7d
| stats count by alert_name, severity
| sort -count
```

### Alert-to-investigation ratio by rule - false positive rate proxy
```spl
index=alerts earliest=-30d
| stats
    count as total_alerts,
    count(eval(status="false_positive")) as fp_count,
    count(eval(status="true_positive")) as tp_count
  by alert_name
| eval fp_rate = round((fp_count / total_alerts) * 100, 1)
| eval tp_rate = round((tp_count / total_alerts) * 100, 1)
| sort -fp_rate
```

### MFA fatigue attack detection - many MFA failures followed by success
```spl
-- Detects pattern where many MFA prompts were rejected (fatigue attack)
-- followed by an eventual success (user approved under fatigue)
index=auth_logs result=mfa_failure earliest=-1h
| stats count as mfa_failures by user, src_ip
| where mfa_failures > 10
| join user [
    search index=auth_logs result=mfa_success earliest=-1h
    | stats count as mfa_successes by user
  ]
| where mfa_successes > 0
| table user, src_ip, mfa_failures, mfa_successes
```


---