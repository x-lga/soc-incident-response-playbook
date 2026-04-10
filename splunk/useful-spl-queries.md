# Splunk SPL Queries - L1 SOC Reference

All queries tested in Splunk Free (local instance with forwarded Windows event logs).

---

## Authentication and Access

```spl
-- Failed logon attempts in last 24 hours by user
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name, src_ip, Failure_Reason
| sort -count

-- Account lockouts
index=windows_security EventCode=4740 earliest=-7d
| stats count by TargetUserName, src_ip
| sort -count

-- Successful logons outside business hours (before 07:00 or after 19:00)
index=windows_security EventCode=4624 earliest=-7d
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| stats count by Account_Name, src_ip, hour
| sort -count

-- Users logging in from multiple source IPs (potential account sharing or compromise)
index=windows_security EventCode=4624 earliest=-24h
| stats dc(src_ip) as unique_ips by Account_Name
| where unique_ips > 3
| sort -unique_ips
```

---

## Network and Firewall Events

```spl
-- Top talkers by bytes out (potential exfiltration)
index=firewall_logs earliest=-24h
| stats sum(bytes_out) as total_bytes by src_ip
| sort -total_bytes
| head 20
| eval total_MB = round(total_bytes/1024/1024, 2)

-- Outbound connections to unusual ports
index=firewall_logs action=allowed earliest=-24h
| where dest_port NOT IN (80, 443, 53, 25, 587, 3389, 22)
| stats count by src_ip, dest_ip, dest_port
| sort -count

-- Traffic to newly registered or rare domains (requires Threat Intel feed)
index=dns_logs earliest=-24h
| stats count by query
| sort count
| head 50
```

---

## System and Process Events

```spl
-- PowerShell execution with download commands (common malware dropper)
index=windows_sysmon EventCode=1 earliest=-24h
| where Image like "%powershell%" AND (CommandLine like "%DownloadString%" OR CommandLine like "%IEX%" OR CommandLine like "%Invoke-Expression%")
| table _time, host, User, CommandLine

-- Processes running from unusual locations
index=windows_sysmon EventCode=1 earliest=-24h
| where (Image like "%AppData%" OR Image like "%Temp%" OR Image like "%Downloads%") AND Image like "%.exe%"
| stats count by Image, User, host
| sort -count

-- New services created (persistence mechanism)
index=windows_security EventCode=7045 earliest=-24h
| table _time, host, ServiceName, ServiceFileName, ServiceAccount
```

---

## Alert Volume Management

```spl
-- Alert count by type over last 7 days (for identifying noisy rules)
index=alerts earliest=-7d
| stats count by alert_name, severity
| sort -count