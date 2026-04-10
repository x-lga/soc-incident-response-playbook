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
