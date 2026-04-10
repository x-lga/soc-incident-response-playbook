# Splunk SPL Queries — L1 SOC Reference

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