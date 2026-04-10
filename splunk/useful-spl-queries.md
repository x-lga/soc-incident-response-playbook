# Splunk SPL Queries — L1 SOC Reference

All queries tested in Splunk Free (local instance with forwarded Windows event logs).

---

## Authentication and Access

```spl
-- Failed logon attempts in last 24 hours by user
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name, src_ip, Failure_Reason
| sort -count