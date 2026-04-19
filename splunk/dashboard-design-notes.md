# Splunk Dashboard Design Notes - Security Overview

Built and validated in Splunk Free (local instance). All panels use inline SPL
with no lookup dependencies, no premium apps, and no scheduled alerts (not available
in Splunk Free). Every panel runs a real-time or time-ranged search against raw
index data.

---

## Dashboard Philosophy

Splunk Free constrains you to a single CPU core, no search concurrency controls,
no scheduled searches, and no role-based access. These dashboards are designed
around those constraints: every panel is lightweight, uses `earliest=` and `latest=`
strictly to avoid open-ended scans, and is grouped by triage priority so an L1
analyst can work top-to-bottom through them at shift start.

---

## Dashboard 1 - Security Overview (SOC Shift Start)

**Purpose:** Single-pane shift start. Answers "is anything on fire right now?"
in under 30 seconds without requiring analyst judgement for the first scan.

**Time range:** Last 24 hours (default), adjustable via time picker.

**Auto-refresh:** 5 minutes (slower prevents Splunk Free CPU saturation).

---

### Panel Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│  [Time Picker Input]          [Auto-Refresh: 5 min]                     │
├──────────────┬──────────────┬──────────────┬────────────────────────────┤
│ Failed Logons│ Account      │ Priv Logons  │ Alert Volume (7 days)      │
│   (Single)   │ Lockouts     │ After Hours  │   (Column Chart)           │
│              │  (Single)    │  (Single)    │                            │
├──────────────┴──────────────┴──────────────┴────────────────────────────┤
│            Top Failed Logon Accounts - Last 24h (Bar Chart)             │
├─────────────────────────────────────────────────────────────────────────┤
│            Failed vs Successful Logons Over Time (Line Chart)           │
├─────────────────────────────────────────────────────────────────────────┤
│  Suspicious Process Executions (Table - CommandLine truncated)          │
├─────────────────────────────────────────────────────────────────────────┤
│  Top Outbound Talkers (Table - src_ip, dest_ip, MB)                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Panel Specifications

#### KPI 1 - Failed Logon Count
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count
```
Threshold colouring:
- Green: 0-49
- Yellow: 50-199
- Red: 200+

Tune thresholds after 2 weeks of baseline observation in your environment.
Generic defaults generate constant yellow noise.

#### KPI 2 - Account Lockouts
```spl
index=windows_security EventCode=4740 earliest=-24h
| stats count
```
Threshold colouring:
- Green: 0
- Yellow: 1-4
- Red: 5+

#### KPI 3 - Privileged Account Logons Outside Business Hours
```spl
index=windows_security EventCode=4624 earliest=-24h
| eval hour=strftime(_time, "%H")
| where (hour < 7 OR hour > 19)
| search Account_Name IN ("Administrator", "*admin*", "*svc*")
| stats count
```
Threshold colouring:
- Green: 0
- Yellow: 1–2
- Red: 3+

Expand the Account_Name search filter to match your environment's naming convention
for privileged accounts (e.g., include your actual service account prefixes).

#### KPI 4 - Alert Volume Last 7 Days (Column Chart)
```spl
index=alerts earliest=-7d
| timechart span=1d count by severity
```
Series colours: critical=red, high=orange, medium=yellow, low=blue.
A spike in alert volume may indicate a scanning campaign, a new attack wave,
or a misconfigured detection rule generating noise. Either requires attention.

#### Row 2 - Top Failed Logon Accounts (Bar Chart)
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name
| sort -count
| head 10
```
X-axis: Account_Name | Y-axis: count
Drill-down: clicking a bar should set a token `$selected_account$` that filters
dependent panels to show events for that account only.

#### Row 3 - Logon Activity Over Time (Line Chart)
```spl
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-24h
| eval event_type=if(EventCode=4624, "Success", "Failure")
| timechart span=1h count by event_type
```
Two series: Success (blue), Failure (red).
Visualising both on the same chart makes anomalies obvious. A spike in failures
without a corresponding success spike = brute force attempt (not a service outage).
A spike in successes without preceding failures = unusual logon wave.

#### Row 4 - Suspicious Process Executions (Table)
```spl
index=windows_sysmon EventCode=1 earliest=-24h
| where (Image like "%AppData%" OR Image like "%Temp%" OR Image like "%Downloads%")
      OR (CommandLine like "%IEX%" OR CommandLine like "%DownloadString%"
          OR CommandLine like "%EncodedCommand%")
| table _time, host, User, Image, CommandLine
| sort -_time
| head 20
```
Columns: _time, host, User, Image, CommandLine.
Set CommandLine column to wrap text. Long CommandLine values contain the most
forensically useful information and should not be truncated in the table view.

#### Row 5 - Outbound Traffic Top Talkers (Table)
```spl
index=firewall_logs action=allowed earliest=-24h
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval total_MB = round(total_bytes/1024/1024, 2)
| sort -total_MB
| head 15
| fields src_ip, dest_ip, total_MB
```

---

## Dashboard 2 - Authentication Deep Dive

**Purpose:** Used when a failed-logon spike triggers during triage. Provides granular
breakdown by user, source IP, time, and success/failure ratio.

**Trigger:** Linked from the Failed Logon KPI via drill-down.

### Key Panels

| Panel | Type | SPL Summary |
|-------|------|-------------|
| Failed logons by user (last 7d) | Bar chart | stats count by Account_Name, sorted desc |
| Failed logons by source IP | Bar chart | stats count by src_ip, sorted desc |
| Lockout timeline | Line chart | timechart of EventCode=4740 by TargetUserName |
| Multi-IP logon users | Table | dc(src_ip) > 3 by Account_Name |
| Success/Failure ratio by user | Table | xyseries of outcomes |

**Success/failure ratio - full SPL:**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-7d
| eval outcome = if(EventCode=4624, "success", "failure")
| stats count by Account_Name, outcome
| xyseries Account_Name outcome count
| fillnull value=0
| eval fail_rate = round(failure / (success + failure) * 100, 1)
| sort -failure
```

---

## Dashboard 3 - Endpoint Threat Indicators

**Purpose:** Host-based signal investigation. Used during escalation to T2 or when
corroborating a network-layer alert with endpoint evidence.

### Panels

| Panel | Sysmon EventCode | Threat Relevance |
|-------|-----------------|-----------------|
| New Windows services | 7045 | Persistence (T1543.003) |
| Scheduled tasks created | 4698, 4702 | Persistence (T1053.005) |
| PowerShell encoded / download commands | 1 | Execution (T1059.001) |
| LSASS access events | 10 (Sysmon) | Credential dumping (T1003.001) |
| Lateral movement NTLM pattern | 4624 LogonType=3 NTLM | Lateral movement (T1550.002) |

**LSASS access - full SPL:**
```spl
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe" earliest=-24h
| table _time, host, SourceImage, SourceCommandLine, GrantedAccess
| sort -_time
```

---

## General Design Notes

### Tokens and Drill-Down
Define a `$host$` token on the dashboard. Every table including `host` should pass
the clicked value to this token and use it to filter dependent panels. This turns
any row click into a host-scoped investigation view without leaving the dashboard.

### Performance on Splunk Free
Splunk Free limits searches to a single CPU core with no concurrency controls.
To keep dashboards responsive:
- Always use `earliest=` and `latest=` on every search
- Apply `| head N` before expensive `| stats` operations where possible
- Avoid `| transaction` - replace with `| stats` and `| eventstats`
- Dashboard auto-refresh should be no faster than 5 minutes

### Colour Conventions
| Colour | Meaning |
|--------|---------|
| Red | Critical / confirmed malicious |
| Orange | High severity / requires review |
| Yellow | Medium / suspicious but unconfirmed |
| Blue | Informational / baseline |
| Green | Within normal thresholds |

### XML - Threshold Colouring on a Single Value Panel
```xml
<option name="rangeColors">["0x65A637","0xF7BC38","0xD93F3C"]</option>
<option name="ranges">[0,50,200]</option>
<option name="colorMode">block</option>
```
Adjust range boundaries after 2 weeks of baseline observation.


---