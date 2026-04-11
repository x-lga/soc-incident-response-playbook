# Splunk Dashboard Design Notes - Security Overview

Built and validated on Splunk Free (local instance). All panels use inline SPL - no lookup dependencies or premium app requirements.

---

## Dashboard Philosophy

Splunk Free has no role-based access, scheduled alerts, or summary indexing. These dashboards are designed around that constraint: every panel runs a real-time or time-ranged search on raw index data. Panels are grouped by triage priority so an L1 analyst can work top-to-bottom during a shift handover.

---

## Dashboard 1 - Security Overview (SOC Home)

**Purpose:** Single-pane shift start. Answers "is anything on fire right now?" in under 30 seconds.

**Time range token:** Last 24 hours (default), adjustable via time picker input.

---

### Panel Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  [Time Picker]   [Auto-refresh: 5 min]                              │
├──────────────┬──────────────┬──────────────┬───────────────────────┤
│ Failed Logons│ Account      │ Priv Logons  │  Alert Volume (7d)    │
│   (Single)   │ Lockouts     │  Off-Hours   │    (Column Chart)     │
│              │  (Single)    │  (Single)    │                       │
├──────────────┴──────────────┴──────────────┴───────────────────────┤
│              Top Failed Logon Users (Bar Chart)                     │
├─────────────────────────────────────────────────────────────────────┤
│              Logon Activity Over Time (Line Chart)                  │
├─────────────────────────────────────────────────────────────────────┤
│  Suspicious Process Executions (Table)                              │
├─────────────────────────────────────────────────────────────────────┤
│  Outbound Traffic — Top Talkers (Table)                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Panel Specifications

#### Row 1 - KPI Singles (Threshold Colouring)

**Failed Logon Count**
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count
```
- Green: < 50 | Yellow: 50–200 | Red: > 200
- Threshold values should be tuned after 2 weeks of baseline observation.

**Account Lockouts**
```spl
index=windows_security EventCode=4740 earliest=-24h
| stats count
```
- Green: 0 | Yellow: 1–5 | Red: > 5

**Privileged Logons Outside Business Hours**
```spl
index=windows_security EventCode=4624 earliest=-24h
| eval hour=strftime(_time, "%H")
| where (hour < 7 OR hour > 19)
| search Account_Name IN ("Administrator", "admin", "*svc*")
| stats count
```
- Green: 0 | Yellow: 1–3 | Red: > 3
- Expand the `Account_Name` filter to match your environment's privileged account naming convention.

**Alert Volume - Last 7 Days (Column Chart)**
```spl
index=alerts earliest=-7d
| timechart span=1d count by severity
```
- Series: `critical` (red), `high` (orange), `medium` (yellow), `low` (blue)
- Helps spot alert spikes that may indicate scanning activity or a misconfigured rule.

---

#### Row 2 - Top Failed Logon Users (Bar Chart)

```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name
| sort -count
| head 10
```
- X-axis: `Account_Name` | Y-axis: `count`
- Drill-down: clicking a bar should filter the table panels below by that username (use token `$click.value$`).

---

#### Row 3 - Logon Activity Over Time (Line Chart)

```spl
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-24h
| eval event_type=if(EventCode=4624, "Success", "Failure")
| timechart span=1h count by event_type
```
- Two series: Success (blue), Failure (red)
- Visualising both on one chart makes volume anomalies obvious — a spike in failures without a corresponding success spike suggests a brute-force attempt rather than a service outage.

---

#### Row 4 - Suspicious Process Executions (Table)

```spl
index=windows_sysmon EventCode=1 earliest=-24h
| where (Image like "%AppData%" OR Image like "%Temp%" OR Image like "%Downloads%")
      OR (CommandLine like "%IEX%" OR CommandLine like "%DownloadString%" OR CommandLine like "%EncodedCommand%")
| table _time, host, User, Image, CommandLine
| sort -_time
```

Columns to display: `_time`, `host`, `User`, `Image`, `CommandLine`

> **Note on column width:** CommandLine values are long. Set that column to wrap text in the dashboard XML (`<option name="drilldown">cell</option>` and fixed-width layout).

---

#### Row 5 - Outbound Traffic Top Talkers (Table)

```spl
index=firewall_logs action=allowed earliest=-24h
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval total_MB=round(total_bytes/1024/1024, 2)
| sort -total_MB
| head 15
| fields src_ip, dest_ip, total_MB
```

---

## Dashboard 2 - Authentication Deep Dive

**Purpose:** Used when a failed-logon spike is flagged during triage. Breaks down auth events by user, host, IP, and time.

**Trigger:** Linked from the Failed Logon KPI tile via drill-down.

---

### Panels

| Panel | Type | Key Fields |
|---|---|---|
| Failed Logons by User (last 7d) | Bar chart | Account_Name, count |
| Failed Logons by Source IP | Bar chart | src_ip, count |
| Lockout Timeline | Line chart | TargetUserName, timechart |
| Logon Success/Fail Ratio by User | Table | Account_Name, success_count, fail_count, ratio |
| Multi-IP Logon Users | Table | Account_Name, dc(src_ip) |

**Success/Fail ratio panel SPL:**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-7d
| eval outcome=if(EventCode=4624, "success", "failure")
| stats count by Account_Name, outcome
| xyseries Account_Name outcome count
| fillnull value=0
| eval ratio=round(success/(success+failure)*100, 1)
| sort -failure
```

---

## Dashboard 3 - Endpoint Threat Indicators

**Purpose:** Focused on host-based signals. Used during escalation to T2 or when corroborating a network-layer alert.

---

### Panels

| Panel | SPL EventCode | Threat Relevance |
|---|---|---|
| New Services Created | 7045 | Persistence |
| Scheduled Tasks Modified | 4698, 4702 | Persistence |
| PowerShell Encoded Commands | Sysmon 1 | Execution / Obfuscation |
| Process Injections | Sysmon 8 | Defense Evasion |
| Lateral Movement (Pass-the-Hash indicators) | 4624 LogonType=3 with NTLM | Lateral Movement |


**Lateral movement indicator SPL:**
```spl
index=windows_security EventCode=4624 Logon_Type=3 earliest=-24h
| where Authentication_Package="NTLM" AND NOT Account_Name="ANONYMOUS LOGON"
| stats count by Account_Name, src_ip, host
| sort -count
```

---

## General Design Notes

### Tokens and Drill-Down
- Define a `$host$` token on the dashboard. Every table that includes `host` should pass the clicked value to this token and use it to filter dependent panels. This turns any row click into a host-scoped investigation view without leaving the dashboard.
- Set `<drilldown><link><![CDATA[/app/search/search?q=...]]></link></drilldown>` to link directly into a pre-populated Splunk search for full event review.

### Performance on Splunk Free
Splunk Free limits searches to a single CPU core and has no search concurrency controls. To keep dashboards responsive:
- Use `earliest=` and `latest=` on every search; avoid open-ended queries.
- Apply `| head N` before expensive `| stats` operations where possible.
- Avoid `| transaction` — replace with `| stats` and `| eventstats` equivalents.
- Dashboard auto-refresh should be no faster than 5 minutes unless actively triaging an incident.
