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

#### Row 1 — KPI Singles (Threshold Colouring)

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

**Alert Volume — Last 7 Days (Column Chart)**
```spl
index=alerts earliest=-7d
| timechart span=1d count by severity
```
- Series: `critical` (red), `high` (orange), `medium` (yellow), `low` (blue)
- Helps spot alert spikes that may indicate scanning activity or a misconfigured rule.

---
