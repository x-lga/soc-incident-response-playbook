# Splunk Dashboard Design Notes - Security Overview

Built and validated on Splunk Free (local instance). All panels use inline SPL — no lookup dependencies or premium app requirements.

---

## Dashboard Philosophy

Splunk Free has no role-based access, scheduled alerts, or summary indexing. These dashboards are designed around that constraint: every panel runs a real-time or time-ranged search on raw index data. Panels are grouped by triage priority so an L1 analyst can work top-to-bottom during a shift handover.

---

## Dashboard 1 — Security Overview (SOC Home)

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
