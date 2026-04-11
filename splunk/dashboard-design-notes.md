# Splunk Dashboard Design Notes - Security Overview

Built and validated on Splunk Free (local instance). All panels use inline SPL — no lookup dependencies or premium app requirements.

---

## Dashboard Philosophy

Splunk Free has no role-based access, scheduled alerts, or summary indexing. These dashboards are designed around that constraint: every panel runs a real-time or time-ranged search on raw index data. Panels are grouped by triage priority so an L1 analyst can work top-to-bottom during a shift handover.

---