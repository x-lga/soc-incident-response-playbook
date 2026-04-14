# IAM Access Review Procedure - Periodic Review Steps and Documentation

This procedure covers the end-to-end access review cycle: scoping, data collection, reviewer assignments, remediation, and evidence retention. It is intended for quarterly execution against Tier 1 and Tier 2 systems and annually against Tier 3 systems.

---

## Overview

Access reviews (also called entitlement reviews or recertification campaigns) verify that every user's access rights remain appropriate for their current role. They are a core control in frameworks including ISO 27001 (A.9.2.6), NIST 800-53 (AC-2), and SOC 2 (CC6.3).

A review that produces no revocations is not automatically a sign of a well-managed environment — it may indicate the review was rubber-stamped. Treat zero revocations as a flag to investigate reviewer engagement, not as evidence of clean data.

---

## Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **IAM Team** | Generates access reports, coordinates campaign timeline, performs technical revocations, retains evidence |
| **System Owner** | Accountable for the accuracy of access within their system; escalation point if a reviewer is unavailable |
| **Access Reviewer** | Typically a manager or team lead; reviews each account and certifies or flags for removal |
| **Security Team** | Spot-checks completed reviews, validates revocations were executed, signs off on campaign closure |

---

## Step 1 — Scoping and Scheduling

Complete at least 2 weeks before the review window opens.

- [ ] Confirm which systems are in scope for this cycle (use the system register; tier assignments drive frequency)
- [ ] Confirm the review window dates (typically 10 business days for standard reviews; reduce to 5 for elevated-risk campaigns)
- [ ] Identify the reviewer for each system — default to direct manager for user accounts, system owner for service accounts
- [ ] Identify and assign backups for any reviewer who is on leave during the window
- [ ] Confirm the IAM team has export access to each in-scope system's user directory or access log

**Scope register — fill in per cycle:**

| System | Tier | Reviewer | Backup Reviewer | Review Window |
|---|---|---|---|---|
| | | | | |
| | | | | |

---