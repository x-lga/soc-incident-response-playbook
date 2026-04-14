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