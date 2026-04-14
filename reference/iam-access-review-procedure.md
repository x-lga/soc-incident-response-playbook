# IAM Access Review Procedure - Periodic Review Steps and Documentation

This procedure covers the end-to-end access review cycle: scoping, data collection, reviewer assignments, remediation, and evidence retention. It is intended for quarterly execution against Tier 1 and Tier 2 systems and annually against Tier 3 systems.

---

## Overview

Access reviews (also called entitlement reviews or recertification campaigns) verify that every user's access rights remain appropriate for their current role. They are a core control in frameworks including ISO 27001 (A.9.2.6), NIST 800-53 (AC-2), and SOC 2 (CC6.3).

A review that produces no revocations is not automatically a sign of a well-managed environment - it may indicate the review was rubber-stamped. Treat zero revocations as a flag to investigate reviewer engagement, not as evidence of clean data.

---

## Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **IAM Team** | Generates access reports, coordinates campaign timeline, performs technical revocations, retains evidence |
| **System Owner** | Accountable for the accuracy of access within their system; escalation point if a reviewer is unavailable |
| **Access Reviewer** | Typically a manager or team lead; reviews each account and certifies or flags for removal |
| **Security Team** | Spot-checks completed reviews, validates revocations were executed, signs off on campaign closure |

---

## Step 1 - Scoping and Scheduling

Complete at least 2 weeks before the review window opens.

- [ ] Confirm which systems are in scope for this cycle (use the system register; tier assignments drive frequency)
- [ ] Confirm the review window dates (typically 10 business days for standard reviews; reduce to 5 for elevated-risk campaigns)
- [ ] Identify the reviewer for each system - default to direct manager for user accounts, system owner for service accounts
- [ ] Identify and assign backups for any reviewer who is on leave during the window
- [ ] Confirm the IAM team has export access to each in-scope system's user directory or access log

**Scope register - fill in per cycle:**

| System | Tier | Reviewer | Backup Reviewer | Review Window |
|---|---|---|---|---|
| | | | | |
| | | | | |

---

## Step 2 - Access Data Collection

Run exports no more than 3 business days before the review window opens to minimise data staleness.

### What to Collect

For each in-scope system, extract:

1. **Active user accounts** - username, display name, account status (enabled/disabled), last login date, creation date
2. **Role / group memberships** - every role, group, or privilege level assigned to each account
3. **Privileged access** - separately flag any account with admin, owner, or elevated permissions
4. **Service and shared accounts** - list separately; these require a named human owner on record

### Data Quality Checks Before Sending to Reviewers

- [ ] Remove or flag accounts with no login in > 90 days - reviewers should default to revoking these unless there is a documented reason (e.g., parental leave)
- [ ] Flag accounts with multiple high-privilege roles - reviewers should confirm all are still required
- [ ] Cross-reference account list against HR termination records for the past 90 days - any terminated user with an active account is an automatic revocation, do not send to reviewer
- [ ] Confirm service accounts have a named owner in the export - unnamed service accounts must be investigated before the review closes

---

## Step 3 - Reviewer Assignment and Briefing

- [ ] Send reviewers the access report for their scope in a read-only format (CSV or IAM platform task)
- [ ] Include the review deadline and escalation contact in the brief
- [ ] Include the decision criteria (see below) - do not assume reviewers remember them from previous cycles

### Decision Criteria for Reviewers

For each account, reviewers must select one of three dispositions:

| Decision | Meaning | Action Required |
|---|---|---|
| **Certify** | Access is appropriate for the user's current role | No change |
| **Modify** | User still needs some access but the current level is excessive | IAM team adjusts permissions as specified by reviewer |
| **Revoke** | User should not have this access | IAM team disables or removes access within SLA |

Reviewers must not leave dispositions blank. A blank line is treated as a certification only if the campaign closes with explicit IAM team acknowledgement - this exception should be rare.

---

## Step 4 - Review Execution and Chasing

| Day | Action |
|---|---|
| Day 1 | Campaign opens; reviewers notified |
| Day 5 | First chase: email any reviewer with < 50% completion |
| Day 8 | Second chase: escalate to system owner for any reviewer with 0% completion |
| Day 10 | Campaign closes; incomplete items escalated to CISO or equivalent for acceptance or forced revocation |

- [ ] Log all chase actions and responses - this is part of the audit trail
- [ ] Any reviewer who misses the deadline should have their open items auto-revoked or escalated for forced sign-off, depending on organisational policy. Document which approach applies.

---

## Step 5 - Remediation and Revocation

Revocations and modifications identified during the review must be actioned within defined SLAs:

| Account Type | SLA |
|---|---|
| Privileged / admin accounts | 24 hours from decision |
| Standard user accounts | 5 business days |
| Dormant accounts (> 90 days inactive) | 5 business days |
| Terminated user accounts (should never reach this stage - see Step 2) | Immediate |

### Revocation Steps (generic - adapt to each system)

1. Disable the account first (do not delete - deletion destroys the audit log)
2. Remove group memberships and role assignments
3. Revoke active sessions / tokens if the system supports it
4. Log the revocation with: username, system, reviewer name, date of decision, date of execution
5. Retain the export and reviewer sign-off as evidence (see Step 6)

### Verify Revocations

Before closing the campaign, re-run the access export for the in-scope systems and confirm:

- [ ] All revoked accounts show as disabled or removed
- [ ] All modifications reflect the access level specified by the reviewer
- [ ] No new accounts have been added since the export was taken that fall outside the review scope

---


## Step 6 - Evidence Retention

The following artefacts must be retained for a minimum of 3 years (adjust to your regulatory requirement):

| Artefact | Format | Retention Location |
|---|---|---|
| Pre-review access export (raw) | CSV / system export | Secure shared drive or DLP-protected folder |
| Completed review with reviewer decisions | CSV or IAM platform report | Same as above |
| Chase log (emails / ticket history) | Email archive or ticket export | Linked to review record |
| Revocation log (who, what, when) | CSV or ITSM ticket export | Same as above |
| Campaign closure sign-off | Signed document or approval record | GRC tool or document management system |

---

## Step 7 - Campaign Closure and Metrics

Complete after all remediations are verified.

**Metrics to record per campaign:**

| Metric | Value |
|---|---|
| Total accounts reviewed | |
| Certifications (no change) | |
| Modifications | |
| Revocations | |
| Automatic revocations (terminated users found) | |
| Reviewer completion rate (% completed before deadline) | |
| Revocations executed within SLA | |
| Revocations outside SLA (with reason) | |

A revocation rate of less than 2% in a mature environment warrants a review of reviewer engagement or access provisioning controls. A rate above 15% may indicate systemic over-provisioning during onboarding.

**Campaign closure sign-off:**

| Role | Name | Date |
|---|---|---|
| IAM Team Lead | | |
| Security Team Lead | | |
| CISO / Risk Owner | | |

---

## Appendix A — Handling Special Account Types

### Shared / Generic Accounts

Shared accounts (e.g., `reception-pc`, `kiosk-user`) must have:
- A named human owner accountable for activity on the account
- Documented justification for why a personal account cannot be used
- A review of whether the account is still required at each access review cycle

If no owner can be identified, disable the account and raise a ticket to investigate.

### Service Accounts

Service accounts must have:
- A named application owner (not a team — a specific person)
- A record of which systems and services authenticate using the account
- Access scoped to the minimum required for the service function (principle of least privilege)
- No interactive login enabled unless technically required

Service accounts with domain admin or equivalent privileges require individual justification and should be migrated to managed identities or certificate-based auth where the platform supports it.

### Contractor and Third-Party Accounts

- [ ] Contractor accounts must have an expiry date set at the time of provisioning
- [ ] Accounts without an expiry date are flagged as a gap during the review
- [ ] Third-party vendor accounts must be sponsored by an internal owner who certifies continued need at each review cycle

---