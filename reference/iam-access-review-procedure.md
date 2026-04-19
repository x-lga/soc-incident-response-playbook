# IAM Access Review Procedure - Periodic Review Steps and Evidence Retention

This procedure covers the complete access review cycle: scoping, data collection,
reviewer assignment, decision execution, remediation, and evidence retention. It is
designed for quarterly execution against Tier 1 and Tier 2 systems, and annual
execution against Tier 3 systems.

Access reviews are a required control under:
- ISO 27001:2022 (A.8.2 - Privileged Access Rights, A.8.3 - Information Access Restriction)
- SOC 2 (CC6.2 - Access Provisioning and Deprovisioning, CC6.3 — Access Review)
- Kenya Data Protection Act 2019 (Principle 4 - Data Minimisation, Article 41 - Security of Processing)
- CBK Prudential Guideline on Information Systems Security (Section 4.2.3)

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **IAM Team** | Generates access reports, coordinates campaign timeline, executes technical revocations, retains evidence |
| **System Owner** | Accountable for access accuracy within their system; escalation point if a reviewer is unavailable |
| **Access Reviewer** | Typically a manager or team lead; reviews each account and certifies or flags for modification/removal |
| **Security Team** | Spot-checks completed reviews, validates revocations were executed, signs off on campaign closure |

---

## Step 1 - Scoping and Scheduling

Complete at least 2 weeks before the review window opens.

- [ ] Confirm which systems are in scope for this cycle:
  - Reference the system register with tier assignments
  - Quarterly: Tier 1 and Tier 2 systems
  - Annually: Tier 3 systems

- [ ] Confirm the review window dates:
  - Standard: 10 business days for reviews
  - Elevated risk campaigns (post-breach, after significant access changes): 5 business days

- [ ] Identify and confirm the access reviewer for each in-scope system:
  - Default: direct manager for user accounts
  - Default: system owner for service accounts and shared accounts
  - Identify backup reviewers for anyone on leave during the window

- [ ] Confirm the IAM team has export access to each in-scope system's user directory

**Scope register - fill in per cycle:**
| System | Tier | Reviewer | Backup | Window Start | Window End |
|--------|------|---------|--------|-------------|-----------|
| | | | | | |

---

## Step 2 - Access Data Collection

Run exports no more than 3 business days before the review window opens.
Stale data misleads reviewers.

### What to collect for each in-scope system

1. **Active user accounts:** username, display name, account status, last login date, creation date
2. **Role / group memberships:** every role, group, or privilege level assigned to each account
3. **Privileged access (flag separately):** any account with admin, owner, or elevated permissions
4. **Service and shared accounts:** listed separately with their named human owner

### Data quality checks before sending to reviewers

- [ ] Remove or flag accounts with no login in 90+ days
  These should default to revocation unless a documented reason exists
  (parental leave, extended sick leave, seasonal role)

- [ ] Flag accounts with multiple high-privilege roles
  Reviewers should confirm that all elevated roles are still required
  (principle of least privilege)

- [ ] Cross-reference against HR termination records for the past 90 days:
  Any terminated user with an active account is an automatic revocation.
  Do NOT send to reviewer - execute revocation directly and document it.

- [ ] Confirm every service account has a named owner in the export:
  Unnamed service accounts must be investigated before the review closes.
  No orphaned service accounts should pass through to reviewers unchallenged.

---

## Step 3 - Reviewer Assignment and Briefing

- [ ] Send reviewers the access report for their scope in a read-only format
  (CSV or IAM platform task - not an editable spreadsheet)

- [ ] Include in the brief:
  - Review deadline and escalation contact
  - Decision criteria (see below)
  - Instructions for how to submit decisions
  - Consequences of leaving rows blank (auto-certify policy - see Step 4)

### Decision Criteria for Reviewers

For each account, the reviewer must select one of three dispositions:

| Decision | Meaning | Action Required |
|----------|---------|----------------|
| **Certify** | Access is appropriate for the user's current role and responsibilities | No change - IAM team records as certified |
| **Modify** | User still needs some access but the current level is excessive or incorrect | Reviewer specifies the correct access level; IAM team adjusts |
| **Revoke** | User should not have this access — role changed, left the team, or access was never needed | IAM team disables or removes access within SLA |

Reviewers must not leave dispositions blank. A blank entry should never silently
auto-certify - it should be chased by the IAM team and escalated if not completed.

---

## Step 4 - Review Execution and Chasing

| Day | Action |
|-----|--------|
| Day 1 | Campaign opens; all reviewers notified via email with instructions |
| Day 3 | First check: how many reviewers have started? |
| Day 5 | First chase email: any reviewer with less than 50% completion |
| Day 8 | Second chase: escalate to system owner for any reviewer with 0% completion |
| Day 10 | Campaign closes: incomplete items escalated to CISO for forced revocation or extension |

- [ ] Log every chase action and response - this is part of the audit trail
- [ ] Any reviewer who misses the deadline: apply the documented late completion policy
  (forced revocation for all uncertified items, or L1 approval of extension with justification)

---

## Step 5 - Remediation and Revocation

Execute all revocations and modifications within defined SLAs:

| Account Type | Revocation SLA |
|-------------|---------------|
| Global Admin / Domain Admin / privileged accounts | 24 hours from decision |
| Standard user accounts | 5 business days |
| Dormant accounts (90+ days inactive) | 5 business days |
| Terminated user accounts (identified in Step 2) | Immediate - do not wait for the review cycle |

### Revocation Steps

1. Disable the account first - do NOT delete. Deletion destroys the audit log entry.
2. Remove group memberships and role assignments
3. Revoke active sessions and tokens if the system supports it
4. Log the revocation: username, system, reviewer name, date of decision, date of execution
5. Retain the export and reviewer sign-off as evidence (see Step 6)

### Verify Revocations Before Closing

Before closing the campaign, re-run the access export for all in-scope systems and confirm:
- [ ] All revoked accounts show as disabled or removed
- [ ] All modifications reflect the access level specified by the reviewer
- [ ] No new accounts were added since the export was taken that fall outside the review scope

---

## Step 6 - Evidence Retention

The following artefacts must be retained for a minimum of 3 years (adjust to your
regulatory requirement - Kenya DPA 2019 does not specify a minimum retention period,
but industry practice for security records is 3-7 years):

| Artefact | Format | Retention Location |
|---------|--------|------------------|
| Pre-review access export (raw) | CSV / system export | Secure shared drive or DLP-protected folder |
| Completed review with reviewer decisions | CSV or IAM platform report | Same as above |
| Chase log (emails and ticket history) | Email archive or ticket export | Linked to review record |
| Revocation log (who, what, when) | CSV or ITSM ticket export | Same as above |
| Campaign closure sign-off | Signed document or approval record | GRC tool or document management system |

---

## Step 7 - Campaign Closure Metrics

Record these metrics for every campaign. They provide the baseline for improvement
over time and are required for ISO 27001 and SOC 2 evidence packages.

| Metric | Value |
|--------|-------|
| Total accounts reviewed | |
| Certifications (no change) | |
| Modifications | |
| Revocations | |
| Automatic revocations (terminated users found) | |
| Reviewer completion rate before deadline | |
| Revocations executed within SLA | |
| Revocations outside SLA (with reason) | |

**Interpreting the revocation rate:**
- Less than 2% revocations: May indicate reviewers are rubber-stamping without real review.
  Investigate reviewer engagement. Consider a spot-check audit.
- More than 15% revocations: Indicates systematic over-provisioning during onboarding.
  Review the onboarding process and provisioning approvals.

**Campaign closure sign-off:**
| Role | Name | Date |
|------|------|------|
| IAM Team Lead | | |
| Security Team Lead | | |
| CISO / Risk Owner | | |

---

## Appendix A - Handling Special Account Types

### Shared / Generic Accounts
Generic accounts (reception-pc, kiosk-user, shared-finance) must have:
- A named human owner accountable for all activity on the account
- Documented justification for why individual accounts cannot be used
- A review at every access review cycle confirming the account is still needed
If no owner can be identified: disable immediately and investigate whether services depend on it.

### Service Accounts
Service accounts must have:
- A named application owner (a specific person, not a team)
- A record of every system and service that authenticates using this account
- Access scoped to the minimum required for the service function
- No interactive login enabled unless technically required
- A documented review at every access review cycle

Service accounts with Domain Admin or equivalent privileges require individual written
justification. Every such account should be migrated to managed identities, service
principals, or certificate-based auth where the platform supports it.

### Contractor and Third-Party Accounts
- [ ] All contractor accounts must have an expiry date set at provisioning
- [ ] Any contractor account without an expiry date is flagged as a gap
- [ ] Third-party vendor accounts require an internal sponsor who certifies continued need

---

## Appendix B - Useful Splunk Queries for Pre-Review Data Collection

```spl
-- Last login date per account (supplement IdP report with log data)
index=windows_security EventCode=4624 earliest=-90d
| stats latest(_time) as last_login by Account_Name
| eval last_login_date = strftime(last_login, "%Y-%m-%d")
| sort Account_Name

-- Accounts with no login in the last 90 days (dormant account candidates)
index=windows_security EventCode=4624 earliest=-90d
| stats latest(_time) as last_login by Account_Name
| where (now() - last_login) > 7776000
| eval last_login_date = strftime(last_login, "%Y-%m-%d")
| table Account_Name, last_login_date
| sort last_login

-- Privilege group membership changes in the last 30 days
-- Use to catch access creep before the formal review
index=windows_security (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-30d
| eval action = case(
    EventCode=4728, "Added to global security group",
    EventCode=4732, "Added to local security group",
    EventCode=4756, "Added to universal security group"
  )
| table _time, SubjectUserName, MemberName, TargetUserName, action
| sort -_time

-- Admin rights added in the last 30 days
index=windows_security EventCode=4672 earliest=-30d
| stats count by Account_Name, Privilege_List
| sort -count
| where Privilege_List like "%SeDebugPrivilege%"
     OR Privilege_List like "%SeTakeOwnershipPrivilege%"
     OR Privilege_List like "%SeLoadDriverPrivilege%"
```


---
