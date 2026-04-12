# MFA Enforcement Checklist - Rollout Verification and Gap Remediation

Use this checklist during an MFA rollout or audit cycle. Work through each section in order. Flag gaps in the tracking table at the bottom and assign a remediation owner before closing the review.

---

## Phase 1 - Scope Definition

Before verifying enforcement, confirm what is in scope. Skipping this step leads to false confidence when coverage metrics look complete but exclude high-risk systems.

- [ ] Identify all authentication entry points (VPN, cloud console, SSO portal, legacy web apps, remote desktop gateways, admin jump hosts)
- [ ] Classify each entry point by risk tier:
  - **Tier 1** - Internet-facing, privileged access, or handles regulated data
  - **Tier 2** - Internal systems with broad access
  - **Tier 3** - Internal systems with limited blast radius
- [ ] Confirm whether contractors, service accounts, and shared accounts are included in scope
- [ ] Document any systems formally excluded from MFA enforcement and the business justification

---

## Phase 2 - Identity Provider (IdP) Configuration Review

### Conditional Access / Authentication Policies

- [ ] MFA is enforced at the IdP level, not only at the application level (application-level enforcement can be bypassed if the IdP session already exists)
- [ ] Legacy authentication protocols (Basic Auth, NTLM, IMAP/POP3, SMTP AUTH) are blocked or have compensating controls - these protocols cannot pass MFA challenges
- [ ] "Remember this device" / trusted device tokens are set to expire (recommended: ≤ 30 days for Tier 1 systems)
- [ ] Break-glass / emergency access accounts are documented, stored offline, and excluded from standard MFA policy only via a named exception with a review date
- [ ] MFA policy applies to guest and external user accounts, not just internal directory members


### Supported MFA Methods (rank by strength)

| Method | Phishing-Resistant | Acceptable for Tier 1 |
|---|---|---|
| FIDO2 hardware key (YubiKey, etc.) | Yes | Yes |
| Passkey (device-bound) | Yes | Yes |
| Certificate-based auth | Yes | Yes |
| Authenticator app (TOTP/push) | No | Yes (with caveats) |
| SMS / voice OTP | No | Not recommended — document exception if used |
| Email OTP | No | Not recommended |

- [ ] Tier 1 systems require phishing-resistant MFA (FIDO2 or certificate) OR there is a documented exception with a migration timeline
- [ ] Push notification MFA has number-matching or additional context enabled to defend against MFA fatigue attacks
- [ ] Users cannot self-enrol a new MFA method without re-authenticating or manager approval (prevents attacker enrolment after password compromise)

---

## Phase 3 - Coverage Verification

Run these checks against your IdP's sign-in logs or user directory report. Document findings using the gap table in Phase 5.

### User Account Coverage

```
Total in-scope user accounts:           ________
Accounts with MFA registered:           ________
Accounts with MFA enforced (policy):    ________
Accounts with MFA capable but not yet
  required (grace period / exclusion):  ________
Accounts with no MFA method at all:     ________
```

- [ ] Accounts with no MFA registered are identified and owners notified
- [ ] Grace period / exclusion list is reviewed - any account excluded for > 30 days requires written justification
- [ ] Privileged accounts (global admin, domain admin, security admin roles) are at 100% MFA coverage - no exceptions

### Service Account Review

- [ ] Service accounts that do authenticate interactively are enrolled in MFA or migrated to certificate-based auth / managed identity
- [ ] Service accounts using shared passwords with no MFA are logged and on a remediation timeline
- [ ] Service accounts not capable of MFA are network-restricted (firewall rules limiting source IPs / hosts) as a compensating control


### Application-Level Spot Checks

Pick three Tier 1 applications. For each:

- [ ] App 1: `__________________________` — MFA enforced: Yes / No / Partial
- [ ] App 2: `__________________________` — MFA enforced: Yes / No / Partial
- [ ] App 3: `__________________________` — MFA enforced: Yes / No / Partial

To test enforcement manually: open an in-private browser session, navigate to the application, and attempt sign-in with a test account that has no active SSO session. Confirm an MFA challenge is presented before access is granted.

---
## Phase 4 - Monitoring and Alerting Verification

MFA enforcement is only effective if attempts to bypass or disable it are detected.

- [ ] Alerting exists for MFA method changes (new authenticator app registered, phone number changed)
- [ ] Alerting exists for MFA bypass events (conditional access policy exclusion applied to a user at sign-in)
- [ ] Alerting exists for repeated MFA failures followed by a successful authentication (may indicate MFA fatigue success)
- [ ] Sign-in logs are retained for a minimum of 90 days (30 days is insufficient for incident response timelines)
- [ ] A test alert was triggered and acknowledged within the expected SLA during the last 90 days

**Sample SPL - MFA fatigue pattern detection (if sign-in logs forwarded to Splunk):**
```spl
index=auth_logs result=mfa_failure earliest=-1h
| stats count as mfa_failures by user, src_ip
| where mfa_failures > 10
| join user [
    search index=auth_logs result=success earliest=-1h
    | stats count as success_count by user
  ]
| where success_count > 0
| table user, src_ip, mfa_failures, success_count
```

---

## Phase 5 - Gap Tracking and Remediation

Document every gap identified during the review. Do not close this checklist until each row has an owner and a target date.

| # | Gap Description | Affected System / User Group | Risk Tier | Owner | Target Date | Status |
|---|---|---|---|---|---|---|
| 1 | | | | | | Open |
| 2 | | | | | | Open |
| 3 | | | | | | Open |

**Status values:** Open / In Progress / Resolved / Accepted Risk (requires sign-off)

---