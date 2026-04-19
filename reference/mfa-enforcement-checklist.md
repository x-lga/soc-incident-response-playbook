# MFA Enforcement Checklist - Rollout Verification and Gap Remediation

Use this checklist during an MFA rollout, security audit, or annual review cycle.
Work through each section in order. Flag every gap in the tracking table in Phase 5
and assign a remediation owner with a target date before closing the review.

This checklist applies to Kenyan organisations under the Data Protection Act 2019,
CBK Prudential Guidelines, and international frameworks including ISO 27001 and SOC 2.

---

## Phase 1 - Scope Definition

Before verifying enforcement, confirm what is in scope. Skipping this step creates
false confidence - coverage metrics may look complete while high-risk systems are excluded.

- [ ] Identify every authentication entry point in the environment:
  - Internet-facing portals (M365, Azure, corporate VPN, remote desktop gateways)
  - Internal admin consoles (Active Directory, Azure admin portal, firewall management)
  - Business applications (ERP, HR, finance systems, banking platforms)
  - Developer tools (GitHub, Azure DevOps, cloud consoles)
  - Email (Outlook, OWA, Exchange Admin Centre)

- [ ] Classify each entry point by risk tier:
  - **Tier 1 - Critical:** Internet-facing or handles regulated/sensitive data (financial records, PII, patient data)
  - **Tier 2 - High:** Internal systems with broad access to corporate data
  - **Tier 3 - Standard:** Internal systems with limited blast radius

- [ ] Confirm whether the following account types are included in scope:
  - All internal employees
  - Contractors and third-party users
  - Service accounts (those capable of interactive logon)
  - Shared or generic accounts (e.g., reception-desk, kiosk-user)
  - External partner accounts with access to any internal system

- [ ] Document any systems or account types formally excluded from MFA enforcement
  and the written business justification for the exclusion. No undocumented exclusions.

---

## Phase 2 - Identity Provider Configuration Review

### Conditional Access / Authentication Policies

- [ ] MFA is enforced at the identity provider (IdP) level - NOT only at the application level.
  Application-level enforcement can be bypassed if the IdP session already exists.
  In Microsoft 365: Conditional Access policies in Entra ID are the enforcement point.

- [ ] Legacy authentication protocols are blocked or have compensating controls:
  - Basic Authentication (HTTP Basic)
  - NTLM (where replaceable with Kerberos or modern auth)
  - IMAP/POP3 email access (cannot pass MFA challenges)
  - SMTP AUTH (for legacy email clients)
  Verify: Entra ID Sign-in logs → filter by Legacy Authentication Client Type.

- [ ] "Remember this device" / trusted device token expiry is configured:
  - Recommended maximum: 30 days for Tier 1 systems
  - Indefinite remember = effectively no MFA for users who never clear cookies

- [ ] Break-glass / emergency access accounts are:
  - Inventoried with a documented owner
  - Excluded from MFA policy only via a named exception with a review date
  - Stored securely offline (not in LastPass or a shared password manager)
  - Audited quarterly for any use

- [ ] MFA policy applies to guest accounts and external users accessing internal resources

### Supported MFA Methods - Phishing Resistance Matters

Not all MFA methods are equal. SMS OTP can be intercepted via SIM swapping.
Push notification MFA is vulnerable to MFA fatigue attacks. Phishing-resistant
methods are meaningfully stronger.

| Method | Phishing-Resistant | Acceptable for Tier 1 | Notes |
|--------|-------------------|----------------------|-------|
| FIDO2 hardware key (YubiKey, etc.) | ✅ Yes | ✅ Yes | Strongest. Key is bound to domain - cannot be phished. |
| Passkey (device-bound platform authenticator) | ✅ Yes | ✅ Yes | Strong. Biometric + device binding. |
| Certificate-based authentication | ✅ Yes | ✅ Yes | Strong. Smart card or device certificate. |
| Authenticator app - TOTP (time-based code) | ❌ No | ✅ Yes (with caveats) | Code can be phished in real time - but far better than SMS |
| Authenticator app - Push notification | ❌ No | ✅ Yes (with number matching) | Vulnerable to MFA fatigue. Must enable number matching. |
| SMS / voice OTP | ❌ No | ❌ Not recommended | SIM swap risk. Deprecate where possible. Document if still in use. |
| Email OTP | ❌ No | ❌ Not recommended | Email may already be compromised. |

- [ ] Tier 1 systems require phishing-resistant MFA OR there is a documented migration
  timeline to phishing-resistant methods with an agreed completion date

- [ ] Push notification MFA has number matching enabled:
  In Microsoft Authenticator: Require number matching = True in Entra ID MFA settings.
  In Duo: Enable number match. In Okta: Enable number challenge.
  Number matching prevents approving "just click approve" MFA fatigue attacks.

- [ ] Users cannot self-enrol a new MFA method without re-authenticating or manager approval:
  This prevents an attacker who has stolen a password from registering their own
  authenticator app before the victim notices.

---

## Phase 3 - Coverage Verification

Run these checks against your IdP's sign-in log export or user directory report.
Document findings in the gap table (Phase 5) - do not skip any row.

### User Account Coverage
```
Total in-scope user accounts:                    ________
Accounts with MFA registered (any method):       ________
Accounts with MFA enforced (policy applied):     ________
Accounts with MFA capable but not yet required:  ________
  (grace period / named exclusion)
Accounts with NO MFA method registered at all:   ________
```

- [ ] All accounts with no MFA registered are identified and the account owners are notified
  with a deadline for registration
- [ ] Any account in a grace period or exclusion list for more than 30 days has
  written justification and a confirmed completion date
- [ ] All privileged accounts (Global Admin, Domain Admin, Security Admin, any
  role with admin privileges) are at 100% MFA coverage - zero exceptions

### Service Account Review

Service accounts present a particular challenge because they often cannot complete
an interactive MFA challenge. The approach depends on what they do:

- [ ] Service accounts that authenticate interactively (not just machine-to-machine)
  are enrolled in MFA or migrated to certificate-based auth / Managed Identity

- [ ] Service accounts using shared passwords with no MFA are documented on a
  remediation timeline. Interim control: network restriction (firewall rules limiting
  the source hosts this account can authenticate from)

- [ ] All service accounts have a named human owner on record. No orphaned service
  accounts with no owner. If no owner can be identified: disable the account and
  investigate whether the service still runs.

### Application-Level Spot Checks

Pick three Tier 1 applications and test each manually:

```
Method: Open an in-private/incognito browser session.
Navigate to the application.
Attempt sign-in with a test account that has no active SSO session.
Confirm an MFA challenge is presented before access is granted.
```

- [ ] Application 1: `_____________________________` — MFA enforced: Yes / No / Partial
- [ ] Application 2: `_____________________________` — MFA enforced: Yes / No / Partial
- [ ] Application 3: `_____________________________` — MFA enforced: Yes / No / Partial

---

## Phase 4 - Monitoring and Alerting Verification

MFA enforcement is only effective if bypass attempts are detected.

- [ ] Alert exists for MFA method changes (new authenticator app registered, phone number changed)
  If an attacker steals a password, they may register their own MFA method before the user notices.

- [ ] Alert exists for MFA bypass events (conditional access policy exclusion applied at sign-in)
  A sign-in log entry showing a named exclusion was applied means someone bypassed MFA. Why?

- [ ] Alert exists for repeated MFA failures followed by a successful authentication
  This is the signature of an MFA fatigue attack. SPL query from `splunk/useful-spl-queries.md`.

- [ ] Sign-in logs retained for minimum 90 days (30 days is insufficient for incident response)

- [ ] A test alert was triggered and acknowledged within SLA in the last 90 days

**MFA fatigue detection in Splunk:**
```spl
-- Repeated MFA failures followed by success from the same user
-- Indicates possible MFA fatigue attack (approve out of frustration)
index=auth_logs result=mfa_failure earliest=-1h
| stats count as mfa_failures by user, src_ip
| where mfa_failures > 10
| join user [
    search index=auth_logs result=mfa_success earliest=-1h
    | stats count as mfa_successes by user
  ]
| where mfa_successes > 0
| table user, src_ip, mfa_failures, mfa_successes
```

---

## Phase 5 - Gap Tracking and Remediation

Every gap identified during this review must be documented here. Do not close this
checklist until every row has an assigned owner and a target completion date.

| # | Gap Description | Affected System or User Group | Risk Tier | Owner | Target Date | Status |
|---|----------------|------------------------------|-----------|-------|-------------|--------|
| 1 | | | | | | Open |
| 2 | | | | | | Open |
| 3 | | | | | | Open |

**Status values:** Open / In Progress / Resolved / Accepted Risk (requires sign-off)

Accepted Risk status requires written sign-off from: the system owner, the Security
team lead, and the CISO (or equivalent). Accepted Risk is not the same as ignored risk.

---

## Phase 6 - Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| IAM / IdP Owner | | | |
| Security Team Lead | | | |
| System Owner (if scoped to a specific system) | | | |

---

## Reference - Common Remediation Actions

| Gap | Recommended Remediation |
|-----|------------------------|
| User has no MFA method registered | Force registration via Conditional Access (block access until MFA enrolled); set a deadline |
| Legacy auth protocol in use | Block in IdP (Conditional Access policy); coordinate with application owner on migration timeline |
| SMS OTP in use for Tier 1 accounts | Issue hardware keys or enrol in authenticator app; set deprecation date for SMS |
| Push MFA without number matching | Enable number matching in IdP MFA settings (Entra ID, Okta, Duo all support this) |
| Service account using password only | Migrate to Managed Identity or certificate auth; add network restriction as interim control |
| Break-glass account undocumented | Inventory all global admin accounts; store credentials in a sealed physical envelope in a secure location; audit access quarterly |
| Grace period running longer than 30 days | Escalate to account owner's manager; enforce hard cut-off date with no further extensions |


---
