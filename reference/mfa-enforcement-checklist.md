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

