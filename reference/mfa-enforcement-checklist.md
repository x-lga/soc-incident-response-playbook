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


