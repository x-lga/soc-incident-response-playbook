# Playbook 01 — Phishing Email Triage

**Category:** Security Incident — Email  
**ITIL 4 Priority:** P1 if user clicked / credentials entered. P2 if reported before clicking.  

---

## Step 1 — Initial User Contact

- [ ] Thank user for reporting (positive reinforcement encourages future reporting)
- [ ] Ask: "Did you click any links or open any attachments?" → determines P1 vs P2
- [ ] Ask: "Did you enter any credentials?" → if yes: P1 immediately
- [ ] Instruct: "Do not forward, do not click anything further, do not delete the email"

---

## Step 2 — Access Email via Admin Console

**Do NOT access from the user's machine.** Use the admin console:

- Microsoft 365: Exchange Admin Center → Mail Flow → Message Trace
- Google Workspace: Admin Console → Reports → Email Log Search

Check:
- [ ] Full sender email address (not just display name)
- [ ] Reply-To address (does it differ from From address?)
- [ ] Return-Path header
- [ ] Received: headers (trace message origin)
- [ ] X-Originating-IP

---

## Step 3 — Header Analysis

Extract full email headers. Paste into a header analyser:
- Google Admin Toolbox: toolbox.googleapps.com/apps/messageheader
- MXToolbox: mxtoolbox.com/EmailHeaders.aspx

Look for:
- [ ] SPF: FAIL or SOFTFAIL → sender domain mismatch
- [ ] DKIM: FAIL → message was modified in transit or forged
- [ ] DMARC: FAIL → fails both SPF and DKIM alignment
- [ ] Unusual geographic origin in Received headers

---
