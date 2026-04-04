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

## Step 4 — URL and Attachment Analysis

**Never click URLs directly.**

```
For URLs:
1. Right-click the link → Copy Link Address (if safe to do in admin console)
2. Submit to VirusTotal: virustotal.com → URL tab
3. Submit to URLScan: urlscan.io → Scan
4. Check domain age: whois lookup — newly registered domains are high risk

For attachments:
1. Do NOT open.
2. Submit file hash or the file to VirusTotal → File tab
3. Check sandbox behaviour report if available
```

---

## Step 5 — Classification

| Indicator Count | Classification | Action |
|-----------------|---------------|--------|
| 0 indicators | Likely legitimate | Whitelist sender if appropriate, close ticket |
| 1–2 minor | Suspicious | Monitor, notify user, do not whitelist |
| 3+ indicators | Phishing confirmed | Proceed to Step 6 |
| User clicked / credentials entered | P1 Compromise | Jump to Step 7 immediately |

---

## Step 6 — Phishing Confirmed Response

- [ ] Quarantine email from all mailboxes (admin console → content search → purge)
- [ ] Block sender domain at email gateway
- [ ] Document all indicators: sender, subject, URLs, IPs, file hashes
- [ ] Send user education note (see template below)
- [ ] Create formal security incident ticket
- [ ] Escalate to L2/Security team with full analysis
