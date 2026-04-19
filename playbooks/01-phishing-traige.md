# Playbook 01 - Phishing Email Triage

**Category:** Security Incident - Email-Based Attack
**ITIL 4 Priority:** P1 if user clicked or entered credentials | P2 if reported before any interaction
**SLA - P1 Response:** 15 minutes | **P1 Resolution:** 4 hours
**SLA - P2 Response:** 1 hour | **P2 Resolution:** 8 hours
**Average triage time at L1:** 20-35 minutes (P2, no interaction)
**MITRE ATT&CK coverage:** T1566 (Phishing), T1566.001 (Spearphishing Attachment),
T1566.002 (Spearphishing Link), T1598 (Phishing for Information),
T1204 (User Execution), T1204.001 (Malicious Link), T1204.002 (Malicious File),
T1078 (Valid Accounts - post-click risk)
**Last reviewed:** 2026-07

---

## Why This Playbook Exists

Phishing is the initial access vector in approximately 90% of successful enterprise
breaches. It is not a theoretical concern - it is the most common way attackers gain
their first foothold in a network. For a Tier 1 SOC analyst, phishing triage is one
of the highest-frequency, highest-stakes activities in the role.

Most junior analysts know they should "check the headers." This playbook documents
exactly which headers, what each result means, which tools to use for URL analysis,
what to say to the affected user, what containment actions to take, and at precisely
what point P2 becomes P1. Nothing is assumed. Nothing is skipped.

---

## Understanding the Attack Chain Before You Start

Before looking at a single email header, understand what the attacker is trying to
accomplish. Phishing is Initial Access (MITRE Tactic TA0001). The attacker's goal
is to advance to the next tactic.

**Three primary objectives of phishing campaigns:**

**Credential harvesting (T1598):**
The email contains a link to a fake login page - often a convincing copy of Microsoft
365, a bank portal, or a corporate VPN page. The attacker wants the user's username
and password. If the user enters credentials: immediate P1. The attacker now has valid
account credentials and will use them within minutes.

**Malware delivery (T1566.001 - attachment, T1566.002 - link to payload):**
The email contains an attachment (Word document with macro, PDF with embedded link,
ZIP containing an executable) or a link to a page that serves malware. If the user
opens the file or clicks the download link and executes: immediate P1. Switch to
Playbook 02 (Malware Alert Response).

**Business Email Compromise (BEC - social engineering):**
No malware, no credential page. The attacker impersonates a senior executive or
finance contact and requests a wire transfer, gift card purchase, or sensitive
document. No technical indicators - purely social. The "payload" is the user
taking the requested action. P1 immediately if action was taken.

**Why this matters for triage:**
The type of phishing determines the response urgency and the containment actions.
A credential harvesting attack where the user entered credentials requires immediate
account disable and session revoke. A malware delivery where the user opened the
file requires Playbook 02 procedures for the endpoint. A BEC where the user sent
a wire transfer requires immediate escalation to management and finance.

---

## Step 1 - Initial User Contact: The First 60 Seconds

The first question you ask determines whether this is a P2 investigation or a
P1 emergency requiring immediate containment. Ask in this exact order.

```
MANDATORY OPENING - say this before any other question:

"Please do not click any links in the email, do not open any attachments,
do not forward the email to anyone, and do not delete it yet. I need to
examine it exactly as it is. Can you leave it completely alone while
I investigate?"

THEN ask in order:

Question 1: "Did you click any link in the email?"
  → YES: P1. Tell the user not to touch the machine. Go to Step 7 NOW.

Question 2: "Did you open any attachment?"
  → YES: P1. Tell user not to touch the machine. Switch to Playbook 02 NOW.

Question 3: "Did you enter your username, password, or any other
             credentials on any page that opened?"
  → YES: P1. Tell user not to touch the machine. Go to Step 7 NOW.

Question 4: "Did you click anything and then close it, or did
             anything download that you may have ignored?"
  → YES to anything: treat as P1 until confirmed otherwise.
```

**If all answers are NO:** This is P2. Continue with the investigation steps below.

**While continuing:** Tell the user:
"Thank you for reporting this - that was exactly the right thing to do.
Do not touch the email while I investigate. I will contact you when
I have completed the analysis."

---

## Step 2 - Access the Email via Admin Console

**Do NOT access or open the email from the user's machine.**

Reasons this rule is non-negotiable:
- Email clients may auto-load remote images that contain tracking pixels, beacon
  code, or trigger download of secondary payloads
- If the user's machine has already been compromised by a separate malware infection,
  accessing the phishing email there may expose you to the same payload
- If this escalates to P1, the user's machine becomes a forensic asset - any additional access may alter evidence

Use the admin console:

**Microsoft 365 / Exchange Online:**
```
Method A - Exchange Admin Centre:
  admin.microsoft.com → Exchange Admin Centre →
  Mail Flow → Message Trace →
  Search by recipient address and approximate time

Method B - Microsoft 365 Compliance:
  compliance.microsoft.com → Content Search →
  New Search → search by sender, subject, or recipient →
  Preview the email (do not download to your local machine)
```

**Google Workspace:**
```
admin.google.com → Reports → Audit → Gmail →
  Filter by recipient and time window →
  View message details and headers
```

Retrieve and save:
- The full raw email source including headers
- The sender's From address, Reply-To address, and Return-Path
- The subject line
- All URLs in the email body (do not click - copy from source)
- Any attachment names and file extensions

---

## Step 3 - Analyse the Sender Identity

The display name - what the user sees in their email client - is trivially easy
to spoof and means nothing. The actual sending domain is what matters.

**Check the From address against the display name:**
```
Example of display name spoofing:

Display name (what user sees) : "Microsoft Security Team"
Actual From address           : noreply@micros0ft-sec.xyz

The domain "micros0ft-sec.xyz" is not microsoft.com.
The display name is irrelevant. The From address reveals the attacker.
```

**Check the Reply-To address:**
If a legitimate-looking From address is paired with a Reply-To pointing to a
free webmail account (gmail, yahoo, protonmail) or an unrelated domain, the
From address was spoofed. The attacker wants replies to go to an address they control.

```
From      : payroll@legitimatecompany.com
Reply-To  : hrpayroll2026@gmail.com   ← attacker's address
```

**Check for homograph and typosquatting attacks:**
```
Legitimate  : @microsoft.com       | Spoofed : @micros0ft.com (zero not o)
Legitimate  : @amazon.com          | Spoofed : @amazon-support.com
Legitimate  : @paypal.com          | Spoofed : @paypa1.com (one not l)
Legitimate  : @barclays.co.ke      | Spoofed : @barcIays.co.ke (capital I not l)
Legitimate  : @microsoft.com       | Spoofed : @microsoft.com.login-verify.net
                                     (legitimate domain used as subdomain)
```

**Check the Return-Path header:**
The Return-Path shows where bounce/delivery failure messages go. If it differs
significantly from the From domain, the From was spoofed.

---

## Step 4 - Analyse Email Authentication Headers: SPF, DKIM, DMARC

Email authentication headers tell you whether the sending mail server was
authorised to send on behalf of the claimed From domain. These are the most
reliable technical indicators in phishing analysis.

**How to extract full headers:**
- Outlook desktop: File > Properties > Internet Headers (copy all text)
- Outlook web: Three dots on the email > View > View message source
- Gmail: Three dots > Show original
- Exchange Admin: Message trace → drill into message details

**How to analyse headers:**
Paste the full header text into one of these analysers:
- Google Admin Toolbox: `toolbox.googleapps.com/apps/messageheader`
- MXToolbox Header Analyser: `mxtoolbox.com/EmailHeaders.aspx`
- Mail Header Analyser: `mailheader.org`

**What to look for:**

| Authentication Result | What It Means | Indicator Level |
|----------------------|---------------|----------------|
| SPF: pass | The sending IP is authorised in the domain's SPF record | Legitimate |
| SPF: fail | The sending IP is NOT authorised to send for this domain | Strong phishing indicator |
| SPF: softfail (~all) | Policy is permissive - inconclusive | Mild indicator |
| SPF: none | Domain has no SPF record - unprotected | No determination possible |
| DKIM: pass | Message content was not altered in transit and was signed with the domain's key | Legitimate |
| DKIM: fail | Message was modified in transit or the signature does not match the domain | Strong phishing indicator |
| DMARC: pass | Message passed alignment on SPF or DKIM | Legitimate |
| DMARC: fail | Failed both SPF and DKIM alignment | Definitive spoofing indicator |
| DMARC: none | No DMARC policy on the domain | No determination |

**Check the originating IP address:**

In the `Received:` headers, trace back to the first (originating) `Received:` entry.
The IP in that entry is where the email actually came from.

Geolocate it at `ipinfo.io` or `whatismyipaddress.com`.

Indicators to flag:
- Origin country inconsistent with the claimed sender's location
- Origin IP belonging to a cloud hosting provider, VPS, or bulletproof hosting
- Origin IP on a known spam or malicious IP blocklist
  (check at `mxtoolbox.com/blacklists.aspx`)

---

## Step 5 - Analyse URLs: Never Click, Always Sandbox

**This rule has no exceptions: never click a URL from a suspected phishing email.
Not in a regular browser. Not in an incognito window. Not in a VM without snapshots.**

Modern credential harvesting pages are often fingerprinted - they detect security
researcher IPs, virtual machines, or known sandbox environments and show benign
content to avoid detection. Even in a sandboxed environment, clicking unknown URLs
creates unnecessary risk.

**Safe URL extraction:**
- From the email source code, find all `href=` attributes - the actual destination URL
  is in the href value, not the link display text
- From a web-based email client, right-click the link → Copy link address
  (this copies the href value without following it)

**Sanitise URLs before documenting:**
When documenting phishing URLs in a ticket, defang them to prevent accidental
clicking:
```
Original : https://malicious-credential-page.xyz/microsoft/login
Defanged : hxxps://malicious-credential-page[.]xyz/microsoft/login
```
Replace `https` with `hxxps` and wrap dots in square brackets.

**URL analysis tools:**

```
1. VirusTotal (virustotal.com) → URL tab → paste the URL → Analyse
   What it shows: detection by 80+ security engines, category, known malicious status
   Look for: "phishing", "malicious", "suspicious" from multiple engines
   High confidence: 5+ engines detecting as phishing/malicious

2. URLScan.io (urlscan.io) → paste URL → Submit
   What it shows: screenshot of the page, full DOM, external requests,
                  certificate details, domain registration info
   Particularly useful for: seeing if the page renders a fake login form,
                             identifying the hosting provider

3. Hybrid Analysis (hybrid-analysis.com) → URL analysis
   What it shows: behavioral sandbox analysis of what the page does on load
   Useful for: detecting drive-by downloads or browser exploit pages

4. Whois lookup (whois.domaintools.com or icann.org/whois)
   What it shows: domain registration date, registrar, registrant info
   Look for: creation date less than 30 days ago (high-risk indicator),
             privacy-protected registration hiding registrant details,
             bulk/cheap registrar (Namecheap, GoDaddy used heavily for phishing)
```

**Key URL red flags:**
- Domain registered within the last 30 days
- Domain name mimics a well-known brand with slight variation
- Path contains `/login`, `/verify`, `/secure`, `/account`, `/update`
- URL uses HTTP (not HTTPS) for a page asking for credentials
- URL shortener used to obscure the actual destination (bit.ly, tinyurl, etc.)
- Long subdomain string followed by a short, unfamiliar root domain

---

## Step 6 - Analyse Attachments: Never Open, Always Hash

**Never open a suspicious attachment directly.**

**Safe attachment analysis:**

If the attachment is already on the user's machine and you need to analyse it:
```powershell
# Get the file hash without opening it
Get-FileHash "C:\Users\jsmith\Downloads\invoice_july.zip" -Algorithm SHA256
# or
Get-FileHash "C:\Users\jsmith\Downloads\document.pdf" -Algorithm MD5, SHA256
```

Submit the hash to VirusTotal:
1. Go to `virustotal.com`
2. Click the Search tab
3. Paste the SHA256 hash
4. A hash lookup does NOT upload anything - it only checks if the hash
   already exists in VirusTotal's database (safe to do on any machine)
5. If the hash is unknown to VirusTotal: the file may be a newly compiled
   variant specifically crafted to evade known signatures — treat with higher suspicion

**High-risk attachment types:**
```
Execution risk — HIGH:
.exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .wsf, .hta, .msi, .scr

Execution risk — HIGH (macro-enabled Office):
.docm, .xlsm, .pptm, .xlam, .xla

Execution risk — MEDIUM (can contain embedded code or links):
.doc, .xls, .ppt, .pdf, .rtf, .odt

Execution risk — MEDIUM (archive that may contain above):
.zip, .rar, .7z, .gz, .tar, .iso, .img
```

**Common attachment delivery techniques (MITRE T1204.002):**
- Word document prompting user to "Enable Editing" and "Enable Content"
  (macro execution disguised as a legitimate action)
- PDF with embedded link opening a browser to a credential page
- ZIP file containing an executable with a misleading name like "Invoice_PDF.exe"
  (double extension trick: the icon looks like a PDF, the extension is .exe)
- ISO image containing an LNK shortcut that executes a script on double-click

---

## Step 7 - P1 Response: User Clicked, Opened, or Entered Credentials

**This is a P1 Security Incident. Execute all of the following, in order, immediately.**

**Action 1: Disable the user's Active Directory account**
```powershell
Disable-ADAccount -Identity <samaccountname>
Write-Host "Account disabled: <samaccountname> — $(Get-Date)"
```
This blocks all new domain logon attempts using this account immediately.

**Action 2: Revoke all active Microsoft 365 and Entra ID sessions**
```
Azure Portal → Entra ID → Users → [username] → Revoke Sessions
```
This signs the user out of all active browser sessions, Outlook, Teams, OneDrive,
and mobile apps. If the attacker used harvested credentials to log into M365,
their session is terminated immediately.

**Action 3: Phone call to L2 Security - do not wait for the ticket queue**
Call directly. State clearly:
- Username affected
- What action was taken (clicked link / opened file / entered credentials)
- Which credentials were entered if known (M365 only? VPN? AD domain password?)
- Time the user reports the click/entry occurred
- What you have done so far (account disabled, sessions revoked)

**Action 4: Preserve forensic evidence - do NOT do these things:**
- Do NOT log the user out of their local Windows session
- Do NOT restart or power off the machine
- Do NOT run cleanup tools on the machine
- Do NOT let the user continue using the machine

The machine is now a forensic asset. Its RAM may contain the attacker's process,
decryption keys, injected shellcode, or credential artefacts that forensics needs.
Powering it down destroys this. Leave it running. If network isolation is available
via Defender for Endpoint or Intune, isolate it remotely.

**Action 5: Document for the incident ticket**
```
P1 INCIDENT RECORD - PHISHING
──────────────────────────────────────────────────
Time reported         : [HH:MM]
User                  : [Name and username]
Machine               : [Computer name]
Action taken by user  : [Clicked link / Opened attachment / Entered credentials]
Credentials entered   : [Which systems — M365, AD, VPN, banking, other]
Time of user action   : [When did the user click/enter — approximate if unsure]
Account disabled at   : [HH:MM]
Sessions revoked at   : [HH:MM]
L2 Security notified  : [HH:MM, name of person notified]
Machine status        : [Isolated / Left running / User still on it]
──────────────────────────────────────────────────
```

**Do NOT re-enable the account without explicit written authorisation from L2 Security.**
Even if the user is a senior executive. Even if they are very frustrated.
Re-enabling a compromised account gives the attacker back their access.

---

## Step 8 - P2 Response: Phishing Confirmed, User Did Not Interact

**1. Quarantine the email from all mailboxes**

Microsoft 365:
```
compliance.microsoft.com → Content Search → New Search
  Add conditions: Subject = "[subject of phishing email]"
                  From = "[sender address]"
  Once search complete: More actions → Purge messages → Soft delete
  (soft delete moves to Recoverable Items — can be restored if needed)
```

This removes the email from every inbox in the organisation - not just the
reporting user's. Other employees may have received the same campaign and not
yet reported it.

**2. Block the sender domain at the email gateway**
```
M365 Admin → Security → Policies & Rules → Anti-spam policies →
  Connection filter → IP Block list: add sending IP
  OR
  Tenant Allow/Block List → Domains: add sender domain
```

**3. Create a hunting query to find other recipients**
```spl
-- Splunk: check if other users received the same email (if mail logs are forwarded)
index=mail_logs sender_domain="malicious-domain.xyz" earliest=-7d
| stats count by recipient, subject
| sort -count
```

**4. Document all indicators in the ticket**

Minimum required documentation before closing:
```
PHISHING TRIAGE RECORD
──────────────────────────────────────────────────
Ticket ID            :
Reporter             : [Name and username]
Reported at          : [Timestamp]
──────────────────────────────────────────────────
Sender display name  :
Sender From address  :
Sender Reply-To      :
Sender Return-Path   :
Subject line         :
Originating IP       :
Origin country/ISP   :
──────────────────────────────────────────────────
SPF result           :
DKIM result          :
DMARC result         :
──────────────────────────────────────────────────
URLs found           : [defanged — hxxps://example[.]com/path]
VirusTotal URL result: [detection count / link to scan]
URLScan result       : [link to scan / screenshot description]
Domain created       : [registration date from whois]
──────────────────────────────────────────────────
Classification       : [Phishing confirmed / Suspicious / False positive]
Classification basis : [specific indicators that led to this decision]
──────────────────────────────────────────────────
Actions taken        :
  [ ] Email quarantined from all mailboxes at [HH:MM]
  [ ] Sender domain blocked at email gateway at [HH:MM]
  [ ] User education note sent at [HH:MM]
  [ ] L2 Security notified: [Yes / No — reason]
──────────────────────────────────────────────────
```

**5. Send user education note**

```
To      : [user]@contoso.com
Subject : Phishing Email Report - Analysis Complete and Action Taken

Hi [Name],

Thank you for reporting the suspicious email. Reporting it was exactly
the right action and you have helped protect the organisation — we were
able to investigate and remove it before anyone else could interact with it.

Our analysis confirmed this was a phishing attempt. Here is what we found:

  What the email was trying to do:
  [The email was attempting to steal Microsoft 365 login credentials
   by directing users to a fake login page.]
   OR
  [The email contained a malicious attachment designed to install
   software on your computer if opened.]

  Indicators we found:
  - The sender address was [actual malicious address], not a legitimate domain
  - [SPF/DKIM/DMARC failed - the sender was not authorised for this domain]
  - The link pointed to a credential harvesting page registered [X] days ago

  What we have done:
  The email has been removed from all mailboxes in the organisation.
  The sender domain has been blocked at the email gateway.

  No action is required from you.

  What to watch for in future:
  - Any email creating urgency ("your account will be suspended in 24 hours")
  - Any email asking you to click a link and log in - even if it looks real
  - Any email with an attachment you were not expecting
  - Any email from an executive asking for an urgent financial action

  If you ever receive a suspicious email in future, please forward it to
  security@contoso.com or use the Report Phishing button in Outlook.

  IT Security Team
```

---

## ITIL 4 Documentation Requirements

Before closing any phishing ticket - P1 or P2 - the following must be present:

- [ ] Reported time and initial call notes with exact user statement
- [ ] Classification decision (P1 / P2 / false positive) and the specific evidence
- [ ] SPF, DKIM, DMARC results
- [ ] VirusTotal and URLScan results (links or screenshots)
- [ ] All actions taken with timestamps
- [ ] User education note: sent / not sent / not applicable
- [ ] L2 escalation: yes/no and reason
- [ ] If P1: account status (disabled/re-enabled), L2 Security sign-off reference
- [ ] If malware suspected: Playbook 02 reference and endpoint status


---
