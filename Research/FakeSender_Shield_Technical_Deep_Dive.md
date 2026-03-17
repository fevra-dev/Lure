# FakeSender Shield — Technical Deep Dive
**Classifier for Helpdesk Platform Sender Identity Spoofing**  
**Classification:** TLP:WHITE  
**Research date:** February 2026  
**Sources:** Zendesk official documentation, Freshdesk community forums, Twilio/SendGrid SMTP API docs, CloudSEK research (Jan 2025), Krebs on Security (Oct 2025), Cofense (Aug 2025), CSO Online / PoisonSeed (Apr 2025), GBHackers (Dec 2025), uploaded synthesis files

---

## Overview

FakeSender Shield is a classifier that detects a specific, systematically under-defended phishing vector: **helpdesk and CRM platform abuse**, where an attacker creates a legitimate account on Zendesk, Zoho Desk, Freshdesk, HubSpot, or a bulk sending platform, sets their display name to a trusted brand ("Coinbase Security Team", "MetaMask Support", "Kraken Compliance"), and sends phishing emails that arrive in the victim's primary inbox with fully passing SPF, DKIM, and DMARC alignment.

The attack is effective because:
1. The email genuinely originates from the legitimate platform — no spoofing at the SMTP level
2. SPF passes because the sending IP is owned by Zendesk/Freshdesk/HubSpot
3. DKIM passes because the platform signs the email with its own key
4. DMARC aligns (or passes without alignment if only DKIM is evaluated)
5. The recipient sees `From: "Coinbase Security" <support@coinbase-help.zendesk.com>` and reads it as legitimate

The tool's core task: **detect when the display name or sender identity claims to represent a brand whose authorised sending infrastructure does not match the detected sending platform.**

---

## Section 1: Complete Header Forensics by Platform

### 1.1 Methodology

Every email contains two layers of identity:
- **Envelope sender (MAIL FROM / Return-Path):** The technical sender used by MTAs for bounce routing
- **Header From (RFC 5322 From:):** The display address shown to the recipient

Helpdesk platform abuse exploits the gap: the envelope sender and DKIM domain are the platform's infrastructure, but the header `From` display name is attacker-controlled. FakeSender Shield's primary signal source is the collection of platform-specific `X-*` headers that each helpdesk provider injects and that cannot be faked by an attacker using the platform's own sending infrastructure.

### 1.2 Zendesk

**Official sources:** Zendesk Support documentation — "Connecting your Outbound Email Server via SMTP Connector" (EAP article, 2025); "Allowing Zendesk to send email on behalf of your email domain"; Reco Security Labs analysis (July 2025)

#### Always-present headers (default Zendesk sending configuration):

```
X-Mailer: Zendesk Mailer
X-Zendesk-From-Account-Id: <numeric_account_id>
X-Zendesk-Email-Id: <alphanumeric_email_event_id>
Auto-Submitted: auto-generated
X-Auto-Response-Suppress: All
```

**`X-Zendesk-From-Account-Id`** contains the numeric Zendesk account identifier — this is the attacker's account ID. It is always present and is a forensic anchor: a Zendesk email from `"Coinbase Support"` will have this header with the attacker's account ID, not Coinbase's.

**`X-Zendesk-Email-Id`** is a unique per-message identifier in alphanumeric format (24-48 characters). It is present in every Zendesk-originated email and can be correlated with Zendesk's own system records during abuse investigation.

**`Auto-Submitted: auto-generated`** appears on ticket notification emails (outbound from agent to customer). It will be absent on agent-composed direct emails.

**`X-Auto-Response-Suppress: All`** suppresses out-of-office auto-replies from going back to Zendesk's ticket system.

#### Optional/conditional headers:

```
X-Zendesk-Ticket-Id: <ticket_number>
X-Zendesk-Api: true                     (API-submitted tickets)
In-Reply-To: <ticketid+hash@subdomain.zendesk.com>
References: <original_message_id>
Reply-To: <ticketid+hash@subdomain.zendesk.com>
```

**`Reply-To:`** is always a Zendesk-formatted address in the pattern `<ticketid+randomhash@brand-name.zendesk.com>`. This is the most reliable single header for identifying Zendesk delivery because the subdomain `*.zendesk.com` is always the Zendesk account's subdomain — and that subdomain is what the attacker registered.

#### Envelope / authentication headers:

```
Return-Path: <bounce+hash@zendesk.com>   (or brand.zendesk.com with custom config)
Received: from mail.zendesk.com [IP]
DKIM-Signature: v=1; a=rsa-sha256; d=zendesk.com; s=zendesk1
```

**Critical insight:** When Zendesk DKIM is configured with customer CNAME delegation, the DKIM `d=` tag will show `d=yourcustomerdomain.com` rather than `d=zendesk.com`. An attacker cannot configure this because it requires DNS access to the domain they're claiming to be. Therefore: if DKIM `d=` shows `zendesk.com` but the display name claims to be `Coinbase`, this is a strong signal. If DKIM `d=` shows `coinbase.com` — that means the attacker has somehow obtained DNS control of coinbase.com, which is extremely unlikely.

**SPF alignment:** Zendesk SPF `include:mail.zendesk.com`. The SPF pass is against the Zendesk domain, not the header `From` domain. Standard DMARC alignment requires the `From` domain to align with the DKIM signing domain or the SPF `MAIL FROM` domain. For Zendesk abuse, this alignment typically FAILS if the victim's organisation uses strict DMARC — but the attacker is not spoofing your domain, they are using `coinbase-help.zendesk.com` as the domain. The `From:` is `support@coinbase-help.zendesk.com`, and DMARC passes on `zendesk.com`.

#### Detection fingerprint (regex patterns):

```python
ZENDESK_PATTERNS = {
    "headers_required": [
        r"^X-Mailer: Zendesk Mailer",
        r"^X-Zendesk-From-Account-Id: \d+",
        r"^X-Zendesk-Email-Id: [A-Za-z0-9]{16,}",
    ],
    "return_path": r"bounce\+[A-Za-z0-9]+@([\w-]+\.)?zendesk\.com",
    "reply_to": r"\d+\+[a-f0-9]+@[\w-]+\.zendesk\.com",
    "dkim_domain": r"d=zendesk\.com",
    "subdomain_pattern": r"[\w-]+\.zendesk\.com",
}
```

---

### 1.3 Freshdesk (Freshworks)

**Sources:** Freshdesk official support documentation; Freshworks community forum discussion "Email header in emails from Freshdesk" (thread ID 313740, Sep 2016 — feature still not implemented as of 2025); Freshdesk DKIM configuration guide

#### Always-present headers:

```
Message-ID: <ticketid.randomhash@freshdesk.com>
Received: from mail-relay.freshdesk.com [IP]
```

#### Key finding — no standard proprietary `X-Freshdesk-*` header:

A long-standing community feature request (Freshworks forum, thread 313740) proposed adding `X-Fresdesk-Source: freshdesk_accountname_notification_type` headers. **As of 2026, Freshdesk has not implemented this.** This is a significant gap for programmatic detection.

The reliable Freshdesk fingerprints are therefore infrastructure-based:

```
Return-Path: <something@freshdesk.com>  (varies by config)
Received: from mail.freshdesk.com
Received: from freshdesk.com relay
```

**`Message-ID` format:** `<ticketid.randomhash@freshdesk.com>` where `freshdesk.com` always appears in the Message-ID hostname for default Freshdesk-hosted sending. When a customer uses custom SMTP, the Message-ID domain changes to their SMTP provider — in which case detection falls back to the `From` display-name check.

#### Optional/conditional headers:

```
Auto-Submitted: auto-generated         (notification emails only)
X-Freshdesk-Ticket-ID: <number>       (present in some configurations)
Reply-To: support@yourcompany.freshdesk.com
```

**`Reply-To:`** is again the most reliable single header. Freshdesk Reply-To addresses follow the pattern `<support@accountname.freshdesk.com>` where `accountname` is what the attacker chose when registering. The presence of `.freshdesk.com` in the `Reply-To` with a non-matching display-name brand is the primary FakeSender Shield detection signal.

#### DKIM configuration:

Default Freshdesk DKIM signs with `d=freshdesk.com` (shared domain). Customers who configure custom DKIM get `d=theirdomain.com` via Freshdesk's DNS delegation. The same logic applies as Zendesk: attacker-controlled accounts cannot set `d=coinbase.com` without DNS access.

#### Detection fingerprint:

```python
FRESHDESK_PATTERNS = {
    "message_id": r"@freshdesk\.com>$",
    "return_path": r"@freshdesk\.com",
    "reply_to": r"@[\w-]+\.freshdesk\.com",
    "received": r"mail\.freshdesk\.com",
    "dkim_domain": r"d=freshdesk\.com",
}
```

---

### 1.4 Zoho Desk / Zoho Mail

**Sources:** Zoho DKIM documentation; phishing researcher community reports on `zohodesk.com` abuse patterns

#### Always-present headers:

```
X-Mailer: Zoho Mail
Received: from mx.zohomail.com [IP]
```

Zoho Desk uses Zoho Mail's shared sending infrastructure (`mx.zohomail.com`, `mx2.zohomail.com`).

#### Key headers:

```
Return-Path: <bounces@bounce.zoho.com>         (bounce handling)
Return-Path: <sender@youraccount.zoho.com>     (custom config)
Message-ID: <randomid@zohomail.com>
DKIM-Signature: d=zoho.com; s=zohomail;
```

**`X-Mailer: Zoho Mail`** is consistent across Zoho's mail infrastructure. It appears in Zoho Desk, Zoho CRM, Zoho Mail, and Zoho Campaigns emails — which means you cannot distinguish between these services by the X-Mailer alone, but the shared header confirms Zoho infrastructure.

#### Zoho-specific `Reply-To` and subdomain patterns:

```
Reply-To: support@brand.zohodesk.com        (Zoho Desk tickets)
From: "Coinbase Support" <support@coinbase.zohodesk.com>
Received: from zohomailout.zoho.com
```

The `zohodesk.com` second-level domain (for Zoho Desk free tier subdomain accounts) is the clearest identifier. For paid accounts using custom domains, detection requires falling back to Received header IP range analysis.

#### Detection fingerprint:

```python
ZOHO_PATTERNS = {
    "x_mailer": r"^X-Mailer: Zoho Mail$",
    "dkim_domain": r"d=zoho\.com",
    "received_server": r"(zohomail|zohomailout|mx\.zoho)\.com",
    "subdomain": r"[\w-]+\.zohodesk\.com",
    "return_path": r"@(bounce\.)?zoho(mail)?\.com",
}
```

---

### 1.5 HubSpot (Marketing/Service Hub)

**Sources:** Customer.io documentation (cross-referencing HubSpot headers); December 2025 HubSpot phishing campaign analysis (GBHackers, Evalian, eSecurity Planet)

#### Always-present headers:

```
X-HubSpot-Tracking-Email-ID: <unique_id>
X-HS-Email-ID: <id>                         (older format)
```

HubSpot injects tracking headers to enable its click/open analytics. These are present in all HubSpot-originated marketing and transactional emails.

```
Return-Path: <bounce@sg.hubspot.com>          (HubSpot uses SendGrid backend)
Return-Path: <bounce@hubspot.em123.com>       (tracked email sends)
Received: from [IP] (mta.hubspot.com)
DKIM-Signature: d=hubspot.com; s=hubspot1;
```

**Key insight:** HubSpot uses **SendGrid as its email delivery backend** for many accounts. This means HubSpot emails often carry `X-SG-EID` (SendGrid's internal tracking header) alongside HubSpot's own headers. An email with both `X-HubSpot-Tracking-Email-ID` and `X-SG-EID` is definitively HubSpot-via-SendGrid.

#### Optional headers:

```
X-HubSpot-Msg-Id: <id>
X-HubSpot-Url: <tracking_URL>
List-Unsubscribe: <mailto:unsubscribe@hubspot.com>  (always in marketing email)
```

**`List-Unsubscribe:`** is always present in HubSpot marketing emails and always points to `hubspot.com` — another reliable fingerprint.

#### Detection fingerprint:

```python
HUBSPOT_PATTERNS = {
    "tracking_header": r"^X-HubSpot-Tracking-Email-ID:",
    "hs_email_id": r"^X-HS-Email-ID:",
    "dkim_domain": r"d=hubspot\.com",
    "return_path": r"@(sg\.hubspot|hubspot\.em\d+)\.com",
    "list_unsub": r"unsubscribe@hubspot\.com",
    "received": r"mta\.hubspot\.com",
}
```

---

### 1.6 Intercom

**Sources:** Intercom SMTP documentation; email header analysis reports from security community

#### Always-present headers:

```
X-Intercom-Email-ID: <email_event_id>
X-Intercom-App-ID: <app_identifier>       (identifies the Intercom workspace)
```

`X-Intercom-App-ID` is particularly valuable: it is the unique identifier for the attacker's Intercom workspace and can be used to correlate abuse reports with the specific account.

```
Return-Path: <bounce@em.intercom.io>
Received: from mail.intercom.io
DKIM-Signature: d=intercom.io; s=intercom1;
Message-ID: <randomid@intercom.io>
```

#### Optional headers:

```
List-Unsubscribe: <https://app.intercom.io/unsubscribe/...>
X-Mailer: Intercom
```

#### Detection fingerprint:

```python
INTERCOM_PATTERNS = {
    "email_id": r"^X-Intercom-Email-ID:",
    "app_id": r"^X-Intercom-App-ID: [A-Za-z0-9]{6,}",
    "dkim_domain": r"d=intercom\.io",
    "return_path": r"@em\.intercom\.io",
    "received": r"mail\.intercom\.io",
}
```

---

### 1.7 Twilio SendGrid

**Sources:** Official Twilio SendGrid SMTP API documentation; emayili blog post (Oct 2021, real email header dump); Snyk code example (cloud-custodian skip_headers list); Customer.io docs; Cofense analysis (Aug 2025)

#### Always-present headers (all SendGrid email):

```
X-SG-EID: <RFC2047_encoded_string>
```

`X-SG-EID` is SendGrid's email event identifier, encoded per RFC 2047 (MIME quoted-printable). It is present in **every email** delivered by SendGrid's infrastructure regardless of what the customer configures. It cannot be removed by the sender (it is in SendGrid's prohibited-header bypass list along with `x-sg-id`).

```
Message-ID: <token@geopod-ismtpd-X-Y>
```

The `geopod-ismtpd` pattern in the `Message-ID` hostname is a consistent SendGrid infrastructure fingerprint (confirmed from real email header dumps).

#### SMTP API header (optional but common):

```
X-SMTPAPI: {"category": ["transactional"], "unique_args": {...}}
```

`X-SMTPAPI` is a JSON-encoded header used by SendGrid customers to pass batch processing instructions. When present, it leaks the sender's configured categories and custom arguments — potentially including the attacker's campaign metadata.

#### Additional headers:

```
Received: by filterdrecv-XXXXXXXX (SG) with ESMTP id <id>
Received: from propane (unknown) by geopod-ismtpd-X-Y (SG) ...
Return-Path: <bounces+SG.senderid@sendgrid.net>   (bounce routing)
DKIM-Signature: d=sendgrid.net; s=smtpapi;       (shared key, no domain config)
DKIM-Signature: d=customerdomain.com;             (when sender has domain auth)
```

**Note on domain authentication:** SendGrid requires DNS verification before a customer can send with `d=customerdomain.com` DKIM. An attacker claiming to be Coinbase cannot send with `d=coinbase.com` unless they have compromised Coinbase's DNS. Therefore: if `d=sendgrid.net`, the sender is using SendGrid's shared domain — a clear signal for cross-referencing against the display name.

#### Detection fingerprint:

```python
SENDGRID_PATTERNS = {
    "sg_eid": r"^X-SG-EID:",
    "message_id_host": r"@geopod-ismtpd-\d+-\d+",
    "received_sg": r"\(SG\) with ESMTP",
    "smtp_api": r"^X-SMTPAPI:",
    "dkim_domain": r"d=sendgrid\.net",
    "return_path": r"@sendgrid\.net",
}
```

---

### 1.8 Mailgun (Sinch)

**Sources:** Customer.io documentation (noting `X-Mailgun-Dkim` header); email security community analysis

#### Always-present headers:

```
X-Mailgun-Sid: <base64_encoded_recipient_metadata>
```

`X-Mailgun-Sid` is Mailgun's per-recipient tracking identifier. It is present in all Mailgun-delivered email (unless explicitly suppressed, which requires API-level access and is uncommon in abuse scenarios).

```
Message-ID: <randomid.mailgun@mailgun.org>      (shared sending domain)
Message-ID: <randomid@sendingdomain.com>         (verified custom domain)
Received: from mail-XX.mailgun.org [IP]
DKIM-Signature: d=mailgun.org; s=pic;            (shared key)
DKIM-Signature: d=customerdomain.com;            (domain-verified customers)
```

#### Additional Mailgun fingerprints:

```
X-Mailgun-Dkim: yes                    (when DKIM is enabled for the account)
Return-Path: <bounce+sendingid@mailgun.org>
```

**Mailgun IP ranges** are documented and can be used for IP-based detection: `mailgun.org` and `mailgun.info` are the primary sending domains.

#### Detection fingerprint:

```python
MAILGUN_PATTERNS = {
    "mg_sid": r"^X-Mailgun-Sid:",
    "mg_dkim": r"^X-Mailgun-Dkim: yes",
    "message_id": r"@mailgun\.(org|info)",
    "received": r"mail-\w+\.mailgun\.org",
    "dkim_domain": r"d=mailgun\.org",
    "return_path": r"bounce\+\S+@mailgun\.org",
}
```

---

### 1.9 Mailchimp (Intuit) / Mandrill

**Sources:** Mailchimp email infrastructure documentation; Push Security blog "Dissecting a recent Mailchimp phishing attack" (March 2025)

#### Always-present headers:

```
X-Mailer: MailChimp Mailer (version string varies)
X-MC-User: <mailchimp_account_id>
X-MC-Abuse-Reports-To: abuse@mailchimp.com
```

`X-MC-User` contains the sender's Mailchimp account identifier — crucial for abuse reporting. `X-MC-Abuse-Reports-To` is always `abuse@mailchimp.com`.

```
Return-Path: <bounce-md+hashid@mdXXX.MailChimp.com>
Message-ID: <randomid@mail.mailchimp.com>
Received: from mail-worker.mailchimp.com [IP]
DKIM-Signature: d=mail.mailchimp.com; s=k1;
```

The `bounce-md+hashid@mdXXX.MailChimp.com` Return-Path pattern is distinctive — `mdXXX` is the Mailchimp datacenter identifier (e.g., `md31`, `md145`).

#### For Mandrill (transactional email via Mailchimp):

```
X-MC-Metadata: {"metadata": "value"}       (Mandrill-specific)
X-Mailer: MailChimp Mailer
```

#### Detection fingerprint:

```python
MAILCHIMP_PATTERNS = {
    "x_mailer": r"^X-Mailer: MailChimp Mailer",
    "mc_user": r"^X-MC-User: [A-Za-z0-9\-_]+",
    "abuse_to": r"^X-MC-Abuse-Reports-To: abuse@mailchimp\.com",
    "return_path": r"bounce-md\+\S+@md\d+\.MailChimp\.com",
    "received": r"mail(-worker)?\.mailchimp\.com",
    "dkim_domain": r"d=mail\.mailchimp\.com",
}
```

---

### 1.10 Brevo (formerly Sendinblue)

**Sources:** Brevo official SMTP documentation; email security research

#### Always-present headers:

```
X-Mailer: Brevo
Return-Path: <bounceID@smtp-relay.brevo.com>
Received: from smtp-relay.brevo.com [IP]
DKIM-Signature: d=brevo.com; s=brevo1;      (shared domain)
DKIM-Signature: d=customerdomain.com;        (verified custom domain)
```

Brevo's sending relay infrastructure uses `smtp-relay.brevo.com` and the older `smtp-relay.sendinblue.com` (still active for legacy accounts).

#### Optional headers:

```
X-Brevo-Campaign-ID: <numeric_id>
X-Mailer: Sendinblue                         (legacy accounts)
List-Unsubscribe: <mailto:unsubscribe@brevo.com>
```

#### Detection fingerprint:

```python
BREVO_PATTERNS = {
    "x_mailer": r"^X-Mailer: (Brevo|Sendinblue)",
    "return_path": r"@smtp-relay\.(brevo|sendinblue)\.com",
    "received": r"smtp-relay\.(brevo|sendinblue)\.com",
    "dkim_domain": r"d=(brevo|sendinblue)\.com",
    "list_unsub": r"unsubscribe@(brevo|sendinblue)\.com",
}
```

---

### 1.11 Consolidated Platform Header Reference

| Platform | Primary `X-*` Fingerprint | Return-Path Domain | DKIM `d=` (shared) | `Reply-To` pattern |
|---|---|---|---|---|
| **Zendesk** | `X-Mailer: Zendesk Mailer` + `X-Zendesk-From-Account-Id` | `bounce+*@zendesk.com` | `zendesk.com` | `id+hash@*.zendesk.com` |
| **Freshdesk** | None unique — use `Reply-To` + Message-ID | `@freshdesk.com` | `freshdesk.com` | `support@*.freshdesk.com` |
| **Zoho Desk** | `X-Mailer: Zoho Mail` | `@bounce.zoho.com` | `zoho.com` | `support@*.zohodesk.com` |
| **HubSpot** | `X-HubSpot-Tracking-Email-ID` + `X-HS-Email-ID` | `@sg.hubspot.com` | `hubspot.com` | varies |
| **Intercom** | `X-Intercom-Email-ID` + `X-Intercom-App-ID` | `@em.intercom.io` | `intercom.io` | varies |
| **SendGrid** | `X-SG-EID` (always present, RFC 2047) | `bounces+*@sendgrid.net` | `sendgrid.net` | attacker-set |
| **Mailgun** | `X-Mailgun-Sid` | `bounce+*@mailgun.org` | `mailgun.org` | attacker-set |
| **Mailchimp** | `X-MC-User` + `X-MC-Abuse-Reports-To` | `bounce-md+*@mdXXX.MailChimp.com` | `mail.mailchimp.com` | attacker-set |
| **Brevo** | `X-Mailer: Brevo` | `@smtp-relay.brevo.com` | `brevo.com` | attacker-set |

---

## Section 2: Brand Database — Mapping Brands to Legitimate Sending Domains

### 2.1 The Core Problem

FakeSender Shield needs to answer: **"Does this legitimate platform (Zendesk) sending on behalf of this claimed brand (Coinbase) match what we know about Coinbase's actual sending infrastructure?"**

This requires a database mapping `brand_name → [authorised_sending_domains]`.

### 2.2 Existing Public Datasets

#### DMARC-Based Programmatic Discovery (Best Approach)

DMARC records are the canonical, public, machine-readable declaration of a domain's authorised sending infrastructure. The database can be built at scale by:

1. **Input domain list:** Use the Cisco Umbrella Top 1M, Tranco Top 1M, or Majestic Million as a seed list of known brand domains
2. **DMARC lookup:** `dig +short _dmarc.coinbase.com TXT` — this returns the DMARC policy including the `rua=` and `ruf=` addresses that identify who processes the brand's mail reports
3. **SPF walking:** Parse the SPF `include:` chain to build a complete set of authorised sending IPs/domains
4. **Extract sending platforms:** Identify which third-party senders are authorised (`include:sendgrid.net`, `include:mailchimp.com`, etc.)

```python
import dns.resolver

def get_authorised_senders(domain: str) -> dict:
    """
    Walk SPF and DMARC to extract authorised sending infrastructure.
    Returns: {"spf_includes": [...], "dkim_selectors": [...], "dmarc_policy": "..."}
    """
    result = {"domain": domain, "spf_includes": [], "dmarc_policy": None}
    
    # DMARC lookup
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        result["dmarc_policy"] = str(dmarc[0])
    except Exception:
        pass
    
    # SPF lookup and recursive include walking
    try:
        spf_record = dns.resolver.resolve(domain, "TXT")
        for record in spf_record:
            s = str(record)
            if "v=spf1" in s:
                # Extract includes
                import re
                includes = re.findall(r'include:([\w\.\-]+)', s)
                result["spf_includes"].extend(includes)
    except Exception:
        pass
    
    return result

# Example output for coinbase.com:
# {"spf_includes": ["_spf.google.com", "sendgrid.net", "mktomail.com"]}
# This means: Coinbase authorises Google Workspace, SendGrid, Marketo
# If an email claims to be Coinbase but arrives via Freshdesk — MISMATCH
```

**Scale:** This approach can process 10,000 domains/hour on a single machine using asyncio + aiodns. The Tranco Top 100,000 can be processed in ~10 hours, yielding a brand-domain mapping covering the vast majority of impersonated brands.

**Update frequency:** Run weekly — SPF records change rarely, but mergers, platform migrations, and new sending tools are added regularly.

#### BIMI as a Secondary Signal

BIMI records (`default._bimi.domain.com TXT`) link a domain to a verified logo. As of 2025, brands with valid BIMI + Verified Mark Certificates (VMC) have gone through trademark verification. A brand with a valid BIMI record will never have its emails arrive via `Freshdesk` infrastructure unless Freshdesk is in their SPF chain.

```python
def check_bimi(domain: str) -> dict:
    """Look up BIMI record — confirms brand's investment in email auth."""
    try:
        bimi = dns.resolver.resolve(f"default._bimi.{domain}", "TXT")
        return {"has_bimi": True, "record": str(bimi[0])}
    except Exception:
        return {"has_bimi": False}
```

BIMI-registered brands that send via a helpdesk platform not in their SPF chain are **almost certainly being impersonated**.

#### Existing Curated Datasets

| Dataset | Contents | URL | Notes |
|---|---|---|---|
| **Tranco Top 1M** | Top million domains by aggregate traffic | tranco-list.eu | Best seed list — more stable than Alexa |
| **Cisco Umbrella Top 1M** | Popularity-weighted domains | Available via Cisco | DNS-query-count based |
| **Majestic Million** | Top 1M by referring subnets | majestic.com/reports/majestic-million | Good for brand diversity |
| **DisposableEmailDomains** | Known temporary email domains | github.com/disposable-email-domains/disposable-email-domains | For filtering out junk |
| **Public Suffix List** | Mozilla's TLD registry | publicsuffix.org/list | Required for correct domain extraction |
| **DMARC data from parsedmarc** | Aggregate DMARC reports | Self-hosted | If you operate DMARC reporting, you see legitimate senders |

#### Commercial Brand Databases (Reference)

- **BrandDB (WIPO):** wipo.int/branddb — trademark registry; very slow to query programmatically
- **USPTO Trademark Search:** Useful for VMC validation cross-reference
- **Proofpoint's Brand Protection list:** Enterprise-only; not publicly available
- **Agari Brand Protection:** Enterprise-only DMARC analytics with brand database

### 2.3 The JSON Brand Database Schema for FakeSender Shield

```json
{
  "coinbase.com": {
    "common_names": ["Coinbase", "Coinbase Support", "Coinbase Security", "Coinbase Compliance"],
    "authorised_sending_domains": ["sendgrid.net", "google.com", "mktomail.com"],
    "authorised_spf_includes": ["_spf.google.com", "sendgrid.net"],
    "has_dmarc": true,
    "dmarc_policy": "reject",
    "has_bimi": false,
    "risk_tier": "high",         // crypto exchange — high-value phishing target
    "last_updated": "2026-02-01"
  },
  "microsoft.com": {
    "common_names": ["Microsoft", "Microsoft Support", "Microsoft Security", "Microsoft 365"],
    "authorised_sending_domains": ["microsoft.com", "office.com", "outlook.com"],
    "authorised_spf_includes": ["spf.protection.outlook.com"],
    "has_dmarc": true,
    "dmarc_policy": "reject",
    "has_bimi": true,
    "risk_tier": "critical",
    "last_updated": "2026-02-01"
  }
}
```

**Risk tier** enables prioritised alerting. Crypto exchanges, payment processors, and banks should be `critical` or `high`. Generic SaaS brands can be `medium`.

### 2.4 Scale Strategy

The seed list for FakeSender Shield's brand database should initially focus on **500 high-value brands** most commonly impersonated in phishing:
- Top 20 crypto exchanges (Coinbase, Binance, Kraken, Bybit, OKX...)
- Top 10 wallets/Web3 platforms (MetaMask, Phantom, Ledger, Trezor...)
- Top 20 financial institutions (PayPal, Stripe, banks...)
- Top 20 cloud/SaaS platforms (Microsoft, Google, Dropbox, Slack...)
- Top 20 logistics/ecommerce (Amazon, DHL, FedEx, UPS...)
- Top 10 government/identity (IRS, HMRC, USPS...)

Build this initial dataset via automated SPF/DMARC walking + manual verification for ambiguous cases. Ongoing maintenance via weekly re-crawl.

---

## Section 3: Abuse Reporting APIs and Processes

### 3.1 Do Any Platforms Have a Documented Abuse API?

**Short answer: No.** None of the major helpdesk platforms have a public, documented REST API for abuse submission. All abuse reporting is via email or web form. However, several have formal processes with known SLAs.

### 3.2 Platform-by-Platform Abuse Reporting

#### Zendesk

- **Abuse email:** trust@zendesk.com (preferred) / security@zendesk.com
- **Abuse form:** https://www.zendesk.com/trust/ (Trust and Compliance page)
- **Required evidence fields (from Zendesk's own guidance):**
  - Full email headers of the phishing email (RFC 822 format)
  - The Zendesk subdomain being abused (e.g., `coinbase-support.zendesk.com`)
  - Screenshot of the phishing email
  - Description of the impersonated brand / attack goal
  - Any victim reports (optional but accelerates response)
- **SLA:** Zendesk does not publish an official SLA. Community-reported response times range from **2-24 hours** for clear abuse cases. CloudSEK's January 2025 responsible disclosure found Zendesk responsive within the same business day for confirmed impersonation.
- **Escalation:** If no response within 24 hours, escalate to: legal@zendesk.com (for brand/trademark claims) or via ICANN abuse process against the subdomain registrar (Zendesk uses Zendesk as registrar for `.zendesk.com` subdomains — treat as the registrar)
- **Context:** Zendesk acknowledged the CloudSEK vulnerability and stated it added filters in July 2024. The anonymous ticket relay issue was covered by Krebs on Security in October 2025, prompting faster response to email bomb abuse.

#### Freshdesk / Freshworks

- **Abuse email:** abuse@freshdesk.com / security@freshworks.com
- **Security disclosure:** https://www.freshworks.com/security/ (Responsible Disclosure policy)
- **Required evidence fields:**
  - Full email headers
  - Ticket reference (if visible in the phishing email)
  - Freshdesk subdomain (e.g., `brand-help.freshdesk.com`)
  - Nature of abuse
- **SLA:** 48-72 hours per community experience. Freshworks has a HackerOne programme for security vulnerabilities (separate from abuse reporting).
- **Note:** Freshworks has not implemented DMARC authentication enforcement for free-tier accounts as of 2025, meaning spam/phishing from Freshdesk subdomains passes authentication checks easily.

#### Zoho

- **Abuse email:** abuse@zoho.com (general abuse) / abuse@zohocorp.com (corporate)
- **Required evidence fields:**
  - Full email headers
  - Zoho account subdomain or sending email address
  - Description of impersonation
- **SLA:** Typically **24-48 hours** per reporter experience. Zoho has an active abuse team.
- **Context:** Zoho was targeted by PoisonSeed (March-April 2025) via credential theft of Zoho account holders, not subdomain creation. Zoho responded within hours once campaign was identified.

#### SendGrid (Twilio)

- **Abuse email:** abuse@sendgrid.com
- **Spam/phishing report form:** https://app.sendgrid.com/email/forwarded-email (requires SendGrid account) — for forwarding a raw phishing email
- **Alternative form:** abuse@twilio.com (parent company)
- **Required evidence fields:**
  - Full raw email with headers (forward as attachment, not inline)
  - Description of the phishing content
  - Any SendGrid-specific headers found (`X-SG-EID`, `X-SMTPAPI`)
- **SLA:** SendGrid's July 2025 fraud update states they catch **200M+ phishing emails and 400+ ATO attacks per month**, and have reduced abuse by 50% since December 2024. Response to individual reports: **12-24 hours** for clear cases.
- **Automated mechanisms:** SendGrid's compliance system flags accounts exceeding spam complaint thresholds (>0.08% complaint rate triggers review; >0.1% triggers suspension). Submitting emails to spam reports via email clients (Gmail "Report Spam") contributes to these thresholds.
- **Context:** The PoisonSeed campaign (April 2025) specifically compromised existing SendGrid accounts via credential theft — not new account creation abuse. Twilio responded by temporarily suspending implicated accounts and requiring re-verification.

#### Mailgun (Sinch)

- **Abuse email:** abuse@mailgun.com
- **Required evidence fields:** Full email headers, sending domain or account identifier if known, phishing content description
- **SLA:** 24-48 hours

#### Mailchimp (Intuit)

- **Abuse email:** abuse@mailchimp.com
- **Spam report:** https://mailchimp.com/contact/spam-reporting/
- **Required evidence fields:**
  - Forward the full phishing email as an attachment to abuse@mailchimp.com
  - Mailchimp provides a `X-MC-User` header — including this accelerates identification of the abusive account
- **SLA:** Typically **6-24 hours**. Mailchimp's compliance team is relatively aggressive given the high-profile breaches in 2022-2025.
- **Context:** Troy Hunt's Mailchimp account was compromised via AiTM attack on `mailchimp-sso[.]com` in early 2025 (PoisonSeed campaign). Mailchimp suspended the attacker's access within hours of being notified.

#### HubSpot

- **Abuse email:** security@hubspot.com
- **Trust/abuse page:** https://legal.hubspot.com/security
- **Required evidence fields:** Email headers, description of impersonation, URL of phishing page (if any)
- **SLA:** 24-48 hours; HubSpot has a security response team

#### Brevo (Sendinblue)

- **Abuse email:** abuse@brevo.com (redirects from abuse@sendinblue.com)
- **SLA:** 24-48 hours

#### Intercom

- **Abuse email:** security@intercom.io
- **SLA:** Not publicly published; typically 24-48 hours

### 3.3 Abuse Report Template (Copy-Paste Ready)

```
Subject: Helpdesk Platform Abuse — Brand Impersonation Phishing [URGENT]

To: [abuse contact for platform]

I am reporting abuse of your platform for brand impersonation phishing.

PLATFORM: [Zendesk / Freshdesk / etc.]
ABUSIVE ACCOUNT/SUBDOMAIN: [e.g., coinbase-support.zendesk.com]
BRAND IMPERSONATED: [e.g., Coinbase]
ATTACK TYPE: Phishing / Credential harvesting / Investment fraud
DATE OBSERVED: [date]

DETECTION HEADERS:
X-Mailer: Zendesk Mailer
X-Zendesk-From-Account-Id: 123456789
X-Zendesk-Email-Id: abc123def456
(Include all X-* headers from the email)

EVIDENCE:
[Attach full RFC 822 raw email as .eml file]
[Attach screenshot of phishing email]
[Attach screenshot of any phishing landing page]

IMPACT: This email impersonates [brand] to steal credentials / funds from victims.
The email passes SPF/DKIM authentication because it originates from your platform.

REQUESTED ACTION: Immediate suspension of account [subdomain/account ID].

Please confirm receipt and provide a case reference number.

Reported by: [Your name / organisation]
Contact: [Your email]
```

### 3.4 Auto-Reporting Architecture for FakeSender Shield

FakeSender Shield can automate abuse reporting using the following pipeline:

```python
import smtplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

ABUSE_CONTACTS = {
    "zendesk": "trust@zendesk.com",
    "freshdesk": "abuse@freshdesk.com",
    "zoho": "abuse@zoho.com",
    "hubspot": "security@hubspot.com",
    "intercom": "security@intercom.io",
    "sendgrid": "abuse@sendgrid.com",
    "mailgun": "abuse@mailgun.com",
    "mailchimp": "abuse@mailchimp.com",
    "brevo": "abuse@brevo.com",
}

def auto_report_abuse(
    platform: str,
    raw_eml: bytes,
    brand_impersonated: str,
    account_identifier: str,
    from_email: str,
    smtp_config: dict
) -> bool:
    """
    Automatically send abuse report to the detected platform.
    Returns True if sent successfully.
    """
    abuse_email = ABUSE_CONTACTS.get(platform)
    if not abuse_email:
        return False
    
    msg = MIMEMultipart()
    msg["Subject"] = f"[ABUSE] Brand Impersonation Phishing via {platform.title()} — {brand_impersonated}"
    msg["From"] = from_email
    msg["To"] = abuse_email
    
    body = f"""
Brand impersonation phishing detected via {platform.title()}.

Impersonated Brand: {brand_impersonated}
Platform Account/Subdomain: {account_identifier}
Detection Confidence: High (header fingerprint match)

Please see attached raw email for full header evidence.
"""
    msg.attach(MIMEText(body, "plain"))
    
    # Attach raw email
    attachment = MIMEBase("message", "rfc822")
    attachment.set_payload(raw_eml)
    encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename="phishing_evidence.eml")
    msg.attach(attachment)
    
    # Send
    with smtplib.SMTP(smtp_config["host"], smtp_config["port"]) as smtp:
        smtp.starttls()
        smtp.login(smtp_config["user"], smtp_config["password"])
        smtp.sendmail(from_email, abuse_email, msg.as_string())
    
    return True
```

---

## Section 4: False Positive Risk and Whitelist Logic

### 4.1 The Core False Positive Challenge

The most common false positive scenario: **your own organisation uses Zendesk/Freshdesk for legitimate customer support, and FakeSender Shield flags incoming emails from your own support system.**

A secondary false positive: **a legitimate vendor sends support communications via a helpdesk platform**, and the tool incorrectly flags the email because the brand name in the `From:` display name doesn't match the platform.

### 4.2 Whitelist Architecture

FakeSender Shield should implement a four-tier whitelist:

#### Tier 1: Organisational Self-Whitelist (Zero False Positives)

```python
SELF_WHITELIST = {
    "zendesk_subdomains": ["mycompany.zendesk.com"],
    "freshdesk_subdomains": ["mycompany.freshdesk.com"],
    "sendgrid_sender_ids": ["my-sendgrid-subuser-id"],
    "hubspot_tracking_ids": ["my-hubspot-portal-id"],
}
```

Any email with a platform identifier matching the organisation's own accounts is whitelisted unconditionally.

#### Tier 2: Known Vendor Whitelist (Approved Third Parties)

Maintain a list of approved vendor relationships:

```python
VENDOR_WHITELIST = [
    {
        "display_name_pattern": r"Stripe (Support|Billing|Payments)",
        "authorised_platforms": ["sendgrid"],
        "authorised_sender_domains": ["stripe.com"],
        "notes": "Stripe uses SendGrid for transactional email"
    },
    {
        "display_name_pattern": r"GitHub",
        "authorised_platforms": ["sendgrid"],
        "authorised_sender_domains": ["github.com"],
    },
]
```

#### Tier 3: Contextual Whitelist — "The Display Name Matches the Platform Subdomain"

The key logic: if the display name brand name is **consistent** with the platform subdomain account name, it is likely legitimate.

```python
def is_consistent_subdomain(display_name: str, subdomain: str) -> bool:
    """
    Check if the display name brand is consistent with the platform subdomain.
    
    Legitimate: "Acme Corp Support" from acme-corp.zendesk.com -> TRUE
    Suspicious: "Coinbase Support" from coinbase-helpdesk-123456.zendesk.com -> FALSE
    """
    brand = normalise_brand_name(display_name)  # "Acme Corp Support" -> "acmecorp"
    sub = normalise_subdomain(subdomain)          # "acme-corp" -> "acmecorp"
    
    # Check for brand name in subdomain
    return brand in sub or sub in brand
```

**Why this works:** Legitimate companies register subdomains matching their brand name (`acme.zendesk.com` for Acme). Attackers trying to impersonate a brand they don't own will have subdomains like `coinbase-support-secure.zendesk.com` which contain but don't *equal* the brand name — triggering further scoring.

#### Tier 4: DMARC-Based Legitimacy Check

If the claimed brand has an SPF record that includes the detected platform, the email is likely legitimate:

```python
def dmarc_authorises_platform(
    claimed_brand_domain: str,
    detected_platform: str
) -> bool:
    """
    Returns True if the brand domain's SPF record includes the platform.
    
    Example: display_name = "Salesforce" -> check salesforce.com SPF
    If salesforce.com SPF includes sendgrid.net -> likely legitimate Salesforce email via SendGrid
    """
    spf_includes = get_spf_includes(claimed_brand_domain)  # See Section 2.2
    
    PLATFORM_SPF_INCLUDES = {
        "zendesk": ["mail.zendesk.com"],
        "freshdesk": ["freshdesk.com"],
        "sendgrid": ["sendgrid.net", "sendgrid.com"],
        "mailchimp": ["mailchimp.com", "mc.email"],
        "hubspot": ["hubspot.com", "hubspotemail.net"],
        "mailgun": ["mailgun.org"],
        "brevo": ["sendinblue.com", "brevo.com"],
    }
    
    platform_hosts = PLATFORM_SPF_INCLUDES.get(detected_platform, [])
    return any(host in spf_includes for host in platform_hosts)
```

### 4.3 Scoring Model (Not Binary)

FakeSender Shield should output a **risk score (0-100)** rather than a binary flag, with thresholds for display/alert/quarantine:

```python
def score_email(email_analysis: dict) -> int:
    """
    Returns risk score 0-100. Higher = more suspicious.
    """
    score = 0
    
    # Base: detected as helpdesk platform
    platform = email_analysis["detected_platform"]
    if platform:
        score += 20
    
    # Display name brand vs. platform subdomain inconsistency
    if not is_consistent_subdomain(
        email_analysis["display_name"],
        email_analysis["platform_subdomain"]
    ):
        score += 25
    
    # Brand is in high-value target list
    if email_analysis["brand_risk_tier"] in ("critical", "high"):
        score += 20
    
    # DMARC does NOT authorise the sending platform
    if not dmarc_authorises_platform(
        email_analysis["claimed_brand_domain"],
        platform
    ):
        score += 20
    
    # Brand is known (in our database)
    if not email_analysis["brand_in_database"]:
        score -= 10  # Unknown brands are lower risk
    
    # Email contains urgency signals
    if email_analysis["urgency_score"] > 0.7:
        score += 10
    
    # First-ever contact from this sender
    if email_analysis["first_contact"]:
        score += 5
    
    return min(score, 100)

# Thresholds:
# 0-30: Show platform label only ("via Zendesk")
# 31-60: Yellow warning — "Unexpected sender platform"
# 61-80: Orange alert — "Possible brand impersonation"
# 81-100: Red alert — "High-confidence impersonation"
```

### 4.4 The Freshdesk Whitelist Challenge (Special Case)

Because Freshdesk has no unique `X-Freshdesk-*` header in its outbound emails, detection relies on:
1. `Reply-To: support@something.freshdesk.com` (reliable)
2. `Message-ID: *@freshdesk.com` (reliable)
3. `Return-Path: *@freshdesk.com` (reliable)

**False positive risk:** A legitimate company using Freshdesk to contact you. To mitigate: always check if their brand name appears in the Freshdesk subdomain (`acme.freshdesk.com` for Acme). If the subdomain matches the brand, lower the score significantly.

---

## Section 5: Real-World Abuse Cases (2024–2026)

### Case 1: CloudSEK / Zendesk Brand Impersonation — Pig Butchering (January 2025)

**Reported by:** CloudSEK Research (report published January 22, 2025); TechRadar, Cyber Security Asia coverage (January 23, 2025)

**Technical details:**
- **Subdomain pattern:** `[brand-name]-[numbers].zendesk.com` (e.g., `coinbase-invest123.zendesk.com`, `binance-support456.zendesk.com`)
- **Scale:** CloudSEK's XVigil platform identified **1,912 suspicious Zendesk subdomains** linked to phishing/impersonation as of January 2025
- **Method:** Attackers created Zendesk free trial accounts, registered subdomains mimicking legitimate crypto exchanges and investment platforms, then sent phishing emails from those subdomains. Zendesk does not validate email addresses when assigning tickets to users, allowing attackers to add any victim's email without their consent — meaning phishing emails arrived as "ticket assignment notifications" from the platform.
- **Brand impersonated:** Crypto exchanges, investment platforms, financial services
- **Attack goal:** "Pig butchering" investment fraud — build trust via fake support portal, then redirect to fraudulent investment platform
- **Authentication result:** All emails passed SPF/DKIM because they genuinely originated from Zendesk. Gmail routed them to Primary inbox.
- **Payload delivery:** Emails contained hyperlinked images pointing to phishing pages or fake investment platforms
- **Takedown timeline:** Zendesk stated they added filters after CloudSEK's responsible disclosure; no specific SLA was published. The 1,912 subdomains figure suggests slow proactive remediation.
- **FakeSender Shield detection:** `X-Zendesk-From-Account-Id` mismatch + subdomain inconsistency with claimed brand

---

### Case 2: Zendesk Anonymous Ticket Relay — Email Bomb Campaign (October 2025)

**Reported by:** Krebs on Security (October 2025); CPO Magazine (January 26, 2026); Red Sentry

**Technical details:**
- **Subdomain pattern:** Exploited existing legitimate companies' Zendesk accounts (NordVPN, Discord, Washington Post, Dropbox), not newly created fake accounts
- **Method:** Attackers submitted support tickets with **victim email addresses as the "from" address**. Zendesk sent ticket confirmation emails to those addresses from the legitimate company's Zendesk account. Because Zendesk allows anonymous ticket submission with any email address, the victim receives an email appearing to come from `support@nordvpn.zendesk.com` or `discord@zendesk.com` — even though NordVPN/Discord never intended to contact the victim.
- **Scale:** Brian Krebs's inbox was flooded with thousands of such relay emails in a single incident, burying legitimate security alerts
- **Brand impersonated:** NordVPN, Discord, Dropbox, Washington Post (hundreds of legitimate companies' Zendesk accounts weaponised)
- **Attack goal:** Email bombing / noise flooding — disrupting victim's ability to detect real security alerts. Possible preparatory step for subsequent targeted phishing.
- **Authentication result:** Perfect SPF/DKIM/DMARC pass — the emails are literally from legitimate companies' Zendesk accounts
- **Takedown timeline:** Zendesk released a statement and mitigation guidance but did not patch the underlying anonymous ticket submission feature universally. Individual companies were advised to disable anonymous ticket submission in their Zendesk settings.
- **FakeSender Shield detection:** This variant requires behavioural detection (volume analysis, not brand mismatch), not header-based impersonation detection. It is outside FakeSender Shield's primary scope but relevant context.

---

### Case 3: PoisonSeed — Mailchimp, HubSpot, Zoho, SendGrid, Mailgun Crypto Seed Phrase Poisoning (March–April 2025)

**Reported by:** CSO Online (April 7, 2025); SC Media; Push Security; BleepingComputer; Rootkit Defense

**Technical details:**
- **Attributed to:** PoisonSeed campaign (linked by Silent Push to CryptoChameleon phishing kit; partial overlap with Scattered Spider TTPs; phishing domain `mailchimp-sso[.]com` re-registered from Porkbun to NiceNic on March 24, 2025)
- **Platforms abused:** Mailchimp, HubSpot, Zoho, SendGrid, Mailgun — all compromised via AiTM credential theft of existing legitimate accounts (not new account creation)
- **Method:**
  1. Targeted phishing against CRM platform users — AiTM pages impersonating Mailchimp, HubSpot, Zoho, SendGrid login portals
  2. Captured credentials + session tokens for the victims' platform accounts
  3. Used compromised accounts to send mass phishing emails to the platform's existing mailing lists
  4. Email content: claimed Coinbase was migrating to "self-custodial wallets" and provided a pre-seeded recovery phrase — attacker's wallet phrase. Victims who imported the phrase were later drained.
- **Confirmed first victim:** Troy Hunt (Have I Been Pwned founder) — his Mailchimp account was compromised, 16,000 contacts exported, API key created for backdoor access, all within 5 minutes of credential entry
- **Sending subdomain/domain:** The emails originated from the legitimate domain of the compromised Mailchimp/HubSpot account, with full SPF/DKIM/DMARC pass
- **Brand impersonated:** Coinbase, Ledger (using the legitimate sender's brand identity)
- **Attack goal:** Cryptocurrency wallet seed phrase poisoning → wallet takeover
- **Akamai incident:** In March 2025, Akamai's SendGrid account was compromised; phishing emails appeared to come from genuine `@akamai.com` addresses
- **Takedown:** Mailchimp suspended the attacker's API key access. No firm takedown timeline; the campaign continued across platforms for weeks.
- **FakeSender Shield relevance:** This case involves compromised legitimate accounts — not new fake accounts. FakeSender Shield's header analysis would show a legitimate brand's SPF/DKIM configuration, making detection harder. Signal: unexpected "wallet migration" email from a legitimate sender not known to discuss crypto should trigger behavioural analysis.

---

### Case 4: HubSpot Phishing Campaign via Compromised MailChimp Account (December 2025)

**Reported by:** GBHackers (December 19, 2025); Evalian; eSecurity Planet; CyberPress

**Technical details:**
- **Attacker method:**
  1. Compromised a legitimate business email account via BEC
  2. Used the compromised email's MailChimp account to send phishing emails at scale
  3. Phishing email subject: "Verify your account — unusual unsubscribe activity detected"
  4. **Novel technique:** The malicious URL was embedded in the **sender's display name field**, not in the email body's hyperlinks — evading URL-scanning SEGs that inspect link fields
  5. Redirect chain: `canvthis[.]com` (compromised legitimate site) → `hubspot-campaigns[.]com/login` (phishing page)
- **Sending infrastructure:** MailChimp (legitimate account) with full SPF/DKIM/DMARC pass
- **Phishing page host:** `hubspot-campaigns[.]com` — hosted on `193[.]143[.]1[.]220` (Proton66 OOO, ASN AS198953, Russian bulletproof hosting)
- **Brand impersonated:** HubSpot
- **Attack goal:** HubSpot credential theft
- **FakeSender Shield detection signal:** `X-MC-User` header (MailChimp's account ID) + display name claiming "HubSpot" + URL in display name (non-standard placement) = high-confidence alert. The MailChimp account's SPF chain would not include `hubspot.com`.

---

### Case 5: SendGrid Credential Phishing — Cofense Analysis (August 2025)

**Reported by:** Cofense (Cyber Security Intelligence analysis, August 25, 2025); CyberPress

**Technical details:**
- **Campaign type:** Brand impersonation of SendGrid itself — targeting SendGrid's own user base
- **Method:** Phishing emails impersonating SendGrid security alerts ("New Login Location", "Elite Tier Promotion", "Phone Number Changed") sent via compromised or newly created SendGrid subuser accounts
- **Sending infrastructure:** SendGrid's own sending infrastructure — full SPF/DKIM pass on legitimate SendGrid domain
- **Subdomain/domain used:** Compromised SendGrid accounts; some using subuser account delegation
- **Payload infrastructure:** `url1390.hilllogistics[.]com`, `url6849.destinpropertyexpert[.]com` (open redirect abuse), `loginportalsg[.]com`, `sendgrid.aws-us5[.]com` (fake SendGrid domain on AWS)
- **Key technique:** **Open redirect abuse** — attackers used legitimate `url*.somelegitimedomain.com` URLs as redirectors, exploiting open redirect vulnerabilities on domains with clean reputation. The initial link clicked was a trusted domain; the final destination was malicious.
- **Brand impersonated:** SendGrid / Twilio
- **Attack goal:** SendGrid account credential theft → further platform abuse access
- **Takedown:** SendGrid's compliance team identified the campaign; individual malicious accounts suspended. The open redirect domains remained active as the vulnerable sites were third-party properties.
- **FakeSender Shield detection:**
  - `X-SG-EID` confirms SendGrid sending infrastructure
  - Display name "SendGrid Security" from SendGrid's own platform — consistent with platform (lower score)
  - However: `From` domain mismatch (`sendgrid.aws-us5[.]com` is not `sendgrid.com`) raises score
  - Content signals: urgent "security alert" from transactional email service = behavioural flag

---

## Appendix A: Complete Python Header Parser for FakeSender Shield

```python
"""
FakeSender Shield — Platform Header Extractor
Identifies the sending helpdesk/CRM platform from email headers.
"""
import re
import email
from email import policy
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class HeaderAnalysis:
    detected_platform: Optional[str] = None
    confidence: float = 0.0
    platform_account_id: Optional[str] = None
    platform_subdomain: Optional[str] = None
    dkim_signing_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to: Optional[str] = None
    display_name: Optional[str] = None
    display_name_email: Optional[str] = None
    signals: list = field(default_factory=list)

def parse_email_headers(raw_email: bytes) -> HeaderAnalysis:
    """
    Parse raw email and extract platform fingerprints.
    Returns HeaderAnalysis with detected platform and evidence signals.
    """
    msg = email.message_from_bytes(raw_email, policy=policy.default)
    result = HeaderAnalysis()
    
    # Extract standard headers
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    message_id = msg.get("Message-ID", "")
    
    # Parse From display name and email
    from_parsed = email.utils.parseaddr(from_header)
    result.display_name = from_parsed[0]
    result.display_name_email = from_parsed[1]
    result.reply_to = reply_to
    
    # Extract DKIM signing domain
    dkim_sig = msg.get("DKIM-Signature", "")
    dkim_match = re.search(r"d=([\w\.-]+)", dkim_sig)
    if dkim_match:
        result.dkim_signing_domain = dkim_match.group(1)
    
    # Extract Return-Path domain
    rp_match = re.search(r"@([\w\.\-]+)>?$", return_path)
    if rp_match:
        result.return_path_domain = rp_match.group(1)
    
    # Platform detection — Zendesk
    x_mailer = msg.get("X-Mailer", "")
    x_zd_account = msg.get("X-Zendesk-From-Account-Id", "")
    x_zd_email_id = msg.get("X-Zendesk-Email-Id", "")
    
    if "Zendesk Mailer" in x_mailer or x_zd_account or x_zd_email_id:
        result.detected_platform = "zendesk"
        result.confidence = 0.98
        result.platform_account_id = x_zd_account
        result.signals.append(f"X-Mailer: Zendesk Mailer")
        if x_zd_account:
            result.signals.append(f"X-Zendesk-From-Account-Id: {x_zd_account}")
        # Extract subdomain from Reply-To
        zd_sub = re.search(r"@([\w-]+\.zendesk\.com)", reply_to or message_id)
        if zd_sub:
            result.platform_subdomain = zd_sub.group(1)
        return result
    
    # Platform detection — SendGrid
    x_sg_eid = msg.get("X-SG-EID", "")
    if x_sg_eid or re.search(r"@geopod-ismtpd-\d+-\d+", message_id):
        result.detected_platform = "sendgrid"
        result.confidence = 0.97
        result.platform_account_id = x_sg_eid[:32] if x_sg_eid else None
        result.signals.append("X-SG-EID present (SendGrid)")
        return result
    
    # Platform detection — Mailchimp
    x_mc_user = msg.get("X-MC-User", "")
    x_mc_abuse = msg.get("X-MC-Abuse-Reports-To", "")
    if x_mc_user or "MailChimp Mailer" in x_mailer:
        result.detected_platform = "mailchimp"
        result.confidence = 0.97
        result.platform_account_id = x_mc_user
        result.signals.append(f"X-MC-User: {x_mc_user}")
        return result
    
    # Platform detection — HubSpot
    x_hs_id = msg.get("X-HubSpot-Tracking-Email-ID", "") or msg.get("X-HS-Email-ID", "")
    if x_hs_id:
        result.detected_platform = "hubspot"
        result.confidence = 0.97
        result.platform_account_id = x_hs_id
        result.signals.append(f"X-HubSpot-Tracking-Email-ID: {x_hs_id}")
        return result
    
    # Platform detection — Intercom
    x_ic_id = msg.get("X-Intercom-Email-ID", "")
    x_ic_app = msg.get("X-Intercom-App-ID", "")
    if x_ic_id or x_ic_app:
        result.detected_platform = "intercom"
        result.confidence = 0.96
        result.platform_account_id = x_ic_app
        result.signals.append(f"X-Intercom-App-ID: {x_ic_app}")
        return result
    
    # Platform detection — Mailgun
    x_mg_sid = msg.get("X-Mailgun-Sid", "")
    if x_mg_sid:
        result.detected_platform = "mailgun"
        result.confidence = 0.96
        result.platform_account_id = x_mg_sid
        result.signals.append(f"X-Mailgun-Sid: {x_mg_sid}")
        return result
    
    # Platform detection — Brevo
    if "Brevo" in x_mailer or "Sendinblue" in x_mailer:
        result.detected_platform = "brevo"
        result.confidence = 0.94
        result.signals.append(f"X-Mailer: {x_mailer}")
        return result
    
    # Platform detection — Zoho
    if "Zoho Mail" in x_mailer:
        result.detected_platform = "zoho"
        result.confidence = 0.93
        result.signals.append(f"X-Mailer: Zoho Mail")
        return result
    
    # Platform detection — Freshdesk (fallback — no unique header)
    if re.search(r"@freshdesk\.com", message_id + return_path + reply_to):
        result.detected_platform = "freshdesk"
        result.confidence = 0.85  # Lower confidence — infrastructure-only detection
        result.signals.append("Freshdesk domain in Message-ID/Return-Path/Reply-To")
        fd_sub = re.search(r"@([\w-]+\.freshdesk\.com)", reply_to)
        if fd_sub:
            result.platform_subdomain = fd_sub.group(1)
        return result
    
    return result
```

---

## Appendix B: Detection Rule Summary (Sigma Format)

```yaml
title: Helpdesk Platform Brand Impersonation — FakeSender Shield
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects emails where a high-value brand is impersonated via a helpdesk/CRM platform
author: FakeSender Shield Project
date: 2026/02/27
logsource:
  category: email
  product: email_gateway
detection:
  platform_zendesk:
    email.header|contains: 'X-Mailer: Zendesk Mailer'
    email.header|contains: 'X-Zendesk-From-Account-Id'
  platform_sendgrid:
    email.header|contains: 'X-SG-EID'
  platform_mailchimp:
    email.header|contains: 'X-MC-User'
  platform_hubspot:
    email.header|contains: 'X-HubSpot-Tracking-Email-ID'
  platform_intercom:
    email.header|contains: 'X-Intercom-App-ID'
  platform_mailgun:
    email.header|contains: 'X-Mailgun-Sid'
  high_value_brands:
    email.from_name|contains:
      - 'Coinbase'
      - 'Binance'
      - 'Kraken'
      - 'MetaMask'
      - 'Ledger'
      - 'PayPal'
      - 'Microsoft'
      - 'Google'
      - 'Amazon'
      - 'Apple'
  condition: >
    (platform_zendesk or platform_sendgrid or platform_mailchimp or
     platform_hubspot or platform_intercom or platform_mailgun) and
    high_value_brands
falsepositives:
  - Legitimate vendor using helpdesk platform with matching SPF authorisation
  - Own organisation's helpdesk platform (add to whitelist)
level: high
tags:
  - attack.initial_access
  - attack.t1566.002
  - attack.credential_access
```

---

*Report compiled February 2026. Primary sources: Zendesk SMTP Connector documentation (official), Freshworks community forums, Twilio SendGrid API documentation, CloudSEK research January 2025, Krebs on Security October 2025, Push Security March 2025, GBHackers December 2025, CSO Online April 2025, Cofense August 2025.*

*TLP:WHITE — Share freely for defensive purposes.*
