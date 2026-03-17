import { useState } from "react";

/* ─────────────────────────────────────────────────────────────
   DESIGN SYSTEM — Dieter Rams / Braun-inspired
   ─────────────────────────────────────────────────────────────
   Palette:   Warm off-white canvas, near-black text, one accent
   Type:      Work Sans (headings), JetBrains Mono (technical)
   Grid:      8pt base unit, mathematical spacing
   Principle: As little design as possible. Remove until broken,
              then stop. Every pixel justifies itself.
   ───────────────────────────────────────────────────────────── */

const C = {
  canvas:   "#F5F3EF",
  surface:  "#EDEBE6",
  line:     "#D4D1CB",
  dim:      "#9B9690",
  body:     "#3A3835",
  ink:      "#1A1917",
  accent:   "#C84B2F",
  accentBg: "#F9EDE9",
  code:     "#EDEAE4",
  white:    "#FAFAF8",
};

const RESEARCH_PROMPT = `# Deep Research Prompt: Phishing Threat Landscape 2026

You are a senior threat intelligence researcher and security engineer. Conduct an exhaustive, citation-rich deep research report on the following topics. For each section, provide concrete findings, real tool names, real GitHub repositories with star counts, real API endpoints where applicable, and specific actionable recommendations. Avoid generic advice — ground everything in what is current as of 2025–2026.

---

## SECTION 1: Emerging Phishing Techniques in 2026

Investigate and document:

1.1 Generative AI-Powered Phishing
- How are threat actors using LLMs to generate hyper-personalized spear phishing at scale?
- What is "polymorphic phishing" and how does AI make each email unique to evade signature-based detection?
- Document real-world campaigns where AI-generated content was confirmed by researchers

1.2 Trusted Platform Abuse (TPA) Techniques
- Which legitimate SaaS platforms are most abused in 2025-2026 as phishing redirects?
- How do attackers chain multiple trusted platforms to maximize evasion?
- What detection signals exist for TPA if the domains themselves are trusted?

1.3 QR Code Phishing (Quishing)
- Current prevalence and success rates
- How are QR codes being embedded in PDFs, physical mail, and invoices?

1.4 Adversary-in-the-Middle (AiTM) Phishing
- How do frameworks like Evilginx3, Modlishka, and Muraena bypass MFA?
- What is the detection gap for AiTM vs traditional phishing detection?

1.5 Crypto-Specific Phishing Vectors
- Fake airdrop campaigns, Discord compromises, wallet extension clones
- Seed phrase harvesting, signature phishing (permit/setApprovalForAll)
- Smart contract phishing disguised as mints

1.6 Infrastructure Innovations
- Bullet-proof hosting, Cloudflare Workers / Vercel abuse for phishing pages
- Domain generation algorithms in 2025-2026 campaigns

---

## SECTION 2: Major Threat Actor Groups (2025-2026)

2.1 State-Sponsored: Lazarus Group/APT38, APT29, APT41 — current crypto TTPs
2.2 Criminal Groups: Scattered Spider, TA558, DragonForce
2.3 Crypto-Specific: Angel Drainer successors, Telegram phishing kit vendors
2.4 PhaaS Platforms: LabHost successors, Darcula, Tycoon 2FA — costs, features, targets

---

## SECTION 3: Platforms Abused for Fake Sender Identities

For each platform document: account creation ease, domain verification, abuse report mechanism, known abuse cases, SPF/DKIM pass-through behavior.

Platforms: Zoho Desk, Freshdesk, Zendesk, HubSpot, Intercom, Crisp, Drift, Help Scout, Front, Gorgias, Salesforce, SendGrid, Mailgun, Mailchimp, Brevo, ActiveCampaign, Klaviyo, Twilio, and others discovered.

---

## SECTION 4: Best Phishing Reporting Resources

4.1 IOC Submission: MISP, OpenCTI, FS-ISAC, OTX, VirusTotal, URLhaus, PhishTank, ThreatFox, CIRCL, Spamhaus
4.2 Platform Abuse: Exact URLs/emails, expected SLAs for all major platforms. ICANN UDRP process.
4.3 Law Enforcement: FBI IC3, CISA, Europol EC3, Action Fraud UK, ACSC Australia

---

## SECTION 5: Top GitHub Repositories for Phishing Detection

For each repo provide: name, URL, star count, last commit, language, purpose, and how to use or extend it.

Categories: ML-based classifiers, URL detection, DMARC tools, typosquat detection, crypto-specific security, IOC management, phishing simulation.

---

## SECTION 6: Gaps in Current Tooling

6.1 Where do tools fail? Trusted platform abuse, AI content detection, QR scanning, multilingual phishing
6.2 Gap between enterprise tools and SMB-accessible solutions
6.3 Automation opportunities: manual processes, open training datasets, API combination pipelines

---

## SECTION 7: Libraries, APIs and Best Practices

7.1 Python: email parsing, URL analysis, WHOIS, DNS, ML classification libraries
7.2 JS/Node: browser-side detection, extension development
7.3 APIs with endpoints, rate limits, auth, cost: VirusTotal, Google Safe Browsing, URLhaus, PhishTank, Shodan, WHOIS XML, crt.sh, Cloudflare Radar, AbuseIPDB
7.4 Best practices: safe URL sandboxing, STIX 2.1 format, privacy considerations

---

## DELIVERABLE FORMAT

- Executive summary (500 words max) — 5 most important findings
- Each section fully developed with cited sources, real URLs, real data
- Top 10 Actionable Recommendations ordered by impact
- Consolidated resource directory at the end
- Flag areas where data was sparse or conflicting
- Prioritize 2025-2026 sources; note explicitly where things changed since 2024`;

const SECTIONS = [
  {
    id: "ioc",
    label: "IOC Submission",
    desc: "Submit indicators of compromise to shared threat databases",
    resources: [
      { name: "MISP Project",          url: "https://misp-project.org",                                                          note: "Open-source threat intel sharing platform",               tag: "Platform", key: true },
      { name: "AlienVault OTX",        url: "https://otx.alienvault.com",                                                        note: "Open Threat Exchange — free IOC community",               tag: "API" },
      { name: "URLhaus",               url: "https://urlhaus.abuse.ch/api",                                                      note: "Submit malicious URLs via REST API — abuse.ch",           tag: "API",      key: true },
      { name: "ThreatFox",             url: "https://threatfox.abuse.ch/api",                                                    note: "Submit IPs, domains, URLs, hashes — abuse.ch",            tag: "API" },
      { name: "PhishTank",             url: "https://phishtank.org/add_web_phish.php",                                           note: "Community-verified phishing URL submission",              tag: "Submit" },
      { name: "OpenPhish",             url: "https://openphish.com",                                                             note: "Automated phishing intelligence feed",                    tag: "Feed" },
      { name: "VirusTotal",            url: "https://virustotal.com",                                                            note: "Scan URLs, files, domains — 500 req/day free",            tag: "API",      key: true },
      { name: "Google Safe Browsing",  url: "https://safebrowsing.google.com/safebrowsing/report_phish/",                        note: "Report phishing to Google's global blocklist",            tag: "Report" },
      { name: "Spamhaus DBL",          url: "https://www.spamhaus.org/submit-sample/",                                           note: "Submit domains to Spamhaus Domain Block List",            tag: "Submit" },
      { name: "Cloudflare Radar",      url: "https://radar.cloudflare.com/scan",                                                 note: "URL scanner — page content and redirect analysis",        tag: "API" },
      { name: "AbuseIPDB",             url: "https://www.abuseipdb.com/report",                                                  note: "Report malicious IPs — 1000 lookups/day free",            tag: "API" },
      { name: "OpenCTI",               url: "https://www.opencti.io",                                                            note: "Structured threat intel platform, self-hosted",           tag: "Platform" },
    ],
  },
  {
    id: "isac",
    label: "ISACs & Authorities",
    desc: "Sector intelligence sharing centers and law enforcement reporting",
    resources: [
      { name: "FS-ISAC",               url: "https://www.fsisac.com",                                                            note: "Financial Services ISAC — covers crypto and fintech",     tag: "Join",     key: true },
      { name: "FBI IC3",               url: "https://www.ic3.gov",                                                               note: "Internet Crime Complaint Center",                         tag: "Report" },
      { name: "CISA",                  url: "https://www.cisa.gov/report",                                                       note: "US Cybersecurity and Infrastructure Security Agency",     tag: "Report" },
      { name: "MS-ISAC",               url: "https://www.cisecurity.org/ms-isac",                                                note: "Multi-State ISAC — open to all US entities",              tag: "Join" },
      { name: "Action Fraud",          url: "https://www.actionfraud.police.uk",                                                 note: "UK national fraud and cybercrime reporting",              tag: "Report" },
      { name: "ACSC Australia",        url: "https://www.cyber.gov.au/report-and-recover",                                       note: "Australian Cyber Security Centre",                        tag: "Report" },
      { name: "Europol EC3",           url: "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",             note: "European Cybercrime Centre",                              tag: "Report" },
      { name: "CIRCL Luxembourg",      url: "https://www.circl.lu/services/misp-malware-information-sharing-platform",           note: "EU MISP hosting and threat sharing community",            tag: "Platform" },
      { name: "Microsoft SmartScreen", url: "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",                  note: "Report phishing to Microsoft Defender blocklist",         tag: "Report" },
    ],
  },
  {
    id: "typosquat",
    label: "Typosquat Monitoring",
    desc: "Detect domains impersonating your brand before they are weaponised",
    resources: [
      { name: "DNSTwist Web",          url: "https://dnstwist.it",                                                               note: "Browser-based typosquat scanner, no install needed",      tag: "Tool",     key: true },
      { name: "DNSTwist GitHub",       url: "https://github.com/elceef/dnstwist",                                                note: "Self-host for automated weekly cron scans",               tag: "GitHub",   key: true },
      { name: "crt.sh",                url: "https://crt.sh",                                                                    note: "Certificate Transparency — find certs issued for brand",  tag: "Tool",     key: true },
      { name: "URLCrazy",              url: "https://github.com/urbanadventurer/urlcrazy",                                       note: "Domain typo and variation generator",                     tag: "GitHub" },
      { name: "ICANN UDRP",            url: "https://www.icann.org/resources/pages/udrp-2012-02-25-en",                          note: "Formal domain takedown process for impersonation",        tag: "Legal" },
      { name: "WHOIS / RDAP",          url: "https://lookup.icann.org",                                                          note: "Check ownership of discovered typosquat domains",         tag: "Tool" },
      { name: "MXToolbox SuperTool",   url: "https://mxtoolbox.com/SuperTool.aspx",                                              note: "Check DNS records, blacklists, SPF/DKIM/DMARC",          tag: "Tool" },
      { name: "BrandShield",           url: "https://www.brandshield.com",                                                       note: "Continuous brand impersonation monitoring service",       tag: "Commercial" },
      { name: "PhishLabs",             url: "https://www.phishlabs.com",                                                         note: "Enterprise brand monitoring and takedown service",        tag: "Commercial" },
      { name: "DomainFuzz",            url: "https://github.com/monkeym4ster/DomainFuzz",                                        note: "Domain permutation engine for monitoring pipelines",      tag: "GitHub" },
    ],
  },
  {
    id: "dmarc",
    label: "DMARC & Email Auth",
    desc: "Stop spoofing of your domain — SPF, DKIM, DMARC deployment",
    resources: [
      { name: "MXToolbox SuperTool",   url: "https://mxtoolbox.com/SuperTool.aspx",                                              note: "Check SPF, DKIM, DMARC — free email health check",        tag: "Tool",     key: true },
      { name: "Dmarcian",              url: "https://dmarcian.com",                                                              note: "DMARC report parsing and monitoring dashboard",           tag: "Tool",     key: true },
      { name: "Postmark DMARC",        url: "https://dmarc.postmarkapp.com",                                                     note: "Free DMARC monitoring for one domain",                    tag: "Free" },
      { name: "Valimail",              url: "https://www.valimail.com",                                                          note: "Automated DMARC enforcement platform",                    tag: "Commercial" },
      { name: "Google Admin Toolbox",  url: "https://toolbox.googleapps.com/apps/checkmx",                                       note: "Verify DNS records — SPF, DMARC, MX",                    tag: "Tool" },
      { name: "DMARC Analyzer",        url: "https://www.dmarcanalyzer.com",                                                     note: "Aggregate report analysis and enforcement dashboard",     tag: "Tool" },
      { name: "Mail-Tester",           url: "https://www.mail-tester.com",                                                       note: "Test email deliverability and spam score",                tag: "Tool" },
      { name: "Email Header Analyzer", url: "https://mxtoolbox.com/EmailHeaders.aspx",                                           note: "Decode and analyse raw email headers",                    tag: "Tool" },
      { name: "PowerDMARC",            url: "https://powerdmarc.com",                                                            note: "DMARC, DKIM, SPF, BIMI management platform",             tag: "Commercial" },
      { name: "RFC 7489",              url: "https://tools.ietf.org/html/rfc7489",                                               note: "Official DMARC specification",                            tag: "Docs" },
    ],
  },
  {
    id: "platforms",
    label: "Platform Abuse Reports",
    desc: "Report fake helpdesk and email accounts used to deliver phishing",
    resources: [
      { name: "Zoho",                  url: "mailto:abuse@zoho.com",                                                             note: "abuse@zoho.com — fraudulent Zoho Desk accounts",          tag: "Email",    key: true },
      { name: "Calendly",              url: "mailto:security@calendly.com",                                                      note: "security@calendly.com — brand impersonation",             tag: "Email",    key: true },
      { name: "Cloudflare",            url: "https://www.cloudflare.com/abuse/form",                                             note: "Report phishing pages behind Cloudflare CDN",             tag: "Form",     key: true },
      { name: "Google Workspace",      url: "https://support.google.com/a/contact/abuse",                                        note: "Report phishing via Google Forms and Drive",              tag: "Form" },
      { name: "Notion",                url: "mailto:abuse@makenotion.com",                                                       note: "abuse@makenotion.com — phishing pages on Notion",         tag: "Email" },
      { name: "Typeform",              url: "https://typeform.com/help/a/contact-typeform-support-360029623692",                  note: "Report phishing via Typeform forms",                      tag: "Form" },
      { name: "DocuSign",              url: "mailto:abuse@docusign.com",                                                         note: "abuse@docusign.com — fake DocuSign envelopes",            tag: "Email" },
      { name: "Freshdesk",             url: "mailto:abuse@freshdesk.com",                                                        note: "abuse@freshdesk.com — fraudulent helpdesk accounts",      tag: "Email" },
      { name: "Zendesk",               url: "https://www.zendesk.com/trust",                                                     note: "Report phishing from fraudulent Zendesk accounts",        tag: "Form" },
      { name: "HubSpot",               url: "mailto:abuse@hubspot.com",                                                          note: "abuse@hubspot.com — phishing via HubSpot email",          tag: "Email" },
      { name: "SendGrid / Twilio",     url: "https://sendgrid.com/contact/abuse",                                                note: "Report phishing sent via SendGrid infrastructure",        tag: "Form" },
      { name: "Mailchimp",             url: "https://www.intuit.com/legal/intuit-abuse-policy",                                  note: "Report spam and phishing from Mailchimp accounts",        tag: "Form" },
      { name: "Namecheap",             url: "https://www.namecheap.com/support/knowledgebase/article.aspx/9476",                 note: "Domain abuse and phishing hosted via Namecheap",         tag: "Form" },
      { name: "GoDaddy",               url: "https://supportcenter.godaddy.com/AbuseReport",                                     note: "Report phishing domains registered via GoDaddy",          tag: "Form" },
    ],
  },
  {
    id: "github",
    label: "GitHub Repos",
    desc: "Highest-signal open source tools for detection and defence",
    resources: [
      { name: "Gophish",                      url: "https://github.com/gophish/gophish",                                        note: "Open-source phishing simulation framework",               tag: "Go",       key: true },
      { name: "DNSTwist",                     url: "https://github.com/elceef/dnstwist",                                        note: "Domain permutation engine for typosquat detection",       tag: "Python",   key: true },
      { name: "MetaMask eth-phishing-detect", url: "https://github.com/MetaMask/eth-phishing-detect",                          note: "On-chain phishing address blocklist in MetaMask",         tag: "JS",       key: true },
      { name: "MISP",                         url: "https://github.com/MISP/MISP",                                              note: "Malware Information Sharing Platform — full stack",       tag: "PHP" },
      { name: "OpenCTI",                      url: "https://github.com/OpenCTI-Platform/opencti",                               note: "Structured threat intelligence management",               tag: "Node.js" },
      { name: "theHarvester",                 url: "https://github.com/laramies/theHarvester",                                  note: "OSINT — email, domain and IP recon",                      tag: "Python" },
      { name: "CertStream",                   url: "https://github.com/CaliDog/certstream-python",                             note: "Real-time certificate transparency log monitor",          tag: "Python" },
      { name: "PhishingKitHunter",            url: "https://github.com/t4d/PhishingKitHunter",                                 note: "Detect and analyse phishing kits on live sites",          tag: "Python" },
      { name: "PyMISP",                       url: "https://github.com/MISP/PyMISP",                                           note: "Python library for MISP API integration",                 tag: "Python" },
      { name: "Loki IOC Scanner",             url: "https://github.com/Neo23x0/Loki",                                          note: "Scan systems and files for known IOC matches",            tag: "Python" },
      { name: "Evilginx3",                    url: "https://github.com/kgretzky/evilginx2",                                    note: "AiTM phishing framework — red team research only",        tag: "Go" },
      { name: "Checkphish CLI",               url: "https://github.com/bolster-ai/checkphish-python",                         note: "Real-time URL phishing detection via API",                tag: "Python" },
    ],
  },
  {
    id: "crypto",
    label: "Crypto Defence",
    desc: "Web3 and wallet-specific phishing detection and reporting",
    resources: [
      { name: "Chainabuse",            url: "https://www.chainabuse.com",                                                        note: "Report crypto scam addresses — on-chain IOC sharing",     tag: "Report",   key: true },
      { name: "MetaMask Phishing List",url: "https://github.com/MetaMask/eth-phishing-detect",                                  note: "Submit phishing domains to MetaMask's global blocklist",  tag: "GitHub",   key: true },
      { name: "Revoke.cash",           url: "https://revoke.cash",                                                              note: "Inspect and revoke malicious token approvals",            tag: "Tool",     key: true },
      { name: "ScamSniffer",           url: "https://scamsniffer.io",                                                           note: "Real-time anti-phishing for Web3 transactions",           tag: "Tool" },
      { name: "De.Fi Shield",          url: "https://de.fi/scanner",                                                            note: "Smart contract approval scanner and revoker",             tag: "Tool" },
      { name: "GoPlus Security API",   url: "https://gopluslabs.io",                                                            note: "Token, NFT, and malicious address check API",             tag: "API" },
      { name: "Wallet Guard",          url: "https://www.walletguard.app",                                                      note: "Browser extension for real-time Web3 phishing detection", tag: "Extension" },
      { name: "Webacy",                url: "https://webacy.com",                                                               note: "Real-time wallet threat monitoring and alerts",           tag: "Tool" },
      { name: "Blockthreat Newsletter",url: "https://blockthreat.substack.com",                                                 note: "Weekly crypto security threat intelligence newsletter",   tag: "Intel" },
      { name: "Rekt News",             url: "https://rekt.news",                                                                note: "Post-mortems on major DeFi hacks and phishing",           tag: "Intel" },
    ],
  },
  {
    id: "apis",
    label: "Detection APIs",
    desc: "Build your own automated phishing detection pipeline",
    resources: [
      { name: "VirusTotal API v3",     url: "https://developers.virustotal.com/reference",                                       note: "Scan URLs, IPs, domains, files — 500 req/day free",       tag: "API",      key: true },
      { name: "Google Safe Browsing",  url: "https://developers.google.com/safe-browsing/v4",                                    note: "Check URLs against Google's phishing blocklist",          tag: "API",      key: true },
      { name: "URLhaus API",           url: "https://urlhaus-api.abuse.ch",                                                      note: "Query and submit malicious URLs — free REST",             tag: "API" },
      { name: "urlscan.io",            url: "https://urlscan.io/docs/api",                                                       note: "Sandboxed URL scan — screenshot and DOM analysis",        tag: "API" },
      { name: "PhishTank API",         url: "https://www.phishtank.com/api_info.php",                                            note: "Check URL against verified phishing list",                tag: "API" },
      { name: "AbuseIPDB API",         url: "https://docs.abuseipdb.com",                                                        note: "IP reputation — 1000 checks/day free tier",               tag: "API" },
      { name: "Shodan API",            url: "https://developer.shodan.io",                                                       note: "Infrastructure enrichment — open ports and services",     tag: "API" },
      { name: "IPInfo API",            url: "https://ipinfo.io/developers",                                                      note: "IP geolocation and ASN — 50k req/month free",             tag: "API" },
      { name: "Cloudflare Radar API",  url: "https://developers.cloudflare.com/radar/investigate/url-scanner",                   note: "Analyse page content and redirect chains",                tag: "API" },
      { name: "WHOIS XML API",         url: "https://whois.whoisxmlapi.com/api/documentation/making-requests",                   note: "Bulk WHOIS lookups for domain registration data",         tag: "API" },
      { name: "crt.sh API",            url: "https://crt.sh/?q=%.yourdomain.com&output=json",                                   note: "Query CT logs — brand monitoring via JSON output",        tag: "API" },
      { name: "ThreatFox API",         url: "https://threatfox.abuse.ch/api",                                                    note: "Query and submit IOCs to abuse.ch ThreatFox",             tag: "API" },
    ],
  },
];

const TAG_PALETTE = {
  "API":        { bg: "#E8F0FE", fg: "#1A56CC" },
  "GitHub":     { bg: "#F0EAF8", fg: "#6B28A8" },
  "Tool":       { bg: "#E6F4EA", fg: "#1A6E35" },
  "Free":       { bg: "#E6F4EA", fg: "#1A6E35" },
  "Report":     { bg: "#F9EDE9", fg: "#C84B2F" },
  "Submit":     { bg: "#F9EDE9", fg: "#C84B2F" },
  "Join":       { bg: "#FEF3E2", fg: "#B45309" },
  "Platform":   { bg: "#E0F2FE", fg: "#0C5A8E" },
  "Commercial": { bg: "#EDEBE6", fg: "#9B9690" },
  "Email":      { bg: "#FDF0FF", fg: "#8B1FAA" },
  "Form":       { bg: "#FDF0FF", fg: "#8B1FAA" },
  "Feed":       { bg: "#E0F2FE", fg: "#0C5A8E" },
  "Dataset":    { bg: "#E6F4EA", fg: "#1A6E35" },
  "Python":     { bg: "#FFFBEB", fg: "#7C4E00" },
  "Go":         { bg: "#E0F2FE", fg: "#0C5A8E" },
  "JS":         { bg: "#FFFBEB", fg: "#7C4E00" },
  "Node.js":    { bg: "#FFFBEB", fg: "#7C4E00" },
  "PHP":        { bg: "#F0EAF8", fg: "#6B28A8" },
  "Extension":  { bg: "#E6F4EA", fg: "#1A6E35" },
  "Intel":      { bg: "#F9EDE9", fg: "#C84B2F" },
  "Legal":      { bg: "#EDEBE6", fg: "#3A3835" },
  "Docs":       { bg: "#EDEBE6", fg: "#3A3835" },
};

const SNIPPETS = [
  {
    id: "dnstwist",
    title: "DNSTwist — Typosquat Scanning",
    lang: "bash",
    code: `# Install
pip install dnstwist

# Scan — show only registered variants
dnstwist yourdomain.io --registered

# Export to CSV for weekly cron monitoring
dnstwist yourdomain.io --registered --format csv > results.csv

# Flag variants with live MX records (can already send phishing mail)
dnstwist yourdomain.io --registered --mxcheck`,
  },
  {
    id: "dmarc",
    title: "DMARC DNS Record",
    lang: "dns",
    code: `; Step 1 — add TXT record to your DNS
Host:   _dmarc.yourdomain.com
Value:  v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100

; Step 2 — after reviewing 1 week of reports, upgrade to reject
Value:  v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100

; Verify at: https://mxtoolbox.com/SuperTool.aspx`,
  },
  {
    id: "stix",
    title: "STIX 2.1 — IOC Format",
    lang: "json",
    code: `{
  "type": "indicator",
  "spec_version": "2.1",
  "pattern_type": "stix",
  "pattern": "[email-message:from_ref.value = 'support@exchangeart8364.zohodesk.com']",
  "valid_from": "2026-02-26T00:00:00Z",
  "name": "Phishing sender — fake Exchange.Art airdrop",
  "labels": ["malicious-activity", "phishing"]
}`,
  },
  {
    id: "vt",
    title: "VirusTotal URL Scan — Python",
    lang: "python",
    code: `import requests, base64

API_KEY = "your_vt_api_key"
url     = "https://suspicious-site.example.com"

# Encode URL to base64 (VT v3 requirement)
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

resp = requests.get(
    f"https://www.virustotal.com/api/v3/urls/{url_id}",
    headers={"x-apikey": API_KEY}
)
stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
print(f"Malicious: {stats['malicious']} / {sum(stats.values())}")`,
  },
];

const CHECKLIST = [
  { action: "Report Zoho accounts to abuse@zoho.com",                  priority: "Critical" },
  { action: "Report Calendly link to security@calendly.com",           priority: "Critical" },
  { action: "Submit URL to Google Safe Browsing",                      priority: "Critical" },
  { action: "Submit to URLhaus and PhishTank",                         priority: "Critical" },
  { action: "Block sender domains at email gateway",                   priority: "Critical" },
  { action: "Alert users via email and in-app banner",                 priority: "Critical" },
  { action: "Add DMARC TXT record (p=quarantine)",                     priority: "High" },
  { action: "Verify SPF and DKIM are active",                          priority: "High" },
  { action: "Run DNSTwist scan for typosquats",                        priority: "High" },
  { action: "Report impersonation domains via ICANN UDRP",             priority: "Medium" },
  { action: "Submit IOCs to FS-ISAC and MISP",                         priority: "Medium" },
  { action: "Upgrade DMARC to p=reject after 1-week review",           priority: "High" },
];

export default function App() {
  const [section,  setSection]  = useState("ioc");
  const [tab,      setTab]      = useState("directory");
  const [query,    setQuery]    = useState("");
  const [copied,   setCopied]   = useState("");
  const [checked,  setChecked]  = useState({});

  const current   = SECTIONS.find(s => s.id === section);
  const resources = current?.resources.filter(r =>
    !query ||
    r.name.toLowerCase().includes(query.toLowerCase()) ||
    r.note.toLowerCase().includes(query.toLowerCase())
  ) ?? [];

  function copy(text, id) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(id);
    setTimeout(() => setCopied(""), 1600);
  }

  function tagStyle(tag) {
    const p = TAG_PALETTE[tag] || { bg: C.surface, fg: C.body };
    return {
      background: p.bg, color: p.fg,
      fontSize: 10, fontWeight: 600,
      padding: "2px 7px", borderRadius: 2,
      letterSpacing: "0.04em", textTransform: "uppercase",
      fontFamily: "inherit", display: "inline-block",
    };
  }

  const TABS = [["directory","Directory"],["research","Research Prompt"],["quickref","Quick Ref"]];

  return (
    <div style={{ fontFamily: "'Work Sans', system-ui, sans-serif", background: C.canvas, minHeight: "100vh", color: C.body }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Work+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        a { color: inherit; text-decoration: none; }
        button { font-family: inherit; cursor: pointer; }
        ::-webkit-scrollbar { width: 3px; height: 3px; }
        ::-webkit-scrollbar-track { background: ${C.canvas}; }
        ::-webkit-scrollbar-thumb { background: ${C.line}; }
        .r-card:hover { background: ${C.white} !important; border-color: ${C.ink} !important; }
        .nav-item:hover { background: ${C.surface} !important; }
        .tab-btn:hover { color: ${C.ink} !important; }
        .copy-btn:hover { background: ${C.surface} !important; }
        .check-row:hover { background: ${C.surface} !important; }
        input:focus { outline: none; border-color: ${C.body} !important; }
        input::placeholder { color: ${C.dim}; }
        pre, code { font-family: 'JetBrains Mono', monospace !important; }
      `}</style>

      {/* ── HEADER ── */}
      <header style={{ background: C.white, borderBottom: `1px solid ${C.line}` }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 40px", display: "flex", alignItems: "center", height: 56 }}>
          <div style={{ flex: 1, display: "flex", alignItems: "baseline", gap: 16 }}>
            <span style={{ fontSize: 14, fontWeight: 700, letterSpacing: "-0.3px", color: C.ink }}>
              Phishing Defence Hub
            </span>
            <span style={{ fontSize: 11, color: C.dim }}>
              IOC · DMARC · Typosquats · Abuse Reports · Tools
            </span>
          </div>
          <nav style={{ display: "flex" }}>
            {TABS.map(([id, label]) => (
              <button key={id} className="tab-btn"
                onClick={() => setTab(id)}
                style={{
                  background: "none", border: "none", padding: "0 16px", height: 56,
                  fontSize: 12, fontWeight: tab === id ? 600 : 400,
                  color: tab === id ? C.ink : C.dim,
                  borderBottom: `2px solid ${tab === id ? C.ink : "transparent"}`,
                  transition: "color 100ms, border-color 100ms",
                }}>
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* ── DIRECTORY TAB ── */}
      {tab === "directory" && (
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 40px", display: "flex", gap: 40 }}>

          {/* Sidebar */}
          <aside style={{ width: 188, flexShrink: 0 }}>
            <p style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 12 }}>
              Categories
            </p>
            {SECTIONS.map(s => (
              <button key={s.id} className="nav-item"
                onClick={() => { setSection(s.id); setQuery(""); }}
                style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  width: "100%", background: section === s.id ? C.surface : "none", border: "none",
                  borderLeft: `2px solid ${section === s.id ? C.ink : "transparent"}`,
                  padding: "8px 10px 8px 12px", marginBottom: 1, textAlign: "left",
                  transition: "background 100ms",
                }}>
                <span style={{ fontSize: 12, fontWeight: section === s.id ? 600 : 400, color: section === s.id ? C.ink : C.body }}>
                  {s.label}
                </span>
                <span style={{ fontSize: 10, color: C.dim }}>{s.resources.length}</span>
              </button>
            ))}
          </aside>

          {/* Content */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 24 }}>
              <div>
                <h1 style={{ fontSize: 17, fontWeight: 600, color: C.ink, letterSpacing: "-0.3px", marginBottom: 5 }}>
                  {current?.label}
                </h1>
                <p style={{ fontSize: 12, color: C.dim, lineHeight: 1.6 }}>{current?.desc}</p>
              </div>
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter…"
                style={{
                  width: 172, background: C.white, border: `1px solid ${C.line}`,
                  borderRadius: 0, padding: "7px 12px", fontSize: 12, color: C.body, flexShrink: 0,
                  transition: "border-color 100ms",
                }}
              />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
              {resources.map((r, i) => (
                <a key={i} href={r.url} target="_blank" rel="noopener noreferrer"
                  className="r-card"
                  style={{
                    display: "block", background: C.white, border: `1px solid ${C.line}`,
                    padding: "14px 16px", position: "relative", transition: "background 100ms, border-color 100ms",
                  }}>
                  {r.key && (
                    <div style={{
                      position: "absolute", top: 0, right: 0,
                      background: C.ink, color: C.canvas,
                      fontSize: 8, fontWeight: 700, padding: "3px 7px",
                      letterSpacing: "0.12em",
                    }}>KEY</div>
                  )}
                  <p style={{ fontSize: 12, fontWeight: 600, color: C.ink, marginBottom: 6, paddingRight: r.key ? 36 : 0 }}>
                    {r.name}
                  </p>
                  <p style={{ fontSize: 11, color: C.dim, lineHeight: 1.55, marginBottom: 12 }}>
                    {r.note}
                  </p>
                  <span style={tagStyle(r.tag)}>{r.tag}</span>
                </a>
              ))}
            </div>

            {resources.length === 0 && (
              <p style={{ fontSize: 12, color: C.dim, textAlign: "center", padding: "48px 0" }}>
                No results for "{query}"
              </p>
            )}
          </div>
        </div>
      )}

      {/* ── RESEARCH PROMPT TAB ── */}
      {tab === "research" && (
        <div style={{ maxWidth: 760, margin: "0 auto", padding: "40px 40px" }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 24, marginBottom: 28 }}>
            <div>
              <h1 style={{ fontSize: 17, fontWeight: 600, color: C.ink, letterSpacing: "-0.3px", marginBottom: 6 }}>
                2026 Phishing Deep Research Prompt
              </h1>
              <p style={{ fontSize: 12, color: C.dim, lineHeight: 1.6, maxWidth: 480 }}>
                Paste into Claude Research, Perplexity Deep Research, or any AI research tool for a comprehensive, citation-rich threat landscape report.
              </p>
            </div>
            <button className="copy-btn"
              onClick={() => copy(RESEARCH_PROMPT, "prompt")}
              style={{
                background: C.white, border: `1px solid ${C.line}`, padding: "8px 18px",
                fontSize: 12, color: C.body, flexShrink: 0, transition: "background 100ms",
              }}>
              {copied === "prompt" ? "Copied" : "Copy prompt"}
            </button>
          </div>

          {/* Section overview grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, background: C.line, marginBottom: 28 }}>
            {[
              ["1 — Techniques",    "AI phishing, AiTM, Quishing, Trusted Platform Abuse, crypto vectors"],
              ["2 — Actors",        "State-sponsored groups, PhaaS platforms, crypto-specific threat actors"],
              ["3 — Platform Abuse","Zoho, Freshdesk, SendGrid + 15 others — SPF/DKIM pass-through survey"],
              ["4 — Reporting",     "IOC platforms, ISACs, law enforcement reporting with exact URLs"],
              ["5 — GitHub Repos",  "Top repos by stars — purpose, last commit, extension opportunities"],
              ["6 — Tooling Gaps",  "Unmet detection needs, automation opportunities, open datasets"],
              ["7 — Libraries/APIs","Python, JS, key APIs with endpoints, rate limits, and best practices"],
            ].map(([label, desc]) => (
              <div key={label} style={{ background: C.white, padding: "13px 16px" }}>
                <p style={{ fontSize: 10, fontWeight: 700, color: C.ink, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 4 }}>
                  {label}
                </p>
                <p style={{ fontSize: 11, color: C.dim, lineHeight: 1.55 }}>{desc}</p>
              </div>
            ))}
          </div>

          {/* Prompt */}
          <div style={{ background: C.white, border: `1px solid ${C.line}` }}>
            <div style={{ padding: "10px 16px", borderBottom: `1px solid ${C.line}`, background: C.surface, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.1em", textTransform: "uppercase" }}>
                Prompt text
              </span>
              <span style={{ fontSize: 10, color: C.dim }}>{RESEARCH_PROMPT.length.toLocaleString()} chars</span>
            </div>
            <pre style={{ padding: "20px", fontSize: 11, color: C.body, lineHeight: 1.85, maxHeight: 480, overflowY: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {RESEARCH_PROMPT}
            </pre>
          </div>
        </div>
      )}

      {/* ── QUICK REF TAB ── */}
      {tab === "quickref" && (
        <div style={{ maxWidth: 920, margin: "0 auto", padding: "40px 40px" }}>
          <h1 style={{ fontSize: 17, fontWeight: 600, color: C.ink, letterSpacing: "-0.3px", marginBottom: 6 }}>Quick Reference</h1>
          <p style={{ fontSize: 12, color: C.dim, marginBottom: 32 }}>Copy-ready commands, DNS records, and an incident response checklist.</p>

          {/* Key contacts */}
          <p style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 10 }}>
            Key Contacts
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 1, background: C.line, marginBottom: 40 }}>
            {[
              { label: "Zoho abuse",         val: "abuse@zoho.com",            href: "mailto:abuse@zoho.com" },
              { label: "Calendly security",  val: "security@calendly.com",     href: "mailto:security@calendly.com" },
              { label: "Google Safe Browse", val: "Report phishing →",         href: "https://safebrowsing.google.com/safebrowsing/report_phish/" },
              { label: "URLhaus",            val: "urlhaus.abuse.ch/api",       href: "https://urlhaus.abuse.ch/api" },
              { label: "PhishTank",          val: "phishtank.org/add_web_phish",href: "https://phishtank.org/add_web_phish.php" },
              { label: "FBI IC3",            val: "ic3.gov",                    href: "https://www.ic3.gov" },
            ].map(c => (
              <div key={c.label} style={{ background: C.white, padding: "14px 16px" }}>
                <p style={{ fontSize: 10, fontWeight: 600, color: C.dim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>
                  {c.label}
                </p>
                <a href={c.href} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize: 12, fontWeight: 500, color: C.accent }}>
                  {c.val}
                </a>
              </div>
            ))}
          </div>

          {/* Snippets */}
          <p style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 10 }}>
            Code Snippets
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 1, background: C.line, marginBottom: 40 }}>
            {SNIPPETS.map(s => (
              <div key={s.id} style={{ background: C.white }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "9px 16px", borderBottom: `1px solid ${C.line}`, background: C.surface }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: C.ink }}>{s.title}</span>
                    <span style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono', monospace" }}>{s.lang}</span>
                  </div>
                  <button className="copy-btn"
                    onClick={() => copy(s.code, s.id)}
                    style={{ background: "none", border: `1px solid ${C.line}`, padding: "4px 12px", fontSize: 10, color: C.dim, transition: "background 100ms" }}>
                    {copied === s.id ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre style={{ padding: "16px 20px", fontSize: 11, color: C.body, lineHeight: 1.85, overflowX: "auto" }}>
                  {s.code}
                </pre>
              </div>
            ))}
          </div>

          {/* Checklist */}
          <p style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 10 }}>
            Incident Response Checklist
          </p>
          <div style={{ border: `1px solid ${C.line}`, background: C.white }}>
            {CHECKLIST.map((item, i) => {
              const done = !!checked[i];
              const pc   = item.priority === "Critical" ? C.accent : item.priority === "High" ? "#B45309" : C.dim;
              return (
                <div key={i} className="check-row"
                  onClick={() => setChecked(p => ({ ...p, [i]: !p[i] }))}
                  style={{
                    display: "flex", alignItems: "center", gap: 14,
                    padding: "11px 16px",
                    borderBottom: i < CHECKLIST.length - 1 ? `1px solid ${C.line}` : "none",
                    cursor: "pointer",
                    background: done ? C.surface : C.white,
                    transition: "background 100ms",
                  }}>
                  <div style={{
                    width: 15, height: 15, border: `1.5px solid ${done ? C.ink : C.line}`,
                    background: done ? C.ink : "none", flexShrink: 0,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    {done && <span style={{ color: C.canvas, fontSize: 9, lineHeight: 1 }}>✓</span>}
                  </div>
                  <span style={{ flex: 1, fontSize: 12, color: done ? C.dim : C.body, textDecoration: done ? "line-through" : "none" }}>
                    {item.action}
                  </span>
                  <span style={{ fontSize: 10, fontWeight: 600, color: pc, flexShrink: 0, minWidth: 48, textAlign: "right" }}>
                    {item.priority}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: `1px solid ${C.line}`, padding: "20px 40px", marginTop: 48 }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <p style={{ fontSize: 10, color: C.dim, letterSpacing: "0.06em" }}>
            Phishing Defence Hub — Exchange.Art Security — 2026
          </p>
        </div>
      </footer>
    </div>
  );
}
