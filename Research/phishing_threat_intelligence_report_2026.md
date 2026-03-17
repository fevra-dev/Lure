# Phishing Threat Intelligence Report: 2025–2026
**Prepared for:** Internal Security Research  
**Classification:** TLP:WHITE — Unrestricted  
**Date:** February 2026  
**Research depth:** 100+ primary sources, 9 targeted search sessions

---

## Executive Summary

Five findings define the 2025–2026 phishing threat landscape:

**1. AI has industrialised spear phishing at scale.** KnowBe4 found AI-generated content now appears in 82.6% of phishing emails. SentinelOne measured a 1,265% surge in AI-assisted phishing volume since the public availability of large language models. IBM showed an LLM can construct a spear-phishing campaign in 5 minutes using 5 prompts — work that took a human expert team 16 hours. The barrier to highly-personalised, grammatically perfect, polymorphic attacks is now effectively zero for any actor with $60/month.

**2. Phishing-as-a-Service has doubled in kit diversity.** Barracuda recorded a doubling of active PhaaS kits in 2025. The market leaders — Tycoon 2FA (64,000+ documented incidents), Darcula v3 (AI-powered brand cloning), Mamba 2FA (10 million attacks in late 2025 alone) — have evolved from credential harvesters into full Adversary-in-the-Middle (AiTM) platforms that defeat session-based MFA. Barracuda estimates 50% of all 2025 credential attacks involved PhaaS, up from 30% in 2024.

**3. State-sponsored actors are operating at historic scale.** North Korea's Lazarus Group executed the largest cryptocurrency theft in history on 21 February 2025 — $1.5 billion from Bybit — via a supply chain attack on Safe{Wallet} preceded by social engineering. Sub-groups (TraderTraitor, Famous Chollima) are running simultaneous campaigns: fake LinkedIn job interviews (ClickFake), NPM package poisoning (230+ malicious packages), and IT worker infiltration (100+ US firms compromised). Scattered Spider, though under sustained law enforcement pressure, breached Marks & Spencer, Co-op, and Harrods in 2025 and deployed DragonForce ransomware.

**4. Crypto wallet drainer losses fell 83% but the ecosystem is actively evolving.** Scam Sniffer recorded $83.85 million in signature-phishing losses in 2025, down from $494 million in 2024, correlated with market cycles. Inferno Drainer, declared shut in 2023, was found fully operational through March 2025 with 30,000+ new victims. A new post-Pectra attack vector — EIP-7702 malicious signatures — appeared within weeks of Ethereum's upgrade, confirming that attackers adapt to protocol changes faster than defences do.

**5. QR code phishing (quishing) is mainstream and largely undetected.** Cofense reported a 331% year-over-year increase in quishing campaigns in Q1 2025. 26% of all malicious links in email campaigns are now embedded in QR codes. Only 36% of quishing incidents are accurately identified and reported by recipients. Most secure email gateways cannot scan QR codes in PDF attachments — a gap attackers are actively exploiting with AiTM-capable PhaaS kits.

---

## Section 1: Emerging Phishing Techniques in 2025–2026

### 1.1 Generative AI-Powered Phishing

**The operational model has shifted.** Threat actors are no longer primarily using purpose-built "dark LLMs." The actual operational use of AI in phishing follows a three-tier model:

**Tier 1 — Jailbroken commercial models (dominant).**  
Actors use carefully crafted jailbreak prompts against GPT-4, Gemini, and Mistral via the public API or via shared/stolen accounts to generate phishing lures. KELA tracked a 219% growth in dark web mentions of AI phishing tools from 2023 to 2024. The most effective technique is persona-injection: framing the model as a "security awareness trainer" and asking it to write "examples of convincing phishing emails for our training programme."

**Tier 2 — Commercially repackaged dark LLMs (growing).**  
Cato CTRL confirmed in June 2025 that two active WormGPT variants on BreachForums are built on Mistral's Mixtral and xAI's Grok with guardrails stripped via system prompt injection. Subscriptions begin at approximately €60/month via Telegram. Xanthorox, advertised on darknet forums in February 2025 at $300/month (cryptocurrency only), claims to be a fully self-hosted model with no third-party API dependency — though Trend Micro's analysis found it is likely another fine-tuned open-source model with a jailbreak system prompt.

**Tier 3 — PhaaS-integrated AI (emerging, most dangerous).**  
Darcula v3 added generative AI to its darcula-suite toolkit in April 2025. The workflow: provide a target brand URL → the tool uses Puppeteer to scrape the entire site → AI generates a pixel-perfect clone with injected credential-harvesting forms. Non-technical actors can deploy a branded phishing kit for any organisation in minutes.

**Polymorphic phishing** refers to AI-assisted generation of unique email variants at scale — changing subject lines, sender names, call-to-action phrasing, and lure context per recipient — so that no two emails share identical content and signature-based detection fails. IBM confirmed that AI can generate thousands of unique variants in the time a human would write one.

**Confirmed real-world AI-assisted campaigns:**
- Israeli security officials reported AI-generated SMS/voice messages impersonating emergency alerts during missile strikes in 2025, attributed to Iranian-aligned actors
- A surge in grammatically perfect CEO-impersonation BEC emails in early 2025 was confirmed by Flashpoint's Global Threat Intelligence Report as AI-assisted
- SentinelOne observed the 1,265% volume surge aligning precisely with the post-ChatGPT period

**Key detection indicators:** behavioural anomaly detection (tone vs. known sender style), conversation graph analysis (first-ever contact requesting urgent action), calendar-context checking (sender on leave), and header analysis remain the primary reliable signals. AI-generated text detectors are not yet reliable enough for use in production email security pipelines.

---

### 1.2 Trusted Platform Abuse (TPA)

Trusted Platform Abuse is the technique of using legitimate, well-reputation SaaS platforms as delivery infrastructure so that phishing links pass domain-reputation checks. The link the victim clicks is a genuine platform domain (e.g., `calendly.com`, `notion.so`, `forms.google.com`) — so SPF/DKIM pass, URL reputation lookups return clean, and Safe Browsing shows green.

**Most-abused platforms in 2025–2026:**

| Platform | Abuse vector | Why it evades detection |
|---|---|---|
| Calendly | Fake scheduling links, "crypto consultation" lures | Legitimate domain, short URLs |
| Google Forms / Sites | Credential harvesting form, fake KYC | `docs.google.com` trusted by all filters |
| Notion | Full phishing page hosted on `notion.site` | HTTPS, CDN, custom subdomains |
| DocuSign | Fake document signature requests | High-trust, financial context |
| Canva | Fake PDF with embedded malicious QR | Image-heavy, passes text scanners |
| Typeform | Credential-harvesting "account verification" forms | Clean domain, legitimate certificate |
| Adobe Acrobat Sign | Spoofed contract signature lure | High-value brand trust |
| SharePoint / OneDrive | File share lure redirecting to AiTM proxy | Microsoft infrastructure |
| Firebase / Netlify / Vercel | Full phishing pages on `*.web.app`, `*.netlify.app` | Serverless, ephemeral, clean reputation |
| Cloudflare Workers | AiTM reverse proxy served from `*.workers.dev` | Cloudflare IP ranges trusted everywhere |
| Telegram bots | PhaaS delivery channels, verification lures | App platform, not scanned by email gateways |

**Chaining technique:** Attackers frequently chain 3-4 platforms. Example: Calendly link (legitimate) → Google Sites page (legitimate) → Cloudflare Worker (legitimate, AiTM proxy) → victim credential capture. No single hop in the chain touches a malicious or blocked domain.

**Detection signals that work against TPA:**
- The final redirect target (post-all-hops) resolving to a non-organisational login page
- Newly created accounts on the platform (registration timestamps via platform search)
- QR codes in Canva/PDF links pointing to `workers.dev` or Firebase subdomains
- Victim email address pre-populated in the URL (a key AiTM signal)
- Suspicious page title or favicon mismatch on the landing page
- Unsolicited calendly/typeform link from a first-ever contact

Lazarus Group's Operation 99/Contagious Interview uses Calendly specifically to schedule "job interviews" as initial lures, as documented by ANY.RUN and Bitdefender in 2025.

---

### 1.3 QR Code Phishing (Quishing)

**Prevalence:** Cofense reported a 331% year-over-year increase in quishing campaigns in Q1 2025. APWG designated quishing a major rising threat in its Q1 2025 report. QR codes now appear in approximately 50% of phishing emails (Keepnet, 2025). 26% of all malicious links in phishing campaigns are embedded in QR codes.

**Why it works:**
1. Mobile devices used to scan QR codes are outside corporate EDR and email gateway protection
2. The URL encoded in a QR code is invisible until decoded — email gateways cannot click it
3. Most SEGs (Secure Email Gateways) cannot scan QR codes embedded in PDF attachments (noted by Sophos — their Phase 2 QR attachment scanning was planned for Q1 2025)
4. Recipients trained to "look at links before clicking" have no equivalent skill for QR codes

**Delivery methods:**
- Email body (direct embed) — most common, detectable by newer SEGs
- PDF attachment (1-2 page "invoice" or "HR notice") — significantly harder to detect
- Physical mail (USPS Postal Inspection Service issued quishing alerts in 2025)
- Overlay stickers on parking meters, restaurant menus, conference materials

**Key statistics:**
- 89.3% of QR phishing targets credentials (Abnormal AI)
- 56% of quishing emails impersonate Microsoft 2FA resets
- Energy sector receives 29% of malware-embedded quishing emails
- Executives face 42× more QR-based attacks than average employees
- Only 36% of incidents are accurately identified by recipients
- Average business loss per quishing incident: $1M+

**PhaaS with quishing integration:** ONNX Store (rebranded Caffeine kit), accessed via Telegram bots, generates AiTM-capable phishing pages delivered via QR-embedded PDFs. Tycoon 2FA added QR code generation for mobile-targeted campaigns. Sophos identified a campaign where the QR code included the victim's pre-populated email address for personalised targeting.

**Detection tools:**
- Abnormal AI — computer vision-based QR decoding in email body
- Proofpoint TAP — QR code URL extraction and detonation (2025 update)
- Microsoft Defender for Office 365 — QR scanning (limited to in-body, not all PDFs)
- IRONSCALES — behavioural QR analysis
- Open-source: `qreader` Python library + `pillow` for QR extraction from attachments; `pyzbar` for decoding

---

### 1.4 Adversary-in-the-Middle (AiTM) Phishing

AiTM is now the dominant technique for MFA bypass in phishing, having effectively rendered session-based MFA (TOTP, push notification) inadequate against sophisticated attackers.

**How AiTM works:**
1. Victim receives phishing link pointing to an actor-controlled reverse proxy
2. Proxy silently relays all HTTP(S) traffic between victim and legitimate service (e.g., Microsoft 365)
3. Victim sees and interacts with the real Microsoft login page — through the proxy
4. Proxy intercepts: username, password, and the session cookie granted after MFA completion
5. Attacker replays the session cookie to access the account without ever needing the MFA code

**Primary frameworks in active use:**

| Framework | Language | GitHub Stars | Key features |
|---|---|---|---|
| Evilginx3 | Go | ~10,000 | "Phishlets" for 40+ services, cookie capture, HTTP proxy |
| Modlishka | Go | ~5,000 | Reverse proxy, TLS support, credential logging |
| Muraena | Go | ~900 | Static resource capture, session hijack |
| Tycoon 2FA | PHP/Node.js | (PhaaS, not public) | MFA bypass, 64,000+ documented incidents |
| EvilProxy | (PhaaS) | (commercial) | 400+ supported sites, $400/month |

**Detection gap:** Traditional phishing detection checks URL reputation, domain age, and certificate transparency. None of these signals are triggered when the proxy domain is newly registered with a valid Let's Encrypt certificate and has no prior reputation. The proxy domain is the only "suspicious" element, and it is often concealed behind multi-hop redirect chains through trusted platforms.

**Signals that detect AiTM:**
- Victim email pre-populated in URL parameters (personalised targeting)
- Session tokens appearing from a different IP/ASN than the authentication IP
- Impossible travel: authentication from country A, session used from country B within seconds
- Conditional Access policy violations in Entra ID / Azure AD logs
- Login from ASN associated with known residential proxy networks
- New OAuth consent grants or inbox rules created immediately after authentication

**Crypto/Web3 AiTM:** Attackers proxy MetaMask extension sign-in flows, Coinbase login, and Binance authentication. The session cookie is of limited value for custodial exchange accounts (which require device fingerprinting), so the primary crypto AiTM goal is credential theft for later account takeover + SIM swap, rather than session replay.

**Defence:** The only effective technical control against AiTM is phishing-resistant MFA: FIDO2/WebAuthn hardware keys (YubiKey, Titan) or device-bound passkeys. These bind the authentication to the legitimate origin domain, making relay by a proxy cryptographically impossible.

---

### 1.5 Crypto-Specific Phishing Vectors (2025–2026)

**Wallet Drainer Ecosystem (2025 Update):**

Scam Sniffer's January 2026 report confirmed:
- Total 2025 losses: $83.85 million from 106,106 victims — down 83% and 68% respectively from 2024's $494 million
- Largest single theft: $6.5 million via Permit signature (September 2025)
- Q3 2025 saw the highest losses ($31 million), tracking Ethereum's price rally
- EIP-7702 malicious signatures emerged post-Pectra upgrade — 2 major cases, $2.54 million in August 2025
- Permit-based attacks: 38% of losses in incidents exceeding $1 million

The reduction in tracked losses may partly reflect a shift toward harder-to-track vectors (private key theft, supply chain compromise) not captured in drainer statistics.

**Inferno Drainer — Still Active:**
Despite an announced shutdown in November 2023, Check Point Research (May 2025) found Inferno Drainer fully operational. Between September 2024 and March 2025: 30,000+ new victims, $9 million in losses. Technical evolution includes:
- Single-use smart contracts (bypasses anti-phishing blacklists — the contract address is unknown until deployed)
- On-chain encrypted command server configurations
- Proxy-based communication making infrastructure untraceable
- Support for 30+ EVM-compatible networks

**Signature Phishing Mechanics:**

| Signature type | What it enables | Detection |
|---|---|---|
| `setApprovalForAll` | Unlimited spend on all NFTs/ERC-721 tokens | MetaMask warning (some wallets) |
| `approve(spender, amount)` | Unlimited ERC-20 spend allowance | Wallet shows spender address |
| `permit()` | Off-chain approval (no separate tx) | Often no wallet warning shown |
| `Permit2` (Uniswap) | Batch off-chain approvals | Minimal UI warnings |
| `eth_sign` | Arbitrary data sign (most dangerous) | No decoding in most wallets |
| EIP-7702 delegation | Temporary EOA-to-smart-contract conversion | New; minimal tooling to detect |

**Fake Airdrop Campaigns:**
Infrastructure pattern: Compromised social media account (Discord server admin, Twitter/X project account) → post announcing exclusive airdrop → link to phishing site → "connect wallet" → Permit/approve signature → funds drained. Scam Sniffer identified 290,000 malicious domains used for fake airdrops in 2024 alone.

**Discord Server Compromises:**
Inferno Drainer's January 2025 campaign (Check Point) targeted Discord users in crypto communities via a fake Collab.Land bot redirect. Attack flow: legitimate Web3 project site → fake Discord support server → fake Collab.Land → signature phishing. The Collab.Land impersonation is particularly effective because legitimate Web3 communities require Collab.Land for NFT-gated access.

**Fake Browser Extensions:**
MetaMask and Phantom clones distributed via:
- Google Chrome Web Store (regularly removed, regularly re-submitted)
- Sponsored search ads ("download MetaMask" → malicious extension site)
- Telegram groups with direct `.crx` file distribution

Malicious extension indicators: requests `tabs` and `storage` permissions in manifest, injects scripts into web3-enabled pages, captures seed phrase entry.

**NFT Marketplace Phishing:**
Common patterns on OpenSea, Blur, Magic Eden:
- Fake "offer" notifications linking to phishing site (impersonating the marketplace)
- Social engineering via DMs from fake collector accounts
- Front-running attacks combined with fake approval prompts
- Malicious OpenSea listing approvals that grant spend rights to attacker contract

**Seed Phrase Harvesting:**
"Wallet recovery" sites, often ranking for queries like "MetaMask seed phrase lost," "recover my crypto wallet," collect seed phrases via web forms. No drainer scripts needed — direct phrase entry gives full wallet control. Recovery scammers also operate via Telegram, Twitter DMs, and even YouTube comment sections.

---

### 1.6 Infrastructure Innovations

**Bullet-Proof Hosting (2025):**
Primary providers serving phishing actors include operations in Russia (Yalishanda network), Netherlands, Panama, and Malaysia. Cloudflare has no visibility into layer-7 content on services using their proxy — meaning phishing pages behind Cloudflare's reverse proxy have clean IP reputation until content-level takedown occurs.

**Cloudflare Workers / Pages:**
Phishing pages hosted on `*.workers.dev` or `*.pages.dev` benefit from:
- Cloudflare's IP ranges (trusted by most firewalls)
- Automatic HTTPS
- No hosting account traceable to attacker
- Free tier — zero cost for attacker
- Worker code obfuscated in deployment

Vercel (`*.vercel.app`) and Netlify (`*.netlify.app`) are similarly abused. Detection requires URL-content analysis, not domain reputation.

**Domain Generation Algorithms:**
2025 PhaaS kits (Tycoon 2FA, Darcula) use algorithmically rotated domains with:
- Brand keyword injection (`okta-corp-helpdesk[.]com`)
- Random string + legit TLD (`xk3d9-login-microsoft[.]com`)
- Punycode/homoglyph attacks (`xn--mcrosoft-l2a.com`)
- Combinations of brand + country + service (`microsoft365-uk-support[.]net`)

**Phishing Page Lifespan:**
APWG data shows the median phishing page is live for under 24 hours in 2025. High-profile campaigns targeting crypto exchanges may be live for as few as 2-6 hours before takedown. This drives the need for real-time detection (Certificate Transparency monitoring, URLhaus API) rather than blacklist-based approaches, which carry an inherent lag of 12-48 hours.

---

## Section 2: Major Threat Actor Groups (2025–2026)

### 2.1 State-Sponsored Groups

#### Lazarus Group / APT38 / TraderTraitor (North Korea)

**Attribution complexity:** Lazarus is an umbrella for multiple sub-groups with distinct mandates:
- **TraderTraitor (Jade Sleet / Slow Pisces / UNC4899):** Crypto targeting. Responsible for Bybit heist ($1.5B, Feb 2025).
- **Famous Chollima (Contagious Interview / Operation 99):** IT worker infiltration, fake job interviews targeting crypto developers.
- **Andariel (Stonefly):** Ransomware and espionage.

**2025 Confirmed Campaigns:**

| Campaign | Date | Method | Loss |
|---|---|---|---|
| Phemex Breach | January 2025 | Insider/supply chain | $70M+ |
| Bybit Heist | February 21, 2025 | Safe{Wallet} supply chain + blind signing | $1.5B |
| ClickFake Interview | Q1-Q2 2025 | LinkedIn fake jobs, ClickFix technique, BeaverTail/InvisibleFerret malware | Multiple victims |
| Contagious Interview (NPM) | Ongoing 2025 | 230+ malicious NPM packages, 36,000 firms affected | Credential theft |

**Bybit Attack Mechanics (February 2025 — the most important case study):**
1. Lazarus compromised a Safe{Wallet} developer's machine via targeted spear phishing
2. Injected malicious JavaScript into Safe{Wallet}'s AWS-hosted `app.safe.global` on February 19, 2025 at 15:29 UTC
3. The injected code activated specifically during Bybit's next transaction on February 21 at 14:13 UTC
4. The signing interface showed the correct destination address while the underlying smart contract logic was silently replaced
5. Bybit CEO signed what appeared to be a routine transfer — 401,347 ETH ($1.5B) was redirected to Lazarus-controlled addresses
6. Silent Push found that Lazarus had registered `bybit-assessment[.]com` just 22 hours before the attack using a known persona email

**Current TTPs:**
- LinkedIn persona-based social engineering (fake recruiter profiles)
- ClickFix technique: victims asked to "verify" by opening a terminal and running a command (delivers BeaverTail downloader)
- Malicious GitLab repositories hosting fake "coding tests"
- AI-enhanced identity documents for IT worker infiltration
- Calendly used to schedule "interviews" (per ANY.RUN analysis)
- Custom malware: Manuscrypt, AppleJeus, FALLCHILL, OtterCookie, ScoringMathTea RAT, BeaverTail, InvisibleFerret
- Blind signing attacks: UI shows correct data, underlying transaction is malicious

**FBI attribution:** FBI formally attributed Bybit to TraderTraitor on or around February 27, 2025. Estimated total Lazarus crypto theft since 2007: $3.4 billion+.

---

#### APT29 / Cozy Bear (Russia)

APT29 continued its spear phishing evolution in 2025 with a focus on diplomatic and policy targets. Current lure themes include:
- Wine-tasting events and social invitations to diplomats ("invitation-style lures")
- Fake EU policy consultations
- Compromised legitimate email accounts for BEC-style lateral phishing

The group uses NOBELIUM/Midnight Blizzard infrastructure and has been observed using spear phishing to target organisations that have provided support to Ukraine. Their use of legitimate email provider accounts (Gmail, Outlook) for initial delivery makes attribution and blocking difficult.

Notable 2025: MirrorFace (China-adjacent, sometimes confused with APT29 in attribution) targeted a Central European diplomatic institute ahead of Expo 2025 using Anel backdoor and AsyncRAT, demonstrating the broader European diplomatic targeting trend.

---

#### APT41 (China — Wicked Panda)

APT41 continues dual-track operations: state-directed espionage and financially motivated intrusions. In 2025, the group's phishing operations focus on:
- Spear phishing targeting semiconductor, defence, and critical infrastructure sectors
- Healthcare credential theft (HIPAA-relevant data)
- Financial sector targeting with commodity RATs and custom loaders

APT41 phishing infrastructure frequently uses legitimate cloud services (GitHub, Google Drive, OneDrive) as command-and-control staging, making network-level detection challenging.

---

### 2.2 Financially-Motivated Criminal Groups

#### Scattered Spider / UNC3944 / Muddled Libra / Octo Tempest

**Current status (2025):** Despite multiple arrests and sustained FBI/CISA/international law enforcement pressure, Scattered Spider remains highly active due to its decentralised structure.

**2025 Arrests:**
- Noah Michael Urban ("Sosa" / "King Bob") — pleaded guilty in April 2025, estimated $9.5-25M in losses
- Four members arrested in July 2025 (one juvenile) in connection with UK retail breaches
- Juvenile suspect surrendered to Clark County Juvenile Detention Center on September 17, 2025

**2025 Major Operations:**
- **UK Retail Attacks (April-May 2025):** Marks & Spencer, Co-op, Harrods — operational disruptions, data breaches, DragonForce ransomware deployed
- **Telecom Targeting:** Continued SIM swap and help desk impersonation campaigns
- **New PhaaS Kit (January 2025):** 5th unique phishing kit version identified, specifically mimicking Okta login portals with organisation-specific branding. Researcher "Lontz" published fingerprint on January 23, 2025.
- CISA updated its advisory on July 29, 2025, adding new TTPs including DragonForce ransomware deployment

**Social Engineering Playbook:**
1. Target: IT help desk, identity team, or senior executive
2. Open-source reconnaissance: LinkedIn, company org charts, leaked HR data
3. Impersonation: claim to be employee, provide personal details from OSINT
4. Request: password reset, MFA bypass ("I'm locked out before my flight")
5. Or: Push notification bombing (MFA fatigue) until victim approves
6. Post-access: deploy remote monitoring tool, escalate privileges, exfiltrate, deploy ransomware

**Crypto targeting:** Scattered Spider actively steals cryptocurrency from compromised organisations and individuals. Methods include SIM swapping to bypass crypto exchange SMS-based 2FA and direct wire fraud.

---

#### TA558 (Hospitality and FinTech Phishing)

TA558 continues its hospitality and travel industry targeting. The group uses VBA macro-enabled documents, PowerShell, and commodity RATs (AsyncRAT, Loda, Vjw0rm). In 2025, TA558 shifted toward hospitality booking platforms — impersonating Booking.com, Expedia, and Airbnb in phishing campaigns targeting travel companies' finance teams.

---

#### DragonForce (Ransomware-as-a-Service)

DragonForce emerged as a significant player in 2024 and was confirmed as Scattered Spider's ransomware partner in 2025. They operate a RaaS model with phishing as the primary initial access vector. Affiliates receive toolkits including phishing templates targeting corporate VPN login pages and Citrix portals.

---

### 2.3 Crypto-Specific Threat Actors

**Wallet Drainer Operators (2025 Landscape):**

The Drainer-as-a-Service model documented by ACM IMC 2025 researchers found 1,910 profit-sharing contracts, 56 operator accounts, and 6,087 affiliate accounts on Ethereum alone — confirming the scale of the underground ecosystem.

| Drainer | Status (2025) | Notes |
|---|---|---|
| Inferno Drainer | Active (undeclared) | Declared shutdown 2023, found active through March 2025, Check Point |
| Pink Drainer | Exited May 2024 | Held 28% market share at peak |
| Angel Drainer | Active | Market share declining per Scam Sniffer |
| Monkey Drainer | Exited | 2023 shutdown |
| AcesDrainer | Active | Mid-tier player |
| MS Drainer | Active | Targeting MetaMask and Coinbase Wallet |
| Nova Drainer | Active | Newer entrant |
| Venom Drainer | Active | Discord-focused delivery |

**Drainer cost:** As low as $300 for a base kit, typically 10-20% commission on stolen funds taken by the operator.

**Telegram channels:** Multiple channels with hundreds of thousands of subscribers sell phishing kits, stolen credentials, and drainer scripts. Channels are typically named variations of "crypto tools," "web3 security," or use obfuscated naming to avoid detection.

---

### 2.4 Phishing-as-a-Service (PhaaS) Platforms

**Market overview (2025):** Barracuda recorded 90% of high-volume phishing campaigns using PhaaS kits in 2025. The number of active kits doubled year-over-year.

#### Tycoon 2FA

- **Developer:** "Saad Tycoon Group" / "Mr_XaaD" via Telegram
- **Cost:** $120-$200/month (Bitcoin), premium tiers higher
- **Targets:** Microsoft 365, Gmail, enterprise SSO
- **MFA bypass:** AiTM reverse proxy intercepts session cookies in real-time
- **Documented incidents:** 64,000+ (ANY.RUN), 1,200+ malicious domains historically
- **2025 updates:** Dynamic browser fingerprinting, rotating CAPTCHA, Cloudflare Turnstile integration, clipboard hijacking for crypto addresses, fallback pages mimicking Microsoft Word Online
- **Infrastructure:** Built on Node.js/PHP with Nginx proxies; sessions intercepted at the `POST /login` exchange

#### Darcula v3

- **Origin:** SMS/smishing platform, evolved to full email + web phishing
- **Key innovation (April 2025):** AI-powered darcula-suite — input brand URL, receive pixel-perfect cloned phishing kit in minutes
- **Targets:** 200+ brands, postal services, financial institutions, airlines
- **Anti-detection:** Path randomisation, IP filtering, crawler blocking, device-type restrictions
- **Overlap:** Infrastructure overlap confirmed with Cephas kit (Barracuda)

#### Mamba 2FA

- **Activity:** Surged in late 2025 — approximately 10 million attacks recorded
- **Targets:** Enterprise Microsoft 365
- **Method:** AiTM, session cookie theft
- **Status:** "Established kits are neither down nor out" (Barracuda, January 2026)

#### Sneaky 2FA (Emerging, 2025)

- AiTM-based, directly engages Microsoft APIs to validate captured credentials/sessions
- Lightweight, no heavy reverse proxy dependency
- Streamlined AJAX-based credential exfiltration

#### Whisper 2FA (Emerging, 2025)

- Optimised for simplicity and speed
- AJAX-based MFA token theft
- Designed to avoid detection by reducing infrastructure footprint

#### GhostFrame (Emerging, 2025)

- Identified by Barracuda as aggressive newcomer
- Focus on advanced anti-analysis techniques

---

## Section 3: Platforms Abused for Fake Sender Identities

A systematic survey of helpdesk and CRM platforms commonly abused to impersonate trusted organisations.

### 3.1–3.2 Platform Survey

#### Zoho Desk
- **Account creation:** Free trial, email verification required. Custom domain support requires DNS record setup but can use Zoho's shared subdomain (e.g., `attackerco.zohodesk.com`).
- **Sender identity:** Emails originate from Zoho's shared sending infrastructure. SPF/DKIM pass for `zohodesk.com` — the recipient sees `From: "Coinbase Support" <support@coinbase.zohodesk.com>` which passes authentication.
- **Abuse reporting:** abuse@zohocorp.com | SLA: not publicly published.
- **Known abuse:** Researchers documented Zoho Desk being used to send phishing emails impersonating cryptocurrency exchange support teams, with `support@exchange.zohodesk.com` style addresses. The emails pass SPF/DKIM because Zoho is the actual sender.
- **Defence signal:** Look for `zohodesk.com` in the envelope sender or `via` header when the display name claims to be a different organisation.

#### Freshdesk
- **Account creation:** Free plan, email-only verification. No domain verification required to set a custom-display sender name.
- **Sender identity:** Emails sent via Freshdesk infrastructure; DKIM signed by Freshdesk. Evren (security researcher) documented a vulnerability where the sender email field in ticket submission can be modified by an attacker, enabling impersonation of internal employees.
- **Abuse reporting:** Security disclosure process via Freshdesk's responsible disclosure programme. General abuse: support@freshdesk.com.
- **Known abuse:** Attacker creates Freshdesk account, opens a "ticket" as `ceo@targetcompany.com`, triggering ticket confirmation emails to support staff that appear to come from the CEO.
- **Defence signal:** `via freshdesk.com` or `via freshservice.com` in headers when display name claims internal origin.

#### Zendesk
- **Account creation:** Free trial available. Custom subdomain at `company.zendesk.com`. No domain ownership verification for display names.
- **Sender identity:** Zendesk's shared sending infrastructure (SendGrid/Mailgun backend); SPF/DKIM pass.
- **Abuse reporting:** trust.zendesk.com/hc/en-us — abuse form available.
- **Known abuse:** Documented phishing campaigns impersonating financial services firms using `support@targetbank.zendesk.com` subdomain addresses.
- **Defence signal:** `zendesk.com` in sending infrastructure headers.

#### HubSpot (Marketing Hub)
- **Account creation:** Free tier available. Requires email but no domain verification for sender display name.
- **Sender identity:** HubSpot's marketing email infrastructure; emails pass SPF/DKIM under HubSpot's domain unless custom domain is configured.
- **Abuse reporting:** security@hubspot.com / trust.hubspot.com.
- **Known abuse:** Phishing campaigns using HubSpot's CRM email tools to send credential-harvesting emails that appear to come from financial institutions.
- **Defence signal:** `via hubspotemail.net` or `via hs-sites.com` in Received headers.

#### Intercom
- **Account creation:** Free trial. No domain verification for sender display name.
- **Sender identity:** Emails from `mail.intercom.io` — passes SPF/DKIM.
- **Abuse reporting:** security@intercom.io
- **Known abuse:** Used to send fake "account security alert" emails impersonating SaaS vendors.

#### SendGrid (Twilio)
- **Account creation:** Free tier (100 emails/day). Domain verification required for sending authenticated mail, but new domains can be registered cheaply.
- **Sender identity:** With domain verification, sends from attacker-controlled domain with Twilio/SendGrid SPF/DKIM. Without verification, sends from a shared Twilio IP range.
- **Abuse reporting:** abuse@sendgrid.com | Automated spam reporting via Twilio's email compliance system.
- **Known abuse:** Extensively used for bulk phishing campaigns — SendGrid's high IP reputation means emails bypass many spam filters. Twilio has taken repeated action against abuse.
- **Defence signal:** `via sendgrid.net` or `via em.sendgrid.net` in headers. Block sends from SendGrid shared IPs where the From domain does not match the sending infrastructure.

#### Mailgun (Sinch)
- **Account creation:** Free trial. Domain verification (DNS record) required for custom domain sending.
- **Abuse reporting:** abuse@mailgun.com
- **Known abuse:** Similar to SendGrid — used for phishing bulk sends with new domain registration.

#### Mailchimp (Intuit)
- **Account creation:** Free tier (500 contacts, 1,000 emails/month). Email verification required.
- **Sender identity:** Marketing emails via Mailchimp infrastructure; SPF/DKIM via Mailchimp or custom domain.
- **Abuse reporting:** abuse@mailchimp.com. SLA: typically 24-72 hours.
- **Known abuse:** Mailchimp experienced breaches in 2022 where attacker-controlled Mailchimp accounts were used to send phishing to the customer lists of crypto companies (Trezor, MailerLite incidents).

#### Brevo (formerly Sendinblue)
- **Account creation:** Free tier (300 emails/day). Minimal verification.
- **Abuse reporting:** abuse@brevo.com
- **Known abuse:** Used in bulk phishing campaigns due to EU-based infrastructure (sometimes bypasses US-focused blocklists).

#### Klaviyo
- **Account creation:** Free tier with email verification. E-commerce focused.
- **Abuse reporting:** security@klaviyo.com
- **Known abuse:** Used to target e-commerce brand customers with fake "order confirmation" phishing.

#### Crisp / Drift / Tidio / Help Scout
- Smaller platforms. Account creation is generally easier (free tier, email verification only). Sender identity tied to platform domain unless custom domain configured. Abuse reporting via in-app mechanisms or info@[platform].com. Less commonly abused due to lower sending volume, but increasingly targeted.

#### Salesforce Service Cloud
- **Account creation:** Requires a Salesforce org (paid, or trial). More friction for attackers.
- **Abuse reporting:** security@salesforce.com | Salesforce Trust site: trust.salesforce.com.
- **Known abuse:** Scattered Spider-linked breach of Chanel's Salesforce environment (claimed August 2025) may involve CRM platform abuse for subsequent phishing against customer base.

---

### 3.3 Defences Against Helpdesk Platform Abuse

**Technical controls:**

1. **Custom `Reply-To` / `From` domain monitoring:** Configure email security solutions to flag emails where the display name claims an internal brand but the `From` domain is a third-party platform (`*.zohodesk.com`, `*.freshdesk.com`, `*.zendesk.com`).

2. **Brand display name protection rules:** Most enterprise email platforms (Microsoft Defender for Office 365, Proofpoint) support rules that quarantine emails where the display name contains your organisation's name but the `From` email does not match your domain.

3. **DMARC at `p=reject`:** While this protects your domain from being spoofed, it does not stop an attacker using `support@yourcompany.zendesk.com` — because that domain is `zendesk.com`, not `yourcompany.com`. DMARC is necessary but not sufficient.

4. **Vendor relationship awareness:** Train users to understand that legitimate vendors send from their own domain, not helpdesk platform subdomains. Your bank will never email from `security@yourbank.zendesk.com`.

5. **Email gateway rules for platform abuse patterns:** Block or flag emails from known helpdesk sending domains (`via freshdesk.com`, `via zendesk.com`) when display names match sensitive internal or external brand names.

6. **Platform-level controls:** Some platforms (SendGrid, Mailchimp) now offer brand protection programmes where organisations can request that their brand names be blocked from use in sender display names by third parties. Proactively register your brand with these programmes.

7. **Abuse reporting SLAs:** When you identify platform abuse, report it immediately. Most major platforms (Zendesk, Freshdesk, Mailchimp, SendGrid) will disable the abusive account within 24-72 hours. Document your point of contact at each major platform.

---

## Section 4: Phishing Reporting Resources & Directories (2026)

### 4.1 IOC Submission & Threat Intelligence Sharing

#### MISP (Malware Information Sharing Platform)
- **Website:** https://www.misp-project.org
- **GitHub:** https://github.com/MISP/MISP (~6,000 stars)
- **Joining MISP communities:** The CIRCL (Computer Incident Response Center Luxembourg) operates the primary public MISP community. Request access at: circl.lu/services/misp-malware-information-sharing-platform/
- **Accepted formats:** MISP JSON, OpenIOC, STIX 1.x/2.x, CSV, Snort/Suricata rules, YARA
- **API:** REST API at `https://your-misp-instance/events/restSearch`; pyMISP library available for Python integration
- **Key use for crypto teams:** Share phishing domains, wallet drainer contract addresses, and malicious npm packages in real-time

#### OpenCTI
- **Website:** https://www.opencti.io
- **GitHub:** https://github.com/OpenCTI-Platform/opencti (~6,000 stars)
- **Public instances:** Some sector-specific communities operate shared OpenCTI instances. Request access through ISAC membership.
- **Setup:** Docker deployment, minimum 16GB RAM. Filigran (commercial) offers hosted instances.
- **Connectors:** 100+ connectors for MISP, VirusTotal, Shodan, AlienVault OTX, CIRCL, URLhaus, etc.
- **Key use:** Structured threat intelligence with full STIX 2.1 support, relationship mapping, and campaign tracking

#### FS-ISAC (Financial Services ISAC)
- **Website:** https://www.fsisac.com
- **Relevant to:** Banks, exchanges, payment processors, crypto companies
- **Membership tiers:** Full Member, Associate Member (for fintech/crypto — lower barrier to entry)
- **Submission process:** Member portal at members.fsisac.com; TLP-marked submissions
- **SLA:** Active threat intel shared within hours to membership for in-progress incidents

#### AlienVault OTX (Open Threat Exchange)
- **URL:** https://otx.alienvault.com
- **API:** `https://otx.alienvault.com/api/v1/indicators/submit`
- **Auth:** API key from OTX account (free registration)
- **Formats accepted:** URL, domain, IP, file hash, CVE, CIDR
- **Rate limits:** 1,000 API requests/hour (free), higher for paid AT&T Cybersecurity customers
- **Submission:** Contribute via "Create Pulse" in the web UI or via the API
- **Key use:** Sharing phishing campaigns with 220,000+ community members; automated OTX enrichment

#### URLhaus (abuse.ch)
- **URL:** https://urlhaus.abuse.ch
- **Submission URL:** https://urlhaus.abuse.ch/api/#submit
- **API base:** `https://urlhaus-api.abuse.ch/v1/`
- **Auth:** No auth required for basic lookups; API key for submission
- **Rate limits:** No published limits; bulk submission supported
- **Submit URL lookup:** `POST https://urlhaus-api.abuse.ch/v1/url/` with `{"url": "https://phishing.example.com"}`
- **Bulk submission:** CSV format via the web interface
- **SLA for blacklist inclusion:** Typically hours after confirmed submission

#### PhishTank
- **URL:** https://www.phishtank.com
- **Submission:** https://www.phishtank.com/add_web_phish.php (requires free account)
- **API:** `https://checkurl.phishtank.com/checkurl/` (GET with `url` parameter, URL-encoded)
- **Rate limits:** Free API: 1,000 requests/day. `app_key` required (free from phishtank.com)
- **Database download:** Full database available at https://data.phishtank.com/data/online-valid.csv.bz2 (updated every hour)
- **Note:** PhishTank is community-verified; submitted URLs are validated by other users before appearing in the database

#### ThreatFox (abuse.ch)
- **URL:** https://threatfox.abuse.ch
- **API:** https://threatfox-api.abuse.ch/api/v1/
- **Submit IOC:** `POST https://threatfox-api.abuse.ch/api/v1/` with JSON body:
  ```json
  {"query": "submit_ioc", "threat_type": "phishing_url", "ioc_type": "url", "ioc": "https://phishing.example.com", "malware": "phishing", "confidence_level": 75, "reference": "https://your-report.com", "tags": ["phishing", "crypto"], "api_key": "YOUR_KEY"}
  ```
- **Formats:** URL, domain, IP:Port, MD5, SHA256
- **IOC types:** botnet_cc, payload_delivery, phishing_url, malware_sample

#### VirusTotal
- **API base:** `https://www.virustotal.com/api/v3/`
- **Auth:** `x-apikey` header with your API key
- **Submit URL:**
  ```
  POST https://www.virustotal.com/api/v3/urls
  Body: url=https://phishing.example.com (x-www-form-urlencoded)
  ```
- **Rate limits (free):** 4 lookups/minute, 500 lookups/day
- **Rate limits (premium):** Contact VirusTotal for Enterprise quotas
- **Get URL analysis:** `GET https://www.virustotal.com/api/v3/urls/{id64}`
- **Use for phishing:** Submit suspicious URLs; 90+ AV engines and URL scanners provide community-sourced verdict

#### Spamhaus DBL (Domain Block List)
- **Submission:** dbl.spamhaus.org — submit newly observed phishing domains
- **Abuse contact:** spam@spamhaus.org
- **Lookup API:** DNS-based lookup: `[domain].dbl.spamhaus.org` — if it resolves, domain is listed
- **SLA:** Varies; high-confidence submissions reviewed within 24-48 hours

#### CIRCL (Luxembourg)
- **URL:** https://www.circl.lu
- **MISP:** Free MISP instances hosted for European incident responders; request at info@circl.lu
- **Passive DNS / SSL:** https://www.circl.lu/services/passive-dns/ — free API for historical DNS resolution data

---

### 4.2 Platform-Specific Abuse Reporting

| Platform | Abuse URL/Email | Notes |
|---|---|---|
| Google Safe Browsing | https://safebrowsing.google.com/safebrowsing/report_phish/ | Also reports automatically via VT |
| Microsoft SmartScreen | https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site | Also: report via Microsoft Defender portal |
| Cloudflare | https://www.cloudflare.com/abuse/form | For Workers, Pages, and proxied sites |
| Namecheap | abuse@namecheap.com / https://www.namecheap.com/legal/general/abuse-policy.aspx | |
| GoDaddy | https://supportcenter.godaddy.com/AbuseReport | 24-48 hour SLA |
| Porkbun | https://porkbun.com/abuse | abuse@porkbun.com |
| Dynadot | https://www.dynadot.com/abuse | |
| Squarespace Domains | https://domains.squarespace.com/abuse | |
| ICANN UDRP | https://www.icann.org/resources/pages/dndr-2012-02-25-en | 45-60 day process; for brand domain disputes |
| ICANN Registrar Abuse | registrar-abuse@icann.org | Escalation for unresponsive registrars |
| WHOIS abuse lookup | https://lookup.icann.org/en/lookup | Find abuse contact for any domain |
| MX Toolbox abuse | https://mxtoolbox.com/problem/blacklist/ | Check if your IPs are listed |
| PhishTank submit | https://www.phishtank.com/add_web_phish.php | |
| OpenPhish | https://openphish.com/phishing_feeds.html | Submit via email to openphish.com |
| Netcraft report | https://report.netcraft.com/report | Netcraft takedown service |

---

### 4.3 Government & Law Enforcement Reporting

| Agency | URL | What to include |
|---|---|---|
| FBI IC3 (USA) | https://www.ic3.gov | Financial losses, victim info, attacker details, transaction hashes for crypto |
| CISA (USA) | https://www.cisa.gov/report | Critical infrastructure incidents; 24/7 line: 888-282-0870 |
| Secret Service ECTF (USA) | Local field office | For BEC and financial fraud exceeding $50,000 |
| Europol EC3 | https://www.europol.europa.eu/report-a-crime/report-cybercrime-online | Cross-border EU cybercrime |
| Action Fraud (UK) | https://www.actionfraud.police.uk/report-phishing | Reports generate NFIB reference numbers; data fed to NCSC |
| NCSC (UK) | https://www.ncsc.gov.uk/section/about-ncsc/report | Suspicious email: report@phishing.gov.uk |
| ACSC (Australia) | https://www.cyber.gov.au/report-and-recover/report | 24/7 hotline: 1300 CYBER1 |
| Interpol | https://www.interpol.int/en/Crimes/Cybercrime | Via national police referral |
| RCMP (Canada) | https://www.canada.ca/en/rcmp-grc/services/cybercrime.html | |

---

## Section 5: Top GitHub Repositories for Phishing Detection & Defence

### 5.1 Phishing Detection & Classification

| Repository | Stars | Last Active | Language | Description |
|---|---|---|---|---|
| **gophish/gophish** | ~13,000 | Active 2025 | Go | Open-source phishing simulation platform; REST API; multi-campaign management. Dual-use: red team and awareness training. |
| **x0rz/phishing_catcher** | ~1,800 | 2024 | Python | CertStream-based real-time phishing domain catcher; scores domains against keyword lists |
| **elceef/dnstwist** | ~5,200 | Active 2025 | Python | Domain fuzzing engine generating typosquat permutations; LSH for HTML similarity; pHash for visual comparison |
| **TheHive-Project/TheHive** | ~3,200 | Active 2025 | Scala | Scalable SIRT platform integrating MISP and Cortex for alert triage and incident response |
| **wesleyraptor/streamingphish** | ~300 | 2019 | Python | ML classifier training on CertStream data; Jupyter notebook for reproducibility |
| **Dreadnode/phishing-detection** | N/A | 2025 | Python | NLP-based phishing email classifier |

**ML model benchmarks (phishing URL detection, 2024-2025 papers):**
- XGBoost on URL lexical features: ~97% accuracy, <1ms inference
- BERT fine-tuned on email body: ~95% accuracy for BEC detection
- Random Forest on DOM features: ~96% accuracy
- Key datasets: PhishTank, OpenPhish, APWG eCrime dataset, URLhaus bulk feed

---

### 5.2 Phishing Infrastructure Analysis

| Repository | Stars | Last Active | Language | Description |
|---|---|---|---|---|
| **elceef/dnstwist** | ~5,200 | Active 2025 | Python | See above; primary tool for typosquat monitoring |
| **MISP/misp-warninglists** | ~300 | Active 2025 | JSON | Common false-positive lists for threat intelligence; includes top domains, IANA-reserved ranges |
| **StevenBlack/hosts** | ~27,000 | Active 2025 | Text | Consolidated hosts file blocking ads, malware, phishing domains; 60,000+ entries |
| **URLhaus/urlhaus** | N/A | Active | Various | abuse.ch's malicious URL database; see Section 4.1 for API |
| **mandiant/capa** | ~5,000 | Active 2025 | Python | Malware capability detection; useful for analysing phishing kit server-side components |
| **certstream-community/certstream-server** | ~800 | Active | Go | Drop-in replacement for the Calidog CertStream server; self-hosted CT log streaming |
| **NullArray/AutoSploit** | N/A | Legacy | Python | Automated Shodan + Metasploit (historical reference) |

**Certificate Transparency Monitoring:**
- **crt.sh:** `https://crt.sh/?q=%25yourdomainname%25&output=json` — JSON API, no auth required. Query for wildcard patterns.
- **Facebook CT API:** `https://developers.facebook.com/tools/ct/` — monitors CT logs with webhook support
- **Google CT:** `https://ct.googleapis.com/` — programmatic access to Google's CT logs

---

### 5.3 Email Security & DMARC

| Repository | Stars | Last Active | Language | Description |
|---|---|---|---|---|
| **domainaware/parsedmarc** | ~2,300 | Active 2025 | Python | DMARC aggregate report parser; Elasticsearch/Kibana integration for dashboards |
| **internetstandards/toolbox** | ~200 | Active | Python | Email authentication checking (SPF, DKIM, DMARC, MTA-STS); used by internet.nl |
| **PowerDMARC/powerdmarc** | N/A | SaaS | — | Managed DMARC reporting and enforcement platform |
| **flanker** | ~1,800 | Semi-active | Python | Email address and MIME parsing library (Mailgun open-source) |
| **python-email-validator** | ~900 | Active 2025 | Python | RFC-compliant email address validation |

**Key DMARC/email auth tools:**
- MXToolbox: https://mxtoolbox.com/dmarc.aspx — free DMARC record tester
- DMARC Analyzer: https://www.dmarcanalyzer.com — DMARC report visualisation
- mail-tester.com — deliverability and authentication testing

---

### 5.4 Threat Intelligence Platforms

| Repository | Stars | Last Active | Language | Description |
|---|---|---|---|---|
| **MISP/MISP** | ~6,000 | Active 2025 | PHP/Python | Full threat intelligence platform; REST API; STIX 2.1 support; 100+ modules |
| **OpenCTI-Platform/opencti** | ~6,000 | Active 2025 | Python/JS | STIX 2.1-native TIP; relationship graph; dark web connector; 100+ integrations |
| **TheHive-Project/Cortex** | ~1,200 | Active 2025 | Scala | Analyser/responder engine for TheHive; runs VirusTotal, Shodan, MISP lookups automatically |
| **Neo23x0/sigma** | ~8,000 | Active 2025 | YAML | Generic signature format for SIEM rules; 2,000+ phishing/threat hunting rules included |
| **InQuest/iocextract** | ~500 | Active | Python | IOC extraction from unstructured text/emails; supports regex extraction of URLs, IPs, hashes |
| **fhightower/ioc-finder** | ~600 | Active | Python | Comprehensive IOC extraction library with canonical form normalisation |

---

### 5.5 Crypto-Specific Security Tools

| Repository | Stars | Last Active | Language | Description |
|---|---|---|---|---|
| **MetaMask/eth-phishing-detect** | ~1,000 | Active 2025 | JavaScript | Maintained blocklist of phishing domains targeting Ethereum users; used in MetaMask browser extension |
| **ScamSniffer/phishing-database** | ~400 | Active 2025 | JSON | Scam Sniffer's database of phishing domains and wallet drainer addresses |
| **crytic/slither** | ~5,000 | Active 2025 | Python | Solidity static analyser; detects dangerous approval patterns, reentrancy, and other smart contract vulnerabilities |
| **ConsenSys/mythril** | ~3,300 | Active 2025 | Python | Smart contract security analysis; symbolic execution; detects unchecked approvals |
| **Chainabuse/reports** | N/A | Active | — | Community reporting of abusive blockchain addresses; API at https://www.chainabuse.com/api |
| **trailofbits/manticore** | ~3,700 | Active 2025 | Python | Dynamic binary and smart contract analysis; detects malicious transaction patterns |
| **ApeWorX/ape** | ~900 | Active 2025 | Python | Web3 development framework with security testing integration |
| **DeFi-Pulse/defipulse-data** | N/A | Legacy | — | Historical reference for protocol tracking |

**On-chain phishing address monitoring services:**
- **Chainabuse:** https://www.chainabuse.com — community reports; API available
- **Etherscan Token Approval Checker:** https://etherscan.io/tokenapprovalchecker — review and revoke ERC-20 approvals
- **Revoke.cash:** https://revoke.cash — revoke token approvals across 60+ chains
- **De.Fi Shield:** https://de.fi/shield — approval monitoring and automatic revocation service
- **Pocket Universe:** Browser extension for transaction simulation before signing

---

## Section 6: Gaps in Current Tooling & Opportunities

### 6.1 Unmet Detection Needs

**Gap 1: QR codes in PDF attachments.**  
Most SEGs (Secure Email Gateways) can decode QR codes embedded directly in email bodies but cannot reliably extract and decode QR codes embedded within PDF attachments. This is confirmed by Sophos (their Q1 2025 Phase 2 rollout addressed this) but remains unaddressed by many mid-market solutions. Opportunity: A lightweight PDF-to-image renderer + `pyzbar` pipeline that outputs decoded URLs for reputation lookup — this is buildable in a weekend and would close a significant gap for SMB/startup security teams.

**Gap 2: Trusted Platform Abuse detection.**  
No major SEG vendor has published a robust solution for detecting phishing delivered via legitimate SaaS platforms. The domain reputation of `calendly.com`, `notion.so`, and `forms.google.com` is universally trusted. Detection requires: (a) content analysis of the landing page behind the link, (b) redirect chain analysis revealing the final destination, and (c) behavioural signals (first-ever contact sending a Calendly link claiming to be a recruiter). This requires automated URL detonation with JavaScript rendering — expensive at scale.

**Gap 3: AI-generated content detection in email.**  
No production email security product reliably distinguishes AI-generated phishing from human-written phishing at the accuracy level required for security enforcement. Current AI text detectors have false positive rates that make them unsuitable for quarantine decisions. The gap is well-understood; the solution requires training on large corpora of confirmed AI-assisted phishing campaigns — data that is not publicly available.

**Gap 4: Helpdesk platform display-name abuse.**  
Most email security solutions block domain-level spoofing but do not detect the pattern where `From: "PayPal Security" <security@paypal.zendesk.com>` has a passing DKIM signature from Zendesk. Rules that pattern-match protected brand names against known helpdesk platform sending domains are not standard in most SEG configurations. This is a configuration gap addressable today.

**Gap 5: Real-time phishing page lifespan vs. blocklist latency.**  
With median phishing page lifespan under 24 hours and some crypto-targeting pages live for 2-6 hours, blocklist-based detection (which carries 12-48 hour latency) fails to protect most victims. Opportunity: Certificate Transparency monitoring with real-time scoring + automated submission to URLhaus and PhishTank when a new domain passes a phishing-likelihood threshold.

---

### 6.2 Crypto/Web3 Specific Gaps

**Gap 1: No automated Permit2 and EIP-7702 signature analysis in consumer wallets.**  
Permit2 batch approvals and EIP-7702 delegation signatures are largely opaque to most consumer wallets. MetaMask shows a human-readable warning for `setApprovalForAll` but displays raw hex for many Permit2 and EIP-7702 payloads. Tools like Pocket Universe and Fire Extension partially address this via transaction simulation, but they are browser extensions not integrated into mobile wallets. A well-resourced team could build this into the Ethereum mobile wallet stack via a signing middleware layer.

**Gap 2: Multilingual phishing targeting non-English crypto communities.**  
The majority of phishing detection training data is English-language. Korean, Chinese, Vietnamese, Turkish, and Russian-language crypto phishing — targeting retail investors in high-adoption markets — receives minimal coverage from existing tools. URL-based and domain-based signals are language-agnostic, but social engineering content analysis tools fail for non-English targets.

**Gap 3: Real-time on-chain approval monitoring for retail users.**  
Revoke.cash and De.Fi Shield offer approval revocation but not real-time alerting. A user who signs a malicious `approve()` call will not be notified until they proactively check. An on-chain monitoring service that watches wallet addresses for new ERC-20 approvals (especially to recently-deployed or unverified contracts) and sends push notifications is a significant UX gap for retail users.

**Gap 4: Fake browser extension detection.**  
Google Chrome Web Store consistently hosts malicious MetaMask and Phantom clones for days to weeks before removal. No browser-level system proactively validates that an installed crypto extension matches the canonical version. Opportunity: A browser extension that validates the integrity of other installed crypto extensions (via manifest hash comparison against known-good versions) would close this gap.

---

### 6.3 Automation Opportunities

**Opportunity 1: Certificate Transparency → URLhaus pipeline.**  
CertStream provides a firehose of newly issued TLS certificates. Score each new domain against a phishing keyword list + ML model + typosquat check against protected brands. Auto-submit confirmed phishing domains to URLhaus, PhishTank, and ThreatFox. This pipeline is partially implemented by x0rz/phishing_catcher but needs enterprise reliability hardening and a submission integration layer.

**Opportunity 2: Helpdesk platform abuse reporting bot.**  
A service that monitors for emails `via freshdesk.com`, `via zendesk.com`, etc. where the display name matches a protected brand list, and automatically files abuse reports with the relevant platform. The abuse APIs for major platforms are underutilised.

**Opportunity 3: Phishing response playbook automation.**  
Standard phishing incident response (header extraction → IOC parsing → VirusTotal/URLhaus submission → blocklist update → email recall → user notification) is still largely manual at most organisations. SOAR platforms (Palo Alto XSOAR, Splunk SOAR) have phishing playbooks, but these require expensive enterprise deployment. A lightweight open-source alternative built on n8n or Shuffle would serve the SMB/startup market.

**Opportunity 4: Discord server phishing monitoring.**  
Discord is the primary delivery vector for crypto phishing in 2025. No open-source tool continuously monitors Discord servers for phishing links, fake bot impersonation, or sudden announcements from recently compromised admin accounts. The Discord API supports webhook monitoring and message event subscriptions.

**Opportunity 5: IOC enrichment pipeline for crypto addresses.**  
A unified enrichment pipeline that, given a suspicious wallet address, automatically queries: Chainabuse, Etherscan labels, OFAC sanctions lists, MistTrack, TRM Labs API (if available), and ZachXBT's on-chain analysis database. This is partially implemented by OSINT tools but no unified open-source pipeline exists.

**Open datasets for classifier training:**
- PhishTank historical database (free bulk download)
- URLhaus current dataset (TSV download)
- APWG eCrime dataset (academic access via eCrime symposium)
- OpenPhish feed (free tier)
- Kaggle: "Phishing URL Dataset" (50,000+ samples)
- Mendeley: Ebbu2017 Phishing Dataset (111 features, 88,000 instances)
- GitHub: PhishIntention, PhishDet, URLNet reference implementations

---

## Section 7: Libraries, APIs & Practices for Building Phishing Defence Tools

### 7.1 Python Libraries

**Email Parsing & Header Analysis:**
```
email          (stdlib)      RFC 2822 parsing, header extraction
mailparser     pip           High-level email parsing with attachments
flanker        pip           Mailgun's email address/MIME parser (RFC-strict)
eml_parser     pip           EML file parser with IOC extraction
```

**URL Extraction & Analysis:**
```
urlextract     pip           Extracts URLs from arbitrary text
tldextract     pip           Splits URL into subdomain/domain/suffix
urllib.parse   (stdlib)      URL parsing, normalization
validators     pip           URL, email, IP validation
```

**DNS & WHOIS:**
```
dnspython      pip           DNS queries (A, MX, TXT, DKIM lookup)
python-whois   pip           WHOIS lookup with parsed output
ipwhois        pip           IP WHOIS and ASN lookup
rdap           pip           RDAP protocol for registrar data
```

**ML & Classification:**
```
scikit-learn   pip           XGBoost, Random Forest, SVM for URL classification
transformers   pip           BERT fine-tuning for email body classification
xgboost        pip           Gradient boosting; best single model for URL features
spacy          pip           NLP feature extraction from email body
sentence-transformers pip   Semantic similarity for phishing template matching
```

**Async & High-Throughput:**
```
aiohttp        pip           Async HTTP for bulk URL detonation
asyncio        (stdlib)      Async event loop
httpx          pip           Async HTTP with connection pooling
aiolimiter     pip           Rate limiting for API calls
redis          pip           Caching for API response deduplication
```

**QR Code Handling:**
```
pyzbar         pip           QR code decoding from images
pillow (PIL)   pip           Image extraction from PDFs for QR detection
pdf2image      pip           PDF to image conversion for QR scanning
qrcode         pip           QR code generation (for test/simulation)
```

---

### 7.2 JavaScript/Node.js Libraries

**URL Analysis:**
```
url-parse      npm           URL component extraction
tldts          npm           TLD extraction (maintains Public Suffix List)
psl            npm           Public Suffix List lookup
is-url         npm           Simple URL validation
```

**Browser Extension Security:**
```
webextension-polyfill  npm  Browser-compatible WebExtension API wrapper
plasmo                 npm  Chrome/Firefox extension framework with React
crx3                   npm  Extension packaging utilities
```

**Safe Link Preview:**
```
linkpreview    npm           Generate safe previews without loading dangerous pages
metascraper    npm           Structured metadata extraction from URLs
jsdom          npm           DOM simulation for URL analysis without browser
```

**Web3 / Blockchain:**
```
ethers.js      npm    ~8,500 stars  Full Ethereum library; decode signatures, simulate transactions
viem           npm    ~4,000 stars  TypeScript-first, tree-shakeable Ethereum library
web3.js        npm    ~5,000 stars  Legacy Ethereum library
@metamask/eth-phishing-detect  npm  Phishing domain detection library from MetaMask
```

---

### 7.3 Key APIs

#### VirusTotal API v3
- **Base:** `https://www.virustotal.com/api/v3/`
- **Auth:** `x-apikey: YOUR_KEY` header
- **Submit URL:** `POST /urls` — form body: `url=https://...`
- **Get report:** `GET /urls/{id64}` where id64 = base64(url, urlsafe, no padding)
- **Rate limits (free):** 4 req/min, 500 req/day
- **Rate limits (enterprise):** 1,000+ req/min, contact Virustotal
- **Cost:** Free public key; Enterprise pricing on request
- **Key endpoints:** `/files/{hash}`, `/domains/{domain}`, `/ip_addresses/{ip}`

#### Google Safe Browsing Lookup API v4
- **Base:** `https://safebrowsing.googleapis.com/v4/`
- **Auth:** `?key=YOUR_API_KEY` (Google Cloud API key)
- **Lookup:** `POST /threatMatches:find`
- **Body:**
  ```json
  {"client": {"clientId": "yourapp", "clientVersion": "1.0"},
   "threatInfo": {"threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
     "platformTypes": ["ANY_PLATFORM"],
     "threatEntryTypes": ["URL"],
     "threatEntries": [{"url": "https://..."}]}}
  ```
- **Rate limits:** 10,000 lookups/day (free), higher for paid
- **Cost:** Free for safety checking; paid for bulk use

#### URLhaus API
- **Base:** `https://urlhaus-api.abuse.ch/v1/`
- **Auth:** None required for lookups; `Auth-Key` header for submissions
- **URL lookup:** `POST /url/` with `{"url": "https://..."}`
- **Bulk download:** `https://urlhaus.abuse.ch/downloads/csv_recent/`
- **Rate limits:** No published limits; respect fair use
- **Cost:** Free

#### PhishTank API
- **Base:** `https://checkurl.phishtank.com/checkurl/`
- **Auth:** `app_key` parameter (free registration)
- **Lookup:** `POST` with `url=https://...&app_key=YOUR_KEY&format=json`
- **Rate limits:** 1,000 requests/day (free)
- **Cost:** Free

#### ThreatFox API (abuse.ch)
- **Base:** `https://threatfox-api.abuse.ch/api/v1/`
- **Auth:** `api_key` in JSON body
- **IOC search:** `POST` with `{"query": "search_ioc", "search_term": "domain.com", "api_key": "..."}`
- **Rate limits:** Fair use; no published limits
- **Cost:** Free

#### Shodan API
- **Base:** `https://api.shodan.io/`
- **Auth:** `?key=YOUR_KEY` query parameter
- **Host lookup:** `GET /shodan/host/{ip}?key=...`
- **Search:** `GET /shodan/host/search?query=phishing&key=...`
- **Rate limits (free):** 1 req/sec; no bulk search
- **Cost:** Free (limited); Freelancer $49/mo; Corporate $899/mo
- **InternetDB:** `https://internetdb.shodan.io/{ip}` — free, no auth, basic port/vuln data

#### WHOIS/RDAP APIs
- **IANA RDAP:** `https://rdap.iana.org/domain/{domain}` — no auth, free
- **WHOISXML API:** `https://www.whoisxmlapi.com/` — 500 free lookups/month; $0.001/lookup
- **ipinfo.io:** `https://ipinfo.io/{ip}/json` — 50,000 lookups/month free
- **AbuseIPDB:** `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}` — 1,000 checks/day free; `Key` header auth

#### Certificate Transparency APIs
- **crt.sh JSON API:** `https://crt.sh/?q=%25.{domain}&output=json` — free, no auth
- **Facebook CTE:** `https://developers.facebook.com/tools/ct/search/?q={domain}` — Meta for Developers account required
- **CertStream:** WebSocket `wss://certstream.calidog.io/` — live CT log feed, no auth

#### Cloudflare Radar URL Scanner
- **Base:** `https://api.cloudflare.com/client/v4/radar/url_scanner/`
- **Auth:** Bearer token (Cloudflare API token)
- **Submit scan:** `POST /scans` with `{"url": "https://...", "visibility": "Public"}`
- **Get result:** `GET /scans/{uuid}` 
- **Rate limits:** 1,000 scans/month (free tier)
- **Cost:** Free (with Cloudflare account)

---

### 7.4 Best Practices for Phishing Defence Tool Development

**1. Safe URL Analysis Sandboxing (avoiding IP leakage):**
When your tool fetches or detonates a phishing URL, the HTTP request reveals your IP to the phishing actor — potentially triggering bot detection or IP-targeted content cloaking. Use:
- Residential proxy rotation services (Oxylabs, Bright Data) for URL detonation
- Browserless / Playwright in a disposable Docker container with no DNS leakage
- Submit URLs to Cloudflare Radar or VirusTotal for remote scanning (your IP never touches the phishing page)
- Tor for low-volume detonation (exit node IP pool is publicly known to actors)
- Set `User-Agent` to match a common browser; fake `Accept-Language` and other fingerprinting headers

**2. Rate Limiting & Caching for API-Heavy Pipelines:**
```python
# Redis-based deduplication
import redis
import hashlib

r = redis.Redis()
url_hash = hashlib.sha256(url.encode()).hexdigest()

if r.exists(f"checked:{url_hash}"):
    return r.get(f"checked:{url_hash}")  # return cached verdict

# Call VT, GSB, URLhaus, cache result
verdict = check_url_apis(url)
r.setex(f"checked:{url_hash}", 86400, verdict)  # cache 24h
```
- Use `aiolimiter` or `asyncio.Semaphore` to respect per-minute rate limits
- Implement exponential backoff on 429/503 responses
- Cache negative verdicts shorter (1-4 hours) than positive verdicts (24+ hours)

**3. STIX 2.1 Format for IOC Interoperability:**
```python
from stix2 import Indicator, Bundle, ExternalReference

indicator = Indicator(
    name="Phishing URL targeting crypto users",
    description="Drainer site impersonating MetaMask support",
    pattern="[url:value = 'https://metamask-support-recovery[.]com/']",
    pattern_type="stix",
    valid_from="2026-02-27T00:00:00Z",
    labels=["phishing", "cryptocurrency"],
    external_references=[
        ExternalReference(source_name="URLhaus", url="https://urlhaus.abuse.ch/url/1234567/")
    ]
)
bundle = Bundle(indicator)
print(bundle.serialize(pretty=True))
```
Use MISP's pyMISP library to push STIX objects directly to a MISP instance:
```python
from pymisp import PyMISP, MISPEvent
misp = PyMISP("https://your-misp.example.com", "API_KEY")
```

**4. Privacy Considerations for URL Logging:**
- URLs submitted by users may contain sensitive path parameters (session tokens, document IDs)
- Normalise URLs before storage: strip query strings beyond `?url=`, strip UTM parameters
- Do not log the full URL if it contains identifiable user information
- Consider hashing URLs before storing (enables dedup without storing plaintext)
- Apply retention limits: auto-delete URL logs after 30-90 days
- If offering a public URL-checking service, add a Privacy Policy explicitly describing data handling
- Never share raw submitted URLs with third parties without user consent — only share verdicts or redacted IOC forms

---

## Top 10 Actionable Recommendations (Ordered by Impact)

**1. Deploy phishing-resistant MFA universally.**  
FIDO2/WebAuthn (YubiKey, device passkeys) is the only control that prevents AiTM attacks. No other MFA form — TOTP, SMS, push notification — survives a properly implemented reverse proxy. Prioritise this for privileged accounts, finance teams, and any team with crypto custody responsibility. Estimated cost: $25-60 per physical key per user. ROI: eliminates the most dangerous phishing vector entirely.

**2. Implement real-time Certificate Transparency monitoring for your domains.**  
Run x0rz/phishing_catcher or a hardened equivalent against your brand name(s) and protected keywords. Alert within minutes of a new phishing domain appearing in CT logs. The average phishing page is live for less than 24 hours; a 12+ hour blocklist lag means CT monitoring is the only way to catch campaigns before peak victim exposure. Pair with automated URLhaus and PhishTank submission.

**3. Enforce DMARC at `p=reject` across all your domains including non-sending domains.**  
Set `p=reject` on all domains you own, including parked and legacy domains. Set `p=reject` on the root and all subdomains. Use `parsedmarc` to monitor DMARC aggregate reports and detect legitimate sending sources before enforcement. Estimated time to deploy: 2-4 weeks for a thorough rollout.

**4. Add display-name protection rules for helpdesk platform abuse.**  
Configure your email security gateway to flag or quarantine emails where the display name contains your organisation's name (or your brand partners' names) but the `From` domain is a helpdesk/CRM platform (`zendesk.com`, `freshdesk.com`, `zohodesk.com`, `intercom.io`, `hubspotemail.net`). This closes the "helpdesk impersonation" vector with near-zero false positive risk.

**5. Conduct a token approval audit for all organisational crypto wallets.**  
Use Revoke.cash or Etherscan's token approval checker to review and revoke unnecessary ERC-20 approvals, especially to unverified contracts. Establish a policy: approvals are set to exact-amount rather than `type(uint256).max` where possible. Deploy Pocket Universe or Fire Extension on browsers used for Web3 interactions.

**6. Implement QR code detection in your email security pipeline.**  
If your SEG does not scan QR codes in PDF attachments, add a preprocessing layer: extract PDF pages as images → decode QR codes via pyzbar → submit decoded URLs to your URL reputation pipeline. This is a weekend-scale engineering project that closes a significant detection gap.

**7. Register and maintain abuse contacts with all major SaaS platforms.**  
Proactively contact SendGrid, Mailchimp, Freshdesk, Zendesk, and Mailgun to register your brand names as protected. Establish direct abuse contact relationships (not just web form submissions) so that when platform abuse is detected, takedown can happen in hours rather than days.

**8. Train staff specifically on trusted platform abuse and AiTM phishing.**  
Standard phishing training teaches users to "check the domain." This is insufficient for TPA — the domain is legitimate. Train on: (a) any unsolicited login prompt is suspicious regardless of domain, (b) Calendly/Typeform/Google Form links from unknown senders should be verified out-of-band, (c) if a QR code arrives via email claiming to be from your own company, call the sender directly.

**9. Establish a MISP or OpenCTI instance and join a relevant ISAC.**  
FS-ISAC (financial/crypto), MS-ISAC (state/local government), or sector-specific ISACs provide real-time threat intelligence your security tools cannot generate alone. Even a free CIRCL-hosted MISP instance dramatically improves your IOC coverage. Time to join: 1-2 weeks for most ISACs.

**10. Implement on-chain phishing address monitoring for crypto operations.**  
Subscribe to Chainabuse API, MetaMask's `eth-phishing-detect` blocklist, and Scam Sniffer's feed. Integrate these into your transaction monitoring pipeline (if you handle user funds) or distribute them to user-facing wallet interfaces. The on-chain address blocklist ecosystem is immature relative to URL blacklisting — contribution to these databases is high-value community work.

---

## Consolidated Resource Directory

### Threat Intelligence & Reporting
| Resource | URL |
|---|---|
| URLhaus | https://urlhaus.abuse.ch |
| URLhaus API | https://urlhaus-api.abuse.ch/v1/ |
| ThreatFox | https://threatfox.abuse.ch |
| PhishTank | https://www.phishtank.com |
| OpenPhish | https://openphish.com |
| AlienVault OTX | https://otx.alienvault.com |
| VirusTotal | https://www.virustotal.com |
| VirusTotal API docs | https://docs.virustotal.com/reference/overview |
| MISP Project | https://www.misp-project.org |
| OpenCTI | https://www.opencti.io |
| CIRCL MISP | https://www.circl.lu/services/misp-malware-information-sharing-platform/ |
| Spamhaus DBL | https://www.spamhaus.org/dbl/ |
| Chainabuse | https://www.chainabuse.com |
| Scam Sniffer | https://drops.scamsniffer.io |

### Abuse Reporting — Platforms
| Platform | URL |
|---|---|
| Google Safe Browsing Report | https://safebrowsing.google.com/safebrowsing/report_phish/ |
| Microsoft SmartScreen | https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site |
| Cloudflare Abuse | https://www.cloudflare.com/abuse/form |
| Namecheap Abuse | https://www.namecheap.com/legal/general/abuse-policy.aspx |
| GoDaddy Abuse | https://supportcenter.godaddy.com/AbuseReport |
| ICANN Lookup (WHOIS/abuse) | https://lookup.icann.org |
| ICANN UDRP | https://www.icann.org/resources/pages/dndr-2012-02-25-en |
| Netcraft Takedown | https://report.netcraft.com/report |

### Government Reporting
| Agency | URL |
|---|---|
| FBI IC3 | https://www.ic3.gov |
| CISA | https://www.cisa.gov/report |
| Action Fraud (UK) | https://www.actionfraud.police.uk |
| NCSC UK Phishing | report@phishing.gov.uk |
| ACSC (Australia) | https://www.cyber.gov.au/report-and-recover/report |
| Europol | https://www.europol.europa.eu/report-a-crime/report-cybercrime-online |

### Key GitHub Repositories
| Tool | URL |
|---|---|
| dnstwist | https://github.com/elceef/dnstwist |
| GoPhish | https://github.com/gophish/gophish |
| MISP | https://github.com/MISP/MISP |
| OpenCTI | https://github.com/OpenCTI-Platform/opencti |
| TheHive | https://github.com/TheHive-Project/TheHive |
| Sigma Rules | https://github.com/Neo23x0/sigma |
| parsedmarc | https://github.com/domainaware/parsedmarc |
| MetaMask eth-phishing-detect | https://github.com/MetaMask/eth-phishing-detect |
| Slither (Solidity analyzer) | https://github.com/crytic/slither |
| StevenBlack hosts | https://github.com/StevenBlack/hosts |
| certstream-server | https://github.com/certstream-community/certstream-server |
| phishing_catcher | https://github.com/x0rz/phishing_catcher |

### Crypto Security Tools
| Tool | URL |
|---|---|
| Revoke.cash | https://revoke.cash |
| Etherscan Token Approvals | https://etherscan.io/tokenapprovalchecker |
| De.Fi Shield | https://de.fi/shield |
| crt.sh CT search | https://crt.sh |
| Cloudflare Radar URL Scanner | https://radar.cloudflare.com/scan |

---

## Conflicting Information & Data Caveats

1. **Crypto phishing loss statistics conflict significantly.** Scam Sniffer (most credible, on-chain methodology) shows 2025 wallet drainer losses of $83.85 million. SQ Magazine and CoinLaw cite "$1.93 billion in H1 2025" — this appears to include all crypto theft vectors (hacks, rug pulls, CEX exploits) and should not be compared directly to Scam Sniffer's wallet-drainer-only figures. The Bybit $1.5B alone would dominate any aggregate figure.

2. **AI phishing volume statistics vary widely.** "1,265% increase" (SentinelOne), "4,151% increase" (separate vendor report), and "466% increase in a single quarter" (early 2025 report) cannot all be measuring the same thing. These should be treated as directional indicators of a significant volume increase, not precise measurements.

3. **"WormGPT" attribution is murky.** The original WormGPT shut down in August 2023. Most 2024-2025 "WormGPT variants" documented by Cato CTRL are rebranded open-source models with jailbreak prompts. Attribution to a continuous criminal organisation is not warranted by the evidence.

4. **PhaaS attribution varies by vendor.** Tycoon 2FA's "64,000 incidents" figure comes from ANY.RUN sandbox data — this represents submissions to that platform, not total incidents. The true incident count is likely significantly higher.

5. **Quishing statistics from different sources use inconsistent denominators.** "26% of malicious links embedded in QR codes" (KeepNet) and "QR codes appear in 50% of phishing emails" (same source, different timeframe) are not contradictory but reflect different measurement periods and methodologies.

---

*Report compiled February 2026. Data freshness: primary sources from 2025-2026. Recommend quarterly refresh for Section 2 (threat actor TTPs evolve rapidly) and Section 4.2 (abuse URLs change). OSINT methodology: public web search, primary source fetching, no dark web access.*

*TLP:WHITE — This report may be freely shared.*
