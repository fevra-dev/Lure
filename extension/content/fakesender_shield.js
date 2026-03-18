/**
 * extension/content/fakesender_shield.js
 *
 * FakeSender Shield — Helpdesk Platform Brand Impersonation Detection
 *
 * Detects landing pages on helpdesk platform subdomains (Zendesk, Freshdesk,
 * Zoho Desk, etc.) that impersonate known brands. Attackers create free-tier
 * helpdesk accounts with brand display names; emails pass SPF/DKIM/DMARC
 * because they originate from legitimate helpdesk infrastructure.
 *
 * Signal architecture:
 *   fakesender:helpdesk_brand_subdomain_mismatch  +0.40
 *   fakesender:external_phishing_link             +0.30
 *   fakesender:credential_on_helpdesk             +0.25
 *   fakesender:brand_impersonation_text           +0.25
 *   fakesender:free_tier_indicator                +0.20
 *   fakesender:urgent_action_language             +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module FakeSenderShield
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Helpdesk Platform Database                                         */
/* ------------------------------------------------------------------ */

const HELPDESK_PLATFORMS = {
  zendesk:   { suffix: '.zendesk.com', name: 'Zendesk' },
  freshdesk: { suffix: '.freshdesk.com', name: 'Freshdesk' },
  zoho:      { suffix: '.zohodesk.com', name: 'Zoho Desk' },
  hubspot:   { suffix: '.hubspot.com', name: 'HubSpot' },
  intercom:  { suffix: '.intercom.io', name: 'Intercom' },
  jira:      { suffix: '.atlassian.net', name: 'Jira Service Desk' },
  helpscout: { suffix: '.helpscoutdocs.com', name: 'Help Scout' },
  kayako:    { suffix: '.kayako.com', name: 'Kayako' },
};

/* ------------------------------------------------------------------ */
/*  Known Brand Database (subset — duplicated for MV3 content script   */
/*  isolation; each content script is a separate execution context)    */
/* ------------------------------------------------------------------ */

const KNOWN_BRANDS = {
  microsoft: {
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com'],
    keywords: ['microsoft', 'outlook', 'office 365', 'office365', 'onedrive', 'teams', 'azure'],
  },
  google: {
    domains: ['google.com', 'gmail.com', 'accounts.google.com', 'youtube.com'],
    keywords: ['google', 'gmail', 'google workspace'],
  },
  apple: {
    domains: ['apple.com', 'icloud.com', 'appleid.apple.com'],
    keywords: ['apple', 'icloud', 'apple id', 'itunes'],
  },
  paypal: {
    domains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal'],
  },
  amazon: {
    domains: ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'],
    keywords: ['amazon', 'aws', 'amazon prime'],
  },
  facebook: {
    domains: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com'],
    keywords: ['facebook', 'meta', 'instagram'],
  },
  github: {
    domains: ['github.com', 'github.io'],
    keywords: ['github'],
  },
  linkedin: {
    domains: ['linkedin.com'],
    keywords: ['linkedin'],
  },
  dropbox: {
    domains: ['dropbox.com'],
    keywords: ['dropbox'],
  },
  salesforce: {
    domains: ['salesforce.com', 'force.com'],
    keywords: ['salesforce'],
  },
  adobe: {
    domains: ['adobe.com'],
    keywords: ['adobe', 'creative cloud'],
  },
  netflix: {
    domains: ['netflix.com'],
    keywords: ['netflix'],
  },
  slack: {
    domains: ['slack.com'],
    keywords: ['slack'],
  },
  zoom: {
    domains: ['zoom.us', 'zoom.com'],
    keywords: ['zoom'],
  },
  okta: {
    domains: ['okta.com'],
    keywords: ['okta'],
  },
  coinbase: {
    domains: ['coinbase.com'],
    keywords: ['coinbase'],
  },
  docusign: {
    domains: ['docusign.com', 'docusign.net'],
    keywords: ['docusign'],
  },
  stripe: {
    domains: ['stripe.com'],
    keywords: ['stripe'],
  },
};

/* ------------------------------------------------------------------ */
/*  Urgency Phrases                                                    */
/* ------------------------------------------------------------------ */

const URGENCY_PHRASES = [
  'account suspended',
  'account has been suspended',
  'verify immediately',
  'verify your account immediately',
  'unauthorized access',
  'unauthorized activity',
  'action required within',
  'action required',
  'immediate action required',
  'your account will be closed',
  'your account will be locked',
  'verify your identity',
  'confirm your identity',
  'suspicious activity detected',
  'update your payment',
  'payment failed',
  'billing issue',
];

/* ------------------------------------------------------------------ */
/*  Free Tier Indicators                                               */
/* ------------------------------------------------------------------ */

const FREE_TIER_INDICATORS = [
  'powered by zendesk',
  'powered by freshdesk',
  'powered by zoho',
  'powered by hubspot',
  'powered by intercom',
  'powered by help scout',
  'powered by kayako',
  'free plan',
  'trial account',
  'demo account',
];

/* ------------------------------------------------------------------ */
/*  Utility Functions                                                   */
/* ------------------------------------------------------------------ */

/**
 * Check if a hostname belongs to a known helpdesk platform.
 * @param {string} hostname
 * @returns {{ platformKey: string, platform: Object, subdomain: string } | null}
 */
export function isHelpdeskPlatform(hostname) {
  if (!hostname) return null;

  for (const [key, platform] of Object.entries(HELPDESK_PLATFORMS)) {
    if (hostname.endsWith(platform.suffix)) {
      const subdomain = hostname.replace(platform.suffix, '');
      return { platformKey: key, platform, subdomain };
    }
  }

  return null;
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Detect helpdesk subdomain containing a known brand name that doesn't
 * belong to the brand (e.g., coinbase-help.zendesk.com).
 */
export function checkHelpdeskBrandSubdomainMismatch(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const hdInfo = isHelpdeskPlatform(hostname);
  if (!hdInfo) return [];

  const signals = [];
  const subdomain = hdInfo.subdomain.toLowerCase();
  const title = (doc.title || '').toLowerCase();
  const combinedText = subdomain + ' ' + title;

  for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
    // Check if subdomain or title contains brand keywords
    const matchesSubdomain = brand.keywords.some(kw => subdomain.includes(kw));
    const matchesTitle = brand.keywords.some(kw => title.includes(kw));

    if (matchesSubdomain || matchesTitle) {
      signals.push({
        id: 'fakesender:helpdesk_brand_subdomain_mismatch',
        weight: 0.40,
        matchedBrand: brandName,
        platform: hdInfo.platform.name,
      });
      break; // One brand match is enough
    }
  }

  return signals;
}

/**
 * Detect credential input fields on a helpdesk page (unusual for support pages).
 */
export function checkCredentialOnHelpdesk(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const hdInfo = isHelpdeskPlatform(hostname);
  if (!hdInfo) return [];

  const signals = [];
  const passwordFields = doc.querySelectorAll('input[type="password"]');
  const autocompleteFields = doc.querySelectorAll(
    'input[autocomplete="current-password"], input[autocomplete="new-password"]'
  );

  if (passwordFields.length > 0 || autocompleteFields.length > 0) {
    signals.push({
      id: 'fakesender:credential_on_helpdesk',
      weight: 0.25,
    });
  }

  return signals;
}

/**
 * Detect links to external domains that are NOT the claimed brand's legitimate domains.
 */
export function checkExternalPhishingLinks(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const hdInfo = isHelpdeskPlatform(hostname);
  if (!hdInfo) return [];

  const signals = [];
  const links = doc.querySelectorAll('a[href]');

  // Find which brand is being impersonated (from subdomain or title)
  let impersonatedBrand = null;
  const subdomain = hdInfo.subdomain.toLowerCase();
  const title = (doc.title || '').toLowerCase();

  for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
    if (brand.keywords.some(kw => subdomain.includes(kw) || title.includes(kw))) {
      impersonatedBrand = brand;
      break;
    }
  }

  if (!impersonatedBrand) return [];

  let suspiciousLinkCount = 0;

  for (const link of links) {
    const href = link.getAttribute('href') || '';
    if (!href || href.startsWith('#') || href.startsWith('/') || href.startsWith('?') || href.startsWith('mailto:')) continue;

    try {
      const linkUrl = new URL(href, `https://${hostname}`);
      const linkHost = linkUrl.hostname;

      // Skip same-domain links
      if (linkHost === hostname || linkHost.endsWith('.' + hostname.split('.').slice(-2).join('.'))) continue;

      // Skip links to the impersonated brand's legitimate domains
      const isLegitBrand = impersonatedBrand.domains.some(d =>
        linkHost === d || linkHost.endsWith('.' + d)
      );
      if (isLegitBrand) continue;

      suspiciousLinkCount++;
    } catch (_) {
      // Malformed URL
    }
  }

  if (suspiciousLinkCount > 0) {
    signals.push({
      id: 'fakesender:external_phishing_link',
      weight: 0.30,
    });
  }

  return signals;
}

/**
 * Detect heavy brand references in page text on a helpdesk domain.
 */
export function checkBrandImpersonationText(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const hdInfo = isHelpdeskPlatform(hostname);
  if (!hdInfo) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
    // Count brand keyword occurrences
    let occurrences = 0;
    for (const kw of brand.keywords) {
      const regex = new RegExp(kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const matches = combinedText.match(regex);
      if (matches) occurrences += matches.length;
    }

    // Heavy reference = 3+ occurrences of brand keywords
    if (occurrences >= 3) {
      signals.push({
        id: 'fakesender:brand_impersonation_text',
        weight: 0.25,
        matchedBrand: brandName,
      });
      break;
    }
  }

  return signals;
}

/**
 * Detect free-tier helpdesk indicators (platform branding watermarks).
 */
export function checkFreeTierIndicator(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const hdInfo = isHelpdeskPlatform(hostname);
  if (!hdInfo) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();

  const hasFreeTier = FREE_TIER_INDICATORS.some(indicator => bodyText.includes(indicator));

  if (hasFreeTier) {
    signals.push({
      id: 'fakesender:free_tier_indicator',
      weight: 0.20,
    });
  }

  return signals;
}

/**
 * Detect urgency language commonly used in phishing.
 */
export function checkUrgentActionLanguage(doc) {
  if (!doc) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  const matchedPhrases = URGENCY_PHRASES.filter(phrase => combinedText.includes(phrase));

  if (matchedPhrases.length >= 2) {
    signals.push({
      id: 'fakesender:urgent_action_language',
      weight: 0.15,
      matchedPhrases,
    });
  }

  return signals;
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
export function calculateFakeSenderRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner for helpdesk brand impersonation.
 */
export function injectFakeSenderWarningBanner(riskScore, matchedBrand, platform, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-fakesender-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const brandDisplay = matchedBrand ? matchedBrand.charAt(0).toUpperCase() + matchedBrand.slice(1) : 'Unknown';
  const platformDisplay = platform || 'Helpdesk';

  const banner = document.createElement('div');
  banner.id = 'phishops-fakesender-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected ${brandDisplay} Impersonation on ${platformDisplay}</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('fakesender:', '')).join(', ')}
    </div>
    <button id="phishops-fakesender-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-fakesender-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full FakeSender Shield analysis on the current page.
 */
export function runFakeSenderAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') return;

  // Fast path: skip if not on a helpdesk platform
  if (!isHelpdeskPlatform(hostname)) return;

  const doc = document;

  const subdomainSignals = checkHelpdeskBrandSubdomainMismatch(doc, hostname);
  const credentialSignals = checkCredentialOnHelpdesk(doc, hostname);
  const linkSignals = checkExternalPhishingLinks(doc, hostname);
  const textSignals = checkBrandImpersonationText(doc, hostname);
  const freeTierSignals = checkFreeTierIndicator(doc, hostname);
  const urgencySignals = checkUrgentActionLanguage(doc);

  const allSignals = [
    ...subdomainSignals,
    ...credentialSignals,
    ...linkSignals,
    ...textSignals,
    ...freeTierSignals,
    ...urgencySignals,
  ];

  const { riskScore, signalList } = calculateFakeSenderRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const matchedBrand = allSignals.find(s => s.matchedBrand)?.matchedBrand || null;
  const platform = allSignals.find(s => s.platform)?.platform || null;
  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectFakeSenderWarningBanner(riskScore, matchedBrand, platform, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'FAKESENDER_EVENT',
      payload: {
        eventType: 'FAKESENDER_BRAND_IMPERSONATION',
        riskScore,
        severity,
        matchedBrand,
        platform,
        signals: signalList,
        url: globalThis.location?.href || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof document !== 'undefined' && typeof process === 'undefined') {
  runFakeSenderAnalysis();
}
