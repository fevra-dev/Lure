/**
 * extension/content/phishvision.js
 *
 * PhishVision — Brand Impersonation Detection
 *
 * Detects pages that visually mimic known brand login pages on non-brand
 * domains. Uses heuristic DOM analysis: brand keyword matching, login form
 * detection, domain suspicion scoring, favicon analysis, color palette
 * comparison, and text-to-HTML ratio checks.
 *
 * Signal architecture:
 *   phishvision:brand_keyword_mismatch  +0.35
 *   phishvision:favicon_brand_match     +0.30
 *   phishvision:suspicious_domain       +0.25
 *   phishvision:login_form_present      +0.20
 *   phishvision:brand_color_match       +0.20
 *   phishvision:low_text_ratio          +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module PhishVision
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Known Brand Database                                               */
/* ------------------------------------------------------------------ */

const KNOWN_BRANDS = {
  microsoft: {
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'windows.net', 'azure.com', 'hotmail.com'],
    keywords: ['microsoft', 'outlook', 'office 365', 'office365', 'onedrive', 'teams', 'sharepoint', 'azure', 'windows live', 'hotmail'],
    titlePatterns: [/sign\s*in.*microsoft/i, /microsoft.*sign\s*in/i, /outlook.*sign\s*in/i, /office\s*365/i],
    faviconPatterns: ['microsoft', 'office', 'outlook', 'msft'],
    colors: ['#0078D4', '#FFB900', '#D83B01', '#107C10'],
  },
  google: {
    domains: ['google.com', 'gmail.com', 'accounts.google.com', 'googleapis.com', 'gstatic.com', 'youtube.com'],
    keywords: ['google', 'gmail', 'google account', 'google workspace', 'g suite'],
    titlePatterns: [/sign\s*in.*google/i, /google.*sign\s*in/i, /gmail/i],
    faviconPatterns: ['google', 'gmail', 'gstatic'],
    colors: ['#4285F4', '#EA4335', '#FBBC05', '#34A853'],
  },
  apple: {
    domains: ['apple.com', 'icloud.com', 'appleid.apple.com', 'itunes.com'],
    keywords: ['apple', 'icloud', 'apple id', 'itunes', 'app store'],
    titlePatterns: [/sign\s*in.*apple/i, /apple\s*id/i, /icloud/i],
    faviconPatterns: ['apple'],
    colors: ['#000000', '#A2AAAD', '#555555'],
  },
  paypal: {
    domains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal', 'pay pal'],
    titlePatterns: [/log\s*in.*paypal/i, /paypal.*log\s*in/i],
    faviconPatterns: ['paypal'],
    colors: ['#003087', '#009CDE', '#012169'],
  },
  amazon: {
    domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'aws.amazon.com'],
    keywords: ['amazon', 'aws', 'amazon prime', 'kindle'],
    titlePatterns: [/sign\s*in.*amazon/i, /amazon.*sign\s*in/i],
    faviconPatterns: ['amazon', 'aws'],
    colors: ['#FF9900', '#232F3E', '#146EB4'],
  },
  facebook: {
    domains: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com', 'instagram.com'],
    keywords: ['facebook', 'meta', 'messenger', 'instagram'],
    titlePatterns: [/log\s*in.*facebook/i, /facebook.*log\s*in/i, /meta.*log\s*in/i],
    faviconPatterns: ['facebook', 'fb', 'meta'],
    colors: ['#1877F2', '#4267B2', '#898F9C'],
  },
  github: {
    domains: ['github.com', 'github.io', 'githubusercontent.com'],
    keywords: ['github', 'git hub'],
    titlePatterns: [/sign\s*in.*github/i, /github.*sign\s*in/i],
    faviconPatterns: ['github', 'octocat'],
    colors: ['#24292E', '#0366D6', '#2EA44F'],
  },
  linkedin: {
    domains: ['linkedin.com'],
    keywords: ['linkedin', 'linked in'],
    titlePatterns: [/sign\s*in.*linkedin/i, /linkedin.*sign\s*in/i],
    faviconPatterns: ['linkedin'],
    colors: ['#0A66C2', '#004182'],
  },
  dropbox: {
    domains: ['dropbox.com', 'dropboxusercontent.com'],
    keywords: ['dropbox', 'drop box'],
    titlePatterns: [/sign\s*in.*dropbox/i, /dropbox.*sign\s*in/i],
    faviconPatterns: ['dropbox'],
    colors: ['#0061FF', '#1E1919'],
  },
  salesforce: {
    domains: ['salesforce.com', 'force.com', 'lightning.force.com'],
    keywords: ['salesforce', 'sales force'],
    titlePatterns: [/log\s*in.*salesforce/i, /salesforce.*log\s*in/i],
    faviconPatterns: ['salesforce'],
    colors: ['#00A1E0', '#1B5297'],
  },
  adobe: {
    domains: ['adobe.com', 'creativecloud.adobe.com'],
    keywords: ['adobe', 'creative cloud', 'acrobat'],
    titlePatterns: [/sign\s*in.*adobe/i, /adobe.*sign\s*in/i],
    faviconPatterns: ['adobe'],
    colors: ['#FF0000', '#EB1000', '#FA0F00'],
  },
  netflix: {
    domains: ['netflix.com'],
    keywords: ['netflix'],
    titlePatterns: [/sign\s*in.*netflix/i, /netflix.*sign\s*in/i],
    faviconPatterns: ['netflix'],
    colors: ['#E50914', '#221F1F', '#B81D24'],
  },
  slack: {
    domains: ['slack.com'],
    keywords: ['slack'],
    titlePatterns: [/sign\s*in.*slack/i, /slack.*sign\s*in/i],
    faviconPatterns: ['slack'],
    colors: ['#4A154B', '#36C5F0', '#2EB67D', '#ECB22E', '#E01E5A'],
  },
  zoom: {
    domains: ['zoom.us', 'zoom.com'],
    keywords: ['zoom'],
    titlePatterns: [/sign\s*in.*zoom/i, /zoom.*sign\s*in/i],
    faviconPatterns: ['zoom'],
    colors: ['#2D8CFF', '#0B5CFF'],
  },
  okta: {
    domains: ['okta.com', 'oktapreview.com'],
    keywords: ['okta'],
    titlePatterns: [/sign\s*in.*okta/i, /okta.*sign\s*in/i],
    faviconPatterns: ['okta'],
    colors: ['#007DC1', '#00297A'],
  },
  coinbase: {
    domains: ['coinbase.com'],
    keywords: ['coinbase', 'coin base'],
    titlePatterns: [/sign\s*in.*coinbase/i, /coinbase.*sign\s*in/i],
    faviconPatterns: ['coinbase'],
    colors: ['#0052FF', '#1652F0'],
  },
  docusign: {
    domains: ['docusign.com', 'docusign.net'],
    keywords: ['docusign', 'docu sign'],
    titlePatterns: [/sign\s*in.*docusign/i, /docusign.*sign\s*in/i, /review.*document/i],
    faviconPatterns: ['docusign'],
    colors: ['#FF961C', '#25282B'],
  },
  stripe: {
    domains: ['stripe.com', 'dashboard.stripe.com'],
    keywords: ['stripe'],
    titlePatterns: [/sign\s*in.*stripe/i, /stripe.*sign\s*in/i],
    faviconPatterns: ['stripe'],
    colors: ['#635BFF', '#0A2540'],
  },
};

/* ------------------------------------------------------------------ */
/*  Suspicious Domain Suffixes                                         */
/* ------------------------------------------------------------------ */

const SUSPICIOUS_DOMAIN_SUFFIXES = [
  '.pages.dev',
  '.netlify.app',
  '.vercel.app',
  '.herokuapp.com',
  '.firebaseapp.com',
  '.web.app',
  '.glitch.me',
  '.repl.co',
  '.surge.sh',
  '.render.com',
  '.fly.dev',
  '.railway.app',
  '.onrender.com',
  '.deno.dev',
  '.workers.dev',
  '.r2.dev',
  '.ngrok.io',
  '.ngrok-free.app',
  '.trycloudflare.com',
  '.github.io',
  '.gitlab.io',
  '.bitbucket.io',
  '.blogspot.com',
  '.weebly.com',
  '.wixsite.com',
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if page contains brand keywords/title patterns but hostname
 * doesn't match that brand's known domains.
 */
export function checkBrandKeywordSignals(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];
  const title = (doc.title || '').toLowerCase();
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
    // Skip if hostname belongs to this brand
    const isOwnDomain = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
    if (isOwnDomain) continue;

    // Check title patterns
    const titleMatch = brand.titlePatterns.some(p => p.test(doc.title || ''));

    // Check keywords in combined text
    const keywordMatch = brand.keywords.some(kw => combinedText.includes(kw));

    if (titleMatch || keywordMatch) {
      signals.push({
        id: 'phishvision:brand_keyword_mismatch',
        weight: 0.35,
        matchedBrand: brandName,
      });
      break; // One brand match is enough
    }
  }

  return signals;
}

/**
 * Check if page has login/credential form fields.
 */
export function checkLoginFormSignals(doc) {
  if (!doc) return [];

  const signals = [];

  const passwordFields = doc.querySelectorAll('input[type="password"]');
  const emailFields = doc.querySelectorAll('input[type="email"]');
  const autocompleteFields = doc.querySelectorAll(
    'input[autocomplete="username"], input[autocomplete="current-password"], input[autocomplete="new-password"]'
  );

  if (passwordFields.length > 0 || emailFields.length > 0 || autocompleteFields.length > 0) {
    signals.push({
      id: 'phishvision:login_form_present',
      weight: 0.20,
    });
  }

  return signals;
}

/**
 * Check if hostname is suspicious (free hosting, IP address, excessive subdomains).
 */
export function checkDomainSuspicion(hostname) {
  if (!hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];

  // Free hosting suffix
  const isFreeHosting = SUSPICIOUS_DOMAIN_SUFFIXES.some(suffix => hostname.endsWith(suffix));

  // IP address (IPv4)
  const isIPAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);

  // Excessive subdomains (4+ parts, excluding common TLDs like co.uk)
  const parts = hostname.split('.');
  const hasExcessiveSubdomains = parts.length >= 5;

  if (isFreeHosting || isIPAddress || hasExcessiveSubdomains) {
    signals.push({
      id: 'phishvision:suspicious_domain',
      weight: 0.25,
    });
  }

  return signals;
}

/**
 * Check text-to-HTML ratio — very low ratio with credential fields
 * suggests a GAN-generated or template phishing page.
 */
export function checkTextToHtmlRatio(doc) {
  if (!doc) return [];

  const signals = [];
  const html = doc.documentElement?.outerHTML || '';
  const text = doc.body?.innerText || doc.body?.textContent || '';

  if (html.length === 0) return [];

  const ratio = text.length / html.length;
  const hasPasswordField = doc.querySelectorAll('input[type="password"]').length > 0;

  if (ratio < 0.08 && hasPasswordField) {
    signals.push({
      id: 'phishvision:low_text_ratio',
      weight: 0.15,
    });
  }

  return signals;
}

/**
 * Check if favicon links reference a brand on a non-brand domain.
 */
export function checkFaviconBrandMatch(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];
  const faviconLinks = doc.querySelectorAll('link[rel*="icon"]');

  if (faviconLinks.length === 0) return [];

  for (const link of faviconLinks) {
    const href = (link.getAttribute('href') || '').toLowerCase();
    if (!href) continue;

    for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
      const isOwnDomain = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
      if (isOwnDomain) continue;

      const faviconMatch = brand.faviconPatterns.some(p => href.includes(p));
      if (faviconMatch) {
        signals.push({
          id: 'phishvision:favicon_brand_match',
          weight: 0.30,
          matchedBrand: brandName,
        });
        return signals; // One match is enough
      }
    }
  }

  return signals;
}

/**
 * Check if page uses brand-specific color palette on a non-brand domain.
 * Checks computed background-color and color on key elements.
 */
export function checkColorPaletteMatch(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  // getComputedStyle may not be available (jsdom)
  if (typeof globalThis.getComputedStyle !== 'function') return [];

  const signals = [];
  const elements = doc.querySelectorAll('button, a, input[type="submit"], [role="button"], h1, h2, .btn, .button');

  if (elements.length === 0) return [];

  for (const [brandName, brand] of Object.entries(KNOWN_BRANDS)) {
    const isOwnDomain = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
    if (isOwnDomain) continue;

    let colorMatches = 0;
    const brandColorsLower = brand.colors.map(c => c.toLowerCase());

    for (const el of elements) {
      try {
        const style = globalThis.getComputedStyle(el);
        const bgColor = style.backgroundColor || '';
        const textColor = style.color || '';

        // Convert rgb to hex for comparison
        const bgHex = rgbToHex(bgColor);
        const textHex = rgbToHex(textColor);

        if (bgHex && brandColorsLower.includes(bgHex.toLowerCase())) colorMatches++;
        if (textHex && brandColorsLower.includes(textHex.toLowerCase())) colorMatches++;
      } catch (_) {
        // getComputedStyle may fail on some elements
      }
    }

    if (colorMatches >= 3) {
      signals.push({
        id: 'phishvision:brand_color_match',
        weight: 0.20,
        matchedBrand: brandName,
      });
      break;
    }
  }

  return signals;
}

/**
 * Convert rgb(r, g, b) string to hex.
 */
function rgbToHex(rgb) {
  if (!rgb) return null;
  // Already hex
  if (rgb.startsWith('#')) return rgb;
  const match = rgb.match(/rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/);
  if (!match) return null;
  const r = parseInt(match[1], 10);
  const g = parseInt(match[2], 10);
  const b = parseInt(match[3], 10);
  return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1).toUpperCase();
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
export function calculatePhishVisionRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner into the page.
 */
export function injectPhishVisionWarningBanner(riskScore, matchedBrand, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-phishvision-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const brandDisplay = matchedBrand ? matchedBrand.charAt(0).toUpperCase() + matchedBrand.slice(1) : 'Unknown';

  const banner = document.createElement('div');
  banner.id = 'phishops-phishvision-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected ${brandDisplay} Impersonation</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('phishvision:', '')).join(', ')}
    </div>
    <button id="phishops-phishvision-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-phishvision-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full PhishVision analysis on the current page.
 */
export function runPhishVisionAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') return;

  const doc = document;

  const brandSignals = checkBrandKeywordSignals(doc, hostname);
  const loginSignals = checkLoginFormSignals(doc);
  const domainSignals = checkDomainSuspicion(hostname);
  const ratioSignals = checkTextToHtmlRatio(doc);
  const faviconSignals = checkFaviconBrandMatch(doc, hostname);
  const colorSignals = checkColorPaletteMatch(doc, hostname);

  const allSignals = [
    ...brandSignals,
    ...loginSignals,
    ...domainSignals,
    ...ratioSignals,
    ...faviconSignals,
    ...colorSignals,
  ];

  const { riskScore, signalList } = calculatePhishVisionRiskScore(allSignals);

  if (riskScore < 0.50) return;

  // Determine matched brand from signals
  const matchedBrand = allSignals.find(s => s.matchedBrand)?.matchedBrand || null;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectPhishVisionWarningBanner(riskScore, matchedBrand, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'PHISHVISION_EVENT',
      payload: {
        eventType: 'PHISHVISION_BRAND_IMPERSONATION',
        riskScore,
        severity,
        matchedBrand,
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
  runPhishVisionAnalysis();
}
