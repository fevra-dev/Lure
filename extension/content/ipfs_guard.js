/**
 * extension/content/ipfs_guard.js
 *
 * IPFSGuard — IPFS Gateway Phishing Detection
 *
 * Detects phishing pages hosted on IPFS gateways. IPFS-hosted content is
 * takedown-resistant — immutable, served through multiple gateways. 84
 * campaigns identified in Feb 2024 (SANS ISC). Detects CID patterns,
 * credential harvesting on gateway domains, and brand impersonation.
 *
 * Signal architecture:
 *   ipfs:gateway_hosted_page     +0.35
 *   ipfs:credential_on_gateway   +0.30
 *   ipfs:cid_in_url              +0.25
 *   ipfs:external_ipfs_links     +0.20
 *   ipfs:suspicious_ipfs_content +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module IPFSGuard
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const IPFS_GATEWAY_DOMAINS = [
  'ipfs.io',
  'cloudflare-ipfs.com',
  'dweb.link',
  'nftstorage.link',
  'gateway.pinata.cloud',
  'via0.com',
  'astyanax.io',
  'w3s.link',
  'cf-ipfs.com',
  'ipfs.fleek.co',
  'hub.textile.io',
  'ipfs.runfission.com',
  'fleek.cool',
  'ipfs.eth.aragon.network',
  'ipfs.jpu.jp',
];

const CID_V0_REGEX = /Qm[A-Za-z0-9]{44}/;
const CID_V1_REGEX = /baf[yk][a-z2-7]{50,}/;

/** Duplicated from phishvision.js — MV3 content scripts cannot share modules. */
const BRAND_KEYWORDS = [
  'microsoft', 'outlook', 'office 365', 'office365', 'onedrive',
  'google', 'gmail', 'apple', 'icloud',
  'paypal', 'amazon', 'aws',
  'facebook', 'meta', 'instagram',
  'github', 'linkedin', 'dropbox',
  'salesforce', 'adobe', 'netflix',
  'slack', 'zoom', 'okta',
  'coinbase', 'docusign', 'stripe',
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if hostname matches a known IPFS gateway domain.
 */
function checkGatewayHostedPage(hostname) {
  if (!hostname) return [];

  const isGateway = IPFS_GATEWAY_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );

  if (isGateway) {
    return [{
      id: 'ipfs:gateway_hosted_page',
      weight: 0.35,
      gateway: hostname,
    }];
  }

  return [];
}

/**
 * Check if page on an IPFS gateway contains credential fields.
 */
function checkCredentialOnGateway(doc, hostname) {
  if (!doc || !hostname) return [];

  const isGateway = IPFS_GATEWAY_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
  if (!isGateway) return [];

  const hasPassword = doc.querySelectorAll('input[type="password"]').length > 0;
  const hasEmail = doc.querySelectorAll('input[type="email"]').length > 0;

  if (hasPassword || hasEmail) {
    return [{
      id: 'ipfs:credential_on_gateway',
      weight: 0.30,
    }];
  }

  return [];
}

/**
 * Check if URL contains a CIDv0 or CIDv1 pattern.
 */
function checkCidInUrl(urlString) {
  if (!urlString) return [];

  if (CID_V0_REGEX.test(urlString) || CID_V1_REGEX.test(urlString)) {
    return [{
      id: 'ipfs:cid_in_url',
      weight: 0.25,
    }];
  }

  return [];
}

/**
 * Check if page contains 2+ links to IPFS gateway URLs.
 */
function checkExternalIpfsLinks(doc) {
  if (!doc) return [];

  const links = doc.querySelectorAll('a[href]');
  let ipfsLinkCount = 0;

  for (const link of links) {
    const href = link.getAttribute('href') || '';
    const isIpfsLink = IPFS_GATEWAY_DOMAINS.some(d => href.includes(d));
    const hasCid = CID_V0_REGEX.test(href) || CID_V1_REGEX.test(href);

    if (isIpfsLink || hasCid) {
      ipfsLinkCount++;
    }
  }

  if (ipfsLinkCount >= 2) {
    return [{
      id: 'ipfs:external_ipfs_links',
      weight: 0.20,
      linkCount: ipfsLinkCount,
    }];
  }

  return [];
}

/**
 * Check if page on an IPFS gateway contains brand keywords.
 */
function checkSuspiciousIpfsContent(doc, hostname) {
  if (!doc || !hostname) return [];

  const isGateway = IPFS_GATEWAY_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
  if (!isGateway) return [];

  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  const matchedBrand = BRAND_KEYWORDS.find(kw => combinedText.includes(kw));

  if (matchedBrand) {
    return [{
      id: 'ipfs:suspicious_ipfs_content',
      weight: 0.15,
      matchedBrand,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
function calculateIpfsRiskScore(signals) {
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
function injectIpfsWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-ipfs-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const matchedBrand = signals.find(s => s.matchedBrand)?.matchedBrand || null;
  const brandDisplay = matchedBrand
    ? matchedBrand.charAt(0).toUpperCase() + matchedBrand.slice(1)
    : 'Unknown Brand';

  const banner = document.createElement('div');
  banner.id = 'phishops-ipfs-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected IPFS Phishing${matchedBrand ? ` (${brandDisplay})` : ''}</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('ipfs:', '')).join(', ')}
    </div>
    <button id="phishops-ipfs-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-ipfs-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full IPFSGuard analysis on the current page.
 */
function runIpfsGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  const url = globalThis.location?.href || '';
  if (!hostname) return;

  const doc = document;

  const gatewaySignals = checkGatewayHostedPage(hostname);
  const credentialSignals = checkCredentialOnGateway(doc, hostname);
  const cidSignals = checkCidInUrl(url);
  const linkSignals = checkExternalIpfsLinks(doc);
  const contentSignals = checkSuspiciousIpfsContent(doc, hostname);

  const allSignals = [
    ...gatewaySignals,
    ...credentialSignals,
    ...cidSignals,
    ...linkSignals,
    ...contentSignals,
  ];

  const { riskScore, signalList } = calculateIpfsRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';
  const matchedBrand = allSignals.find(s => s.matchedBrand)?.matchedBrand || null;

  injectIpfsWarningBanner(riskScore, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'IPFSGUARD_EVENT',
      payload: {
        eventType: 'IPFS_PHISHING_DETECTED',
        riskScore,
        severity,
        matchedBrand,
        gateway: hostname,
        signals: signalList,
        url,
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
  runIpfsGuardAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['ipfs_guard'] = {
    checkGatewayHostedPage,
    checkCredentialOnGateway,
    checkCidInUrl,
    checkExternalIpfsLinks,
    checkSuspiciousIpfsContent,
    calculateIpfsRiskScore,
    injectIpfsWarningBanner,
    runIpfsGuardAnalysis,
  };
}

})();
