/**
 * extension/lib/threat_intel_sync.js
 *
 * ThreatIntelSync — External Threat Intelligence Feed Ingestion
 *
 * Periodically pulls from PhishStats API and phishnet.cc feed.txt,
 * builds compact domain/IP/exfil-endpoint lookup sets, and persists
 * them to chrome.storage.local['threatIntel'].
 *
 * Architecture constraints:
 *   - External lookups are supplementary, never blocking
 *   - Cached locally; service worker reads the cache on each webNavigation
 *   - Graceful degradation: if unreachable, prior cache is kept intact
 *   - No per-page-load API calls — alarm-based batch sync only
 */

'use strict';

const STORAGE_KEY = 'threatIntel';
const PHISHSTATS_URL = 'https://api.phishstats.info/api/phishing?_where=(score,gt,4)&_sort=-date&_size=200&_p=1';
const PHISHNET_FEED_URL = 'https://phishnet.cc/feed.txt';
const FETCH_TIMEOUT_MS = 10000;

// ---------------------------------------------------------------------------
// Pure parsing functions (no chrome deps — testable in vitest/jsdom)
// ---------------------------------------------------------------------------

/**
 * Parse phishnet.cc feed.txt into an array of unique domains.
 * Feed uses defanged URLs: hxxps://example[.]com/path
 * @param {string} text
 * @returns {string[]}
 */
export function parsePhishnetFeed(text) {
  const domains = new Set();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const refanged = trimmed
      .replace(/^hxxps?/i, 'https')
      .replace(/\[\.\]/g, '.');
    const domain = extractDomainFromUrl(refanged);
    if (domain) domains.add(domain);
  }
  return [...domains];
}

/**
 * Build a deduplicated domain array from PhishStats API records.
 * @param {Object[]} records
 * @returns {string[]}
 */
export function buildDomainSet(records) {
  const domains = new Set();
  for (const record of records) {
    const domain = extractDomainFromUrl(record.url || '');
    if (domain) domains.add(domain);
  }
  return [...domains];
}

/**
 * Build a deduplicated IP array from PhishStats API records.
 * @param {Object[]} records
 * @returns {string[]}
 */
export function buildIPSet(records) {
  const ips = new Set();
  for (const record of records) {
    if (record.ip && typeof record.ip === 'string' && record.ip.trim()) {
      ips.add(record.ip.trim());
    }
  }
  return [...ips];
}

/**
 * Build deduplicated exfil endpoint domains from PhishStats records.
 * PhishStats includes an exfil_url field on some records from kit analysis.
 * @param {Object[]} records
 * @returns {string[]}
 */
export function buildExfilEndpointSet(records) {
  const endpoints = new Set();
  for (const record of records) {
    const domain = extractDomainFromUrl(record.exfil_url || '');
    if (domain) endpoints.add(domain);
  }
  return [...endpoints];
}

/**
 * Extract hostname from URL string. Strips www prefix.
 * Returns null for malformed URLs.
 * @param {string} urlString
 * @returns {string|null}
 */
export function extractDomainFromUrl(urlString) {
  try {
    const url = new URL(urlString);
    return url.hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

/**
 * Check if a domain (or any parent domain) is in the known-bad set.
 * Handles subdomain matching: login.evil.com matches evil.com in list.
 * @param {string} domain
 * @param {Object|null} intel
 * @returns {boolean}
 */
export function isDomainKnownBad(domain, intel) {
  if (!intel || !intel.badDomains?.length) return false;
  const badSet = new Set(intel.badDomains);
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    if (badSet.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

/**
 * Check if an IP is in the known-bad set.
 * @param {string} ip
 * @param {Object|null} intel
 * @returns {boolean}
 */
export function isIPKnownBad(ip, intel) {
  if (!intel || !intel.badIPs?.length) return false;
  return intel.badIPs.includes(ip);
}

/**
 * Check if a domain is a known credential exfiltration endpoint.
 * @param {string} domain
 * @param {Object|null} intel
 * @returns {boolean}
 */
export function isExfilEndpointKnownBad(domain, intel) {
  if (!intel || !intel.badExfilEndpoints?.length) return false;
  return intel.badExfilEndpoints.includes(domain);
}

/**
 * Compute set size statistics for reporting.
 * @param {Object} intel
 * @returns {{ domainCount: number, ipCount: number, exfilCount: number }}
 */
export function computeThreatIntelStats(intel) {
  return {
    domainCount: intel.badDomains?.length ?? 0,
    ipCount: intel.badIPs?.length ?? 0,
    exfilCount: intel.badExfilEndpoints?.length ?? 0,
  };
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/**
 * Read cached threat intel from chrome.storage.local.
 * Returns null if nothing stored or in test context.
 * @returns {Promise<Object|null>}
 */
export async function getStoredThreatIntel() {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return null;
    const data = await chrome.storage.local.get(STORAGE_KEY);
    return data[STORAGE_KEY] || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Feed fetching (chrome deps — tested via mocks)
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch PhishStats API and return records array.
 * Returns empty array on any failure.
 * @returns {Promise<Object[]>}
 */
export async function fetchPhishStatsRecords() {
  try {
    const response = await fetchWithTimeout(PHISHSTATS_URL);
    const records = await response.json();
    return Array.isArray(records) ? records : [];
  } catch (err) {
    console.debug('[PHISHOPS_THREATINTEL] PhishStats fetch failed: %s', err.message);
    return [];
  }
}

/**
 * Fetch phishnet.cc feed.txt and return parsed domain array.
 * Returns empty array on any failure.
 * @returns {Promise<string[]>}
 */
export async function fetchPhishnetDomains() {
  try {
    const response = await fetchWithTimeout(PHISHNET_FEED_URL);
    const text = await response.text();
    return parsePhishnetFeed(text);
  } catch (err) {
    console.debug('[PHISHOPS_THREATINTEL] phishnet.cc fetch failed: %s', err.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// Main sync function
// ---------------------------------------------------------------------------

/**
 * Sync threat intel from all sources and persist to chrome.storage.local.
 * Called on extension install and every 4 hours via chrome.alarms.
 * @returns {Promise<Object>} The intel object that was persisted
 */
export async function syncThreatIntel() {
  console.info('[PHISHOPS_THREATINTEL] Starting threat intel sync...');

  const [phishstatsRecords, phishnetDomains] = await Promise.all([
    fetchPhishStatsRecords(),
    fetchPhishnetDomains(),
  ]);

  const badDomains = [...new Set([
    ...buildDomainSet(phishstatsRecords),
    ...phishnetDomains,
  ])];
  const badIPs = buildIPSet(phishstatsRecords);
  const badExfilEndpoints = buildExfilEndpointSet(phishstatsRecords);

  const intel = {
    badDomains,
    badIPs,
    badExfilEndpoints,
    lastSync: new Date().toISOString(),
    sourceStats: {
      phishstatsRecords: phishstatsRecords.length,
      phishnetDomains: phishnetDomains.length,
    },
  };

  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      await chrome.storage.local.set({ [STORAGE_KEY]: intel });
    }
  } catch (err) {
    console.debug('[PHISHOPS_THREATINTEL] Storage write failed: %s', err.message);
  }

  const stats = computeThreatIntelStats(intel);
  console.info('[PHISHOPS_THREATINTEL] Sync complete — %d domains, %d IPs, %d exfil endpoints',
    stats.domainCount, stats.ipCount, stats.exfilCount);

  return intel;
}
