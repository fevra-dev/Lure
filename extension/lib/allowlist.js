/**
 * extension/lib/allowlist.js
 *
 * Unified domain allowlist for PhishOps. Combines a hardcoded builtin list
 * (mega-merge of all detector-specific trusted domains) with a user-editable
 * list stored in chrome.storage.local['phishops_user_allowlist'].
 *
 * Used by:
 *   - Service worker (ES module import) — suppress telemetry for allowlisted domains
 *   - Popup (via window.LureAllowlist) — allowlist editor UI
 *
 * NOTE: extension/content/allowlist_gate.js duplicates the builtin list
 * as an inline Set because content scripts can't import ES modules.
 * If you add/remove domains here, update allowlist_gate.js too.
 */

'use strict';

const STORAGE_KEY = 'phishops_user_allowlist';

/**
 * Builtin allowlist — well-known legitimate domains that consistently trigger
 * false positives across multiple detectors. Merged from:
 *   - proxy_guard.js LEGIT_DOMAIN_ALLOWLIST (34 domains)
 *   - qrljacking_guard.js KNOWN_QR_AUTH_PLATFORMS (7 domains)
 *   - clickfix_clipboard_defender.js ALLOWLISTED_ORIGINS (6 domains)
 *   - fullscreen_guard.js VIDEO_PLATFORMS (8 domains)
 *   - webrtc_guard.js KNOWN_VIDEO_PLATFORMS (10 domains)
 *   - sync_guard.js TRUSTED_REFERRER_DOMAINS (7 domains)
 *   - autofill_guard.js OAUTH_ENDPOINTS (7 domains)
 *   - service-worker.js SPA_TRUSTED_PLATFORMS (6 domains)
 *   - Top-500 most-trafficked websites (Moz DA list)
 *   - FP events observed in field testing (2026-04-09)
 *
 * Deduplicated and sorted. Per-detector lists remain in their respective
 * files for detector-specific logic (e.g., elevated thresholds). This global
 * list is the "never alert on these at all" set.
 */
const BUILTIN_ALLOWLIST = new Set([
  // Major platforms & social
  'linkedin.com',
  'github.com',
  'gitlab.com',
  'bitbucket.org',
  'stackoverflow.com',
  'stackexchange.com',
  'reddit.com',
  'twitter.com',
  'x.com',
  'facebook.com',
  'instagram.com',
  'youtube.com',
  'pinterest.com',
  'tiktok.com',
  'whatsapp.com',
  'telegram.org',
  'discord.com',
  'slack.com',
  'medium.com',
  'substack.com',
  'quora.com',
  'tumblr.com',
  'vk.com',
  'weibo.com',

  // Search & portals
  'google.com',
  'bing.com',
  'yahoo.com',
  'duckduckgo.com',
  'baidu.com',

  // AI platforms
  'claude.ai',
  'anthropic.com',
  'openai.com',
  'huggingface.co',
  'kaggle.com',

  // Dev tools & code
  'codepen.io',
  'codesandbox.io',
  'replit.com',
  'notion.so',
  'figma.com',
  'canva.com',
  'wordpress.org',
  'wordpress.com',
  'joomla.org',

  // Video & streaming
  'vimeo.com',
  'twitch.tv',
  'dailymotion.com',
  'spotify.com',
  'netflix.com',
  'disney.com',
  'deezer.com',
  'soundcloud.com',
  'bandcamp.com',

  // Video conferencing
  'zoom.us',
  'webex.com',
  'whereby.com',
  'gather.town',
  'streamyard.com',
  'restream.io',

  // Shopping & commerce
  'amazon.com',
  'amazon.co.uk',
  'amazon.de',
  'amazon.co.jp',
  'amazon.ca',
  'amazon.fr',
  'amazon.es',
  'ebay.com',
  'paypal.com',
  'shopify.com',
  'aliexpress.com',
  'alibaba.com',
  'walmart.com',
  'target.com',
  'ikea.com',
  'booking.com',
  'etsy.com',

  // News & media
  'nytimes.com',
  'washingtonpost.com',
  'bbc.com',
  'bbc.co.uk',
  'cnn.com',
  'reuters.com',
  'bloomberg.com',
  'forbes.com',
  'theguardian.com',
  'usatoday.com',
  'wsj.com',
  'foxnews.com',
  'nbcnews.com',
  'cbsnews.com',
  'apnews.com',
  'npr.org',
  'huffpost.com',
  'businessinsider.com',
  'cnbc.com',
  'techcrunch.com',
  'theverge.com',
  'wired.com',
  'engadget.com',
  'mashable.com',
  'cnet.com',
  'nature.com',
  'economist.com',
  'newyorker.com',
  'theatlantic.com',
  'ft.com',
  'latimes.com',
  'independent.co.uk',
  'telegraph.co.uk',
  'dailymail.co.uk',
  'newsweek.com',
  'time.com',
  'variety.com',
  'espn.com',
  'imdb.com',

  // Cloud & infrastructure
  'cloudflare.com',
  'microsoft.com',
  'apple.com',
  'adobe.com',
  'oracle.com',
  'ibm.com',
  'samsung.com',
  'intel.com',
  'hp.com',
  'salesforce.com',
  'hubspot.com',
  'zendesk.com',
  'mailchimp.com',

  // Auth providers
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
  'auth.apple.com',
  'login.salesforce.com',
  'login.okta.com',

  // Messaging web apps
  'web.whatsapp.com',
  'web.telegram.org',
  'teams.microsoft.com',

  // Google properties
  'mail.google.com',
  'docs.google.com',
  'drive.google.com',
  'meet.google.com',
  'maps.google.com',
  'calendar.google.com',
  'translate.google.com',
  'blog.google',
  'play.google.com',

  // Microsoft properties
  'outlook.office.com',
  'outlook.live.com',
  'outlook.com',
  'office.com',
  'live.com',
  'learn.microsoft.com',

  // Documentation & reference
  'developer.mozilla.org',
  'developer.apple.com',
  'docs.aws.amazon.com',
  'wikipedia.org',
  'wikimedia.org',
  'britannica.com',
  'archive.org',
  'wikihow.com',

  // Education
  'harvard.edu',
  'stanford.edu',
  'mit.edu',
  'berkeley.edu',
  'cornell.edu',

  // Security / CTF
  'tryhackme.com',
  'hackthebox.com',
  'splunk.com',

  // Privacy / secure email
  'protonmail.com',
  'proton.me',

  // Finance & productivity
  'dropbox.com',
  'box.com',
  'evernote.com',
  'trello.com',

  // Other major sites observed in FP logs
  'opera.com',
  'mozilla.org',
  'moz.com',
  'mediafire.com',
  'vimeo.com',
  'europa.eu',
  'surveymonkey.com',
  'eventbrite.com',
  'goodreads.com',
  'tripadvisor.com',
  'yelp.com',
  'trustpilot.com',
  'ted.com',
  'kickstarter.com',
  'gofundme.com',
  'scribd.com',
  'issuu.com',
  'prezi.com',
  'slideshare.net',
  'academia.edu',
  'researchgate.net',
  'arxiv.org',
  'doi.org',
  'pbs.org',
  'steampowered.com',
  'playstation.com',
  'xbox.com',
  'ea.com',
  'nba.com',
  'fifa.com',
  'nationalgeographic.com',
  'weather.com',
  'webmd.com',
  'mayoclinic.org',

  // Government
  'nih.gov',
  'cdc.gov',
  'nasa.gov',
  'whitehouse.gov',
  'un.org',
  'unesco.org',
  'unicef.org',
  'who.int',

  // Japanese & regional
  'rakuten.co.jp',
  'yahoo.co.jp',
  'nhk.or.jp',
  'naver.com',

  // Other top-traffic sites
  'flickr.com',
  'giphy.com',
  'unsplash.com',
  'pixabay.com',
  'pexels.com',
  'freepik.com',
  'gettyimages.com',
  'istockphoto.com',
  'shutterstock.com',

  // Link aggregators & tools
  'linktr.ee',
  'reddit.com',
]);

/**
 * Check whether a hostname is in the builtin OR user allowlist.
 *
 * @param {string} hostname — bare hostname (e.g. 'chat.claude.ai')
 * @returns {Promise<boolean>}
 */
async function isDomainAllowlisted(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase().replace(/^www\./, '');

  if (_matchesSet(h, BUILTIN_ALLOWLIST)) return true;

  const userList = await getUserAllowlist();
  return _matchesArray(h, userList);
}

/**
 * Read the user-editable allowlist from storage.
 * @returns {Promise<string[]>}
 */
async function getUserAllowlist() {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return [];
    const data = await chrome.storage.local.get(STORAGE_KEY);
    return Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
  } catch {
    return [];
  }
}

/**
 * Add a domain to the user allowlist.
 * @param {string} domain — bare domain (e.g. 'internal.corp.com')
 */
async function addToUserAllowlist(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  if (!d) return;
  const list = await getUserAllowlist();
  if (list.includes(d)) return;
  list.push(d);
  list.sort();
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
}

/**
 * Remove a domain from the user allowlist.
 * @param {string} domain
 */
async function removeFromUserAllowlist(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  const list = await getUserAllowlist();
  const updated = list.filter((entry) => entry !== d);
  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
}

function _matchesSet(hostname, set) {
  if (set.has(hostname)) return true;
  for (const d of set) {
    if (hostname.endsWith('.' + d)) return true;
  }
  return false;
}

function _matchesArray(hostname, arr) {
  for (const d of arr) {
    if (hostname === d || hostname.endsWith('.' + d)) return true;
  }
  return false;
}

const LureAllowlist = {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
};
if (typeof window !== 'undefined') window.LureAllowlist = LureAllowlist;
export {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
};
