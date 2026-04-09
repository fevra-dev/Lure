/**
 * extension/content/allowlist_gate.js
 *
 * Runs at document_start BEFORE all other PhishOps content scripts.
 * If the current page's domain is in the builtin or user allowlist,
 * this script:
 *
 *   1. Injects a <style> rule hiding all PhishOps-injected banners
 *      (every banner uses an id starting with "phishops-")
 *
 *   2. Sets window.__phishopsAllowlisted = true so detectors can
 *      optionally short-circuit expensive work (not required — the
 *      CSS rule handles visual suppression regardless)
 *
 * NOTE: The GATE_BUILTIN_ALLOWLIST below is a duplicate of BUILTIN_ALLOWLIST
 * from lib/allowlist.js. This file is a classic content script and cannot
 * import ES modules. If you add/remove domains in lib/allowlist.js,
 * update this list too.
 */

'use strict';

/* eslint-disable no-var */

var GATE_BUILTIN_ALLOWLIST = new Set([
  'academia.edu',
  'accounts.google.com',
  'adobe.com',
  'alibaba.com',
  'aliexpress.com',
  'amazon.ca',
  'amazon.co.jp',
  'amazon.co.uk',
  'amazon.com',
  'amazon.de',
  'amazon.es',
  'amazon.fr',
  'anthropic.com',
  'apnews.com',
  'apple.com',
  'archive.org',
  'arxiv.org',
  'auth.apple.com',
  'baidu.com',
  'bandcamp.com',
  'bbc.co.uk',
  'bbc.com',
  'berkeley.edu',
  'bing.com',
  'bitbucket.org',
  'blog.google',
  'bloomberg.com',
  'booking.com',
  'box.com',
  'britannica.com',
  'businessinsider.com',
  'calendar.google.com',
  'canva.com',
  'cbsnews.com',
  'cdc.gov',
  'claude.ai',
  'cloudflare.com',
  'cnbc.com',
  'cnet.com',
  'cnn.com',
  'codepen.io',
  'codesandbox.io',
  'cornell.edu',
  'dailymail.co.uk',
  'dailymotion.com',
  'deezer.com',
  'developer.apple.com',
  'developer.mozilla.org',
  'discord.com',
  'disney.com',
  'docs.aws.amazon.com',
  'docs.google.com',
  'doi.org',
  'drive.google.com',
  'dropbox.com',
  'duckduckgo.com',
  'ea.com',
  'ebay.com',
  'economist.com',
  'engadget.com',
  'espn.com',
  'etsy.com',
  'europa.eu',
  'eventbrite.com',
  'evernote.com',
  'facebook.com',
  'fifa.com',
  'figma.com',
  'flickr.com',
  'forbes.com',
  'foxnews.com',
  'freepik.com',
  'ft.com',
  'gather.town',
  'gettyimages.com',
  'giphy.com',
  'github.com',
  'gitlab.com',
  'gofundme.com',
  'goodreads.com',
  'google.com',
  'hackthebox.com',
  'harvard.edu',
  'hp.com',
  'hubspot.com',
  'huffpost.com',
  'huggingface.co',
  'ibm.com',
  'ikea.com',
  'imdb.com',
  'independent.co.uk',
  'instagram.com',
  'intel.com',
  'issuu.com',
  'istockphoto.com',
  'joomla.org',
  'kaggle.com',
  'kickstarter.com',
  'latimes.com',
  'learn.microsoft.com',
  'linkedin.com',
  'linktr.ee',
  'live.com',
  'login.live.com',
  'login.microsoftonline.com',
  'login.okta.com',
  'login.salesforce.com',
  'login.windows.net',
  'mail.google.com',
  'mailchimp.com',
  'maps.google.com',
  'mashable.com',
  'mayoclinic.org',
  'mediafire.com',
  'medium.com',
  'meet.google.com',
  'microsoft.com',
  'mit.edu',
  'moz.com',
  'mozilla.org',
  'nasa.gov',
  'nationalgeographic.com',
  'nature.com',
  'naver.com',
  'nba.com',
  'nbcnews.com',
  'netflix.com',
  'newsweek.com',
  'newyorker.com',
  'nhk.or.jp',
  'nih.gov',
  'notion.so',
  'npr.org',
  'nytimes.com',
  'office.com',
  'openai.com',
  'opera.com',
  'oracle.com',
  'outlook.com',
  'outlook.live.com',
  'outlook.office.com',
  'paypal.com',
  'pbs.org',
  'pexels.com',
  'pinterest.com',
  'pixabay.com',
  'play.google.com',
  'playstation.com',
  'prezi.com',
  'proton.me',
  'protonmail.com',
  'quora.com',
  'rakuten.co.jp',
  'reddit.com',
  'replit.com',
  'researchgate.net',
  'restream.io',
  'reuters.com',
  'salesforce.com',
  'samsung.com',
  'scribd.com',
  'shopify.com',
  'shutterstock.com',
  'slack.com',
  'slideshare.net',
  'soundcloud.com',
  'splunk.com',
  'spotify.com',
  'stackexchange.com',
  'stackoverflow.com',
  'stanford.edu',
  'steampowered.com',
  'streamyard.com',
  'substack.com',
  'surveymonkey.com',
  'target.com',
  'teams.microsoft.com',
  'techcrunch.com',
  'ted.com',
  'telegram.org',
  'telegraph.co.uk',
  'theatlantic.com',
  'theguardian.com',
  'theverge.com',
  'tiktok.com',
  'time.com',
  'translate.google.com',
  'trello.com',
  'tripadvisor.com',
  'trustpilot.com',
  'tryhackme.com',
  'tumblr.com',
  'twitch.tv',
  'twitter.com',
  'un.org',
  'unesco.org',
  'unicef.org',
  'unsplash.com',
  'usatoday.com',
  'variety.com',
  'vimeo.com',
  'vk.com',
  'walmart.com',
  'washingtonpost.com',
  'weather.com',
  'web.telegram.org',
  'web.whatsapp.com',
  'webex.com',
  'webmd.com',
  'weibo.com',
  'whatsapp.com',
  'whereby.com',
  'whitehouse.gov',
  'who.int',
  'wikihow.com',
  'wikimedia.org',
  'wikipedia.org',
  'wired.com',
  'wordpress.com',
  'wordpress.org',
  'wsj.com',
  'x.com',
  'xbox.com',
  'yahoo.co.jp',
  'yahoo.com',
  'yelp.com',
  'youtube.com',
  'zendesk.com',
  'zoom.us',
]);

(function allowlistGate() {
  var hostname = '';
  try {
    hostname = location.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return;
  }
  if (!hostname) return;

  // Check builtin list first (sync, fast)
  var isBuiltinAllowlisted = GATE_BUILTIN_ALLOWLIST.has(hostname);
  if (!isBuiltinAllowlisted) {
    for (var d of GATE_BUILTIN_ALLOWLIST) {
      if (hostname.endsWith('.' + d)) {
        isBuiltinAllowlisted = true;
        break;
      }
    }
  }

  if (isBuiltinAllowlisted) {
    _applySuppression();
    return;
  }

  // Check user allowlist (async — may race with document_start detectors,
  // but CSS rule still hides banners even if injected after detector fires)
  try {
    chrome.storage.local.get('phishops_user_allowlist', function (data) {
      var userList = Array.isArray(data.phishops_user_allowlist)
        ? data.phishops_user_allowlist
        : [];
      for (var i = 0; i < userList.length; i++) {
        var ud = userList[i];
        if (hostname === ud || hostname.endsWith('.' + ud)) {
          _applySuppression();
          return;
        }
      }
    });
  } catch {
    // Not in extension context
  }

  function _applySuppression() {
    // 1. CSS rule to hide all PhishOps banners
    var style = document.createElement('style');
    style.textContent = '[id^="phishops-"] { display: none !important; }';
    (document.head || document.documentElement).appendChild(style);

    // 2. Flag for detectors to optionally short-circuit
    try {
      Object.defineProperty(window, '__phishopsAllowlisted', {
        value: true,
        writable: false,
        configurable: false,
      });
    } catch {
      window.__phishopsAllowlisted = true;
    }
  }
})();
