/**
 * extension/content/etherhiding_guard.js
 *
 * EtherHidingGuard — Blockchain-Hosted Phishing Payload Delivery
 *
 * Detects landing pages (often compromised WordPress via ClearFake/ClickFix)
 * that retrieve phishing payloads from BSC/ETH smart contracts via eth_call
 * JSON-RPC to public RPC gateways, then inject into DOM via eval/innerHTML/
 * document.write/dynamic script. Payload lives on-chain — immune to URL
 * blocklists. First documented by Guardio Labs (Oct 2023), adopted by
 * ClearFake/ClickFix campaigns 2024-2026.
 *
 * Complements drainer_guard.js (which detects wallet draining, not payload
 * delivery).
 *
 * Injected at document_start to wrap fetch() and XMLHttpRequest before page
 * scripts can cache references to the original APIs.
 *
 * Signal architecture:
 *   etherhide:rpc_call_to_blockchain_endpoint     +0.40
 *   etherhide:eth_call_response_injected          +0.30
 *   etherhide:contract_address_in_inline_script   +0.25
 *   etherhide:web3_library_on_non_dapp            +0.20
 *   etherhide:dynamic_script_from_rpc_response    +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module EtherHidingGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const BLOCKCHAIN_RPC_ENDPOINTS = [
  'bsc-dataseed1.binance.org',
  'bsc-dataseed2.binance.org',
  'bsc-dataseed3.binance.org',
  'bsc-dataseed4.binance.org',
  'rpc.ankr.com',
  'bsc.publicnode.com',
  'bsc-rpc.publicnode.com',
  'eth.llamarpc.com',
  'cloudflare-eth.com',
  'mainnet.infura.io',
  'eth-mainnet.g.alchemy.com',
];

const ETH_CALL_METHODS = ['eth_call', 'eth_getCode', 'eth_getStorageAt'];

const CONTRACT_ADDRESS_PATTERN = /0x[a-fA-F0-9]{40}/;

const WEB3_LIB_PATTERNS = [/ethers\.js/i, /web3\.min\.js/i, /web3\.js/i, /ethers\.umd/i];

const DAPP_INDICATORS = [/connect\s*wallet/i, /web3modal/i, /walletconnect/i, /metamask/i, /uniswap/i, /opensea/i];

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

const rpcCalls = [];       // { url, hostname, method, responseText }
const injectionEvents = []; // { type: 'eval'|'innerHTML'|'documentWrite'|'dynamicScript', content }
const dynamicScripts = []; // { textContent }
let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if fetch/XHR made POST to known blockchain RPC endpoint with eth_call.
 */
function checkRpcCallToBlockchainEndpoint(calls) {
  if (!calls || calls.length === 0) return [];

  for (const call of calls) {
    const hostname = call.hostname || '';
    const isRpcEndpoint = BLOCKCHAIN_RPC_ENDPOINTS.some(ep =>
      hostname === ep || hostname.endsWith('.' + ep)
    );
    if (isRpcEndpoint && call.method) {
      return [{
        id: 'etherhide:rpc_call_to_blockchain_endpoint',
        weight: 0.40,
        hostname,
        method: call.method,
      }];
    }
  }

  return [];
}

/**
 * Check if RPC response content was injected into the DOM.
 */
function checkEthCallResponseInjected(calls, injections) {
  if (!calls || calls.length === 0 || !injections || injections.length === 0) return [];

  for (const call of calls) {
    if (!call.responseText || call.responseText.length < 20) continue;

    // Decode ABI response: strip first 128 hex chars (offset + length), hex-decode remainder
    const decoded = decodeAbiResponse(call.responseText);
    if (!decoded || decoded.length < 10) continue;

    for (const injection of injections) {
      const content = injection.content || '';
      if (content.length < 10) continue;

      // Check if decoded response substring appears in injected content
      const snippet = decoded.substring(0, 100);
      if (content.includes(snippet)) {
        return [{
          id: 'etherhide:eth_call_response_injected',
          weight: 0.30,
          injectionType: injection.type,
        }];
      }
    }
  }

  return [];
}

/**
 * Check for contract address (0x + 40 hex) in inline script alongside RPC method strings.
 */
function checkContractAddressInInlineScript(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    if (script.src) continue; // Skip external scripts
    const content = script.textContent || '';
    if (!content) continue;

    const hasAddress = CONTRACT_ADDRESS_PATTERN.test(content);
    const hasMethod = ETH_CALL_METHODS.some(m => content.includes(m));

    if (hasAddress && hasMethod) {
      return [{
        id: 'etherhide:contract_address_in_inline_script',
        weight: 0.25,
      }];
    }
  }

  return [];
}

/**
 * Check if web3/ethers library loaded on page with no DApp UI indicators.
 */
function checkWeb3LibraryOnNonDapp(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script[src]');
  let hasWeb3Lib = false;

  for (const script of scripts) {
    const src = script.src || '';
    if (WEB3_LIB_PATTERNS.some(p => p.test(src))) {
      hasWeb3Lib = true;
      break;
    }
  }

  if (!hasWeb3Lib) return [];

  // Check for DApp UI indicators in page text
  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  const hasDappUi = DAPP_INDICATORS.some(p => p.test(bodyText));

  if (!hasDappUi) {
    return [{
      id: 'etherhide:web3_library_on_non_dapp',
      weight: 0.20,
    }];
  }

  return [];
}

/**
 * Check if dynamic script content matches RPC response data.
 */
function checkDynamicScriptFromRpcResponse(calls, dynScripts) {
  if (!calls || calls.length === 0 || !dynScripts || dynScripts.length === 0) return [];

  for (const call of calls) {
    if (!call.responseText || call.responseText.length < 20) continue;

    const decoded = decodeAbiResponse(call.responseText);
    if (!decoded || decoded.length < 10) continue;

    for (const script of dynScripts) {
      const text = script.textContent || '';
      if (text.length < 10) continue;

      const snippet = decoded.substring(0, 100);
      if (text.includes(snippet)) {
        return [{
          id: 'etherhide:dynamic_script_from_rpc_response',
          weight: 0.15,
        }];
      }
    }
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  ABI Response Decoder                                               */
/* ------------------------------------------------------------------ */

/**
 * Decode ABI-encoded hex response from eth_call.
 * Strip first 128 hex chars (offset 64 + length 64), hex-decode remainder.
 */
function decodeAbiResponse(hexResult) {
  if (!hexResult || typeof hexResult !== 'string') return '';

  // Strip 0x prefix if present
  let hex = hexResult.startsWith('0x') ? hexResult.slice(2) : hexResult;

  // Need at least 128 hex chars for offset + length header, plus some payload
  if (hex.length < 130) return '';

  // Strip first 128 hex chars (64 bytes = offset + length)
  hex = hex.slice(128);

  // Hex decode remainder
  try {
    let decoded = '';
    for (let i = 0; i < hex.length - 1; i += 2) {
      const byte = parseInt(hex.substring(i, i + 2), 16);
      if (byte >= 32 && byte <= 126) {
        decoded += String.fromCharCode(byte);
      }
    }
    return decoded;
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateEtherHidingRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectEtherHidingWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-etherhiding-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-etherhiding-banner';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#0A0907', 'border-bottom:2px solid #BF1B1B',
    'padding:14px 20px',
    "font-family:'Work Sans',system-ui,-apple-system,sans-serif",
    'display:flex', 'align-items:center', 'gap:14px',
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:24px;flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B;font-size:15px;display:block;margin-bottom:3px;font-family:'Work Sans',system-ui,sans-serif;">
        blockchain payload delivery detected \u2014 phishops etherhidingguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('etherhide:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-etherhiding-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-etherhiding-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run full EtherHidingGuard analysis.
 */
function runEtherHidingAnalysis(doc, calls, injections, dynScripts) {
  if (!doc) return;

  const rpcSignals = checkRpcCallToBlockchainEndpoint(calls);
  const injectedSignals = checkEthCallResponseInjected(calls, injections);
  const contractSignals = checkContractAddressInInlineScript(doc);
  const web3Signals = checkWeb3LibraryOnNonDapp(doc);
  const dynamicSignals = checkDynamicScriptFromRpcResponse(calls, dynScripts);

  const allSignals = [
    ...rpcSignals,
    ...injectedSignals,
    ...contractSignals,
    ...web3Signals,
    ...dynamicSignals,
  ];

  if (allSignals.length === 0) return;

  const { riskScore, signalList } = calculateEtherHidingRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectEtherHidingWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'ETHERHIDINGGUARD_EVENT',
      payload: {
        eventType: 'ETHERHIDING_PAYLOAD_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Fetch / XHR Proxy Installer                                        */
/* ------------------------------------------------------------------ */

/**
 * Parse hostname from a URL string.
 */
function parseHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/**
 * Check if a JSON body contains an eth_call method.
 */
function extractRpcMethod(bodyText) {
  if (!bodyText || typeof bodyText !== 'string') return null;
  try {
    const parsed = JSON.parse(bodyText);
    const method = parsed.method || '';
    if (ETH_CALL_METHODS.includes(method)) return method;
  } catch { /* not JSON */ }
  return null;
}

/**
 * Install fetch and XHR proxies at document_start.
 */
function installEtherHidingProxy() {
  if (typeof window === 'undefined') return;

  // --- Wrap fetch ---
  if (window.fetch) {
    const originalFetch = window.fetch;

    window.fetch = async function(input, init) {
      const url = typeof input === 'string' ? input : (input?.url || '');
      const method = (init?.method || 'GET').toUpperCase();
      const hostname = parseHostname(url);

      const isRpcEndpoint = BLOCKCHAIN_RPC_ENDPOINTS.some(ep =>
        hostname === ep || hostname.endsWith('.' + ep)
      );

      if (method === 'POST' && isRpcEndpoint) {
        const bodyText = typeof init?.body === 'string' ? init.body : '';
        const rpcMethod = extractRpcMethod(bodyText);

        if (rpcMethod) {
          // Call original, clone response to read
          const response = await originalFetch.call(this, input, init);
          const cloned = response.clone();

          cloned.text().then(text => {
            let resultHex = '';
            try {
              const parsed = JSON.parse(text);
              resultHex = parsed.result || '';
            } catch { /* not JSON */ }

            rpcCalls.push({
              url,
              hostname,
              method: rpcMethod,
              responseText: resultHex,
            });
          }).catch(() => {});

          return response;
        }
      }

      return originalFetch.call(this, input, init);
    };
  }

  // --- Wrap XMLHttpRequest ---
  if (typeof XMLHttpRequest !== 'undefined') {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this._etherhiding_url = String(url);
      this._etherhiding_method = String(method).toUpperCase();
      return originalOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function(body) {
      const url = this._etherhiding_url || '';
      const httpMethod = this._etherhiding_method || 'GET';
      const hostname = parseHostname(url);

      const isRpcEndpoint = BLOCKCHAIN_RPC_ENDPOINTS.some(ep =>
        hostname === ep || hostname.endsWith('.' + ep)
      );

      if (httpMethod === 'POST' && isRpcEndpoint) {
        const bodyText = typeof body === 'string' ? body : '';
        const rpcMethod = extractRpcMethod(bodyText);

        if (rpcMethod) {
          this.addEventListener('load', function() {
            try {
              const text = this.responseText || '';
              let resultHex = '';
              try {
                const parsed = JSON.parse(text);
                resultHex = parsed.result || '';
              } catch { /* not JSON */ }

              rpcCalls.push({
                url,
                hostname,
                method: rpcMethod,
                responseText: resultHex,
              });
            } catch { /* non-critical */ }
          });
        }
      }

      return originalSend.call(this, body);
    };
  }

  // --- MutationObserver for dynamic scripts ---
  if (typeof document !== 'undefined' && typeof MutationObserver !== 'undefined') {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeName === 'SCRIPT' && !node.src) {
            const text = node.textContent || '';
            if (text.length > 0) {
              dynamicScripts.push({ textContent: text });
            }
          }
        }
      }
    });

    // Observe as soon as documentElement is available
    if (document.documentElement) {
      observer.observe(document.documentElement, { childList: true, subtree: true });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.documentElement, { childList: true, subtree: true });
      });
    }
  }

  // --- Monitor eval/innerHTML/document.write injections ---
  if (typeof window !== 'undefined') {
    // Wrap eval
    const originalEval = window.eval;
    window.eval = function(code) {
      if (typeof code === 'string' && code.length > 0) {
        injectionEvents.push({ type: 'eval', content: code.substring(0, 500) });
      }
      return originalEval.call(this, code);
    };

    // Wrap document.write
    if (typeof document !== 'undefined' && document.write) {
      const originalWrite = document.write.bind(document);
      document.write = function(html) {
        if (typeof html === 'string' && html.length > 0) {
          injectionEvents.push({ type: 'documentWrite', content: html.substring(0, 500) });
        }
        return originalWrite(html);
      };
    }
  }

  // --- Run analysis on DOMContentLoaded + 1s delay ---
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun) {
          analysisRun = true;
          runEtherHidingAnalysis(document, rpcCalls, injectionEvents, dynamicScripts);
        }
      }, 1000);
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

function _getRpcCalls() {
  return rpcCalls;
}

function _getInjectionEvents() {
  return injectionEvents;
}

function _getDynamicScripts() {
  return dynamicScripts;
}

function _resetState() {
  rpcCalls.length = 0;
  injectionEvents.length = 0;
  dynamicScripts.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installEtherHidingProxy();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['etherhiding_guard'] = {
    checkRpcCallToBlockchainEndpoint,
    checkEthCallResponseInjected,
    checkContractAddressInInlineScript,
    checkWeb3LibraryOnNonDapp,
    checkDynamicScriptFromRpcResponse,
    decodeAbiResponse,
    calculateEtherHidingRiskScore,
    injectEtherHidingWarningBanner,
    runEtherHidingAnalysis,
    parseHostname,
    installEtherHidingProxy,
    _getRpcCalls,
    _getInjectionEvents,
    _getDynamicScripts,
    _resetState,
  };
}
