/**
 * extension/__tests__/etherhiding_guard.test.js
 *
 * Tests for EtherHidingGuard — Blockchain-Hosted Phishing Payload Delivery
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

import '../content/etherhiding_guard.js';
const { checkRpcCallToBlockchainEndpoint, checkEthCallResponseInjected, checkContractAddressInInlineScript, checkWeb3LibraryOnNonDapp, checkDynamicScriptFromRpcResponse, decodeAbiResponse, calculateEtherHidingRiskScore, injectEtherHidingWarningBanner, runEtherHidingAnalysis, parseHostname, _resetState } = globalThis.__phishopsExports['etherhiding_guard'];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function makeDoc(html = '<html><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeRpcCall(overrides = {}) {
  return {
    url: 'https://bsc-dataseed1.binance.org/',
    hostname: 'bsc-dataseed1.binance.org',
    method: 'eth_call',
    responseText: '',
    ...overrides,
  };
}

/**
 * Generate a hex-encoded ABI response with 128-char header + payload.
 */
function makeAbiResponse(payloadText) {
  // 64 chars offset + 64 chars length = 128 hex header
  const header = '0'.repeat(128);
  let hexPayload = '';
  for (let i = 0; i < payloadText.length; i++) {
    hexPayload += payloadText.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return '0x' + header + hexPayload;
}

/* ------------------------------------------------------------------ */
/*  Setup                                                              */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  _resetState();
});

/* ------------------------------------------------------------------ */
/*  checkRpcCallToBlockchainEndpoint                                   */
/* ------------------------------------------------------------------ */

describe('checkRpcCallToBlockchainEndpoint', () => {
  it('detects eth_call to BSC RPC endpoint', () => {
    const calls = [makeRpcCall()];
    const signals = checkRpcCallToBlockchainEndpoint(calls);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('etherhide:rpc_call_to_blockchain_endpoint');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].method).toBe('eth_call');
  });

  it('detects eth_getCode to Cloudflare ETH', () => {
    const calls = [makeRpcCall({ hostname: 'cloudflare-eth.com', method: 'eth_getCode' })];
    const signals = checkRpcCallToBlockchainEndpoint(calls);
    expect(signals).toHaveLength(1);
    expect(signals[0].method).toBe('eth_getCode');
  });

  it('detects eth_getStorageAt to Ankr', () => {
    const calls = [makeRpcCall({ hostname: 'rpc.ankr.com', method: 'eth_getStorageAt' })];
    const signals = checkRpcCallToBlockchainEndpoint(calls);
    expect(signals).toHaveLength(1);
  });

  it('returns empty for non-RPC hostname', () => {
    const calls = [makeRpcCall({ hostname: 'api.example.com' })];
    expect(checkRpcCallToBlockchainEndpoint(calls)).toEqual([]);
  });

  it('returns empty for null/empty input', () => {
    expect(checkRpcCallToBlockchainEndpoint(null)).toEqual([]);
    expect(checkRpcCallToBlockchainEndpoint([])).toEqual([]);
  });

  it('returns empty when method is null', () => {
    const calls = [makeRpcCall({ method: null })];
    expect(checkRpcCallToBlockchainEndpoint(calls)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkEthCallResponseInjected                                       */
/* ------------------------------------------------------------------ */

describe('checkEthCallResponseInjected', () => {
  it('detects response injected via eval', () => {
    const payload = '<script>alert("phish")</script>';
    const calls = [makeRpcCall({ responseText: makeAbiResponse(payload) })];
    const injections = [{ type: 'eval', content: payload }];
    const signals = checkEthCallResponseInjected(calls, injections);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('etherhide:eth_call_response_injected');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].injectionType).toBe('eval');
  });

  it('detects response injected via documentWrite', () => {
    const payload = '<div class="fake-login">Enter password</div>';
    const calls = [makeRpcCall({ responseText: makeAbiResponse(payload) })];
    const injections = [{ type: 'documentWrite', content: payload }];
    const signals = checkEthCallResponseInjected(calls, injections);
    expect(signals).toHaveLength(1);
  });

  it('returns empty when no correlation', () => {
    const calls = [makeRpcCall({ responseText: makeAbiResponse('hello world payload') })];
    const injections = [{ type: 'eval', content: 'completely different content' }];
    expect(checkEthCallResponseInjected(calls, injections)).toEqual([]);
  });

  it('returns empty for short responses', () => {
    const calls = [makeRpcCall({ responseText: '0x1234' })];
    const injections = [{ type: 'eval', content: 'test' }];
    expect(checkEthCallResponseInjected(calls, injections)).toEqual([]);
  });

  it('returns empty for null inputs', () => {
    expect(checkEthCallResponseInjected(null, [])).toEqual([]);
    expect(checkEthCallResponseInjected([], null)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkContractAddressInInlineScript                                 */
/* ------------------------------------------------------------------ */

describe('checkContractAddressInInlineScript', () => {
  it('detects contract address + eth_call in inline script', () => {
    const doc = makeDoc(`<html><body>
      <script>
        const addr = "0x1234567890abcdef1234567890abcdef12345678";
        fetch(rpc, { method: "eth_call", params: [{ to: addr }] });
      </script>
    </body></html>`);
    const signals = checkContractAddressInInlineScript(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('etherhide:contract_address_in_inline_script');
    expect(signals[0].weight).toBe(0.25);
  });

  it('returns empty without eth method', () => {
    const doc = makeDoc(`<html><body>
      <script>
        const addr = "0x1234567890abcdef1234567890abcdef12345678";
        console.log(addr);
      </script>
    </body></html>`);
    expect(checkContractAddressInInlineScript(doc)).toEqual([]);
  });

  it('returns empty without contract address', () => {
    const doc = makeDoc(`<html><body>
      <script>fetch(rpc, { method: "eth_call" });</script>
    </body></html>`);
    expect(checkContractAddressInInlineScript(doc)).toEqual([]);
  });

  it('skips external scripts', () => {
    const doc = makeDoc(`<html><body>
      <script src="https://cdn.example.com/etherhiding.js"></script>
    </body></html>`);
    expect(checkContractAddressInInlineScript(doc)).toEqual([]);
  });

  it('returns empty for null doc', () => {
    expect(checkContractAddressInInlineScript(null)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkWeb3LibraryOnNonDapp                                          */
/* ------------------------------------------------------------------ */

describe('checkWeb3LibraryOnNonDapp', () => {
  it('detects ethers.js on non-DApp page', () => {
    const doc = makeDoc(`<html><body>
      <script src="https://cdn.example.com/ethers.js"></script>
      <p>Click here to update your browser</p>
    </body></html>`);
    const signals = checkWeb3LibraryOnNonDapp(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('etherhide:web3_library_on_non_dapp');
    expect(signals[0].weight).toBe(0.20);
  });

  it('detects web3.min.js on non-DApp page', () => {
    const doc = makeDoc(`<html><body>
      <script src="https://cdn.example.com/web3.min.js"></script>
      <p>Some blog content here</p>
    </body></html>`);
    expect(checkWeb3LibraryOnNonDapp(doc)).toHaveLength(1);
  });

  it('returns empty when DApp indicators present', () => {
    const doc = makeDoc(`<html><body>
      <script src="https://cdn.example.com/ethers.js"></script>
      <button>Connect Wallet</button>
    </body></html>`);
    expect(checkWeb3LibraryOnNonDapp(doc)).toEqual([]);
  });

  it('returns empty without web3 library', () => {
    const doc = makeDoc(`<html><body>
      <script src="https://cdn.example.com/jquery.min.js"></script>
    </body></html>`);
    expect(checkWeb3LibraryOnNonDapp(doc)).toEqual([]);
  });

  it('returns empty for null doc', () => {
    expect(checkWeb3LibraryOnNonDapp(null)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkDynamicScriptFromRpcResponse                                  */
/* ------------------------------------------------------------------ */

describe('checkDynamicScriptFromRpcResponse', () => {
  it('detects dynamic script matching RPC response', () => {
    const payload = 'document.write("<form>steal creds</form>")';
    const calls = [makeRpcCall({ responseText: makeAbiResponse(payload) })];
    const dynScripts = [{ textContent: payload }];
    const signals = checkDynamicScriptFromRpcResponse(calls, dynScripts);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('etherhide:dynamic_script_from_rpc_response');
    expect(signals[0].weight).toBe(0.15);
  });

  it('returns empty when no correlation', () => {
    const calls = [makeRpcCall({ responseText: makeAbiResponse('payload A content here') })];
    const dynScripts = [{ textContent: 'completely unrelated script content' }];
    expect(checkDynamicScriptFromRpcResponse(calls, dynScripts)).toEqual([]);
  });

  it('returns empty for null inputs', () => {
    expect(checkDynamicScriptFromRpcResponse(null, [])).toEqual([]);
    expect(checkDynamicScriptFromRpcResponse([], null)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  decodeAbiResponse                                                  */
/* ------------------------------------------------------------------ */

describe('decodeAbiResponse', () => {
  it('decodes hex-encoded ABI response', () => {
    const payload = 'Hello phishing payload';
    const encoded = makeAbiResponse(payload);
    const decoded = decodeAbiResponse(encoded);
    expect(decoded).toBe(payload);
  });

  it('handles 0x prefix', () => {
    const payload = 'test';
    const encoded = makeAbiResponse(payload);
    expect(encoded.startsWith('0x')).toBe(true);
    expect(decodeAbiResponse(encoded)).toBe(payload);
  });

  it('handles without 0x prefix', () => {
    const payload = 'test';
    const encoded = makeAbiResponse(payload).slice(2); // Remove 0x
    expect(decodeAbiResponse(encoded)).toBe(payload);
  });

  it('returns empty for too-short input', () => {
    expect(decodeAbiResponse('0x1234')).toBe('');
  });

  it('returns empty for null/undefined', () => {
    expect(decodeAbiResponse(null)).toBe('');
    expect(decodeAbiResponse(undefined)).toBe('');
    expect(decodeAbiResponse('')).toBe('');
  });

  it('strips non-printable characters', () => {
    // Create hex with some non-printable bytes
    const header = '0'.repeat(128);
    const hex = '0x' + header + '41' + '01' + '42'; // A, \x01, B
    const decoded = decodeAbiResponse(hex);
    expect(decoded).toBe('AB'); // Non-printable byte skipped
  });
});

/* ------------------------------------------------------------------ */
/*  calculateEtherHidingRiskScore                                      */
/* ------------------------------------------------------------------ */

describe('calculateEtherHidingRiskScore', () => {
  it('sums signal weights', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
    ];
    const { riskScore, signalList } = calculateEtherHidingRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.70, 2);
    expect(signalList).toEqual(['a', 'b']);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    const { riskScore } = calculateEtherHidingRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for empty signals', () => {
    expect(calculateEtherHidingRiskScore([]).riskScore).toBe(0);
    expect(calculateEtherHidingRiskScore(null).riskScore).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/*  parseHostname                                                      */
/* ------------------------------------------------------------------ */

describe('parseHostname', () => {
  it('extracts hostname from URL', () => {
    expect(parseHostname('https://bsc-dataseed1.binance.org/')).toBe('bsc-dataseed1.binance.org');
  });

  it('returns empty for invalid URL', () => {
    expect(parseHostname('not-a-url')).toBe('');
  });
});

/* ------------------------------------------------------------------ */
/*  runEtherHidingAnalysis                                             */
/* ------------------------------------------------------------------ */

describe('runEtherHidingAnalysis', () => {
  it('emits telemetry when threshold exceeded', () => {
    const sendMessage = vi.fn().mockReturnValue(Promise.resolve());
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    const payload = '<script>alert("phish")</script>';
    const doc = makeDoc(`<html><body>
      <script>
        const addr = "0x1234567890abcdef1234567890abcdef12345678";
        fetch(rpc, { method: "eth_call" });
      </script>
    </body></html>`);

    const calls = [makeRpcCall({ responseText: makeAbiResponse(payload) })];
    const injections = [{ type: 'eval', content: payload }];

    runEtherHidingAnalysis(doc, calls, injections, []);

    expect(sendMessage).toHaveBeenCalledTimes(1);
    const msg = sendMessage.mock.calls[0][0];
    expect(msg.type).toBe('ETHERHIDINGGUARD_EVENT');
    expect(msg.payload.eventType).toBe('ETHERHIDING_PAYLOAD_DETECTED');
    expect(msg.payload.riskScore).toBeGreaterThanOrEqual(0.50);

    vi.unstubAllGlobals();
  });

  it('does not emit when below threshold', () => {
    const sendMessage = vi.fn().mockReturnValue(Promise.resolve());
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    const doc = makeDoc('<html><body><p>Safe page</p></body></html>');

    runEtherHidingAnalysis(doc, [], [], []);

    expect(sendMessage).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it('does not crash on null doc', () => {
    expect(() => runEtherHidingAnalysis(null, [], [], [])).not.toThrow();
  });
});

/* ------------------------------------------------------------------ */
/*  injectEtherHidingWarningBanner                                     */
/* ------------------------------------------------------------------ */

describe('injectEtherHidingWarningBanner', () => {
  it('creates banner in DOM', () => {
    const dom = new JSDOM('<html><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'etherhide:rpc_call_to_blockchain_endpoint', weight: 0.40 }];
    injectEtherHidingWarningBanner(0.70, signals);

    const banner = dom.window.document.getElementById('phishops-etherhiding-banner');
    expect(banner).not.toBeNull();
    expect(banner.innerHTML).toContain('blockchain payload delivery detected');

    vi.unstubAllGlobals();
  });

  it('does not create duplicate banners', () => {
    const dom = new JSDOM('<html><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'test', weight: 0.5 }];
    injectEtherHidingWarningBanner(0.70, signals);
    injectEtherHidingWarningBanner(0.70, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-etherhiding-banner');
    expect(banners.length).toBe(1);

    vi.unstubAllGlobals();
  });
});
