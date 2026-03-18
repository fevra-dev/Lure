/**
 * extension/content/drainer_guard.js
 *
 * DrainerGuard — Crypto Wallet Drainer Detection
 *
 * Detects wallet drainer scripts that call window.ethereum.request() with
 * dangerous methods (eth_sendTransaction, eth_signTypedData_v4, eth_sign,
 * personal_sign) to trick users into signing malicious transactions.
 * $300M+ stolen via drainers in 2024 (Scam Sniffer). Major campaigns:
 * Inferno Drainer ($70M+), Angel Drainer, Pink Drainer.
 *
 * Signal architecture:
 *   drainer:dangerous_eth_method_call      +0.40
 *   drainer:approve_unlimited_allowance    +0.35
 *   drainer:multicall_batch_transaction    +0.25
 *   drainer:known_drainer_contract         +0.20
 *   drainer:airdrop_claim_lure             +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module DrainerGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const DANGEROUS_ETH_METHODS = [
  'eth_sendTransaction',
  'eth_signTypedData_v4',
  'eth_signTypedData_v3',
  'eth_signTypedData',
  'eth_sign',
  'personal_sign',
];

const APPROVE_SELECTOR = '0x095ea7b3'; // ERC-20 approve(address,uint256)
const SETAPPROVALFORALL_SELECTOR = '0xa22cb465'; // ERC-721/1155 setApprovalForAll
const MAX_UINT256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const MULTICALL_SELECTORS = ['0xac9650d8', '0x5ae401dc'];

const KNOWN_DRAINER_ADDRESSES = new Set([
  // Inferno Drainer contracts (representative samples from ScamSniffer reports)
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
  '0x0000000000001ff3684f28c67538d4d072c22734',
]);

const AIRDROP_LURE_PATTERNS = [
  /claim\s+(your\s+)?(airdrop|tokens|nft|reward)/i,
  /free\s+mint/i,
  /connect\s+wallet\s+to\s+(claim|receive|get)/i,
  /eligible\s+for\s+(airdrop|reward|distribution)/i,
];

const WALLET_CONNECT_PATTERNS = [
  /connect\s*wallet/i,
  /web3modal/i,
  /walletconnect/i,
  /metamask/i,
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if page scripts call dangerous ethereum methods.
 * Scans inline script content for method name references.
 */
export function checkDangerousEthMethodCall(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent || '';
    for (const method of DANGEROUS_ETH_METHODS) {
      if (content.includes(method)) {
        return [{
          id: 'drainer:dangerous_eth_method_call',
          weight: 0.40,
          method,
        }];
      }
    }
  }

  return [];
}

/**
 * Check for ERC-20 approve() with unlimited allowance (max uint256).
 * This is the signature of token approval drain attacks.
 */
export function checkApproveUnlimitedAllowance(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent || '';

    // Check for approve selector + max uint256
    const hasApprove = content.includes(APPROVE_SELECTOR) ||
      content.includes(SETAPPROVALFORALL_SELECTOR);
    const hasMaxAllowance = content.includes(MAX_UINT256) ||
      content.includes('0x' + MAX_UINT256);

    if (hasApprove && hasMaxAllowance) {
      return [{
        id: 'drainer:approve_unlimited_allowance',
        weight: 0.35,
        selector: content.includes(APPROVE_SELECTOR) ? 'approve' : 'setApprovalForAll',
      }];
    }
  }

  return [];
}

/**
 * Check for multicall/batch function selectors in script content.
 * Drainers batch multiple asset transfers in a single transaction.
 */
export function checkMulticallBatchTransaction(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent || '';
    for (const selector of MULTICALL_SELECTORS) {
      if (content.includes(selector)) {
        return [{
          id: 'drainer:multicall_batch_transaction',
          weight: 0.25,
          selector,
        }];
      }
    }
  }

  return [];
}

/**
 * Check if scripts reference known drainer contract addresses.
 */
export function checkKnownDrainerContract(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = (script.textContent || '').toLowerCase();
    for (const addr of KNOWN_DRAINER_ADDRESSES) {
      if (content.includes(addr)) {
        return [{
          id: 'drainer:known_drainer_contract',
          weight: 0.20,
          address: addr,
        }];
      }
    }
  }

  return [];
}

/**
 * Check for airdrop claim lure text near a wallet connect button/text.
 */
export function checkAirdropClaimLure(doc) {
  if (!doc || !doc.body) return [];

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';

  const hasLure = AIRDROP_LURE_PATTERNS.some(p => p.test(bodyText));
  const hasWalletConnect = WALLET_CONNECT_PATTERNS.some(p => p.test(bodyText));

  if (hasLure && hasWalletConnect) {
    return [{
      id: 'drainer:airdrop_claim_lure',
      weight: 0.15,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculateDrainerRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectDrainerWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-drainer-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-drainer-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected Crypto Wallet Drainer</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('drainer:', '')).join(', ')}
    </div>
    <button id="phishops-drainer-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-drainer-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

export function runDrainerGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  const doc = document;

  const methodSignals = checkDangerousEthMethodCall(doc);
  const approveSignals = checkApproveUnlimitedAllowance(doc);
  const multicallSignals = checkMulticallBatchTransaction(doc);
  const contractSignals = checkKnownDrainerContract(doc);
  const lureSignals = checkAirdropClaimLure(doc);

  const allSignals = [
    ...methodSignals,
    ...approveSignals,
    ...multicallSignals,
    ...contractSignals,
    ...lureSignals,
  ];

  const { riskScore, signalList } = calculateDrainerRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectDrainerWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'DRAINERGUARD_EVENT',
      payload: {
        eventType: 'CRYPTO_DRAINER_DETECTED',
        riskScore,
        severity,
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
  runDrainerGuardAnalysis();
}
