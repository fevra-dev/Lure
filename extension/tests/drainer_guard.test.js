/**
 * extension/__tests__/drainer_guard.test.js
 *
 * Tests for DrainerGuard — Crypto Wallet Drainer Detection
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkDangerousEthMethodCall,
  checkApproveUnlimitedAllowance,
  checkMulticallBatchTransaction,
  checkKnownDrainerContract,
  checkAirdropClaimLure,
  calculateDrainerRiskScore,
  injectDrainerWarningBanner,
} from '../content/drainer_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkDangerousEthMethodCall                                         */
/* ================================================================== */

describe('checkDangerousEthMethodCall', () => {
  it('detects eth_sendTransaction in script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          window.ethereum.request({ method: 'eth_sendTransaction', params: [txObj] });
        </script>
      </body></html>
    `);
    const signals = checkDangerousEthMethodCall(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('drainer:dangerous_eth_method_call');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].method).toBe('eth_sendTransaction');
  });

  it('detects eth_signTypedData_v4', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          await provider.request({ method: 'eth_signTypedData_v4', params: [addr, data] });
        </script>
      </body></html>
    `);
    const signals = checkDangerousEthMethodCall(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].method).toBe('eth_signTypedData_v4');
  });

  it('detects personal_sign', () => {
    const doc = makeDoc(`
      <html><body>
        <script>ethereum.request({ method: 'personal_sign' });</script>
      </body></html>
    `);
    expect(checkDangerousEthMethodCall(doc)).toHaveLength(1);
  });

  it('does NOT flag eth_chainId (non-dangerous method)', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          ethereum.request({ method: 'eth_chainId' });
        </script>
      </body></html>
    `);
    expect(checkDangerousEthMethodCall(doc)).toHaveLength(0);
  });

  it('does NOT flag pages without ethereum calls', () => {
    const doc = makeDoc('<html><body><script>var x = 1;</script></body></html>');
    expect(checkDangerousEthMethodCall(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkDangerousEthMethodCall(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkApproveUnlimitedAllowance                                      */
/* ================================================================== */

describe('checkApproveUnlimitedAllowance', () => {
  it('detects approve selector + max uint256', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var data = '0x095ea7b3' + spender + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
        </script>
      </body></html>
    `);
    const signals = checkApproveUnlimitedAllowance(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('drainer:approve_unlimited_allowance');
    expect(signals[0].weight).toBe(0.35);
  });

  it('detects setApprovalForAll + max allowance', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var data = '0xa22cb465' + addr + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
        </script>
      </body></html>
    `);
    expect(checkApproveUnlimitedAllowance(doc)).toHaveLength(1);
  });

  it('does NOT flag approve without max allowance', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var data = '0x095ea7b3' + spender + '00000000000000000000000000000000000000000000000000000000000186a0';</script>
      </body></html>
    `);
    expect(checkApproveUnlimitedAllowance(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkApproveUnlimitedAllowance(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkMulticallBatchTransaction                                      */
/* ================================================================== */

describe('checkMulticallBatchTransaction', () => {
  it('detects multicall selector 0xac9650d8', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var calldata = '0xac9650d8' + encodedCalls;</script>
      </body></html>
    `);
    const signals = checkMulticallBatchTransaction(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('drainer:multicall_batch_transaction');
  });

  it('detects multicall selector 0x5ae401dc', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var data = '0x5ae401dc';</script>
      </body></html>
    `);
    expect(checkMulticallBatchTransaction(doc)).toHaveLength(1);
  });

  it('does NOT flag pages without multicall', () => {
    const doc = makeDoc('<html><body><script>var x = "0xdeadbeef";</script></body></html>');
    expect(checkMulticallBatchTransaction(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkMulticallBatchTransaction(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkKnownDrainerContract                                           */
/* ================================================================== */

describe('checkKnownDrainerContract', () => {
  it('detects known drainer address in script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var target = '0x00000000000000adc04c56bf30ac9d3c0aaf14dc';
        </script>
      </body></html>
    `);
    const signals = checkKnownDrainerContract(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('drainer:known_drainer_contract');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag unknown addresses', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var addr = '0x1234567890abcdef1234567890abcdef12345678';</script>
      </body></html>
    `);
    expect(checkKnownDrainerContract(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkKnownDrainerContract(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkAirdropClaimLure                                               */
/* ================================================================== */

describe('checkAirdropClaimLure', () => {
  it('detects airdrop lure + wallet connect text', () => {
    const doc = makeDoc(`
      <html><body>
        <h1>Claim your airdrop tokens now!</h1>
        <button>Connect Wallet</button>
      </body></html>
    `);
    const signals = checkAirdropClaimLure(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('drainer:airdrop_claim_lure');
    expect(signals[0].weight).toBe(0.15);
  });

  it('detects "free mint" + metamask reference', () => {
    const doc = makeDoc(`
      <html><body>
        <h1>Free mint available!</h1>
        <p>Connect your MetaMask to claim</p>
      </body></html>
    `);
    expect(checkAirdropClaimLure(doc)).toHaveLength(1);
  });

  it('does NOT flag lure text without wallet connect', () => {
    const doc = makeDoc(`
      <html><body>
        <h1>Claim your airdrop!</h1>
        <p>Just visit our website</p>
      </body></html>
    `);
    expect(checkAirdropClaimLure(doc)).toHaveLength(0);
  });

  it('does NOT flag wallet connect without lure text', () => {
    const doc = makeDoc(`
      <html><body>
        <h1>Welcome to DeFi</h1>
        <button>Connect Wallet</button>
      </body></html>
    `);
    expect(checkAirdropClaimLure(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkAirdropClaimLure(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateDrainerRiskScore                                           */
/* ================================================================== */

describe('calculateDrainerRiskScore', () => {
  it('returns 0 for no signals', () => {
    expect(calculateDrainerRiskScore([]).riskScore).toBe(0);
  });

  it('sums correctly', () => {
    const { riskScore } = calculateDrainerRiskScore([
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.35 },
    ]);
    expect(riskScore).toBeCloseTo(0.75, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.35 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    expect(calculateDrainerRiskScore(signals).riskScore).toBe(1.0);
  });
});

/* ================================================================== */
/*  injectDrainerWarningBanner                                          */
/* ================================================================== */

describe('injectDrainerWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectDrainerWarningBanner(0.75, [
      { id: 'drainer:dangerous_eth_method_call', weight: 0.40 },
    ]);

    const banner = dom.window.document.getElementById('phishops-drainer-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Crypto Wallet Drainer');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'drainer:test', weight: 0.50 }];
    injectDrainerWarningBanner(0.50, signals);
    injectDrainerWarningBanner(0.50, signals);

    expect(dom.window.document.querySelectorAll('#phishops-drainer-banner')).toHaveLength(1);
  });
});
