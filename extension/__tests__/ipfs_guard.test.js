/**
 * extension/__tests__/ipfs_guard.test.js
 *
 * Tests for IPFSGuard — IPFS Gateway Phishing Detection
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkGatewayHostedPage,
  checkCredentialOnGateway,
  checkCidInUrl,
  checkExternalIpfsLinks,
  checkSuspiciousIpfsContent,
  calculateIpfsRiskScore,
  injectIpfsWarningBanner,
} from '../content/ipfs_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

/* ================================================================== */
/*  checkGatewayHostedPage                                             */
/* ================================================================== */

describe('checkGatewayHostedPage', () => {
  it('detects ipfs.io gateway', () => {
    const signals = checkGatewayHostedPage('ipfs.io');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ipfs:gateway_hosted_page');
    expect(signals[0].weight).toBe(0.35);
  });

  it('detects cloudflare-ipfs.com gateway', () => {
    const signals = checkGatewayHostedPage('cloudflare-ipfs.com');
    expect(signals).toHaveLength(1);
  });

  it('detects subdomain of gateway (bafyxxx.ipfs.dweb.link)', () => {
    const signals = checkGatewayHostedPage('bafyxxx.ipfs.dweb.link');
    expect(signals).toHaveLength(1);
  });

  it('detects gateway.pinata.cloud', () => {
    const signals = checkGatewayHostedPage('gateway.pinata.cloud');
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag non-gateway domain', () => {
    expect(checkGatewayHostedPage('example.com')).toHaveLength(0);
    expect(checkGatewayHostedPage('google.com')).toHaveLength(0);
  });

  it('returns empty for null/empty', () => {
    expect(checkGatewayHostedPage(null)).toHaveLength(0);
    expect(checkGatewayHostedPage('')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCredentialOnGateway                                           */
/* ================================================================== */

describe('checkCredentialOnGateway', () => {
  it('detects password field on gateway', () => {
    const doc = makeDoc('<html><body><input type="password"></body></html>');
    const signals = checkCredentialOnGateway(doc, 'ipfs.io');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ipfs:credential_on_gateway');
    expect(signals[0].weight).toBe(0.30);
  });

  it('detects email field on gateway', () => {
    const doc = makeDoc('<html><body><input type="email"></body></html>');
    const signals = checkCredentialOnGateway(doc, 'cloudflare-ipfs.com');
    expect(signals).toHaveLength(1);
  });

  it('does NOT fire on non-gateway domain', () => {
    const doc = makeDoc('<html><body><input type="password"></body></html>');
    const signals = checkCredentialOnGateway(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text"></body></html>');
    const signals = checkCredentialOnGateway(doc, 'ipfs.io');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCredentialOnGateway(null, 'ipfs.io')).toHaveLength(0);
    expect(checkCredentialOnGateway(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCidInUrl                                                      */
/* ================================================================== */

describe('checkCidInUrl', () => {
  it('detects CIDv0 pattern (Qm...)', () => {
    const url = 'https://ipfs.io/ipfs/QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX';
    const signals = checkCidInUrl(url);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ipfs:cid_in_url');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects CIDv1 pattern (bafy...)', () => {
    const url = 'https://dweb.link/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
    const signals = checkCidInUrl(url);
    expect(signals).toHaveLength(1);
  });

  it('detects CIDv1 bafk pattern', () => {
    const url = 'https://w3s.link/ipfs/bafkreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
    const signals = checkCidInUrl(url);
    expect(signals).toHaveLength(1);
  });

  it('does NOT fire on URL without CID', () => {
    expect(checkCidInUrl('https://example.com/page')).toHaveLength(0);
    expect(checkCidInUrl('https://ipfs.io/')).toHaveLength(0);
  });

  it('returns empty for null/empty', () => {
    expect(checkCidInUrl(null)).toHaveLength(0);
    expect(checkCidInUrl('')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkExternalIpfsLinks                                             */
/* ================================================================== */

describe('checkExternalIpfsLinks', () => {
  it('fires when 2+ links to IPFS gateways', () => {
    const doc = makeDoc(`
      <html><body>
        <a href="https://ipfs.io/ipfs/QmTest1234567890123456789012345678901234567890">Link 1</a>
        <a href="https://dweb.link/ipfs/QmTest1234567890123456789012345678901234567891">Link 2</a>
      </body></html>
    `);
    const signals = checkExternalIpfsLinks(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ipfs:external_ipfs_links');
    expect(signals[0].linkCount).toBe(2);
  });

  it('fires when links contain CID patterns', () => {
    const doc = makeDoc(`
      <html><body>
        <a href="https://example.com/QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX">A</a>
        <a href="https://other.com/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi">B</a>
      </body></html>
    `);
    const signals = checkExternalIpfsLinks(doc);
    expect(signals).toHaveLength(1);
  });

  it('does NOT fire with only 1 IPFS link', () => {
    const doc = makeDoc('<html><body><a href="https://ipfs.io/page">Link</a></body></html>');
    const signals = checkExternalIpfsLinks(doc);
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire with no links', () => {
    const doc = makeDoc('<html><body><p>No links</p></body></html>');
    expect(checkExternalIpfsLinks(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkExternalIpfsLinks(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSuspiciousIpfsContent                                         */
/* ================================================================== */

describe('checkSuspiciousIpfsContent', () => {
  it('detects Microsoft brand keywords on gateway', () => {
    const doc = makeDoc('<html><head><title>Microsoft Login</title></head><body>Microsoft account</body></html>');
    const signals = checkSuspiciousIpfsContent(doc, 'ipfs.io');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ipfs:suspicious_ipfs_content');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].matchedBrand).toBe('microsoft');
  });

  it('detects PayPal brand on gateway', () => {
    const doc = makeDoc('<html><body>PayPal verification required</body></html>');
    const signals = checkSuspiciousIpfsContent(doc, 'cloudflare-ipfs.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('paypal');
  });

  it('does NOT fire on non-gateway domain', () => {
    const doc = makeDoc('<html><body>Microsoft login</body></html>');
    expect(checkSuspiciousIpfsContent(doc, 'example.com')).toHaveLength(0);
  });

  it('does NOT fire without brand keywords', () => {
    const doc = makeDoc('<html><body>Welcome to our page</body></html>');
    expect(checkSuspiciousIpfsContent(doc, 'ipfs.io')).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkSuspiciousIpfsContent(null, 'ipfs.io')).toHaveLength(0);
    expect(checkSuspiciousIpfsContent(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateIpfsRiskScore                                             */
/* ================================================================== */

describe('calculateIpfsRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const { riskScore, signalList } = calculateIpfsRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    expect(calculateIpfsRiskScore(null).riskScore).toBe(0);
  });

  it('scores gateway + credential correctly', () => {
    const { riskScore } = calculateIpfsRiskScore([
      { id: 'ipfs:gateway_hosted_page', weight: 0.35 },
      { id: 'ipfs:credential_on_gateway', weight: 0.30 },
    ]);
    expect(riskScore).toBeCloseTo(0.65);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateIpfsRiskScore([
      { id: 'a', weight: 0.35 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.15 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('returns signal list', () => {
    const { signalList } = calculateIpfsRiskScore([
      { id: 'ipfs:gateway_hosted_page', weight: 0.35 },
      { id: 'ipfs:cid_in_url', weight: 0.25 },
    ]);
    expect(signalList).toEqual(['ipfs:gateway_hosted_page', 'ipfs:cid_in_url']);
  });
});

/* ================================================================== */
/*  injectIpfsWarningBanner                                            */
/* ================================================================== */

describe('injectIpfsWarningBanner', () => {
  let dom, doc;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    doc = dom.window.document;
    vi.stubGlobal('document', doc);
  });

  it('injects banner into document', () => {
    injectIpfsWarningBanner(0.80, [
      { id: 'ipfs:gateway_hosted_page', matchedBrand: 'microsoft' },
    ]);
    const banner = doc.getElementById('phishops-ipfs-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('IPFS Phishing');
    expect(banner.textContent).toContain('Microsoft');
  });

  it('is idempotent', () => {
    injectIpfsWarningBanner(0.80, [{ id: 'a' }]);
    injectIpfsWarningBanner(0.80, [{ id: 'a' }]);
    const banners = doc.querySelectorAll('#phishops-ipfs-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays correct severity', () => {
    injectIpfsWarningBanner(0.95, [{ id: 'a' }]);
    const banner = doc.getElementById('phishops-ipfs-banner');
    expect(banner.textContent).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    injectIpfsWarningBanner(0.70, [{ id: 'a' }]);
    const dismiss = doc.getElementById('phishops-ipfs-dismiss');
    dismiss.click();
    expect(doc.getElementById('phishops-ipfs-banner')).toBeNull();
  });
});
