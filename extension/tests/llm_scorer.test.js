/**
 * extension/__tests__/llm_scorer.test.js
 *
 * Tests for LLMScorer — AI-Generated Phishing Page Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/llm_scorer.js';
const { checkUniformSentenceLength, checkUrgencyPhraseDensity, checkLowTypoRateWithCredForm, checkSlopPhraseDensity, checkRepetitiveDomStructure, checkAiMetaArtifacts, calculateLlmRiskScore, injectLlmWarningBanner } = globalThis.__phishopsExports['llm_scorer'];

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkUniformSentenceLength                                          */
/* ================================================================== */

describe('checkUniformSentenceLength', () => {
  it('detects LLM-typical uniform sentence lengths (low CV)', () => {
    // Generate 15 sentences all roughly 10 words long (very uniform)
    const sentences = Array.from({ length: 15 }, (_, i) =>
      `This is sentence number ${i} with exactly ten words total.`
    ).join(' ');
    const signals = checkUniformSentenceLength(sentences);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:uniform_sentence_length');
    expect(signals[0].weight).toBe(0.30);
  });

  it('does NOT flag human-written text with varied sentence lengths', () => {
    const humanText = [
      'Short one.',
      'This is a medium length sentence with a few more words added in.',
      'OK.',
      'Here is a longer sentence that has quite a few words in it to make the variation much higher than what an LLM would produce naturally.',
      'Another.',
      'Medium length goes here with extra words for padding.',
      'Tiny.',
      'Yet another sentence that is moderately long and adds some variety to the overall text.',
      'Yes.',
      'This sentence is deliberately different in length from the others to increase the coefficient of variation well above the threshold.',
      'No.',
    ].join(' ');
    const signals = checkUniformSentenceLength(humanText);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for text with fewer than 10 sentences', () => {
    const shortText = 'First sentence here. Second sentence here. Third one. Fourth. Fifth.';
    expect(checkUniformSentenceLength(shortText)).toHaveLength(0);
  });

  it('returns empty for empty/null input', () => {
    expect(checkUniformSentenceLength('')).toHaveLength(0);
    expect(checkUniformSentenceLength(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkUrgencyPhraseDensity                                           */
/* ================================================================== */

describe('checkUrgencyPhraseDensity', () => {
  it('detects high urgency phrase density', () => {
    const text = 'Your account has been suspended. Verify your identity immediately. ' +
      'Action required within 24 hours. Confirm your account. ' +
      'Unauthorized access detected on your account.';
    const signals = checkUrgencyPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:urgency_phrase_density');
    expect(signals[0].weight).toBe(0.25);
  });

  it('does NOT flag text with zero urgency phrases', () => {
    const text = 'Welcome to our website. We offer great products at reasonable prices. ' +
      'Browse our catalog and find what you need. Contact us for more information. ' +
      'Our team is here to help you with any questions.';
    expect(checkUrgencyPhraseDensity(text)).toHaveLength(0);
  });

  it('does NOT flag with only 1-2 urgency phrases in long text', () => {
    const text = 'Your account has been suspended. ' + 'A'.repeat(500) +
      ' Regular content continues here with nothing urgent at all.';
    expect(checkUrgencyPhraseDensity(text)).toHaveLength(0);
  });

  it('returns empty for short text (< 100 chars)', () => {
    expect(checkUrgencyPhraseDensity('Verify your identity immediately.')).toHaveLength(0);
  });

  it('returns empty for empty/null input', () => {
    expect(checkUrgencyPhraseDensity('')).toHaveLength(0);
    expect(checkUrgencyPhraseDensity(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLowTypoRateWithCredForm                                        */
/* ================================================================== */

describe('checkLowTypoRateWithCredForm', () => {
  it('detects clean text with credential fields (LLM indicator)', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password" />
        <input type="email" />
      </body></html>
    `);
    // 200+ words of perfectly spelled text
    const words = Array.from({ length: 210 }, (_, i) => `word${i}`).join(' ');
    const signals = checkLowTypoRateWithCredForm(doc, words);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:low_typo_rate_with_cred_form');
    expect(signals[0].weight).toBe(0.25);
  });

  it('does NOT flag text containing common typos', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password" />
      </body></html>
    `);
    const words = Array.from({ length: 210 }, (_, i) => `word${i}`).join(' ') +
      ' teh quick brown fox';
    expect(checkLowTypoRateWithCredForm(doc, words)).toHaveLength(0);
  });

  it('does NOT flag when no credential fields present', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const words = Array.from({ length: 210 }, (_, i) => `word${i}`).join(' ');
    expect(checkLowTypoRateWithCredForm(doc, words)).toHaveLength(0);
  });

  it('does NOT flag text with fewer than 200 words', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const words = Array.from({ length: 50 }, (_, i) => `word${i}`).join(' ');
    expect(checkLowTypoRateWithCredForm(doc, words)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkLowTypoRateWithCredForm(null, 'text')).toHaveLength(0);
    expect(checkLowTypoRateWithCredForm(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSlopPhraseDensity                                               */
/* ================================================================== */

describe('checkSlopPhraseDensity', () => {
  it('detects high-density AI slop phrases (>2.0 per 100 words) with +0.20 weight', () => {
    // ~50 words, 4 slop hits → density = 8.0 per 100 words
    const text = [
      'I hope this email finds you well.',
      'It is important to note that your account has been temporarily suspended.',
      'Kindly verify your credentials to restore access.',
      'Thank you for your continued cooperation.',
      'We value your business and trust.',
    ].join(' ');
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:slop_phrase_density');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].density).toBeGreaterThanOrEqual(2.0);
  });

  it('detects moderate-density slop phrases (>0.8) with +0.10 weight', () => {
    // 1 hit in ~120 words → density ≈ 0.83 per 100 words (between 0.8 and 2.0)
    const filler = Array.from({ length: 110 }, (_, i) => `neutral${i}`).join(' ');
    const text = `Kindly be advised that we need your attention. ${filler}`;
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:slop_phrase_density');
    expect(signals[0].weight).toBe(0.10);
  });

  it('detects throat-clearing openers', () => {
    const text = "In today's rapidly changing digital world, you must act now. " +
      Array.from({ length: 30 }, (_, i) => `word${i}`).join(' ');
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:slop_phrase_density');
  });

  it('detects formal register tells ("please be advised")', () => {
    const text = "Please be advised that your account requires verification. " +
      "As per our records, this is mandatory. " +
      Array.from({ length: 30 }, (_, i) => `word${i}`).join(' ');
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
  });

  it('detects credential lure formulae', () => {
    const text = "Your account has been locked. " +
      "Verify your identity by clicking the link below. " +
      "Failure to do so will result in permanent suspension. " +
      "For the security of your account, act immediately.";
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].hits).toBeGreaterThanOrEqual(3);
  });

  it('detects emphasis crutches ("delve into", "seamlessly")', () => {
    const text = "Let's delve into the details of your account security. " +
      "We provide a seamless experience for all our users. " +
      "Unlock the full potential of our platform today. " +
      Array.from({ length: 30 }, (_, i) => `word${i}`).join(' ');
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
  });

  it('detects performative wrap-up endings', () => {
    const text = Array.from({ length: 30 }, (_, i) => `word${i}`).join(' ') +
      " Thank you for your prompt attention. " +
      "Don't hesitate to contact us. " +
      "We appreciate your cooperation. " +
      "Stay safe online.";
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag clean human-written text', () => {
    const text = 'Hey, just a heads up — we noticed some unusual login attempts on your account ' +
      'from an IP in Eastern Europe. Changed your password yet? If not, I can walk you through it. ' +
      'The security team already blocked the IP but better safe than sorry. Let me know if you ' +
      'need anything. Cheers, Mike.';
    expect(checkSlopPhraseDensity(text)).toHaveLength(0);
  });

  it('does NOT flag text with zero slop phrases', () => {
    const text = Array.from({ length: 100 }, (_, i) => `word${i}`).join(' ');
    expect(checkSlopPhraseDensity(text)).toHaveLength(0);
  });

  it('returns empty for text shorter than 30 words', () => {
    const text = 'Kindly verify your account. Thank you for your cooperation.';
    expect(checkSlopPhraseDensity(text)).toHaveLength(0);
  });

  it('returns empty for empty/null input', () => {
    expect(checkSlopPhraseDensity('')).toHaveLength(0);
    expect(checkSlopPhraseDensity(null)).toHaveLength(0);
  });

  it('returns matched patterns in signal metadata', () => {
    const text = [
      'I hope this email finds you well.',
      'Kindly note that your account has been flagged.',
      'Verify your identity by clicking the link below.',
      'Failure to do so will result in account closure.',
      'For the security of your account please act now.',
      'Thank you for your continued patience.',
      'We value your trust and cooperation.',
    ].join(' ');
    const signals = checkSlopPhraseDensity(text);
    expect(signals).toHaveLength(1);
    expect(signals[0].matched).toBeDefined();
    expect(signals[0].matched.length).toBeGreaterThan(0);
  });
});

/* ================================================================== */
/*  checkRepetitiveDomStructure                                          */
/* ================================================================== */

describe('checkRepetitiveDomStructure', () => {
  it('detects 4+ identical sibling structures', () => {
    const doc = makeDoc(`
      <html><body>
        <div>
          <div><h3>Title 1</h3><p>Text 1</p></div>
          <div><h3>Title 2</h3><p>Text 2</p></div>
          <div><h3>Title 3</h3><p>Text 3</p></div>
          <div><h3>Title 4</h3><p>Text 4</p></div>
        </div>
      </body></html>
    `);
    const signals = checkRepetitiveDomStructure(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:repetitive_dom_structure');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].maxRepetition).toBeGreaterThanOrEqual(4);
  });

  it('does NOT flag varied sibling structures', () => {
    const doc = makeDoc(`
      <html><body>
        <div>
          <div><h3>Title</h3><p>Text</p></div>
          <div><span>Different</span></div>
          <section><h2>Also different</h2></section>
          <p>Just a paragraph</p>
        </div>
      </body></html>
    `);
    expect(checkRepetitiveDomStructure(doc)).toHaveLength(0);
  });

  it('does NOT flag container with fewer than 4 children', () => {
    const doc = makeDoc(`
      <html><body>
        <div>
          <div><h3>Title</h3><p>Text</p></div>
          <div><h3>Title</h3><p>Text</p></div>
          <div><h3>Title</h3><p>Text</p></div>
        </div>
      </body></html>
    `);
    expect(checkRepetitiveDomStructure(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkRepetitiveDomStructure(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkAiMetaArtifacts                                                */
/* ================================================================== */

describe('checkAiMetaArtifacts', () => {
  it('detects AI generator meta tag', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="generator" content="Generated by ChatGPT">
      </head><body></body></html>
    `);
    const signals = checkAiMetaArtifacts(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('llm:ai_meta_artifacts');
    expect(signals[0].source).toBe('meta_tag');
  });

  it('detects GPT-4 reference in meta content', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="description" content="Built with GPT-4 assistance">
      </head><body></body></html>
    `);
    expect(checkAiMetaArtifacts(doc)).toHaveLength(1);
  });

  it('detects AI reference in HTML comment', () => {
    const doc = makeDoc(`
      <html><head></head><body>
        <!-- Generated with OpenAI GPT -->
        <div>Content</div>
      </body></html>
    `);
    const signals = checkAiMetaArtifacts(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].source).toBe('html_comment');
  });

  it('does NOT flag pages without AI artifacts', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="generator" content="WordPress 6.4">
        <meta name="description" content="A normal website">
      </head><body>
        <!-- Standard HTML comment -->
      </body></html>
    `);
    expect(checkAiMetaArtifacts(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkAiMetaArtifacts(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateLlmRiskScore                                               */
/* ================================================================== */

describe('calculateLlmRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateLlmRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'llm:uniform_sentence_length', weight: 0.30 },
      { id: 'llm:urgency_phrase_density', weight: 0.25 },
    ];
    const { riskScore } = calculateLlmRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.55, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.30 },
      { id: 'b', weight: 0.25 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.15 },
    ];
    const { riskScore } = calculateLlmRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns null/empty for null input', () => {
    const { riskScore, signalList } = calculateLlmRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectLlmWarningBanner                                              */
/* ================================================================== */

describe('injectLlmWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectLlmWarningBanner(0.75, [
      { id: 'llm:uniform_sentence_length', weight: 0.30 },
      { id: 'llm:urgency_phrase_density', weight: 0.25 },
    ]);

    const banner = dom.window.document.getElementById('phishops-llm-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('AI-Generated Phishing');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'llm:test', weight: 0.50 }];
    injectLlmWarningBanner(0.50, signals);
    injectLlmWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-llm-banner');
    expect(banners).toHaveLength(1);
  });
});
