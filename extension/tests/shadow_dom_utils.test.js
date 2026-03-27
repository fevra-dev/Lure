import { describe, it, expect } from 'vitest';
import { JSDOM } from 'jsdom';
import { deepQuerySelectorAll } from '../lib/shadow_dom_utils.js';

function makeDoc(html = '') {
  return new JSDOM(`<!DOCTYPE html><html><body>${html}</body></html>`).window.document;
}

describe('deepQuerySelectorAll', () => {
  it('finds elements in the light DOM', () => {
    const doc = makeDoc('<input type="password" id="pw">');
    const results = deepQuerySelectorAll('input[type="password"]', doc);
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('pw');
  });

  it('returns empty array when no match', () => {
    const doc = makeDoc('<input type="text">');
    expect(deepQuerySelectorAll('input[type="password"]', doc)).toEqual([]);
  });

  it('finds elements inside an open shadow root', () => {
    const doc = makeDoc('<div id="host"></div>');
    const host = doc.getElementById('host');
    const shadow = host.attachShadow({ mode: 'open' });
    const input = doc.createElement('input');
    input.type = 'password';
    input.id = 'shadow-pw';
    shadow.appendChild(input);
    const results = deepQuerySelectorAll('input[type="password"]', doc);
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('shadow-pw');
  });

  it('finds elements in both light DOM and shadow root', () => {
    const doc = makeDoc('<input type="password" id="light-pw"><div id="host"></div>');
    const host = doc.getElementById('host');
    const shadow = host.attachShadow({ mode: 'open' });
    const input = doc.createElement('input');
    input.type = 'password';
    input.id = 'shadow-pw';
    shadow.appendChild(input);
    const results = deepQuerySelectorAll('input[type="password"]', doc);
    expect(results).toHaveLength(2);
    const ids = results.map(el => el.id);
    expect(ids).toContain('light-pw');
    expect(ids).toContain('shadow-pw');
  });

  it('traverses nested shadow roots', () => {
    const doc = makeDoc('<div id="outer"></div>');
    const outer = doc.getElementById('outer');
    const outerShadow = outer.attachShadow({ mode: 'open' });
    const inner = doc.createElement('div');
    inner.id = 'inner';
    outerShadow.appendChild(inner);
    const innerShadow = inner.attachShadow({ mode: 'open' });
    const input = doc.createElement('input');
    input.type = 'password';
    input.id = 'nested-pw';
    innerShadow.appendChild(input);
    const results = deepQuerySelectorAll('input[type="password"]', doc);
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('nested-pw');
  });

  it('respects depth limit of 5', () => {
    const doc = makeDoc('<div id="d0"></div>');
    let current = doc.getElementById('d0');
    for (let i = 1; i <= 7; i++) {
      const shadow = current.attachShadow({ mode: 'open' });
      const child = doc.createElement('div');
      child.id = `d${i}`;
      shadow.appendChild(child);
      if (i === 7) {
        const input = doc.createElement('input');
        input.type = 'password';
        shadow.appendChild(input);
      }
      current = child;
    }
    // Depth 7 exceeds limit of 5 — should NOT be found
    const results = deepQuerySelectorAll('input[type="password"]', doc);
    expect(results).toHaveLength(0);
  });

  it('handles document with no shadow roots', () => {
    const doc = makeDoc('<form><input type="text"><input type="password"></form>');
    expect(deepQuerySelectorAll('input[type="password"]', doc)).toHaveLength(1);
  });

  it('does not throw for normal selectors', () => {
    const doc = makeDoc('<input type="password">');
    expect(() => deepQuerySelectorAll('input[type="password"]', doc)).not.toThrow();
  });

  it('works with email inputs', () => {
    const doc = makeDoc('<div id="host"></div>');
    const host = doc.getElementById('host');
    const shadow = host.attachShadow({ mode: 'open' });
    const input = doc.createElement('input');
    input.type = 'email';
    shadow.appendChild(input);
    expect(deepQuerySelectorAll('input[type="email"]', doc)).toHaveLength(1);
  });

  it('handles shadow root with no matching elements', () => {
    const doc = makeDoc('<div id="host"></div>');
    const host = doc.getElementById('host');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.appendChild(doc.createElement('span'));
    expect(deepQuerySelectorAll('input[type="password"]', doc)).toHaveLength(0);
  });
});
