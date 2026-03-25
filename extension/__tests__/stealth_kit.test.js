/**
 * extension/__tests__/stealth_kit.test.js
 *
 * Tests for StealthKit — Proxy-based API wrapping utility.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

/* ------------------------------------------------------------------ */
/*  Bootstrap StealthKit in test environment                           */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  // Reset any prior StealthKit state
  if (globalThis.__PHISHOPS_STEALTH) {
    globalThis.__PHISHOPS_STEALTH._reset();
    delete globalThis.__PHISHOPS_STEALTH;
  }
});

function loadStealthKit() {
  delete globalThis.__PHISHOPS_STEALTH;
  // Re-run the IIFE by evaluating the module
  const fs = require('fs');
  const path = require('path');
  const code = fs.readFileSync(
    path.resolve(__dirname, '../lib/stealth_kit.js'),
    'utf8'
  );
  // eslint-disable-next-line no-eval
  eval(code);
  return globalThis.__PHISHOPS_STEALTH;
}

/* ================================================================== */
/*  Module Loading                                                     */
/* ================================================================== */

describe('StealthKit — Module Loading', () => {
  it('exposes globalThis.__PHISHOPS_STEALTH', () => {
    const sk = loadStealthKit();
    expect(sk).toBeDefined();
    expect(typeof sk.stealthWrap).toBe('function');
    expect(typeof sk.patchToString).toBe('function');
    expect(typeof sk.stripProxyFromErrors).toBe('function');
    expect(typeof sk.apply).toBe('function');
  });

  it('is frozen (immutable)', () => {
    const sk = loadStealthKit();
    expect(Object.isFrozen(sk)).toBe(true);
  });

  it('is idempotent — second load does not overwrite', () => {
    const sk1 = loadStealthKit();
    // Do NOT delete global before second load — test the guard clause
    const fs = require('fs');
    const path = require('path');
    const code = fs.readFileSync(
      path.resolve(__dirname, '../lib/stealth_kit.js'),
      'utf8'
    );
    eval(code);
    const sk2 = globalThis.__PHISHOPS_STEALTH;
    expect(sk1).toBe(sk2);
  });
});

/* ================================================================== */
/*  stealthWrap                                                        */
/* ================================================================== */

describe('StealthKit — stealthWrap', () => {
  it('wraps a function and calls the handler', () => {
    const sk = loadStealthKit();
    const calls = [];

    const obj = {
      myFn: function(a, b) { return a + b; },
    };

    sk.stealthWrap(obj, 'myFn', (target, thisArg, args) => {
      calls.push(args);
      return sk.apply(target, thisArg, args);
    });

    const result = obj.myFn(2, 3);
    expect(result).toBe(5);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual([2, 3]);
  });

  it('returns the proxy', () => {
    const sk = loadStealthKit();
    const obj = { fn: function() {} };
    const proxy = sk.stealthWrap(obj, 'fn', (t, _, a) => sk.apply(t, _, a));
    expect(proxy).toBe(obj.fn);
  });

  it('preserves typeof as function', () => {
    const sk = loadStealthKit();
    const obj = { fn: function() {} };
    sk.stealthWrap(obj, 'fn', (t, _, a) => sk.apply(t, _, a));
    expect(typeof obj.fn).toBe('function');
  });

  it('throws TypeError for non-function properties', () => {
    const sk = loadStealthKit();
    const obj = { val: 42 };
    expect(() => sk.stealthWrap(obj, 'val', () => {})).toThrow(TypeError);
  });

  it('handler receives correct target, thisArg, and args', () => {
    const sk = loadStealthKit();
    let captured = {};

    const obj = {
      greet: function(name) { return `hello ${name}`; },
    };

    sk.stealthWrap(obj, 'greet', (target, thisArg, args) => {
      captured = { target, thisArg, args: [...args] };
      return sk.apply(target, thisArg, args);
    });

    const result = obj.greet('world');
    expect(result).toBe('hello world');
    expect(captured.args).toEqual(['world']);
    expect(typeof captured.target).toBe('function');
  });

  it('works on prototype methods', () => {
    const sk = loadStealthKit();
    const calls = [];

    const proto = {
      doWork: function(x) { return x * 2; },
    };

    sk.stealthWrapProto(proto, 'doWork', (target, thisArg, args) => {
      calls.push('intercepted');
      return sk.apply(target, thisArg, args);
    });

    expect(proto.doWork(5)).toBe(10);
    expect(calls).toEqual(['intercepted']);
  });
});

/* ================================================================== */
/*  patchToString                                                      */
/* ================================================================== */

describe('StealthKit — patchToString', () => {
  it('patched toString returns native-looking string for wrapped functions', () => {
    const sk = loadStealthKit();
    const obj = {
      fetch: function fetch() { return 'native'; },
    };

    sk.stealthWrap(obj, 'fetch', (t, _, a) => sk.apply(t, _, a));
    sk.patchToString();

    const str = Function.prototype.toString.call(obj.fetch);
    // Should return the original function's toString, not the proxy's
    expect(str).toContain('fetch');
  });

  it('is idempotent — multiple calls do not throw', () => {
    const sk = loadStealthKit();
    sk.patchToString();
    sk.patchToString();
    expect(sk._isToStringPatched()).toBe(true);
  });

  it('non-wrapped functions still get normal toString', () => {
    const sk = loadStealthKit();
    sk.patchToString();

    function myFunc() { return 42; }
    const str = Function.prototype.toString.call(myFunc);
    expect(str).toContain('myFunc');
    expect(str).toContain('return 42');
  });

  it('toString of toString itself returns native-looking string', () => {
    const sk = loadStealthKit();
    sk.patchToString();

    const str = Function.prototype.toString.call(Function.prototype.toString);
    // The toString proxy is mapped to the original toString, so this
    // should return the original native toString string
    expect(str).toContain('toString');
  });
});

/* ================================================================== */
/*  Probe callback                                                     */
/* ================================================================== */

describe('StealthKit — Probe Callback', () => {
  it('fires onProbe when toString is called on a security API', () => {
    const sk = loadStealthKit();
    const probed = [];

    const obj = {
      fetch: function fetch() {},
    };

    sk.stealthWrap(obj, 'fetch', (t, _, a) => sk.apply(t, _, a), {
      securityApi: true,
    });

    sk.patchToString({
      onProbe: (fn) => probed.push(fn),
    });

    Function.prototype.toString.call(obj.fetch);
    expect(probed).toHaveLength(1);
  });

  it('does not fire onProbe for non-security APIs', () => {
    const sk = loadStealthKit();
    const probed = [];

    const obj = {
      helper: function helper() {},
    };

    sk.stealthWrap(obj, 'helper', (t, _, a) => sk.apply(t, _, a));
    sk.patchToString({ onProbe: (fn) => probed.push(fn) });

    Function.prototype.toString.call(obj.helper);
    expect(probed).toHaveLength(0);
  });

  it('can update probe callback on already-patched toString', () => {
    const sk = loadStealthKit();
    const probed1 = [];
    const probed2 = [];

    const obj = { fetch: function fetch() {} };
    sk.stealthWrap(obj, 'fetch', (t, _, a) => sk.apply(t, _, a), {
      securityApi: true,
    });

    sk.patchToString({ onProbe: (fn) => probed1.push(fn) });
    Function.prototype.toString.call(obj.fetch);
    expect(probed1).toHaveLength(1);

    sk.patchToString({ onProbe: (fn) => probed2.push(fn) });
    Function.prototype.toString.call(obj.fetch);
    expect(probed2).toHaveLength(1);
  });

  it('registerSecurityApi adds functions for probe tracking', () => {
    const sk = loadStealthKit();
    const probed = [];

    function myApi() {}
    sk.registerSecurityApi(myApi);
    sk.patchToString({ onProbe: (fn) => probed.push(fn) });

    Function.prototype.toString.call(myApi);
    expect(probed).toHaveLength(1);
  });
});

/* ================================================================== */
/*  stripProxyFromErrors                                               */
/* ================================================================== */

describe('StealthKit — stripProxyFromErrors', () => {
  it('removes Proxy-revealing lines from error stacks', () => {
    const sk = loadStealthKit();

    const fn = sk.stripProxyFromErrors(() => {
      const err = new Error('test error');
      err.stack = [
        'Error: test error',
        '    at Object.apply (eval at <anonymous>)',
        '    at Proxy.fetch (<anonymous>:1:1)',
        '    at Reflect.apply (<anonymous>:1:1)',
        '    at myCode (app.js:42:10)',
        '    at stealth_kit.js:100:5',
      ].join('\n');
      throw err;
    });

    try {
      fn();
    } catch (err) {
      const lines = err.stack.split('\n');
      expect(lines).toHaveLength(2); // Error line + myCode line
      expect(lines[0]).toBe('Error: test error');
      expect(lines[1]).toContain('myCode');
    }
  });

  it('passes through normally when no error', () => {
    const sk = loadStealthKit();
    const fn = sk.stripProxyFromErrors(() => 42);
    expect(fn()).toBe(42);
  });

  it('re-throws errors without stack unchanged', () => {
    const sk = loadStealthKit();
    const fn = sk.stripProxyFromErrors(() => {
      const err = new Error('no stack');
      delete err.stack;
      throw err;
    });

    expect(() => fn()).toThrow('no stack');
  });
});

/* ================================================================== */
/*  _reset (test helper)                                               */
/* ================================================================== */

describe('StealthKit — _reset', () => {
  it('restores native toString and clears patched flag', () => {
    const sk = loadStealthKit();
    sk.patchToString();
    expect(sk._isToStringPatched()).toBe(true);

    sk._reset();
    expect(sk._isToStringPatched()).toBe(false);
  });
});

/* ================================================================== */
/*  Edge cases                                                         */
/* ================================================================== */

describe('StealthKit — Edge Cases', () => {
  it('multiple wraps on different objects do not interfere', () => {
    const sk = loadStealthKit();
    const calls = { a: 0, b: 0 };

    const objA = { fn: function() { return 'A'; } };
    const objB = { fn: function() { return 'B'; } };

    sk.stealthWrap(objA, 'fn', (t, _, a) => { calls.a++; return sk.apply(t, _, a); });
    sk.stealthWrap(objB, 'fn', (t, _, a) => { calls.b++; return sk.apply(t, _, a); });

    expect(objA.fn()).toBe('A');
    expect(objB.fn()).toBe('B');
    expect(calls.a).toBe(1);
    expect(calls.b).toBe(1);
  });

  it('wrapped function preserves this binding', () => {
    const sk = loadStealthKit();

    const obj = {
      value: 99,
      getValue: function() { return this.value; },
    };

    sk.stealthWrap(obj, 'getValue', (target, thisArg, args) => {
      return sk.apply(target, thisArg, args);
    });

    expect(obj.getValue()).toBe(99);
  });

  it('handler can modify arguments before passing through', () => {
    const sk = loadStealthKit();

    const obj = {
      add: function(a, b) { return a + b; },
    };

    sk.stealthWrap(obj, 'add', (target, thisArg, args) => {
      return sk.apply(target, thisArg, [args[0] * 10, args[1]]);
    });

    expect(obj.add(2, 3)).toBe(23); // 20 + 3
  });

  it('handler can intercept and return early', () => {
    const sk = loadStealthKit();

    const obj = {
      fetch: function() { return 'original'; },
    };

    sk.stealthWrap(obj, 'fetch', () => 'blocked');

    expect(obj.fetch()).toBe('blocked');
  });
});
