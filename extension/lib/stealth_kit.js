/**
 * extension/lib/stealth_kit.js
 *
 * StealthKit — Proxy-based API wrapping with toString patching + stack sanitisation.
 *
 * Provides hardened wrappers that defeat Function.prototype.toString detection,
 * typeof/name/length checks, and error stack trace analysis. Designed for use
 * in MAIN world content scripts where page scripts may probe for security tools.
 *
 * Exposes a frozen globalThis.__PHISHOPS_STEALTH namespace.
 *
 * @module StealthKit
 */

'use strict';

(function() {
  if (globalThis.__PHISHOPS_STEALTH) return; // idempotent

  /* ------------------------------------------------------------------ */
  /*  Phase 1: Preload native references before anything can tamper      */
  /* ------------------------------------------------------------------ */

  const _Reflect_apply = Reflect.apply;
  const _Reflect_get = Reflect.get;
  const _Object_defineProperty = Object.defineProperty;
  const _Object_getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const _nativeToString = Function.prototype.toString;
  const _nativeToStringStr = Function.prototype.toString.call(Function.prototype.toString);
  const _WeakMap = WeakMap;
  const _Set = Set;

  /* ------------------------------------------------------------------ */
  /*  Phase 2: Proxy→Original mapping                                    */
  /* ------------------------------------------------------------------ */

  /** @type {WeakMap<Function, Function>} proxy → original target */
  const _proxyMap = new _WeakMap();

  /** @type {Set<Function>} security-sensitive functions for probe detection */
  const _securityApis = new _Set();

  /** @type {Function|null} callback fired when toString is called on a security API */
  let _probeCallback = null;

  /** @type {boolean} whether patchToString has been applied */
  let _toStringPatched = false;

  /* ------------------------------------------------------------------ */
  /*  Phase 3: stripProxyFromErrors                                      */
  /* ------------------------------------------------------------------ */

  const STACK_FILTER_PATTERNS = [
    /\bProxy\b/,
    /\bReflect\.apply\b/,
    /\bObject\.apply\b/,
    /stealth_kit/,
  ];

  /**
   * Sanitise error stack traces by removing Proxy/Reflect-revealing frames.
   * @param {Function} fn - The function to wrap.
   * @returns {Function} Wrapped function with stack sanitisation.
   */
  function stripProxyFromErrors(fn) {
    return function() {
      try {
        return fn.apply(this, arguments);
      } catch (err) {
        if (err && err.stack) {
          const lines = err.stack.split('\n');
          err.stack = lines
            .filter(line => !STACK_FILTER_PATTERNS.some(p => p.test(line)))
            .join('\n');
        }
        throw err;
      }
    };
  }

  /* ------------------------------------------------------------------ */
  /*  Phase 4: patchToString                                             */
  /* ------------------------------------------------------------------ */

  /**
   * Patch Function.prototype.toString to return native-looking strings
   * for all Proxy-wrapped functions in the _proxyMap.
   *
   * @param {Object} [options]
   * @param {Function} [options.onProbe] - Callback fired when toString is
   *   called on a function in _securityApis. Receives the function as argument.
   */
  function patchToString(options) {
    if (_toStringPatched) {
      // Allow updating probe callback even if already patched
      if (options && typeof options.onProbe === 'function') {
        _probeCallback = options.onProbe;
      }
      return;
    }

    if (options && typeof options.onProbe === 'function') {
      _probeCallback = options.onProbe;
    }

    const toStringProxy = new Proxy(_nativeToString, {
      apply: function(target, thisArg, args) {
        // Check if this is a probe on a security API
        if (_probeCallback && _securityApis.has(thisArg)) {
          try { _probeCallback(thisArg); } catch { /* non-critical */ }
        }

        // If thisArg is a proxy we created, return the original's toString
        const original = _proxyMap.get(thisArg);
        if (original) {
          return _Reflect_apply(_nativeToString, original, args);
        }

        return _Reflect_apply(target, thisArg, args);
      },
    });

    // Map the toString proxy itself so its own toString returns [native code]
    _proxyMap.set(toStringProxy, _nativeToString);

    _Object_defineProperty(Function.prototype, 'toString', {
      value: toStringProxy,
      writable: true,
      configurable: true,
      enumerable: false,
    });

    _toStringPatched = true;
  }

  /* ------------------------------------------------------------------ */
  /*  Phase 5: stealthWrap                                               */
  /* ------------------------------------------------------------------ */

  /**
   * Replace obj[prop] with a Proxy-based wrapper that passes toString,
   * typeof, name, and length checks.
   *
   * @param {Object} obj - The object owning the property (e.g. window).
   * @param {string} prop - The property name (e.g. 'fetch').
   * @param {Function} handler - Proxy apply trap: (target, thisArg, args) => result.
   *   Call `sk.apply(target, thisArg, args)` to invoke the original.
   * @param {Object} [options]
   * @param {boolean} [options.securityApi] - If true, register this API for
   *   probe detection (toString calls on it will trigger the probe callback).
   * @returns {Proxy} The proxy that replaced the original function.
   */
  function stealthWrap(obj, prop, handler, options) {
    const original = obj[prop];
    if (typeof original !== 'function') {
      throw new TypeError(`stealthWrap: ${prop} is not a function`);
    }

    const safeHandler = stripProxyFromErrors(handler);

    const proxy = new Proxy(original, {
      apply: function(target, thisArg, args) {
        return safeHandler.call(null, target, thisArg, args);
      },
    });

    // Store mapping for toString patching
    _proxyMap.set(proxy, original);

    // Register as security API if requested
    if (options && options.securityApi) {
      _securityApis.add(proxy);
      // Also track the original so probes on either reference trigger
      _securityApis.add(original);
    }

    // Replace the property, preserving the original descriptor flags
    const desc = _Object_getOwnPropertyDescriptor(obj, prop);
    if (desc && desc.configurable !== false) {
      _Object_defineProperty(obj, prop, {
        value: proxy,
        writable: desc.writable !== false,
        configurable: desc.configurable !== false,
        enumerable: desc.enumerable === true,
      });
    } else {
      // Fallback for non-configurable properties (e.g. on prototypes)
      try {
        obj[prop] = proxy;
      } catch { /* best-effort */ }
    }

    return proxy;
  }

  /* ------------------------------------------------------------------ */
  /*  Phase 6: Prototype-level stealthWrap                               */
  /* ------------------------------------------------------------------ */

  /**
   * Replace a method on a prototype with a Proxy-based wrapper.
   * Convenience wrapper around stealthWrap for prototype methods.
   *
   * @param {Object} proto - The prototype (e.g. EventTarget.prototype).
   * @param {string} method - The method name (e.g. 'addEventListener').
   * @param {Function} handler - Proxy apply trap.
   * @param {Object} [options] - Same options as stealthWrap.
   * @returns {Proxy} The proxy.
   */
  function stealthWrapProto(proto, method, handler, options) {
    return stealthWrap(proto, method, handler, options);
  }

  /* ------------------------------------------------------------------ */
  /*  Phase 7: Expose frozen namespace                                   */
  /* ------------------------------------------------------------------ */

  const StealthKit = Object.freeze({
    /** Cached Reflect.apply — use instead of target.apply for safety */
    apply: _Reflect_apply,

    /** Cached Reflect.get */
    get: _Reflect_get,

    /** Patch Function.prototype.toString for all wrapped functions */
    patchToString,

    /** Wrap obj[prop] with a stealth Proxy */
    stealthWrap,

    /** Wrap proto[method] with a stealth Proxy (convenience) */
    stealthWrapProto,

    /** Sanitise a function's error stack traces */
    stripProxyFromErrors,

    /** Register a function as a security-sensitive API for probe detection */
    registerSecurityApi(fn) {
      if (typeof fn === 'function') _securityApis.add(fn);
    },

    /* -- Test-only accessors ----------------------------------------- */
    _getProxyMap() { return _proxyMap; },
    _getSecurityApis() { return _securityApis; },
    _isToStringPatched() { return _toStringPatched; },
    _reset() {
      _toStringPatched = false;
      _probeCallback = null;
      // Restore native toString if patched
      _Object_defineProperty(Function.prototype, 'toString', {
        value: _nativeToString,
        writable: true,
        configurable: true,
        enumerable: false,
      });
    },
  });

  globalThis.__PHISHOPS_STEALTH = StealthKit;
})();
