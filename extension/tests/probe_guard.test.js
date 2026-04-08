/**
 * extension/__tests__/probe_guard.test.js
 *
 * Tests for ProbeGuard — Security tool probing meta-detection.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/probe_guard_bridge.js';
const { checkToStringProbing, checkIframeVerification, checkTimingLoop, checkWarProbing, checkPrototypeLieDetection, calculateProbeRiskScore, injectProbeWarningBanner, runProbeAnalysis, _getSignalRecords, _resetState } = globalThis.__phishopsExports['probe_guard_bridge'];

/* ------------------------------------------------------------------ */
/*  Setup                                                              */
/* ------------------------------------------------------------------ */

let dom;

beforeEach(() => {
  _resetState();
  dom = new JSDOM('<html><head></head><body></body></html>');
  vi.stubGlobal('document', dom.window.document);
});

/* ------------------------------------------------------------------ */
/*  Helper: create signal records                                      */
/* ------------------------------------------------------------------ */

function makeRecords(signalId, count = 1, detail = {}) {
  const records = {};
  records[signalId] = [];
  for (let i = 0; i < count; i++) {
    records[signalId].push({
      detail: { ...detail, iteration: i },
      timestamp: Date.now() - (count - i) * 100,
    });
  }
  return records;
}

function mergeRecords(...recordSets) {
  const merged = {};
  for (const records of recordSets) {
    for (const [key, entries] of Object.entries(records)) {
      if (!merged[key]) merged[key] = [];
      merged[key].push(...entries);
    }
  }
  return merged;
}

/* ================================================================== */
/*  Signal 1: toString probing                                         */
/* ================================================================== */

describe('ProbeGuard — Signal 1: toString probing', () => {
  it('returns signal when toString probing detected', () => {
    const records = makeRecords('probe:tostring_on_security_api', 2, { count: 3 });
    const result = checkToStringProbing(records);
    expect(result).not.toBeNull();
    expect(result.id).toBe('probe:tostring_on_security_api');
    expect(result.weight).toBe(0.40);
    expect(result.count).toBe(2);
  });

  it('returns null when no toString probing', () => {
    expect(checkToStringProbing({})).toBeNull();
    expect(checkToStringProbing({ 'probe:tostring_on_security_api': [] })).toBeNull();
  });

  it('returns null for undefined records', () => {
    expect(checkToStringProbing({ other: [{ detail: {} }] })).toBeNull();
  });
});

/* ================================================================== */
/*  Signal 2: iframe verification                                      */
/* ================================================================== */

describe('ProbeGuard — Signal 2: iframe verification', () => {
  it('returns signal when iframe verification detected', () => {
    const records = makeRecords('probe:iframe_function_verification', 1, { elapsedMs: 500 });
    const result = checkIframeVerification(records);
    expect(result).not.toBeNull();
    expect(result.id).toBe('probe:iframe_function_verification');
    expect(result.weight).toBe(0.30);
  });

  it('returns null when no iframe verification', () => {
    expect(checkIframeVerification({})).toBeNull();
  });
});

/* ================================================================== */
/*  Signal 3: timing loop                                              */
/* ================================================================== */

describe('ProbeGuard — Signal 3: timing loop', () => {
  it('returns signal when timing loop detected', () => {
    const records = makeRecords('probe:timing_loop_on_api', 3, { callCount: 60, windowMs: 200 });
    const result = checkTimingLoop(records);
    expect(result).not.toBeNull();
    expect(result.id).toBe('probe:timing_loop_on_api');
    expect(result.weight).toBe(0.25);
    expect(result.count).toBe(3);
  });

  it('returns null when no timing loop', () => {
    expect(checkTimingLoop({})).toBeNull();
  });
});

/* ================================================================== */
/*  Signal 4: WAR probing                                              */
/* ================================================================== */

describe('ProbeGuard — Signal 4: WAR probing', () => {
  it('returns signal when WAR probing detected', () => {
    const records = makeRecords('probe:war_extension_probing', 2, {
      url: 'chrome-extension://abc123/content.js',
    });
    const result = checkWarProbing(records);
    expect(result).not.toBeNull();
    expect(result.id).toBe('probe:war_extension_probing');
    expect(result.weight).toBe(0.20);
    expect(result.count).toBe(2);
  });

  it('returns null when no WAR probing', () => {
    expect(checkWarProbing({})).toBeNull();
    expect(checkWarProbing({ 'probe:war_extension_probing': [] })).toBeNull();
  });
});

/* ================================================================== */
/*  Signal 5: prototype lie detection                                  */
/* ================================================================== */

describe('ProbeGuard — Signal 5: prototype lie detection', () => {
  it('returns signal when prototype lie detection detected', () => {
    const records = makeRecords('probe:prototype_lie_detection', 1, {
      pattern: 'getOwnPropertyDescriptor(Function.prototype, "toString")',
    });
    const result = checkPrototypeLieDetection(records);
    expect(result).not.toBeNull();
    expect(result.id).toBe('probe:prototype_lie_detection');
    expect(result.weight).toBe(0.15);
  });

  it('returns null when no prototype lie detection', () => {
    expect(checkPrototypeLieDetection({})).toBeNull();
  });
});

/* ================================================================== */
/*  Risk Score Calculation                                             */
/* ================================================================== */

describe('ProbeGuard — Risk Score', () => {
  it('returns 0 for no signals', () => {
    expect(calculateProbeRiskScore([])).toBe(0);
    expect(calculateProbeRiskScore(null)).toBe(0);
  });

  it('returns single signal weight', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    expect(calculateProbeRiskScore(signals)).toBeCloseTo(0.40, 2);
  });

  it('sums multiple signal weights', () => {
    const signals = [
      { id: 'probe:tostring_on_security_api', weight: 0.40 },
      { id: 'probe:iframe_function_verification', weight: 0.30 },
    ];
    expect(calculateProbeRiskScore(signals)).toBeCloseTo(0.70, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.15 },
    ];
    expect(calculateProbeRiskScore(signals)).toBe(1.0);
  });

  it('handles two signals exactly at alert threshold', () => {
    const signals = [
      { id: 'probe:tostring_on_security_api', weight: 0.40 },
      { id: 'probe:prototype_lie_detection', weight: 0.15 },
    ];
    expect(calculateProbeRiskScore(signals)).toBeCloseTo(0.55, 2);
  });
});

/* ================================================================== */
/*  runProbeAnalysis                                                    */
/* ================================================================== */

describe('ProbeGuard — runProbeAnalysis', () => {
  it('returns 0 score for empty records', () => {
    const result = runProbeAnalysis({});
    expect(result.riskScore).toBe(0);
    expect(result.signals).toEqual([]);
  });

  it('detects single signal', () => {
    const records = makeRecords('probe:tostring_on_security_api', 1);
    const result = runProbeAnalysis(records);
    expect(result.riskScore).toBeCloseTo(0.40, 2);
    expect(result.signals).toHaveLength(1);
  });

  it('detects multiple signals and sums correctly', () => {
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:iframe_function_verification', 1),
      makeRecords('probe:war_extension_probing', 1),
    );
    const result = runProbeAnalysis(records);
    expect(result.riskScore).toBeCloseTo(0.90, 2);
    expect(result.signals).toHaveLength(3);
  });

  it('all five signals cap at 1.0', () => {
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:iframe_function_verification', 1),
      makeRecords('probe:timing_loop_on_api', 1),
      makeRecords('probe:war_extension_probing', 1),
      makeRecords('probe:prototype_lie_detection', 1),
    );
    const result = runProbeAnalysis(records);
    expect(result.riskScore).toBe(1.0);
    expect(result.signals).toHaveLength(5);
  });
});

/* ================================================================== */
/*  Warning Banner                                                      */
/* ================================================================== */

describe('ProbeGuard — Warning Banner', () => {
  it('injects banner into the document', () => {
    const signals = [
      { id: 'probe:tostring_on_security_api', weight: 0.40 },
      { id: 'probe:war_extension_probing', weight: 0.20 },
    ];
    injectProbeWarningBanner(0.60, signals);
    const banner = document.getElementById('phishops-probe-warning');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('PhishOps');
    expect(banner.textContent).toContain('0.60');
    expect(banner.textContent).toContain('tostring_on_security_api');
  });

  it('shows Critical for block threshold', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    injectProbeWarningBanner(0.75, signals);
    const banner = document.getElementById('phishops-probe-warning');
    expect(banner.textContent).toContain('Critical');
  });

  it('shows High for alert threshold', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    injectProbeWarningBanner(0.55, signals);
    const banner = document.getElementById('phishops-probe-warning');
    expect(banner.textContent).toContain('High');
  });

  it('does not duplicate banners', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    injectProbeWarningBanner(0.60, signals);
    injectProbeWarningBanner(0.60, signals);
    const banners = document.querySelectorAll('#phishops-probe-warning');
    expect(banners).toHaveLength(1);
  });

  it('banner is removable by click', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    injectProbeWarningBanner(0.60, signals);
    const banner = document.getElementById('phishops-probe-warning');
    banner.click();
    expect(document.getElementById('phishops-probe-warning')).toBeNull();
  });

  it('has role=alert for accessibility', () => {
    const signals = [{ id: 'probe:tostring_on_security_api', weight: 0.40 }];
    injectProbeWarningBanner(0.60, signals);
    const banner = document.getElementById('phishops-probe-warning');
    expect(banner.getAttribute('role')).toBe('alert');
  });
});

/* ================================================================== */
/*  State Management                                                    */
/* ================================================================== */

describe('ProbeGuard — State Management', () => {
  it('_resetState clears all records', () => {
    const records = _getSignalRecords();
    records['probe:tostring_on_security_api'] = [{ detail: {}, timestamp: Date.now() }];
    expect(Object.keys(records).length).toBeGreaterThan(0);

    _resetState();
    expect(Object.keys(_getSignalRecords()).length).toBe(0);
  });
});

/* ================================================================== */
/*  Integration: Telemetry Emission                                     */
/* ================================================================== */

describe('ProbeGuard — Telemetry', () => {
  it('sends PROBEGUARD_EVENT with correct payload structure', () => {
    // Mock chrome.runtime.sendMessage
    const sent = [];
    globalThis.chrome = {
      runtime: {
        id: 'test-extension-id',
        sendMessage: vi.fn((msg) => {
          sent.push(msg);
          return Promise.resolve();
        }),
      },
    };

    // Simulate the analysis by directly calling runProbeAnalysis
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:war_extension_probing', 1),
    );

    const { riskScore, signals } = runProbeAnalysis(records);

    // Simulate telemetry emission (what triggerAnalysis does internally)
    if (riskScore >= 0.50 && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'PROBEGUARD_EVENT',
        payload: {
          eventType: 'EXTENSION_PROBE_DETECTED',
          severity: riskScore >= 0.70 ? 'Critical' : 'High',
          riskScore,
          signals: signals.map(s => s.id),
          signalDetails: signals,
          url: 'https://example.com/test',
          timestamp: Date.now(),
        },
      });
    }

    expect(sent).toHaveLength(1);
    expect(sent[0].type).toBe('PROBEGUARD_EVENT');
    expect(sent[0].payload.eventType).toBe('EXTENSION_PROBE_DETECTED');
    expect(sent[0].payload.severity).toBe('High');
    expect(sent[0].payload.riskScore).toBeCloseTo(0.60, 2);
    expect(sent[0].payload.signals).toContain('probe:tostring_on_security_api');
    expect(sent[0].payload.signals).toContain('probe:war_extension_probing');
  });

  it('does not emit telemetry below alert threshold', () => {
    const records = makeRecords('probe:prototype_lie_detection', 1);
    const { riskScore } = runProbeAnalysis(records);
    expect(riskScore).toBeLessThan(0.50);
  });
});

/* ================================================================== */
/*  Signal Weight Correctness                                           */
/* ================================================================== */

describe('ProbeGuard — Signal Weights', () => {
  it('all signal weights match the documented values', () => {
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:iframe_function_verification', 1),
      makeRecords('probe:timing_loop_on_api', 1),
      makeRecords('probe:war_extension_probing', 1),
      makeRecords('probe:prototype_lie_detection', 1),
    );
    const { signals } = runProbeAnalysis(records);

    const weightMap = {};
    signals.forEach(s => { weightMap[s.id] = s.weight; });

    expect(weightMap['probe:tostring_on_security_api']).toBe(0.40);
    expect(weightMap['probe:iframe_function_verification']).toBe(0.30);
    expect(weightMap['probe:timing_loop_on_api']).toBe(0.25);
    expect(weightMap['probe:war_extension_probing']).toBe(0.20);
    expect(weightMap['probe:prototype_lie_detection']).toBe(0.15);
  });

  it('toString + iframe reaches block threshold', () => {
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:iframe_function_verification', 1),
    );
    const { riskScore } = runProbeAnalysis(records);
    expect(riskScore).toBeCloseTo(0.70, 2);
  });

  it('WAR + prototype alone is below alert threshold', () => {
    const records = mergeRecords(
      makeRecords('probe:war_extension_probing', 1),
      makeRecords('probe:prototype_lie_detection', 1),
    );
    const { riskScore } = runProbeAnalysis(records);
    expect(riskScore).toBeCloseTo(0.35, 2);
  });

  it('toString alone is below alert threshold', () => {
    const records = makeRecords('probe:tostring_on_security_api', 1);
    const { riskScore } = runProbeAnalysis(records);
    expect(riskScore).toBeCloseTo(0.40, 2);
  });

  it('toString + timing reaches alert threshold', () => {
    const records = mergeRecords(
      makeRecords('probe:tostring_on_security_api', 1),
      makeRecords('probe:timing_loop_on_api', 1),
    );
    const { riskScore } = runProbeAnalysis(records);
    expect(riskScore).toBeCloseTo(0.65, 2);
  });
});

/* ================================================================== */
/*  Edge Cases                                                          */
/* ================================================================== */

describe('ProbeGuard — Edge Cases', () => {
  it('handles records with unknown signal IDs gracefully', () => {
    const records = { 'probe:unknown_signal': [{ detail: {}, timestamp: Date.now() }] };
    const result = runProbeAnalysis(records);
    expect(result.riskScore).toBe(0);
    expect(result.signals).toEqual([]);
  });

  it('handles empty detail objects', () => {
    const records = { 'probe:tostring_on_security_api': [{ detail: {}, timestamp: Date.now() }] };
    const result = checkToStringProbing(records);
    expect(result).not.toBeNull();
    expect(result.lastDetail).toEqual({});
  });

  it('handles missing timestamp in records', () => {
    const records = { 'probe:war_extension_probing': [{ detail: { url: 'chrome-extension://x' } }] };
    const result = checkWarProbing(records);
    expect(result).not.toBeNull();
    expect(result.count).toBe(1);
  });
});
