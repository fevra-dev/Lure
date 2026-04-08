/**
 * extension/tests/event_export.test.js
 *
 * Unit tests for the pure export helpers used by the popup.
 */

import { describe, it, expect } from 'vitest';
import { eventsToJSON, eventsToCSV } from '../lib/event_export.js';

const SAMPLE_EVENTS = [
  {
    eventType: 'PROXY_AITM_DETECTED',
    severity: 'Critical',
    timestamp: '2026-04-08T10:15:00.000Z',
    targetProvider: 'microsoft',
    url: 'https://evil.example/login',
    signals: ['cname-chain', 'cdn-wrap'],
    extensionVersion: '1.0.0',
    source: 'PhishOps',
  },
  {
    eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
    severity: 'High',
    timestamp: '2026-04-08T10:14:00.000Z',
    payloadSnippet: 'powershell -enc ...',
    url: 'https://foo.test/page',
    extensionVersion: '1.0.0',
    source: 'PhishOps',
  },
];

describe('eventsToJSON', () => {
  it('returns a pretty-printed JSON bundle with metadata and events', () => {
    const now = new Date('2026-04-08T12:00:00.000Z');
    const out = eventsToJSON(SAMPLE_EVENTS, { now, extensionVersion: '1.0.0' });
    const parsed = JSON.parse(out);
    expect(parsed.exportedAt).toBe('2026-04-08T12:00:00.000Z');
    expect(parsed.extensionVersion).toBe('1.0.0');
    expect(parsed.eventCount).toBe(2);
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0].eventType).toBe('PROXY_AITM_DETECTED');
  });

  it('handles empty input', () => {
    const out = eventsToJSON([], { now: new Date('2026-04-08T12:00:00.000Z') });
    const parsed = JSON.parse(out);
    expect(parsed.eventCount).toBe(0);
    expect(parsed.events).toEqual([]);
  });
});

describe('eventsToCSV', () => {
  it('produces a header row and one row per event with core columns', () => {
    const csv = eventsToCSV(SAMPLE_EVENTS);
    const lines = csv.split('\n');
    expect(lines[0]).toBe('timestamp,severity,eventType,url,extensionVersion,signals,detail');
    expect(lines).toHaveLength(3); // header + 2 events
    expect(lines[1]).toContain('2026-04-08T10:15:00.000Z');
    expect(lines[1]).toContain('Critical');
    expect(lines[1]).toContain('PROXY_AITM_DETECTED');
    expect(lines[1]).toContain('https://evil.example/login');
  });

  it('quotes fields containing commas, quotes, or newlines', () => {
    const csv = eventsToCSV([{
      eventType: 'TEST',
      severity: 'Low',
      timestamp: '2026-04-08T00:00:00.000Z',
      url: 'https://a,b.test/"quoted"',
      extensionVersion: '1.0.0',
      signals: ['one', 'two,three'],
    }]);
    const lines = csv.split('\n');
    // URL contains a comma AND double-quotes → must be wrapped in quotes with "" escapes
    expect(lines[1]).toContain('"https://a,b.test/""quoted"""');
    // signals joined with "; " and wrapped because it contains ","
    expect(lines[1]).toContain('"one; two,three"');
  });

  it('handles empty input by returning only the header', () => {
    const csv = eventsToCSV([]);
    expect(csv).toBe('timestamp,severity,eventType,url,extensionVersion,signals,detail');
  });
});
