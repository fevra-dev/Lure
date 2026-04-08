/**
 * extension/__tests__/telemetry.test.js
 *
 * Unit tests for the shared telemetry module.
 *
 * Run: npx vitest run
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome.storage.local before importing
const mockStorage = {};
const mockGet = vi.fn(async (key) => ({ [key]: mockStorage[key] || null }));
const mockSet = vi.fn(async (obj) => { Object.assign(mockStorage, obj); });

vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: mockGet,
      set: mockSet,
    },
  },
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn(),
  },
  runtime: {
    getManifest: vi.fn(() => ({ version: '1.0.0' })),
  },
});

// Now import after mocks are in place
const { emitTelemetry, getStoredEvents, clearStoredEvents } = await import('../lib/telemetry.js');

describe('emitTelemetry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_events;
  });

  it('stores event to chrome.storage.local', async () => {
    await emitTelemetry({ eventType: 'TEST_EVENT', severity: 'High' });

    expect(mockSet).toHaveBeenCalled();
    const setArg = mockSet.mock.calls[0][0];
    expect(setArg.phishops_events).toBeDefined();
    expect(setArg.phishops_events[0].eventType).toBe('TEST_EVENT');
  });

  it('enriches event with timestamp and version', async () => {
    await emitTelemetry({ eventType: 'TEST_EVENT' });

    const setArg = mockSet.mock.calls[0][0];
    const event = setArg.phishops_events[0];
    expect(event.timestamp).toBeDefined();
    expect(event.extensionVersion).toBe('1.0.0');
    expect(event.source).toBe('PhishOps');
  });

  it('prepends new events (most recent first)', async () => {
    mockStorage.phishops_events = [{ eventType: 'OLD_EVENT', timestamp: '2026-01-01T00:00:00Z' }];

    await emitTelemetry({ eventType: 'NEW_EVENT' });

    const setArg = mockSet.mock.calls[0][0];
    expect(setArg.phishops_events[0].eventType).toBe('NEW_EVENT');
    expect(setArg.phishops_events[1].eventType).toBe('OLD_EVENT');
  });

  it('does not lose events when called concurrently', async () => {
    mockGet.mockImplementation(async (key) => {
      await new Promise(r => setTimeout(r, 10));
      return { [key]: mockStorage[key] || null };
    });

    await Promise.all([
      emitTelemetry({ eventType: 'EVENT_A', severity: 'High' }),
      emitTelemetry({ eventType: 'EVENT_B', severity: 'Medium' }),
    ]);

    const lastSetCall = mockSet.mock.calls[mockSet.mock.calls.length - 1][0];
    const stored = lastSetCall.phishops_events;
    const types = stored.map(e => e.eventType);
    expect(types).toContain('EVENT_A');
    expect(types).toContain('EVENT_B');
  });

  it('reads extensionVersion from manifest when available', async () => {
    await emitTelemetry({ eventType: 'VERSION_TEST' });
    const setArg = mockSet.mock.calls[0][0];
    const event = setArg.phishops_events[0];
    expect(event.extensionVersion).toBe('1.0.0');
  });
});

describe('getStoredEvents', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns empty array when no events stored', async () => {
    mockGet.mockResolvedValueOnce({});
    const events = await getStoredEvents();
    expect(events).toEqual([]);
  });
});

describe('clearStoredEvents', () => {
  it('sets events to empty array', async () => {
    await clearStoredEvents();
    expect(mockSet).toHaveBeenCalledWith({ phishops_events: [] });
  });
});

describe('clearEventsOlderThan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_events;
  });

  it('removes events older than the cutoff and keeps newer ones', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    const now = Date.now();
    mockStorage.phishops_events = [
      { eventType: 'FRESH',  timestamp: new Date(now - 1 * 60 * 60 * 1000).toISOString() },   // 1h ago
      { eventType: 'BORDER', timestamp: new Date(now - 6 * 60 * 60 * 1000).toISOString() },   // 6h ago
      { eventType: 'OLD',    timestamp: new Date(now - 48 * 60 * 60 * 1000).toISOString() },  // 48h ago
    ];

    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000); // 24h

    expect(removed).toBe(1);
    const lastSet = mockSet.mock.calls.at(-1)[0];
    const kept = lastSet.phishops_events.map((e) => e.eventType);
    expect(kept).toEqual(['FRESH', 'BORDER']);
  });

  it('is a no-op when there are no events', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000);
    expect(removed).toBe(0);
  });

  it('drops events with missing/invalid timestamps (treats them as old)', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    mockStorage.phishops_events = [
      { eventType: 'NO_TS' },
      { eventType: 'BAD_TS', timestamp: 'not-a-date' },
      { eventType: 'FRESH', timestamp: new Date().toISOString() },
    ];
    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000);
    expect(removed).toBe(2);
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_events.map((e) => e.eventType)).toEqual(['FRESH']);
  });
});
