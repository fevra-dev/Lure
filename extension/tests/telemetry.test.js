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
