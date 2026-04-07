/**
 * extension/__tests__/intelligence_lifecycle.test.js
 *
 * Tests for the PhishOps Intelligence Lifecycle Manager.
 * Validates PIR definitions, event processing, correlation,
 * tactical summary generation, and efficacy metrics.
 */

import { describe, it, expect } from 'vitest';
import {
  PRIORITY_INTELLIGENCE_REQUIREMENTS,
  assessConfidence,
  deduplicateEvents,
  correlateEvents,
  generateTacticalSummary,
  calculateEfficacyMetrics,
} from '../lib/intelligence_lifecycle.js';

// ---------------------------------------------------------------------------
// Phase 1: PIR definitions
// ---------------------------------------------------------------------------

describe('Priority Intelligence Requirements', () => {
  it('defines at least 5 active PIRs', () => {
    const active = PRIORITY_INTELLIGENCE_REQUIREMENTS.filter(p => p.status === 'active');
    expect(active.length).toBeGreaterThanOrEqual(5);
  });

  it('every PIR has required fields', () => {
    for (const pir of PRIORITY_INTELLIGENCE_REQUIREMENTS) {
      expect(pir.id).toMatch(/^PIR-\d{3}$/);
      expect(pir.question).toBeTruthy();
      expect(pir.detectors.length).toBeGreaterThan(0);
      expect(pir.collectionSources.length).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium']).toContain(pir.priority);
    }
  });

  it('covers all major event types across PIRs', () => {
    const allDetectors = PRIORITY_INTELLIGENCE_REQUIREMENTS.flatMap(p => p.detectors);
    expect(allDetectors).toContain('OAUTH_DEVICE_CODE_FLOW');
    expect(allDetectors).toContain('BLOB_URL_CREDENTIAL_PAGE');
    expect(allDetectors).toContain('AUTOFILL_HIDDEN_FIELD_HARVEST');
    expect(allDetectors).toContain('EXTENSION_C2_POLLING');
  });
});

// ---------------------------------------------------------------------------
// Phase 2 & 3: Processing
// ---------------------------------------------------------------------------

describe('assessConfidence', () => {
  it('returns high for multi-signal high-score events', () => {
    expect(assessConfidence({ riskScore: 0.90, signals: ['a', 'b', 'c'] })).toBe('high');
  });

  it('returns medium for single-signal above threshold', () => {
    expect(assessConfidence({ riskScore: 0.60, signals: ['a'] })).toBe('medium');
  });

  it('returns low for weak signals', () => {
    expect(assessConfidence({ riskScore: 0.20, signals: ['a'] })).toBe('low');
  });

  it('returns low for events with no signals', () => {
    expect(assessConfidence({ riskScore: 0.10 })).toBe('low');
  });
});

describe('deduplicateEvents', () => {
  it('removes events with same type and URL within 60s', () => {
    const events = [
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil.com/phish', timestamp: '2026-03-17T00:00:00Z' },
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil.com/phish', timestamp: '2026-03-17T00:00:30Z' },
    ];
    const result = deduplicateEvents(events);
    expect(result).toHaveLength(1);
  });

  it('keeps events with same type but different URLs', () => {
    const events = [
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil1.com/phish', timestamp: '2026-03-17T00:00:00Z' },
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil2.com/phish', timestamp: '2026-03-17T00:00:30Z' },
    ];
    const result = deduplicateEvents(events);
    expect(result).toHaveLength(2);
  });

  it('keeps events beyond 60s window', () => {
    const events = [
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil.com/phish', timestamp: '2026-03-17T00:00:00Z' },
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', url: 'https://evil.com/phish', timestamp: '2026-03-17T00:02:00Z' },
    ];
    const result = deduplicateEvents(events);
    expect(result).toHaveLength(2);
  });

  it('returns empty array for empty input', () => {
    expect(deduplicateEvents([])).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Phase 4: Correlation
// ---------------------------------------------------------------------------

describe('correlateEvents', () => {
  it('groups related OAuth events within 2-hour window', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'OAUTH_STATE_EMAIL_ENCODED', timestamp: '2026-03-17T00:05:00Z', url: 'https://b.com', riskScore: 0.85 },
    ];
    const { campaigns } = correlateEvents(events);
    expect(campaigns).toHaveLength(1);
    expect(campaigns[0].eventTypes).toContain('OAUTH_DEVICE_CODE_FLOW');
    expect(campaigns[0].eventTypes).toContain('OAUTH_STATE_EMAIL_ENCODED');
  });

  it('correlates related events 90 minutes apart', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'OAUTH_STATE_EMAIL_ENCODED', timestamp: '2026-03-17T01:30:00Z', url: 'https://b.com', riskScore: 0.85 },
    ];
    const { campaigns } = correlateEvents(events);
    expect(campaigns).toHaveLength(1);
    expect(campaigns[0].eventTypes).toContain('OAUTH_DEVICE_CODE_FLOW');
    expect(campaigns[0].eventTypes).toContain('OAUTH_STATE_EMAIL_ENCODED');
  });

  it('does not correlate related events more than 2 hours apart', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'OAUTH_STATE_EMAIL_ENCODED', timestamp: '2026-03-17T02:01:00Z', url: 'https://b.com', riskScore: 0.85 },
    ];
    const { campaigns, uncorrelated } = correlateEvents(events);
    expect(campaigns).toHaveLength(0);
    expect(uncorrelated).toHaveLength(2);
  });

  it('does not group unrelated events', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'EXTENSION_DNR_AUDIT', timestamp: '2026-03-17T00:05:00Z', url: 'https://b.com', riskScore: 0.60 },
    ];
    const { campaigns, uncorrelated } = correlateEvents(events);
    expect(campaigns).toHaveLength(0);
    expect(uncorrelated).toHaveLength(2);
  });

  it('groups extension audit events together', () => {
    const events = [
      { eventType: 'EXTENSION_DNR_AUDIT', timestamp: '2026-03-17T00:00:00Z', riskScore: 0.60 },
      { eventType: 'EXTENSION_OWNERSHIP_DRIFT', timestamp: '2026-03-17T00:03:00Z', riskScore: 0.75 },
    ];
    const { campaigns } = correlateEvents(events);
    expect(campaigns).toHaveLength(1);
  });

  it('returns empty campaigns for single event', () => {
    const { campaigns } = correlateEvents([{ eventType: 'BLOB_URL_CREDENTIAL_PAGE', timestamp: '2026-03-17T00:00:00Z', riskScore: 0.70 }]);
    expect(campaigns).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Phase 5: Dissemination
// ---------------------------------------------------------------------------

describe('generateTacticalSummary', () => {
  const recentTimestamp = new Date(Date.now() - 3600000).toISOString(); // 1 hour ago

  it('generates summary with event counts', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical', riskScore: 0.90, timestamp: recentTimestamp, signals: ['a'] },
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', severity: 'High', riskScore: 0.80, timestamp: recentTimestamp, signals: ['b'] },
    ];
    const summary = generateTacticalSummary(events);
    expect(summary.totalEvents).toBe(2);
    expect(summary.criticalCount).toBe(1);
    expect(summary.highCount).toBe(1);
  });

  it('includes event breakdown by type', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical', timestamp: recentTimestamp, signals: [] },
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical', timestamp: recentTimestamp, signals: [] },
    ];
    const summary = generateTacticalSummary(events);
    expect(summary.eventBreakdown.OAUTH_DEVICE_CODE_FLOW).toBe(2);
  });

  it('excludes events older than 24 hours', () => {
    const oldTimestamp = new Date(Date.now() - 25 * 3600000).toISOString();
    const events = [
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', severity: 'High', timestamp: oldTimestamp, signals: [] },
    ];
    const summary = generateTacticalSummary(events);
    expect(summary.totalEvents).toBe(0);
  });

  it('includes PIR coverage report', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical', timestamp: recentTimestamp, signals: [] },
    ];
    const summary = generateTacticalSummary(events);
    expect(summary.pirCoverage.length).toBeGreaterThan(0);
    const oauthPir = summary.pirCoverage.find(p => p.id === 'PIR-001');
    expect(oauthPir.status).toBe('data_collected');
  });

  it('returns empty summary for no events', () => {
    const summary = generateTacticalSummary([]);
    expect(summary.totalEvents).toBe(0);
    expect(summary.activeCampaigns).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Phase 6: Feedback / Efficacy
// ---------------------------------------------------------------------------

describe('calculateEfficacyMetrics', () => {
  it('calculates detector coverage', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', riskScore: 0.90, signals: ['a', 'b'] },
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', riskScore: 0.90, signals: ['a'] },
      { eventType: 'BLOB_URL_CREDENTIAL_PAGE', riskScore: 0.80, signals: ['c'] },
    ];
    const metrics = calculateEfficacyMetrics(events);
    expect(metrics.detectorCoverage.OAUTH_DEVICE_CODE_FLOW).toBe(2);
    expect(metrics.detectorCoverage.BLOB_URL_CREDENTIAL_PAGE).toBe(1);
  });

  it('calculates confidence distribution', () => {
    const events = [
      { eventType: 'X', riskScore: 0.90, signals: ['a', 'b'] }, // high
      { eventType: 'Y', riskScore: 0.60, signals: ['a'] },       // medium
      { eventType: 'Z', riskScore: 0.10, signals: [] },           // low
    ];
    const metrics = calculateEfficacyMetrics(events);
    expect(metrics.confidenceDistribution.high).toBe(1);
    expect(metrics.confidenceDistribution.medium).toBe(1);
    expect(metrics.confidenceDistribution.low).toBe(1);
  });

  it('calculates PIR coverage percentage', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', riskScore: 0.90, signals: ['a'] },
      { eventType: 'AUTOFILL_HIDDEN_FIELD_HARVEST', riskScore: 0.70, signals: ['b'] },
    ];
    const metrics = calculateEfficacyMetrics(events);
    expect(metrics.pirCoverage).toBeGreaterThan(0);
    expect(metrics.pirCoverage).toBeLessThanOrEqual(100);
  });

  it('returns zero metrics for empty events', () => {
    const metrics = calculateEfficacyMetrics([]);
    expect(metrics.totalEvents).toBe(0);
    expect(metrics.pirCoverage).toBe(0);
  });
});
