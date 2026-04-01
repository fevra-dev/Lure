/**
 * extension/__tests__/triage.test.js
 *
 * Tests for the PhishOps Incident Triage Engine (lib/triage.js).
 * Validates NIST 800-61r3 classification, priority/SLA assignment,
 * MITRE ATT&CK mapping, and recommended actions.
 */

import { describe, it, expect } from 'vitest';
import { triageEvent, formatTriageReport } from '../lib/triage.js';

describe('triageEvent', () => {
  it('classifies OAUTH_DEVICE_CODE_FLOW as credential_harvest with T1528', () => {
    const event = { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical', riskScore: 0.90 };
    const result = triageEvent(event);
    expect(result.triage.classified).toBe(true);
    expect(result.triage.category).toBe('credential_harvest');
    expect(result.triage.mitreAttack).toBe('T1528');
    expect(result.triage.threatActor).toBe('Storm-2372');
  });

  it('assigns P1 priority for Critical severity', () => {
    const event = { eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical' };
    const result = triageEvent(event);
    expect(result.triage.priority).toBe('P1');
    expect(result.triage.sla.acknowledge).toBe('15 minutes');
    expect(result.triage.sla.containment).toBe('1 hour');
  });

  it('assigns P2 priority for High severity', () => {
    const event = { eventType: 'EXTENSION_C2_POLLING', severity: 'High' };
    const result = triageEvent(event);
    expect(result.triage.priority).toBe('P2');
    expect(result.triage.sla.acknowledge).toBe('30 minutes');
  });

  it('assigns P3 priority for Medium severity', () => {
    const event = { eventType: 'EXTENSION_DNR_AUDIT', severity: 'Medium' };
    const result = triageEvent(event);
    expect(result.triage.priority).toBe('P3');
  });

  it('classifies BLOB_URL_CREDENTIAL_PAGE with HTML smuggling TTP', () => {
    const event = { eventType: 'BLOB_URL_CREDENTIAL_PAGE', severity: 'High', riskScore: 0.80 };
    const result = triageEvent(event);
    expect(result.triage.mitreAttack).toBe('T1027.006');
    expect(result.triage.mitreName).toContain('HTML Smuggling');
  });

  it('classifies AUTOFILL_HIDDEN_FIELD_HARVEST with Input Capture TTP', () => {
    const event = { eventType: 'AUTOFILL_HIDDEN_FIELD_HARVEST', severity: 'High' };
    const result = triageEvent(event);
    expect(result.triage.mitreAttack).toBe('T1056.003');
    expect(result.triage.threatActor).toBe('Kuosmanen-class');
  });

  it('classifies AUTOFILL_EXTENSION_CLICKJACK with Toth attribution', () => {
    const event = { eventType: 'AUTOFILL_EXTENSION_CLICKJACK', severity: 'Medium' };
    const result = triageEvent(event);
    expect(result.triage.threatActor).toContain('th-class');
    expect(result.triage.description).toContain('Extension Clickjacking');
  });

  it('classifies EXTENSION_OWNERSHIP_DRIFT as supply chain compromise', () => {
    const event = { eventType: 'EXTENSION_OWNERSHIP_DRIFT', severity: 'High' };
    const result = triageEvent(event);
    expect(result.triage.category).toBe('unauthorized_access');
    expect(result.triage.mitreAttack).toBe('T1195.002');
  });

  it('provides recommended actions for each event type', () => {
    const eventTypes = [
      'OAUTH_DEVICE_CODE_FLOW', 'OAUTH_STATE_EMAIL_ENCODED',
      'BLOB_URL_CREDENTIAL_PAGE', 'EXTENSION_C2_POLLING',
      'AUTOFILL_HIDDEN_FIELD_HARVEST', 'AUTOFILL_EXTENSION_CLICKJACK',
    ];
    for (const eventType of eventTypes) {
      const result = triageEvent({ eventType, severity: 'High' });
      expect(result.triage.recommendedActions.length).toBeGreaterThan(0);
    }
  });

  it('provides escalation target based on priority', () => {
    const critical = triageEvent({ eventType: 'OAUTH_DEVICE_CODE_FLOW', severity: 'Critical' });
    expect(critical.triage.escalationTarget).toContain('CIRT');

    const high = triageEvent({ eventType: 'EXTENSION_C2_POLLING', severity: 'High' });
    expect(high.triage.escalationTarget).toContain('Tier 2');
  });

  it('handles unknown event type gracefully', () => {
    const event = { eventType: 'UNKNOWN_EVENT', severity: 'Low' };
    const result = triageEvent(event);
    expect(result.triage.classified).toBe(false);
    expect(result.triage.priority).toBe('P4');
  });

  it('classifies SPA_SUSPICIOUS_NAVIGATION with valid category', () => {
    const event = { eventType: 'SPA_SUSPICIOUS_NAVIGATION', severity: 'Medium' };
    const result = triageEvent(event);
    expect(result.triage.category).toBe('credential_harvest');
    expect(result.triage.category).not.toBe('credential-access');
  });

  it('classifies WEBRTC_SYNTHETIC_TRACK_DETECTED with valid category', () => {
    const event = { eventType: 'WEBRTC_SYNTHETIC_TRACK_DETECTED', severity: 'High' };
    const result = triageEvent(event);
    expect(result.triage.category).toBe('credential_harvest');
    expect(result.triage.category).not.toBe('credential-access');
  });

  it('provides recommended actions for all Wave 21-25 event types', () => {
    const eventTypes = [
      'SUSPICIOUS_PAYMENT_REQUEST_DETECTED',
      'FILE_SYSTEM_PICKER_ABUSE_DETECTED',
      'THREAT_INTEL_DOMAIN_HIT',
      'SPA_SUSPICIOUS_NAVIGATION',
      'WEBRTC_SYNTHETIC_TRACK_DETECTED',
    ];
    for (const eventType of eventTypes) {
      const result = triageEvent({ eventType, severity: 'High' });
      expect(result.triage.recommendedActions.length,
        `Expected actions for ${eventType}`).toBeGreaterThan(1);
    }
  });

  it('provides recommended actions for AgentIntentGuard supplementary signals', () => {
    const eventTypes = ['SUSPICION_RAISED', 'PHISHVISION_SUPPLEMENTARY_SIGNAL'];
    for (const eventType of eventTypes) {
      const result = triageEvent({ eventType, severity: 'Medium' });
      expect(result.triage.recommendedActions.length,
        `Expected actions for ${eventType}`).toBeGreaterThan(1);
    }
  });

  it('preserves original event fields alongside triage data', () => {
    const event = {
      eventType: 'OAUTH_DEVICE_CODE_FLOW',
      severity: 'Critical',
      riskScore: 0.90,
      url: 'https://login.microsoftonline.com/oauth2/devicecode',
      signals: ['device_code_flow_detected'],
    };
    const result = triageEvent(event);
    expect(result.riskScore).toBe(0.90);
    expect(result.url).toBe(event.url);
    expect(result.signals).toEqual(event.signals);
    expect(result.triage).toBeDefined();
  });
});

describe('formatTriageReport', () => {
  it('generates structured report with all sections', () => {
    const event = triageEvent({
      eventType: 'AUTOFILL_HIDDEN_FIELD_HARVEST',
      severity: 'High',
      riskScore: 0.75,
      url: 'https://evil.com/phish',
      signals: ['hidden_field:display_none', 'exfil:cross_origin_action'],
      timestamp: '2026-03-17T00:00:00Z',
    });
    const report = formatTriageReport(event);
    expect(report).toContain('INCIDENT TRIAGE REPORT');
    expect(report).toContain('AUTOFILL_HIDDEN_FIELD_HARVEST');
    expect(report).toContain('credential_harvest');
    expect(report).toContain('T1056.003');
    expect(report).toContain('P2 - High');
    expect(report).toContain('RECOMMENDED ACTIONS');
    expect(report).toContain('ESCALATION');
  });

  it('handles unclassified events', () => {
    const event = triageEvent({ eventType: 'UNKNOWN_EVENT' });
    const report = formatTriageReport(event);
    expect(report).toContain('[UNCLASSIFIED]');
  });
});
