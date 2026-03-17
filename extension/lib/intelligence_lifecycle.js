/**
 * extension/lib/intelligence_lifecycle.js
 *
 * PhishOps Intelligence Lifecycle Manager
 *
 * Implements the six-phase intelligence lifecycle for PhishOps detection data:
 *   1. Planning & Direction  — PIRs mapped to detectors
 *   2. Collection            — Detector → event pipeline
 *   3. Processing            — Normalization, deduplication, confidence scoring
 *   4. Analysis              — Correlation, campaign grouping, trend detection
 *   5. Dissemination         — Structured products for SOC, IR, executives
 *   6. Feedback              — Detection efficacy metrics
 *
 * This module runs in the background service worker alongside telemetry.js.
 * It enriches stored events with intelligence context and produces periodic
 * intelligence summaries.
 *
 * References:
 *   - FIRST CTI-SIG Maturity Model
 *   - NIST SP 800-150: Guide to Cyber Threat Information Sharing
 *   - STIX 2.1 structured threat intelligence format
 */

'use strict';

// ---------------------------------------------------------------------------
// Phase 1: Planning & Direction — Priority Intelligence Requirements
// ---------------------------------------------------------------------------

/**
 * Priority Intelligence Requirements (PIRs) for PhishOps.
 * Each PIR maps to one or more detectors that collect relevant data.
 * Reviewed quarterly; last review: Q1 2026.
 *
 * @type {Array<{ id: string, question: string, detectors: string[], priority: 'critical'|'high'|'medium', status: 'active'|'addressed'|'gap' }>}
 */
export const PRIORITY_INTELLIGENCE_REQUIREMENTS = [
  {
    id: 'PIR-001',
    question: 'Are threat actors using OAuth device code phishing (Storm-2372 TTP) to target our users?',
    detectors: ['OAUTH_DEVICE_CODE_FLOW'],
    collectionSources: ['webRequest listener on OAuth endpoints', 'Azure AD sign-in logs'],
    priority: 'critical',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-002',
    question: 'Are phishing campaigns encoding victim email in OAuth state parameters for C2 exfiltration?',
    detectors: ['OAUTH_STATE_EMAIL_ENCODED'],
    collectionSources: ['webRequest listener on OAuth endpoints', 'email gateway logs'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-003',
    question: 'Are HTML smuggling attacks using blob: URLs to deliver credential harvesting pages that bypass gateway security?',
    detectors: ['BLOB_URL_CREDENTIAL_PAGE'],
    collectionSources: ['webNavigation listener on blob: scheme', 'web proxy logs'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-004',
    question: 'Are installed browser extensions being compromised via supply chain attacks (DNR stripping, ownership drift, C2 polling)?',
    detectors: ['EXTENSION_DNR_AUDIT', 'EXTENSION_OWNERSHIP_DRIFT', 'EXTENSION_C2_POLLING'],
    collectionSources: ['chrome.management API', 'webRequest on extension origins', 'Chrome Web Store metadata'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-005',
    question: 'Are autofill credential harvesting attacks (hidden field or extension clickjacking) targeting users with unpatched password managers?',
    detectors: ['AUTOFILL_HIDDEN_FIELD_HARVEST', 'AUTOFILL_EXTENSION_CLICKJACK'],
    collectionSources: ['DOM MutationObserver', 'form submit interception', 'computed style analysis'],
    priority: 'critical',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-006',
    question: 'Are LLM agents being manipulated to interact with credential fields on suspicious pages?',
    detectors: ['AGENTIC_BLABBERING_GUARDRAIL_BYPASS', 'SUSPICION_RAISED'],
    collectionSources: ['focusin listener on credential fields', 'GAN-optimised page heuristic'],
    priority: 'medium',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-007',
    question: 'Are ClickFix clipboard injection attacks targeting users with fake CAPTCHA/verification pages?',
    detectors: ['CLICKFIX_CLIPBOARD_INJECTION'],
    collectionSources: ['Clipboard.prototype.writeText interception', 'DOM text analysis for fake CAPTCHA signals'],
    priority: 'critical',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-008',
    question: 'Are Browser-in-the-Middle fullscreen overlay attacks targeting users with unpatched password managers?',
    detectors: ['FULLSCREEN_BITM_OVERLAY'],
    collectionSources: ['fullscreenchange listener', 'MutationObserver for overlay/opacity changes'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-009',
    question: 'Are passkey/WebAuthn credential substitution attacks targeting users via sync fabric phishing?',
    detectors: ['PASSKEY_CREDENTIAL_INTERCEPTION'],
    collectionSources: ['navigator.credentials.create/get interception', 'RP ID mismatch analysis', 'typosquatting detection'],
    priority: 'critical',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-010',
    question: 'Are QRLjacking or Device Code Flow QR attacks being used to hijack user sessions?',
    detectors: ['QRLJACKING_SESSION_HIJACK'],
    collectionSources: ['MutationObserver on img/canvas src changes', 'page context analysis for device code references'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-011',
    question: 'Are deepfake video injection attacks targeting users via virtual cameras in browser-based video calls?',
    detectors: ['WEBRTC_VIRTUAL_CAMERA_DETECTED'],
    collectionSources: ['navigator.mediaDevices.enumerateDevices() label analysis', 'applyConstraints timing', 'frame jitter measurement'],
    priority: 'high',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
  {
    id: 'PIR-012',
    question: 'Are TOAD screen share attacks being used to capture credentials or MFA codes via social engineering?',
    detectors: ['SCREENSHARE_TOAD_DETECTED'],
    collectionSources: ['navigator.mediaDevices.getDisplayMedia() interception', 'credential field focus during active share'],
    priority: 'critical',
    status: 'active',
    quarterAdded: 'Q1-2026',
  },
];

// ---------------------------------------------------------------------------
// Phase 2 & 3: Collection + Processing — Event normalization
// ---------------------------------------------------------------------------

/**
 * Confidence levels for detection events based on signal composition.
 */
const CONFIDENCE_THRESHOLDS = {
  HIGH:   0.80,  // Multiple corroborating signals, known TTP match
  MEDIUM: 0.50,  // Single strong signal or multiple weak signals
  LOW:    0.25,  // Single weak signal, possible false positive
};

/**
 * Assess confidence level of a detection event based on signal count and risk score.
 *
 * @param {Object} event
 * @returns {'high'|'medium'|'low'}
 */
export function assessConfidence(event) {
  const signalCount = (event.signals || []).length;
  const riskScore = event.riskScore || 0;

  if (riskScore >= CONFIDENCE_THRESHOLDS.HIGH && signalCount >= 2) return 'high';
  if (riskScore >= CONFIDENCE_THRESHOLDS.MEDIUM) return 'medium';
  return 'low';
}

/**
 * Deduplicate events by checking for near-identical events within a time window.
 * Two events are duplicates if they share the same eventType, url (first 100 chars),
 * and occur within 60 seconds of each other.
 *
 * @param {Object[]} events - Array of events (newest first)
 * @returns {Object[]} Deduplicated array
 */
export function deduplicateEvents(events) {
  const seen = new Map();
  const result = [];

  for (const event of events) {
    const key = `${event.eventType}|${(event.url || event.blobUrl || '').substring(0, 100)}`;
    const ts = new Date(event.timestamp || 0).getTime();
    const lastSeen = seen.get(key);

    if (lastSeen && Math.abs(ts - lastSeen) < 60000) {
      continue; // Duplicate within 60s window
    }

    seen.set(key, ts);
    result.push(event);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Phase 4: Analysis — Correlation and campaign grouping
// ---------------------------------------------------------------------------

/**
 * Correlate events to identify potential campaigns.
 * Groups events that share temporal proximity and related TTPs.
 *
 * @param {Object[]} events
 * @returns {{ campaigns: Object[], uncorrelated: Object[] }}
 */
export function correlateEvents(events) {
  if (events.length < 2) {
    return { campaigns: [], uncorrelated: events };
  }

  // Group by 15-minute time windows
  const WINDOW_MS = 15 * 60 * 1000;
  const campaigns = [];
  const used = new Set();

  // Related event types that indicate a multi-stage attack
  const RELATED_TYPES = [
    new Set(['OAUTH_DEVICE_CODE_FLOW', 'OAUTH_STATE_EMAIL_ENCODED']),
    new Set(['BLOB_URL_CREDENTIAL_PAGE', 'AUTOFILL_HIDDEN_FIELD_HARVEST']),
    new Set(['EXTENSION_DNR_AUDIT', 'EXTENSION_OWNERSHIP_DRIFT', 'EXTENSION_C2_POLLING']),
    new Set(['SUSPICION_RAISED', 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS', 'PHISHVISION_SUPPLEMENTARY_SIGNAL']),
    new Set(['CLICKFIX_CLIPBOARD_INJECTION', 'FULLSCREEN_BITM_OVERLAY', 'AUTOFILL_EXTENSION_CLICKJACK']),
    new Set(['PASSKEY_CREDENTIAL_INTERCEPTION', 'QRLJACKING_SESSION_HIJACK', 'OAUTH_DEVICE_CODE_FLOW']),
    new Set(['WEBRTC_VIRTUAL_CAMERA_DETECTED', 'SCREENSHARE_TOAD_DETECTED', 'CLICKFIX_CLIPBOARD_INJECTION']),
  ];

  for (let i = 0; i < events.length; i++) {
    if (used.has(i)) continue;

    const anchor = events[i];
    const anchorTs = new Date(anchor.timestamp || 0).getTime();
    const campaign = [anchor];

    // Find related type set for this event
    const relatedSet = RELATED_TYPES.find(s => s.has(anchor.eventType));

    for (let j = i + 1; j < events.length; j++) {
      if (used.has(j)) continue;
      const candidate = events[j];
      const candidateTs = new Date(candidate.timestamp || 0).getTime();

      if (Math.abs(candidateTs - anchorTs) > WINDOW_MS) continue;

      // Same URL or related event type
      const sameUrl = anchor.url && candidate.url &&
        anchor.url.substring(0, 100) === candidate.url.substring(0, 100);
      const relatedType = relatedSet?.has(candidate.eventType);

      if (sameUrl || relatedType) {
        campaign.push(candidate);
        used.add(j);
      }
    }

    if (campaign.length >= 2) {
      used.add(i);
      campaigns.push({
        id: `CAMP-${Date.now()}-${campaigns.length}`,
        events: campaign,
        eventTypes: [...new Set(campaign.map(e => e.eventType))],
        timespan: {
          start: campaign.reduce((min, e) => {
            const t = new Date(e.timestamp || 0).getTime();
            return t < min ? t : min;
          }, Infinity),
          end: campaign.reduce((max, e) => {
            const t = new Date(e.timestamp || 0).getTime();
            return t > max ? t : max;
          }, 0),
        },
        maxRiskScore: Math.max(...campaign.map(e => e.riskScore || 0)),
      });
    }
  }

  const uncorrelated = events.filter((_, i) => !used.has(i));
  return { campaigns, uncorrelated };
}

// ---------------------------------------------------------------------------
// Phase 5: Dissemination — Intelligence product generation
// ---------------------------------------------------------------------------

/**
 * Generate a tactical intelligence summary from stored events.
 * Suitable for SOC analysts: actionable indicators, block/monitor recommendations.
 *
 * @param {Object[]} events
 * @returns {Object}
 */
export function generateTacticalSummary(events) {
  const last24h = events.filter(e => {
    const age = Date.now() - new Date(e.timestamp || 0).getTime();
    return age < 24 * 60 * 60 * 1000;
  });

  const byType = {};
  for (const event of last24h) {
    byType[event.eventType] = (byType[event.eventType] || 0) + 1;
  }

  const criticalEvents = last24h.filter(e => e.severity === 'Critical');
  const highEvents = last24h.filter(e => e.severity === 'High');

  // Extract IOCs
  const urls = [...new Set(last24h
    .map(e => e.url || e.blobUrl || '')
    .filter(u => u.length > 0)
    .map(u => u.substring(0, 200))
  )];

  const { campaigns } = correlateEvents(last24h);

  return {
    period: 'Last 24 hours',
    generatedAt: new Date().toISOString(),
    totalEvents: last24h.length,
    criticalCount: criticalEvents.length,
    highCount: highEvents.length,
    eventBreakdown: byType,
    activeCampaigns: campaigns.length,
    campaigns: campaigns.map(c => ({
      id: c.id,
      eventTypes: c.eventTypes,
      eventCount: c.events.length,
      maxRiskScore: c.maxRiskScore,
    })),
    iocs: {
      urls: urls.slice(0, 20),
    },
    pirCoverage: PRIORITY_INTELLIGENCE_REQUIREMENTS.map(pir => ({
      id: pir.id,
      question: pir.question,
      eventsCollected: last24h.filter(e => pir.detectors.includes(e.eventType)).length,
      status: last24h.some(e => pir.detectors.includes(e.eventType)) ? 'data_collected' : 'no_data',
    })),
  };
}

// ---------------------------------------------------------------------------
// Phase 6: Feedback — Detection efficacy metrics
// ---------------------------------------------------------------------------

/**
 * Calculate detection efficacy metrics from stored events.
 *
 * @param {Object[]} allEvents - All stored events
 * @returns {Object}
 */
export function calculateEfficacyMetrics(allEvents) {
  if (allEvents.length === 0) {
    return { totalEvents: 0, detectorCoverage: {}, confidenceDistribution: {}, pirCoverage: 0 };
  }

  // Events per detector
  const detectorCoverage = {};
  for (const event of allEvents) {
    detectorCoverage[event.eventType] = (detectorCoverage[event.eventType] || 0) + 1;
  }

  // Confidence distribution
  const confidenceDistribution = { high: 0, medium: 0, low: 0 };
  for (const event of allEvents) {
    const conf = assessConfidence(event);
    confidenceDistribution[conf]++;
  }

  // PIR coverage: how many PIRs have at least one event
  const activePirs = PRIORITY_INTELLIGENCE_REQUIREMENTS.filter(pir => pir.status === 'active');
  const coveredPirs = activePirs.filter(pir =>
    allEvents.some(e => pir.detectors.includes(e.eventType))
  );

  return {
    totalEvents: allEvents.length,
    detectorCoverage,
    confidenceDistribution,
    pirCoverage: activePirs.length > 0
      ? Math.round((coveredPirs.length / activePirs.length) * 100)
      : 0,
    pirDetails: activePirs.map(pir => ({
      id: pir.id,
      covered: allEvents.some(e => pir.detectors.includes(e.eventType)),
      eventCount: allEvents.filter(e => pir.detectors.includes(e.eventType)).length,
    })),
  };
}
