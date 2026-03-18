/**
 * extension/popup/popup.js
 *
 * PhishOps popup dashboard — reads detection events from chrome.storage.local
 * and renders them as a timeline.
 */

'use strict';

const STORAGE_KEY = 'phishops_events';

const EVENT_TYPE_LABELS = {
  'OAUTH_DEVICE_CODE_FLOW': 'Device Code Flow',
  'OAUTH_STATE_EMAIL_ENCODED': 'State Param Email',
  'BLOB_URL_CREDENTIAL_PAGE': 'Blob Credential Page',
  'EXTENSION_DNR_AUDIT': 'DNR Audit',
  'EXTENSION_OWNERSHIP_DRIFT': 'Ownership Drift',
  'EXTENSION_C2_POLLING': 'C2 Polling',
  'SUSPICION_RAISED': 'Suspicion Raised',
  'PHISHVISION_SUPPLEMENTARY_SIGNAL': 'GAN Page Signal',
  'AGENTIC_BLABBERING_GUARDRAIL_BYPASS': 'Guardrail Bypass',
  'AUTOFILL_HIDDEN_FIELD_HARVEST': 'Hidden Field Harvest',
  'AUTOFILL_EXTENSION_CLICKJACK': 'Extension Clickjacking',
  'CLICKFIX_CLIPBOARD_INJECTION': 'Clipboard Injection',
  'FULLSCREEN_BITM_OVERLAY': 'Fullscreen Overlay',
  'PASSKEY_CREDENTIAL_INTERCEPTION': 'Passkey Interception',
  'QRLJACKING_SESSION_HIJACK': 'QR Session Hijack',
  'WEBRTC_VIRTUAL_CAMERA_DETECTED': 'Virtual Camera',
  'SCREENSHARE_TOAD_DETECTED': 'TOAD Screen Share',
  'PHISHVISION_BRAND_IMPERSONATION': 'Brand Impersonation',
  'PROXY_AITM_DETECTED': 'AiTM Proxy',
  'SYNC_HIJACK_DETECTED': 'Sync Hijack',
  'FAKESENDER_BRAND_IMPERSONATION': 'Helpdesk Impersonation',
  'FIDO_DOWNGRADE_DETECTED': 'FIDO Downgrade',
  'IPFS_PHISHING_DETECTED': 'IPFS Phishing',
  'LLM_GENERATED_PHISHING_DETECTED': 'AI-Generated Phishing',
  'VNC_AITM_DETECTED': 'VNC AiTM',
  'PWA_PHISHING_DETECTED': 'PWA Phishing',
  'TPA_CONSENT_PHISHING_DETECTED': 'Consent Phishing',
  'CRYPTO_DRAINER_DETECTED': 'Wallet Drainer',
  'CSS_CREDENTIAL_EXFIL_DETECTED': 'CSS Exfiltration',
};

document.addEventListener('DOMContentLoaded', async () => {
  await loadEvents();

  document.getElementById('clear-btn').addEventListener('click', async () => {
    await chrome.storage.local.set({ [STORAGE_KEY]: [] });
    if (chrome.action?.setBadgeText) {
      chrome.action.setBadgeText({ text: '' });
    }
    await loadEvents();
  });
});

async function loadEvents() {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  const events = data[STORAGE_KEY] || [];

  // Update counts
  const criticalCount = events.filter(e => e.severity === 'Critical').length;
  const highCount = events.filter(e => e.severity === 'High').length;

  document.getElementById('critical-count').textContent = criticalCount;
  document.getElementById('high-count').textContent = highCount;
  document.getElementById('total-count').textContent = events.length;

  // Render event list
  const listEl = document.getElementById('event-list');

  if (events.length === 0) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="icon">&#x1F6E1;&#xFE0F;</div>
        <div>No detections yet</div>
        <div style="font-size:11px; margin-top:4px;">Open a demo page to trigger detectors</div>
      </div>
    `;
    return;
  }

  listEl.innerHTML = events.slice(0, 50).map(event => {
    const severity = event.severity || 'Low';
    const typeLabel = EVENT_TYPE_LABELS[event.eventType] || event.eventType;
    const detail = formatEventDetail(event);
    const time = formatTime(event.timestamp);

    return `
      <div class="event severity-${severity}">
        <div class="event-type">${typeLabel}</div>
        ${detail ? `<div class="event-detail">${detail}</div>` : ''}
        <div class="event-time">${time}</div>
      </div>
    `;
  }).join('');
}

function formatEventDetail(event) {
  switch (event.eventType) {
    case 'OAUTH_STATE_EMAIL_ENCODED':
      return `Email: ${event.decodedEmail || '?'} (${event.encodingMethod || '?'})`;
    case 'OAUTH_DEVICE_CODE_FLOW':
      return `Endpoint: ${event.endpoint || '?'}`;
    case 'BLOB_URL_CREDENTIAL_PAGE':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Brands: ${(event.matchedBrands || []).join(', ') || 'none'}`;
    case 'EXTENSION_OWNERSHIP_DRIFT':
      return `${event.previousHomepage || '?'} \u2192 ${event.currentHomepage || '?'}`;
    case 'EXTENSION_C2_POLLING':
      return `${event.requestCount || 0} requests, avg ${Math.round((event.avgIntervalMs || 0) / 1000)}s interval`;
    case 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS':
      return `Trigger: ${event.trigger || '?'}`;
    case 'AUTOFILL_HIDDEN_FIELD_HARVEST':
    case 'AUTOFILL_EXTENSION_CLICKJACK':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Vector: ${event.vector || '?'} | Fields: ${event.hiddenFieldCount || 0}`;
    case 'CLICKFIX_CLIPBOARD_INJECTION':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Action: ${event.action || '?'} | ${(event.payloadSnippet || '').substring(0, 60)}`;
    case 'FULLSCREEN_BITM_OVERLAY':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Target: ${event.fullscreenTarget || '?'} | Action: ${event.action || 'alerted'}`;
    case 'PASSKEY_CREDENTIAL_INTERCEPTION':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | RP: ${event.rpId || '?'} | ${event.callType || '?'} | Action: ${event.action || '?'}`;
    case 'QRLJACKING_SESSION_HIJACK':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Refreshes: ${event.refreshCount || 0} | ${(event.signals || []).slice(0, 2).join(', ')}`;
    case 'WEBRTC_VIRTUAL_CAMERA_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Device: ${event.deviceLabel || '?'} | Action: ${event.action || '?'}`;
    case 'SCREENSHARE_TOAD_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Action: ${event.action || '?'} | Cred: ${event.credentialFieldFocused ? 'yes' : 'no'}`;
    case 'PHISHVISION_BRAND_IMPERSONATION':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Brand: ${event.matchedBrand || '?'} | Action: ${event.action || '?'}`;
    case 'PROXY_AITM_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Provider: ${event.targetProvider || '?'} | Action: ${event.action || '?'}`;
    case 'SYNC_HIJACK_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Referrer: ${event.referrer || '?'} | Action: ${event.action || '?'}`;
    case 'FAKESENDER_BRAND_IMPERSONATION':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Brand: ${event.matchedBrand || '?'} | Platform: ${event.platform || '?'} | Action: ${event.action || '?'}`;
    case 'FIDO_DOWNGRADE_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    case 'IPFS_PHISHING_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Gateway: ${event.gateway || '?'} | Brand: ${event.matchedBrand || '?'} | Action: ${event.action || '?'}`;
    case 'LLM_GENERATED_PHISHING_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 3).join(', ')} | Action: ${event.action || '?'}`;
    case 'VNC_AITM_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    case 'PWA_PHISHING_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | Brand: ${event.matchedBrand || '?'} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    case 'TPA_CONSENT_PHISHING_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    case 'CRYPTO_DRAINER_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    case 'CSS_CREDENTIAL_EXFIL_DETECTED':
      return `Score: ${(event.riskScore || 0).toFixed(2)} | ${(event.signals || []).slice(0, 2).join(', ')} | Action: ${event.action || '?'}`;
    default:
      return event.signals ? event.signals.join(', ') : '';
  }
}

function formatTime(timestamp) {
  if (!timestamp) return '';
  try {
    const d = new Date(timestamp);
    const now = new Date();
    const diffMs = now - d;

    if (diffMs < 60000) return 'just now';
    if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)}m ago`;
    if (diffMs < 86400000) return `${Math.floor(diffMs / 3600000)}h ago`;

    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (_) {
    return '';
  }
}
