/**
 * extension/lib/triage.js
 *
 * PhishOps Incident Triage Engine
 *
 * Applies NIST SP 800-61r3 classification and SANS PICERL severity assignment
 * to PhishOps detection events. Each event emitted by a detector is enriched
 * with structured triage metadata before telemetry persistence.
 *
 * Usage:
 *   import { triageEvent } from '../lib/triage.js';
 *   const triaged = triageEvent(rawEvent);
 *   // triaged now has .triage { classification, severity, priority, sla, ... }
 *
 * This module is consumed by the service worker message router and by the
 * popup dashboard for rendering triage context alongside detection events.
 *
 * References:
 *   - NIST SP 800-61r3: Computer Security Incident Handling Guide
 *   - SANS PICERL: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
 *   - MITRE ATT&CK: Technique mappings per detector
 */

'use strict';

// ---------------------------------------------------------------------------
// NIST SP 800-61r3 Incident Classification Taxonomy
// ---------------------------------------------------------------------------

/**
 * @typedef {'unauthorized_access'|'malicious_code'|'reconnaissance'|'web_application_attack'|'improper_usage'|'credential_harvest'} IncidentCategory
 */

/**
 * Map each PhishOps event type to a NIST incident category and MITRE ATT&CK
 * technique ID.
 */
const EVENT_CLASSIFICATION = {
  // Wave 1: OAuthGuard
  OAUTH_DEVICE_CODE_FLOW: {
    category: 'credential_harvest',
    mitreAttack: 'T1528',
    mitreName: 'Steal Application Access Token',
    threatActor: 'Storm-2372',
    description: 'OAuth device code phishing — victim enters code granting attacker persistent token access',
  },
  OAUTH_STATE_EMAIL_ENCODED: {
    category: 'reconnaissance',
    mitreAttack: 'T1598.004',
    mitreName: 'Phishing for Information: Spearphishing Service',
    threatActor: 'Storm-2372',
    description: 'OAuth state parameter encodes victim email — C2 exfiltration of target identity',
  },

  // Wave 2: DataEgressMonitor
  BLOB_URL_CREDENTIAL_PAGE: {
    category: 'credential_harvest',
    mitreAttack: 'T1027.006',
    mitreName: 'Obfuscated Files or Information: HTML Smuggling',
    threatActor: 'NOBELIUM / TA4557',
    description: 'Credential harvesting page delivered via blob: URL to bypass gateway security',
  },

  // Wave 3: ExtensionAuditor
  EXTENSION_DNR_AUDIT: {
    category: 'web_application_attack',
    mitreAttack: 'T1195.002',
    mitreName: 'Supply Chain Compromise: Compromise Software Supply Chain',
    threatActor: 'QuickLens',
    description: 'Extension uses declarativeNetRequest to strip security headers (CSP, X-Frame-Options)',
  },
  EXTENSION_OWNERSHIP_DRIFT: {
    category: 'unauthorized_access',
    mitreAttack: 'T1195.002',
    mitreName: 'Supply Chain Compromise: Compromise Software Supply Chain',
    threatActor: 'Cyberhaven-style',
    description: 'Extension developer homepage URL changed — possible account takeover or ownership transfer',
  },
  EXTENSION_C2_POLLING: {
    category: 'malicious_code',
    mitreAttack: 'T1071.001',
    mitreName: 'Application Layer Protocol: Web Protocols',
    threatActor: 'Multiple',
    description: 'Extension makes regular-interval HTTP requests consistent with C2 beaconing',
  },

  // Wave 3: AgentIntentGuard
  SUSPICION_RAISED: {
    category: 'reconnaissance',
    mitreAttack: 'T1204.001',
    mitreName: 'User Execution: Malicious Link',
    threatActor: 'Agentic',
    description: 'External signal raised suspicion — monitoring credential field interaction',
  },
  PHISHVISION_SUPPLEMENTARY_SIGNAL: {
    category: 'reconnaissance',
    mitreAttack: 'T1566.002',
    mitreName: 'Phishing: Spearphishing Link',
    threatActor: 'GAN-generated',
    description: 'Page has abnormally low text-to-HTML ratio with credential fields — possible GAN-optimised phishing',
  },
  AGENTIC_BLABBERING_GUARDRAIL_BYPASS: {
    category: 'credential_harvest',
    mitreAttack: 'T1056.003',
    mitreName: 'Input Capture: Web Portal Capture',
    threatActor: 'Agentic',
    description: 'LLM agent focused on credential field during suspicion window — guardrail bypass detected',
  },

  // Wave 4: AutofillGuard
  AUTOFILL_HIDDEN_FIELD_HARVEST: {
    category: 'credential_harvest',
    mitreAttack: 'T1056.003',
    mitreName: 'Input Capture: Web Portal Capture',
    threatActor: 'Kuosmanen-class',
    description: 'Hidden credential fields designed to silently harvest autofilled passwords',
  },
  AUTOFILL_EXTENSION_CLICKJACK: {
    category: 'credential_harvest',
    mitreAttack: 'T1056.003',
    mitreName: 'Input Capture: Web Portal Capture',
    threatActor: 'Tóth-class',
    description: 'DOM-based Extension Clickjacking — page opacity manipulation hides password manager autofill UI',
  },

  // Wave 5: ClickFix Clipboard Defender
  CLICKFIX_CLIPBOARD_INJECTION: {
    category: 'malicious_code',
    mitreAttack: 'T1059.001',
    mitreName: 'Command and Scripting Interpreter: PowerShell',
    threatActor: 'FIN7 / Lazarus / Storm-1865',
    description: 'ClickFix clipboard injection — malicious command written to clipboard via fake CAPTCHA lure',
  },

  // Wave 5: FullscreenGuard
  FULLSCREEN_BITM_OVERLAY: {
    category: 'credential_harvest',
    mitreAttack: 'T1185',
    mitreName: 'Browser Session Hijacking',
    threatActor: 'BitM-class',
    description: 'Browser-in-the-Middle fullscreen overlay attack — fake browser chrome to steal credentials',
  },

  // Wave 6: PasskeyGuard
  PASSKEY_CREDENTIAL_INTERCEPTION: {
    category: 'credential_harvest',
    mitreAttack: 'T1556.006',
    mitreName: 'Modify Authentication Process: Multi-Factor Authentication',
    threatActor: 'Passkey sync fabric phishing (Spensky DEF CON 33)',
    description: 'WebAuthn/Passkey credential substitution — attacker redirects passkey registration or relays authentication challenges',
  },

  // Wave 6: QRLjackingGuard
  QRLJACKING_SESSION_HIJACK: {
    category: 'credential_harvest',
    mitreAttack: 'T1539',
    mitreName: 'Steal Web Session Cookie',
    threatActor: 'Storm-2372 / APT29 / TA2723',
    description: 'QR code session hijacking — attacker proxies legitimate QR codes to steal authenticated sessions in real time',
  },

  // Wave 7: WebRTCGuard
  WEBRTC_VIRTUAL_CAMERA_DETECTED: {
    category: 'reconnaissance',
    mitreAttack: 'T1566.003',
    mitreName: 'Phishing: Spearphishing via Service',
    threatActor: 'Scattered Spider / UNC3944',
    description: 'Virtual camera device detected — possible deepfake video injection via OBS Virtual Camera, VCAMSX, or similar',
  },

  // Wave 7: ScreenShareGuard
  SCREENSHARE_TOAD_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1113',
    mitreName: 'Screen Capture',
    threatActor: 'MuddyWater/TA450 / RansomHub / Luna Moth / BazarCall',
    description: 'TOAD screen share attack — attacker uses social engineering to observe credentials and MFA codes via screen share',
  },

  // Wave 8: PhishVision
  PHISHVISION_BRAND_IMPERSONATION: {
    category: 'credential_harvest',
    mitreAttack: 'T1566.002',
    mitreName: 'Phishing: Spearphishing Link',
    threatActor: 'Multiple (brand impersonation is universal)',
    description: 'Brand impersonation phishing page — mimics known login portal on non-brand domain',
  },

  // Wave 8: ProxyGuard
  PROXY_AITM_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1557.003',
    mitreName: 'Adversary-in-the-Middle: Proxy',
    threatActor: 'Starkiller / Evilginx / Modlishka operators',
    description: 'AiTM reverse proxy phishing — transparent relay captures credentials and session tokens, defeating MFA',
  },

  // Wave 9: SyncGuard
  SYNC_HIJACK_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1078.004',
    mitreName: 'Valid Accounts: Cloud Accounts',
    threatActor: 'Scattered Spider / UNC3944',
    description: 'Browser sync hijacking — social engineering to add attacker-controlled account to victim browser sync, replicating all saved credentials',
  },

  // Wave 9: FakeSender Shield
  FAKESENDER_BRAND_IMPERSONATION: {
    category: 'credential_harvest',
    mitreAttack: 'T1566.002',
    mitreName: 'Phishing: Spearphishing Link',
    threatActor: 'Multiple (helpdesk platform abuse)',
    description: 'Helpdesk platform brand impersonation — attacker abuses free-tier helpdesk to impersonate brand and harvest credentials',
  },

  // Wave 10: CTAPGuard
  FIDO_DOWNGRADE_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1556.006',
    mitreName: 'Modify Authentication Process: Multi-Factor Authentication',
    threatActor: 'Evilginx operators / Tycoon 2FA',
    description: 'FIDO downgrade attack — User-Agent spoofing forces identity provider to fall back from passkey to password+OTP, enabling AiTM credential capture',
  },

  // Wave 10: IPFSGuard
  IPFS_PHISHING_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1583.006',
    mitreName: 'Acquire Infrastructure: Web Services',
    threatActor: 'Multiple (commodity)',
    description: 'Phishing page hosted on IPFS gateway — takedown-resistant content served through decentralized infrastructure',
  },

  // Wave 11: LLMScorer
  LLM_GENERATED_PHISHING_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1566.002',
    mitreName: 'Phishing: Spearphishing Link',
    threatActor: 'TA4557 / Scattered Spider (AI phishing kits)',
    description: 'AI-generated phishing page detected — statistical text regularities, urgency phrase density, and DOM structure patterns consistent with LLM output',
  },

  // Wave 11: VNCGuard
  VNC_AITM_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1557.003',
    mitreName: 'Adversary-in-the-Middle: Proxy',
    threatActor: 'Storm-1811 / TA577 (EvilnoVNC operators)',
    description: 'EvilnoVNC WebSocket AiTM attack — real login page streamed via VNC canvas to victim browser, capturing credentials and session tokens transparently',
  },

  // Wave 12: PWAGuard
  PWA_PHISHING_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1036.005',
    mitreName: 'Masquerading: Match Legitimate Name or Location',
    threatActor: 'Czech/Hungarian banking campaigns / US FinServ PWA kits',
    description: 'Malicious Progressive Web App impersonating legitimate brand — installs as standalone app without URL bar to harvest credentials',
  },

  // Wave 12: TPASentinel
  TPA_CONSENT_PHISHING_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1528',
    mitreName: 'Steal Application Access Token',
    threatActor: 'Storm-0324 / Midnight Blizzard (APT29)',
    description: 'Malicious OAuth app consent phishing — app requests dangerous permissions (Mail.ReadWrite, Files.ReadWrite.All) via social engineering',
  },

  // Wave 13: DrainerGuard
  CRYPTO_DRAINER_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1656',
    mitreName: 'Impersonation',
    threatActor: 'Inferno Drainer / Angel Drainer / Pink Drainer',
    description: 'Crypto wallet drainer detected — malicious script attempts to sign dangerous transactions (eth_sendTransaction, unlimited approve, multicall batch)',
  },

  // Wave 13: StyleAuditor
  CSS_CREDENTIAL_EXFIL_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1056.003',
    mitreName: 'Input Capture: Web Portal Capture',
    threatActor: 'Advanced phishing kit authors',
    description: 'CSS-based credential exfiltration or LOTL DOM camouflage — input[value] attribute selectors with url() or hidden iframe/form credential harvesting',
  },

  // Wave 14: WebSocketExfilGuard
  WEBSOCKET_CREDENTIAL_EXFIL_DETECTED: {
    category: 'credential_harvest',
    mitreAttack: 'T1056.003',
    mitreName: 'Input Capture: Web Portal Capture',
    threatActor: 'EvilProxy derivatives / Modlishka 2.0+ / custom PhaaS kits',
    description: 'Real-time credential exfiltration via WebSocket — keystroke relay, cross-origin WS channels, or form value leakage on credential pages',
  },

  // Wave 14: ServiceWorkerGuard
  SERVICE_WORKER_PERSISTENCE_DETECTED: {
    category: 'malicious_code',
    mitreAttack: 'T1176',
    mitreName: 'Browser Extensions',
    threatActor: 'Advanced phishing kits / watering-hole campaigns',
    description: 'Service Worker persistence on credential page — phishing form caching, fetch interception for credential relay, push re-engagement, or background sync C2 callback',
  },
};

// ---------------------------------------------------------------------------
// Severity → Priority → SLA mapping
// ---------------------------------------------------------------------------

/**
 * Response SLA targets per SANS PICERL priority levels.
 */
const PRIORITY_SLA = {
  P1: { acknowledge: '15 minutes', containment: '1 hour',   investigation: '4 hours' },
  P2: { acknowledge: '30 minutes', containment: '4 hours',  investigation: '24 hours' },
  P3: { acknowledge: '2 hours',    containment: '24 hours', investigation: '72 hours' },
  P4: { acknowledge: '8 hours',    containment: '72 hours', investigation: '1 week' },
};

/**
 * Map severity string to priority level.
 * @param {string} severity
 * @returns {string}
 */
function severityToPriority(severity) {
  switch (severity) {
    case 'Critical': return 'P1';
    case 'High':     return 'P2';
    case 'Medium':   return 'P3';
    default:         return 'P4';
  }
}

// ---------------------------------------------------------------------------
// Triage engine
// ---------------------------------------------------------------------------

/**
 * Enrich a raw detection event with structured triage metadata.
 *
 * @param {Object} event - Raw detection event from a PhishOps detector
 * @returns {Object} Event with .triage field added
 */
export function triageEvent(event) {
  const classification = EVENT_CLASSIFICATION[event.eventType];
  if (!classification) {
    // Unknown event type — pass through with minimal triage
    return {
      ...event,
      triage: {
        classified: false,
        category: 'unknown',
        priority: 'P4',
        sla: PRIORITY_SLA.P4,
      },
    };
  }

  const severity = event.severity || 'Low';
  const priority = severityToPriority(severity);
  const sla = PRIORITY_SLA[priority];

  return {
    ...event,
    triage: {
      classified: true,
      category: classification.category,
      mitreAttack: classification.mitreAttack,
      mitreName: classification.mitreName,
      threatActor: classification.threatActor,
      description: classification.description,
      severity,
      priority,
      sla,
      recommendedActions: getRecommendedActions(event.eventType, severity),
      escalationTarget: getEscalationTarget(priority),
    },
  };
}

/**
 * Get recommended containment/investigation actions for an event type.
 *
 * @param {string} eventType
 * @param {string} severity
 * @returns {string[]}
 */
function getRecommendedActions(eventType, severity) {
  const actions = [];

  switch (eventType) {
    case 'OAUTH_DEVICE_CODE_FLOW':
      actions.push('Revoke active OAuth tokens for the affected user');
      actions.push('Check Azure AD / Google Workspace audit logs for token grant events');
      actions.push('Verify no persistent app consent was granted');
      if (severity === 'Critical') actions.push('Reset user password and MFA re-enrollment');
      break;

    case 'OAUTH_STATE_EMAIL_ENCODED':
      actions.push('Block the OAuth redirect URL at web proxy');
      actions.push('Alert the targeted user about potential phishing');
      actions.push('Search email gateway for the originating phishing email');
      break;

    case 'BLOB_URL_CREDENTIAL_PAGE':
      actions.push('Check if credentials were submitted before detection');
      actions.push('Search web proxy logs for the blob: origin page URL');
      actions.push('Block the delivery domain at DNS/web proxy');
      if (severity === 'Critical' || severity === 'High') {
        actions.push('Force password reset for user if credentials were entered');
      }
      break;

    case 'EXTENSION_DNR_AUDIT':
      actions.push('Review the flagged extension\'s declarativeNetRequest rules');
      actions.push('Check Chrome Web Store for recent version updates');
      actions.push('Consider force-removing the extension via group policy');
      break;

    case 'EXTENSION_OWNERSHIP_DRIFT':
      actions.push('Audit the extension\'s new homepage and developer profile');
      actions.push('Compare extension code before and after the ownership change');
      actions.push('Evaluate force-removal if ownership transfer is suspicious');
      break;

    case 'EXTENSION_C2_POLLING':
      actions.push('Capture and analyse the polled URLs for C2 indicators');
      actions.push('Block the polling destination at web proxy');
      actions.push('Force-remove the extension and scan endpoints');
      break;

    case 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS':
      actions.push('Terminate the LLM agent session');
      actions.push('Review the agent\'s action log for credential access');
      actions.push('Verify no credentials were exfiltrated');
      break;

    case 'AUTOFILL_HIDDEN_FIELD_HARVEST':
      actions.push('Check if password manager autofilled the hidden fields');
      actions.push('Force password reset if autofill occurred');
      actions.push('Block the form submission domain at web proxy');
      actions.push('Report the page to Safe Browsing / PhishTank');
      break;

    case 'AUTOFILL_EXTENSION_CLICKJACK':
      actions.push('Verify password manager autofill status on the affected page');
      actions.push('Force password reset if autofill UI was clicked');
      actions.push('Report to password manager vendor (1Password/LastPass)');
      actions.push('Block the page domain at DNS/web proxy');
      break;

    case 'CLICKFIX_CLIPBOARD_INJECTION':
      actions.push('Clear the user\'s clipboard immediately');
      actions.push('Check if the user executed the pasted command (Win+R or terminal history)');
      actions.push('If executed: isolate the endpoint and scan for malware');
      actions.push('Block the page domain at DNS/web proxy');
      actions.push('Report the page to Safe Browsing / PhishTank');
      break;

    case 'FULLSCREEN_BITM_OVERLAY':
      actions.push('Check if credentials were entered during the fullscreen session');
      actions.push('Force password reset if credential entry is confirmed');
      actions.push('Block the page domain at DNS/web proxy');
      actions.push('Report to affected password manager vendor if applicable');
      break;

    case 'PASSKEY_CREDENTIAL_INTERCEPTION':
      actions.push('Revoke any passkeys registered during the suspicious ceremony');
      actions.push('Audit passkey registrations in the identity provider (Entra ID, Google, Apple)');
      actions.push('Check if the relying party ID matches a known typosquat domain');
      actions.push('Block the page domain at DNS/web proxy');
      if (severity === 'Critical' || severity === 'High') {
        actions.push('Force re-enrollment of passkeys for the affected user');
      }
      break;

    case 'QRLJACKING_SESSION_HIJACK':
      actions.push('Terminate active sessions for the affected service (WhatsApp Web, Teams, etc.)');
      actions.push('Check if the QR code was scanned — revoke session tokens if so');
      actions.push('Block the phishing page domain at DNS/web proxy');
      actions.push('Search email/chat logs for the QR phishing delivery URL');
      break;

    case 'WEBRTC_VIRTUAL_CAMERA_DETECTED':
      actions.push('Verify the user is aware a virtual camera is active on their device');
      actions.push('Check if the video call was initiated by a known contact or unexpected party');
      actions.push('Review meeting invite source for social engineering indicators');
      actions.push('If deepfake suspected: terminate the call and verify via a separate channel');
      break;

    case 'SCREENSHARE_TOAD_DETECTED':
      actions.push('Terminate the screen share session immediately');
      actions.push('Verify the identity of the person requesting screen share via a separate channel');
      actions.push('Check if credentials or MFA codes were visible during the screen share');
      actions.push('If credentials were exposed: force password reset and revoke active sessions');
      actions.push('Block the page domain at DNS/web proxy');
      break;

    case 'PHISHVISION_BRAND_IMPERSONATION':
      actions.push('Block the phishing page domain at DNS/web proxy');
      actions.push('Check if credentials were entered on the impersonation page');
      actions.push('If credentials were entered: force password reset for the affected user');
      actions.push('Report the page to Safe Browsing / PhishTank');
      actions.push('Search email gateway for delivery URLs linking to this domain');
      break;

    case 'PROXY_AITM_DETECTED':
      actions.push('Block the proxy domain at DNS/web proxy immediately');
      actions.push('Revoke all active sessions for the targeted auth provider');
      actions.push('Force password reset AND re-enroll MFA (session tokens may be compromised)');
      actions.push('Check auth provider audit logs for suspicious token grants');
      actions.push('Report the proxy infrastructure to the targeted provider\'s abuse team');
      break;

    case 'SYNC_HIJACK_DETECTED':
      actions.push('Remove the attacker-controlled account from the browser profile immediately');
      actions.push('Disable browser sync and revoke sync tokens');
      actions.push('Force password reset for all accounts synced to the browser');
      actions.push('Audit Google/Microsoft account activity for unauthorized access');
      actions.push('Check for remote support tools (TeamViewer, AnyDesk) on the endpoint');
      break;

    case 'FAKESENDER_BRAND_IMPERSONATION':
      actions.push('Block the helpdesk subdomain at DNS/web proxy');
      actions.push('Check if credentials were entered on the impersonation page');
      actions.push('If credentials were entered: force password reset for the affected user');
      actions.push('Report the helpdesk account to the platform abuse team (Zendesk, Freshdesk, etc.)');
      actions.push('Search email gateway for delivery URLs linking to this helpdesk subdomain');
      break;

    case 'FIDO_DOWNGRADE_DETECTED':
      actions.push('Check if credentials were entered on the downgraded login page');
      actions.push('Verify User-Agent header in proxy/CDN logs for Safari+Windows mismatch');
      actions.push('If credentials compromised: force password reset AND revoke session tokens');
      actions.push('Block the proxy domain at DNS/web proxy');
      actions.push('Report to the identity provider abuse team (Microsoft, Google, Okta)');
      break;

    case 'IPFS_PHISHING_DETECTED':
      actions.push('Block the IPFS gateway domain at DNS/web proxy');
      actions.push('Check if credentials were entered on the IPFS-hosted page');
      actions.push('If credentials compromised: force password reset for the affected user');
      actions.push('Report the CID to IPFS gateway abuse teams for denylist addition');
      actions.push('Search email gateway for delivery URLs containing the IPFS CID');
      break;

    case 'LLM_GENERATED_PHISHING_DETECTED':
      actions.push('Block the phishing page domain at DNS/web proxy');
      actions.push('Check if credentials were entered on the AI-generated page');
      actions.push('If credentials compromised: force password reset for the affected user');
      actions.push('Report the page to Safe Browsing / PhishTank');
      actions.push('Search email gateway for delivery URLs linking to this domain');
      break;

    case 'VNC_AITM_DETECTED':
      actions.push('Block the VNC proxy domain at DNS/web proxy immediately');
      actions.push('Revoke all active sessions for the targeted auth provider');
      actions.push('Force password reset AND re-enroll MFA (session tokens may be compromised)');
      actions.push('Check auth provider audit logs for suspicious token grants');
      actions.push('Report the EvilnoVNC infrastructure to the targeted provider\'s abuse team');
      break;

    case 'PWA_PHISHING_DETECTED':
      actions.push('Uninstall the malicious PWA from the user\'s device');
      actions.push('Block the PWA hosting domain at DNS/web proxy');
      actions.push('Check if credentials were entered in the standalone PWA window');
      actions.push('If credentials compromised: force password reset for the affected user');
      actions.push('Report the page to Safe Browsing / PhishTank');
      break;

    case 'TPA_CONSENT_PHISHING_DETECTED':
      actions.push('Revoke the malicious app consent in Azure AD / Google Workspace admin portal');
      actions.push('Review OAuth app audit logs for data access by the malicious app');
      actions.push('Block the app client ID in Conditional Access / OAuth app policies');
      actions.push('If tokens were granted: revoke all active sessions for the affected user');
      actions.push('Search email gateway for the phishing URL that led to the consent page');
      break;

    case 'CRYPTO_DRAINER_DETECTED':
      actions.push('Block the drainer page domain at DNS/web proxy immediately');
      actions.push('Check if the user approved any transactions — revoke token approvals via revoke.cash');
      actions.push('If transactions were signed: assess asset loss and notify affected user');
      actions.push('Report the drainer contract address to ScamSniffer / Chainabuse');
      actions.push('Search for the phishing delivery URL in email/chat/social media');
      break;

    case 'CSS_CREDENTIAL_EXFIL_DETECTED':
      actions.push('Block the page domain at DNS/web proxy');
      actions.push('Check if credentials were autofilled into hidden or exfiltrated fields');
      actions.push('If credentials compromised: force password reset for the affected user');
      actions.push('Report the CSS exfiltration technique to Safe Browsing / PhishTank');
      actions.push('Review browser autofill settings to restrict cross-origin autofill');
      break;

    case 'WEBSOCKET_CREDENTIAL_EXFIL_DETECTED':
      actions.push('Block the WebSocket C2 server domain/IP at network firewall');
      actions.push('Assume partial credential compromise — force password reset for the affected user');
      actions.push('Check if keystroke data was relayed before the user completed entry');
      actions.push('Report the phishing page domain to Safe Browsing / PhishTank');
      actions.push('Search for the delivery URL in email/chat logs for additional victims');
      break;

    case 'SERVICE_WORKER_PERSISTENCE_DETECTED':
      actions.push('Navigate to chrome://serviceworker-internals and unregister the suspicious SW');
      actions.push('Clear site data for the affected domain (cookies, cache, storage)');
      actions.push('If credentials were entered: force password reset for the affected user');
      actions.push('Block the phishing domain at DNS/web proxy');
      actions.push('Check push notification subscriptions for the domain and revoke them');
      break;

    default:
      actions.push('Review detection signals and assess false positive likelihood');
      actions.push('Correlate with other alerts on the same host/user');
  }

  return actions;
}

/**
 * Get escalation target based on priority level.
 *
 * @param {string} priority
 * @returns {string}
 */
function getEscalationTarget(priority) {
  switch (priority) {
    case 'P1': return 'CIRT / Incident Commander';
    case 'P2': return 'Tier 2 — Malware IR / Identity team';
    case 'P3': return 'Tier 1 — SOC analyst investigation queue';
    case 'P4': return 'Tier 1 — Low priority investigation queue';
    default:   return 'Tier 1';
  }
}

/**
 * Generate a structured triage report string for an event.
 * Follows NIST SP 800-61r3 incident record format.
 *
 * @param {Object} triagedEvent - Event with .triage field from triageEvent()
 * @returns {string}
 */
export function formatTriageReport(triagedEvent) {
  const t = triagedEvent.triage;
  if (!t?.classified) return `[UNCLASSIFIED] ${triagedEvent.eventType}`;

  const lines = [
    'INCIDENT TRIAGE REPORT',
    '======================',
    `Event Type:      ${triagedEvent.eventType}`,
    `Timestamp:       ${triagedEvent.timestamp || new Date().toISOString()}`,
    '',
    'CLASSIFICATION',
    `Category:        ${t.category}`,
    `Severity:        ${t.priority} - ${t.severity}`,
    `MITRE ATT&CK:   ${t.mitreAttack} (${t.mitreName})`,
    `Threat Actor:    ${t.threatActor}`,
    `Description:     ${t.description}`,
    '',
    'AFFECTED SCOPE',
    `URL:             ${triagedEvent.url || triagedEvent.blobUrl || 'N/A'}`,
    `Tab ID:          ${triagedEvent.tabId ?? 'N/A'}`,
    `Risk Score:      ${(triagedEvent.riskScore || 0).toFixed(2)}`,
    `Signals:         ${(triagedEvent.signals || []).join(', ') || 'none'}`,
    '',
    'RECOMMENDED ACTIONS',
    ...t.recommendedActions.map((a, i) => `${i + 1}. ${a}`),
    '',
    'ESCALATION',
    `Routed To:       ${t.escalationTarget}`,
    `SLA Acknowledge: ${t.sla.acknowledge}`,
    `SLA Containment: ${t.sla.containment}`,
  ];

  return lines.join('\n');
}
