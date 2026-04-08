/**
 * extension/content/filesystem_guard_bridge.js
 *
 * FileSystemGuard — Isolated World Bridge & Signal Analyzer
 *
 * Receives observations from the MAIN world interceptor
 * (filesystem_guard_main.js) via window.postMessage, accumulates state,
 * and runs heuristic analysis to detect File System Access API abuse on
 * phishing pages.
 *
 * Threat model: A phishing page calls showDirectoryPicker() to gain
 * recursive read access to an entire directory tree. Once the user selects
 * a folder, the page can silently enumerate and read credential files
 * (~/.aws/credentials, ~/.kube/config, .env, shell histories, etc.) and
 * exfiltrate them via fetch() — all with a single click and zero additional
 * prompts. Chrome's blocklist does not cover these critical files.
 *
 * Signal architecture:
 *   fsg:directory_picker_invoked      +0.30  showDirectoryPicker() called
 *   fsg:directory_write_access        +0.20  mode: 'readwrite' requested
 *   fsg:file_picker_invoked           +0.15  showOpenFilePicker() called
 *   fsg:save_picker_invoked           +0.20  showSaveFilePicker() called
 *   fsg:suspicious_start_location     +0.15  startIn: 'desktop'|'documents'
 *   fsg:directory_enumeration         +0.25  .entries()/.values() on dir handle
 *   fsg:file_read_attempt             +0.10  .getFile() on file handle
 *   fsg:credential_file_targeted      +0.35  file name matches credential patterns
 *   fsg:write_stream_opened           +0.20  .createWritable() called
 *   fsg:post_read_network_exfil       +0.40  Fetch/XHR within 5000ms of file read
 *
 * Alert threshold: 0.40 | Block threshold: 0.65
 *
 * @module FileSystemGuardBridge
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.40;
const BLOCK_THRESHOLD = 0.65;

const SOURCE_ID = 'PHISHOPS_FSG';

/** Network request correlation window after a file read (ms). */
const EXFIL_WINDOW_MS = 5000;

/** Well-known directories that are suspicious targets for data exfil. */
const SUSPICIOUS_START_LOCATIONS = new Set(['desktop', 'documents']);

/**
 * Credential and sensitive file name patterns.
 * Tested against FileSystemFileHandle.name (filename only, no path).
 */
const CREDENTIAL_PATTERNS = [
  /^credentials$/i,
  /^config$/i,
  /^\.env$/i,
  /\.env(\.|$)/i,          // .env.local, .env.production, etc.
  /^id_rsa$/i,
  /^id_ed25519$/i,
  /^id_ecdsa$/i,
  /^id_dsa$/i,
  /^\.netrc$/i,
  /^\.npmrc$/i,
  /^\.gitconfig$/i,
  /^\.bash_history$/i,
  /^\.zsh_history$/i,
  /^Login Data$/i,
  /^kubeconfig$/i,
  /^\.aws$/i,
  /^\.kube$/i,
  /docker/i,
  /^\.bashrc$/i,
  /^\.zshrc$/i,
  /^\.profile$/i,
];

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/** Records of picker invocations from the MAIN world. */
const pickerRecords = [];

/** Records of directory enumeration (.entries/.values/.keys calls). */
const enumRecords = [];

/** Records of file read attempts (.getFile calls). */
const fileReadRecords = [];

/** Records of write stream opens (.createWritable calls). */
const writeRecords = [];

/** Network requests observed in this isolated world. */
const networkRecords = [];

let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Network monitoring (fetch + XHR in isolated world)                */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined') {
  // Monitor fetch for post-read exfiltration correlation
  if (typeof window.fetch === 'function') {
    const origFetch = window.fetch;
    window.fetch = function (...args) {
      try {
        networkRecords.push({
          url: typeof args[0] === 'string' ? args[0] : (args[0]?.url || ''),
          method: args[1]?.method || 'GET',
          timestamp: Date.now(),
        });
      } catch { /* non-critical */ }
      return origFetch.apply(this, args);
    };
  }

  // Monitor XHR
  if (typeof XMLHttpRequest !== 'undefined') {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      try {
        networkRecords.push({
          url: String(url),
          method: String(method),
          timestamp: Date.now(),
        });
      } catch { /* non-critical */ }
      return origOpen.call(this, method, url, ...rest);
    };
  }
}

/* ------------------------------------------------------------------ */
/*  Message Listener (MAIN world -> isolated world bridge)            */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined') {
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== SOURCE_ID) return;

    const { type, data } = event.data;

    switch (type) {
      case 'FSG_DIRECTORY_PICKER_INVOKED':
        pickerRecords.push({
          type: 'directory',
          mode: data?.mode || 'read',
          startIn: data?.startIn || null,
          timestamp: data?.timestamp || Date.now(),
        });
        break;
      case 'FSG_FILE_PICKER_INVOKED':
        pickerRecords.push({
          type: 'open',
          multiple: !!data?.multiple,
          startIn: data?.startIn || null,
          timestamp: data?.timestamp || Date.now(),
        });
        break;
      case 'FSG_SAVE_PICKER_INVOKED':
        pickerRecords.push({
          type: 'save',
          startIn: data?.startIn || null,
          timestamp: data?.timestamp || Date.now(),
        });
        break;
      case 'FSG_DIRECTORY_ENUMERATION':
        enumRecords.push({
          method: data?.method || 'entries',
          name: data?.name || '',
          timestamp: data?.timestamp || Date.now(),
        });
        break;
      case 'FSG_FILE_READ_ATTEMPT':
        fileReadRecords.push({
          name: data?.name || '',
          timestamp: data?.timestamp || Date.now(),
        });
        break;
      case 'FSG_WRITE_STREAM_OPENED':
        writeRecords.push({
          name: data?.name || '',
          timestamp: data?.timestamp || Date.now(),
        });
        break;
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                   */
/* ------------------------------------------------------------------ */

/**
 * Signal: showDirectoryPicker() was called.
 * Also emits fsg:directory_write_access and fsg:suspicious_start_location
 * if applicable.
 * Base weight: 0.30 — directory picker gives bulk recursive access.
 */
function checkDirectoryPickerInvoked(records) {
  const dirPickers = (records || []).filter(r => r.type === 'directory');
  if (dirPickers.length === 0) return [];

  const signals = [{
    id: 'fsg:directory_picker_invoked',
    weight: 0.30,
    count: dirPickers.length,
  }];

  if (dirPickers.some(r => r.mode === 'readwrite')) {
    signals.push({ id: 'fsg:directory_write_access', weight: 0.20 });
  }

  if (dirPickers.some(r => SUSPICIOUS_START_LOCATIONS.has(r.startIn))) {
    signals.push({ id: 'fsg:suspicious_start_location', weight: 0.15 });
  }

  return signals;
}

/**
 * Signal: showOpenFilePicker() was called.
 * Also emits fsg:suspicious_start_location if applicable.
 * Weight: 0.15 — file picker grants single-file access; less severe than
 * directory picker but still anomalous on non-IDE phishing pages.
 */
function checkFilePickerInvoked(records) {
  const openPickers = (records || []).filter(r => r.type === 'open');
  if (openPickers.length === 0) return [];

  const signals = [{
    id: 'fsg:file_picker_invoked',
    weight: 0.15,
    count: openPickers.length,
  }];

  if (openPickers.some(r => SUSPICIOUS_START_LOCATIONS.has(r.startIn))) {
    signals.push({ id: 'fsg:suspicious_start_location', weight: 0.15 });
  }

  return signals;
}

/**
 * Signal: showSaveFilePicker() was called.
 * Weight: 0.20 — save picker creates files on disk without Chrome download
 * history (FileJacking research, Print3M 2025). Used for DLL/EXE planting.
 */
function checkSavePickerInvoked(records) {
  const savePickers = (records || []).filter(r => r.type === 'save');
  if (savePickers.length === 0) return [];

  return [{
    id: 'fsg:save_picker_invoked',
    weight: 0.20,
    count: savePickers.length,
  }];
}

/**
 * Signal: Directory handle .entries() / .values() / .keys() was called.
 * Weight: 0.25 — recursive enumeration is the prerequisite for bulk exfil.
 */
function checkDirectoryEnumeration(records) {
  if (!records || records.length === 0) return [];

  return [{
    id: 'fsg:directory_enumeration',
    weight: 0.25,
    count: records.length,
  }];
}

/**
 * Signal: File handle .getFile() was called.
 * Weight: 0.10 — confirms the page actually reads file content,
 * not just obtains a handle.
 */
function checkFileReadAttempts(records) {
  if (!records || records.length === 0) return [];

  return [{
    id: 'fsg:file_read_attempt',
    weight: 0.10,
    count: records.length,
  }];
}

/**
 * Signal: A file with a credential-related name was targeted.
 * Weight: 0.35 — reading files named 'credentials', '.env', 'id_rsa',
 * 'Login Data', etc. is a near-definitive indicator of credential theft.
 */
function checkCredentialFileTargeted(records) {
  if (!records || records.length === 0) return [];

  const matched = records
    .map(r => r.name || '')
    .filter(name => name && CREDENTIAL_PATTERNS.some(p => p.test(name)));

  if (matched.length === 0) return [];

  return [{
    id: 'fsg:credential_file_targeted',
    weight: 0.35,
    matchedFiles: [...new Set(matched)],
  }];
}

/**
 * Signal: File handle .createWritable() was called.
 * Weight: 0.20 — write access enables ransomware-style file modification
 * or planting of malicious files (cf. RøB, USENIX 2023).
 */
function checkWriteStreamOpened(records) {
  if (!records || records.length === 0) return [];

  return [{
    id: 'fsg:write_stream_opened',
    weight: 0.20,
    count: records.length,
  }];
}

/**
 * Signal: Network request occurred within EXFIL_WINDOW_MS after a file read.
 * Weight: 0.40 — the highest-confidence signal. File read immediately
 * followed by an outbound request is the complete credential exfiltration
 * sequence.
 */
function checkPostReadExfil(fileReads, networkReqs) {
  if (!fileReads || fileReads.length === 0) return [];
  if (!networkReqs || networkReqs.length === 0) return [];

  const lastReadTs = Math.max(...fileReads.map(r => r.timestamp));
  const hasExfil = networkReqs.some(n =>
    n.timestamp > lastReadTs && (n.timestamp - lastReadTs) <= EXFIL_WINDOW_MS
  );

  if (!hasExfil) return [];

  return [{ id: 'fsg:post_read_network_exfil', weight: 0.40 }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateFsgRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectFsgWarningBanner(riskScore, signals, credFiles) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-fsg-banner')) return;

  const severity = riskScore >= 0.85 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const credText = credFiles && credFiles.length > 0
    ? ` | Files: ${credFiles.slice(0, 3).join(', ')}`
    : '';

  const banner = document.createElement('div');
  banner.id = 'phishops-fsg-banner';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#0A0907', 'border-bottom:2px solid #BF1B1B',
    'padding:14px 20px',
    "font-family:'Work Sans',system-ui,-apple-system,sans-serif",
    'display:flex', 'align-items:center', 'gap:14px',
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:24px;flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B;font-size:15px;display:block;margin-bottom:3px;font-family:'Work Sans',system-ui,sans-serif;">
        file system access api abuse detected \u2014 phishops filesystemguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('fsg:', '')).join(', ')}${credText}
      </span>
    </div>
    <button id="phishops-fsg-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-fsg-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on all accumulated File System Access API observations.
 */
function runFsgAnalysis(pickerRecs, enumRecs, fileRecs, writeRecs, netRecs) {
  const allSignals = [
    ...checkDirectoryPickerInvoked(pickerRecs),
    ...checkFilePickerInvoked(pickerRecs),
    ...checkSavePickerInvoked(pickerRecs),
    ...checkDirectoryEnumeration(enumRecs),
    ...checkFileReadAttempts(fileRecs),
    ...checkCredentialFileTargeted(fileRecs),
    ...checkWriteStreamOpened(writeRecs),
    ...checkPostReadExfil(fileRecs, netRecs),
  ];

  const { riskScore, signalList } = calculateFsgRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.85 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  const dirRecord = (pickerRecs || []).find(r => r.type === 'directory');
  const pickerType = dirRecord ? 'directory'
    : ((pickerRecs || []).find(r => r.type === 'save') ? 'save' : 'open');

  const credSignal = allSignals.find(s => s.id === 'fsg:credential_file_targeted');
  const credentialFilesDetected = credSignal?.matchedFiles || [];

  injectFsgWarningBanner(riskScore, allSignals, credentialFilesDetected);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'FILESYSTEMGUARD_EVENT',
      payload: {
        eventType: 'FILE_SYSTEM_PICKER_ABUSE_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        pickerType,
        fileCount: (fileRecs || []).length + (enumRecs || []).length,
        credentialFilesDetected,
        writeAccessRequested: (writeRecs || []).length > 0 || dirRecord?.mode === 'readwrite',
        postReadExfil: signalList.includes('fsg:post_read_network_exfil'),
        action,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                            */
/* ------------------------------------------------------------------ */

function _getPickerRecords()   { return pickerRecords; }
function _getFileReadRecords() { return fileReadRecords; }
function _getNetworkRecords()  { return networkRecords; }

function _resetState() {
  pickerRecords.length = 0;
  enumRecords.length = 0;
  fileReadRecords.length = 0;
  writeRecords.length = 0;
  networkRecords.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (typeof document !== 'undefined') {
    const trigger = () => {
      setTimeout(() => {
        if (!analysisRun) {
          runFsgAnalysis(pickerRecords, enumRecords, fileReadRecords, writeRecords, networkRecords);
          analysisRun = true;
        }
      }, 3000);
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', trigger);
    } else {
      trigger();
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['filesystem_guard_bridge'] = {
    checkDirectoryPickerInvoked,
    checkFilePickerInvoked,
    checkSavePickerInvoked,
    checkDirectoryEnumeration,
    checkFileReadAttempts,
    checkCredentialFileTargeted,
    checkWriteStreamOpened,
    checkPostReadExfil,
    calculateFsgRiskScore,
    injectFsgWarningBanner,
    runFsgAnalysis,
    _getPickerRecords,
    _getFileReadRecords,
    _getNetworkRecords,
    _resetState,
  };
}
