/**
 * extension/tests/filesystem_guard.test.js
 *
 * Tests for FileSystemGuard — File System Access API Credential Exfiltration Detection
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  checkDirectoryPickerInvoked,
  checkFilePickerInvoked,
  checkSavePickerInvoked,
  checkDirectoryEnumeration,
  checkFileReadAttempts,
  checkCredentialFileTargeted,
  checkWriteStreamOpened,
  checkPostReadExfil,
  calculateFsgRiskScore,
  runFsgAnalysis,
  _resetState,
} from '../content/filesystem_guard_bridge.js';

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
/* ------------------------------------------------------------------ */

function makePickerRecord(opts = {}) {
  return {
    type: opts.type || 'directory',
    mode: opts.mode || 'read',
    startIn: opts.startIn || null,
    multiple: opts.multiple || false,
    timestamp: opts.timestamp || Date.now(),
  };
}

function makeFileReadRecord(name = 'file.txt', ts = Date.now()) {
  return { name, timestamp: ts };
}

function makeNetworkRecord(url = 'https://evil.example.com/collect', ts = Date.now()) {
  return { url, method: 'POST', timestamp: ts };
}

function makeEnumRecord(method = 'entries', ts = Date.now()) {
  return { method, name: 'SomeDirectory', timestamp: ts };
}

function makeWriteRecord(name = 'output.exe', ts = Date.now()) {
  return { name, timestamp: ts };
}

afterEach(() => {
  _resetState();
  vi.unstubAllGlobals();
});

/* ------------------------------------------------------------------ */
/*  checkDirectoryPickerInvoked                                        */
/* ------------------------------------------------------------------ */

describe('checkDirectoryPickerInvoked', () => {
  it('returns fsg:directory_picker_invoked for a directory record', () => {
    const signals = checkDirectoryPickerInvoked([makePickerRecord({ type: 'directory' })]);
    expect(signals.some(s => s.id === 'fsg:directory_picker_invoked')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:directory_picker_invoked').weight).toBe(0.30);
  });

  it('returns fsg:directory_write_access when mode is readwrite', () => {
    const signals = checkDirectoryPickerInvoked([
      makePickerRecord({ type: 'directory', mode: 'readwrite' }),
    ]);
    expect(signals.some(s => s.id === 'fsg:directory_write_access')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:directory_write_access').weight).toBe(0.20);
  });

  it('returns fsg:suspicious_start_location when startIn is desktop', () => {
    const signals = checkDirectoryPickerInvoked([
      makePickerRecord({ type: 'directory', startIn: 'desktop' }),
    ]);
    expect(signals.some(s => s.id === 'fsg:suspicious_start_location')).toBe(true);
  });

  it('returns fsg:suspicious_start_location when startIn is documents', () => {
    const signals = checkDirectoryPickerInvoked([
      makePickerRecord({ type: 'directory', startIn: 'documents' }),
    ]);
    expect(signals.some(s => s.id === 'fsg:suspicious_start_location')).toBe(true);
  });

  it('does NOT return directory signals for open picker type', () => {
    const signals = checkDirectoryPickerInvoked([makePickerRecord({ type: 'open' })]);
    expect(signals).toHaveLength(0);
  });

  it('returns empty array for empty records', () => {
    expect(checkDirectoryPickerInvoked([])).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkFilePickerInvoked                                             */
/* ------------------------------------------------------------------ */

describe('checkFilePickerInvoked', () => {
  it('returns fsg:file_picker_invoked for an open picker record', () => {
    const signals = checkFilePickerInvoked([makePickerRecord({ type: 'open' })]);
    expect(signals.some(s => s.id === 'fsg:file_picker_invoked')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:file_picker_invoked').weight).toBe(0.15);
  });

  it('returns fsg:suspicious_start_location when startIn is desktop', () => {
    const signals = checkFilePickerInvoked([
      makePickerRecord({ type: 'open', startIn: 'desktop' }),
    ]);
    expect(signals.some(s => s.id === 'fsg:suspicious_start_location')).toBe(true);
  });

  it('does NOT return file picker signal for directory type', () => {
    const signals = checkFilePickerInvoked([makePickerRecord({ type: 'directory' })]);
    expect(signals).toHaveLength(0);
  });

  it('returns empty array for null records', () => {
    expect(checkFilePickerInvoked(null)).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkSavePickerInvoked                                             */
/* ------------------------------------------------------------------ */

describe('checkSavePickerInvoked', () => {
  it('returns fsg:save_picker_invoked for a save picker record', () => {
    const signals = checkSavePickerInvoked([makePickerRecord({ type: 'save' })]);
    expect(signals.some(s => s.id === 'fsg:save_picker_invoked')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:save_picker_invoked').weight).toBe(0.20);
  });

  it('does NOT return save signal for open picker', () => {
    const signals = checkSavePickerInvoked([makePickerRecord({ type: 'open' })]);
    expect(signals).toHaveLength(0);
  });

  it('returns empty array for null records', () => {
    expect(checkSavePickerInvoked(null)).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkDirectoryEnumeration                                          */
/* ------------------------------------------------------------------ */

describe('checkDirectoryEnumeration', () => {
  it('detects .entries() enumeration call', () => {
    const signals = checkDirectoryEnumeration([makeEnumRecord('entries')]);
    expect(signals.some(s => s.id === 'fsg:directory_enumeration')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:directory_enumeration').weight).toBe(0.25);
  });

  it('detects .values() enumeration call', () => {
    const signals = checkDirectoryEnumeration([makeEnumRecord('values')]);
    expect(signals.some(s => s.id === 'fsg:directory_enumeration')).toBe(true);
  });

  it('returns empty for empty records', () => {
    expect(checkDirectoryEnumeration([])).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkFileReadAttempts                                              */
/* ------------------------------------------------------------------ */

describe('checkFileReadAttempts', () => {
  it('returns fsg:file_read_attempt signal', () => {
    const signals = checkFileReadAttempts([makeFileReadRecord('readme.txt')]);
    expect(signals.some(s => s.id === 'fsg:file_read_attempt')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:file_read_attempt').weight).toBe(0.10);
  });

  it('count reflects multiple reads', () => {
    const signals = checkFileReadAttempts([
      makeFileReadRecord('a.txt'),
      makeFileReadRecord('b.txt'),
      makeFileReadRecord('c.txt'),
    ]);
    expect(signals.find(s => s.id === 'fsg:file_read_attempt').count).toBe(3);
  });

  it('returns empty for empty records', () => {
    expect(checkFileReadAttempts([])).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkCredentialFileTargeted                                        */
/* ------------------------------------------------------------------ */

describe('checkCredentialFileTargeted', () => {
  it('matches "credentials"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('credentials')])).toHaveLength(1);
  });

  it('matches ".env"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.env')])).toHaveLength(1);
  });

  it('matches ".env.local" (subdot pattern)', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.env.local')])).toHaveLength(1);
  });

  it('matches ".env.production"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.env.production')])).toHaveLength(1);
  });

  it('matches "id_rsa"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('id_rsa')])).toHaveLength(1);
  });

  it('matches "id_ed25519"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('id_ed25519')])).toHaveLength(1);
  });

  it('matches "id_ecdsa"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('id_ecdsa')])).toHaveLength(1);
  });

  it('matches ".npmrc"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.npmrc')])).toHaveLength(1);
  });

  it('matches ".gitconfig"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.gitconfig')])).toHaveLength(1);
  });

  it('matches ".bash_history"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.bash_history')])).toHaveLength(1);
  });

  it('matches ".zsh_history"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('.zsh_history')])).toHaveLength(1);
  });

  it('matches "Login Data"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('Login Data')])).toHaveLength(1);
  });

  it('matches "kubeconfig"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('kubeconfig')])).toHaveLength(1);
  });

  it('matches filename containing "docker"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('docker-compose.yml')])).toHaveLength(1);
  });

  it('does NOT match "index.html"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('index.html')])).toHaveLength(0);
  });

  it('does NOT match "readme.txt"', () => {
    expect(checkCredentialFileTargeted([makeFileReadRecord('readme.txt')])).toHaveLength(0);
  });

  it('returns correct matchedFiles list', () => {
    const signals = checkCredentialFileTargeted([
      makeFileReadRecord('credentials'),
      makeFileReadRecord('.env'),
      makeFileReadRecord('readme.txt'),
    ]);
    expect(signals[0].matchedFiles).toContain('credentials');
    expect(signals[0].matchedFiles).toContain('.env');
    expect(signals[0].matchedFiles).not.toContain('readme.txt');
  });

  it('returns empty for empty records', () => {
    expect(checkCredentialFileTargeted([])).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkWriteStreamOpened                                             */
/* ------------------------------------------------------------------ */

describe('checkWriteStreamOpened', () => {
  it('returns fsg:write_stream_opened signal', () => {
    const signals = checkWriteStreamOpened([makeWriteRecord()]);
    expect(signals.some(s => s.id === 'fsg:write_stream_opened')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:write_stream_opened').weight).toBe(0.20);
  });

  it('returns empty for empty records', () => {
    expect(checkWriteStreamOpened([])).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  checkPostReadExfil                                                 */
/* ------------------------------------------------------------------ */

describe('checkPostReadExfil', () => {
  it('detects exfil within 5000ms of file read', () => {
    const now = Date.now();
    const fileReads = [makeFileReadRecord('credentials', now)];
    const netReqs = [makeNetworkRecord('https://evil.com/upload', now + 1000)];
    const signals = checkPostReadExfil(fileReads, netReqs);
    expect(signals.some(s => s.id === 'fsg:post_read_network_exfil')).toBe(true);
    expect(signals.find(s => s.id === 'fsg:post_read_network_exfil').weight).toBe(0.40);
  });

  it('does NOT detect exfil 6000ms after file read (outside window)', () => {
    const now = Date.now();
    const fileReads = [makeFileReadRecord('.env', now)];
    const netReqs = [makeNetworkRecord('https://evil.com/upload', now + 6000)];
    const signals = checkPostReadExfil(fileReads, netReqs);
    expect(signals).toHaveLength(0);
  });

  it('detects correctly at boundary edge (4999ms)', () => {
    const now = Date.now();
    const fileReads = [makeFileReadRecord('id_rsa', now)];
    const netReqs = [makeNetworkRecord('https://evil.com/steal', now + 4999)];
    const signals = checkPostReadExfil(fileReads, netReqs);
    expect(signals.some(s => s.id === 'fsg:post_read_network_exfil')).toBe(true);
  });

  it('does NOT detect when no file reads occurred', () => {
    const netReqs = [makeNetworkRecord()];
    const signals = checkPostReadExfil([], netReqs);
    expect(signals).toHaveLength(0);
  });

  it('does NOT detect when no network requests occurred', () => {
    const fileReads = [makeFileReadRecord('credentials')];
    const signals = checkPostReadExfil(fileReads, []);
    expect(signals).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  calculateFsgRiskScore                                              */
/* ------------------------------------------------------------------ */

describe('calculateFsgRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore } = calculateFsgRiskScore([]);
    expect(riskScore).toBe(0);
  });

  it('sums weights correctly (0.30 + 0.25 = 0.55)', () => {
    const signals = [
      { id: 'fsg:directory_picker_invoked', weight: 0.30 },
      { id: 'fsg:directory_enumeration', weight: 0.25 },
    ];
    const { riskScore } = calculateFsgRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.55, 5);
  });

  it('caps at 1.0 when weights overflow', () => {
    const signals = [
      { id: 'fsg:directory_picker_invoked', weight: 0.30 },
      { id: 'fsg:directory_enumeration', weight: 0.25 },
      { id: 'fsg:credential_file_targeted', weight: 0.35 },
      { id: 'fsg:post_read_network_exfil', weight: 0.40 },
    ];
    const { riskScore } = calculateFsgRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns signalList array of IDs', () => {
    const signals = [
      { id: 'fsg:directory_picker_invoked', weight: 0.30 },
      { id: 'fsg:directory_enumeration', weight: 0.25 },
    ];
    const { signalList } = calculateFsgRiskScore(signals);
    expect(signalList).toContain('fsg:directory_picker_invoked');
    expect(signalList).toContain('fsg:directory_enumeration');
  });
});

/* ------------------------------------------------------------------ */
/*  runFsgAnalysis (integration)                                       */
/* ------------------------------------------------------------------ */

describe('runFsgAnalysis', () => {
  function mockChrome() {
    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });
    return sendMessage;
  }

  it('does NOT fire telemetry below ALERT_THRESHOLD (0.40)', () => {
    const sendMessage = mockChrome();
    // Only file picker = 0.15, below threshold
    const pickers = [makePickerRecord({ type: 'open' })];
    runFsgAnalysis(pickers, [], [], [], []);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('fires telemetry when risk score exceeds ALERT_THRESHOLD', () => {
    const sendMessage = mockChrome();
    // Directory picker (0.30) + enumeration (0.25) = 0.55, above 0.40
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    runFsgAnalysis(pickers, enums, [], [], []);
    expect(sendMessage).toHaveBeenCalled();
  });

  it('sends correct message type FILESYSTEMGUARD_EVENT', () => {
    const sendMessage = mockChrome();
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    runFsgAnalysis(pickers, enums, [], [], []);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'FILESYSTEMGUARD_EVENT' })
    );
  });

  it('sends correct eventType FILE_SYSTEM_PICKER_ABUSE_DETECTED', () => {
    const sendMessage = mockChrome();
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    runFsgAnalysis(pickers, enums, [], [], []);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({
          eventType: 'FILE_SYSTEM_PICKER_ABUSE_DETECTED',
        }),
      })
    );
  });

  it('sets severity Critical when riskScore >= 0.85', () => {
    const sendMessage = mockChrome();
    const now = Date.now();
    // 0.30 + 0.25 + 0.35 + 0.40 = 1.30 → capped 1.0 >= 0.85 → Critical
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    const fileReads = [makeFileReadRecord('credentials', now)];
    const netReqs = [makeNetworkRecord('https://evil.com/steal', now + 500)];
    runFsgAnalysis(pickers, enums, fileReads, [], netReqs);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({ severity: 'Critical' }),
      })
    );
  });

  it('sets severity High when 0.65 <= riskScore < 0.85', () => {
    const sendMessage = mockChrome();
    // 0.30 + 0.25 + 0.20 = 0.75 → High
    const pickers = [makePickerRecord({ type: 'directory', mode: 'readwrite' })];
    const enums = [makeEnumRecord()];
    runFsgAnalysis(pickers, enums, [], [], []);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({ severity: 'High' }),
      })
    );
  });

  it('sets severity Medium when 0.40 <= riskScore < 0.65', () => {
    const sendMessage = mockChrome();
    // Directory picker 0.30 + suspicious startIn 0.15 = 0.45 → Medium
    const pickers = [makePickerRecord({ type: 'directory', startIn: 'desktop' })];
    runFsgAnalysis(pickers, [], [], [], []);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({ severity: 'Medium' }),
      })
    );
  });

  it('sets postReadExfil true when exfil signal present', () => {
    const sendMessage = mockChrome();
    const now = Date.now();
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    const fileReads = [makeFileReadRecord('credentials', now)];
    const netReqs = [makeNetworkRecord('https://evil.com/c2', now + 1000)];
    runFsgAnalysis(pickers, enums, fileReads, [], netReqs);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({ postReadExfil: true }),
      })
    );
  });

  it('populates credentialFilesDetected array', () => {
    const sendMessage = mockChrome();
    const pickers = [makePickerRecord({ type: 'directory' })];
    const enums = [makeEnumRecord()];
    const fileReads = [makeFileReadRecord('credentials'), makeFileReadRecord('.env')];
    runFsgAnalysis(pickers, enums, fileReads, [], []);
    const call = sendMessage.mock.calls[0][0];
    expect(call.payload.credentialFilesDetected).toContain('credentials');
    expect(call.payload.credentialFilesDetected).toContain('.env');
  });
});
