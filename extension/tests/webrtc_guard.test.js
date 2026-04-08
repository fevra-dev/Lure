/**
 * extension/__tests__/webrtc_guard.test.js
 *
 * Tests for WebRTCGuard — Virtual camera detection in WebRTC streams.
 *
 * jsdom limitations:
 *   - navigator.mediaDevices not available. Mocked via Object.defineProperty.
 *   - getUserMedia() returns a fake stream with getVideoTracks().
 *   - enumerateDevices() returns mock device descriptors.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome APIs before importing the module
const mockSendMessage = vi.fn();
vi.stubGlobal('chrome', {
  runtime: {
    id: 'test-extension-id',
    sendMessage: mockSendMessage,
  },
});

import '../content/webrtc_guard.js';
const { checkVirtualCameraSignals, checkWebRTCPageContext, calculateWebRTCRiskScore, injectWebRTCWarningBanner, installGetUserMediaInterceptor, _setLastGestureTimestamp } = globalThis.__phishopsExports['webrtc_guard'];

beforeEach(() => {
  document.body.innerHTML = '';
  document.getElementById('phishops-webrtc-warning')?.remove();
  vi.clearAllMocks();
  _setLastGestureTimestamp(0);
});

// =========================================================================
// checkVirtualCameraSignals
// =========================================================================

describe('checkVirtualCameraSignals', () => {
  it('detects OBS Virtual Camera label', () => {
    const devices = [
      { kind: 'videoinput', label: 'OBS Virtual Camera', deviceId: 'abc' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(true);
    expect(signals.find(s => s.id === 'webrtc:virtual_camera_label').weight).toBe(0.45);
  });

  it('detects ManyCam label', () => {
    const devices = [
      { kind: 'videoinput', label: 'ManyCam Virtual Webcam', deviceId: 'def' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(true);
  });

  it('detects Camo label', () => {
    const devices = [
      { kind: 'videoinput', label: 'Camo', deviceId: 'ghi' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(true);
  });

  it('detects Snap Camera label', () => {
    const devices = [
      { kind: 'videoinput', label: 'Snap Camera', deviceId: 'jkl' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(true);
  });

  it('does NOT flag physical camera', () => {
    const devices = [
      { kind: 'videoinput', label: 'FaceTime HD Camera (Built-in)', deviceId: 'phys' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(false);
  });

  it('does NOT flag audio input devices', () => {
    const devices = [
      { kind: 'audioinput', label: 'OBS Virtual Camera Audio', deviceId: 'aud' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(false);
  });

  it('does NOT flag device with empty label', () => {
    const devices = [
      { kind: 'videoinput', label: '', deviceId: 'empty' },
    ];
    const signals = checkVirtualCameraSignals(devices);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(false);
  });

  it('handles null/missing devices gracefully', () => {
    expect(() => checkVirtualCameraSignals(null)).not.toThrow();
    expect(() => checkVirtualCameraSignals(undefined)).not.toThrow();
    const signals = checkVirtualCameraSignals(null);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(false);
  });

  it('detects fast constraint response (<15ms)', () => {
    const devices = [];
    const streamInfo = { constraintResponseMs: 5 };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:fast_constraint_response')).toBe(true);
    expect(signals.find(s => s.id === 'webrtc:fast_constraint_response').weight).toBe(0.30);
  });

  it('does NOT flag slow constraint response (>=15ms)', () => {
    const devices = [];
    const streamInfo = { constraintResponseMs: 80 };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:fast_constraint_response')).toBe(false);
  });

  it('detects arbitrary resolution', () => {
    const devices = [];
    const streamInfo = { arbitraryResolution: true };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:arbitrary_resolution')).toBe(true);
    expect(signals.find(s => s.id === 'webrtc:arbitrary_resolution').weight).toBe(0.20);
  });

  it('does NOT flag discrete resolution (arbitraryResolution=false)', () => {
    const devices = [];
    const streamInfo = { arbitraryResolution: false };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:arbitrary_resolution')).toBe(false);
  });

  it('detects low frame jitter (<0.5ms)', () => {
    const devices = [];
    const streamInfo = { frameJitterStddev: 0.2 };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:low_frame_jitter')).toBe(true);
    expect(signals.find(s => s.id === 'webrtc:low_frame_jitter').weight).toBe(0.25);
  });

  it('does NOT flag normal frame jitter (>=0.5ms)', () => {
    const devices = [];
    const streamInfo = { frameJitterStddev: 2.5 };
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.some(s => s.id === 'webrtc:low_frame_jitter')).toBe(false);
  });

  it('detects no user gesture', () => {
    _setLastGestureTimestamp(0); // Very old
    const signals = checkVirtualCameraSignals([]);
    expect(signals.some(s => s.id === 'webrtc:no_user_gesture')).toBe(true);
  });

  it('does NOT flag when gesture is recent', () => {
    _setLastGestureTimestamp(Date.now()); // Just now
    const signals = checkVirtualCameraSignals([]);
    expect(signals.some(s => s.id === 'webrtc:no_user_gesture')).toBe(false);
  });

  it('combines multiple signals', () => {
    const devices = [
      { kind: 'videoinput', label: 'OBS Virtual Camera', deviceId: 'obs' },
    ];
    const streamInfo = { constraintResponseMs: 3, frameJitterStddev: 0.1 };
    _setLastGestureTimestamp(0);
    const signals = checkVirtualCameraSignals(devices, streamInfo);
    expect(signals.length).toBeGreaterThanOrEqual(4);
    expect(signals.some(s => s.id === 'webrtc:virtual_camera_label')).toBe(true);
    expect(signals.some(s => s.id === 'webrtc:fast_constraint_response')).toBe(true);
    expect(signals.some(s => s.id === 'webrtc:low_frame_jitter')).toBe(true);
    expect(signals.some(s => s.id === 'webrtc:no_user_gesture')).toBe(true);
  });
});

// =========================================================================
// checkWebRTCPageContext
// =========================================================================

describe('checkWebRTCPageContext', () => {
  it('returns empty for localhost (jsdom default) even with verification text', () => {
    // jsdom hostname is localhost, which is explicitly skipped in the guard
    document.body.textContent = 'Please complete identity verification to proceed.';
    const signals = checkWebRTCPageContext();
    expect(signals).toHaveLength(0);
  });

  it('returns empty for clean page', () => {
    document.body.textContent = 'Welcome to our video conferencing platform.';
    const signals = checkWebRTCPageContext();
    expect(signals).toHaveLength(0);
  });

  it('returns empty for known video platform hostname', () => {
    // localhost is explicitly skipped, so no signal should fire
    document.body.textContent = 'identity verification required';
    const signals = checkWebRTCPageContext();
    expect(signals).toHaveLength(0);
  });
});

// =========================================================================
// calculateWebRTCRiskScore
// =========================================================================

describe('calculateWebRTCRiskScore', () => {
  it('returns 0.0 for empty signals', () => {
    const { riskScore, signalList } = calculateWebRTCRiskScore([]);
    expect(riskScore).toBe(0.0);
    expect(signalList).toHaveLength(0);
  });

  it('returns correct score for single signal', () => {
    const { riskScore } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
    ]);
    expect(riskScore).toBe(0.45);
  });

  it('sums multiple signals', () => {
    const { riskScore, signalList } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
      { id: 'webrtc:no_user_gesture', weight: 0.25 },
    ]);
    expect(riskScore).toBe(0.70);
    expect(signalList).toHaveLength(2);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
      { id: 'webrtc:fast_constraint_response', weight: 0.30 },
      { id: 'webrtc:low_frame_jitter', weight: 0.25 },
      { id: 'webrtc:no_user_gesture', weight: 0.25 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('alert threshold is 0.50', () => {
    const { riskScore } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
      { id: 'webrtc:suspicious_page_context', weight: 0.20 },
    ]);
    expect(riskScore).toBe(0.65);
    expect(riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('block threshold is 0.70', () => {
    const { riskScore } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
      { id: 'webrtc:no_user_gesture', weight: 0.25 },
    ]);
    expect(riskScore).toBe(0.70);
    expect(riskScore).toBeGreaterThanOrEqual(0.70);
  });

  it('includes all signal IDs in signalList', () => {
    const { signalList } = calculateWebRTCRiskScore([
      { id: 'webrtc:virtual_camera_label', weight: 0.45 },
      { id: 'webrtc:fast_constraint_response', weight: 0.30 },
    ]);
    expect(signalList).toEqual(['webrtc:virtual_camera_label', 'webrtc:fast_constraint_response']);
  });
});

// =========================================================================
// injectWebRTCWarningBanner
// =========================================================================

describe('injectWebRTCWarningBanner', () => {
  it('injects a banner into the DOM', () => {
    injectWebRTCWarningBanner(0.75, 'OBS Virtual Camera', ['webrtc:virtual_camera_label']);
    const banner = document.getElementById('phishops-webrtc-warning');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
  });

  it('is idempotent', () => {
    injectWebRTCWarningBanner(0.75, 'OBS', ['a']);
    injectWebRTCWarningBanner(0.80, 'ManyCam', ['b']);
    const banners = document.querySelectorAll('#phishops-webrtc-warning');
    expect(banners).toHaveLength(1);
  });

  it('displays the risk score', () => {
    injectWebRTCWarningBanner(0.85, 'OBS Virtual Camera', ['webrtc:virtual_camera_label']);
    const banner = document.getElementById('phishops-webrtc-warning');
    expect(banner.textContent).toContain('0.85');
  });

  it('displays the device label', () => {
    injectWebRTCWarningBanner(0.75, 'ManyCam Virtual Webcam', ['webrtc:virtual_camera_label']);
    const banner = document.getElementById('phishops-webrtc-warning');
    expect(banner.textContent).toContain('ManyCam Virtual Webcam');
  });

  it('contains webrtc-specific title text', () => {
    injectWebRTCWarningBanner(0.75, 'OBS', ['webrtc:virtual_camera_label']);
    const banner = document.getElementById('phishops-webrtc-warning');
    expect(banner.textContent).toContain('virtual camera detected');
  });

  it('dismiss button removes the banner', () => {
    injectWebRTCWarningBanner(0.75, 'OBS', ['webrtc:virtual_camera_label']);
    const dismissBtn = document.getElementById('phishops-webrtc-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-webrtc-warning')).toBeNull();
  });

  it('handles null deviceLabel gracefully', () => {
    injectWebRTCWarningBanner(0.75, null, ['webrtc:no_user_gesture']);
    const banner = document.getElementById('phishops-webrtc-warning');
    expect(banner.textContent).toContain('unknown');
  });
});

// =========================================================================
// installGetUserMediaInterceptor
// =========================================================================

describe('installGetUserMediaInterceptor', () => {
  let mockGetUserMedia;
  let mockEnumerateDevices;

  beforeEach(() => {
    const mockTrack = {
      label: 'FaceTime HD Camera',
      applyConstraints: vi.fn().mockResolvedValue(undefined),
      getConstraints: vi.fn().mockReturnValue({}),
      getCapabilities: vi.fn().mockReturnValue({
        width: { min: 640, max: 1920, step: 1 },
        height: { min: 480, max: 1080, step: 1 },
      }),
    };
    const mockStream = {
      getVideoTracks: vi.fn().mockReturnValue([mockTrack]),
    };
    mockGetUserMedia = vi.fn().mockResolvedValue(mockStream);
    mockEnumerateDevices = vi.fn().mockResolvedValue([
      { kind: 'videoinput', label: 'FaceTime HD Camera', deviceId: 'phys' },
    ]);

    Object.defineProperty(navigator, 'mediaDevices', {
      value: {
        getUserMedia: mockGetUserMedia,
        enumerateDevices: mockEnumerateDevices,
      },
      writable: true,
      configurable: true,
    });

    document.getElementById('phishops-webrtc-warning')?.remove();
  });

  it('installs without error', () => {
    expect(() => installGetUserMediaInterceptor()).not.toThrow();
  });

  it('passes through to original getUserMedia for audio-only', async () => {
    installGetUserMediaInterceptor();
    await navigator.mediaDevices.getUserMedia({ audio: true });
    expect(mockGetUserMedia).toHaveBeenCalledWith({ audio: true });
  });

  it('returns stream for legitimate physical camera', async () => {
    _setLastGestureTimestamp(Date.now()); // Simulate recent gesture
    installGetUserMediaInterceptor();
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    expect(stream).toBeDefined();
    expect(stream.getVideoTracks).toBeDefined();
    expect(mockGetUserMedia).toHaveBeenCalled();
  });

  it('sends telemetry when virtual camera is detected', async () => {
    mockEnumerateDevices.mockResolvedValue([
      { kind: 'videoinput', label: 'OBS Virtual Camera', deviceId: 'obs' },
    ]);

    const mockTrack = {
      label: 'OBS Virtual Camera',
      applyConstraints: vi.fn().mockResolvedValue(undefined),
      getConstraints: vi.fn().mockReturnValue({}),
      getCapabilities: vi.fn().mockReturnValue({}),
    };
    const mockStream = {
      getVideoTracks: vi.fn().mockReturnValue([mockTrack]),
    };
    mockGetUserMedia.mockResolvedValue(mockStream);

    installGetUserMediaInterceptor();
    await navigator.mediaDevices.getUserMedia({ video: true });

    // Wait for async analysis to complete
    await new Promise(r => setTimeout(r, 50));

    expect(mockSendMessage).toHaveBeenCalled();
    const call = mockSendMessage.mock.calls[0][0];
    expect(call.type).toBe('WEBRTCGUARD_EVENT');
    expect(call.payload.eventType).toBe('WEBRTC_VIRTUAL_CAMERA_DETECTED');
    expect(call.payload.action).toBe('alerted');
    expect(call.payload.deviceLabel).toBe('OBS Virtual Camera');
  });

  it('does NOT send telemetry for physical camera with gesture and realistic timing', async () => {
    // Mock a realistic physical camera: slow constraint response, discrete resolution steps
    const mockTrack = {
      label: 'FaceTime HD Camera',
      applyConstraints: vi.fn().mockImplementation(() => new Promise(r => setTimeout(r, 50))),
      getConstraints: vi.fn().mockReturnValue({}),
      getCapabilities: vi.fn().mockReturnValue({
        width: { min: 640, max: 1920, step: 160 },
        height: { min: 480, max: 1080, step: 120 },
      }),
    };
    const mockStream = {
      getVideoTracks: vi.fn().mockReturnValue([mockTrack]),
    };
    mockGetUserMedia.mockResolvedValue(mockStream);

    _setLastGestureTimestamp(Date.now());
    installGetUserMediaInterceptor();
    await navigator.mediaDevices.getUserMedia({ video: true });

    // Wait for async analysis (including the 50ms applyConstraints)
    await new Promise(r => setTimeout(r, 150));

    expect(mockSendMessage).not.toHaveBeenCalled();
  });
});
