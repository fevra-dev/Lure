import { describe, it, expect } from 'vitest';
import '../content/webrtc_synthetic_track_main.js';
const { computeSyntheticTrackRiskScore, isSyntheticTrack, isVideoConferencingDomain } = globalThis.__phishopsExports['webrtc_synthetic_track_main'];

describe('computeSyntheticTrackRiskScore', () => {
  it('returns 0 for empty signal set', () => {
    expect(computeSyntheticTrackRiskScore([]).riskScore).toBe(0);
  });

  it('returns 0.30 for generator-only signal', () => {
    expect(computeSyntheticTrackRiskScore(['webrtc:track_generator_created']).riskScore).toBe(0.30);
  });

  it('returns 0.50 for processor + generator', () => {
    expect(computeSyntheticTrackRiskScore([
      'webrtc:track_generator_created',
      'webrtc:track_processor_created',
    ]).riskScore).toBe(0.50);
  });

  it('returns 1.0 (capped) for full compound pipeline', () => {
    expect(computeSyntheticTrackRiskScore([
      'webrtc:track_generator_created',
      'webrtc:track_processor_created',
      'webrtc:synthetic_track_added_to_peerconnection',
      'webrtc:getuseromedia_plus_synthetic_pipeline',
    ]).riskScore).toBe(1.0);
  });

  it('caps risk score at 1.0 for all signals combined', () => {
    expect(computeSyntheticTrackRiskScore([
      'webrtc:track_generator_created',
      'webrtc:track_processor_created',
      'webrtc:synthetic_track_added_to_peerconnection',
      'webrtc:getuseromedia_plus_synthetic_pipeline',
      'webrtc:ml_model_fetch_detected',
      'webrtc:video_track_generator_created',
    ]).riskScore).toBe(1.0);
  });

  it('returns the signal list unchanged', () => {
    const signals = ['webrtc:track_generator_created', 'webrtc:track_processor_created'];
    expect(computeSyntheticTrackRiskScore(signals).signalList).toEqual(signals);
  });

  it('returns 0.20 for processor-only signal', () => {
    expect(computeSyntheticTrackRiskScore(['webrtc:track_processor_created']).riskScore).toBe(0.20);
  });

  it('returns 0.40 for synthetic track added without pipeline context', () => {
    expect(computeSyntheticTrackRiskScore([
      'webrtc:synthetic_track_added_to_peerconnection',
    ]).riskScore).toBe(0.40);
  });

  it('returns 0.20 for ML model fetch signal alone', () => {
    expect(computeSyntheticTrackRiskScore(['webrtc:ml_model_fetch_detected']).riskScore).toBe(0.20);
  });

  it('returns 0.30 for VideoTrackGenerator signal', () => {
    expect(computeSyntheticTrackRiskScore(['webrtc:video_track_generator_created']).riskScore).toBe(0.30);
  });
});

describe('isSyntheticTrack', () => {
  it('returns true for track with empty label and no deviceId', () => {
    expect(isSyntheticTrack({ label: '', getSettings: () => ({}) })).toBe(true);
  });

  it('returns true for track with label but no deviceId in settings', () => {
    expect(isSyntheticTrack({ label: 'some-label', getSettings: () => ({}) })).toBe(true);
  });

  it('returns false for real camera track with label and deviceId', () => {
    expect(isSyntheticTrack({
      label: 'FaceTime HD Camera',
      getSettings: () => ({ deviceId: 'abc123', width: 1280, height: 720 }),
    })).toBe(false);
  });

  it('returns false for screen share track with displaySurface', () => {
    expect(isSyntheticTrack({
      label: '',
      getSettings: () => ({ displaySurface: 'monitor' }),
    })).toBe(false);
  });

  it('handles track without getSettings gracefully', () => {
    expect(() => isSyntheticTrack({ label: '' })).not.toThrow();
    expect(isSyntheticTrack({ label: '' })).toBe(true);
  });

  it('returns false for null track', () => {
    expect(isSyntheticTrack(null)).toBe(false);
  });
});

describe('isVideoConferencingDomain', () => {
  it('returns true for zoom.us', () => {
    expect(isVideoConferencingDomain('zoom.us')).toBe(true);
  });

  it('returns true for meet.google.com', () => {
    expect(isVideoConferencingDomain('meet.google.com')).toBe(true);
  });

  it('returns true for teams.microsoft.com', () => {
    expect(isVideoConferencingDomain('teams.microsoft.com')).toBe(true);
  });

  it('returns false for unknown domain', () => {
    expect(isVideoConferencingDomain('evil-verification.com')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(isVideoConferencingDomain('')).toBe(false);
  });

  it('returns false for domain containing platform name as substring', () => {
    expect(isVideoConferencingDomain('fake-zoom-meeting.phish.com')).toBe(false);
  });

  it('returns true for whereby.com', () => {
    expect(isVideoConferencingDomain('whereby.com')).toBe(true);
  });
});
