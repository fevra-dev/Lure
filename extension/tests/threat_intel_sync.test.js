import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  parsePhishnetFeed,
  buildDomainSet,
  buildIPSet,
  buildExfilEndpointSet,
  extractDomainFromUrl,
  isDomainKnownBad,
  isIPKnownBad,
  isExfilEndpointKnownBad,
  computeThreatIntelStats,
  fetchPhishStatsRecords,
  fetchPhishnetDomains,
  syncThreatIntel,
} from '../lib/threat_intel_sync.js';

describe('parsePhishnetFeed', () => {
  it('refangs hxxp:// URLs', () => {
    const result = parsePhishnetFeed('hxxps://evil[.]com/phish\nhxxp://bad[.]org/login');
    expect(result).toContain('evil.com');
    expect(result).toContain('bad.org');
  });

  it('handles nested [.] pattern', () => {
    const result = parsePhishnetFeed('hxxps://sub[.]example[.]com/path');
    expect(result).toContain('sub.example.com');
  });

  it('skips blank lines and comments', () => {
    const result = parsePhishnetFeed('\n\n# comment\nhxxps://real[.]com/x\n\n');
    expect(result).toHaveLength(1);
    expect(result[0]).toBe('real.com');
  });

  it('deduplicates domains from multiple paths on same host', () => {
    const result = parsePhishnetFeed('hxxps://dup[.]com/a\nhxxps://dup[.]com/b');
    expect(result.filter(d => d === 'dup.com')).toHaveLength(1);
  });

  it('returns empty array for empty input', () => {
    expect(parsePhishnetFeed('')).toEqual([]);
  });

  it('handles plain https:// lines without defanging', () => {
    const result = parsePhishnetFeed('https://normal[.]com/path');
    expect(result).toContain('normal.com');
  });
});

describe('buildDomainSet', () => {
  const records = [
    { url: 'https://phish1.com/login', score: 6 },
    { url: 'https://phish2.net/steal', score: 5 },
    { url: 'https://phish1.com/other', score: 7 },
    { url: 'not-a-url', score: 6 },
  ];

  it('extracts unique domains from phishstats records', () => {
    const result = buildDomainSet(records);
    expect(result).toContain('phish1.com');
    expect(result).toContain('phish2.net');
  });

  it('deduplicates domains', () => {
    const result = buildDomainSet(records);
    expect(result.filter(d => d === 'phish1.com')).toHaveLength(1);
  });

  it('skips malformed URLs without throwing', () => {
    expect(() => buildDomainSet(records)).not.toThrow();
  });

  it('returns empty array for empty input', () => {
    expect(buildDomainSet([])).toEqual([]);
  });
});

describe('buildIPSet', () => {
  const records = [
    { ip: '192.168.1.1' },
    { ip: '10.0.0.1' },
    { ip: '192.168.1.1' },
    { ip: null },
    { ip: '' },
  ];

  it('extracts unique valid IPs', () => {
    const result = buildIPSet(records);
    expect(result).toContain('192.168.1.1');
    expect(result).toContain('10.0.0.1');
  });

  it('deduplicates IPs', () => {
    const result = buildIPSet(records);
    expect(result.filter(ip => ip === '192.168.1.1')).toHaveLength(1);
  });

  it('skips null and empty IPs', () => {
    const result = buildIPSet(records);
    expect(result).not.toContain(null);
    expect(result).not.toContain('');
  });
});

describe('buildExfilEndpointSet', () => {
  it('extracts exfil endpoint domains when present', () => {
    const records = [
      { url: 'https://phish.com', exfil_url: 'https://collect.evil.com/steal.php' },
      { url: 'https://other.com', exfil_url: null },
    ];
    const result = buildExfilEndpointSet(records);
    expect(result).toContain('collect.evil.com');
  });

  it('handles records without exfil_url gracefully', () => {
    expect(() => buildExfilEndpointSet([{ url: 'x' }])).not.toThrow();
  });

  it('returns empty for records with no exfil_url fields', () => {
    const result = buildExfilEndpointSet([{ url: 'https://a.com' }, { url: 'https://b.com' }]);
    expect(result).toEqual([]);
  });
});

describe('extractDomainFromUrl', () => {
  it('extracts hostname from valid URL', () => {
    expect(extractDomainFromUrl('https://example.com/path')).toBe('example.com');
  });

  it('returns null for invalid URL', () => {
    expect(extractDomainFromUrl('not-a-url')).toBeNull();
  });

  it('strips www prefix', () => {
    expect(extractDomainFromUrl('https://www.example.com/path')).toBe('example.com');
  });

  it('handles port numbers', () => {
    expect(extractDomainFromUrl('https://example.com:8080/path')).toBe('example.com');
  });

  it('returns null for empty string', () => {
    expect(extractDomainFromUrl('')).toBeNull();
  });
});

describe('isDomainKnownBad', () => {
  const intel = {
    badDomains: ['evil.com', 'phish.net'],
    badIPs: [],
    badExfilEndpoints: [],
    lastSync: new Date().toISOString(),
  };

  it('returns true for exact domain match', () => {
    expect(isDomainKnownBad('evil.com', intel)).toBe(true);
  });

  it('returns true for subdomain of known-bad domain', () => {
    expect(isDomainKnownBad('login.evil.com', intel)).toBe(true);
  });

  it('returns true for deep subdomain', () => {
    expect(isDomainKnownBad('a.b.phish.net', intel)).toBe(true);
  });

  it('returns false for unknown domain', () => {
    expect(isDomainKnownBad('safe.com', intel)).toBe(false);
  });

  it('returns false when intel is null', () => {
    expect(isDomainKnownBad('evil.com', null)).toBe(false);
  });

  it('returns false when intel has empty badDomains', () => {
    expect(isDomainKnownBad('evil.com', { badDomains: [], badIPs: [], badExfilEndpoints: [] })).toBe(false);
  });
});

describe('isIPKnownBad', () => {
  const intel = { badDomains: [], badIPs: ['1.2.3.4', '5.6.7.8'], badExfilEndpoints: [] };

  it('returns true for known-bad IP', () => {
    expect(isIPKnownBad('1.2.3.4', intel)).toBe(true);
  });

  it('returns false for unknown IP', () => {
    expect(isIPKnownBad('9.9.9.9', intel)).toBe(false);
  });

  it('returns false when intel is null', () => {
    expect(isIPKnownBad('1.2.3.4', null)).toBe(false);
  });
});

describe('isExfilEndpointKnownBad', () => {
  const intel = { badDomains: [], badIPs: [], badExfilEndpoints: ['collect.evil.com'] };

  it('returns true for known exfil endpoint', () => {
    expect(isExfilEndpointKnownBad('collect.evil.com', intel)).toBe(true);
  });

  it('returns false for unknown endpoint', () => {
    expect(isExfilEndpointKnownBad('legit.com', intel)).toBe(false);
  });

  it('returns false when intel is null', () => {
    expect(isExfilEndpointKnownBad('collect.evil.com', null)).toBe(false);
  });
});

describe('computeThreatIntelStats', () => {
  it('returns counts of all sets', () => {
    const intel = {
      badDomains: ['a.com', 'b.com'],
      badIPs: ['1.1.1.1'],
      badExfilEndpoints: ['x.com', 'y.com', 'z.com'],
    };
    const stats = computeThreatIntelStats(intel);
    expect(stats.domainCount).toBe(2);
    expect(stats.ipCount).toBe(1);
    expect(stats.exfilCount).toBe(3);
  });

  it('handles empty sets', () => {
    const stats = computeThreatIntelStats({ badDomains: [], badIPs: [], badExfilEndpoints: [] });
    expect(stats.domainCount).toBe(0);
    expect(stats.ipCount).toBe(0);
    expect(stats.exfilCount).toBe(0);
  });
});

describe('fetchPhishStatsRecords', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('returns parsed records on success', async () => {
    const mockRecords = [{ url: 'https://phish.com/login', ip: '1.2.3.4', score: 7 }];
    vi.mocked(fetch).mockResolvedValue({ ok: true, json: async () => mockRecords });
    expect(await fetchPhishStatsRecords()).toEqual(mockRecords);
  });

  it('returns empty array on HTTP 429', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: false, status: 429 });
    expect(await fetchPhishStatsRecords()).toEqual([]);
  });

  it('returns empty array on network failure', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('network error'));
    expect(await fetchPhishStatsRecords()).toEqual([]);
  });

  it('returns empty array when API returns non-array', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, json: async () => ({ error: 'bad' }) });
    expect(await fetchPhishStatsRecords()).toEqual([]);
  });
});

describe('fetchPhishnetDomains', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('returns parsed domains on success', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      text: async () => 'hxxps://evil[.]com/phish\nhxxps://bad[.]net/x',
    });
    const result = await fetchPhishnetDomains();
    expect(result).toContain('evil.com');
    expect(result).toContain('bad.net');
  });

  it('returns empty array on failure', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('timeout'));
    expect(await fetchPhishnetDomains()).toEqual([]);
  });
});

describe('syncThreatIntel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    vi.stubGlobal('chrome', {
      storage: { local: { get: vi.fn().mockResolvedValue({}), set: vi.fn().mockResolvedValue(undefined) } },
    });
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('merges PhishStats and phishnet domains', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({ ok: true, json: async () => [{ url: 'https://ps.com/x', ip: '1.1.1.1', score: 6 }] })
      .mockResolvedValueOnce({ ok: true, text: async () => 'hxxps://pn[.]com/y' });
    const intel = await syncThreatIntel();
    expect(intel.badDomains).toContain('ps.com');
    expect(intel.badDomains).toContain('pn.com');
    expect(intel.badIPs).toContain('1.1.1.1');
  });

  it('persists intel to chrome.storage.local', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, text: async () => '' });
    await syncThreatIntel();
    expect(chrome.storage.local.set).toHaveBeenCalledWith(
      expect.objectContaining({ threatIntel: expect.any(Object) })
    );
  });

  it('includes lastSync ISO timestamp', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, text: async () => '' });
    const intel = await syncThreatIntel();
    expect(new Date(intel.lastSync).getTime()).toBeGreaterThan(0);
  });

  it('succeeds when both fetches fail (offline mode)', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('offline'));
    const intel = await syncThreatIntel();
    expect(intel.badDomains).toEqual([]);
    expect(intel.badIPs).toEqual([]);
  });

  it('deduplicates domains appearing in both sources', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({ ok: true, json: async () => [{ url: 'https://dup.com/x', ip: null, score: 6 }] })
      .mockResolvedValueOnce({ ok: true, text: async () => 'hxxps://dup[.]com/y' });
    const intel = await syncThreatIntel();
    expect(intel.badDomains.filter(d => d === 'dup.com')).toHaveLength(1);
  });
});
