/**
 * extension/tests/allowlist.test.js
 *
 * Unit tests for the unified domain allowlist module.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

const mockStorage = {};
const mockGet = vi.fn(async (key) => ({ [key]: mockStorage[key] ?? null }));
const mockSet = vi.fn(async (obj) => { Object.assign(mockStorage, obj); });

vi.stubGlobal('chrome', {
  storage: { local: { get: mockGet, set: mockSet } },
});

const {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
} = await import('../lib/allowlist.js');

describe('BUILTIN_ALLOWLIST', () => {
  it('contains well-known safe domains', () => {
    expect(BUILTIN_ALLOWLIST.has('linkedin.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('github.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('claude.ai')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('tryhackme.com')).toBe(true);
  });

  it('contains FP-triggering domains from field testing', () => {
    expect(BUILTIN_ALLOWLIST.has('bloomberg.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('forbes.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('aliexpress.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('tiktok.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('moz.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('opera.com')).toBe(true);
  });

  it('does not contain random domains', () => {
    expect(BUILTIN_ALLOWLIST.has('evil-phish.example')).toBe(false);
  });
});

describe('isDomainAllowlisted', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('returns true for a builtin domain', async () => {
    expect(await isDomainAllowlisted('linkedin.com')).toBe(true);
  });

  it('matches subdomains of builtin entries', async () => {
    expect(await isDomainAllowlisted('www.linkedin.com')).toBe(true);
    expect(await isDomainAllowlisted('chat.claude.ai')).toBe(true);
  });

  it('returns true for a user-added domain', async () => {
    mockStorage.phishops_user_allowlist = ['internal.corp.com'];
    expect(await isDomainAllowlisted('internal.corp.com')).toBe(true);
  });

  it('matches subdomains of user-added entries', async () => {
    mockStorage.phishops_user_allowlist = ['corp.com'];
    expect(await isDomainAllowlisted('app.corp.com')).toBe(true);
  });

  it('returns false for unknown domains', async () => {
    expect(await isDomainAllowlisted('evil-phish.example')).toBe(false);
  });

  it('strips www. prefix before checking', async () => {
    expect(await isDomainAllowlisted('www.github.com')).toBe(true);
  });

  it('handles empty/null input', async () => {
    expect(await isDomainAllowlisted('')).toBe(false);
    expect(await isDomainAllowlisted(null)).toBe(false);
  });
});

describe('addToUserAllowlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('adds a domain to storage', async () => {
    await addToUserAllowlist('example.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['example.com']);
  });

  it('strips www. and lowercases', async () => {
    await addToUserAllowlist('www.Example.COM');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['example.com']);
  });

  it('does not add duplicates', async () => {
    mockStorage.phishops_user_allowlist = ['example.com'];
    await addToUserAllowlist('example.com');
    const list = await getUserAllowlist();
    expect(list).toEqual(['example.com']);
  });

  it('sorts entries alphabetically', async () => {
    mockStorage.phishops_user_allowlist = ['zzz.com'];
    await addToUserAllowlist('aaa.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['aaa.com', 'zzz.com']);
  });

  it('ignores empty input', async () => {
    await addToUserAllowlist('');
    expect(mockSet).not.toHaveBeenCalled();
  });
});

describe('removeFromUserAllowlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('removes a domain from the list', async () => {
    mockStorage.phishops_user_allowlist = ['a.com', 'b.com', 'c.com'];
    await removeFromUserAllowlist('b.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['a.com', 'c.com']);
  });

  it('is a no-op for a domain not in the list', async () => {
    mockStorage.phishops_user_allowlist = ['a.com'];
    await removeFromUserAllowlist('b.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['a.com']);
  });
});
