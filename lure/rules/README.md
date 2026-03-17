# PhishOps YARA Rules

## Custom Rules

`phishing_custom.yar` contains PhishOps-specific detection rules:

| Rule | Severity | Threat |
|------|----------|--------|
| `phishops_clickfix_clipboard_lure` | Critical | ClickFix social engineering — clipboard injection via fake CAPTCHA |
| `phishops_tycoon2fa_kit` | High | Tycoon 2FA AiTM reverse proxy phishing kit indicators |
| `phishops_device_code_lure` | High | Storm-2372 OAuth device code phishing lure text |
| `phishops_html_smuggling_loader` | High | HTML smuggling via atob() + Blob + createObjectURL |
| `phishops_credential_harvest_form` | Medium | Password field with external form action + brand impersonation |
| `phishops_qr_code_phishing` | Medium | QR code phishing (quishing) with urgency + MFA lure |
| `phishops_vba_macro_downloader` | Critical | VBA macro with auto-open trigger and download/exec capabilities |
| `phishops_base64_encoded_url` | Low | Base64-encoded HTTP(S) URL in email body |

## Adding External Rulesets

### Neo23x0 signature-base (recommended)

```bash
cd lure/rules
git clone https://github.com/Neo23x0/signature-base.git
```

The scanner automatically loads all `.yar` files from the `rules/` directory.

### InQuest yara-rules

```bash
cd lure/rules
git clone https://github.com/InQuest/yara-rules.git
```

### Custom rules

Add any `.yar` file to the `rules/` directory. It will be compiled into a separate namespace matching the filename.

## Rule Development

1. Write the rule in a `.yar` file
2. Test compilation: `python -c "import yara; yara.compile('rules/your_rule.yar')"`
3. Run tests: `pytest tests/test_scanner.py -v`
4. Add test fixtures to `tests/test_scanner.py`
