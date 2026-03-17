/*
 * PhishOps Custom YARA Rules — phishing_custom.yar
 *
 * Targeted detection rules for phishing email patterns observed in
 * active campaigns. Each rule maps to a specific threat actor TTP or
 * phishing kit signature.
 *
 * Usage:
 *   Compiled and loaded by lure/modules/scanner.py at import time.
 *   Scanned against email body (text + HTML) and attachment payloads.
 *
 * Rule naming convention:
 *   phishops_{threat}_{variant}
 *
 * Adding new rules:
 *   1. Add the rule to this file
 *   2. Run: lure rules update  (validates compilation)
 *   3. Run: pytest tests/test_scanner.py  (verify against test fixtures)
 */

rule phishops_clickfix_clipboard_lure {
    meta:
        description = "ClickFix social engineering — instructs user to paste clipboard content into Run dialog"
        author = "PhishOps"
        date = "2026-03"
        severity = "critical"
        mitre_attack = "T1204.001"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix"

    strings:
        $win_r = "Win+R" ascii nocase
        $windows_r = "Windows+R" ascii nocase
        $ctrl_v = "Ctrl+V" ascii nocase
        $run_dialog = "Run dialog" ascii nocase
        $paste_run = "paste" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd = "cmd.exe" ascii nocase

        // Verification lure patterns
        $verify1 = "verify you are human" ascii nocase
        $verify2 = "I'm not a robot" ascii nocase
        $verify3 = "complete verification" ascii nocase

    condition:
        ($win_r or $windows_r) and ($ctrl_v or $paste_run) and
        ($verify1 or $verify2 or $verify3 or $run_dialog or $powershell or $cmd)
}

rule phishops_tycoon2fa_kit {
    meta:
        description = "Tycoon 2FA phishing kit — AiTM reverse proxy indicators"
        author = "PhishOps"
        date = "2026-03"
        severity = "high"
        mitre_attack = "T1557.003"
        reference = "https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis/"

    strings:
        $cloudflare_turnstile = "challenges.cloudflare.com/turnstile" ascii
        $svg_captcha = "<svg" ascii
        $canvas_fp = "canvas.toDataURL" ascii
        $webgl_fp = "WEBGL_debug_renderer_info" ascii

        // Common Tycoon paths
        $path1 = "/api/v1/auth" ascii
        $path2 = "/verify-human" ascii
        $path3 = ".workers.dev" ascii

        // Anti-analysis
        $antidbg1 = "debugger" ascii
        $antidbg2 = "devtools" ascii nocase

    condition:
        ($cloudflare_turnstile or $svg_captcha) and
        ($canvas_fp or $webgl_fp) and
        (any of ($path*) or any of ($antidbg*))
}

rule phishops_device_code_lure {
    meta:
        description = "OAuth device code phishing lure — instructs victim to enter code at device login page"
        author = "PhishOps"
        date = "2026-03"
        severity = "high"
        mitre_attack = "T1528"
        reference = "Storm-2372 device code phishing (Microsoft, March 2026)"

    strings:
        $ms_device = "microsoft.com/devicelogin" ascii nocase
        $device_code = "device code" ascii nocase
        $enter_code = "enter the code" ascii nocase
        $enter_this = "enter this code" ascii nocase
        $code_pattern = /[A-Z0-9]{8,9}/ ascii

        // Common lure body text
        $teams_invite = "Teams meeting" ascii nocase
        $mfa_prompt = "multi-factor" ascii nocase
        $verify_identity = "verify your identity" ascii nocase

    condition:
        ($ms_device or $device_code) and
        ($enter_code or $enter_this) and
        ($teams_invite or $mfa_prompt or $verify_identity or $code_pattern)
}

rule phishops_html_smuggling_loader {
    meta:
        description = "HTML smuggling payload — JavaScript creates blob URL from decoded content"
        author = "PhishOps"
        date = "2026-03"
        severity = "high"
        mitre_attack = "T1027.006"
        reference = "Mandiant 2025: HTML smuggling by NOBELIUM, TA4557"

    strings:
        $atob = "atob(" ascii
        $blob_new = "new Blob(" ascii
        $create_url = "createObjectURL" ascii
        $nav_assign = "location.assign" ascii
        $nav_href = "location.href" ascii
        $nav_replace = "location.replace" ascii
        $download = "download" ascii
        $msSaveBlob = "msSaveBlob" ascii

    condition:
        $atob and $blob_new and
        ($create_url or $nav_assign or $nav_href or $nav_replace or $download or $msSaveBlob)
}

rule phishops_credential_harvest_form {
    meta:
        description = "Credential harvesting form — password field with external submission target"
        author = "PhishOps"
        date = "2026-03"
        severity = "medium"
        mitre_attack = "T1056.003"

    strings:
        $password_input = "<input" ascii nocase
        $type_password = "type=\"password\"" ascii nocase
        $type_password2 = "type='password'" ascii nocase
        $type_password3 = "type=password" ascii nocase
        $form_action = "action=\"http" ascii nocase
        $form_action2 = "action='http" ascii nocase

        // Brand impersonation
        $brand1 = "microsoft" ascii nocase
        $brand2 = "outlook" ascii nocase
        $brand3 = "google" ascii nocase
        $brand4 = "paypal" ascii nocase
        $brand5 = "apple" ascii nocase

    condition:
        $password_input and
        ($type_password or $type_password2 or $type_password3) and
        ($form_action or $form_action2) and
        any of ($brand*)
}

rule phishops_qr_code_phishing {
    meta:
        description = "QR code phishing (quishing) — email body contains QR code image with suspicious context"
        author = "PhishOps"
        date = "2026-03"
        severity = "medium"
        mitre_attack = "T1566.002"

    strings:
        $qr_mention = "QR code" ascii nocase
        $scan_qr = "scan" ascii nocase
        $camera = "camera" ascii nocase
        $phone = "phone" ascii nocase

        // Urgency indicators
        $urgent1 = "immediately" ascii nocase
        $urgent2 = "expires" ascii nocase
        $urgent3 = "within 24 hours" ascii nocase
        $urgent4 = "action required" ascii nocase

        // MFA lure
        $mfa1 = "multi-factor" ascii nocase
        $mfa2 = "two-factor" ascii nocase
        $mfa3 = "2FA" ascii
        $mfa4 = "authentication" ascii nocase

    condition:
        $qr_mention and ($scan_qr or $camera or $phone) and
        any of ($urgent*) and any of ($mfa*)
}

rule phishops_vba_macro_downloader {
    meta:
        description = "VBA macro with download and execution capabilities"
        author = "PhishOps"
        date = "2026-03"
        severity = "critical"
        mitre_attack = "T1059.005"

    strings:
        $auto_open = "AutoOpen" ascii nocase
        $doc_open = "Document_Open" ascii nocase
        $wb_open = "Workbook_Open" ascii nocase

        $shell = "Shell" ascii
        $wscript = "WScript" ascii
        $create_obj = "CreateObject" ascii
        $url_download = "URLDownloadToFile" ascii
        $powershell = "PowerShell" ascii nocase
        $cmd_exe = "cmd.exe" ascii nocase
        $environ = "Environ" ascii

    condition:
        ($auto_open or $doc_open or $wb_open) and
        2 of ($shell, $wscript, $create_obj, $url_download, $powershell, $cmd_exe, $environ)
}

rule phishops_base64_encoded_url {
    meta:
        description = "Base64-encoded URL in email body — common obfuscation technique"
        author = "PhishOps"
        date = "2026-03"
        severity = "low"
        mitre_attack = "T1027"

    strings:
        // Base64 of "https://" = "aHR0cHM6Ly"
        $b64_https = "aHR0cHM6Ly" ascii
        // Base64 of "http://" = "aHR0cDovL"
        $b64_http = "aHR0cDovL" ascii

    condition:
        any of ($b64_*)
}
