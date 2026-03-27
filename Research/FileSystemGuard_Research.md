# FileSystemGuard: Why the File System Access API demands a dedicated PhishOps detector

**The File System Access API gives any Chromium-based web page the ability to recursively read (and write) an entire user-selected directory — and Chrome's blocked-paths list leaves critical credential files like `~/.aws/credentials` and `~/.kube/config` exposed.** Combined with ClickFix-style social engineering (which surged **517%** in early 2025), the attack surface is real: a phishing page that tricks a user into selecting a folder can silently exfiltrate every file in it without additional prompts. Academic researchers have already demonstrated browser-based ransomware using this API that evaded all four tested antivirus products. A MAIN-world content script injected at `document_start` can intercept every picker call, inspect arguments, monitor file reads, and flag exfiltration — making a FileSystemGuard detector both justified and technically feasible.

---

## 1. The spec: a Chromium-only WICG draft, not a web standard

The File System Access API is published as a **Draft Community Group Report** by the Web Platform Incubator Community Group (WICG), dated **10 October 2025**. It is explicitly **not a W3C Standard** and not on the W3C Standards Track. The spec is edited by Ming-Ying Chung (Google) and lives at `wicg.github.io/file-system-access/`, extending the separate WHATWG File System Standard (`fs.spec.whatwg.org`) which defines the base `FileSystemHandle` interfaces and the Origin Private File System (OPFS).

The spec exposes three picker methods on `window`:

**`showOpenFilePicker(options?)`** returns `Promise<FileSystemFileHandle[]>`. Options include `types` (MIME/extension filters), `multiple` (boolean, default `false`), `startIn` (well-known directory or existing handle), `id` (string for remembering directories), and `excludeAcceptAllOption`. The user sees a native OS file picker. A user gesture and secure context (HTTPS) are required; cross-origin iframes are blocked.

**`showSaveFilePicker(options?)`** returns a single `Promise<FileSystemFileHandle>` with read-write permission automatically granted. It adds `suggestedName` for a default filename. Chrome applies Mark-of-the-Web and triggers Safe Browsing scans on dangerous extensions.

**`showDirectoryPicker(options?)`** returns `Promise<FileSystemDirectoryHandle>`. Its `mode` parameter accepts `"read"` (default) or `"readwrite"`. This is the most dangerous method from a data-exfiltration standpoint: **once the user selects a directory, the page can recursively enumerate and read every file and subdirectory with zero additional prompts**.

Once a handle is obtained, `FileSystemFileHandle.getFile()` returns a standard `File` object (readable via `text()`, `arrayBuffer()`, etc.), and `createWritable()` opens a `FileSystemWritableFileStream` for writes. `FileSystemDirectoryHandle` implements the async iterable protocol — `entries()`, `keys()`, `values()`, and `for await...of` enable recursive traversal. The API deliberately does not expose full filesystem paths; only the `name` property (filename or directory name) is visible.

The `startIn` parameter accepts exactly **six well-known tokens** — `"desktop"`, `"documents"`, `"downloads"`, `"music"`, `"pictures"`, `"videos"` — or a previously obtained `FileSystemHandle`. **Arbitrary path strings cannot be specified.** The `id` parameter lets a site remember different starting directories (up to 16 per origin).

**Browser support is Chromium-only.** Chrome and Edge support the full API from version 86+ (October 2020), with `startIn`/`id` added in Chrome 91. **Firefox explicitly opposes** the spec (`position: negative` on mozilla/standards-positions #154). **Safari does not implement** the picker methods. Both browsers support only the OPFS portion of the WHATWG File System Standard. The spec itself annotates each picker method with "In only one current engine."

---

## 2. Chrome's blocked-paths list protects some targets but leaves critical gaps

Chrome's security model for the File System Access API relies on a blocklist defined in `chrome_file_system_access_permission_context.cc` in the Chromium source. This blocklist uses three blocking modes: **`kBlockAllChildren`** (directory and all descendants blocked), **`kBlockNestedDirectories`** (files readable, subdirectories blocked), and **`kDontBlockChildren`** (the directory itself cannot be selected as a root, but its children are accessible).

### What is protected

The blocklist explicitly covers the **highest-value targets** that SSH key theft and credential-stealing attacks would pursue:

- **`~/.ssh`** → `kBlockAllChildren` — all SSH keys blocked
- **`~/.gnupg`** → `kBlockAllChildren` — GPG keys blocked
- **Chrome user data directory** (`DIR_USER_DATA`) → `kBlockAllChildren` — Login Data (saved passwords), cookies, history, and all profile data blocked
- **`~/Library`** (macOS) → `kBlockAllChildren` — Keychain files, Application Support blocked (with carve-outs for CloudStorage, Containers, and Mobile Documents for iCloud/Google Drive)
- **`~/.config`** (Linux) → `kBlockAllChildren` — protects `google-chrome/Default/Login Data` and most app configs
- **`%APPDATA%` and `%LOCALAPPDATA%`** (Windows) → `kBlockAllChildren` — Windows Chrome profile, Credential Manager data blocked
- **System directories** — `/etc`, `/dev`, `/proc`, `/sys`, `/boot` (Linux); `C:\Windows`, `C:\Program Files` (Windows)
- **Chrome installation directories** → `kBlockAllChildren`

Windows additionally blocks local UNC paths (`\\localhost\C$`, `\\127.0.0.1\...`) to prevent bypassing the blocklist via administrative shares. Symbolic links are resolved when the `kFileSystemAccessSymbolicLinkCheck` feature flag is enabled.

### What is NOT protected — the critical gaps

Several **high-value credential and configuration files are NOT on the blocklist**:

- **`~/.aws/credentials`** and **`~/.aws/config`** — AWS access keys (not blocked on Linux/macOS)
- **`~/.kube/config`** — Kubernetes cluster credentials with tokens and certificates
- **`~/.docker/config.json`** — Docker registry authentication
- **`~/.npmrc`** — npm authentication tokens
- **`~/.netrc`** — plaintext credentials for FTP/HTTP services
- **`~/.bash_history`**, **`~/.zsh_history`** — command history (may contain secrets)
- **`~/.gitconfig`** — Git credentials and configuration
- **`.env` files** throughout project directories — frequently contain API keys and database credentials
- **`~/.bashrc`**, **`~/.zshrc`**, **`~/.profile`** — shell configurations

This matters because if a user selects any parent directory containing these files (e.g., their home directory's `Projects` folder), the page gains recursive read access to everything inside it, including `.env` files, config directories, and any sensitive dotfiles that happen to be present.

Crucially, **Chrome explicitly states** in its security FAQ that "the blocklist coverage is not deemed as a security bug" — it is defense-in-depth, not a security boundary. The home directory itself (`~`) is blocked only with `kDontBlockChildren`, meaning the user cannot select `~` directly but can select any non-blocked subdirectory within it.

### How it differs from `<input type="file">`

Counterintuitively, **`<input type="file">` has NO blocklist at all** — any file the user selects in the OS picker can be read, including files in `~/.ssh`. The File System Access API is actually *more* restrictive for individual file reads. However, `showDirectoryPicker()` introduces a qualitatively different risk: **recursive bulk access** to entire directory trees, enabling automated enumeration and exfiltration of thousands of files from a single user action.

---

## 3. Permission model: one click grants recursive access

The user interaction flow works as follows. Calling any picker method triggers a **native OS file picker dialog** — the browser's own chrome, not a page-controlled element. The user must click to invoke it (transient user activation required; `SecurityError` thrown otherwise). The page cannot pre-select files or auto-navigate to specific paths beyond the `startIn` hint.

**Once the user selects a directory, the page can recursively read ALL files and subdirectories without any additional prompts**, provided none fall within blocked paths. The permission propagates to all descendants. Write access requires a separate permission prompt unless the picker was invoked with `mode: 'readwrite'`.

**Chrome 122+ introduced persistent permissions** with a three-way prompt: "Allow this time" (session-only), "Allow on every visit" (persistent until revoked), or "Don't allow." Handles can be stored in IndexedDB and reused across sessions. Prior to Chrome 122, permissions expired approximately 5 seconds after the last tab for the origin closed.

When a user attempts to select a blocked directory, Chrome shows a warning dialog stating the directory cannot be exposed and asks the user to choose a different one. This is the only proactive security intervention beyond the standard file picker.

---

## 4. Published attacks confirm the threat model is real

### RøB: the first browser-based ransomware (USENIX Security 2023)

Researchers from Florida International University and Google published "RøB: Ransomware over Modern Web Browsers" at USENIX Security 2023, demonstrating a fully functional browser-based ransomware built on the File System Access API and WebAssembly. RøB uses hybrid AES-256 + RSA-2048 encryption and was tested across **3 operating systems, 23 file formats, 29 directories, 5 cloud providers (Dropbox, Google Drive, OneDrive, iCloud, Box), and 4 antivirus solutions**. The result: **all tested antivirus products failed to detect it**, because the ransomware runs within the browser with no traditional malicious payloads or suspicious process execution. Cloud providers without file versioning (Apple iCloud, Box Individual) suffered permanent data loss. The researchers proposed RøBguard, an ML-based defense that uses JavaScript API function hooking to detect ransomware-like file access patterns — a direct precursor to the FileSystemGuard concept.

### FileJacking: initial access via all four FSA API vectors (July 2025)

Security researcher Print3M published a comprehensive analysis of four abuse vectors on Windows 11 with Chrome and Edge. The most concerning finding: `showSaveFilePicker()` can create files on disk — including DLLs, EXEs, LNK files, and MSI installers — **without appearing in Chrome's download history**, functioning as "downloads on steroids." Files created via `showDirectoryPicker()` with write access can be created, edited, and deleted silently with no additional user notification after the initial grant. The research confirmed that once access is granted, the website can interact with files "in the background" even when the user is not actively using the page.

### CVE history

**CVE-2021-21123** and five related CVEs (filed by Maciej Pulikowski) exposed file extension spoofing via `showSaveFilePicker()` in Chrome 86-87 — the save dialog could show "Save as type: JPEG (.jpg)" while actually saving a malicious `.lnk` file. **CVE-2025-5065** identified an "inappropriate implementation" in Chromium's FileSystemAccess API affecting Chrome, Edge, and all Chromium-based browsers, where malicious web applications could access or modify files without proper authorization.

### SquareX "Year of Browser Bugs" (2025)

While SquareX's YOBB program did not disclose a vulnerability specific to the File System Access API picker methods, their **Data Splicing Attacks** research (disclosed at BSides SF, April 2025) demonstrated a new class of browser-based exfiltration techniques that bypass all Gartner Magic Quadrant DLP solutions. Their "Angry Magpie" toolkit, released at DEF CON 33, implements four exfiltration methods (data sharding, ciphering, transcoding, smuggling) that would combine naturally with FSA API-based file reading. Their Browser-Native Ransomware research (March 2025) demonstrated ransomware executed entirely within the browser using identity compromise as the access vector.

### No confirmed in-the-wild campaigns — yet

Despite the demonstrated attack surface, **no confirmed malware or phishing campaigns using the File System Access API for data exfiltration have been documented as of March 2026**. This represents a window of opportunity for proactive defense before the technique enters mainstream attacker toolkits.

---

## 5. If users paste PowerShell for a fake CAPTCHA, they will click a file picker

The falsification question — "is the user prompt sufficient protection?" — is answered definitively by the ClickFix epidemic. ClickFix attacks require users to press Win+R, paste a PowerShell command from their clipboard, and press Enter — **a far more unusual and suspicious action** than selecting a folder in a standard-looking file picker dialog. Despite this higher bar, ClickFix surged **517%** from H2 2024 to H1 2025 (ESET data) and accounted for **47% of initial access attempts** in 2025 (Microsoft). Nation-state actors including Russia's APT28, Iran's MuddyWater, and North Korea's Lazarus Group adopted ClickFix because it reliably works.

**A phishing page requesting directory access presents a lower cognitive barrier than ClickFix.** Consider the social engineering scenarios:

A fake "Google Drive" or "OneDrive" page telling users to "Select your project folder to complete the migration" requires only two clicks: the button that triggers `showDirectoryPicker()`, and the OS-native "Select Folder" confirmation. Unlike ClickFix, the user is interacting with a familiar OS dialog that millions of legitimate users encounter with VS Code for the Web, Excalidraw, and Photopea. The interaction looks normal. Once granted, the page silently reads every `.env` file, AWS credential, and Kubernetes config in the directory tree and exfiltrates them via standard `fetch()` requests.

Legitimate applications using `showDirectoryPicker()` are **few and well-known**: VS Code for the Web (vscode.dev), Excalidraw, Photopea, StackBlitz, and similar web-based development tools. The intersection of "page exhibiting phishing indicators" and "page calling File System Access API" should be extremely rare on legitimate sites, making this a **high-signal, low-false-positive detection opportunity**.

---

## 6. A MAIN-world content script can intercept everything that matters

Detection from a Chrome MV3 content script is **fully feasible**. A content script declared in `manifest.json` with `"world": "MAIN"` and `"run_at": "document_start"` (supported since Chrome 111) executes in the same JavaScript context as the page, enabling direct monkey-patching of the File System Access API surface.

**What can be intercepted:**

The content script wraps `window.showOpenFilePicker`, `window.showSaveFilePicker`, and `window.showDirectoryPicker` by saving references to the originals and replacing them with instrumented versions. This captures the `startIn` parameter (revealing whether the page targets `"documents"`, `"desktop"`, etc.), file type filters, and the `mode` parameter. By intercepting the Promise return value, the script can observe the `name` property of every returned `FileSystemFileHandle` and `FileSystemDirectoryHandle`.

Prototype-level wrapping extends monitoring deeper: `FileSystemFileHandle.prototype.getFile` can be wrapped to detect when files are actually read (not just picked), `FileSystemDirectoryHandle.prototype.entries` and `.values()` detect directory enumeration, and `FileSystemFileHandle.prototype.createWritable` detects write operations. Because prototype modifications affect all instances — even those created after the wrap — this approach provides comprehensive coverage.

**What cannot be seen:** Full filesystem paths are intentionally hidden by the API; only file/directory names are available via `handle.name`. However, names alone are highly informative — detecting reads of files named `credentials`, `config`, `id_rsa`, `.env`, or `Login Data` provides strong signal.

**Communication architecture:** MAIN-world scripts cannot access `chrome.runtime.sendMessage()`. The standard pattern uses `window.dispatchEvent(new CustomEvent(...))` from the MAIN-world script to a companion ISOLATED-world content script, which relays messages to the service worker via the extension messaging API.

**Anti-evasion:** Statically declared manifest content scripts are injected before dynamically registered ones and before page scripts. A sophisticated attacker could attempt to save references to the original API methods in an inline `<script>` tag, but static MAIN-world `document_start` injection should execute first in the standard case.

---

## Assessment: FileSystemGuard is justified and should be built

The evidence strongly supports implementing a dedicated FileSystemGuard detector for PhishOps. The reasoning rests on five pillars:

**The attack surface is proven, not theoretical.** Academic researchers demonstrated browser-based ransomware (RøB) that evaded all tested AV products. FileJacking research documented four distinct abuse vectors. CVEs have been filed against the API. The only missing piece is confirmed in-the-wild exploitation — which means defenders have a window to act proactively.

**Chrome's blocklist has known, exploitable gaps.** While `.ssh` and browser profile data are protected, **cloud credentials (`~/.aws/credentials`, `~/.kube/config`), Docker configs, npm tokens, `.env` files, and shell histories are all readable** if the user grants access to a containing directory. These are precisely the credentials an attacker needs for cloud account takeover.

**Social engineering reliably overcomes user prompts.** ClickFix proves users will execute arbitrary PowerShell from a fake CAPTCHA. Selecting a folder in a native file picker — something users do routinely with legitimate web apps — is a *lower* bar. The prompt is not sufficient protection.

**Detection is technically clean.** MAIN-world content script injection at `document_start` enables complete API surface monitoring. The multi-signal detection formula — phishing indicators + FSA API invocation + file content reads + network exfiltration — should produce **very low false positives** because the File System Access API is used by only a handful of well-known applications, none of which operate on phishing-like domains.

**The gap in the ecosystem is real.** No current browser extension, DLP tool, or antivirus product monitors File System Access API calls for abuse patterns. SquareX's research confirms browser-based exfiltration bypasses all major DLP solutions. RøBguard exists only as an academic prototype. FileSystemGuard would be a first-mover in a space where the threat is documented but undefended.

The recommended detection logic should flag when a page with phishing indicators (low domain age, suspicious URL patterns, credential form presence) calls `showDirectoryPicker()` or `showOpenFilePicker()`, monitor for subsequent `getFile()` reads (especially of files with sensitive names like `credentials`, `config`, `.env`, `id_rsa`), and escalate to a block or warning when network requests follow file reads within a short time window. The `startIn` parameter value adds signal — a page requesting `startIn: "documents"` or `startIn: "desktop"` on a non-IDE domain is inherently more suspicious. Persistent permission grants (Chrome 122+ "Allow on every visit") should trigger the highest alert level, as they enable ongoing access across browser sessions.