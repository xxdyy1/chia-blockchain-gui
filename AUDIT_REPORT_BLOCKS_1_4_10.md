# Chia GUI Security Audit (Blocks 1–4 Re-Audit + Block 10)

This report re-audits blocks 1–4 using HackerOne severity labels and adds block 10 (NFT/Offer/metadata parsing). Findings are based on static code review in this repository.

## Commands executed

- `rg -n "rejectUnauthorized|WebSocket" packages/gui/src`
- `rg -n "FETCH_TEXT_RESPONSE|FETCH_POOL_INFO|fetchJSON|CacheManager|cache" packages/gui/src/electron packages/gui/src/util packages/gui/src/components`
- `rg -n "VIRTUAL_ENV|getVirtualEnvExecDir|startChiaDaemon" packages/gui/src`
- `rg -n "useOpenExternal|target=\"_blank\"|window.open|openExternal" packages/gui/src`
- `rg -n "OPEN_KEY_DETAIL|getKeyDetails|secretKey|seed" packages/gui/src`
- `rg -n "metadata" packages/gui/src/components/nfts packages/gui/src/util`
- `rg -n "useFetchAndProcessMetadata|fetchAndProcessMetadata" packages/gui/src/hooks`
- `rg -n "OfferImport" packages/gui/src/components/offers`
- `rg -n "dangerouslySetInnerHTML|innerHTML|document\\.write" packages/gui/src packages/wallets/src packages/core/src`
- `rg -n "SandboxedIframe|srcDoc|Content-Security-Policy" packages/gui/src packages/core/src`
- `rg -n "DOWNLOAD|START_MULTIPLE_DOWNLOAD|SHOW_OPEN_FILE_DIALOG_AND_READ|SHOW_SAVE_DIALOG_AND_SAVE|openExternal" packages/gui/src/electron packages/gui/src/hooks`
- `rg -n "readPrefs|savePrefs|readAddressBook|saveAddressBook|prefs.yaml|contacts.yaml" packages/gui/src`
- `rg -n "bypassCommands|GET_BYPASS_COMMANDS|SET_BYPASS_COMMANDS" packages/gui/src`
- `rg -n "cacheFolder|maxCacheSize|setCacheDirectory" packages/gui/src/electron`

## Block 1: Electron IPC / Network / Process Execution (HackerOne ratings)

### 1.1 TLS certificate validation disabled in WebSocket connections

**Severity:** Medium

The Electron-side WebSocket connections explicitly disable TLS certificate verification, which enables man-in-the-middle interception if an attacker can influence the network path to the daemon. This affects both the WebSocket bridge and the direct command path.

**Evidence:**

- `webSocketBridge` sets `rejectUnauthorized: false` when connecting to the daemon WebSocket.
- `sendCommand` also sets `rejectUnauthorized: false`.

**Impact:** MITM can tamper with or read wallet/daemon traffic over the WebSocket channel.

### 1.2 IPC network fetch allows arbitrary HTTPS/IPFS URLs (SSRF-like reachability)

**Severity:** Medium

IPC handlers allow the renderer to request arbitrary `https://` or `ipfs://` URLs (subject only to protocol validation). This makes the main process perform outbound requests on behalf of the renderer and can be abused for internal network probing or local service access if a renderer compromise occurs.

**Evidence:**

- `FETCH_TEXT_RESPONSE` posts to a renderer-supplied URL.
- `FETCH_POOL_INFO` constructs a URL from input and calls `fetchJSON`.
- `fetchJSON` only validates protocol (`https`/`ipfs`) via `isValidURL`.
- CacheManager exposes `GET_CONTENT`, `GET_HEADERS`, `GET_CHECKSUM`, and `GET_URI` over IPC for arbitrary URLs.

**Impact:** Renderer compromise could lead to internal network probing or access to services not reachable from the renderer sandbox.

### 1.3 Executable path influenced by `VIRTUAL_ENV`

**Severity:** Low

In non-packaged mode, executable path discovery relies on the `VIRTUAL_ENV` environment variable and runs the resolved `chia` binary. If the environment is attacker-controlled, a malicious binary could be executed.

**Evidence:**

- `getVirtualEnvExecDir` reads `process.env.VIRTUAL_ENV` to construct an executable directory.
- `startChiaDaemon` resolves the executable with `getExecutablePath` and spawns it.

**Impact:** Local execution hijack on developer or misconfigured environments.

### 1.4 Shell pipeline in `restoreMessages.js`

**Severity:** Low

A developer script executes a shell pipeline built from `git status` output. Filenames with unusual characters could lead to argument parsing issues or unintended behavior.

**Evidence:**

- `restoreMessages.js` uses `exec` with a shell pipeline on both Windows and non-Windows paths.

**Impact:** Limited to local developer environment; potential for unexpected file operations.

## Block 2: Renderer Input / XSS / External Link Handling (HackerOne ratings)

### 2.1 Reverse tabnabbing risk in web build

**Severity:** Low

In non-Electron environments, external links are opened using `window.open(url, '_blank')` without `noopener`/`noreferrer`, allowing the new page to control `window.opener` and potentially redirect the original tab.

**Evidence:**

- `useOpenExternal` uses `window.open(url, '_blank')` in web builds.

**Impact:** Potential phishing or tab hijack if the opened site is malicious.

## Block 3: Config / Keys / Sensitive Data Exposure (HackerOne ratings)

### 3.1 IPC-exposed private key/seed retrieval to renderer

**Severity:** High

The renderer can invoke `OPEN_KEY_DETAIL`, which fetches private keys/seed phrases in the main process and renders them in a dialog. If the renderer is compromised (XSS or injected code), secret material can be exposed without a privileged boundary.

**Evidence:**

- `AppAPI.OPEN_KEY_DETAIL` triggers `openKeyDetail`.
- `openKeyDetail` calls `getKeyDetails`, which executes `get_private_key`.
- `KeyDetail` renders `secretKey` and `seed` in the UI.

**Impact:** Exposure of seed/secret key material and potential loss of funds if the renderer is compromised.

## Block 4: Dependency / Supply Chain Review (HackerOne ratings)

### 4.1 Dependency audit support exists, but CVE status is not asserted

**Severity:** None (informational)

The repository defines audit scripts and version overrides, but no code in-repo asserts or verifies that installed dependency versions are free from known CVEs. This is a process gap rather than an in-code vulnerability.

**Evidence:**

- Root `package.json` defines `audit` and `audit:fix` scripts, and uses `overrides`.
- `packages/gui/package.json` lists high-impact dependencies (e.g., Electron, WalletConnect, ws) that require external vulnerability tracking.

**Impact:** Requires external tooling to confirm CVE status.

## Block 10: NFT / Offer / External Metadata Parsing (HackerOne ratings)

### 10.1 NFT metadata integrity is only enforced when a hash is present

**Severity:** Low

Metadata integrity checks rely on comparing a provided hash; if a metadata hash is absent, metadata is fetched and parsed without integrity verification. This allows mutable metadata (by design) that can change after minting, which can mislead users.

**Evidence:**

- Metadata fetch uses the first `metadataUri` and calls `fetchAndProcessMetadata` with `metadataHash`.
- `fetchAndProcessMetadata` only rejects when a hash exists and does not match.

**Impact:** Unverified metadata can be swapped to display misleading or malicious content (display-only impact).

### 10.2 External metadata/media fetch can reveal user IP and fetch arbitrary remote resources

**Severity:** Low

NFT preview and metadata fetching resolves arbitrary `https://` and `ipfs://` URLs (via the cache manager) and renders media via `<img>`, `<video>`, and `<audio>`. This allows NFTs to trigger network requests to attacker-controlled endpoints, enabling IP tracking or telemetry.

**Evidence:**

- `useFetchAndProcessMetadata` pulls remote content through cache APIs.
- `downloadFile` accepts any URL validated only by protocol (`https`/`ipfs`).
- `NFTPreview` renders cached media URIs in standard media elements.

**Impact:** Privacy leak (IP address / timing) when viewing malicious NFTs.

### 10.3 Offer import validation is size-limited but relies on regex parsing

**Severity:** None (informational)

Offer import logic enforces a 1MB size limit and extracts the `offer1...` payload via regex before requesting a summary. No direct injection or parsing vulnerability was found in this review.

**Evidence:**

- `OfferImport` rejects files over 1MB and extracts offer payloads using a regex before `getOfferSummary`.

**Impact:** None identified in this audit.

## Block 11: Renderer HTML/Markdown Injection Deep Dive (HackerOne ratings)

### 11.1 Direct HTML injection sinks not found in GUI/core packages

**Severity:** None (informational)

No `dangerouslySetInnerHTML`, `innerHTML`, or `document.write` usage was found in the audited GUI and core React packages. This reduces the likelihood of direct HTML injection vectors in the React layer.

**Evidence:**

- Repository-wide search for HTML injection sinks in GUI/core packages produced no matches.

**Impact:** None identified in this audit.

### 11.2 Sandboxed iframe uses restrictive CSP and cache-only media sources

**Severity:** None (informational)

The sandboxed iframe renderer uses a strict CSP with `default-src 'none'`, disallowing scripts, and only permitting `cache:` for images/media. This limits active content execution even when rendering untrusted content in the iframe.

**Evidence:**

- `SandboxedIframe` renders a `srcDoc` document with CSP restricting all network access and scripts.

**Impact:** None identified in this audit.

## Block 12: Chia Critical-Criteria Mapping (GUI scope)

### 12.1 Consensus/chain integrity primitives not implemented in GUI codebase

**Severity:** None (informational)

The GUI repository does not contain consensus, block creation, or chain-validation logic. Critical issues such as block propagation failures, chain stalls, or Chialisp-level vulnerabilities are expected to live in the core `chia-blockchain` node/consensus codebase and are not present in this repo.

**Evidence:**

- GUI repository focuses on Electron/React UI, IPC, and wallet presentation layers.

**Impact:** Not applicable to this repository; requires auditing the core blockchain node/consensus codebase.

## Block 13: IPC File Dialogs, Downloads, and External Links (HackerOne ratings)

### 13.1 Renderer-initiated file read/write flows rely on user dialogs

**Severity:** Low

The renderer can invoke IPC handlers that open native file dialogs to read or write files. While a user must explicitly choose a file path, a compromised renderer could attempt social engineering to trick the user into selecting sensitive files or overwriting files with crafted content.

**Evidence:**

- `SHOW_OPEN_FILE_DIALOG_AND_READ` reads a user-selected file and returns the bytes.
- `SHOW_SAVE_DIALOG_AND_SAVE` writes arbitrary content to a user-selected path.

**Impact:** Potential for local data exposure or file overwrite if the user is tricked into selecting a sensitive path.

### 13.2 Renderer can trigger downloads without explicit allowlist

**Severity:** Low

The `DOWNLOAD` and `START_MULTIPLE_DOWNLOAD` IPC handlers accept renderer-supplied URLs and trigger downloads after minimal validation (protocol check and filename sanitization). This could allow a compromised renderer to initiate unexpected downloads.

**Evidence:**

- `DOWNLOAD` calls `webContents.downloadURL` after URL validation.
- `START_MULTIPLE_DOWNLOAD` accepts a list of URLs, validates protocol, and downloads to a user-selected directory.

**Impact:** Drive-by downloads or user confusion; requires renderer compromise and user interaction for folder selection.

### 13.3 Main-process `openExternal` lacks URL validation

**Severity:** Low

The main-process `openExternal` IPC handler opens any URL passed to it, and the main handler does not enforce its own URL validation. The renderer-side helper validates URLs, but a compromised renderer can call the IPC directly.

**Evidence:**

- `LinkAPI.OPEN_EXTERNAL` invokes `openExternal` without validating the URL in the main process.

**Impact:** Could open arbitrary URLs (phishing or drive-by navigation) from a compromised renderer.

## Block 14: Preferences and Address Book Persistence (HackerOne ratings)

### 14.1 Renderer can overwrite preferences and address book via IPC

**Severity:** Low

The renderer can call IPC handlers that directly write `prefs.yaml` and `contacts.yaml` data to disk. While these files live in the user data directory, a compromised renderer could overwrite settings or contact metadata without additional validation.

**Evidence:**

- `PreferencesAPI.SAVE` writes the renderer-supplied prefs object to `prefs.yaml`.
- `AddressBookAPI.SAVE` writes the renderer-supplied contacts list to `contacts.yaml`.

**Impact:** Local data tampering or user confusion; does not directly enable remote code execution but may degrade trust or settings integrity if the renderer is compromised.

## Block 15: Bypass Command Preferences (HackerOne ratings)

### 15.1 Renderer can request persistent bypass commands (confirmation required)

**Severity:** Low

The renderer can request updates to the bypass command list via IPC. The main process validates commands and prompts the user for confirmation before persisting them, but a compromised renderer could still present unexpected command lists for user approval.

**Evidence:**

- `GET_BYPASS_COMMANDS` and `SET_BYPASS_COMMANDS` are exposed via IPC and stored in private preferences after a confirmation dialog.

**Impact:** Potential for users to unintentionally allow command bypasses if they approve a maliciously crafted request.

## Block 16: Cache Directory and Size Management (HackerOne ratings)

### 16.1 Cache directory changes and size pruning can impact user-selected paths

**Severity:** Low

Cache management allows the renderer to trigger a cache directory change (via a directory picker) and update max cache size. If a user selects an unexpected directory, cache pruning may delete files matching cache suffixes in that folder. The directory selection is user-mediated, but a compromised renderer could attempt social engineering.

**Evidence:**

- `SET_CACHE_DIRECTORY` invokes a directory picker and moves cache files into the selected folder.
- `SET_MAX_CACHE_SIZE` triggers cache pruning which deletes cache files by suffix in the active cache directory.

**Impact:** Potential local data loss of files with cache suffixes in a user-selected directory; requires user interaction.
