package mixed

import (
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/util/winutil/authenticode"

	"golang.org/x/sys/windows"
)

// InHive fork — Windows browser proxy-auth bypass via Authenticode.
//
// The localhost mixed proxy is password-protected (random per-install creds) so
// other local apps can't probe the tunnel and read the VPN exit IP
// (habr.com/ru/articles/1020080). But a browser routed through the Windows
// system proxy would otherwise hit HTTP 407 and pop a login dialog. We suppress
// that dialog ONLY for genuine, code-signed mainstream browsers: the connecting
// process is resolved to its on-disk .exe, and auth is skipped iff that .exe
// carries a chain-valid EMBEDDED Authenticode signature whose cert subject is a
// known browser vendor.
//
// Two checks, AND'd — they cover each other's weaknesses:
//   - exe BASENAME must be a known browser (from the configured whitelist). This
//     SCOPES the bypass: many non-browser binaries share a trusted signer (e.g.
//     notepad.exe / powershell.exe are signed "Microsoft Corporation", same as
//     Edge), so signature alone would hand every Microsoft-signed LOLBin a free
//     pass. Name alone is trivially spoofed, so it is NOT the boundary — a
//     browser missing from the list merely shows the dialog (fail-safe).
//   - signature must be a CHAIN-VALID Authenticode whose cert subject is a known
//     browser vendor. This is the real boundary: a binary renamed to chrome.exe
//     can't produce Google's CA-issued signature, and a self-signed binary
//     claiming the subject fails the chain check.
//
// Residual: code injected into an already-running signed browser inherits its
// trust; that needs real on-device malware sophistication and is out of scope.
// The random per-install creds remain the ultimate boundary; this gate only
// suppresses the dialog for genuine browsers.
//
// Revocation is intentionally NOT checked (WTD_REVOKE_NONE): online CRL/OCSP
// would block the connection handshake on a censored/offline network, and worse,
// the revocation fetch would itself be routed through our own authenticated
// system proxy (407 → fail). The accepted residual is that a *revoked* but
// chain-valid vendor signing key would still pass — an astronomically rare,
// short-lived, globally-visible event, vs. a guaranteed hang on every connection.
//
// trustedBrowserCertSubjects holds EXACT cert subjects (CERT_NAME_SIMPLE_DISPLAY_TYPE,
// i.e. the signer org/CN), verified 2026-06-14. A wrong or missing string only
// makes that browser show the dialog (fail-safe) — it never opens a hole. Confirm
// on-device with:
//
//	Get-AuthenticodeSignature <exe> | %{ $_.SignerCertificate.Subject }
var trustedBrowserCertSubjects = map[string]bool{
	"Google LLC":              true, // Chrome
	"Microsoft Corporation":   true, // Edge
	"Mozilla Corporation":     true, // Firefox
	"Brave Software, Inc.":    true, // Brave
	"Opera Norway AS":         true, // Opera
	"Vivaldi Technologies AS": true, // Vivaldi
	"YANDEX LLC":              true, // Yandex Browser
	"The Tor Project, Inc.":   true, // Tor Browser
}

// fileIdentity uniquely binds a cached verdict to a specific on-disk file
// instance: volume + NTFS file index identify the file, size + last-write time
// catch in-place modification. A swap to a different file changes the index;
// editing in place changes write-time/size — either invalidates the cache and
// forces re-verification.
type fileIdentity struct {
	volSerial uint32
	idxHigh   uint32
	idxLow    uint32
	sizeHigh  uint32
	sizeLow   uint32
	writeHigh uint32
	writeLow  uint32
}

type browserSigCacheEntry struct {
	trusted bool
	id      fileIdentity
}

const browserSigCacheMax = 256

var (
	browserSigCache   = make(map[string]browserSigCacheEntry)
	browserSigCacheMu sync.Mutex
)

// browserBypassAllowed reports whether the connecting process is a known browser
// exe (name-scoped via whitelist) AND carries a chain-valid browser-vendor
// Authenticode signature. Both are required: the name keeps same-vendor non-
// browser binaries (notepad.exe, powershell.exe …) out; the signature stops a
// renamed impostor.
func browserBypassAllowed(owner *adapter.ConnectionOwner, whitelist map[string]bool) bool {
	if owner == nil || owner.ProcessPath == "" || len(whitelist) == 0 {
		return false
	}
	// Name first (cheap, scopes to browsers). Then the signature (the real check).
	if !whitelist[strings.ToLower(filepath.Base(owner.ProcessPath))] {
		return false
	}
	return isTrustedBrowserExe(owner.ProcessPath)
}

func isTrustedBrowserExe(path string) bool {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	// Open with FILE_SHARE_READ ONLY (no FILE_SHARE_WRITE, no FILE_SHARE_DELETE).
	// Per the CreateFileW contract, while this handle is held "no process can open
	// the file ... if it requests write access" and "no process can open the file
	// ... if it requests delete access" (delete access covers rename). So the file
	// is frozen — content, name and existence can't change — which means the
	// subject QueryCertSubject reads (it re-opens the same frozen path) and the
	// chain we verify (against this very handle) are guaranteed to be the SAME
	// bytes. This closes the TOCTOU where an attacker swaps the binary between the
	// two checks. (Same approach the Tailscale reference relies on.)
	h, err := windows.CreateFile(path16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return false
	}
	id := fileIdentity{
		volSerial: info.VolumeSerialNumber,
		idxHigh:   info.FileIndexHigh,
		idxLow:    info.FileIndexLow,
		sizeHigh:  info.FileSizeHigh,
		sizeLow:   info.FileSizeLow,
		writeHigh: info.LastWriteTime.HighDateTime,
		writeLow:  info.LastWriteTime.LowDateTime,
	}

	browserSigCacheMu.Lock()
	if e, ok := browserSigCache[path]; ok && e.id == id {
		trusted := e.trusted
		browserSigCacheMu.Unlock()
		return trusted
	}
	browserSigCacheMu.Unlock()

	trusted := verifyBrowserSignature(path, path16, h)

	browserSigCacheMu.Lock()
	// Bound memory: a local app can connect from many distinct paths. Normal use
	// never approaches the cap; only an adversary spamming paths would, and
	// dropping the (small) browser entries just means they re-verify cheaply.
	if len(browserSigCache) >= browserSigCacheMax {
		browserSigCache = make(map[string]browserSigCacheEntry)
	}
	browserSigCache[path] = browserSigCacheEntry{trusted: trusted, id: id}
	browserSigCacheMu.Unlock()
	return trusted
}

// verifyBrowserSignature runs with an open deny-write handle h to path, so the
// file can't change underfoot. True iff the file carries an EMBEDDED, chain-valid
// Authenticode signature whose cert subject is a trusted browser vendor. Subject
// membership is checked before the (expensive) chain build; catalog-signed
// binaries are treated as untrusted (fail-safe dialog) since mainstream browsers
// are embedded-signed.
func verifyBrowserSignature(path string, path16 *uint16, h windows.Handle) bool {
	subject, provenance, err := authenticode.QueryCertSubject(path)
	if err != nil || provenance != authenticode.SigProvEmbedded || subject == "" {
		return false
	}
	if !trustedBrowserCertSubjects[subject] {
		return false
	}
	return verifyTrustChainNoRevoke(path16, h) == nil
}

// verifyTrustChainNoRevoke validates the Authenticode chain of the open file h
// against the machine trusted roots, without online revocation checking. The
// handle (not just the path) is passed to WinVerifyTrust so the exact frozen
// file is validated.
func verifyTrustChainNoRevoke(path16 *uint16, h windows.Handle) error {
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: path16,
		File:     h,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	// Always release the trust state, regardless of the verify result. This does
	// not close our file handle h (owned by the caller).
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr
}
