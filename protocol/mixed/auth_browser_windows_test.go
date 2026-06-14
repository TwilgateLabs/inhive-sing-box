package mixed

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestBrowserBypassGate exercises the Windows name+signature gate against real
// on-disk binaries. Requires Microsoft Edge (shipped with Windows) and runs only
// on Windows; skips elsewhere. notepad.exe is signed "Microsoft Windows" (a
// different identity than Edge's "Microsoft Corporation"), so it stands in for a
// vendor-mismatch / impostor binary.
func TestBrowserBypassGate(t *testing.T) {
	edge := firstExisting(
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	)
	if edge == "" {
		t.Skip("Microsoft Edge not found — Windows-only gate test")
	}
	notepad := `C:\Windows\System32\notepad.exe`

	owner := func(path string) *adapter.ConnectionOwner {
		return &adapter.ConnectionOwner{ProcessPath: path}
	}

	// 1. Signed browser + name whitelisted -> bypass (no auth).
	if !browserBypassAllowed(owner(edge), map[string]bool{"msedge.exe": true}) {
		t.Errorf("expected BYPASS for signed Edge with msedge.exe whitelisted")
	}
	// 2. Signed browser but name NOT whitelisted -> no bypass (name scoping).
	if browserBypassAllowed(owner(edge), map[string]bool{"chrome.exe": true}) {
		t.Errorf("expected NO bypass for Edge when its name is not whitelisted")
	}
	// 3. Non-browser (notepad = "Microsoft Windows"), even with name whitelisted ->
	//    no bypass (vendor subject not a browser vendor).
	if browserBypassAllowed(owner(notepad), map[string]bool{"notepad.exe": true}) {
		t.Errorf("expected NO bypass for notepad.exe (not a browser-vendor signature)")
	}
	// 4. Impostor: copy notepad to <tmp>\chrome.exe, whitelist chrome.exe ->
	//    no bypass. The copy keeps notepad's embedded "Microsoft Windows" signature,
	//    so renaming a non-browser binary to a browser name must NOT defeat the gate.
	tmp := filepath.Join(t.TempDir(), "chrome.exe")
	data, err := os.ReadFile(notepad)
	if err != nil {
		t.Fatalf("read notepad: %v", err)
	}
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		t.Fatalf("write impostor: %v", err)
	}
	if browserBypassAllowed(owner(tmp), map[string]bool{"chrome.exe": true}) {
		t.Errorf("expected NO bypass for notepad renamed to chrome.exe (rename must not defeat signature)")
	}
	// 5. Empty whitelist -> no bypass even for a real browser.
	if browserBypassAllowed(owner(edge), map[string]bool{}) {
		t.Errorf("expected NO bypass with empty whitelist")
	}
	// 6. Cache returns the same verdict on a second call (hot path).
	if !browserBypassAllowed(owner(edge), map[string]bool{"msedge.exe": true}) {
		t.Errorf("expected stable BYPASS for Edge on cached second call")
	}
}
