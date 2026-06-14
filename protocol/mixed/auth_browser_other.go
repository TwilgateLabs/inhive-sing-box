//go:build !windows

package mixed

import (
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

// browserBypassAllowed (non-Windows) matches the connecting process against the
// configured whitelist by exe basename or, on Android, package name. Android
// package identity is OS-enforced by PackageManager, so name matching is sound
// there. On non-Windows desktops there is no Authenticode equivalent wired up
// yet, so the basename whitelist is the only bypass path; the random proxy
// creds remain the real boundary.
func browserBypassAllowed(owner *adapter.ConnectionOwner, whitelist map[string]bool) bool {
	if owner == nil || len(whitelist) == 0 {
		return false
	}
	if owner.ProcessPath != "" && whitelist[strings.ToLower(filepath.Base(owner.ProcessPath))] {
		return true
	}
	for _, pkg := range owner.AndroidPackageNames {
		if whitelist[strings.ToLower(pkg)] {
			return true
		}
	}
	return false
}
