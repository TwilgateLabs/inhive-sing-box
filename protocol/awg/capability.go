package awg

// amneziawg-go runtime UAPI capability gate.
//
// The accepted set of AmneziaWG obfuscation UAPI keys changed incompatibly
// between amneziawg-go versions, and a SINGLE unknown key passed to IpcSet makes
// the whole device configuration fail (device/uapi.go `default:` returns
// IpcErrorInvalid). genIpcConfig must therefore emit only the keys the LINKED
// runtime accepts.
//
//   - amneziawg-go v0.2.x (e.g. v0.2.18): accepts jc/jmin/jmax, s1..s4, h1..h4,
//     i1..i5. Does NOT know j1/j2/j3 or itime — emitting them aborts IpcSet.
//   - amneziawg-go v1.0.x (e.g. v1.0.4): accepts jc/jmin/jmax, s1/s2, h1..h4,
//     i1..i5, j1/j2/j3, itime. DROPPED s3/s4 — emitting them aborts IpcSet.
//
// Which version is linked is decided by the build root's go.mod, NOT by a build
// tag, so this constant is the single source of truth and MUST be kept in sync
// with that replace directive.
//
// CURRENT STATE (2026-06-23): the shipped DLL/AAR build from `core/` links
// amneziawg-go v0.2.18 via:
//
//	core/go.mod:
//	  replace github.com/amnezia-vpn/amneziawg-go => github.com/amnezia-vpn/amneziawg-go v0.2.18
//
// Therefore awgRuntimeSupportsControlledJunk is false: s3/s4 ARE emitted,
// j1/j2/j3/itime are NOT (they are still parsed and stored, just suppressed at
// IPC time so a 1.5 share-link does not break the v0.2.18 runtime).
//
// WHEN BUMPING the replace to >= v1.0.4: flip this to true in the SAME change.
// At true, j1/j2/j3/itime ARE emitted and s3/s4 are suppressed (v1.0.4 rejects
// them). See protocol/awg/capability_check_v1.go for the compile-time guard that
// fails the build if this constant claims v1.0.4 support while the v1.0.4-only
// `device/awg` subpackage is absent.
const awgRuntimeSupportsControlledJunk = false
