//go:build awg_runtime_v1

package awg

// Compile-time guard for the v1.0.x amneziawg-go runtime.
//
// This file compiles only when the `awg_runtime_v1` build tag is set. It imports
// the `device/awg` subpackage, which exists ONLY in amneziawg-go >= v1.0.0 —
// under v0.2.x this import does not resolve and the build fails, proving at
// compile time that a v1.0.x runtime is actually linked.
//
// Workflow when bumping `core/go.mod` to amneziawg-go >= v1.0.4:
//  1. set awgRuntimeSupportsControlledJunk = true in capability.go, and
//  2. add `awg_runtime_v1` to the build -tags.
//
// Step 2 makes CI fail fast if the replace was NOT actually bumped (the
// device/awg import won't resolve under v0.2.x), so the capability flag and the
// linked runtime cannot silently disagree.

import (
	// v1.0.x-only subpackage; absent in v0.2.x. The import alone proves a
	// v1.0.x runtime is linked.
	_ "github.com/amnezia-vpn/amneziawg-go/device/awg"
)
