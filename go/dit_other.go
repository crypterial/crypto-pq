//go:build !arm64 || purego

package cryptopq

// Without PSTATE.DIT, the brackets around operations on secrets do nothing, and MAC and KDF calls
// take none.
func ditEnter() bool {
	return false
}

func ditLeave(bool) {}

func keyedDit() bool {
	return false
}

// EnableDataIndependentTiming would make MAC and KDF calls run under PSTATE.DIT; this build has no
// DIT, so it reports false.
func EnableDataIndependentTiming() bool {
	return false
}
