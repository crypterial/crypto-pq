//go:build !arm64 || purego

package cryptopq

import "testing"

// Without PSTATE.DIT, the switch reports false and MAC and KDF calls still take no bracket.
func TestEnableDataIndependentTiming(t *testing.T) {
	if EnableDataIndependentTiming() || EnableDataIndependentTiming() || keyedDit() {
		t.Fatal("EnableDataIndependentTiming reports DIT where there is none")
	}
}
