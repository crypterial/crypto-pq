//go:build !purego

package cryptopq

import (
	"runtime"
	"sync/atomic"
)

// What the CPU offers, asked once when the package is initialized; the purego build tag leaves
// all of it out and runs the portable code.
type armFeatures struct {
	sha2, sha512, sha3, dit, apple bool
}

var arm = armDetect()

var (
	useSHA2   = arm.sha2
	useSHA512 = arm.sha512

	// The SHA3 instructions run on a single pipe of Arm's Neoverse N2, V1 and V2 cores (Graviton 3
	// and 4, Azure Cobalt 100, GitHub's arm64 runners), where they are slower than the portable
	// Keccak; Apple cores run them on every SIMD pipe. So they are used on Apple cores only.
	useKeccakSHA3 = arm.sha3 && arm.apple

	useDIT = arm.dit
)

// MAC and KDF calls take DIT only after EnableDataIndependentTiming: it costs 30-54 ns a call on
// an Apple M3, the whole gap on short MACs, and the prefetcher attacks it stops (GoFetch) need
// intermediates that a small key guess predicts, which ML-KEM, ML-DSA and X25519 have and keyed
// SHA-2, Keccak and BLAKE2 states, each a function of the whole key, do not.
var keyedDIT atomic.Bool

// A test sees every bracket through this, with what ditSet found; it is nil otherwise.
var ditWatch func(wasSet bool)

func midr() uint64

func ditSet() bool

func ditClear()

// Sets PSTATE.DIT, under which the CPU guarantees data-independent timing for the instructions
// Arm lists (on Apple cores it also turns off the data memory-dependent prefetcher), and returns
// what ditLeave needs: deferring ditLeave(ditEnter()) brackets an operation on secrets. The bit
// belongs to the thread, so the goroutine stays on its thread in between; nested brackets leave a
// bit that was set already to the outer one.
func ditEnter() bool {
	if !useDIT {
		return true
	}

	runtime.LockOSThread()

	wasSet := ditSet()

	if ditWatch != nil {
		ditWatch(wasSet)
	}

	return wasSet
}

func ditLeave(wasSet bool) {
	if !useDIT {
		return
	}

	if !wasSet {
		ditClear()
	}

	runtime.UnlockOSThread()
}

// EnableDataIndependentTiming makes every MAC and KDF call from now on, in every goroutine, run
// under PSTATE.DIT, as the KEM and signature operations always do; there is no way back. It
// reports whether the CPU has DIT.
func EnableDataIndependentTiming() bool {
	if useDIT {
		keyedDIT.Store(true)
	}

	return useDIT
}

// Whether a MAC or KDF call brackets itself with ditEnter and ditLeave.
func keyedDit() bool {
	return keyedDIT.Load()
}
