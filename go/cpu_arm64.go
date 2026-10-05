//go:build !purego

package cryptopq

import "runtime"

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

	return ditSet()
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
