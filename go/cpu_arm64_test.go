//go:build !purego

package cryptopq

import (
	"fmt"
	"runtime"
	"testing"
)

func kernelReport() string {
	return fmt.Sprintf("arm64: CPU %+v; SHA-256 instructions %v, SHA-512 instructions %v, SHA3 Keccak %v, DIT %v", arm, useSHA2, useSHA512, useKeccakSHA3, useDIT)
}

// Whether PSTATE.DIT is set on this thread; reading it through ditSet sets it, so it is cleared
// again when it was not.
func ditIsSet() bool {
	set := ditSet()

	if !set {
		ditClear()
	}

	return set
}

// The bit is set inside a bracket, stays set through a nested one, and is clear after both; an
// operation on a secret key leaves it as it found it, clear or set.
func TestDIT(t *testing.T) {
	if !useDIT {
		t.Skip("the CPU has no DIT")
	}

	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	if ditIsSet() {
		t.Fatal("DIT is set before any bracket")
	}

	outer := ditEnter()

	inner := ditEnter()

	if outer || !inner || !ditIsSet() {
		t.Fatalf("DIT inside brackets: outer found %v, inner found %v", outer, inner)
	}

	ditLeave(inner)

	if !ditIsSet() {
		t.Fatal("the inner bracket cleared DIT")
	}

	ditLeave(outer)

	if ditIsSet() {
		t.Fatal("DIT is still set after the brackets")
	}

	pair, err := Hazmat.GenerateKemKeyPair(ML_KEM_768, make([]byte, 64))

	if err != nil {
		t.Fatal(err)
	}

	encapsulation, err := Hazmat.Encapsulate(pair.PublicKey, make([]byte, 32))

	if err != nil {
		t.Fatal(err)
	}

	if _, err := pair.PrivateKey.Decapsulate(encapsulation.Ciphertext); err != nil || ditIsSet() {
		t.Fatalf("Decapsulate left DIT set or failed: %v", err)
	}

	ditSet()

	if _, err := pair.PrivateKey.Decapsulate(encapsulation.Ciphertext); err != nil || !ditIsSet() {
		t.Fatalf("Decapsulate cleared a DIT bit set by its caller or failed: %v", err)
	}

	ditClear()
}
