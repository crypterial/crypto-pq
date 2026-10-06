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

// Every keyed operation of the MACs and KDFs leaves DIT as its caller had it, clear or set.
func TestDITKeyedSymmetric(t *testing.T) {
	if !useDIT {
		t.Skip("the CPU has no DIT")
	}

	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	key, data, out := make([]byte, 32), make([]byte, 100), make([]byte, 64)

	var operations []func()

	for _, algorithm := range []MacAlgorithm{HMAC_SHA_256, HMAC_SHA_512, KMAC128, KMAC256, BLAKE2B_MAC, BLAKE2S_MAC} {
		size := algorithm.DigestSize()

		operations = append(operations,
			func() { algorithm.DigestInto(key, data, out[:size]) },
			func() { algorithm.Verify(key, data, out[:size]) },
			func() {
				mac := algorithm.Create(key)

				mac.Update(data)

				mac.DigestInto(out[:size])

				mac.Verify(out[:size])
			})
	}

	for _, algorithm := range []KdfAlgorithm{HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512} {
		operations = append(operations,
			func() { _ = algorithm.DeriveInto(key, out, nil) },
			func() { algorithm.ExtractInto(key, make([]byte, len(algorithm.Extract(nil, nil))), nil) },
			func() { _ = algorithm.ExpandInto(make([]byte, 64), out, nil) })
	}

	for i, operation := range operations {
		operation()

		if ditIsSet() {
			t.Fatalf("operation %d left DIT set", i)
		}

		ditSet()

		operation()

		if !ditIsSet() {
			t.Fatalf("operation %d cleared a DIT bit set by its caller", i)
		}

		ditClear()
	}
}
