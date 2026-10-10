//go:build !purego

package cryptopq

import (
	"fmt"
	"runtime"
	"slices"
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

// The keyed operations of the MACs and KDFs, one call each, on states made beforehand.
func keyedOperations() []func() {
	key, data, out := make([]byte, 32), make([]byte, 100), make([]byte, 64)

	var operations []func()

	for _, algorithm := range []MacAlgorithm{HMAC_SHA_256, HMAC_SHA_512, KMAC128, KMAC256, BLAKE2B_MAC, BLAKE2S_MAC} {
		size := algorithm.DigestSize()

		tag := algorithm.Digest(key, nil)

		updated, digested, verified := algorithm.Create(key), algorithm.Create(key), algorithm.Create(key)

		operations = append(operations,
			func() { algorithm.DigestInto(key, data, out[:size]) },
			func() { algorithm.Verify(key, data, out[:size]) },
			func() { algorithm.Create(key) },
			func() { updated.Update(data) },
			func() { digested.DigestInto(out[:size]) },
			func() {
				if !verified.Verify(tag) {
					panic("the tag of the empty message does not verify")
				}
			})
	}

	for _, algorithm := range []KdfAlgorithm{HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512} {
		prk := algorithm.Extract(key, nil)

		operations = append(operations,
			func() { _ = algorithm.DeriveInto(key, out, nil) },
			func() { algorithm.ExtractInto(key, prk, nil) },
			func() { _ = algorithm.ExpandInto(prk, out, nil) })
	}

	return operations
}

// MAC and KDF calls take no bracket until EnableDataIndependentTiming, and then one each, which
// sets DIT inside and leaves it as the caller had it, clear or set; KEM operations take theirs
// either way. The bracket of an operation under another one only reads the bit.
func TestDITKeyedOptIn(t *testing.T) {
	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	keyedDIT.Store(false)

	defer keyedDIT.Store(false)

	var entered []bool

	ditWatch = func(wasSet bool) {
		if !ditIsSet() {
			t.Error("DIT is clear inside a bracket")
		}

		entered = append(entered, wasSet)
	}

	defer func() { ditWatch = nil }()

	watch := func(operation func()) []bool {
		entered = nil

		operation()

		return entered
	}

	operations := keyedOperations()

	pair, err := Hazmat.GenerateKemKeyPair(ML_KEM_768, make([]byte, 64))

	if err != nil {
		t.Fatal(err)
	}

	encapsulation, err := Hazmat.Encapsulate(pair.PublicKey, make([]byte, 32))

	if err != nil {
		t.Fatal(err)
	}

	decapsulate := func() {
		if _, err := pair.PrivateKey.Decapsulate(encapsulation.Ciphertext); err != nil {
			t.Fatal(err)
		}
	}

	for i, operation := range operations {
		if brackets := watch(operation); len(brackets) != 0 {
			t.Fatalf("operation %d took %d DIT brackets before EnableDataIndependentTiming", i, len(brackets))
		}
	}

	if brackets := watch(decapsulate); useDIT && (len(brackets) == 0 || brackets[0] || ditIsSet()) {
		t.Fatalf("Decapsulate took the brackets %v", brackets)
	}

	if EnableDataIndependentTiming() != useDIT || EnableDataIndependentTiming() != useDIT || keyedDit() != useDIT {
		t.Fatalf("EnableDataIndependentTiming on a CPU with DIT %v", useDIT)
	}

	if !useDIT {
		return
	}

	for i, operation := range operations {
		if brackets := watch(operation); !slices.Equal(brackets, []bool{false}) || ditIsSet() {
			t.Fatalf("operation %d took the brackets %v and left DIT set %v", i, brackets, ditIsSet())
		}

		ditSet()

		if brackets := watch(operation); !slices.Equal(brackets, []bool{true}) || !ditIsSet() {
			t.Fatalf("operation %d under a bracket took the brackets %v and cleared DIT", i, brackets)
		}

		ditClear()
	}
}
