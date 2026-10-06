package cryptopq_test

import (
	"bytes"
	"fmt"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

// Package-level sinks keep the compiler from dropping the calls whose allocations are counted.
var (
	hashSink cryptopq.HashAlgorithm
	xofSink  cryptopq.XofAlgorithm
	macSink  cryptopq.MacAlgorithm
)

// A configuration the test knows to be valid.
func must[T any](algorithm T, err error) T {
	if err != nil {
		panic(err)
	}

	return algorithm
}

// The hashes, XOFs and MACs beyond the NIST ones, plain and configured, for the tests that apply to
// every algorithm.
func symmetricAlgorithms(t *testing.T) ([]cryptopq.HashAlgorithm, []cryptopq.XofAlgorithm, []cryptopq.MacAlgorithm) {
	t.Helper()

	hashes := []cryptopq.HashAlgorithm{
		cryptopq.BLAKE2B_160, cryptopq.BLAKE2B_256, cryptopq.BLAKE2B_384, cryptopq.BLAKE2B_512,
		cryptopq.BLAKE2S_128, cryptopq.BLAKE2S_160, cryptopq.BLAKE2S_224, cryptopq.BLAKE2S_256,
		cryptopq.ASCON_HASH256,
		must(cryptopq.BLAKE2B_512.Configure(&cryptopq.HashOptions{Salt: []byte("salt"), Personalization: []byte("personal")})),
		must(cryptopq.BLAKE2S_256.Configure(&cryptopq.HashOptions{Salt: []byte("salt"), Personalization: []byte("personal")})),
	}

	xofs := []cryptopq.XofAlgorithm{
		cryptopq.CSHAKE128, cryptopq.CSHAKE256, cryptopq.ASCON_XOF128, cryptopq.ASCON_CXOF128,
		must(cryptopq.CSHAKE128.Configure(&cryptopq.XofOptions{Customization: []byte("customization")})),
		must(cryptopq.CSHAKE256.Configure(&cryptopq.XofOptions{Customization: sequence(200)})),
		must(cryptopq.ASCON_CXOF128.Configure(&cryptopq.XofOptions{Customization: sequence(256)})),
	}

	macs := []cryptopq.MacAlgorithm{
		cryptopq.KMAC128, cryptopq.KMAC256, cryptopq.BLAKE2B_MAC, cryptopq.BLAKE2S_MAC,
		must(cryptopq.KMAC128.Configure(&cryptopq.MacOptions{Length: 20, Customization: []byte("customization")})),
		must(cryptopq.KMAC256.Configure(&cryptopq.MacOptions{Length: 300, Xof: true})),
		must(cryptopq.BLAKE2B_MAC.Configure(&cryptopq.MacOptions{Length: 33, Salt: []byte("salt")})),
		must(cryptopq.BLAKE2S_MAC.Configure(&cryptopq.MacOptions{Length: 7, Personalization: []byte("personal")})),
	}

	return hashes, xofs, macs
}

func TestSymmetricNames(t *testing.T) {
	names := map[fmt.Stringer]string{
		cryptopq.BLAKE2B_160: "BLAKE2b-160", cryptopq.BLAKE2B_256: "BLAKE2b-256", cryptopq.BLAKE2B_384: "BLAKE2b-384", cryptopq.BLAKE2B_512: "BLAKE2b-512",
		cryptopq.BLAKE2S_128: "BLAKE2s-128", cryptopq.BLAKE2S_160: "BLAKE2s-160", cryptopq.BLAKE2S_224: "BLAKE2s-224", cryptopq.BLAKE2S_256: "BLAKE2s-256",
		cryptopq.ASCON_HASH256: "Ascon-Hash256", cryptopq.CSHAKE128: "cSHAKE128", cryptopq.CSHAKE256: "cSHAKE256",
		cryptopq.ASCON_XOF128: "Ascon-XOF128", cryptopq.ASCON_CXOF128: "Ascon-CXOF128", cryptopq.KMAC128: "KMAC128", cryptopq.KMAC256: "KMAC256",
		cryptopq.BLAKE2B_MAC: "BLAKE2b-MAC", cryptopq.BLAKE2S_MAC: "BLAKE2s-MAC",
		cryptopq.HKDF_SHA_256: "HKDF-SHA-256", cryptopq.HKDF_SHA_384: "HKDF-SHA-384", cryptopq.HKDF_SHA_512: "HKDF-SHA-512",
	}

	for algorithm, name := range names {
		if algorithm.String() != name || fmt.Sprint(algorithm) != name {
			t.Fatalf("name %q, want %q", algorithm, name)
		}
	}

	sizes := map[cryptopq.HashAlgorithm]int{cryptopq.BLAKE2B_160: 20, cryptopq.BLAKE2B_256: 32, cryptopq.BLAKE2B_384: 48, cryptopq.BLAKE2B_512: 64, cryptopq.BLAKE2S_128: 16, cryptopq.BLAKE2S_160: 20, cryptopq.BLAKE2S_224: 28, cryptopq.BLAKE2S_256: 32, cryptopq.ASCON_HASH256: 32}

	for algorithm, size := range sizes {
		if algorithm.DigestSize() != size || len(algorithm.Digest(nil)) != size {
			t.Fatalf("%s: digest size %d", algorithm, algorithm.DigestSize())
		}
	}

	if cryptopq.KMAC128.DigestSize() != 32 || cryptopq.KMAC256.DigestSize() != 64 || cryptopq.BLAKE2B_MAC.DigestSize() != 64 || cryptopq.BLAKE2S_MAC.DigestSize() != 32 {
		t.Fatal("default MAC sizes")
	}
}

// The Into forms write what the allocating forms return, and streaming gives the same output, for
// inputs around every block size.
func TestSymmetricFormsAgree(t *testing.T) {
	hashes, xofs, macs := symmetricAlgorithms(t)

	data := sequence(400)

	key := sequence(24)

	for _, length := range []int{0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 135, 136, 137, 167, 168, 169, 255, 256, 257, 400} {
		message := data[:length]

		for _, algorithm := range hashes {
			checkHash(t, fmt.Sprintf("%s, %d bytes", algorithm, length), algorithm, message, algorithm.Digest(message))
		}

		for _, algorithm := range xofs {
			checkXof(t, fmt.Sprintf("%s, %d bytes", algorithm, length), algorithm, message, algorithm.Digest(message, 333))
		}

		for _, algorithm := range macs {
			context := fmt.Sprintf("%s, %d bytes", algorithm, length)

			tag := algorithm.Digest(key, message)

			out := make([]byte, algorithm.DigestSize())

			algorithm.DigestInto(key, message, out)

			same(t, out, tag, context+" DigestInto")

			mac := algorithm.Create(key)

			for _, piece := range pieces(message) {
				mac.Update(piece)
			}

			same(t, mac.Digest(), tag, context+" streamed")

			clear(out)

			mac.DigestInto(out)

			same(t, out, tag, context+" Mac.DigestInto")

			if !mac.Verify(tag) || !algorithm.Verify(key, message, tag) {
				t.Fatalf("%s: the tag does not verify", context)
			}
		}
	}
}

// Digest leaves a hasher or a MAC as it was, so that more data can follow.
func TestSymmetricDigestIsRepeatable(t *testing.T) {
	hashes, xofs, macs := symmetricAlgorithms(t)

	key := []byte("key")

	for _, algorithm := range hashes {
		hasher := algorithm.Create()

		hasher.Update([]byte("abc"))

		first := hasher.Digest()

		if !bytes.Equal(hasher.Digest(), first) || !bytes.Equal(first, algorithm.Digest([]byte("abc"))) {
			t.Fatalf("%s: digest changed the state", algorithm)
		}

		hasher.Update([]byte("def"))

		same(t, hasher.Digest(), algorithm.Digest([]byte("abcdef")), algorithm.String()+" update after digest")
	}

	for _, algorithm := range macs {
		mac := algorithm.Create(key)

		mac.Update([]byte("abc"))

		first := mac.Digest()

		if !bytes.Equal(mac.Digest(), first) || !mac.Verify(first) || !bytes.Equal(first, algorithm.Digest(key, []byte("abc"))) {
			t.Fatalf("%s: digest changed the state", algorithm)
		}

		mac.Update([]byte("def"))

		same(t, mac.Digest(), algorithm.Digest(key, []byte("abcdef")), algorithm.String()+" update after digest")
	}

	for _, algorithm := range xofs {
		xof := algorithm.Create()

		xof.Update([]byte("abc"))

		var got []byte

		for _, n := range []int{0, 1, 7, 8, 9, 135, 1, 167, 200, 496} {
			got = append(got, xof.Read(n)...)
		}

		same(t, got, algorithm.Digest([]byte("abc"), len(got)), algorithm.String()+" streamed reads")

		panics(t, "UNSUPPORTED", func() { xof.Update([]byte("x")) })

		panics(t, "INVALID_LENGTH", func() { xof.Read(-1) })

		panics(t, "INVALID_LENGTH", func() { algorithm.Digest(nil, -1) })
	}
}

// With the output on the caller's side, every one-shot form and every Configure allocates nothing,
// keys and outputs of every size included.
func TestSymmetricIntoAllocatesNothing(t *testing.T) {
	hashes, xofs, macs := symmetricAlgorithms(t)

	data := sequence(1000)

	var out [512]byte

	expect := func(context string, f func()) {
		t.Helper()

		if allocations := testing.AllocsPerRun(20, f); allocations != 0 {
			t.Errorf("%s: %v allocations", context, allocations)
		}
	}

	for _, algorithm := range hashes {
		expect(algorithm.String(), func() { algorithm.DigestInto(data, out[:algorithm.DigestSize()]) })
	}

	for _, algorithm := range xofs {
		expect(algorithm.String(), func() { algorithm.DigestInto(data, out[:]) })
	}

	for _, algorithm := range macs {
		for _, keySize := range []int{1, 32, 64, 200} {
			key := data[:keySize]

			if (algorithm.Name() == "BLAKE2b-MAC" && keySize > 64) || (algorithm.Name() == "BLAKE2s-MAC" && keySize > 32) {
				continue
			}

			tag := out[:algorithm.DigestSize()]

			expect(fmt.Sprintf("%s, %d-byte key", algorithm, keySize), func() { algorithm.DigestInto(key, data, tag) })

			expect(fmt.Sprintf("%s verify, %d-byte key", algorithm, keySize), func() { algorithm.Verify(key, data, tag) })
		}
	}

	for _, algorithm := range kdfs {
		prk := make([]byte, 64)

		size := len(algorithm.Extract(nil, nil))

		options := &cryptopq.KdfOptions{Salt: data[:32], Info: data[:16]}

		long := &cryptopq.KdfOptions{Info: data[:500]}

		expect(algorithm.String()+" DeriveInto", func() { _ = algorithm.DeriveInto(data[:32], out[:200], options) })

		expect(algorithm.String()+" DeriveInto, long info", func() { _ = algorithm.DeriveInto(data[:32], out[:200], long) })

		expect(algorithm.String()+" ExtractInto", func() { algorithm.ExtractInto(data[:32], prk[:size], options) })

		expect(algorithm.String()+" ExpandInto", func() { _ = algorithm.ExpandInto(prk, out[:], options) })
	}

	hashOptions := &cryptopq.HashOptions{Salt: data[:16], Personalization: data[:16]}

	xofOptions := &cryptopq.XofOptions{Customization: data[:256]}

	macOptions := &cryptopq.MacOptions{Length: 48, Customization: data[:300]}

	expect("HashAlgorithm.Configure", func() { hashSink, _ = cryptopq.BLAKE2B_256.Configure(hashOptions) })

	expect("XofAlgorithm.Configure", func() { xofSink, _ = cryptopq.CSHAKE128.Configure(xofOptions) })

	expect("XofAlgorithm.Configure, Ascon", func() { xofSink, _ = cryptopq.ASCON_CXOF128.Configure(xofOptions) })

	expect("MacAlgorithm.Configure", func() { macSink, _ = cryptopq.KMAC256.Configure(macOptions) })
}
