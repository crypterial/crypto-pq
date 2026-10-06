package cryptopq_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

// The RFC 7693 digest sizes of each function, and its MAC.
var blake2Functions = map[string]struct {
	hashes map[int]cryptopq.HashAlgorithm
	mac    cryptopq.MacAlgorithm
	full   int
}{
	"BLAKE2b": {map[int]cryptopq.HashAlgorithm{20: cryptopq.BLAKE2B_160, 32: cryptopq.BLAKE2B_256, 48: cryptopq.BLAKE2B_384, 64: cryptopq.BLAKE2B_512}, cryptopq.BLAKE2B_MAC, 64},
	"BLAKE2s": {map[int]cryptopq.HashAlgorithm{16: cryptopq.BLAKE2S_128, 20: cryptopq.BLAKE2S_160, 28: cryptopq.BLAKE2S_224, 32: cryptopq.BLAKE2S_256}, cryptopq.BLAKE2S_MAC, 32},
}

// BLAKE2 of data at a digest length, keyed when key is not empty, checked against want through
// every form: one-shot, Into, streamed in uneven pieces, and Verify for the MAC.
func checkBlake2(t *testing.T, context, name string, length int, key, salt, personalization, data, want []byte) {
	t.Helper()

	function := blake2Functions[name]

	if len(key) == 0 {
		algorithm, err := function.hashes[length].Configure(&cryptopq.HashOptions{Salt: salt, Personalization: personalization})

		check(t, err)

		same(t, algorithm.Digest(data), want, context)

		out := make([]byte, length)

		algorithm.DigestInto(data, out)

		same(t, out, want, context+" DigestInto")

		hasher := algorithm.Create()

		for _, piece := range pieces(data) {
			hasher.Update(piece)
		}

		same(t, hasher.Digest(), want, context+" streamed")

		return
	}

	algorithm, err := function.mac.Configure(&cryptopq.MacOptions{Length: length, Salt: salt, Personalization: personalization})

	check(t, err)

	same(t, algorithm.Digest(key, data), want, context)

	out := make([]byte, length)

	algorithm.DigestInto(key, data, out)

	same(t, out, want, context+" DigestInto")

	mac := algorithm.Create(key)

	for _, piece := range pieces(data) {
		mac.Update(piece)
	}

	same(t, mac.Digest(), want, context+" streamed")

	if !mac.Verify(want) || !algorithm.Verify(key, data, want) {
		t.Fatalf("%s: the tag does not verify", context)
	}

	flipped := bytes.Clone(want)

	flipped[len(flipped)-1] ^= 1

	if mac.Verify(flipped) || algorithm.Verify(key, data, flipped) || algorithm.Verify(key, data, want[:len(want)-1]) {
		t.Fatalf("%s: a wrong tag verifies", context)
	}
}

func TestBlake2RfcExamples(t *testing.T) {
	tested := 0

	for _, r := range records(t, "rfc/blake2.txt", "out") {
		if r.header["kind"] != "example" {
			continue
		}

		name, size, _ := strings.Cut(r.values["hash"], "-")

		checkBlake2(t, r.values["name"], name, number(t, size)/8, nil, nil, nil, decode(t, r.values["in"]), decode(t, r.values["out"]))

		tested++
	}

	if tested != 2 {
		t.Fatalf("tested %d", tested)
	}
}

// selftest_seq of RFC 7693, Appendix E: a Fibonacci-like sequence from the seed.
func blake2SelfTestSequence(length int, seed uint32) []byte {
	out := make([]byte, length)

	a, b := 0xDEAD4BAD*seed, uint32(1)

	for i := range out {
		t := a + b

		a, b = b, t

		out[i] = byte(t >> 24)
	}

	return out
}

// RFC 7693, Appendix E: every digest length and input length, unkeyed and keyed with a key of the
// digest length, fed into one BLAKE2b-256 (BLAKE2s-256) hash.
func TestBlake2RfcSelfTest(t *testing.T) {
	tested := 0

	for _, r := range records(t, "rfc/blake2.txt", "out") {
		if r.header["kind"] != "selftest" {
			continue
		}

		function := blake2Functions[r.values["hash"]]

		grand := function.hashes[32].Create()

		for _, digestLength := range strings.Split(r.values["digestLengths"], ",") {
			length := number(t, digestLength)

			mac, err := function.mac.Configure(&cryptopq.MacOptions{Length: length})

			check(t, err)

			for _, inputLength := range strings.Split(r.values["inputLengths"], ",") {
				data := blake2SelfTestSequence(number(t, inputLength), uint32(number(t, inputLength)))

				grand.Update(function.hashes[length].Digest(data))

				grand.Update(mac.Digest(blake2SelfTestSequence(length, uint32(length)), data))
			}
		}

		same(t, grand.Digest(), decode(t, r.values["out"]), r.values["name"])

		tested++
	}

	if tested != 2 {
		t.Fatalf("tested %d", tested)
	}
}

// The reference KATs: 0 to 255 bytes, unkeyed and keyed with the longest key, at the full length.
func TestBlake2Kat(t *testing.T) {
	for _, name := range []string{"BLAKE2b", "BLAKE2s"} {
		tested := 0

		for i, r := range records(t, "blake2/"+strings.ToLower(name)+".txt", "out") {
			context := fmt.Sprintf("%s KAT %d", name, i)

			checkBlake2(t, context, name, blake2Functions[name].full, decode(t, r.values["key"]), nil, nil, decode(t, r.values["in"]), decode(t, r.values["out"]))

			tested++
		}

		if tested != 512 {
			t.Fatalf("%s: tested %d", name, tested)
		}
	}
}

// Salts and personalizations at full and half length (zero-padded), with and without keys of one
// byte and the longest length, at every RFC 7693 digest size and the MAC sizes 1, half and full.
func TestBlake2SaltAndPersonalization(t *testing.T) {
	counts := map[string]int{}

	for _, r := range records(t, "derived/blake2.txt", "out") {
		name := r.header["hash"]

		length := number(t, r.values["digestLength"])

		context := fmt.Sprintf("%s-%d key %s salt %s personalization %s, %d bytes", name, length, r.values["key"], r.values["salt"], r.values["personalization"], len(r.values["in"])/2)

		checkBlake2(t, context, name, length, decode(t, r.values["key"]), decode(t, r.values["salt"]), decode(t, r.values["personalization"]), decode(t, r.values["in"]), decode(t, r.values["out"]))

		counts[name]++
	}

	if counts["BLAKE2b"] != 250 || counts["BLAKE2s"] != 250 {
		t.Fatalf("tested %v", counts)
	}
}

func TestBlake2Options(t *testing.T) {
	for name, function := range blake2Functions {
		field := function.full / 4

		for _, algorithm := range function.hashes {
			_, err := algorithm.Configure(&cryptopq.HashOptions{Salt: make([]byte, field+1)})

			expectCode(t, err, cryptopq.INVALID_OPTION)

			_, err = algorithm.Configure(&cryptopq.HashOptions{Personalization: make([]byte, field+1)})

			expectCode(t, err, cryptopq.INVALID_OPTION)

			full, err := algorithm.Configure(&cryptopq.HashOptions{Salt: bytes.Repeat([]byte{7}, field), Personalization: bytes.Repeat([]byte{9}, field)})

			check(t, err)

			if full == algorithm || bytes.Equal(full.Digest(nil), algorithm.Digest(nil)) {
				t.Fatalf("%s: the options changed nothing", algorithm)
			}

			// Shorter values are zero-padded, and all-zero ones are the defaults.
			padded, err := algorithm.Configure(&cryptopq.HashOptions{Salt: []byte{7}, Personalization: append([]byte{9}, make([]byte, field-1)...)})

			check(t, err)

			short, err := algorithm.Configure(&cryptopq.HashOptions{Salt: []byte{7}, Personalization: []byte{9}})

			check(t, err)

			zero, err := algorithm.Configure(&cryptopq.HashOptions{Salt: make([]byte, field)})

			check(t, err)

			unchanged, err := algorithm.Configure(nil)

			check(t, err)

			empty, err := algorithm.Configure(&cryptopq.HashOptions{})

			check(t, err)

			if padded != short || zero != algorithm || unchanged != algorithm || empty != algorithm {
				t.Fatalf("%s: padding or defaults", algorithm)
			}
		}

		for _, length := range []int{-1, function.full + 1} {
			_, err := function.mac.Configure(&cryptopq.MacOptions{Length: length})

			expectCode(t, err, cryptopq.INVALID_OPTION)
		}

		for _, options := range []cryptopq.MacOptions{{Customization: []byte("c")}, {Xof: true}, {Salt: make([]byte, field+1)}, {Personalization: make([]byte, field+1)}} {
			_, err := function.mac.Configure(&options)

			expectCode(t, err, cryptopq.INVALID_OPTION)
		}

		if function.mac.DigestSize() != function.full {
			t.Fatalf("%s: default MAC length %d", name, function.mac.DigestSize())
		}

		one, err := function.mac.Configure(&cryptopq.MacOptions{Length: 1})

		check(t, err)

		if one.DigestSize() != 1 || len(one.Digest([]byte("k"), nil)) != 1 {
			t.Fatalf("%s: one-byte MAC", name)
		}

		for _, size := range []int{0, function.full + 1} {
			panics(t, "INVALID_LENGTH", func() { function.mac.Digest(make([]byte, size), nil) })

			panics(t, "INVALID_LENGTH", func() { function.mac.Create(make([]byte, size)) })

			panics(t, "INVALID_LENGTH", func() { function.mac.Verify(make([]byte, size), nil, make([]byte, function.full)) })
		}
	}
}
