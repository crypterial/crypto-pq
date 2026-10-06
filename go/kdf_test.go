package cryptopq_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var kdfs = map[string]cryptopq.KdfAlgorithm{"HKDF-SHA-256": cryptopq.HKDF_SHA_256, "HKDF-SHA-384": cryptopq.HKDF_SHA_384, "HKDF-SHA-512": cryptopq.HKDF_SHA_512}

func kdfOf(t *testing.T, name string) cryptopq.KdfAlgorithm {
	t.Helper()

	algorithm, ok := kdfs[name]

	if !ok {
		t.Fatalf("unknown parameter set %s", name)
	}

	return algorithm
}

// HKDF of ikm, checked against okm through Derive, DeriveInto, and Extract then Expand in both
// forms.
func checkHkdf(t *testing.T, context string, algorithm cryptopq.KdfAlgorithm, ikm, salt, info, okm []byte) {
	t.Helper()

	options := &cryptopq.KdfOptions{Salt: salt, Info: info}

	derived, err := algorithm.Derive(ikm, len(okm), options)

	check(t, err)

	same(t, derived, okm, context)

	out := make([]byte, len(okm))

	check(t, algorithm.DeriveInto(ikm, out, options))

	same(t, out, okm, context+" DeriveInto")

	prk := algorithm.Extract(ikm, options)

	expanded, err := algorithm.Expand(prk, len(okm), options)

	check(t, err)

	same(t, expanded, okm, context+" Extract and Expand")

	clear(out)

	check(t, algorithm.ExpandInto(prk, out, options))

	same(t, out, okm, context+" ExpandInto")
}

func TestHkdfRfc(t *testing.T) {
	tested := 0

	for _, r := range records(t, "rfc/hkdf.txt", "okm") {
		algorithm := kdfOf(t, r.header["parameterSet"])

		ikm, salt, info := decode(t, r.values["ikm"]), decode(t, r.values["salt"]), decode(t, r.values["info"])

		okm := decode(t, r.values["okm"])

		if len(okm) != number(t, r.values["length"]) {
			t.Fatalf("%s: length", r.values["name"])
		}

		same(t, algorithm.Extract(ikm, &cryptopq.KdfOptions{Salt: salt}), decode(t, r.values["prk"]), r.values["name"]+" PRK")

		checkHkdf(t, r.values["name"], algorithm, ikm, salt, info, okm)

		tested++
	}

	if tested != 3 {
		t.Fatalf("tested %d", tested)
	}
}

func TestHkdfWycheproof(t *testing.T) {
	counts := map[string]int{}

	refused := 0

	for _, r := range records(t, "wycheproof/hkdf.txt", "okm") {
		name := r.header["parameterSet"]

		algorithm := kdfOf(t, name)

		context := fmt.Sprintf("wycheproof %s tcId %s", name, r.values["tcId"])

		ikm, salt, info := decode(t, r.values["ikm"]), decode(t, r.values["salt"]), decode(t, r.values["info"])

		size := number(t, r.values["size"])

		switch r.values["result"] {
		case "valid":
			checkHkdf(t, context, algorithm, ikm, salt, info, decode(t, r.values["okm"]))
		case "invalid":
			_, err := algorithm.Derive(ikm, size, &cryptopq.KdfOptions{Salt: salt, Info: info})

			expectCode(t, err, cryptopq.INVALID_LENGTH)

			_, err = algorithm.Expand(algorithm.Extract(ikm, nil), size, nil)

			expectCode(t, err, cryptopq.INVALID_LENGTH)

			refused++
		default:
			t.Fatalf("%s: result %s", context, r.values["result"])
		}

		counts[name]++
	}

	if counts["HKDF-SHA-256"] != 86 || counts["HKDF-SHA-384"] != 83 || counts["HKDF-SHA-512"] != 83 || refused != 9 {
		t.Fatalf("tested %v, refused %d", counts, refused)
	}
}

// ACVP HKDF of SP 800-56C: a multi-expansion test extracts once and expands once per info.
func TestHkdfAcvp(t *testing.T) {
	tested, expansions := 0, 0

	for _, r := range records(t, "acvp/KDA-HKDF.txt", "okm") {
		algorithm := kdfOf(t, r.header["parameterSet"])

		context := fmt.Sprintf("%s %s tcId %s", r.header["parameterSet"], r.header["revision"], r.values["tcId"])

		ikm, salt := decode(t, r.values["ikm"]), decode(t, r.values["salt"])

		infos, okms := strings.Split(r.values["info"], ","), strings.Split(r.values["okm"], ",")

		if len(infos) != len(okms) {
			t.Fatalf("%s: %d infos and %d outputs", context, len(infos), len(okms))
		}

		length := number(t, r.values["length"])

		prk := algorithm.Extract(ikm, &cryptopq.KdfOptions{Salt: salt})

		for i := range infos {
			info, okm := decode(t, infos[i]), decode(t, okms[i])

			if len(okm) != length {
				t.Fatalf("%s: length", context)
			}

			expanded, err := algorithm.Expand(prk, length, &cryptopq.KdfOptions{Info: info})

			check(t, err)

			same(t, expanded, okm, context)

			if i == 0 {
				checkHkdf(t, context, algorithm, ikm, salt, info, okm)
			}

			expansions++
		}

		tested++
	}

	if tested != 450 || expansions < tested {
		t.Fatalf("tested %d with %d expansions", tested, expansions)
	}
}

func TestHkdfLimits(t *testing.T) {
	for name, algorithm := range kdfs {
		size := map[string]int{"HKDF-SHA-256": 32, "HKDF-SHA-384": 48, "HKDF-SHA-512": 64}[name]

		ikm := sequence(32)

		longest, err := algorithm.Derive(ikm, 255*size, nil)

		check(t, err)

		if len(longest) != 255*size {
			t.Fatalf("%s: %d bytes", name, len(longest))
		}

		for _, length := range []int{-1, 0, 255*size + 1} {
			_, err := algorithm.Derive(ikm, length, nil)

			expectCode(t, err, cryptopq.INVALID_LENGTH)

			_, err = algorithm.Expand(make([]byte, size), length, nil)

			expectCode(t, err, cryptopq.INVALID_LENGTH)
		}

		expectCode(t, algorithm.DeriveInto(ikm, nil, nil), cryptopq.INVALID_LENGTH)

		_, err = algorithm.Expand(make([]byte, size-1), 32, nil)

		expectCode(t, err, cryptopq.INVALID_LENGTH)

		expectCode(t, algorithm.ExpandInto(make([]byte, size-1), make([]byte, 32), nil), cryptopq.INVALID_LENGTH)

		panics(t, "INVALID_LENGTH", func() { algorithm.ExtractInto(ikm, make([]byte, size+1), nil) })

		// Every output is a prefix of the longest; an absent salt equals HashLen zero bytes.
		for _, length := range []int{1, size - 1, size, size + 1, 2*size + 7, 255 * size} {
			derived, err := algorithm.Derive(ikm, length, nil)

			check(t, err)

			same(t, derived, longest[:length], fmt.Sprintf("%s, %d bytes", name, length))
		}

		zeros, err := algorithm.Derive(ikm, 100, &cryptopq.KdfOptions{Salt: make([]byte, size)})

		check(t, err)

		same(t, zeros, longest[:100], name+" zero salt")

		// A long info takes the streaming path; a long PRK is hashed as an HMAC key.
		for _, infoSize := range []int{150, 191, 192, 193, 255, 256, 1000} {
			info := sequence(infoSize)

			prk := algorithm.Extract(ikm, nil)

			want, err := algorithm.Expand(prk, 3*size+5, &cryptopq.KdfOptions{Info: info})

			check(t, err)

			mac := map[string]cryptopq.MacAlgorithm{"HKDF-SHA-256": cryptopq.HMAC_SHA_256, "HKDF-SHA-384": cryptopq.HMAC_SHA_384, "HKDF-SHA-512": cryptopq.HMAC_SHA_512}[name]

			var previous, expected []byte

			for i := byte(1); len(expected) < len(want); i++ {
				previous = mac.Digest(prk, append(append(bytes.Clone(previous), info...), i))

				expected = append(expected, previous...)
			}

			same(t, want, expected[:len(want)], fmt.Sprintf("%s, %d-byte info", name, infoSize))
		}

		long := sequence(300)

		expanded, err := algorithm.Expand(long, 64, nil)

		check(t, err)

		hashed := map[string]cryptopq.HashAlgorithm{"HKDF-SHA-256": cryptopq.SHA_256, "HKDF-SHA-384": cryptopq.SHA_384, "HKDF-SHA-512": cryptopq.SHA_512}[name].Digest(long)

		same(t, expanded, mustExpand(t, algorithm, hashed, 64), name+" long PRK")

		if algorithm.Name() != name || algorithm.String() != name {
			t.Fatalf("name %q", algorithm.Name())
		}
	}
}

func mustExpand(t *testing.T, algorithm cryptopq.KdfAlgorithm, prk []byte, length int) []byte {
	t.Helper()

	out, err := algorithm.Expand(prk, length, nil)

	check(t, err)

	return out
}
