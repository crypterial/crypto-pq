package cryptopq_test

import (
	"bytes"
	"fmt"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var cshakes = map[string]cryptopq.XofAlgorithm{"cSHAKE128": cryptopq.CSHAKE128, "cSHAKE256": cryptopq.CSHAKE256}

var kmacs = map[string]cryptopq.MacAlgorithm{"KMAC128": cryptopq.KMAC128, "KMAC256": cryptopq.KMAC256}

// cSHAKE with a function name goes through the hazmat API, which SP 800-185 reserves to NIST.
func configureCshake(t *testing.T, name string, functionName, customization []byte) cryptopq.XofAlgorithm {
	t.Helper()

	algorithm, ok := cshakes[name]

	if !ok {
		t.Fatalf("unknown parameter set %s", name)
	}

	if len(functionName) > 0 {
		configured, err := cryptopq.Hazmat.ConfigureCshake(algorithm, functionName, customization)

		check(t, err)

		return configured
	}

	configured, err := algorithm.Configure(&cryptopq.XofOptions{Customization: customization})

	check(t, err)

	return configured
}

func TestCshakeVectors(t *testing.T) {
	for _, file := range []struct {
		name  string
		count int
	}{{"nist-examples/cSHAKE.txt", 4}, {"acvp/cSHAKE.txt", 5}} {
		tested := 0

		for _, r := range records(t, file.name, "md") {
			context := fmt.Sprintf("%s %s%s", file.name, r.values["name"], r.values["tcId"])

			algorithm := configureCshake(t, r.header["parameterSet"], decode(t, r.values["functionName"]), decode(t, r.values["customization"]))

			checkXof(t, context, algorithm, decode(t, r.values["msg"]), decode(t, r.values["md"]))

			tested++
		}

		if tested != file.count {
			t.Fatalf("%s: tested %d", file.name, tested)
		}
	}
}

// KMAC of data under key, configured for want's length, the customization and the XOF flag,
// checked through every form; it must verify exactly when valid, and only at the full length.
func checkKmac(t *testing.T, context string, algorithm cryptopq.MacAlgorithm, key, data, customization, want []byte, xof, valid bool) {
	t.Helper()

	configured, err := algorithm.Configure(&cryptopq.MacOptions{Length: len(want), Customization: customization, Xof: xof})

	check(t, err)

	if configured.DigestSize() != len(want) {
		t.Fatalf("%s: digest size %d", context, configured.DigestSize())
	}

	if configured.Verify(key, data, want) != valid {
		t.Fatalf("%s: Verify is %v", context, !valid)
	}

	mac := configured.Create(key)

	for _, piece := range pieces(data) {
		mac.Update(piece)
	}

	if mac.Verify(want) != valid {
		t.Fatalf("%s: Mac.Verify is %v", context, !valid)
	}

	tag := configured.Digest(key, data)

	if bytes.Equal(tag, want) != valid {
		t.Fatalf("%s: got %x", context, tag)
	}

	out := make([]byte, len(want))

	configured.DigestInto(key, data, out)

	same(t, out, tag, context+" DigestInto")

	same(t, mac.Digest(), tag, context+" streamed")

	if configured.Verify(key, data, tag[:len(tag)-1]) || configured.Verify(key, data, append(bytes.Clone(tag), 0)) || mac.Verify(tag[1:]) {
		t.Fatalf("%s: a tag of another length verifies", context)
	}
}

func TestKmacVectors(t *testing.T) {
	for _, file := range []struct {
		name  string
		count int
	}{{"nist-examples/KMAC.txt", 12}, {"acvp/KMAC.txt", 103}} {
		tested, rejected := 0, 0

		for _, r := range records(t, file.name, "mac") {
			context := fmt.Sprintf("%s %s%s", file.name, r.values["name"], r.values["tcId"])

			algorithm, ok := kmacs[r.header["parameterSet"]]

			if !ok {
				t.Fatalf("%s: parameter set %s", context, r.header["parameterSet"])
			}

			valid := r.values["testPassed"] != "false"

			checkKmac(t, context, algorithm, decode(t, r.values["key"]), decode(t, r.values["msg"]), decode(t, r.values["customization"]), decode(t, r.values["mac"]), r.header["xof"] == "true", valid)

			tested++

			if !valid {
				rejected++
			}
		}

		if tested != file.count || (file.count == 103) != (rejected == 2) {
			t.Fatalf("%s: tested %d, %d to reject", file.name, tested, rejected)
		}
	}
}

func TestKmacWycheproof(t *testing.T) {
	tested, rejected := 0, 0

	for _, r := range records(t, "wycheproof/kmac.txt", "tag") {
		context := fmt.Sprintf("wycheproof %s tcId %s", r.header["parameterSet"], r.values["tcId"])

		valid := r.values["result"] == "valid"

		if !valid && r.values["result"] != "invalid" {
			t.Fatalf("%s: result %s", context, r.values["result"])
		}

		checkKmac(t, context, kmacs[r.header["parameterSet"]], decode(t, r.values["key"]), decode(t, r.values["msg"]), nil, decode(t, r.values["tag"]), false, valid)

		tested++

		if !valid {
			rejected++
		}
	}

	if tested != 435 || rejected != 270 {
		t.Fatalf("tested %d, rejected %d", tested, rejected)
	}
}

func TestSp800185Options(t *testing.T) {
	for name, algorithm := range cshakes {
		shake := cryptopq.SHAKE128

		if name == "cSHAKE256" {
			shake = cryptopq.SHAKE256
		}

		// Without a function name and customization cSHAKE is SHAKE.
		data := sequence(300)

		if !bytes.Equal(algorithm.Digest(data, 200), shake.Digest(data, 200)) {
			t.Fatalf("%s: differs from SHAKE", name)
		}

		empty, err := algorithm.Configure(&cryptopq.XofOptions{})

		check(t, err)

		hazmat, err := cryptopq.Hazmat.ConfigureCshake(algorithm, nil, nil)

		check(t, err)

		if empty != algorithm || hazmat != algorithm {
			t.Fatalf("%s: empty options changed the algorithm", name)
		}

		named, err := cryptopq.Hazmat.ConfigureCshake(algorithm, []byte("N"), nil)

		check(t, err)

		customized := configureCshake(t, name, nil, []byte("N"))

		if named == customized || bytes.Equal(named.Digest(nil, 32), customized.Digest(nil, 32)) {
			t.Fatalf("%s: the function name and the customization collide", name)
		}

		// Customizations across a block boundary.
		for _, size := range []int{160, 161, 165, 166, 200, 400} {
			long := configureCshake(t, name, nil, sequence(size))

			checkXof(t, fmt.Sprintf("%s, %d-byte customization", name, size), long, data, long.Digest(data, 100))
		}
	}

	for _, algorithm := range []cryptopq.XofAlgorithm{cryptopq.SHAKE128, cryptopq.SHAKE256, cryptopq.ASCON_XOF128} {
		_, err := cryptopq.Hazmat.ConfigureCshake(algorithm, []byte("N"), nil)

		expectCode(t, err, cryptopq.INVALID_OPTION)

		_, err = algorithm.Configure(&cryptopq.XofOptions{Customization: []byte("S")})

		expectCode(t, err, cryptopq.INVALID_OPTION)
	}

	for name, algorithm := range kmacs {
		for _, length := range []int{-1, 1, 2, 3} {
			_, err := algorithm.Configure(&cryptopq.MacOptions{Length: length})

			expectCode(t, err, cryptopq.INVALID_OPTION)
		}

		for _, options := range []cryptopq.MacOptions{{Salt: []byte{1}}, {Personalization: []byte{1}}} {
			_, err := algorithm.Configure(&options)

			expectCode(t, err, cryptopq.INVALID_OPTION)
		}

		four, err := algorithm.Configure(&cryptopq.MacOptions{Length: 4, Xof: true})

		check(t, err)

		if four.DigestSize() != 4 || len(four.Digest(nil, nil)) != 4 {
			t.Fatalf("%s: four-byte tag", name)
		}

		// KMACXOF's output does not depend on its length, KMAC's does.
		long, err := algorithm.Configure(&cryptopq.MacOptions{Length: 400, Xof: true})

		check(t, err)

		key := sequence(32)

		if !bytes.Equal(long.Digest(key, nil)[:4], four.Digest(key, nil)) {
			t.Fatalf("%s: KMACXOF output is not prefix-free of its length", name)
		}

		fixed, err := algorithm.Configure(&cryptopq.MacOptions{Length: 400})

		check(t, err)

		if bytes.Equal(fixed.Digest(key, nil), long.Digest(key, nil)) {
			t.Fatalf("%s: KMAC equals KMACXOF", name)
		}

		unchanged, err := algorithm.Configure(&cryptopq.MacOptions{})

		check(t, err)

		if unchanged != algorithm {
			t.Fatalf("%s: empty options changed the algorithm", name)
		}

		// Keys of any length, and a tag longer than a block, verify through the block-wise
		// comparison.
		for _, size := range []int{0, 1, 165, 166, 168, 300} {
			checkKmac(t, fmt.Sprintf("%s, %d-byte key", name, size), algorithm, sequence(size), sequence(500), []byte("c"), fixed.Digest(sequence(size), sequence(500))[:200], false, false)

			tag, err := algorithm.Configure(&cryptopq.MacOptions{Length: 400, Customization: []byte("c")})

			check(t, err)

			checkKmac(t, fmt.Sprintf("%s, %d-byte key", name, size), algorithm, sequence(size), sequence(500), []byte("c"), tag.Digest(sequence(size), sequence(500)), false, true)
		}
	}

	for _, algorithm := range []cryptopq.MacAlgorithm{cryptopq.HMAC_SHA_224, cryptopq.HMAC_SHA_256, cryptopq.HMAC_SHA_384, cryptopq.HMAC_SHA_512} {
		for _, options := range []cryptopq.MacOptions{{Length: 16}, {Customization: []byte{1}}, {Xof: true}, {Salt: []byte{1}}, {Personalization: []byte{1}}} {
			_, err := algorithm.Configure(&options)

			expectCode(t, err, cryptopq.INVALID_OPTION)
		}

		unchanged, err := algorithm.Configure(&cryptopq.MacOptions{})

		check(t, err)

		if unchanged != algorithm {
			t.Fatalf("%s: empty options changed the algorithm", algorithm)
		}
	}
}
