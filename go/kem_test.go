package cryptopq_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var kemAlgorithms = map[string]cryptopq.KemAlgorithm{
	"ML-KEM-512":  cryptopq.ML_KEM_512,
	"ML-KEM-768":  cryptopq.ML_KEM_768,
	"ML-KEM-1024": cryptopq.ML_KEM_1024,
}

var kemArcs = map[cryptopq.KemAlgorithm]byte{cryptopq.ML_KEM_512: 1, cryptopq.ML_KEM_768: 2, cryptopq.ML_KEM_1024: 3}

func kemOID(algorithm cryptopq.KemAlgorithm) []byte {
	return der(0x06, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, kemArcs[algorithm]})
}

func pkcs8(oid, privateKey []byte, extra ...[]byte) []byte {
	return der(0x30, append([][]byte{der(0x02, []byte{0}), der(0x30, oid), der(0x04, privateKey)}, extra...)...)
}

func expectCode(t *testing.T, err error, code cryptopq.ErrorCode) {
	t.Helper()

	if !errors.Is(err, code) {
		t.Fatalf("got error %v, want %s", err, code)
	}
}

func check(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func export(t *testing.T, key interface {
	ExportKey(cryptopq.KeyFormat) ([]byte, error)
}, format cryptopq.KeyFormat) []byte {
	t.Helper()

	data, err := key.ExportKey(format)

	check(t, err)

	return data
}

func same(t *testing.T, got, want []byte, context string) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %x, want %x", context, got, want)
	}
}

func TestMlKemAcvpKeyGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/ML-KEM-keyGen.txt", "dk") {
		algorithm := kemAlgorithms[r.header["parameterSet"]]

		context := "tcId " + r.values["tcId"]

		seed := append(decode(t, r.values["d"]), decode(t, r.values["z"])...)

		ek, dk := decode(t, r.values["ek"]), decode(t, r.values["dk"])

		pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

		check(t, err)

		same(t, export(t, pair.PublicKey, cryptopq.RAW), ek, context)

		same(t, export(t, pair.PrivateKey, cryptopq.RAW), seed, context)

		expanded, err := algorithm.ImportPrivateKey(dk, cryptopq.RAW)

		check(t, err)

		same(t, export(t, expanded.PublicKey(), cryptopq.RAW), ek, context)

		same(t, export(t, expanded, cryptopq.RAW), dk, context)

		both := pkcs8(kemOID(algorithm), der(0x30, der(0x04, seed), der(0x04, dk)))

		imported, err := algorithm.ImportPrivateKey(both, cryptopq.DER)

		check(t, err)

		same(t, export(t, imported, cryptopq.RAW), seed, context)
	}
}

func TestMlKemAcvpEncapsulationAndDecapsulation(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/ML-KEM-encapDecap.txt", "tcId") {
		algorithm := kemAlgorithms[r.header["parameterSet"]]

		context := r.header["function"] + " tcId " + r.values["tcId"]

		switch r.header["function"] {
		case "encapsulation":
			publicKey, err := algorithm.ImportPublicKey(decode(t, r.values["ek"]), cryptopq.RAW)

			check(t, err)

			result, err := cryptopq.Hazmat.Encapsulate(publicKey, decode(t, r.values["m"]))

			check(t, err)

			same(t, result.Ciphertext, decode(t, r.values["c"]), context)

			same(t, result.SharedSecret, decode(t, r.values["k"]), context)
		case "decapsulation":
			var privateKey *cryptopq.KemPrivateKey

			if r.header["keyFormat"] == "seed" {
				pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, append(decode(t, r.values["d"]), decode(t, r.values["z"])...))

				check(t, err)

				privateKey = pair.PrivateKey
			} else {
				var err error

				privateKey, err = algorithm.ImportPrivateKey(decode(t, r.values["dk"]), cryptopq.RAW)

				check(t, err)
			}

			sharedSecret, err := privateKey.Decapsulate(decode(t, r.values["c"]))

			check(t, err)

			same(t, sharedSecret, decode(t, r.values["k"]), context)
		case "encapsulationKeyCheck":
			_, err := algorithm.ImportPublicKey(decode(t, r.values["ek"]), cryptopq.RAW)

			if (err == nil) != (r.values["testPassed"] == "true") {
				t.Fatalf("%s: %v", context, err)
			}
		default:
			_, err := algorithm.ImportPrivateKey(decode(t, r.values["dk"]), cryptopq.RAW)

			if (err == nil) != (r.values["testPassed"] == "true") {
				t.Fatalf("%s: %v", context, err)
			}
		}
	}
}

func TestMlKemWycheproofDecapsulation(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/mlkem.txt", "tcId") {
		algorithm := kemAlgorithms[r.header["parameterSet"]]

		seed, c := decode(t, r.values["seed"]), decode(t, r.values["c"])

		context := r.header["parameterSet"] + " tcId " + r.values["tcId"]

		pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

		if len(seed) != 64 {
			expectCode(t, err, cryptopq.INVALID_LENGTH)

			continue
		}

		check(t, err)

		sharedSecret, err := pair.PrivateKey.Decapsulate(c)

		if r.values["result"] == "valid" {
			check(t, err)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), decode(t, r.values["ek"]), context)

			same(t, sharedSecret, decode(t, r.values["K"]), context)
		} else {
			expectCode(t, err, cryptopq.INVALID_LENGTH)
		}
	}
}

func TestMlKemWycheproofEncapsulation(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/mlkem_encaps.txt", "tcId") {
		algorithm := kemAlgorithms[r.header["parameterSet"]]

		ek := decode(t, r.values["ek"])

		context := r.header["parameterSet"] + " tcId " + r.values["tcId"]

		publicKey, err := algorithm.ImportPublicKey(ek, cryptopq.RAW)

		if r.values["result"] != "valid" {
			code := cryptopq.INVALID_PUBLIC_KEY

			if len(ek) != algorithm.PublicKeySize() {
				code = cryptopq.INVALID_LENGTH
			}

			expectCode(t, err, code)

			continue
		}

		check(t, err)

		result, err := cryptopq.Hazmat.Encapsulate(publicKey, decode(t, r.values["m"]))

		check(t, err)

		same(t, result.Ciphertext, decode(t, r.values["c"]), context)

		same(t, result.SharedSecret, decode(t, r.values["K"]), context)
	}
}

func TestMlKemWycheproofExpandedDecapsulation(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/mlkem_semi_expanded_decaps.txt", "tcId") {
		algorithm := kemAlgorithms[r.header["parameterSet"]]

		dk, c, flags := decode(t, r.values["dk"]), decode(t, r.values["c"]), r.values["flags"]

		context := r.header["parameterSet"] + " tcId " + r.values["tcId"]

		privateKey, err := algorithm.ImportPrivateKey(dk, cryptopq.RAW)

		switch {
		case r.values["result"] == "valid":
			check(t, err)

			same(t, export(t, privateKey.PublicKey(), cryptopq.RAW), decode(t, r.values["ek"]), context)

			sharedSecret, err := privateKey.Decapsulate(c)

			check(t, err)

			same(t, sharedSecret, decode(t, r.values["K"]), context)
		case strings.Contains(flags, "IncorrectCiphertextLength"):
			check(t, err)

			_, err = privateKey.Decapsulate(c)

			expectCode(t, err, cryptopq.INVALID_LENGTH)
		case strings.Contains(flags, "IncorrectDecapsulationKeyLength"):
			expectCode(t, err, cryptopq.INVALID_LENGTH)
		default:
			expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)
		}
	}
}

func TestKemRoundTrip(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []cryptopq.KemAlgorithm{cryptopq.ML_KEM_512, cryptopq.ML_KEM_768, cryptopq.ML_KEM_1024, cryptopq.X_WING} {
		pair, err := algorithm.GenerateKeyPair(nil)

		check(t, err)

		encapsulation, err := pair.PublicKey.Encapsulate()

		check(t, err)

		if len(encapsulation.Ciphertext) != algorithm.CiphertextSize() || len(encapsulation.SharedSecret) != algorithm.SharedSecretSize() {
			t.Fatalf("%s: sizes", algorithm)
		}

		sharedSecret, err := pair.PrivateKey.Decapsulate(encapsulation.Ciphertext)

		check(t, err)

		same(t, sharedSecret, encapsulation.SharedSecret, algorithm.Name())

		tampered := bytes.Clone(encapsulation.Ciphertext)

		tampered[0] ^= 1

		if rejected, err := pair.PrivateKey.Decapsulate(tampered); err != nil || bytes.Equal(rejected, sharedSecret) {
			t.Fatalf("%s: tampered ciphertext", algorithm)
		}

		_, err = pair.PrivateKey.Decapsulate(encapsulation.Ciphertext[:len(encapsulation.Ciphertext)-1])

		expectCode(t, err, cryptopq.INVALID_LENGTH)

		if len(export(t, pair.PublicKey, cryptopq.RAW)) != algorithm.PublicKeySize() {
			t.Fatalf("%s: public key size", algorithm)
		}

		unchecked, err := algorithm.GenerateKeyPair(&cryptopq.KeyGenOptions{SkipSelfTest: true})

		check(t, err)

		if unchecked.PublicKey.Algorithm() != algorithm || unchecked.PrivateKey.Algorithm() != algorithm {
			t.Fatalf("%s: algorithm", algorithm)
		}

		if !pair.PrivateKey.PublicKey().Equal(pair.PublicKey) || pair.PublicKey.Equal(unchecked.PublicKey) {
			t.Fatalf("%s: Equal", algorithm)
		}
	}
}

// The matrix of a key is computed on first use, not when the key is made or imported, and the two
// halves of a key pair share one cache, so using either one fills it for both.
func TestKeyCaches(t *testing.T) {
	t.Parallel()

	for _, c := range kemCases {
		generated, err := c.algorithm.GenerateKeyPair(&cryptopq.KeyGenOptions{SkipSelfTest: true})

		check(t, err)

		seeded, err := cryptopq.Hazmat.GenerateKemKeyPair(c.algorithm, sequence(c.seedSize))

		check(t, err)

		imported, err := c.algorithm.ImportPrivateKey(export(t, seeded.PrivateKey, cryptopq.RAW), cryptopq.RAW)

		check(t, err)

		for _, pair := range []*cryptopq.KemKeyPair{generated, seeded, {PublicKey: imported.PublicKey(), PrivateKey: imported}} {
			if shared, expanded := cryptopq.KemCache(pair.PublicKey, pair.PrivateKey); !shared || expanded {
				t.Fatalf("%s: a new key pair", c.algorithm)
			}

			if _, err := pair.PublicKey.Encapsulate(); err != nil {
				t.Fatal(err)
			}

			if shared, expanded := cryptopq.KemCache(pair.PrivateKey.PublicKey(), pair.PrivateKey); !shared || !expanded {
				t.Fatalf("%s: a used key pair", c.algorithm)
			}
		}
	}

	for _, algorithm := range []cryptopq.SignatureAlgorithm{cryptopq.ML_DSA_44, cryptopq.ML_DSA_65, cryptopq.ML_DSA_87} {
		generated, err := algorithm.GenerateKeyPair(&cryptopq.KeyGenOptions{SkipSelfTest: true})

		check(t, err)

		seeded := generateSignatureKey(t, algorithm)

		imported, err := algorithm.ImportPrivateKey(export(t, seeded.PrivateKey, cryptopq.RAW), cryptopq.RAW)

		check(t, err)

		for _, pair := range []*cryptopq.SignatureKeyPair{generated, seeded, {PublicKey: imported.PublicKey(), PrivateKey: imported}} {
			if shared, expanded := cryptopq.SignatureCache(pair.PublicKey, pair.PrivateKey); !shared || expanded {
				t.Fatalf("%s: a new key pair", algorithm)
			}

			if _, err := pair.PrivateKey.Sign([]byte("cache"), nil); err != nil {
				t.Fatal(err)
			}

			if shared, expanded := cryptopq.SignatureCache(pair.PrivateKey.PublicKey(), pair.PrivateKey); !shared || !expanded {
				t.Fatalf("%s: a used key pair", algorithm)
			}
		}
	}
}

// Keys compute what they derive on first use, so goroutines that first use one key, its private and
// public halves and the public keys it returns, all at once, must race safely and agree with a key
// that computes everything alone.
func TestConcurrentFirstUse(t *testing.T) {
	t.Parallel()

	for _, c := range kemCases {
		algorithm, seed, randomness := c.algorithm, sequence(c.seedSize), sequence(c.randomnessSize)

		reference, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

		check(t, err)

		want, err := cryptopq.Hazmat.Encapsulate(reference.PublicKey, randomness)

		check(t, err)

		pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

		check(t, err)

		imported, err := algorithm.ImportPublicKey(export(t, reference.PublicKey, cryptopq.RAW), cryptopq.RAW)

		check(t, err)

		var group sync.WaitGroup

		for i := range 12 {
			group.Go(func() {
				publicKey := [...]*cryptopq.KemPublicKey{pair.PublicKey, pair.PrivateKey.PublicKey(), imported}[i%3]

				got, err := cryptopq.Hazmat.Encapsulate(publicKey, randomness)

				if err != nil || !bytes.Equal(got.Ciphertext, want.Ciphertext) || !bytes.Equal(got.SharedSecret, want.SharedSecret) {
					t.Errorf("%s: a concurrent encapsulation differs", algorithm)
				}

				if secret, err := pair.PrivateKey.Decapsulate(want.Ciphertext); err != nil || !bytes.Equal(secret, want.SharedSecret) {
					t.Errorf("%s: a concurrent decapsulation differs", algorithm)
				}
			})
		}

		group.Wait()
	}

	message := []byte("crypto-pq concurrent first use")

	for _, algorithm := range []cryptopq.SignatureAlgorithm{cryptopq.ML_DSA_44, cryptopq.ML_DSA_65, cryptopq.ML_DSA_87} {
		reference := generateSignatureKey(t, algorithm)

		want, err := reference.PrivateKey.Sign(message, &cryptopq.SignOptions{Deterministic: true})

		check(t, err)

		pair := generateSignatureKey(t, algorithm)

		imported, err := algorithm.ImportPublicKey(export(t, reference.PublicKey, cryptopq.RAW), cryptopq.RAW)

		check(t, err)

		var group sync.WaitGroup

		for i := range 12 {
			group.Go(func() {
				if got, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Deterministic: true}); err != nil || !bytes.Equal(got, want) {
					t.Errorf("%s: a concurrent signature differs", algorithm)
				}

				publicKey := [...]*cryptopq.SignaturePublicKey{pair.PublicKey, pair.PrivateKey.PublicKey(), imported}[i%3]

				if !publicKey.Verify(want, message, nil) {
					t.Errorf("%s: a concurrent verification failed", algorithm)
				}
			})
		}

		group.Wait()
	}
}

func TestKemFormats(t *testing.T) {
	t.Parallel()

	for _, algorithm := range kemAlgorithms {
		pair, err := algorithm.GenerateKeyPair(nil)

		check(t, err)

		for _, format := range []cryptopq.KeyFormat{cryptopq.RAW, cryptopq.DER, cryptopq.PEM} {
			public, err := algorithm.ImportPublicKey(export(t, pair.PublicKey, format), format)

			check(t, err)

			private, err := algorithm.ImportPrivateKey(export(t, pair.PrivateKey, format), format)

			check(t, err)

			if !public.Equal(pair.PublicKey) || !private.PublicKey().Equal(pair.PublicKey) {
				t.Fatalf("%s %s: round trip", algorithm, format)
			}
		}

		if !bytes.HasPrefix(export(t, pair.PublicKey, cryptopq.PEM), []byte("-----BEGIN PUBLIC KEY-----\n")) {
			t.Fatalf("%s: public PEM", algorithm)
		}

		privatePem := export(t, pair.PrivateKey, cryptopq.PEM)

		if !bytes.HasPrefix(privatePem, []byte("-----BEGIN PRIVATE KEY-----\n")) {
			t.Fatalf("%s: private PEM", algorithm)
		}

		privateDer := export(t, pair.PrivateKey, cryptopq.DER)

		same(t, privateDer[len(privateDer)-66:len(privateDer)-64], []byte{0x80, 0x40}, "seed form")

		_, err = pair.PublicKey.ExportKey("jwk")

		expectCode(t, err, cryptopq.INVALID_OPTION)

		_, err = pair.PrivateKey.ExportKey("jwk")

		expectCode(t, err, cryptopq.INVALID_OPTION)

		_, err = algorithm.ImportPublicKey(append(export(t, pair.PublicKey, cryptopq.DER), 0), cryptopq.DER)

		expectCode(t, err, cryptopq.INVALID_ENCODING)

		_, err = algorithm.ImportPublicKey(privatePem, cryptopq.PEM)

		expectCode(t, err, cryptopq.INVALID_ENCODING)

		_, err = algorithm.ImportPrivateKey(make([]byte, 63), cryptopq.RAW)

		expectCode(t, err, cryptopq.INVALID_LENGTH)

		_, err = algorithm.ImportPrivateKey(nil, cryptopq.RAW)

		expectCode(t, err, cryptopq.INVALID_LENGTH)
	}

	pair, err := cryptopq.ML_KEM_768.GenerateKeyPair(nil)

	check(t, err)

	_, err = cryptopq.ML_KEM_512.ImportPublicKey(export(t, pair.PublicKey, cryptopq.DER), cryptopq.DER)

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)

	_, err = cryptopq.ML_KEM_1024.ImportPrivateKey(export(t, pair.PrivateKey, cryptopq.PEM), cryptopq.PEM)

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)
}

// A key imported in expanded form has no seed, so it exports the expanded key.
func TestKemExpandedForm(t *testing.T) {
	t.Parallel()

	r := records(t, "acvp/ML-KEM-keyGen.txt", "dk")[0]

	algorithm := kemAlgorithms[r.header["parameterSet"]]

	seed := append(decode(t, r.values["d"]), decode(t, r.values["z"])...)

	dk := decode(t, r.values["dk"])

	both := pkcs8(kemOID(algorithm), der(0x30, der(0x04, seed), der(0x04, make([]byte, len(dk)))))

	_, err := algorithm.ImportPrivateKey(both, cryptopq.DER)

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	expanded, err := algorithm.ImportPrivateKey(dk, cryptopq.RAW)

	check(t, err)

	same(t, export(t, expanded, cryptopq.DER), pkcs8(kemOID(algorithm), der(0x04, dk)), "der")

	reimported, err := algorithm.ImportPrivateKey(export(t, expanded, cryptopq.PEM), cryptopq.PEM)

	check(t, err)

	same(t, export(t, reimported, cryptopq.RAW), dk, "pem")

	pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

	check(t, err)

	encapsulation, err := pair.PublicKey.Encapsulate()

	check(t, err)

	sharedSecret, err := reimported.Decapsulate(encapsulation.Ciphertext)

	check(t, err)

	same(t, sharedSecret, encapsulation.SharedSecret, "decapsulate")
}

func TestXWing(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "xwing/test-vectors.txt", "seed") {
		pair, err := cryptopq.Hazmat.GenerateKemKeyPair(cryptopq.X_WING, decode(t, r.values["seed"]))

		check(t, err)

		context := "seed " + r.values["seed"][:16]

		same(t, export(t, pair.PublicKey, cryptopq.RAW), decode(t, r.values["pk"]), context)

		same(t, export(t, pair.PrivateKey, cryptopq.RAW), decode(t, r.values["sk"]), context)

		result, err := cryptopq.Hazmat.Encapsulate(pair.PublicKey, decode(t, r.values["eseed"]))

		check(t, err)

		same(t, result.Ciphertext, decode(t, r.values["ct"]), context)

		same(t, result.SharedSecret, decode(t, r.values["ss"]), context)

		sharedSecret, err := pair.PrivateKey.Decapsulate(result.Ciphertext)

		check(t, err)

		same(t, sharedSecret, result.SharedSecret, context)
	}

	pair, err := cryptopq.X_WING.GenerateKeyPair(nil)

	check(t, err)

	for _, format := range []cryptopq.KeyFormat{cryptopq.DER, cryptopq.PEM} {
		_, err = pair.PublicKey.ExportKey(format)

		expectCode(t, err, cryptopq.UNSUPPORTED)

		_, err = pair.PrivateKey.ExportKey(format)

		expectCode(t, err, cryptopq.UNSUPPORTED)

		_, err = cryptopq.X_WING.ImportPrivateKey(nil, format)

		expectCode(t, err, cryptopq.UNSUPPORTED)

		_, err = cryptopq.X_WING.ImportPublicKey(nil, format)

		expectCode(t, err, cryptopq.UNSUPPORTED)
	}

	imported, err := cryptopq.X_WING.ImportPrivateKey(export(t, pair.PrivateKey, cryptopq.RAW), cryptopq.RAW)

	check(t, err)

	if !imported.PublicKey().Equal(pair.PublicKey) {
		t.Fatal("X-Wing raw import")
	}

	_, err = cryptopq.X_WING.ImportPrivateKey(make([]byte, 31), cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_LENGTH)

	invalid := export(t, pair.PublicKey, cryptopq.RAW)

	copy(invalid, []byte{0xff, 0xff})

	_, err = cryptopq.X_WING.ImportPublicKey(invalid, cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_PUBLIC_KEY)
}

func TestKemHazmatLengths(t *testing.T) {
	t.Parallel()

	_, err := cryptopq.Hazmat.GenerateKemKeyPair(cryptopq.X_WING, make([]byte, 64))

	expectCode(t, err, cryptopq.INVALID_LENGTH)

	pair, err := cryptopq.Hazmat.GenerateKemKeyPair(cryptopq.ML_KEM_768, make([]byte, 64))

	check(t, err)

	_, err = cryptopq.Hazmat.Encapsulate(pair.PublicKey, make([]byte, 31))

	expectCode(t, err, cryptopq.INVALID_LENGTH)
}

// DER is strict: single-byte tags, shortest lengths, no trailing data, the OID alone in the
// AlgorithmIdentifier and no unused bits; PEM accepts surrounding whitespace only.
func TestKeyEncodingStrictness(t *testing.T) {
	t.Parallel()

	algorithm := cryptopq.ML_KEM_512

	pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, bytes.Repeat([]byte{1}, 64))

	check(t, err)

	oid := kemOID(algorithm)

	ek := export(t, pair.PublicKey, cryptopq.RAW)

	seed := bytes.Repeat([]byte{1}, 64)

	spki := func(algorithmIdentifier []byte, bitString []byte) []byte {
		return der(0x30, algorithmIdentifier, der(0x03, bitString))
	}

	same(t, export(t, pair.PublicKey, cryptopq.DER), spki(der(0x30, oid), append([]byte{0}, ek...)), "SPKI")

	valid := export(t, pair.PublicKey, cryptopq.DER)

	longForm := append([]byte{valid[0], 0x83, 0, valid[2], valid[3]}, valid[4:]...)

	invalidPublic := map[string][]byte{
		"parameters":      spki(der(0x30, oid, []byte{0x05, 0x00}), append([]byte{0}, ek...)),
		"unused bits":     spki(der(0x30, oid), append([]byte{1}, ek...)),
		"empty bits":      spki(der(0x30, oid), nil),
		"short key":       spki(der(0x30, oid), append([]byte{0}, ek[1:]...)),
		"leading zero":    longForm,
		"indefinite":      append([]byte{0x30, 0x80}, valid[4:]...),
		"truncated":       valid[:len(valid)-1],
		"wrong outer tag": append([]byte{0x31}, valid[1:]...),
		"short length":    append([]byte{0x30, 0x81, 0x05}, valid[4:]...),
		"empty":           nil,
	}

	for name, data := range invalidPublic {
		_, err := algorithm.ImportPublicKey(data, cryptopq.DER)

		if !errors.Is(err, cryptopq.INVALID_ENCODING) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	public := der(0x81, append([]byte{0}, ek...))

	attributes := der(0xa0, der(0x30))

	version1 := der(0x30, der(0x02, []byte{1}), der(0x30, oid), der(0x04, der(0x80, seed)), attributes, public)

	key, err := algorithm.ImportPrivateKey(version1, cryptopq.DER)

	check(t, err)

	if !key.PublicKey().Equal(pair.PublicKey) {
		t.Fatal("PKCS#8 v2")
	}

	other := bytes.Clone(ek)

	other[len(other)-1] ^= 1

	mismatched := der(0x30, der(0x02, []byte{1}), der(0x30, oid), der(0x04, der(0x80, seed)), der(0x81, append([]byte{0}, other...)))

	_, err = algorithm.ImportPrivateKey(mismatched, cryptopq.DER)

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	invalidPrivate := map[string][]byte{
		"public key in v1": der(0x30, der(0x02, []byte{0}), der(0x30, oid), der(0x04, der(0x80, seed)), public),
		"version 2":        der(0x30, der(0x02, []byte{2}), der(0x30, oid), der(0x04, der(0x80, seed))),
		"short seed":       pkcs8(oid, der(0x80, seed[1:])),
		"unknown form":     pkcs8(oid, der(0x81, seed)),
		"empty form":       pkcs8(oid, nil),
		"trailing form":    pkcs8(oid, append(der(0x80, seed), 0)),
		"short expanded":   pkcs8(oid, der(0x04, make([]byte, 1631))),
		"both reordered":   pkcs8(oid, der(0x30, der(0x04, make([]byte, 1632)), der(0x04, seed))),
		"trailing data":    append(pkcs8(oid, der(0x80, seed)), 0),
		"long form 66":     der(0x30, der(0x02, []byte{0}), der(0x30, oid), append([]byte{0x04, 0x81, 0x42}, der(0x80, seed)...)),
	}

	for name, data := range invalidPrivate {
		_, err := algorithm.ImportPrivateKey(data, cryptopq.DER)

		if !errors.Is(err, cryptopq.INVALID_ENCODING) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	pem := export(t, pair.PublicKey, cryptopq.PEM)

	lines := strings.Split(strings.TrimSpace(string(pem)), "\n")

	accepted := []string{
		" \t\n" + string(pem) + "\n\n",
		strings.Join(lines, "\r\n"),
		lines[0] + strings.Join(lines[1:len(lines)-1], "") + lines[len(lines)-1],
	}

	for _, text := range accepted {
		imported, err := algorithm.ImportPublicKey([]byte(text), cryptopq.PEM)

		check(t, err)

		if !imported.Equal(pair.PublicKey) {
			t.Fatal("PEM whitespace")
		}
	}

	body := strings.Join(lines[1:len(lines)-1], "")

	rejected := map[string]string{
		"text before":   "x" + string(pem),
		"text after":    string(pem) + "x",
		"wrong label":   strings.ReplaceAll(string(pem), "PUBLIC KEY", "PRIVATE KEY"),
		"bad character": lines[0] + "\n" + body[:10] + "*" + body[11:] + "\n" + lines[len(lines)-1],
		"non-ASCII":     lines[0] + "\n" + body[:10] + "\xe9" + body[11:] + "\n" + lines[len(lines)-1],
		"bad padding":   lines[0] + "\n" + body[:len(body)-4] + "A=A=\n" + lines[len(lines)-1],
		"length":        lines[0] + "\n" + body[:len(body)-1] + "\n" + lines[len(lines)-1],
		"no body":       lines[0] + lines[len(lines)-1],
	}

	for name, text := range rejected {
		_, err := algorithm.ImportPublicKey([]byte(text), cryptopq.PEM)

		if !errors.Is(err, cryptopq.INVALID_ENCODING) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	noncanonical := []byte("-----BEGIN PUBLIC KEY-----\nAB==\n-----END PUBLIC KEY-----\n")

	_, err = algorithm.ImportPublicKey(noncanonical, cryptopq.PEM)

	expectCode(t, err, cryptopq.INVALID_ENCODING)

	// The 86-byte PKCS#8 seed form ends in one "=", so the character before it carries two
	// unused bits; setting one must be refused even though the bytes would still decode.
	privatePem := export(t, pair.PrivateKey, cryptopq.PEM)

	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	last := bytes.LastIndexByte(privatePem, '=')

	if privatePem[last-1] == '=' {
		t.Fatal("expected one padding character")
	}

	padded := bytes.Clone(privatePem)

	padded[last-1] = alphabet[strings.IndexByte(alphabet, padded[last-1])^1]

	_, err = algorithm.ImportPrivateKey(padded, cryptopq.PEM)

	expectCode(t, err, cryptopq.INVALID_ENCODING)
}

func TestErrors(t *testing.T) {
	t.Parallel()

	_, err := cryptopq.ML_KEM_768.ImportPublicKey([]byte{1}, cryptopq.RAW)

	var detailed *cryptopq.Error

	if !errors.As(err, &detailed) || detailed.Code != cryptopq.INVALID_LENGTH || err.Error() != "cryptopq: INVALID_LENGTH: public key must be 1184 bytes" {
		t.Fatalf("error %v", err)
	}

	if errors.Is(err, cryptopq.INVALID_ENCODING) || cryptopq.UNSUPPORTED.Error() != "cryptopq: UNSUPPORTED" {
		t.Fatal("error codes")
	}

	pair, err := cryptopq.Hazmat.GenerateKemKeyPair(cryptopq.ML_KEM_768, bytes.Repeat([]byte{0xab}, 64))

	check(t, err)

	printed := fmt.Sprintf("%v %+v %#v %s %x %d %q", pair.PrivateKey, pair.PrivateKey, pair.PrivateKey, pair.PrivateKey, pair.PrivateKey, pair.PrivateKey, pair.PrivateKey) + fmt.Sprint(*pair)

	if strings.Contains(printed, "ab ab") || strings.Contains(printed, "abab") || strings.Contains(printed, "171") {
		t.Fatalf("formatting leaks the key: %s", printed)
	}

	if fmt.Sprint(pair.PrivateKey) != "<KemPrivateKey ML-KEM-768>" || cryptopq.X_WING.String() != "X-Wing" {
		t.Fatal("names")
	}

	names := []string{cryptopq.ML_DSA_65.Name(), cryptopq.SLH_DSA_SHA2_128S.Name(), cryptopq.HSS_LMS.Name(), cryptopq.XMSS.Name(), cryptopq.XMSS_MT.Name()}

	if strings.Join(names, " ") != "ML-DSA-65 SLH-DSA-SHA2-128s HSS/LMS XMSS XMSS^MT" {
		t.Fatalf("names %v", names)
	}

	panics(t, "invalid KemAlgorithm", func() { cryptopq.KemAlgorithm(0).Name() })

	panics(t, "invalid SignatureAlgorithm", func() { cryptopq.SignatureAlgorithm(16).Name() })

	panics(t, "invalid StatefulSignatureAlgorithm", func() { cryptopq.StatefulSignatureAlgorithm(4).Name() })
}
