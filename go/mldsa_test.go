package cryptopq_test

import (
	"bytes"
	"strings"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var dsaAlgorithms = map[string]cryptopq.SignatureAlgorithm{
	"ML-DSA-44": cryptopq.ML_DSA_44,
	"ML-DSA-65": cryptopq.ML_DSA_65,
	"ML-DSA-87": cryptopq.ML_DSA_87,
}

var dsaArcs = map[cryptopq.SignatureAlgorithm]byte{cryptopq.ML_DSA_44: 17, cryptopq.ML_DSA_65: 18, cryptopq.ML_DSA_87: 19}

var preHashes = map[string]cryptopq.PreHash{
	"SHA2-224":     cryptopq.SHA_224,
	"SHA2-256":     cryptopq.SHA_256,
	"SHA2-384":     cryptopq.SHA_384,
	"SHA2-512":     cryptopq.SHA_512,
	"SHA2-512/224": cryptopq.SHA_512_224,
	"SHA2-512/256": cryptopq.SHA_512_256,
	"SHA3-224":     cryptopq.SHA3_224,
	"SHA3-256":     cryptopq.SHA3_256,
	"SHA3-384":     cryptopq.SHA3_384,
	"SHA3-512":     cryptopq.SHA3_512,
	"SHAKE-128":    cryptopq.SHAKE128,
	"SHAKE-256":    cryptopq.SHAKE256,
}

func dsaOID(algorithm cryptopq.SignatureAlgorithm) []byte {
	return der(0x06, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, dsaArcs[algorithm]})
}

func recordPreHash(r record) cryptopq.PreHash {
	if r.header["preHash"] == "pure" {
		return nil
	}

	return preHashes[r.values["hashAlg"]]
}

func TestMlDsaAcvpKeyGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/ML-DSA-keyGen.txt", "sk") {
		algorithm := dsaAlgorithms[r.header["parameterSet"]]

		seed, pk, sk := decode(t, r.values["seed"]), decode(t, r.values["pk"]), decode(t, r.values["sk"])

		context := "tcId " + r.values["tcId"]

		pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, seed)

		check(t, err)

		same(t, export(t, pair.PublicKey, cryptopq.RAW), pk, context)

		same(t, export(t, pair.PrivateKey, cryptopq.RAW), seed, context)

		expanded, err := algorithm.ImportPrivateKey(sk, cryptopq.RAW)

		check(t, err)

		same(t, export(t, expanded.PublicKey(), cryptopq.RAW), pk, context)

		same(t, export(t, expanded, cryptopq.RAW), sk, context)

		both := pkcs8(dsaOID(algorithm), der(0x30, der(0x04, seed), der(0x04, sk)))

		imported, err := algorithm.ImportPrivateKey(both, cryptopq.DER)

		check(t, err)

		same(t, export(t, imported, cryptopq.RAW), seed, context)

		corrupted := bytes.Clone(sk)

		corrupted[len(corrupted)-1] ^= 1

		_, err = algorithm.ImportPrivateKey(corrupted, cryptopq.RAW)

		expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)
	}
}

func TestMlDsaAcvpSignatureGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/ML-DSA-sigGen.txt", "signature") {
		algorithm := dsaAlgorithms[r.header["parameterSet"]]

		context := "tcId " + r.values["tcId"]

		var privateKey *cryptopq.SignaturePrivateKey

		if r.header["keyFormat"] == "seed" {
			pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, decode(t, r.values["seed"]))

			check(t, err)

			privateKey = pair.PrivateKey
		} else {
			var err error

			privateKey, err = algorithm.ImportPrivateKey(decode(t, r.values["sk"]), cryptopq.RAW)

			check(t, err)
		}

		same(t, export(t, privateKey.PublicKey(), cryptopq.RAW), decode(t, r.values["pk"]), context)

		randomness := make([]byte, 32)

		if r.header["deterministic"] != "true" {
			randomness = decode(t, r.values["rnd"])
		}

		message := decode(t, r.values["message"])

		options := &cryptopq.SignOptions{Context: decode(t, r.values["context"]), PreHash: recordPreHash(r)}

		signature, err := cryptopq.Hazmat.Sign(privateKey, message, randomness, options)

		check(t, err)

		same(t, signature, decode(t, r.values["signature"]), context)

		verifyOptions := &cryptopq.VerifyOptions{Context: options.Context, PreHash: options.PreHash}

		if !cryptopq.Hazmat.Verify(privateKey.PublicKey(), signature, message, verifyOptions) {
			t.Fatalf("%s: verify", context)
		}
	}
}

func TestMlDsaAcvpSignatureVerification(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/ML-DSA-sigVer.txt", "signature") {
		publicKey, err := dsaAlgorithms[r.header["parameterSet"]].ImportPublicKey(decode(t, r.values["pk"]), cryptopq.RAW)

		check(t, err)

		options := &cryptopq.VerifyOptions{Context: decode(t, r.values["context"]), PreHash: recordPreHash(r)}

		result := cryptopq.Hazmat.Verify(publicKey, decode(t, r.values["signature"]), decode(t, r.values["message"]), options)

		if result != (r.values["testPassed"] == "true") {
			t.Fatalf("tcId %s (%s): got %v", r.values["tcId"], r.values["reason"], result)
		}
	}
}

func TestMlDsaWycheproofVerification(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/mldsa_verify.txt", "tcId") {
		algorithm := dsaAlgorithms[r.header["parameterSet"]]

		key := decode(t, r.header["publicKey"])

		context := r.header["parameterSet"] + " tcId " + r.values["tcId"]

		publicKey, err := algorithm.ImportPublicKey(key, cryptopq.RAW)

		if len(key) != algorithm.PublicKeySize() {
			expectCode(t, err, cryptopq.INVALID_LENGTH)

			continue
		}

		check(t, err)

		if r.header["publicKeyDer"] != "" {
			fromDer, err := algorithm.ImportPublicKey(decode(t, r.header["publicKeyDer"]), cryptopq.DER)

			check(t, err)

			if !fromDer.Equal(publicKey) {
				t.Fatalf("%s: DER", context)
			}
		}

		options := &cryptopq.VerifyOptions{Context: decode(t, r.values["ctx"])}

		if publicKey.Verify(decode(t, r.values["sig"]), decode(t, r.values["msg"]), options) != (r.values["result"] == "valid") {
			t.Fatalf("%s: result %s", context, r.values["result"])
		}
	}
}

func TestMlDsaWycheproofDeterministicSigning(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/mldsa_sign_seed.txt", "tcId") {
		if _, ok := r.values["msg"]; !ok {
			continue
		}

		algorithm := dsaAlgorithms[r.header["parameterSet"]]

		seed, flags := decode(t, r.header["privateSeed"]), r.values["flags"]

		context := r.header["parameterSet"] + " tcId " + r.values["tcId"]

		if strings.Contains(flags, "IncorrectPrivateKeyLength") {
			_, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, seed)

			expectCode(t, err, cryptopq.INVALID_LENGTH)

			continue
		}

		var privateKey *cryptopq.SignaturePrivateKey

		if r.header["privateKeyPkcs8"] != "" {
			var err error

			privateKey, err = algorithm.ImportPrivateKey(decode(t, r.header["privateKeyPkcs8"]), cryptopq.DER)

			check(t, err)
		} else {
			pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, seed)

			check(t, err)

			privateKey = pair.PrivateKey
		}

		same(t, export(t, privateKey.PublicKey(), cryptopq.RAW), decode(t, r.header["publicKey"]), context)

		message, signature := decode(t, r.values["msg"]), decode(t, r.values["sig"])

		ctx := decode(t, r.values["ctx"])

		switch {
		case strings.Contains(flags, "InvalidContext"):
			_, err := privateKey.Sign(message, &cryptopq.SignOptions{Context: ctx})

			expectCode(t, err, cryptopq.INVALID_CONTEXT)
		case strings.Contains(flags, "Randomized"):
			if !privateKey.PublicKey().Verify(signature, message, &cryptopq.VerifyOptions{Context: ctx}) {
				t.Fatalf("%s: randomized signature", context)
			}
		default:
			got, err := privateKey.Sign(message, &cryptopq.SignOptions{Context: ctx, Deterministic: true})

			check(t, err)

			same(t, got, signature, context)
		}
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	t.Parallel()

	for _, algorithm := range dsaAlgorithms {
		pair, err := algorithm.GenerateKeyPair(nil)

		check(t, err)

		message := []byte("message")

		withContext := &cryptopq.VerifyOptions{Context: []byte("context")}

		signature, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Context: []byte("context")})

		check(t, err)

		if len(signature) != algorithm.SignatureSize() {
			t.Fatalf("%s: signature size", algorithm)
		}

		if !pair.PublicKey.Verify(signature, message, withContext) {
			t.Fatalf("%s: verify", algorithm)
		}

		if pair.PublicKey.Verify(signature, message, nil) || pair.PublicKey.Verify(signature, []byte("other"), withContext) || pair.PublicKey.Verify(signature[:len(signature)-1], message, withContext) {
			t.Fatalf("%s: accepted a wrong input", algorithm)
		}

		if pair.PublicKey.Verify(signature, message, &cryptopq.VerifyOptions{Context: make([]byte, 256)}) {
			t.Fatalf("%s: long context", algorithm)
		}

		_, err = pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Context: make([]byte, 256)})

		expectCode(t, err, cryptopq.INVALID_CONTEXT)

		first, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Deterministic: true})

		check(t, err)

		second, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Deterministic: true})

		check(t, err)

		same(t, first, second, "deterministic")

		third, err := pair.PrivateKey.Sign(message, nil)

		check(t, err)

		fourth, err := pair.PrivateKey.Sign(message, nil)

		check(t, err)

		if bytes.Equal(third, fourth) {
			t.Fatalf("%s: hedged signatures repeat", algorithm)
		}

		hashed, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: cryptopq.SHA_512})

		check(t, err)

		if !pair.PublicKey.Verify(hashed, message, &cryptopq.VerifyOptions{PreHash: cryptopq.SHA_512}) || pair.PublicKey.Verify(hashed, message, nil) {
			t.Fatalf("%s: pre-hash", algorithm)
		}

		_, err = pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: cryptopq.SHA_224})

		expectCode(t, err, cryptopq.INVALID_OPTION)

		_, err = pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: cryptopq.HashAlgorithm(0)})

		expectCode(t, err, cryptopq.INVALID_OPTION)

		if pair.PublicKey.Verify(hashed, message, &cryptopq.VerifyOptions{PreHash: cryptopq.XofAlgorithm(3)}) {
			t.Fatalf("%s: invalid pre-hash", algorithm)
		}
	}
}

func TestPreHashStrength(t *testing.T) {
	t.Parallel()

	allowed := map[string]string{
		"ML-DSA-44": "SHA2-256 SHA2-384 SHA2-512 SHA2-512/256 SHA3-256 SHA3-384 SHA3-512 SHAKE-128 SHAKE-256",
		"ML-DSA-65": "SHA2-384 SHA2-512 SHA3-384 SHA3-512 SHAKE-256",
		"ML-DSA-87": "SHA2-512 SHA3-512 SHAKE-256",
	}

	for name, algorithm := range dsaAlgorithms {
		pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, make([]byte, 32))

		check(t, err)

		for label, preHash := range preHashes {
			message := []byte("m")

			if strings.Contains(" "+allowed[name]+" ", " "+label+" ") {
				signature, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: preHash})

				check(t, err)

				if !pair.PublicKey.Verify(signature, message, &cryptopq.VerifyOptions{PreHash: preHash}) {
					t.Fatalf("%s %s: verify", name, label)
				}

				continue
			}

			_, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: preHash})

			expectCode(t, err, cryptopq.INVALID_OPTION)

			signature, err := cryptopq.Hazmat.Sign(pair.PrivateKey, message, make([]byte, 32), &cryptopq.SignOptions{PreHash: preHash})

			check(t, err)

			if !cryptopq.Hazmat.Verify(pair.PublicKey, signature, message, &cryptopq.VerifyOptions{PreHash: preHash}) {
				t.Fatalf("%s %s: hazmat verify", name, label)
			}

			if pair.PublicKey.Verify(signature, message, &cryptopq.VerifyOptions{PreHash: preHash}) {
				t.Fatalf("%s %s: weak pre-hash accepted", name, label)
			}
		}
	}
}

func TestSignatureFormats(t *testing.T) {
	t.Parallel()

	for name, algorithm := range dsaAlgorithms {
		pair, err := algorithm.GenerateKeyPair(&cryptopq.KeyGenOptions{SkipSelfTest: true})

		check(t, err)

		for _, format := range []cryptopq.KeyFormat{cryptopq.RAW, cryptopq.DER, cryptopq.PEM} {
			public, err := algorithm.ImportPublicKey(export(t, pair.PublicKey, format), format)

			check(t, err)

			if !public.Equal(pair.PublicKey) {
				t.Fatalf("%s %s: public", name, format)
			}

			private, err := algorithm.ImportPrivateKey(export(t, pair.PrivateKey, format), format)

			check(t, err)

			same(t, export(t, private, cryptopq.RAW), export(t, pair.PrivateKey, cryptopq.RAW), name)
		}

		privateDer := export(t, pair.PrivateKey, cryptopq.DER)

		same(t, privateDer[len(privateDer)-34:len(privateDer)-32], []byte{0x80, 0x20}, "seed form")

		again, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, export(t, pair.PrivateKey, cryptopq.RAW))

		check(t, err)

		if !again.PublicKey.Equal(pair.PublicKey) {
			t.Fatalf("%s: seed", name)
		}

		other := cryptopq.ML_DSA_44

		if algorithm == cryptopq.ML_DSA_44 {
			other = cryptopq.ML_DSA_65
		}

		_, err = other.ImportPublicKey(export(t, pair.PublicKey, cryptopq.DER), cryptopq.DER)

		expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)

		_, err = algorithm.ImportPrivateKey(make([]byte, 33), cryptopq.RAW)

		expectCode(t, err, cryptopq.INVALID_LENGTH)

		_, err = algorithm.ImportPublicKey(export(t, pair.PublicKey, cryptopq.RAW)[1:], cryptopq.RAW)

		expectCode(t, err, cryptopq.INVALID_LENGTH)

		_, err = cryptopq.Hazmat.Sign(pair.PrivateKey, nil, make([]byte, 31), nil)

		expectCode(t, err, cryptopq.INVALID_LENGTH)
	}
}
