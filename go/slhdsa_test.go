package cryptopq_test

import (
	"bytes"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var slhAlgorithms = map[string]cryptopq.SignatureAlgorithm{
	"SLH-DSA-SHA2-128s":  cryptopq.SLH_DSA_SHA2_128S,
	"SLH-DSA-SHA2-128f":  cryptopq.SLH_DSA_SHA2_128F,
	"SLH-DSA-SHA2-192s":  cryptopq.SLH_DSA_SHA2_192S,
	"SLH-DSA-SHA2-192f":  cryptopq.SLH_DSA_SHA2_192F,
	"SLH-DSA-SHA2-256s":  cryptopq.SLH_DSA_SHA2_256S,
	"SLH-DSA-SHA2-256f":  cryptopq.SLH_DSA_SHA2_256F,
	"SLH-DSA-SHAKE-128s": cryptopq.SLH_DSA_SHAKE_128S,
	"SLH-DSA-SHAKE-128f": cryptopq.SLH_DSA_SHAKE_128F,
	"SLH-DSA-SHAKE-192s": cryptopq.SLH_DSA_SHAKE_192S,
	"SLH-DSA-SHAKE-192f": cryptopq.SLH_DSA_SHAKE_192F,
	"SLH-DSA-SHAKE-256s": cryptopq.SLH_DSA_SHAKE_256S,
	"SLH-DSA-SHAKE-256f": cryptopq.SLH_DSA_SHAKE_256F,
}

func TestSlhDsaAcvpKeyGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/SLH-DSA-keyGen.txt", "sk") {
		t.Run(r.header["parameterSet"]+"/"+r.values["tcId"], func(t *testing.T) {
			t.Parallel()

			algorithm := slhAlgorithms[r.header["parameterSet"]]

			seed := bytes.Join([][]byte{decode(t, r.values["skSeed"]), decode(t, r.values["skPrf"]), decode(t, r.values["pkSeed"])}, nil)

			sk := decode(t, r.values["sk"])

			pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, seed)

			check(t, err)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), decode(t, r.values["pk"]), "public key")

			same(t, export(t, pair.PrivateKey, cryptopq.RAW), sk, "private key")

			imported, err := algorithm.ImportPrivateKey(sk, cryptopq.RAW)

			check(t, err)

			if !imported.PublicKey().Equal(pair.PublicKey) {
				t.Fatal("import")
			}

			corrupted := bytes.Clone(sk)

			corrupted[len(corrupted)-1] ^= 1

			_, err = algorithm.ImportPrivateKey(corrupted, cryptopq.RAW)

			expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)
		})
	}
}

func TestSlhDsaAcvpSignatureGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/SLH-DSA-sigGen.txt", "signature") {
		t.Run(r.header["parameterSet"]+"/"+r.values["tcId"], func(t *testing.T) {
			t.Parallel()

			algorithm := slhAlgorithms[r.header["parameterSet"]]

			sk := decode(t, r.values["sk"])

			privateKey, err := algorithm.ImportPrivateKey(sk, cryptopq.RAW)

			check(t, err)

			n := len(sk) / 4

			randomness := sk[2*n : 3*n]

			if r.header["deterministic"] != "true" {
				randomness = decode(t, r.values["additionalRandomness"])
			}

			options := &cryptopq.SignOptions{Context: decode(t, r.values["context"]), PreHash: recordPreHash(r)}

			signature, err := cryptopq.Hazmat.Sign(privateKey, decode(t, r.values["message"]), randomness, options)

			check(t, err)

			same(t, signature, decode(t, r.values["signature"]), "signature")
		})
	}
}

func TestSlhDsaAcvpSignatureVerification(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/SLH-DSA-sigVer.txt", "signature") {
		publicKey, err := slhAlgorithms[r.header["parameterSet"]].ImportPublicKey(decode(t, r.values["pk"]), cryptopq.RAW)

		check(t, err)

		options := &cryptopq.VerifyOptions{Context: decode(t, r.values["context"]), PreHash: recordPreHash(r)}

		result := cryptopq.Hazmat.Verify(publicKey, decode(t, r.values["signature"]), decode(t, r.values["message"]), options)

		if result != (r.values["testPassed"] == "true") {
			t.Fatalf("tcId %s (%s): got %v", r.values["tcId"], r.values["reason"], result)
		}
	}
}

func TestSlhDsaRoundTrip(t *testing.T) {
	t.Parallel()

	algorithm := cryptopq.SLH_DSA_SHAKE_128F

	pair, err := algorithm.GenerateKeyPair(&cryptopq.KeyGenOptions{SkipSelfTest: true})

	check(t, err)

	message := []byte("message")

	signature, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Context: []byte("context"), Deterministic: true})

	check(t, err)

	withContext := &cryptopq.VerifyOptions{Context: []byte("context")}

	if !pair.PublicKey.Verify(signature, message, withContext) {
		t.Fatal("verify")
	}

	if pair.PublicKey.Verify(signature, message, nil) || pair.PublicKey.Verify(signature[:len(signature)-1], message, withContext) {
		t.Fatal("accepted a wrong input")
	}

	for _, format := range []cryptopq.KeyFormat{cryptopq.RAW, cryptopq.DER, cryptopq.PEM} {
		public, err := algorithm.ImportPublicKey(export(t, pair.PublicKey, format), format)

		check(t, err)

		if !public.Equal(pair.PublicKey) {
			t.Fatalf("%s: public", format)
		}

		private, err := algorithm.ImportPrivateKey(export(t, pair.PrivateKey, format), format)

		check(t, err)

		same(t, export(t, private, cryptopq.RAW), export(t, pair.PrivateKey, cryptopq.RAW), string(format))
	}

	raw := export(t, pair.PrivateKey, cryptopq.RAW)

	if len(raw) != 64 {
		t.Fatalf("private key of %d bytes", len(raw))
	}

	_, err = pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: cryptopq.SHA_224})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	hashed, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{PreHash: cryptopq.SHAKE128})

	check(t, err)

	if !pair.PublicKey.Verify(hashed, message, &cryptopq.VerifyOptions{PreHash: cryptopq.SHAKE128}) {
		t.Fatal("pre-hash")
	}

	again, err := pair.PrivateKey.Sign(message, &cryptopq.SignOptions{Context: []byte("context"), Deterministic: true})

	check(t, err)

	same(t, again, signature, "deterministic")

	pkSeed := export(t, pair.PublicKey, cryptopq.RAW)[:16]

	expected, err := cryptopq.Hazmat.Sign(pair.PrivateKey, message, pkSeed, &cryptopq.SignOptions{Context: []byte("context")})

	check(t, err)

	same(t, signature, expected, "deterministic signing uses opt_rand = PK.seed")

	_, err = algorithm.ImportPrivateKey(raw[1:], cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_LENGTH)

	oid := der(0x06, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 27})

	_, err = algorithm.ImportPrivateKey(pkcs8(oid, raw[1:]), cryptopq.DER)

	expectCode(t, err, cryptopq.INVALID_ENCODING)

	_, err = cryptopq.SLH_DSA_SHAKE_128S.ImportPrivateKey(pkcs8(oid, raw), cryptopq.DER)

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)

	_, err = cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, make([]byte, 47))

	expectCode(t, err, cryptopq.INVALID_LENGTH)
}

// RFC 9909, Appendix C: an SLH-DSA-SHA2-128s private key in PKCS#8.
func TestRfc9909PrivateKey(t *testing.T) {
	t.Parallel()

	pem := "-----BEGIN PRIVATE KEY-----\n" +
		"MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N\n" +
		"HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU\n" +
		"-----END PRIVATE KEY-----\n"

	privateKey, err := cryptopq.SLH_DSA_SHA2_128S.ImportPrivateKey([]byte(pem), cryptopq.PEM)

	check(t, err)

	same(t, export(t, privateKey, cryptopq.PEM), []byte(pem), "PEM")
}
