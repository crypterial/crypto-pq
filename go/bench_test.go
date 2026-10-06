package cryptopq_test

import (
	"strconv"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

// The case names are shared with the benchmark harnesses of the other implementations. Keys
// come from fixed seeds and signing is deterministic, so that every run does the same work;
// signing rotates through benchMessages because the work varies from message to message.
var benchMessages = func() (messages [16][]byte) {
	for i := range messages {
		messages[i] = []byte("crypto-pq benchmark message " + strconv.Itoa(i))
	}

	return messages
}()

var kemCases = []struct {
	algorithm                cryptopq.KemAlgorithm
	seedSize, randomnessSize int
}{
	{cryptopq.ML_KEM_512, 64, 32},
	{cryptopq.ML_KEM_768, 64, 32},
	{cryptopq.ML_KEM_1024, 64, 32},
	{cryptopq.X_WING, 32, 64},
}

type statefulCase struct {
	name      string
	algorithm cryptopq.StatefulSignatureAlgorithm
	options   cryptopq.StatefulKeyGenOptions
	seedSize  int
}

var statefulCases = []statefulCase{
	{"HSS-H10-W4", cryptopq.HSS_LMS, cryptopq.StatefulKeyGenOptions{Levels: []cryptopq.HssLevel{{"LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4"}}}, 48},
	{"HSS-H5H5-W8", cryptopq.HSS_LMS, cryptopq.StatefulKeyGenOptions{Levels: []cryptopq.HssLevel{{"LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"}, {"LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"}}}, 48},
	{"XMSS-SHA2_10_256", cryptopq.XMSS, cryptopq.StatefulKeyGenOptions{Parameters: "XMSS-SHA2_10_256"}, 96},
	{"XMSSMT-SHA2_20/4_256", cryptopq.XMSS_MT, cryptopq.StatefulKeyGenOptions{Parameters: "XMSSMT-SHA2_20/4_256"}, 96},
}

func BenchmarkPQ(b *testing.B) {
	benchmarkHashes(b)

	for _, c := range kemCases {
		b.Run(c.algorithm.Name(), func(b *testing.B) {
			benchmarkKem(b, c.algorithm, c.seedSize, c.randomnessSize)
		})
	}

	for algorithm := cryptopq.ML_DSA_44; algorithm <= cryptopq.SLH_DSA_SHAKE_256F; algorithm++ {
		b.Run(algorithm.Name(), func(b *testing.B) {
			benchmarkSignature(b, algorithm)
		})
	}

	for _, c := range statefulCases {
		b.Run(c.name, func(b *testing.B) {
			benchmarkStateful(b, &c)
		})
	}
}

type hashCase struct {
	name   string
	digest func()
}

func benchmarkHashes(b *testing.B) {
	data, key := sequence(1024), sequence(32)

	var out [128]byte

	cases := []hashCase{
		{"sha-256/64B", func() { cryptopq.SHA_256.DigestInto(data[:64], out[:32]) }},
		{"sha-256/1KiB", func() { cryptopq.SHA_256.DigestInto(data, out[:32]) }},
		{"sha-512/1KiB", func() { cryptopq.SHA_512.DigestInto(data, out[:64]) }},
		{"sha3-256/1KiB", func() { cryptopq.SHA3_256.DigestInto(data, out[:32]) }},
		{"shake128/1KiB", func() { cryptopq.SHAKE128.DigestInto(data, out[:32]) }},
		{"shake256/1KiB", func() { cryptopq.SHAKE256.DigestInto(data, out[:64]) }},
	}

	customization := []byte("crypto-pq benchmark")

	cshake128 := must(cryptopq.CSHAKE128.Configure(&cryptopq.XofOptions{Customization: customization}))

	cshake256 := must(cryptopq.CSHAKE256.Configure(&cryptopq.XofOptions{Customization: customization}))

	cxof := must(cryptopq.ASCON_CXOF128.Configure(&cryptopq.XofOptions{Customization: customization}))

	kmac128 := must(cryptopq.KMAC128.Configure(&cryptopq.MacOptions{Customization: customization}))

	kmac256 := must(cryptopq.KMAC256.Configure(&cryptopq.MacOptions{Customization: customization}))

	for _, size := range []struct {
		length int
		suffix string
	}{{64, "64B"}, {1024, "1KiB"}} {
		d := data[:size.length]

		cases = append(cases, []hashCase{
			{"blake2b-512/" + size.suffix, func() { cryptopq.BLAKE2B_512.DigestInto(d, out[:64]) }},
			{"blake2b-256/" + size.suffix, func() { cryptopq.BLAKE2B_256.DigestInto(d, out[:32]) }},
			{"blake2b-384/" + size.suffix, func() { cryptopq.BLAKE2B_384.DigestInto(d, out[:48]) }},
			{"blake2b-160/" + size.suffix, func() { cryptopq.BLAKE2B_160.DigestInto(d, out[:20]) }},
			{"blake2s-256/" + size.suffix, func() { cryptopq.BLAKE2S_256.DigestInto(d, out[:32]) }},
			{"blake2s-224/" + size.suffix, func() { cryptopq.BLAKE2S_224.DigestInto(d, out[:28]) }},
			{"blake2s-160/" + size.suffix, func() { cryptopq.BLAKE2S_160.DigestInto(d, out[:20]) }},
			{"blake2s-128/" + size.suffix, func() { cryptopq.BLAKE2S_128.DigestInto(d, out[:16]) }},
			{"blake2b-mac/" + size.suffix, func() { cryptopq.BLAKE2B_MAC.DigestInto(key, d, out[:64]) }},
			{"blake2s-mac/" + size.suffix, func() { cryptopq.BLAKE2S_MAC.DigestInto(key, d, out[:32]) }},
			{"ascon-hash256/" + size.suffix, func() { cryptopq.ASCON_HASH256.DigestInto(d, out[:32]) }},
			{"ascon-xof128/" + size.suffix, func() { cryptopq.ASCON_XOF128.DigestInto(d, out[:32]) }},
			{"ascon-cxof128/" + size.suffix, func() { cxof.DigestInto(d, out[:32]) }},
			{"cshake128/" + size.suffix, func() { cshake128.DigestInto(d, out[:32]) }},
			{"cshake256/" + size.suffix, func() { cshake256.DigestInto(d, out[:64]) }},
			{"kmac128/" + size.suffix, func() { kmac128.DigestInto(key, d, out[:32]) }},
			{"kmac256/" + size.suffix, func() { kmac256.DigestInto(key, d, out[:64]) }},
		}...)
	}

	options := &cryptopq.KdfOptions{Salt: sequence(32), Info: []byte("crypto-pq benchmark info")}

	for _, length := range []int{32, 64, 128} {
		suffix := strconv.Itoa(length) + "B"

		cases = append(cases, []hashCase{
			{"hkdf-sha-256/" + suffix, func() { _ = cryptopq.HKDF_SHA_256.DeriveInto(key, out[:length], options) }},
			{"hkdf-sha-384/" + suffix, func() { _ = cryptopq.HKDF_SHA_384.DeriveInto(key, out[:length], options) }},
			{"hkdf-sha-512/" + suffix, func() { _ = cryptopq.HKDF_SHA_512.DeriveInto(key, out[:length], options) }},
		}...)
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				c.digest()
			}
		})
	}
}

func benchmarkKem(b *testing.B, algorithm cryptopq.KemAlgorithm, seedSize, randomnessSize int) {
	seed, randomness := sequence(seedSize), sequence(randomnessSize)

	b.Run("keygen", func(b *testing.B) {
		for b.Loop() {
			if _, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed); err != nil {
				b.Fatal(err)
			}
		}
	})

	pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

	if err != nil {
		b.Fatal(err)
	}

	b.Run("encaps", func(b *testing.B) {
		for b.Loop() {
			if _, err := cryptopq.Hazmat.Encapsulate(pair.PublicKey, randomness); err != nil {
				b.Fatal(err)
			}
		}
	})

	encapsulation, err := cryptopq.Hazmat.Encapsulate(pair.PublicKey, randomness)

	if err != nil {
		b.Fatal(err)
	}

	b.Run("decaps", func(b *testing.B) {
		for b.Loop() {
			if _, err := pair.PrivateKey.Decapsulate(encapsulation.Ciphertext); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// ML-DSA takes a 32-byte seed and SLH-DSA SK.seed || SK.prf || PK.seed, 1.5 public keys long.
func generateSignatureKey(tb testing.TB, algorithm cryptopq.SignatureAlgorithm) *cryptopq.SignatureKeyPair {
	size := 32

	if algorithm >= cryptopq.SLH_DSA_SHA2_128S {
		size = 3 * algorithm.PublicKeySize() / 2
	}

	pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, sequence(size))

	if err != nil {
		tb.Fatal(err)
	}

	return pair
}

func benchmarkSignature(b *testing.B, algorithm cryptopq.SignatureAlgorithm) {
	deterministic := &cryptopq.SignOptions{Deterministic: true}

	b.Run("keygen", func(b *testing.B) {
		for b.Loop() {
			generateSignatureKey(b, algorithm)
		}
	})

	b.Run("sign", func(b *testing.B) {
		pair := generateSignatureKey(b, algorithm)

		i := 0

		for b.Loop() {
			if _, err := pair.PrivateKey.Sign(benchMessages[i%len(benchMessages)], deterministic); err != nil {
				b.Fatal(err)
			}

			i++
		}
	})

	b.Run("verify", func(b *testing.B) {
		pair := generateSignatureKey(b, algorithm)

		var signatures [len(benchMessages)][]byte

		for j := range signatures {
			signature, err := pair.PrivateKey.Sign(benchMessages[j], deterministic)

			if err != nil {
				b.Fatal(err)
			}

			signatures[j] = signature
		}

		i := 0

		for b.Loop() {
			if !pair.PublicKey.Verify(signatures[i%len(signatures)], benchMessages[i%len(signatures)], nil) {
				b.Fatal("a valid signature did not verify")
			}

			i++
		}
	})
}

func (c *statefulCase) generate(tb testing.TB) *cryptopq.StatefulKeyPair {
	options := c.options

	options.StateStore = &memoryStore{}

	pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(c.algorithm, &options, sequence(c.seedSize), 0)

	if err != nil {
		tb.Fatal(err)
	}

	return pair
}

// A key that runs out of signatures is replaced outside the timed region.
func benchmarkStateful(b *testing.B, c *statefulCase) {
	b.Run("keygen", func(b *testing.B) {
		for b.Loop() {
			c.generate(b)
		}
	})

	b.Run("sign", func(b *testing.B) {
		pair := c.generate(b)

		i := 0

		for b.Loop() {
			if pair.PrivateKey.RemainingSignatures() == 0 {
				b.StopTimer()

				pair = c.generate(b)

				b.StartTimer()
			}

			if _, err := pair.PrivateKey.Sign(benchMessages[i%len(benchMessages)]); err != nil {
				b.Fatal(err)
			}

			i++
		}
	})

	b.Run("verify", func(b *testing.B) {
		pair := c.generate(b)

		var signatures [len(benchMessages)][]byte

		for j := range signatures {
			signature, err := pair.PrivateKey.Sign(benchMessages[j])

			if err != nil {
				b.Fatal(err)
			}

			signatures[j] = signature
		}

		i := 0

		for b.Loop() {
			if !pair.PublicKey.Verify(signatures[i%len(signatures)], benchMessages[i%len(signatures)]) {
				b.Fatal("a valid signature did not verify")
			}

			i++
		}
	})
}
