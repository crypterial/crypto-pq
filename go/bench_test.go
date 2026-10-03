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

func benchmarkHashes(b *testing.B) {
	data := sequence(1024)

	cases := []struct {
		name   string
		digest func() []byte
	}{
		{"sha-256/64B", func() []byte { return cryptopq.SHA_256.Digest(data[:64]) }},
		{"sha-256/1KiB", func() []byte { return cryptopq.SHA_256.Digest(data) }},
		{"sha-512/1KiB", func() []byte { return cryptopq.SHA_512.Digest(data) }},
		{"sha3-256/1KiB", func() []byte { return cryptopq.SHA3_256.Digest(data) }},
		{"shake128/1KiB", func() []byte { return cryptopq.SHAKE128.Digest(data, 32) }},
		{"shake256/1KiB", func() []byte { return cryptopq.SHAKE256.Digest(data, 64) }},
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
