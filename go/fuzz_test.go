package cryptopq

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"runtime/metrics"
	"slices"
	"sync"
	"testing"
	"time"
)

// Native fuzz targets for every path that parses untrusted input. Plain `go test` replays the
// seeds and testdata/fuzz; `go test -fuzz=FuzzName` explores. Besides panics, a target fails when
// an input gets an error code the operation does not define, when an accepted input does not
// round-trip, and when a call allocates far more memory than its input or hangs.

var fuzzFormats = [...]KeyFormat{RAW, DER, PEM, "jwk"}

func fuzzFormat(format uint8) KeyFormat {
	return fuzzFormats[int(format)%len(fuzzFormats)]
}

func fuzzPattern(size int, first byte) []byte {
	out := make([]byte, size)

	for i := range out {
		out[i] = first + byte(i)
	}

	return out
}

// Pads or cuts data to exactly size bytes, so that fixed-size formats get past their length check.
func fuzzResize(data []byte, size int) []byte {
	out := make([]byte, size)

	copy(out, data)

	return out
}

func fuzzExpect(t *testing.T, err error, codes ...ErrorCode) {
	t.Helper()

	var failure *Error

	if !errors.As(err, &failure) {
		t.Fatalf("unexpected error %v", err)
	}

	if !slices.Contains(codes, failure.Code) {
		t.Fatalf("unexpected error %v, want one of %v", err, codes)
	}
}

func fuzzCheck(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func fuzzing() bool {
	value := flag.Lookup("test.fuzz")

	return value != nil && value.Value.String() != ""
}

// Runs one call and fails when it allocates far more than its input, which would mean that a
// size read from the input was trusted before it was checked, or when it takes so long that it
// has to be a hang (only while fuzzing, where nothing else shares the process).
func fuzzBounded(t *testing.T, size int, run func()) {
	t.Helper()

	samples := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}

	metrics.Read(samples)

	before := samples[0].Value.Uint64()

	start := time.Now()

	run()

	elapsed := time.Since(start)

	metrics.Read(samples)

	if allocated, limit := samples[0].Value.Uint64()-before, uint64(64<<20)+64*uint64(size); allocated > limit {
		t.Fatalf("allocated %d bytes for %d bytes of input", allocated, size)
	}

	if fuzzing() && elapsed > 30*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

type fuzzExporter interface {
	ExportKey(KeyFormat) ([]byte, error)
}

// An accepted key exports to the encoding it came from: byte for byte in raw and DER, which are
// canonical, and to the same DER inside PEM, which allows any whitespace.
func fuzzSameEncoding(t *testing.T, key fuzzExporter, data []byte, format KeyFormat, label string) {
	t.Helper()

	exported, err := key.ExportKey(format)

	fuzzCheck(t, err)

	original, again := data, exported

	if format == PEM {
		original, err = pemDecode(label, data)

		fuzzCheck(t, err)

		again, err = pemDecode(label, exported)

		fuzzCheck(t, err)
	}

	if !bytes.Equal(original, again) {
		t.Fatalf("exported %x instead of the imported encoding", exported)
	}
}

// Exporting a key and importing the export again gives a key with the same exports.
func fuzzStableExports[K fuzzExporter](t *testing.T, key K, load func([]byte, KeyFormat) (K, error)) {
	t.Helper()

	for _, format := range fuzzFormats[:3] {
		exported, err := key.ExportKey(format)

		if err != nil {
			fuzzExpect(t, err, UNSUPPORTED)

			continue
		}

		again, err := load(exported, format)

		fuzzCheck(t, err)

		for _, other := range fuzzFormats[:3] {
			first, errFirst := key.ExportKey(other)

			second, errSecond := again.ExportKey(other)

			if (errFirst == nil) != (errSecond == nil) || !bytes.Equal(first, second) {
				t.Fatalf("%s export changed after a round trip through %s", other, format)
			}
		}
	}
}

type fuzzKem struct {
	algorithm  KemAlgorithm
	pair       *KemKeyPair
	ciphertext []byte
	secret     []byte
}

var fuzzKems = sync.OnceValue(func() []fuzzKem {
	var out []fuzzKem

	for algorithm := ML_KEM_512; algorithm <= X_WING; algorithm++ {
		spec := algorithm.spec()

		pair, err := Hazmat.GenerateKemKeyPair(algorithm, fuzzPattern(spec.seedSize, 0))

		if err != nil {
			panic(err)
		}

		encapsulation, err := Hazmat.Encapsulate(pair.PublicKey, fuzzPattern(spec.randomnessSize, 0x80))

		if err != nil {
			panic(err)
		}

		out = append(out, fuzzKem{algorithm, pair, encapsulation.Ciphertext, encapsulation.SharedSecret})
	}

	return out
})

func fuzzKemCodes(format KeyFormat, algorithm KemAlgorithm, check ErrorCode) []ErrorCode {
	switch {
	case format != RAW && format != DER && format != PEM:
		return []ErrorCode{INVALID_OPTION}
	case format == RAW:
		return []ErrorCode{INVALID_LENGTH, check}
	case algorithm == X_WING:
		return []ErrorCode{UNSUPPORTED}
	default:
		return []ErrorCode{INVALID_ENCODING, ALGORITHM_MISMATCH, check}
	}
}

func FuzzKemImport(f *testing.F) {
	for i, fixture := range fuzzKems() {
		for format := range 3 {
			public, err := fixture.pair.PublicKey.ExportKey(fuzzFormats[format])

			if err == nil {
				f.Add(public, uint8(i), uint8(format), false)
			}

			private, err := fixture.pair.PrivateKey.ExportKey(fuzzFormats[format])

			if err == nil {
				f.Add(private, uint8(i), uint8(format), true)
			}
		}

		spec := fixture.algorithm.spec()

		if spec.params == nil {
			continue
		}

		seed, dk := fixture.pair.PrivateKey.seed, fixture.pair.PrivateKey.dk

		f.Add(dk, uint8(i), uint8(0), true)

		// FIPS 203 does not check the secret vector of an expanded key against its public part.
		tampered := bytes.Clone(dk)

		tampered[0] ^= 1

		f.Add(tampered, uint8(i), uint8(0), true)

		f.Add(encodePrivateKey(spec.oid, derElement(tagOctetString, dk)), uint8(i), uint8(1), true)

		both := derElement(tagSequence, derElement(tagOctetString, seed), derElement(tagOctetString, dk))

		f.Add(encodePrivateKey(spec.oid, both), uint8(i), uint8(1), true)

		v1 := derElement(tagSequence, derElement(tagInteger, []byte{1}), algorithmIdentifier(spec.oid), derElement(tagOctetString, derElement(tagContext0, seed)), derElement(tagContext1, []byte{0}, fixture.pair.PublicKey.key))

		f.Add(v1, uint8(i), uint8(1), true)
	}

	f.Fuzz(func(t *testing.T, data []byte, selector, format uint8, private bool) {
		fixtures := fuzzKems()

		fixture := fixtures[int(selector)%len(fixtures)]

		keyFormat := fuzzFormat(format)

		fuzzBounded(t, len(data), func() {
			if private {
				fuzzKemPrivate(t, fixture, data, keyFormat)
			} else {
				fuzzKemPublic(t, fixture, data, keyFormat)
			}
		})
	})
}

func fuzzKemPublic(t *testing.T, fixture fuzzKem, data []byte, format KeyFormat) {
	key, err := fixture.algorithm.ImportPublicKey(data, format)

	if err != nil {
		fuzzExpect(t, err, fuzzKemCodes(format, fixture.algorithm, INVALID_PUBLIC_KEY)...)

		return
	}

	fuzzSameEncoding(t, key, data, format, pemPublic)

	fuzzStableExports(t, key, fixture.algorithm.ImportPublicKey)

	encapsulation, err := Hazmat.Encapsulate(key, fuzzPattern(fixture.algorithm.spec().randomnessSize, 0x40))

	fuzzCheck(t, err)

	if len(encapsulation.Ciphertext) != fixture.algorithm.CiphertextSize() || len(encapsulation.SharedSecret) != 32 {
		t.Fatal("encapsulation sizes")
	}
}

func fuzzKemPrivate(t *testing.T, fixture fuzzKem, data []byte, format KeyFormat) {
	key, err := fixture.algorithm.ImportPrivateKey(data, format)

	if err != nil {
		fuzzExpect(t, err, fuzzKemCodes(format, fixture.algorithm, INVALID_PRIVATE_KEY)...)

		return
	}

	if format == RAW {
		fuzzSameEncoding(t, key, data, format, pemPrivate)
	}

	fuzzStableExports(t, key, fixture.algorithm.ImportPrivateKey)

	// A key from a seed decapsulates what its public key encapsulates. FIPS 203 checks only the
	// hash of the public part of an expanded key, so one with another secret vector is accepted
	// and gives the implicit rejection, SHAKE256(z || c).
	encapsulation, err := Hazmat.Encapsulate(key.PublicKey(), fuzzPattern(fixture.algorithm.spec().randomnessSize, 0x40))

	fuzzCheck(t, err)

	secret, err := key.Decapsulate(encapsulation.Ciphertext)

	fuzzCheck(t, err)

	if bytes.Equal(secret, encapsulation.SharedSecret) {
		return
	}

	if key.seed != nil || !bytes.Equal(secret, SHAKE256.Digest(append(bytes.Clone(key.dk[len(key.dk)-32:]), encapsulation.Ciphertext...), 32)) {
		t.Fatal("an imported private key decapsulates to neither the secret nor the implicit rejection")
	}
}

func FuzzDecapsulate(f *testing.F) {
	for i, fixture := range fuzzKems() {
		f.Add(fixture.ciphertext, uint8(i), uint8(0))

		f.Add(fixture.ciphertext[1:], uint8(i), uint8(1))

		f.Add([]byte{}, uint8(i), uint8(0))
	}

	f.Fuzz(func(t *testing.T, ciphertext []byte, selector, mode uint8) {
		fixtures := fuzzKems()

		fixture := fixtures[int(selector)%len(fixtures)]

		if mode&1 == 1 {
			ciphertext = fuzzResize(ciphertext, fixture.algorithm.CiphertextSize())
		}

		fuzzBounded(t, len(ciphertext), func() {
			secret, err := fixture.pair.PrivateKey.Decapsulate(ciphertext)

			if len(ciphertext) != fixture.algorithm.CiphertextSize() {
				fuzzExpect(t, err, INVALID_LENGTH)

				return
			}

			fuzzCheck(t, err)

			// Implicit rejection: any other ciphertext gives a different, pseudorandom secret.
			if len(secret) != 32 || bytes.Equal(secret, fixture.secret) != bytes.Equal(ciphertext, fixture.ciphertext) {
				t.Fatalf("decapsulation gave %x", secret)
			}
		})
	})
}

type fuzzSignature struct {
	algorithm SignatureAlgorithm
	public    *SignaturePublicKey
	private   *SignaturePrivateKey
	message   []byte
	context   []byte
	signature []byte
}

// Real keys and signatures where they are cheap to make; the slow SLH-DSA sets get a public key
// of the right size, which is all that verification checks, and an all-zero signature.
var fuzzSignatures = sync.OnceValue(func() []fuzzSignature {
	var out []fuzzSignature

	for algorithm := ML_DSA_44; algorithm <= SLH_DSA_SHAKE_256F; algorithm++ {
		spec := algorithm.spec()

		fixture := fuzzSignature{algorithm: algorithm, message: []byte("crypto-pq fuzz"), context: []byte("context")}

		if spec.slh != nil && spec.slh.d < 10 {
			fixture.public = &SignaturePublicKey{algorithm: algorithm, key: fuzzPattern(spec.publicKeySize, 0x20)}

			fixture.signature = make([]byte, spec.signatureSize)

			out = append(out, fixture)

			continue
		}

		pair, err := Hazmat.GenerateSignatureKeyPair(algorithm, fuzzPattern(spec.seedSize, 0))

		if err != nil {
			panic(err)
		}

		fixture.public, fixture.private = pair.PublicKey, pair.PrivateKey

		fixture.signature, err = Hazmat.Sign(pair.PrivateKey, fixture.message, fuzzPattern(spec.randomnessSize, 0x60), &SignOptions{Context: fixture.context})

		if err != nil {
			panic(err)
		}

		out = append(out, fixture)
	}

	return out
})

func fuzzSignatureCodes(format KeyFormat, check ErrorCode) []ErrorCode {
	switch {
	case format != RAW && format != DER && format != PEM:
		return []ErrorCode{INVALID_OPTION}
	case format == RAW:
		return []ErrorCode{INVALID_LENGTH, check}
	default:
		return []ErrorCode{INVALID_ENCODING, ALGORITHM_MISMATCH, check}
	}
}

func FuzzSignatureImport(f *testing.F) {
	for i, fixture := range fuzzSignatures() {
		for format := range 3 {
			public, err := fixture.public.ExportKey(fuzzFormats[format])

			fuzzPanic(err)

			f.Add(public, uint8(i), uint8(format), false)

			if fixture.private == nil {
				continue
			}

			private, err := fixture.private.ExportKey(fuzzFormats[format])

			fuzzPanic(err)

			f.Add(private, uint8(i), uint8(format), true)
		}

		if spec := fixture.algorithm.spec(); spec.mldsa != nil {
			seed, expanded := fixture.private.seed, fixture.private.private

			f.Add(expanded, uint8(i), uint8(0), true)

			both := derElement(tagSequence, derElement(tagOctetString, seed), derElement(tagOctetString, expanded))

			f.Add(encodePrivateKey(spec.oid, both), uint8(i), uint8(1), true)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte, selector, format uint8, private bool) {
		fixtures := fuzzSignatures()

		algorithm := fixtures[int(selector)%len(fixtures)].algorithm

		keyFormat := fuzzFormat(format)

		fuzzBounded(t, len(data), func() {
			if private {
				fuzzSignaturePrivate(t, algorithm, data, keyFormat)
			} else {
				fuzzSignaturePublic(t, algorithm, data, keyFormat)
			}
		})
	})
}

func fuzzPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func fuzzSignaturePublic(t *testing.T, algorithm SignatureAlgorithm, data []byte, format KeyFormat) {
	key, err := algorithm.ImportPublicKey(data, format)

	if err != nil {
		fuzzExpect(t, err, fuzzSignatureCodes(format, INVALID_LENGTH)...)

		return
	}

	fuzzSameEncoding(t, key, data, format, pemPublic)

	fuzzStableExports(t, key, algorithm.ImportPublicKey)

	if key.Verify(make([]byte, algorithm.SignatureSize()), nil, nil) {
		t.Fatal("an all-zero signature verified")
	}
}

func fuzzSignaturePrivate(t *testing.T, algorithm SignatureAlgorithm, data []byte, format KeyFormat) {
	key, err := algorithm.ImportPrivateKey(data, format)

	if err != nil {
		fuzzExpect(t, err, fuzzSignatureCodes(format, INVALID_PRIVATE_KEY)...)

		return
	}

	if format == RAW {
		fuzzSameEncoding(t, key, data, format, pemPrivate)
	}

	fuzzStableExports(t, key, algorithm.ImportPrivateKey)

	spec := algorithm.spec()

	if spec.slh != nil {
		if !bytes.Equal(key.public, key.private[2*spec.slh.n:]) {
			t.Fatal("the SLH-DSA public key is not the end of the private key")
		}

		return
	}

	// Every ML-DSA key that import accepts must sign verifiably.
	message := []byte("accepted key")

	signature, err := Hazmat.Sign(key, message, make([]byte, 32), nil)

	fuzzCheck(t, err)

	if !key.PublicKey().Verify(signature, message, nil) {
		t.Fatal("an imported private key made a signature that does not verify")
	}
}

// The pre-hash choices of a fuzz input: none, every hash and XOF, and an invalid value.
func fuzzPreHash(selector uint8) PreHash {
	switch value := int(selector) % 14; {
	case value == 0:
		return nil
	case value <= 10:
		return HashAlgorithm(value)
	case value <= 12:
		return XofAlgorithm(value - 10)
	default:
		return HashAlgorithm(200)
	}
}

func FuzzVerify(f *testing.F) {
	for i, fixture := range fuzzSignatures() {
		f.Add(fixture.signature, fixture.message, fixture.context, uint8(i), uint8(0), uint8(0))

		f.Add(fixture.signature, fixture.message, fixture.context, uint8(i), uint8(3), uint8(2))

		f.Add(fixture.signature[:len(fixture.signature)/2], fixture.message, []byte{}, uint8(i), uint8(11), uint8(1))
	}

	f.Fuzz(func(t *testing.T, signature, message, context []byte, selector, preHash, mode uint8) {
		fixtures := fuzzSignatures()

		fixture := fixtures[int(selector)%len(fixtures)]

		spec := fixture.algorithm.spec()

		if mode&1 == 1 {
			signature = fuzzResize(signature, spec.signatureSize)
		}

		policy := mode&2 == 0

		choice := fuzzPreHash(preHash)

		fuzzBounded(t, len(signature)+len(message)+len(context), func() {
			valid := fixture.public.verify(signature, message, context, choice, policy)

			entry, err := preHashOf(choice)

			weak := err == nil && policy && entry != nil && entry.strength < spec.strength

			if valid && (err != nil || weak || len(context) > 255 || len(signature) != spec.signatureSize) {
				t.Fatal("verification accepted an input it must refuse")
			}

			if valid && fixture.private == nil {
				t.Fatal("a signature verified under a key nobody holds")
			}
		})
	})
}

type fuzzStore struct {
	state []byte
}

func (s *fuzzStore) Read() ([]byte, error) {
	return bytes.Clone(s.state), nil
}

func (s *fuzzStore) Update(previous, next []byte) (bool, error) {
	if (previous == nil) != (s.state == nil) || !bytes.Equal(previous, s.state) {
		return false, nil
	}

	s.state = bytes.Clone(next)

	return true, nil
}

func fuzzSeal(body []byte) []byte {
	return append(bytes.Clone(body), SHA_256.Digest(body)[:16]...)
}

// The hash calls needed to build every tree on the signing path of a key, to keep the
// expensive parameter sets out of the fuzz loop.
func fuzzStatefulCost(parameters statefulParameters) int {
	if p := parameters.xmss; p != nil {
		if p.treeHeight() > 10 {
			return 1 << 30
		}

		return p.d << p.treeHeight() * p.wotsLength() * 16
	}

	total := 0

	for _, level := range parameters.levels {
		if level.lms.h > 10 {
			return 1 << 30
		}

		total += 1 << level.lms.h * level.ots.p << level.ots.w
	}

	return total
}

var fuzzStatefulAlgorithms = [...]StatefulSignatureAlgorithm{HSS_LMS, XMSS, XMSS_MT}

func FuzzLoadPrivateKey(f *testing.F) {
	levels := []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}, {"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"}}

	for i, options := range []StatefulKeyGenOptions{{Levels: levels[:1]}, {Levels: levels}, {Parameters: "XMSS-SHA2_10_256"}, {Parameters: "XMSSMT-SHAKE256_20/4_192"}} {
		algorithm := [...]StatefulSignatureAlgorithm{HSS_LMS, HSS_LMS, XMSS, XMSS_MT}[i]

		parameters, err := algorithm.parameters(&options)

		fuzzPanic(err)

		state := algorithm.encode(parameters, fuzzPattern(parameters.seedSize(), 0), 3)

		f.Add(state, uint8(algorithm-1), uint8(0))

		f.Add(state[:len(state)-16], uint8(algorithm-1), uint8(1))

		f.Add(state[:len(state)-16], uint8(algorithm), uint8(1))
	}

	// Level counts that the body cannot hold, or that HSS does not allow.
	f.Add([]byte{1, 1, 255}, uint8(0), uint8(1))

	f.Add(append([]byte{1, 1, 9}, make([]byte, 72+24+16+8)...), uint8(0), uint8(1))

	f.Fuzz(func(t *testing.T, body []byte, selector, mode uint8) {
		algorithm := fuzzStatefulAlgorithms[int(selector)%len(fuzzStatefulAlgorithms)]

		state := body

		if mode&1 == 1 {
			state = fuzzSeal(body)
		}

		fuzzBounded(t, len(state), func() {
			fuzzLoad(t, algorithm, state)
		})
	})
}

func fuzzLoad(t *testing.T, algorithm StatefulSignatureAlgorithm, state []byte) {
	parameters, seed, index, err := algorithm.decode(state)

	if err != nil {
		fuzzExpect(t, err, INVALID_PRIVATE_KEY, ALGORITHM_MISMATCH)

		_, err = algorithm.LoadPrivateKey(&fuzzStore{state: state}, nil)

		fuzzExpect(t, err, INVALID_PRIVATE_KEY, ALGORITHM_MISMATCH)

		return
	}

	// The state format is canonical: signing compares the stored bytes with a fresh encoding.
	if !bytes.Equal(algorithm.encode(parameters, seed, index), state) {
		t.Fatal("an accepted state does not encode back to itself")
	}

	capacity := parameters.capacity()

	if index > capacity {
		_, err = algorithm.LoadPrivateKey(&fuzzStore{state: state}, nil)

		fuzzExpect(t, err, INVALID_PRIVATE_KEY)

		return
	}

	if fuzzStatefulCost(parameters) > 1<<18 {
		return
	}

	store := &fuzzStore{state: state}

	key, err := algorithm.LoadPrivateKey(store, nil)

	fuzzCheck(t, err)

	if key.RemainingSignatures() != capacity-index {
		t.Fatal("remaining signatures")
	}

	signature, err := key.Sign(state)

	if index == capacity {
		fuzzExpect(t, err, KEY_EXHAUSTED)

		return
	}

	fuzzCheck(t, err)

	if !bytes.Equal(store.state, algorithm.encode(parameters, seed, index+1)) || !key.PublicKey().Verify(signature, state) {
		t.Fatal("signing with a loaded key")
	}
}

func FuzzStatefulVerify(f *testing.F) {
	store := &fuzzStore{}

	hss, err := Hazmat.GenerateStatefulKeyPair(HSS_LMS, &StatefulKeyGenOptions{Levels: []HssLevel{{"LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"}, {"LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1"}}, StateStore: store}, fuzzPattern(40, 0), 33)

	fuzzPanic(err)

	store = &fuzzStore{}

	mt, err := Hazmat.GenerateStatefulKeyPair(XMSS_MT, &StatefulKeyGenOptions{Parameters: "XMSSMT-SHA2_20/4_192", StateStore: store}, fuzzPattern(72, 0), 7)

	fuzzPanic(err)

	message := []byte("crypto-pq fuzz")

	for _, pair := range []*StatefulKeyPair{hss, mt} {
		signature, err := pair.PrivateKey.Sign(message)

		fuzzPanic(err)

		f.Add(pair.PublicKey.key, signature, message, uint8(pair.PublicKey.algorithm-1), uint16(len(signature)))
	}

	// Public keys of the other XMSS sets with all-zero signatures of the right size.
	for i, sets := range [][]xmssParams{xmssSets, xmssMtSets} {
		for _, p := range sets {
			key := binary.BigEndian.AppendUint32(nil, p.oid)

			f.Add(append(key, fuzzPattern(2*p.n, 9)...), make([]byte, p.signatureSize()), message, uint8(1+i), uint16(p.signatureSize()))
		}
	}

	// cut truncates the signature: the byte mutations of the fuzzer rarely remove long tails, and
	// HSS signatures have fields at every depth.
	f.Fuzz(func(t *testing.T, publicKey, signature, message []byte, selector uint8, cut uint16) {
		algorithm := fuzzStatefulAlgorithms[int(selector)%len(fuzzStatefulAlgorithms)]

		signature = signature[:min(len(signature), int(cut))]

		fuzzBounded(t, len(publicKey)+len(signature)+len(message), func() {
			key, err := algorithm.ImportPublicKey(publicKey, RAW)

			if err != nil {
				fuzzExpect(t, err, INVALID_PUBLIC_KEY)

				return
			}

			key.Verify(signature, message)
		})
	})
}

func FuzzStatefulImport(f *testing.F) {
	keys := [][]byte{
		append([]byte{0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 5}, fuzzPattern(40, 0)...),
		append([]byte{0, 0, 0, 8, 0, 0, 0, 0x14, 0, 0, 0, 0x10}, fuzzPattern(40, 0)...),
		append([]byte{0, 0, 0, 1}, fuzzPattern(64, 0)...),
		append([]byte{0, 0, 0, 0x31}, fuzzPattern(48, 0)...),
	}

	for i, key := range keys {
		selector := [...]uint8{0, 0, 1, 2}[i]

		oid := statefulSpecs[selector+1].oid

		f.Add(key, selector, uint8(0))

		f.Add(encodePublicKey(oid, key), selector, uint8(1))

		f.Add(pemEncode(pemPublic, encodePublicKey(oid, key)), selector, uint8(2))
	}

	f.Fuzz(func(t *testing.T, data []byte, selector, format uint8) {
		algorithm := fuzzStatefulAlgorithms[int(selector)%len(fuzzStatefulAlgorithms)]

		keyFormat := fuzzFormat(format)

		fuzzBounded(t, len(data), func() {
			key, err := algorithm.ImportPublicKey(data, keyFormat)

			if err != nil {
				switch keyFormat {
				case RAW:
					fuzzExpect(t, err, INVALID_PUBLIC_KEY)
				case DER, PEM:
					fuzzExpect(t, err, INVALID_ENCODING, ALGORITHM_MISMATCH, INVALID_PUBLIC_KEY)
				default:
					fuzzExpect(t, err, INVALID_OPTION)
				}

				return
			}

			fuzzSameEncoding(t, key, data, keyFormat, pemPublic)

			fuzzStableExports(t, key, algorithm.ImportPublicKey)

			key.Verify(make([]byte, 64), nil)
		})
	})
}

// An independent reading of one DER element under the rules of derReader (single-byte tags,
// definite lengths of at most four bytes in the shortest form), for differential checks.
func fuzzElement(data []byte) (tag byte, content, rest []byte, ok bool) {
	if len(data) < 2 {
		return 0, nil, nil, false
	}

	length, header := uint64(data[1]), 2

	if length&0x80 != 0 {
		size := int(length & 0x7f)

		if size < 1 || size > 4 || len(data) < 2+size {
			return 0, nil, nil, false
		}

		length = 0

		for _, b := range data[2 : 2+size] {
			length = length<<8 | uint64(b)
		}

		if length < 0x80 || length < 1<<(8*(size-1)) {
			return 0, nil, nil, false
		}

		header += size
	}

	if length > uint64(len(data)-header) {
		return 0, nil, nil, false
	}

	end := header + int(length)

	return data[0], data[header:end], data[end:], true
}

func fuzzExactly(data []byte, tag byte) ([]byte, bool) {
	found, content, rest, ok := fuzzElement(data)

	return content, ok && found == tag && len(rest) == 0
}

func fuzzReferencePublicKey(data []byte) (oid, key []byte, ok bool) {
	body, ok := fuzzExactly(data, tagSequence)

	if !ok {
		return nil, nil, false
	}

	tag, algorithm, rest, ok := fuzzElement(body)

	if !ok || tag != tagSequence {
		return nil, nil, false
	}

	if oid, ok = fuzzExactly(algorithm, tagObjectIdentifier); !ok {
		return nil, nil, false
	}

	bits, ok := fuzzExactly(rest, tagBitString)

	if !ok || len(bits) == 0 || bits[0] != 0 {
		return nil, nil, false
	}

	return oid, bits[1:], true
}

func fuzzReferencePrivateKey(data []byte) (oid, key, publicKey []byte, ok bool) {
	body, ok := fuzzExactly(data, tagSequence)

	var tags []byte

	var contents [][]byte

	for ok && len(body) > 0 {
		var tag byte

		var content []byte

		tag, content, body, ok = fuzzElement(body)

		tags, contents = append(tags, tag), append(contents, content)
	}

	if !ok || len(tags) < 3 || len(tags) > 5 || !bytes.Equal(tags[:3], []byte{tagInteger, tagSequence, tagOctetString}) {
		return nil, nil, nil, false
	}

	version := contents[0]

	if len(version) != 1 || version[0] > 1 {
		return nil, nil, nil, false
	}

	if oid, ok = fuzzExactly(contents[1], tagObjectIdentifier); !ok {
		return nil, nil, nil, false
	}

	optional := tags[3:]

	switch {
	case len(optional) == 0, len(optional) == 1 && optional[0] == tagContext0Constructed:
		return oid, contents[2], nil, true
	case optional[len(optional)-1] != tagContext1 || len(optional) == 2 && optional[0] != tagContext0Constructed:
		return nil, nil, nil, false
	}

	bits := contents[len(contents)-1]

	if version[0] != 1 || len(bits) == 0 || bits[0] != 0 {
		return nil, nil, nil, false
	}

	return oid, contents[2], bits[1:], true
}

func FuzzDer(f *testing.F) {
	for _, fixture := range fuzzKems()[:1] {
		public, _ := fixture.pair.PublicKey.ExportKey(DER)

		private, _ := fixture.pair.PrivateKey.ExportKey(DER)

		f.Add(public, uint8(tagSequence))

		f.Add(private, uint8(tagSequence))
	}

	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00}, uint8(tagSequence))

	f.Add([]byte{0x80, 0x20}, uint8(tagContext0))

	f.Add(derElement(tagSequence, derElement(tagOctetString, make([]byte, 32)), derElement(tagOctetString, make([]byte, 200))), uint8(tagSequence))

	f.Fuzz(func(t *testing.T, data []byte, tag uint8) {
		fuzzBounded(t, len(data), func() {
			fuzzDer(t, data, tag)
		})
	})
}

func fuzzDer(t *testing.T, data []byte, tag byte) {
	reader := derReader{data: data}

	for {
		start := reader.offset

		content, err := reader.read(tag)

		_, reference, _, ok := fuzzElement(data[start:])

		ok = ok && data[start] == tag

		if err != nil {
			fuzzExpect(t, err, INVALID_ENCODING)

			if ok {
				t.Fatalf("derReader refused a valid element at %d", start)
			}

			break
		}

		if !ok || !bytes.Equal(content, reference) || !bytes.Equal(derElement(tag, content), data[start:reader.offset]) {
			t.Fatalf("derReader read a malformed element at %d", start)
		}
	}

	oid, key, err := decodePublicKey(data)

	referenceOid, referenceKey, ok := fuzzReferencePublicKey(data)

	if (err == nil) != ok || err == nil && (!bytes.Equal(oid, referenceOid) || !bytes.Equal(key, referenceKey) || !bytes.Equal(encodePublicKey(oid, key), data)) {
		t.Fatalf("decodePublicKey disagrees with the reference: %v", err)
	}

	oid, key, publicKey, err := decodePrivateKey(data)

	referenceOid, referenceKey, referencePublic, ok := fuzzReferencePrivateKey(data)

	if (err == nil) != ok || err == nil && (!bytes.Equal(oid, referenceOid) || !bytes.Equal(key, referenceKey) || !bytes.Equal(publicKey, referencePublic) || (publicKey == nil) != (referencePublic == nil)) {
		t.Fatalf("decodePrivateKey disagrees with the reference: %v", err)
	}

	for _, sizes := range [][2]int{{32, 2560}, {64, 1632}} {
		seed, expanded, err := decodeSeedChoice(data, sizes[0], sizes[1])

		if err != nil {
			fuzzExpect(t, err, INVALID_ENCODING)

			continue
		}

		var encoded []byte

		switch {
		case expanded == nil:
			encoded = derElement(tagContext0, seed)
		case seed == nil:
			encoded = derElement(tagOctetString, expanded)
		default:
			encoded = derElement(tagSequence, derElement(tagOctetString, seed), derElement(tagOctetString, expanded))
		}

		if len(seed) != sizes[0] && seed != nil || len(expanded) != sizes[1] && expanded != nil || !bytes.Equal(encoded, data) {
			t.Fatal("decodeSeedChoice accepted a non-canonical encoding")
		}
	}
}

func fuzzSpace(c byte) bool {
	return c == ' ' || c >= '\t' && c <= '\r'
}

func FuzzPem(f *testing.F) {
	public, _ := fuzzKems()[3].pair.PublicKey.ExportKey(RAW)

	f.Add(pemEncode(pemPublic, public), false)

	private, _ := fuzzKems()[0].pair.PrivateKey.ExportKey(PEM)

	f.Add(private, true)

	f.Add([]byte("-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----"), false)

	f.Add([]byte(" \t-----BEGIN PRIVATE KEY-----\r\nQUJD\vRA==\f-----END PRIVATE KEY-----\n\n"), true)

	f.Fuzz(func(t *testing.T, data []byte, private bool) {
		label := pemPublic

		if private {
			label = pemPrivate
		}

		fuzzBounded(t, len(data), func() {
			der, err := pemDecode(label, data)

			reference, ok := fuzzReferencePem(label, data)

			if err != nil {
				fuzzExpect(t, err, INVALID_ENCODING)

				if ok {
					t.Fatal("pemDecode refused a valid block")
				}

				return
			}

			if !ok || !bytes.Equal(der, reference) {
				t.Fatal("pemDecode disagrees with the reference")
			}

			again, err := pemDecode(label, pemEncode(label, der))

			if err != nil || !bytes.Equal(again, der) {
				t.Fatal("PEM round trip")
			}
		})
	})
}

// RFC 7468 framing around strict standard base64, decoded with the standard library.
func fuzzReferencePem(label string, data []byte) ([]byte, bool) {
	data = bytes.TrimFunc(data, func(r rune) bool { return r < 0x80 && fuzzSpace(byte(r)) })

	begin, end := []byte("-----BEGIN "+label+"-----"), []byte("-----END "+label+"-----")

	if len(data) < len(begin)+len(end) || !bytes.HasPrefix(data, begin) || !bytes.HasSuffix(data, end) {
		return nil, false
	}

	var body []byte

	for _, c := range data[len(begin) : len(data)-len(end)] {
		if !fuzzSpace(c) {
			body = append(body, c)
		}
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(string(body))

	return decoded, err == nil
}

func FuzzBase64(f *testing.F) {
	for _, text := range []string{"", "QQ==", "QUI=", "QUJD", "QR==", "QUJ=", "Q===", "====", "QQ==QQ==", "QUJD\n"} {
		f.Add([]byte(text))
	}

	f.Fuzz(func(t *testing.T, text []byte) {
		fuzzBounded(t, len(text), func() {
			decoded, err := base64Decode(text)

			if err != nil {
				fuzzExpect(t, err, INVALID_ENCODING)
			} else if !bytes.Equal(base64Encode(decoded), text) {
				t.Fatal("base64Decode accepted a non-canonical encoding")
			}

			// The standard library skips line breaks, which pemDecode removes before decoding.
			if !bytes.ContainsAny(text, "\r\n") {
				reference, referenceErr := base64.StdEncoding.Strict().DecodeString(string(text))

				if (err == nil) != (referenceErr == nil) || err == nil && !bytes.Equal(decoded, reference) {
					t.Fatalf("base64Decode disagrees with the standard library: %v, %v", err, referenceErr)
				}
			}

			if encoded := base64Encode(text); string(encoded) != base64.StdEncoding.EncodeToString(text) {
				t.Fatal("base64Encode disagrees with the standard library")
			}
		})
	})
}
