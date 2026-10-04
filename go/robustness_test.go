package cryptopq

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Large and edge inputs, and stateful keys used from many goroutines at once.

// The message whose byte i is i mod 251; the digests below come from an independent
// implementation.
func largeMessage() []byte {
	message := make([]byte, 16<<20)

	for i := range message {
		message[i] = byte(i % 251)
	}

	return message
}

var largeDigests = map[HashAlgorithm]string{
	SHA_224:     "81e763ef9866bdefa03f5c58819e12ba2bc7dd6913eb36e8ec666036",
	SHA_256:     "287507f403176f1f5b22b9a4d9cb49f7d7f88ac19e406b5ae87ce109564846bd",
	SHA_384:     "4bc9798cec40d12e4f7198b89e0a5d4b7e7474ec255f3280b126bd3bc141103ca9a906d12fa05c0c5eb50f2bef840908",
	SHA_512:     "ef9941360046598bd9a89eb56a4440e46255bfa79529f9d3a8813aa899d5c64d8cc75f0c023b8d82ec41cc60ae69d311a80fb9ad372bf3d149574a87bc195c08",
	SHA_512_224: "181650285d94081ca60b6dad6cb501607c0b47b793d95f4b3fe703ef",
	SHA_512_256: "61fb65258a2a6ca095a709e2d1026483ef0d5dab44e374f55599d867e0d5d2f9",
	SHA3_224:    "3e121e54d1b7d67d8a6489426c33d7a5078089e9f7ff736786fc2cf3",
	SHA3_256:    "acade24d564f1dae78e26ca4615bc8061dda3835de1bb7afde3ef0d32a931191",
	SHA3_384:    "4934100bb50d9a97d1463c521a58ca562a59e07b6753076e45a824d8545df2358c346274ad7809ffeaac2e56a9cef7fb",
	SHA3_512:    "314cd6d2e1cc05dfc4c8429541a2877becd82e9def2333f26a4eb7f72cffe758289f9185ddae4bb5017ad7019933404f241787ac650e505530f2973d3233a88d",
}

func TestLargeHashes(t *testing.T) {
	message := largeMessage()

	for algorithm, expected := range largeDigests {
		if got := hex.EncodeToString(algorithm.Digest(message)); got != expected {
			t.Fatalf("%s: %s", algorithm.Name(), got)
		}

		hasher := algorithm.Create()

		for offset := 0; offset < len(message); offset += 1_000_003 {
			hasher.Update(message[offset:min(offset+1_000_003, len(message))])
		}

		if got := hex.EncodeToString(hasher.Digest()); got != expected {
			t.Fatalf("%s streaming: %s", algorithm.Name(), got)
		}
	}

	xofs := map[XofAlgorithm]string{
		SHAKE128: "8a38dce3e6592d50867536f5f352abd74e486bdbfe48c43b8372d55e6547110a",
		SHAKE256: "525fa10737fa7538afe5df929cfadb606e52a2b2e2f0e4c5626510e720319b7366c387167707535aa23a5d027a155150fe5c73c329f2113d1220a8d9d7b9a5e3",
	}

	for algorithm, expected := range xofs {
		if got := hex.EncodeToString(algorithm.Digest(message, len(expected)/2)); got != expected {
			t.Fatalf("%s: %s", algorithm.Name(), got)
		}
	}

	if got := hex.EncodeToString(HMAC_SHA_256.Digest(fuzzPattern(32, 0), message)); got != "e9fb7e5b1f5d2702eba341df5e51ec9e4ed48db395f66dff93e30808b88f0750" {
		t.Fatalf("HMAC-SHA-256: %s", got)
	}
}

func TestLargeAndEmptyMessages(t *testing.T) {
	message := largeMessage()

	changed := bytes.Clone(message)

	changed[len(changed)-1] ^= 1

	longest := fuzzPattern(255, 0)

	for _, algorithm := range []SignatureAlgorithm{ML_DSA_44, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F} {
		pair, err := Hazmat.GenerateSignatureKeyPair(algorithm, fuzzPattern(algorithm.spec().seedSize, 0))

		fuzzCheck(t, err)

		cases := []struct {
			text, context []byte
			preHash       PreHash
		}{
			{message, nil, nil},
			{nil, make([]byte, 255), nil},
			{message, longest, SHA_512},
			{[]byte{}, nil, SHAKE256},
		}

		for _, c := range cases {
			signature, err := pair.PrivateKey.Sign(c.text, &SignOptions{Context: c.context, Deterministic: true, PreHash: c.preHash})

			fuzzCheck(t, err)

			other := []byte{0}

			if len(c.text) > 0 {
				other = changed
			}

			options := &VerifyOptions{Context: c.context, PreHash: c.preHash}

			longer := &VerifyOptions{Context: append(bytes.Clone(c.context), 0), PreHash: c.preHash}

			if !pair.PublicKey.Verify(signature, c.text, options) || pair.PublicKey.Verify(signature, other, options) || pair.PublicKey.Verify(signature, c.text, longer) {
				t.Fatalf("%s: %d-byte message, %d-byte context", algorithm.Name(), len(c.text), len(c.context))
			}
		}

		_, err = pair.PrivateKey.Sign(nil, &SignOptions{Context: make([]byte, 256)})

		fuzzExpect(t, err, INVALID_CONTEXT)
	}

	for _, options := range []*StatefulKeyGenOptions{{Levels: []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}}, {Parameters: "XMSSMT-SHA2_20/4_192"}} {
		options.StateStore = &fuzzStore{}

		algorithm := HSS_LMS

		if options.Parameters != "" {
			algorithm = XMSS_MT
		}

		pair, err := algorithm.GenerateKeyPair(options)

		fuzzCheck(t, err)

		for _, text := range [][]byte{message, nil} {
			signature, err := pair.PrivateKey.Sign(text)

			fuzzCheck(t, err)

			other := []byte{0}

			if len(text) > 0 {
				other = changed
			}

			if !pair.PublicKey.Verify(signature, text) || pair.PublicKey.Verify(signature, other) {
				t.Fatalf("%s: %d-byte message", algorithm.Name(), len(text))
			}
		}
	}
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func TestPemLayouts(t *testing.T) {
	pair, err := Hazmat.GenerateKemKeyPair(ML_KEM_768, fuzzPattern(64, 0))

	fuzzCheck(t, err)

	der, err := pair.PublicKey.ExportKey(DER)

	fuzzCheck(t, err)

	body := base64.StdEncoding.EncodeToString(der)

	var narrow bytes.Buffer

	narrow.WriteString("-----BEGIN PUBLIC KEY-----\n")

	for _, c := range []byte(body) {
		narrow.Write([]byte{c, '\n'})
	}

	narrow.WriteString("-----END PUBLIC KEY-----\n")

	wide := "-----BEGIN PUBLIC KEY-----" + body + "-----END PUBLIC KEY-----"

	for _, text := range [][]byte{narrow.Bytes(), []byte(wide)} {
		key, err := ML_KEM_768.ImportPublicKey(text, PEM)

		if err != nil || !key.Equal(pair.PublicKey) {
			t.Fatalf("%q: %v", text[:40], err)
		}
	}

	// The last base64 quantum of an ML-DSA-44 key carries two unused bits, which must be zero.
	dsa, err := Hazmat.GenerateSignatureKeyPair(ML_DSA_44, fuzzPattern(32, 0))

	fuzzCheck(t, err)

	pem, err := dsa.PublicKey.ExportKey(PEM)

	fuzzCheck(t, err)

	last := bytes.LastIndexByte(pem, '=') - 1

	pem[last] = base64Alphabet[strings.IndexByte(base64Alphabet, pem[last])^1]

	_, err = ML_DSA_44.ImportPublicKey(pem, PEM)

	fuzzExpect(t, err, INVALID_ENCODING)

	huge := base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x84, 0x00, 0xff, 0xff, 0xff}, make([]byte, 4<<20)...))

	for _, text := range []string{huge, huge[:len(huge)-1]} {
		_, err := ML_KEM_768.ImportPublicKey([]byte("-----BEGIN PUBLIC KEY-----\n"+text+"\n-----END PUBLIC KEY-----\n"), PEM)

		fuzzExpect(t, err, INVALID_ENCODING)
	}
}

// The bytes run allocates on the heap; nothing else runs in this test.
func heapAllocated(run func()) uint64 {
	samples := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}

	metrics.Read(samples)

	before := samples[0].Value.Uint64()

	run()

	metrics.Read(samples)

	return samples[0].Value.Uint64() - before
}

// A length field that claims gigabytes is refused before anything that large is allocated; one
// with a needless leading zero byte, and a PKCS#8 version above 1, are refused too.
func TestClaimedDerLengths(t *testing.T) {
	pair, err := Hazmat.GenerateSignatureKeyPair(ML_DSA_65, fuzzPattern(32, 0))

	fuzzCheck(t, err)

	public, err := pair.PublicKey.ExportKey(DER)

	fuzzCheck(t, err)

	private, err := pair.PrivateKey.ExportKey(DER)

	fuzzCheck(t, err)

	join := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}

	cases := [][]byte{
		join([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, public[4:]),
		join([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, public[4:]),
		join(public[:4], []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xf0}, public[6:]),
		join(public[:17], []byte{0x03, 0x84, 0xff, 0xff, 0xff, 0xff}, public[21:]),
		join(private[:2], []byte{0x02, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00}),
		join(private[:20], []byte{0x04, 0x84, 0x40, 0x00, 0x00, 0x00}, private[22:]),
		join([]byte{0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, public[4:]),
		join([]byte{0x30, 0x80}, public[4:], []byte{0, 0}),
		join([]byte{0x30, 0x83, 0x00, 0x07, 0xb2}, public[4:]),
		join([]byte{0x30, 0x82, 0x07, 0xb3}, public[4:17], []byte{0x03, 0x83, 0x00, 0x07, 0xa1}, public[21:]),
		join(private[:4], []byte{2}, private[5:]),
	}

	for _, data := range cases {
		pem := []byte("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(data) + "\n-----END PUBLIC KEY-----\n")

		allocated := heapAllocated(func() {
			_, err := ML_DSA_65.ImportPublicKey(data, DER)

			fuzzExpect(t, err, INVALID_ENCODING)

			_, err = ML_DSA_65.ImportPrivateKey(data, DER)

			fuzzExpect(t, err, INVALID_ENCODING)

			_, err = ML_DSA_65.ImportPublicKey(pem, PEM)

			fuzzExpect(t, err, INVALID_ENCODING)
		})

		if allocated > 1<<20 {
			t.Fatalf("allocated %d bytes for %x", allocated, data[:8])
		}
	}
}

// State blobs that claim too many levels, a tree too tall or an index beyond the capacity are
// refused before any tree is built.
func TestClaimedStateSizes(t *testing.T) {
	parameters, err := HSS_LMS.parameters(&StatefulKeyGenOptions{Levels: []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}})

	fuzzCheck(t, err)

	body := HSS_LMS.encode(parameters, make([]byte, 40), 0)

	body = body[:len(body)-16]

	refused := func(algorithm StatefulSignatureAlgorithm, body []byte) {
		t.Helper()

		allocated := heapAllocated(func() {
			_, err := algorithm.LoadPrivateKey(&fuzzStore{state: fuzzSeal(body)})

			fuzzExpect(t, err, INVALID_PRIVATE_KEY)
		})

		if allocated > 64<<10 {
			t.Fatalf("allocated %d bytes for a refused state", allocated)
		}
	}

	for _, count := range []byte{0, 2, 9, 0xff} {
		claimed := bytes.Clone(body)

		claimed[2] = count

		refused(HSS_LMS, claimed)

		if count != 2 {
			padded := append(bytes.Clone(claimed[:3]), bytes.Repeat([]byte{0, 0, 0, 10, 0, 0, 0, 5}, int(count))...)

			refused(HSS_LMS, append(padded, claimed[11:]...))
		}
	}

	refused(HSS_LMS, append(append([]byte{1, 1, 3}, bytes.Repeat([]byte{0, 0, 0, 14, 0, 0, 0, 5}, 3)...), make([]byte, 48)...))

	for _, index := range []uint64{33, 1<<64 - 1} {
		refused(HSS_LMS, binary.BigEndian.AppendUint64(bytes.Clone(body[:len(body)-8]), index))
	}

	mt, err := XMSS_MT.parameters(&StatefulKeyGenOptions{Parameters: "XMSSMT-SHA2_60/12_256"})

	fuzzCheck(t, err)

	state := XMSS_MT.encode(mt, make([]byte, 96), 0)

	for _, index := range []uint64{1<<60 + 1, 1<<64 - 1} {
		beyond := bytes.Clone(state[:len(state)-16])

		binary.BigEndian.PutUint64(beyond[6:], index)

		refused(XMSS_MT, beyond)
	}
}

// One store shared like a file between processes: compare-and-swap under a lock.
type lockedStore struct {
	mutex sync.Mutex
	state []byte
}

func (s *lockedStore) Read() ([]byte, error) {
	s.mutex.Lock()

	defer s.mutex.Unlock()

	return bytes.Clone(s.state), nil
}

func (s *lockedStore) Update(previous, next []byte) (bool, error) {
	s.mutex.Lock()

	defer s.mutex.Unlock()

	if (previous == nil) != (s.state == nil) || !bytes.Equal(previous, s.state) {
		return false, nil
	}

	s.state = bytes.Clone(next)

	return true, nil
}

var smallLevels = []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}

func sortedIndices(signatures [][]byte) []int {
	indices := make([]int, len(signatures))

	for i, signature := range signatures {
		indices[i] = int(binary.BigEndian.Uint32(signature[4:]))
	}

	sort.Ints(indices)

	return indices
}

// More goroutines than signatures on one key: each index is used once and the rest of the calls
// get KEY_EXHAUSTED.
func TestStatefulConcurrentExhaustion(t *testing.T) {
	store := &lockedStore{}

	pair, err := HSS_LMS.GenerateKeyPair(&StatefulKeyGenOptions{Levels: smallLevels, StateStore: store})

	fuzzCheck(t, err)

	var mutex sync.Mutex

	var signatures [][]byte

	var group sync.WaitGroup

	for i := range 40 {
		group.Go(func() {
			signature, err := pair.PrivateKey.Sign([]byte{byte(i)})

			if err != nil && !errors.Is(err, KEY_EXHAUSTED) {
				t.Error(err)
			}

			if err != nil {
				return
			}

			mutex.Lock()

			defer mutex.Unlock()

			signatures = append(signatures, signature)
		})
	}

	group.Wait()

	for i, index := range sortedIndices(signatures) {
		if index != i {
			t.Fatalf("indices %v", sortedIndices(signatures))
		}
	}

	if len(signatures) != 32 || pair.PrivateKey.RemainingSignatures() != 0 {
		t.Fatalf("%d signatures", len(signatures))
	}
}

// Keys loaded from one store in different goroutines: the compare-and-swap lets one of them use
// each index; the others get STATE_CONFLICT and load the key again.
func TestStatefulConcurrentKeys(t *testing.T) {
	store := &lockedStore{}

	if _, err := HSS_LMS.GenerateKeyPair(&StatefulKeyGenOptions{Levels: smallLevels, StateStore: store}); err != nil {
		t.Fatal(err)
	}

	var mutex sync.Mutex

	var signatures [][]byte

	var group sync.WaitGroup

	start := make(chan struct{})

	for range 6 {
		group.Go(func() {
			key, err := HSS_LMS.LoadPrivateKey(store)

			<-start

			for err == nil {
				var signature []byte

				signature, err = key.Sign([]byte("m"))

				switch {
				case errors.Is(err, KEY_EXHAUSTED):
					return
				case errors.Is(err, STATE_CONFLICT):
					key, err = HSS_LMS.LoadPrivateKey(store)
				case err == nil:
					mutex.Lock()

					signatures = append(signatures, signature)

					mutex.Unlock()
				}
			}

			t.Error(err)
		})
	}

	close(start)

	group.Wait()

	for i, index := range sortedIndices(signatures) {
		if index != i {
			t.Fatalf("indices %v", sortedIndices(signatures))
		}
	}

	if len(signatures) != 32 {
		t.Fatalf("%d signatures", len(signatures))
	}
}

// SplitMix64 and the edits of the other implementations' robustness tests, so that the
// transcript test below sees the inputs they see.
type splitMix uint64

func (r *splitMix) next() uint64 {
	*r += 0x9e3779b97f4a7c15

	z := uint64(*r)

	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9

	z = (z ^ z>>27) * 0x94d049bb133111eb

	return z ^ z>>31
}

func (r *splitMix) below(bound int) int {
	return int(r.next() % uint64(bound))
}

func (r *splitMix) bytes(size int) []byte {
	out := make([]byte, size)

	for i := range out {
		out[i] = byte(r.next())
	}

	return out
}

var editTags = []byte{0x02, 0x03, 0x04, 0x06, 0x30, 0x80, 0x81, 0xa0}

// Indefinite, gigabytes, non-minimal, five bytes long, and plain wrong lengths.
var editLengths = [][]byte{{0x80}, {0x84, 0xff, 0xff, 0xff, 0xff}, {0x84, 0x7f, 0xff, 0xff, 0xff}, {0x83, 0xff, 0xff, 0xff}, {0x82, 0xff, 0xff}, {0x81, 0x05}, {0x81, 0x7f}, {0x82, 0x00, 0x80}, {0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, {0x00}, {0x01}, {0x7f}}

// The OIDs of every algorithm and of SHA-256, those of the stateful schemes, and broken ones.
var editOids = func() [][]byte {
	var out [][]byte

	for arc := range 4 {
		out = append(out, derElement(tagObjectIdentifier, objectIdentifier(2, 16, 840, 1, 101, 3, 4, 4, uint64(1+arc))))
	}

	for arc := range 32 {
		out = append(out, derElement(tagObjectIdentifier, objectIdentifier(2, 16, 840, 1, 101, 3, 4, 3, uint64(16+arc))))
	}

	out = append(out, derElement(tagObjectIdentifier, objectIdentifier(2, 16, 840, 1, 101, 3, 4, 2, 1)))

	for _, spec := range statefulSpecs[1:] {
		out = append(out, derElement(tagObjectIdentifier, spec.oid))
	}

	return append(out, []byte{0x06, 0x00}, []byte{0x06, 0x01, 0x00}, []byte{0x06, 0x81, 0x01, 0x2a})
}()

func editTagPosition(rng *splitMix, data []byte) int {
	for range 16 {
		position := rng.below(len(data))

		if bytes.IndexByte(editTags, data[position]) >= 0 && position+1 < len(data) {
			return position
		}
	}

	return -1
}

func editOidPosition(rng *splitMix, data []byte) int {
	var starts []int

	for i := 0; i+1 < len(data); i++ {
		if data[i] == 0x06 && data[i+1] < 0x10 && i+2+int(data[i+1]) <= len(data) {
			starts = append(starts, i)
		}
	}

	if len(starts) == 0 {
		return -1
	}

	return starts[rng.below(len(starts))]
}

func spliced(data []byte, start, end int, insert []byte) []byte {
	end = min(end, len(data))

	return bytes.Join([][]byte{data[:start], insert, data[end:]}, nil)
}

// One random edit: bits, bytes, insertions, deletions, truncation, DER length fields (huge,
// indefinite, non-minimal), tags, OIDs, or a slice of another valid encoding. An edit that does
// not apply duplicates a slice.
func edit(rng *splitMix, input []byte, others [][]byte) []byte {
	if len(input) == 0 {
		return rng.bytes(rng.below(16))
	}

	data := bytes.Clone(input)

	operation := rng.below(11)

	position := rng.below(len(data))

	header, oid := -1, -1

	if operation == 6 || operation == 7 {
		header = editTagPosition(rng, data)
	}

	if operation == 8 {
		oid = editOidPosition(rng, data)
	}

	switch {
	case operation == 0:
		data[position] ^= 1 << rng.below(8)
	case operation == 1:
		random := byte(rng.below(256))

		choices := []byte{0x00, 0x01, 0x7f, 0x80, 0xff, random}

		data[position] = choices[rng.below(len(choices))]
	case operation == 2:
		data = spliced(data, position, position, rng.bytes(1+rng.below(4)))
	case operation == 3:
		data = spliced(data, position, position+1+rng.below(4), nil)
	case operation == 4:
		data = data[:position]
	case operation == 5:
		data = append(data, rng.bytes(1+rng.below(32))...)
	case operation == 6 && header >= 0:
		first := data[header+1]

		size := 1

		if first&0x80 != 0 {
			size += int(first & 0x7f)
		}

		var length []byte

		if rng.below(2) == 1 {
			length = editLengths[rng.below(len(editLengths))]
		} else {
			length = []byte{byte(rng.below(256))}
		}

		data = spliced(data, header+1, header+1+size, length)
	case operation == 7 && header >= 0:
		random := byte(rng.below(256))

		if rng.below(2) == 1 {
			random = editTags[rng.below(len(editTags))]
		}

		data[header] = random
	case operation == 8 && oid >= 0:
		data = spliced(data, oid, oid+2+int(data[oid+1]), editOids[rng.below(len(editOids))])
	case operation == 9 && len(others) > 0:
		other := others[rng.below(len(others))]

		start := rng.below(len(other) + 1)

		piece := other[start:min(len(other), start+rng.below(64))]

		data = spliced(data, position, position+rng.below(64), piece)
	default:
		end := min(len(data), position+1+rng.below(16))

		data = spliced(data, position, position, bytes.Clone(data[position:end]))
	}

	return data
}

// Random edits of a state blob, mostly resealed so that they reach the parser behind the
// checksum: level counts, type codes, indices at and beyond the capacity, and byte edits.
func editState(rng *splitMix, state []byte) []byte {
	body := bytes.Clone(state[:len(state)-16])

	indexOffset := 6

	if state[1] == 1 && len(state) >= 24 {
		indexOffset = len(state) - 24
	}

	switch operation := rng.below(6); {
	case operation == 0 && len(body) > 2:
		counts := []byte{0, 1, 2, 3, 8, 9, 0x80, 0xff}

		body[2] = counts[rng.below(len(counts))]
	case operation == 1 && len(body) > 6:
		offset := 2

		if body[1] == 1 {
			offset = 3 + 8*rng.below(max(1, int(body[2]))) + 4*rng.below(2)
		}

		values := []uint32{uint32(rng.below(48)), uint32(rng.next()), 0}

		value := values[rng.below(len(values))]

		if offset+4 <= len(body) {
			binary.BigEndian.PutUint32(body[offset:], value)
		}
	case operation == 2 && len(body) >= indexOffset+8:
		heights := []int{5, 10, 20, 40, 60, 64}

		top := uint64(1) << heights[rng.below(len(heights))]

		values := []uint64{0, 1, top - 1, top, top + 1, 1<<64 - 1}

		binary.BigEndian.PutUint64(body[indexOffset:], values[rng.below(len(values))])
	default:
		body = edit(rng, body, nil)
	}

	if rng.below(4) != 0 {
		return fuzzSeal(body)
	}

	return append(body, state[len(state)-16:]...)
}

// Every implementation runs these rounds on the same inputs, made by the same generator from
// byte-identical keys, and hashes each input with its outcome: an error code, true or false, or
// OK and the result. Equal digests mean that all five implementations accept, refuse and compute
// alike on untrusted input.
const (
	transcriptRounds = 96
	transcriptBudget = 1 << 14
)

var transcripts = []string{
	"4d454f3aca564e383f51723ee3814f1fe105a61b1fd38c536e2ea675d78fabe7",
	"db3f28b7c8f7949f104d15d6de629e0dea7fca38f38c970d520278617dc99474",
	"aafe47ac9480c88402b7974385fac0547b2f4d611f36ec692ca2748e5dec949e",
	"ce9fd19a166b8a384fab4dafffed98c85dd9fb7f3e2ab789f33c832cda8b199d",
	"14d657260a5c207db5e73e9dbaac6d3458b0ba16e507f256bea8fac9fd0f2a0a",
	"19d93bae7a287d14492808654d0580f1043443ad3cf6710e043ea34c462b3307",
	"38a35f3547d4414788484ce0b4b836a27f72fba19931a9f3680cbcadd6d5d97a",
	"7b468ce2966d2edd458ed4a62183bf6d4c06e182509a7773c505a3cb2ae12e58",
	"b2ecff951172fdfdd464c3b4bed07055c3041b64d0c11dc6c9bc62eae7cc0b0e",
	"57986f97a5d291a67f8a875f558d59a535f2157155e13b83b364a6a1cca5dc7d",
	"b46878b67dab92d46731b18b1c63b71f24e7ec4cb53bca10ec36540ca1b4b054",
}

type transcript struct {
	hasher *Hasher
}

func (t *transcript) add(data []byte, selector int, code string, output []byte) {
	for _, part := range [][]byte{data, {byte(selector)}, []byte(code), output} {
		t.hasher.Update(binary.BigEndian.AppendUint32(nil, uint32(len(part))))

		t.hasher.Update(part)
	}
}

func outcomeCode(err error) string {
	var failure *Error

	if !errors.As(err, &failure) {
		return err.Error()
	}

	return string(failure.Code)
}

// Random bytes, or the seed with up to three edits, so that some inputs stay valid.
func edited(rng *splitMix, seed []byte, others [][]byte) []byte {
	if rng.below(8) == 0 {
		return rng.bytes(rng.below(96))
	}

	data := seed

	for range rng.below(4) {
		data = edit(rng, data, others)
	}

	return data
}

func resized(rng *splitMix, data []byte, size int) []byte {
	if rng.below(2) == 0 {
		return data
	}

	return fuzzResize(data, size)
}

type transcriptSeed struct {
	encoding         []byte
	function, format int
}

type transcriptImport func([]byte, KeyFormat) ([]byte, error)

func importCase(rng *splitMix, t *transcript, seeds []transcriptSeed, imports []transcriptImport) {
	var others [][]byte

	for _, seed := range seeds {
		others = append(others, seed.encoding)
	}

	for range transcriptRounds {
		seed := seeds[rng.below(len(seeds))]

		data := edited(rng, seed.encoding, others)

		format := seed.format

		if rng.below(4) == 0 {
			format = rng.below(3)
		}

		raw, err := imports[seed.function](data, fuzzFormats[format])

		if err != nil {
			t.add(data, 3*seed.function+format, outcomeCode(err), nil)
		} else {
			t.add(data, 3*seed.function+format, "OK", raw)
		}
	}
}

func signatureCase(rng *splitMix, t *transcript, signature []byte, verify func(data, context []byte) bool) {
	for range transcriptRounds {
		data := resized(rng, edited(rng, signature, [][]byte{signature}), len(signature))

		context := []byte("context")

		if rng.below(2) == 1 {
			context = nil
		}

		result := "false"

		if verify(data, context) {
			result = "true"
		}

		t.add(data, len(context), result, nil)
	}
}

func seedsOf(key fuzzExporter, function int) []transcriptSeed {
	var out []transcriptSeed

	for number, format := range fuzzFormats[:3] {
		encoding, err := key.ExportKey(format)

		fuzzPanic(err)

		out = append(out, transcriptSeed{encoding, function, number})
	}

	return out
}

func importOf[K fuzzExporter](load func([]byte, KeyFormat) (K, error)) transcriptImport {
	return func(data []byte, format KeyFormat) ([]byte, error) {
		key, err := load(data, format)

		if err != nil {
			return nil, err
		}

		return key.ExportKey(RAW)
	}
}

// Loading builds the key's trees, so a valid state of a key larger than the budget is only
// recorded as skipped.
func stateCase(rng *splitMix, t *transcript, base []byte) {
	for range transcriptRounds {
		state := base

		for range 1 + rng.below(2) {
			if len(state) >= 18 {
				state = editState(rng, state)
			} else {
				state = rng.bytes(rng.below(160))
			}
		}

		choice := -1

		if len(state) > 1 && state[1] >= 1 && state[1] <= 3 && rng.below(4) != 0 {
			choice = int(state[1]) - 1
		}

		if choice < 0 {
			choice = rng.below(3)
		}

		algorithm := fuzzStatefulAlgorithms[choice]

		if parameters, _, _, err := algorithm.decode(state); err == nil && fuzzStatefulCost(parameters) > transcriptBudget {
			t.add(state, choice, "SKIP", nil)

			continue
		}

		key, err := algorithm.LoadPrivateKey(&fuzzStore{state: state})

		if err != nil {
			t.add(state, choice, outcomeCode(err), nil)

			continue
		}

		t.add(state, choice, "OK", binary.BigEndian.AppendUint64(key.PublicKey().key, key.RemainingSignatures()))
	}
}

func TestTranscripts(t *testing.T) {
	message := []byte("crypto-pq transcript")

	kem, err := Hazmat.GenerateKemKeyPair(ML_KEM_768, fuzzPattern(64, 0))

	fuzzCheck(t, err)

	encapsulation, err := Hazmat.Encapsulate(kem.PublicKey, fuzzPattern(32, 0x80))

	fuzzCheck(t, err)

	xwing, err := Hazmat.GenerateKemKeyPair(X_WING, fuzzPattern(32, 0))

	fuzzCheck(t, err)

	dsa, err := Hazmat.GenerateSignatureKeyPair(ML_DSA_44, fuzzPattern(32, 0))

	fuzzCheck(t, err)

	signature, err := Hazmat.Sign(dsa.PrivateKey, message, fuzzPattern(32, 0x60), &SignOptions{Context: []byte("context")})

	fuzzCheck(t, err)

	slh, err := Hazmat.GenerateSignatureKeyPair(SLH_DSA_SHA2_128F, fuzzPattern(48, 0))

	fuzzCheck(t, err)

	levels := []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}, {"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}

	hss, err := Hazmat.GenerateStatefulKeyPair(HSS_LMS, &StatefulKeyGenOptions{Levels: levels, StateStore: &fuzzStore{}}, fuzzPattern(40, 0), 33)

	fuzzCheck(t, err)

	hssSignature, err := hss.PrivateKey.Sign(message)

	fuzzCheck(t, err)

	store := &fuzzStore{}

	_, err = Hazmat.GenerateStatefulKeyPair(HSS_LMS, &StatefulKeyGenOptions{Levels: levels[:1], StateStore: store}, fuzzPattern(40, 0), 3)

	fuzzCheck(t, err)

	xmssPublic := append([]byte{0, 0, 0, 1}, fuzzPattern(64, 0)...)

	xmssMtPublic := append([]byte{0, 0, 0, 0x31}, fuzzPattern(48, 0)...)

	xmssMtKey, err := XMSS_MT.ImportPublicKey(xmssMtPublic, RAW)

	fuzzCheck(t, err)

	xmssMtDer, err := xmssMtKey.ExportKey(DER)

	fuzzCheck(t, err)

	statefulSeeds := append(seedsOf(hss.PublicKey, 0), transcriptSeed{xmssPublic, 1, 0}, transcriptSeed{xmssMtPublic, 2, 0}, transcriptSeed{xmssMtDer, 2, 1})

	xwingPublic, _ := xwing.PublicKey.ExportKey(RAW)

	xwingPrivate, _ := xwing.PrivateKey.ExportKey(RAW)

	ciphertext := encapsulation.Ciphertext

	cases := []func(*splitMix, *transcript){
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, seedsOf(kem.PublicKey, 0), []transcriptImport{importOf(ML_KEM_768.ImportPublicKey)})
		},
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, seedsOf(kem.PrivateKey, 0), []transcriptImport{importOf(ML_KEM_768.ImportPrivateKey)})
		},
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, []transcriptSeed{{xwingPublic, 0, 0}, {xwingPrivate, 1, 0}}, []transcriptImport{importOf(X_WING.ImportPublicKey), importOf(X_WING.ImportPrivateKey)})
		},
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, seedsOf(dsa.PublicKey, 0), []transcriptImport{importOf(ML_DSA_44.ImportPublicKey)})
		},
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, seedsOf(dsa.PrivateKey, 0), []transcriptImport{importOf(ML_DSA_44.ImportPrivateKey)})
		},
		func(rng *splitMix, t *transcript) {
			seeds := append(seedsOf(slh.PublicKey, 0), seedsOf(slh.PrivateKey, 1)...)

			importCase(rng, t, seeds, []transcriptImport{importOf(SLH_DSA_SHA2_128F.ImportPublicKey), importOf(SLH_DSA_SHA2_128F.ImportPrivateKey)})
		},
		func(rng *splitMix, t *transcript) {
			importCase(rng, t, statefulSeeds, []transcriptImport{importOf(HSS_LMS.ImportPublicKey), importOf(XMSS.ImportPublicKey), importOf(XMSS_MT.ImportPublicKey)})
		},
		func(rng *splitMix, t *transcript) {
			signatureCase(rng, t, signature, func(data, context []byte) bool {
				return dsa.PublicKey.Verify(data, message, &VerifyOptions{Context: context})
			})
		},
		func(rng *splitMix, t *transcript) {
			for range transcriptRounds {
				data := resized(rng, edited(rng, ciphertext, [][]byte{ciphertext}), len(ciphertext))

				secret, err := kem.PrivateKey.Decapsulate(data)

				if err != nil {
					t.add(data, 0, outcomeCode(err), nil)
				} else {
					t.add(data, 0, "OK", secret)
				}
			}
		},
		func(rng *splitMix, t *transcript) {
			signatureCase(rng, t, hssSignature, func(data, context []byte) bool {
				return hss.PublicKey.Verify(data, append(bytes.Clone(message), context...))
			})
		},
		func(rng *splitMix, t *transcript) {
			stateCase(rng, t, store.state)
		},
	}

	for number, run := range cases {
		rng := splitMix(101 + number)

		record := &transcript{hasher: SHA_256.Create()}

		run(&rng, record)

		if digest := hex.EncodeToString(record.hasher.Digest()); digest != transcripts[number] {
			t.Errorf("case %d: %s", number, digest)
		}
	}
}

// Structures that random edits rarely build: an HSS signature cut inside a field or inside a
// signed child key, counts and leaf indices beyond their range, and hint sections that claim more
// than omega hints, repeat an index or leave padding. Verification refuses every one.
func TestEdgeStructures(t *testing.T) {
	message := []byte("crypto-pq edge")

	levels := []HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}, {"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}

	pair, err := Hazmat.GenerateStatefulKeyPair(HSS_LMS, &StatefulKeyGenOptions{Levels: levels, StateStore: &fuzzStore{}}, fuzzPattern(40, 0), 33)

	fuzzCheck(t, err)

	signature, err := pair.PrivateKey.Sign(message)

	fuzzCheck(t, err)

	// Nspk, then the first LMS signature (4956 bytes), the signed child key (48) and the second.
	end := 4 + 4956

	lengths := []int{0, 1, 3, 4, 5, 8, 12, len(signature) - 1}

	for length := end - 1; length <= end+49; length++ {
		lengths = append(lengths, length)
	}

	for _, length := range lengths {
		if pair.PublicKey.Verify(signature[:length], message) {
			t.Fatalf("an HSS signature cut to %d bytes verified", length)
		}
	}

	if !pair.PublicKey.Verify(signature, message) || pair.PublicKey.Verify(append(bytes.Clone(signature), 0), message) {
		t.Fatal("the whole HSS signature")
	}

	for _, field := range [][2]int{{0, 0}, {0, 2}, {0, 0x7fffffff}, {0, -1}, {4, 32}, {4, -1}, {end + 48, 32}, {end + 48, -1}} {
		edited := bytes.Clone(signature)

		binary.BigEndian.PutUint32(edited[field[0]:], uint32(field[1]))

		if pair.PublicKey.Verify(edited, message) {
			t.Fatalf("an HSS signature with %d at offset %d verified", field[1], field[0])
		}
	}

	// Level counts outside 1 to 8 make a malformed public key.
	for _, count := range []uint32{0, 9, 1<<32 - 1} {
		key := append(binary.BigEndian.AppendUint32(nil, count), pair.PublicKey.key[4:]...)

		_, err := HSS_LMS.ImportPublicKey(key, RAW)

		fuzzExpect(t, err, INVALID_PUBLIC_KEY)
	}

	dsa, err := Hazmat.GenerateSignatureKeyPair(ML_DSA_44, fuzzPattern(32, 0))

	fuzzCheck(t, err)

	valid, err := Hazmat.Sign(dsa.PrivateKey, message, make([]byte, 32), nil)

	fuzzCheck(t, err)

	// ML-DSA-44: omega = 80 hint positions, then k = 4 cumulative counts.
	for _, counts := range [][4]byte{{81, 82, 83, 84}, {200, 201, 202, 203}, {80, 80, 80, 80}, {255, 255, 255, 255}, {5, 3, 3, 3}, {0, 0, 0, 0}} {
		for _, repeat := range []bool{false, true} {
			edited := bytes.Clone(valid)

			hints := edited[len(edited)-84:]

			for i := range 80 {
				hints[i] = byte(i)
			}

			if repeat {
				hints[1] = 0
			}

			copy(hints[80:], counts[:])

			if dsa.PublicKey.Verify(edited, message, nil) {
				t.Fatalf("hint counts %v verified", counts)
			}
		}
	}

	// The valid signature with a nonzero byte after its last hint: the encoding must be canonical.
	if used := int(valid[len(valid)-1]); used < 80 {
		edited := bytes.Clone(valid)

		edited[len(edited)-84+used] = 1

		if !dsa.PublicKey.Verify(valid, message, nil) || dsa.PublicKey.Verify(edited, message, nil) {
			t.Fatal("hint padding")
		}
	}

	for _, c := range []struct {
		algorithm StatefulSignatureAlgorithm
		oid       uint32
		size      int
		index     []byte
	}{
		{XMSS, 0x0d, 4 + 24 + 61*24, []byte{0, 0, 4, 0}},
		{XMSS, 0x0d, 4 + 24 + 61*24, []byte{0xff, 0xff, 0xff, 0xff}},
		{XMSS_MT, 0x22, 3 + 24 + (4*51+20)*24, []byte{0x10, 0, 0}},
		{XMSS_MT, 0x22, 3 + 24 + (4*51+20)*24, []byte{0xff, 0xff, 0xff}},
	} {
		key, err := c.algorithm.ImportPublicKey(append(binary.BigEndian.AppendUint32(nil, c.oid), fuzzPattern(48, 0)...), RAW)

		fuzzCheck(t, err)

		edited := make([]byte, c.size)

		copy(edited, c.index)

		if key.Verify(edited, message) {
			t.Fatalf("%s index %x verified", c.algorithm, c.index)
		}
	}
}
