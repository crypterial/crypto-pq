package cryptopq_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var small = []cryptopq.HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"}}

var slow = os.Getenv("CRYPTO_PQ_SLOW") != ""

type memoryStore struct {
	mutex sync.Mutex
	state []byte
}

func (s *memoryStore) Read() ([]byte, error) {
	s.mutex.Lock()

	defer s.mutex.Unlock()

	return bytes.Clone(s.state), nil
}

func (s *memoryStore) Update(previous, next []byte) (bool, error) {
	s.mutex.Lock()

	defer s.mutex.Unlock()

	if (s.state == nil) != (previous == nil) || !bytes.Equal(s.state, previous) {
		return false, nil
	}

	s.state = bytes.Clone(next)

	return true, nil
}

// Saves a new key, then fails every later write.
type brokenStore struct {
	memoryStore
}

func (s *brokenStore) Update(previous, next []byte) (bool, error) {
	if previous == nil {
		return s.memoryStore.Update(previous, next)
	}

	return false, errors.New("disk full")
}

type unreadableStore struct {
	memoryStore
}

func (s *unreadableStore) Read() ([]byte, error) {
	return nil, errors.New("permission denied")
}

func sequence(length int) []byte {
	data := make([]byte, length)

	for i := range data {
		data[i] = byte(i)
	}

	return data
}

func sign(t *testing.T, key *cryptopq.StatefulPrivateKey, message []byte) []byte {
	t.Helper()

	signature, err := key.Sign(message)

	check(t, err)

	return signature
}

func TestHssAcvpKeyGeneration(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/LMS-keyGen.txt", "publicKey") {
		t.Run(r.values["tcId"], func(t *testing.T) {
			t.Parallel()

			options := &cryptopq.StatefulKeyGenOptions{Levels: []cryptopq.HssLevel{{r.header["lmsMode"], r.header["lmOtsMode"]}}, StateStore: &memoryStore{}}

			pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, options, append(decode(t, r.values["i"]), decode(t, r.values["seed"])...), 0)

			check(t, err)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), append([]byte{0, 0, 0, 1}, decode(t, r.values["publicKey"])...), "public key")
		})
	}
}

func TestHssAcvpVerification(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "acvp/LMS-sigVer.txt", "signature") {
		publicKey, err := cryptopq.HSS_LMS.ImportPublicKey(append([]byte{0, 0, 0, 1}, decode(t, r.header["publicKey"])...), cryptopq.RAW)

		check(t, err)

		result := publicKey.Verify(append([]byte{0, 0, 0, 0}, decode(t, r.values["signature"])...), decode(t, r.values["message"]))

		if result != (r.values["testPassed"] == "true") {
			t.Fatalf("tcId %s (%s): got %v", r.values["tcId"], r.values["reason"], result)
		}
	}
}

// The parameters of every level and the leaf index, read from the public key and the signed
// child keys.
func hssLevels(t *testing.T, public, signature []byte) ([]cryptopq.HssLevel, uint64, int) {
	t.Helper()

	count := int(binary.BigEndian.Uint32(public))

	key := public[4:]

	var levels []cryptopq.HssLevel

	var index uint64

	total, offset := 0, 4

	for level := range count {
		lms, height, m := cryptopq.LmsType(binary.BigEndian.Uint32(key))

		ots, otsSize := cryptopq.LmotsType(binary.BigEndian.Uint32(key[4:]))

		levels = append(levels, cryptopq.HssLevel{Lms: lms, Ots: ots})

		index = index<<height | uint64(binary.BigEndian.Uint32(signature[offset:]))

		total += height

		if level+1 < count {
			offset += 8 + otsSize + height*m

			_, _, childM := cryptopq.LmsType(binary.BigEndian.Uint32(signature[offset:]))

			key = signature[offset : offset+24+childM]

			offset += 24 + childM
		}
	}

	return levels, index, total
}

func TestHssRfcVectors(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "rfc/hss.txt", "signature") {
		t.Run(r.values["name"], func(t *testing.T) {
			t.Parallel()

			public, message, signature := decode(t, r.values["publicKey"]), decode(t, r.values["message"]), decode(t, r.values["signature"])

			publicKey, err := cryptopq.HSS_LMS.ImportPublicKey(public, cryptopq.RAW)

			check(t, err)

			if !publicKey.Verify(signature, message) {
				t.Fatal("verify")
			}

			tampered := bytes.Clone(signature)

			tampered[len(tampered)-1] ^= 1

			if publicKey.Verify(tampered, message) || publicKey.Verify(signature, append(bytes.Clone(message), 0)) {
				t.Fatal("accepted a wrong input")
			}

			if _, ok := r.values["seed"]; !ok {
				return
			}

			levels, index, height := hssLevels(t, public, signature)

			// RFC 9858, A.4, has a height-20 tree: a million leaves.
			if height >= 20 && !slow {
				t.Skip("set CRYPTO_PQ_SLOW=1 to build the height-20 tree")
			}

			store := &memoryStore{}

			options := &cryptopq.StatefulKeyGenOptions{Levels: levels, StateStore: store}

			pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, options, append(decode(t, r.values["i"]), decode(t, r.values["seed"])...), index)

			check(t, err)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), public, "public key")

			same(t, sign(t, pair.PrivateKey, message), signature, "signature")
		})
	}
}

func TestHssStateHandling(t *testing.T) {
	t.Parallel()

	store := &memoryStore{}

	pair, err := cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: store})

	check(t, err)

	if pair.PrivateKey.RemainingSignatures() != 32 {
		t.Fatalf("remaining %d", pair.PrivateKey.RemainingSignatures())
	}

	first, second := sign(t, pair.PrivateKey, []byte("one")), sign(t, pair.PrivateKey, []byte("two"))

	if !pair.PublicKey.Verify(first, []byte("one")) || !pair.PublicKey.Verify(second, []byte("two")) || pair.PublicKey.Verify(first, []byte("two")) {
		t.Fatal("verify")
	}

	if pair.PrivateKey.RemainingSignatures() != 30 {
		t.Fatalf("remaining %d", pair.PrivateKey.RemainingSignatures())
	}

	loaded, err := cryptopq.HSS_LMS.LoadPrivateKey(store)

	check(t, err)

	if !loaded.PublicKey().Equal(pair.PublicKey) || loaded.RemainingSignatures() != 30 {
		t.Fatal("load")
	}

	third := sign(t, loaded, []byte("three"))

	if binary.BigEndian.Uint32(third[4:]) != 2 {
		t.Fatalf("index %d", binary.BigEndian.Uint32(third[4:]))
	}

	_, err = pair.PrivateKey.Sign([]byte("stale"))

	expectCode(t, err, cryptopq.STATE_CONFLICT)

	for loaded.RemainingSignatures() > 0 {
		sign(t, loaded, []byte("m"))
	}

	_, err = loaded.Sign([]byte("m"))

	expectCode(t, err, cryptopq.KEY_EXHAUSTED)

	exhausted, err := cryptopq.HSS_LMS.LoadPrivateKey(store)

	check(t, err)

	_, err = exhausted.Sign([]byte("m"))

	expectCode(t, err, cryptopq.KEY_EXHAUSTED)

	_, err = cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: store})

	expectCode(t, err, cryptopq.STATE_CONFLICT)
}

func TestHssStoreFailures(t *testing.T) {
	t.Parallel()

	broken := &brokenStore{}

	pair, err := cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: broken})

	check(t, err)

	_, err = pair.PrivateKey.Sign([]byte("m"))

	expectCode(t, err, cryptopq.STATE_PERSIST_FAILED)

	if pair.PrivateKey.RemainingSignatures() != 32 {
		t.Fatal("a failed write used an index")
	}

	state, _ := broken.Read()

	damaged := bytes.Clone(state)

	damaged[len(damaged)-20] ^= 1

	_, err = cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{state: damaged})

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	_, err = cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{})

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	_, err = cryptopq.XMSS.LoadPrivateKey(&memoryStore{state: state})

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)

	_, err = cryptopq.HSS_LMS.LoadPrivateKey(&unreadableStore{})

	expectCode(t, err, cryptopq.STATE_PERSIST_FAILED)

	_, err = cryptopq.HSS_LMS.LoadPrivateKey(nil)

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	failing := &brokenStore{memoryStore{state: []byte("occupied")}}

	_, err = cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: failing})

	expectCode(t, err, cryptopq.STATE_CONFLICT)
}

// A checksum makes a damaged state fail, so these states are sealed again after each change.
func TestStateValidation(t *testing.T) {
	t.Parallel()

	seal := func(body []byte) []byte {
		return append(bytes.Clone(body), cryptopq.SHA_256.Digest(body)[:16]...)
	}

	options := &cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: &memoryStore{}}

	pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, options, sequence(40), 32)

	check(t, err)

	if pair.PrivateKey.RemainingSignatures() != 0 {
		t.Fatal("remaining")
	}

	_, err = cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, &cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: &memoryStore{}}, sequence(40), 33)

	expectCode(t, err, cryptopq.INVALID_OPTION)

	state, _ := options.StateStore.Read()

	body := state[:len(state)-16]

	loaded, err := cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{state: seal(body)})

	check(t, err)

	if loaded.RemainingSignatures() != 0 {
		t.Fatal("exhausted key")
	}

	beyond := bytes.Clone(body)

	beyond[len(beyond)-1] = 33

	invalid := map[string][]byte{
		"beyond capacity": seal(beyond),
		"version":         seal(append([]byte{2}, body[1:]...)),
		"no levels":       seal([]byte{1, 1, 0}),
		"empty body":      seal([]byte{1, 1}),
		"unknown type":    seal(append([]byte{1, 1, 1, 0, 0, 0, 99}, body[7:]...)),
		"short":           seal(body[:len(body)-1]),
		"long":            seal(append(bytes.Clone(body), 0)),
		"truncated":       state[:17],
	}

	for name, data := range invalid {
		_, err := cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{state: data})

		if !errors.Is(err, cryptopq.INVALID_PRIVATE_KEY) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	xmssBody := append([]byte{1, 2, 0, 0, 0, 1}, make([]byte, 8+96)...)

	_, err = cryptopq.XMSS.LoadPrivateKey(&memoryStore{state: seal(xmssBody[:len(xmssBody)-1])})

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	xmssBody[5] = 0x7f

	_, err = cryptopq.XMSS.LoadPrivateKey(&memoryStore{state: seal(xmssBody)})

	expectCode(t, err, cryptopq.INVALID_PRIVATE_KEY)

	_, err = cryptopq.XMSS_MT.LoadPrivateKey(&memoryStore{state: seal(xmssBody)})

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)
}

func TestHssParameters(t *testing.T) {
	t.Parallel()

	tooHigh := []cryptopq.HssLevel{{"LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"}, {"LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"}, {"LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8"}}

	cases := []*cryptopq.StatefulKeyGenOptions{
		{Levels: nil},
		{Levels: slicesRepeat(small[0], 9)},
		{Levels: []cryptopq.HssLevel{{"LMS_SHA256_M32_H5", "LMOTS_SHA256_N24_W1"}}},
		{Levels: []cryptopq.HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHAKE_N24_W1"}}},
		{Levels: small, Parameters: "LMS_SHA256_M24_H5"},
		{Parameters: "LMS_SHA256_M24_H5"},
		{Levels: []cryptopq.HssLevel{{"LMS_SHA256_M24_H5", ""}}},
		{Levels: []cryptopq.HssLevel{{"LMS_X", "LMOTS_SHA256_N24_W1"}}},
		{Levels: tooHigh},
	}

	for i, options := range cases {
		options.StateStore = &memoryStore{}

		_, err := cryptopq.HSS_LMS.GenerateKeyPair(options)

		if !errors.Is(err, cryptopq.INVALID_OPTION) {
			t.Fatalf("case %d: %v", i, err)
		}
	}

	_, err := cryptopq.HSS_LMS.GenerateKeyPair(nil)

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, &cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: &memoryStore{}}, make([]byte, 39), 0)

	expectCode(t, err, cryptopq.INVALID_LENGTH)
}

func slicesRepeat(level cryptopq.HssLevel, count int) []cryptopq.HssLevel {
	levels := make([]cryptopq.HssLevel, count)

	for i := range levels {
		levels[i] = level
	}

	return levels
}

func TestHssTreeBoundary(t *testing.T) {
	t.Parallel()

	levels := slicesRepeat(cryptopq.HssLevel{Lms: "LMS_SHA256_M24_H5", Ots: "LMOTS_SHA256_N24_W4"}, 2)

	pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, &cryptopq.StatefulKeyGenOptions{Levels: levels, StateStore: &memoryStore{}}, make([]byte, 40), 31)

	check(t, err)

	signatures := [][]byte{sign(t, pair.PrivateKey, []byte{0}), sign(t, pair.PrivateKey, []byte{1})}

	for i, signature := range signatures {
		if !pair.PublicKey.Verify(signature, []byte{byte(i)}) {
			t.Fatalf("signature %d", i)
		}
	}

	if bytes.Equal(signatures[0][4:8], signatures[1][4:8]) {
		t.Fatal("the top tree leaf did not advance")
	}
}

// With three levels, index 32 replaces only the bottom tree and index 1024 the two lower ones.
func TestHssThreeLevels(t *testing.T) {
	t.Parallel()

	levels := slicesRepeat(cryptopq.HssLevel{Lms: "LMS_SHA256_M24_H5", Ots: "LMOTS_SHA256_N24_W8"}, 3)

	for _, start := range []uint64{31, 1023} {
		store := &memoryStore{}

		pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, &cryptopq.StatefulKeyGenOptions{Levels: levels, StateStore: store}, sequence(40), start)

		check(t, err)

		before, after := sign(t, pair.PrivateKey, []byte("before")), sign(t, pair.PrivateKey, []byte("after"))

		if !pair.PublicKey.Verify(before, []byte("before")) || !pair.PublicKey.Verify(after, []byte("after")) || pair.PublicKey.Verify(after, []byte("before")) {
			t.Fatalf("start %d: verify", start)
		}

		loaded, err := cryptopq.HSS_LMS.LoadPrivateKey(store)

		check(t, err)

		if !pair.PublicKey.Verify(sign(t, loaded, []byte("loaded")), []byte("loaded")) || loaded.RemainingSignatures() != 1<<15-start-3 {
			t.Fatalf("start %d: loaded key", start)
		}
	}
}

func TestHssFormats(t *testing.T) {
	t.Parallel()

	pair, err := cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: &memoryStore{}})

	check(t, err)

	for _, format := range []cryptopq.KeyFormat{cryptopq.RAW, cryptopq.DER, cryptopq.PEM} {
		public, err := cryptopq.HSS_LMS.ImportPublicKey(export(t, pair.PublicKey, format), format)

		check(t, err)

		if !public.Equal(pair.PublicKey) {
			t.Fatalf("%s: round trip", format)
		}
	}

	encoded := export(t, pair.PublicKey, cryptopq.DER)

	if !bytes.Contains(encoded, decode(t, "060b2a864886f70d0109100311")) {
		t.Fatal("OID")
	}

	raw := export(t, pair.PublicKey, cryptopq.RAW)

	_, err = cryptopq.HSS_LMS.ImportPublicKey(append([]byte{0, 0, 0, 9}, raw[4:]...), cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_PUBLIC_KEY)

	_, err = cryptopq.HSS_LMS.ImportPublicKey(raw[:len(raw)-1], cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_PUBLIC_KEY)

	oid := decode(t, "060b2a864886f70d0109100311")

	_, err = cryptopq.HSS_LMS.ImportPublicKey(der(0x30, der(0x30, oid), der(0x03, append([]byte{0}, raw[1:]...))), cryptopq.DER)

	expectCode(t, err, cryptopq.INVALID_PUBLIC_KEY)

	_, err = cryptopq.XMSS.ImportPublicKey(encoded, cryptopq.DER)

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)
}

func TestXmssReferenceVectors(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "xmss/xmss.txt", "signature") {
		t.Run(r.values["name"]+"/"+r.values["index"], func(t *testing.T) {
			t.Parallel()

			name := r.values["name"]

			algorithm := cryptopq.XMSS

			if strings.HasPrefix(name, "XMSSMT") {
				algorithm = cryptopq.XMSS_MT
			}

			index, err := strconv.ParseUint(r.values["index"], 10, 64)

			check(t, err)

			public, message, signature := decode(t, r.values["publicKey"]), decode(t, r.values["message"]), decode(t, r.values["signature"])

			publicKey, err := algorithm.ImportPublicKey(public, cryptopq.RAW)

			check(t, err)

			tampered := bytes.Clone(signature)

			tampered[len(tampered)-1] ^= 1

			if !publicKey.Verify(signature, message) || publicKey.Verify(tampered, message) {
				t.Fatal("verify")
			}

			options := &cryptopq.StatefulKeyGenOptions{Parameters: name, StateStore: &memoryStore{}}

			pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(algorithm, options, decode(t, r.values["seed"]), index)

			check(t, err)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), public, "public key")

			same(t, sign(t, pair.PrivateKey, message), signature, "signature")
		})
	}
}

func TestXmssStateHandling(t *testing.T) {
	t.Parallel()

	store := &memoryStore{}

	pair, err := cryptopq.XMSS_MT.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Parameters: "XMSSMT-SHAKE256_20/4_192", StateStore: store})

	check(t, err)

	if !pair.PublicKey.Verify(sign(t, pair.PrivateKey, []byte("message")), []byte("message")) {
		t.Fatal("verify")
	}

	loaded, err := cryptopq.XMSS_MT.LoadPrivateKey(store)

	check(t, err)

	if loaded.RemainingSignatures() != 1<<20-1 || !loaded.PublicKey().Equal(pair.PublicKey) {
		t.Fatal("load")
	}

	if !pair.PublicKey.Verify(sign(t, loaded, []byte("loaded")), []byte("loaded")) {
		t.Fatal("sign after load")
	}

	for _, format := range []cryptopq.KeyFormat{cryptopq.RAW, cryptopq.DER, cryptopq.PEM} {
		public, err := cryptopq.XMSS_MT.ImportPublicKey(export(t, pair.PublicKey, format), format)

		check(t, err)

		if !public.Equal(pair.PublicKey) {
			t.Fatalf("%s: round trip", format)
		}
	}

	_, err = cryptopq.XMSS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Parameters: "XMSSMT-SHAKE256_20/4_192", StateStore: &memoryStore{}})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.XMSS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Parameters: "XMSS-SHA2_10_256", Levels: small, StateStore: &memoryStore{}})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.XMSS.ImportPublicKey(export(t, pair.PublicKey, cryptopq.RAW), cryptopq.RAW)

	expectCode(t, err, cryptopq.INVALID_PUBLIC_KEY)

	_, err = cryptopq.XMSS.ImportPublicKey(export(t, pair.PublicKey, cryptopq.DER), cryptopq.DER)

	expectCode(t, err, cryptopq.ALGORITHM_MISMATCH)
}

// State blobs and public keys computed with the Python reference: every language must produce
// and load exactly these bytes.
func TestCrossLanguageState(t *testing.T) {
	t.Parallel()

	store := &memoryStore{}

	pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.HSS_LMS, &cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: store}, sequence(40), 3)

	check(t, err)

	hssState := "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627000000000000000332b414e1d42dc2866aeed26f724a5be7"

	hssPublic := "000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6ea3163d0e60e423ce46b051b"

	same(t, store.state, decode(t, hssState), "HSS state")

	same(t, export(t, pair.PublicKey, cryptopq.RAW), decode(t, hssPublic), "HSS public key")

	signature := sign(t, pair.PrivateKey, []byte("crypto-pq"))

	same(t, store.state, decode(t, "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700000000000000047bc402dcf96640ca1c7126fe316fef60"), "HSS state after signing")

	if hex.EncodeToString(cryptopq.SHA_256.Digest(signature)) != "07cb93b630cdd6b575402bcdbce2024b6a88bfdb419d9c7b920c250d7273a5a6" {
		t.Fatal("HSS signature")
	}

	store = &memoryStore{}

	pair, err = cryptopq.Hazmat.GenerateStatefulKeyPair(cryptopq.XMSS_MT, &cryptopq.StatefulKeyGenOptions{Parameters: "XMSSMT-SHAKE256_20/4_192", StateStore: store}, sequence(72), 5)

	check(t, err)

	xmssState := "0103000000320000000000000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647e0dc0d3f343f3dbd989a24e2ad453440"

	xmssPublic := "00000032296d594ddd9688b47a9c461c70e3d9f29e901b8cedcaaa4c303132333435363738393a3b3c3d3e3f4041424344454647"

	same(t, store.state, decode(t, xmssState), "XMSS^MT state")

	same(t, export(t, pair.PublicKey, cryptopq.RAW), decode(t, xmssPublic), "XMSS^MT public key")

	for _, c := range []struct {
		algorithm     cryptopq.StatefulSignatureAlgorithm
		state, public string
	}{{cryptopq.HSS_LMS, hssState, hssPublic}, {cryptopq.XMSS_MT, xmssState, xmssPublic}} {
		loaded, err := c.algorithm.LoadPrivateKey(&memoryStore{state: decode(t, c.state)})

		check(t, err)

		same(t, export(t, loaded.PublicKey(), cryptopq.RAW), decode(t, c.public), c.algorithm.Name()+" loaded")
	}
}

// Sign holds a lock: concurrent calls get distinct indices and the store sees every one.
func TestStatefulConcurrentSigning(t *testing.T) {
	t.Parallel()

	store := &memoryStore{}

	pair, err := cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: small, StateStore: store})

	check(t, err)

	signatures := make([][]byte, 16)

	var group sync.WaitGroup

	for i := range signatures {
		group.Go(func() {
			signatures[i], _ = pair.PrivateKey.Sign([]byte{byte(i)})
		})
	}

	group.Wait()

	seen := map[uint32]bool{}

	for i, signature := range signatures {
		if !pair.PublicKey.Verify(signature, []byte{byte(i)}) {
			t.Fatalf("signature %d", i)
		}

		seen[binary.BigEndian.Uint32(signature[4:])] = true
	}

	if len(seen) != len(signatures) || pair.PrivateKey.RemainingSignatures() != 16 {
		t.Fatal("indices were reused")
	}

	loaded, err := cryptopq.HSS_LMS.LoadPrivateKey(store)

	check(t, err)

	if loaded.RemainingSignatures() != 16 {
		t.Fatal("store")
	}
}
