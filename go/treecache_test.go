package cryptopq_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var (
	cacheTwo = []cryptopq.HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"}, {"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"}}

	cacheThree = []cryptopq.HssLevel{{"LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"}, {"LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1"}, {"LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"}}

	cacheLabel = []byte("crypto-pq tree cache v1")
)

const cacheMt = "XMSSMT-SHA2_20/4_192"

// A stateful key made from a fixed seed, at any index.
type cacheKey struct {
	algorithm cryptopq.StatefulSignatureAlgorithm
	options   cryptopq.StatefulKeyGenOptions
	seed      []byte
}

func hssCacheKey(levels []cryptopq.HssLevel, seed []byte) cacheKey {
	return cacheKey{cryptopq.HSS_LMS, cryptopq.StatefulKeyGenOptions{Levels: levels}, seed}
}

func xmssCacheKey(algorithm cryptopq.StatefulSignatureAlgorithm, parameters string, seed []byte) cacheKey {
	return cacheKey{algorithm, cryptopq.StatefulKeyGenOptions{Parameters: parameters}, seed}
}

// The key at index and the store that holds its state.
func (k cacheKey) at(t *testing.T, index uint64) (*cryptopq.StatefulKeyPair, *memoryStore) {
	t.Helper()

	options, store := k.options, &memoryStore{}

	options.StateStore = store

	pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(k.algorithm, &options, k.seed, index)

	check(t, err)

	return pair, store
}

func (k cacheKey) state(t *testing.T, index uint64) []byte {
	t.Helper()

	_, store := k.at(t, index)

	return store.state
}

// The key at index, after it signed there when signed is set, so that it holds a tree on every
// level; the state it stored and its cache.
func (k cacheKey) exported(t *testing.T, index uint64, signed bool) (*cryptopq.StatefulKeyPair, []byte, []byte) {
	t.Helper()

	pair, store := k.at(t, index)

	if signed {
		sign(t, pair.PrivateKey, []byte("first"))
	}

	return pair, store.state, exportCache(t, pair.PrivateKey)
}

func exportCache(t *testing.T, key *cryptopq.StatefulPrivateKey) []byte {
	t.Helper()

	cache, err := key.ExportTreeCache()

	check(t, err)

	return cache
}

func loadCached(algorithm cryptopq.StatefulSignatureAlgorithm, state, cache []byte) (*cryptopq.StatefulPrivateKey, error) {
	return algorithm.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, &cryptopq.StatefulLoadOptions{TreeCache: cache})
}

func refuses(t *testing.T, code cryptopq.ErrorCode, algorithm cryptopq.StatefulSignatureAlgorithm, state, cache []byte, context string) {
	t.Helper()

	if _, err := loadCached(algorithm, state, cache); !errors.Is(err, code) {
		t.Fatalf("%s: got error %v, want %s", context, err, code)
	}
}

// The key loaded with the cache signs as the key loaded without it.
func assertLoads(t *testing.T, algorithm cryptopq.StatefulSignatureAlgorithm, state, cache []byte, context string) {
	t.Helper()

	loaded, err := loadCached(algorithm, state, cache)

	if err != nil {
		t.Fatalf("%s: %v", context, err)
	}

	plain, err := algorithm.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, nil)

	check(t, err)

	if !loaded.PublicKey().Equal(plain.PublicKey()) || loaded.RemainingSignatures() != plain.RemainingSignatures() {
		t.Fatalf("%s: the key loaded with the cache differs", context)
	}

	if plain.RemainingSignatures() > 0 {
		same(t, sign(t, loaded, []byte("next")), sign(t, plain, []byte("next")), context)
	}
}

func flipped(data []byte, position int, mask byte) []byte {
	out := bytes.Clone(data)

	out[position] ^= mask

	return out
}

func replaced(data []byte, position int, value ...byte) []byte {
	out := bytes.Clone(data)

	copy(out[position:], value)

	return out
}

type cacheTree struct {
	level, low, height, n byte
	number                uint64
	count                 uint32
	nodes                 []byte
}

// A tree cache taken apart, so that a test can change one field and seal it again with the key's
// seed: only then do the checks after the tag see the change. The parameters are an HSS level
// count and a pair of type codes per level, or an XMSS OID.
type cacheParts struct {
	version, kind         byte
	parameters, publicKey []byte
	trees                 []cacheTree
}

func splitCache(data []byte) *cacheParts {
	end := 6

	if data[1] == 1 {
		end = 3 + 8*int(data[2])
	}

	size := int(binary.BigEndian.Uint32(data[end:]))

	parts := &cacheParts{version: data[0], kind: data[1], parameters: bytes.Clone(data[2:end]), publicKey: bytes.Clone(data[end+4 : end+4+size])}

	offset := end + 5 + size

	for range int(data[end+4+size]) {
		tree := cacheTree{level: data[offset], number: binary.BigEndian.Uint64(data[offset+1:]), low: data[offset+9], height: data[offset+10], n: data[offset+11], count: binary.BigEndian.Uint32(data[offset+12:])}

		tree.nodes = bytes.Clone(data[offset+16 : offset+16+int(tree.count)*int(tree.n)])

		parts.trees = append(parts.trees, tree)

		offset += 16 + len(tree.nodes)
	}

	return parts
}

// Where the nodes of tree i start.
func (c *cacheParts) nodesAt(i int) int {
	offset := 7 + len(c.parameters) + len(c.publicKey)

	for _, tree := range c.trees[:i] {
		offset += 16 + len(tree.nodes)
	}

	return offset + 16
}

// Each tree's level, number, lowest cached height, height, n and node count.
func (c *cacheParts) shapes() [][6]uint64 {
	var shapes [][6]uint64

	for _, tree := range c.trees {
		shapes = append(shapes, [6]uint64{uint64(tree.level), tree.number, uint64(tree.low), uint64(tree.height), uint64(tree.n), uint64(tree.count)})
	}

	return shapes
}

// The cache again, tagged with the public HMAC under the key that the seed gives.
func (c *cacheParts) seal(seed []byte) []byte {
	body := append([]byte{c.version, c.kind}, c.parameters...)

	body = binary.BigEndian.AppendUint32(body, uint32(len(c.publicKey)))

	body = append(body, c.publicKey...)

	body = append(body, byte(len(c.trees)))

	for _, tree := range c.trees {
		body = append(body, tree.level)

		body = binary.BigEndian.AppendUint64(body, tree.number)

		body = append(body, tree.low, tree.height, tree.n)

		body = binary.BigEndian.AppendUint32(body, tree.count)

		body = append(body, tree.nodes...)
	}

	return append(body, cryptopq.HMAC_SHA_256.Digest(cryptopq.HMAC_SHA_256.Digest(cacheLabel, seed), body)...)
}

func sealed(cache, seed []byte, edits ...func(*cacheParts)) []byte {
	parts := splitCache(cache)

	for _, edit := range edits {
		edit(parts)
	}

	return parts.seal(seed)
}

func changedNode(i, position int) func(*cacheParts) {
	return func(c *cacheParts) {
		c.trees[i].nodes = flipped(c.trees[i].nodes, position, 1)
	}
}

func renumbered(i int, number uint64) func(*cacheParts) {
	return func(c *cacheParts) {
		c.trees[i].number = number
	}
}

func atLevel(i int, level byte) func(*cacheParts) {
	return func(c *cacheParts) {
		c.trees[i].level = level
	}
}

// A tree of another shape, with as many node bytes as its header claims.
func reshaped(i int, low, height, n byte, count uint32) func(*cacheParts) {
	return func(c *cacheParts) {
		tree := &c.trees[i]

		nodes := make([]byte, int(n)*int(count))

		for j := range nodes {
			nodes[j] = tree.nodes[j%len(tree.nodes)]
		}

		tree.low, tree.height, tree.n, tree.count, tree.nodes = low, height, n, count, nodes
	}
}

func keptTrees(order ...int) func(*cacheParts) {
	return func(c *cacheParts) {
		trees := make([]cacheTree, len(order))

		for j, i := range order {
			trees[j] = c.trees[i]
		}

		c.trees = trees
	}
}

func changedKey(change func([]byte) []byte) func(*cacheParts) {
	return func(c *cacheParts) {
		c.publicKey = change(bytes.Clone(c.publicKey))
	}
}

func changedParameters(t *testing.T, value string) func(*cacheParts) {
	return func(c *cacheParts) {
		c.parameters = decode(t, value)
	}
}

// An HSS state at another index, sealed again.
func hssStateAt(state []byte, index uint64) []byte {
	body := bytes.Clone(state[:len(state)-16])

	binary.BigEndian.PutUint64(body[len(body)-8:], index)

	return append(body, cryptopq.SHA_256.Digest(body)[:16]...)
}

// A key loaded with the cache signs as one loaded without it, verifies, and exports the same cache.
func TestTreeCacheRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key   cacheKey
		index uint64
	}{
		{hssCacheKey(cacheTwo, sequence(40)), 40},
		{hssCacheKey(cacheThree, sequence(48)), 5000},
		{xmssCacheKey(cryptopq.XMSS_MT, cacheMt, sequence(72)), 0x12345},
		{xmssCacheKey(cryptopq.XMSS, "XMSS-SHA2_10_192", sequence(72)), 1000},
	}

	for _, c := range cases {
		algorithm := c.key.algorithm

		context := algorithm.Name() + " at " + strconv.FormatUint(c.index, 10)

		pair, state, cache := c.key.exported(t, c.index, true)

		loaded, err := loadCached(algorithm, state, cache)

		check(t, err)

		plain, err := algorithm.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, nil)

		check(t, err)

		if !loaded.PublicKey().Equal(pair.PublicKey) || loaded.RemainingSignatures() != plain.RemainingSignatures() {
			t.Fatalf("%s: the loaded key differs", context)
		}

		same(t, exportCache(t, loaded), cache, context)

		for _, message := range [][]byte{[]byte("second"), []byte("third")} {
			signature := sign(t, loaded, message)

			if !pair.PublicKey.Verify(signature, message) {
				t.Fatalf("%s: the signature does not verify", context)
			}

			same(t, signature, sign(t, plain, message), context)
		}

		same(t, exportCache(t, loaded), exportCache(t, plain), context)
	}
}

func TestTreeCacheFormat(t *testing.T) {
	t.Parallel()

	seed := sequence(40)

	key := hssCacheKey(cacheTwo, seed)

	pair, _, cache := key.exported(t, 40, true)

	parts, public := splitCache(cache), export(t, pair.PublicKey, cryptopq.RAW)

	if parts.version != 1 || parts.kind != 1 || !bytes.Equal(parts.publicKey, public) {
		t.Fatal("HSS header")
	}

	same(t, parts.parameters, decode(t, "02"+"0000000a00000007"+"0000000a00000006"), "HSS parameters")

	if !slices.Equal(parts.shapes(), [][6]uint64{{0, 0, 0, 5, 24, 63}, {1, 1, 0, 5, 24, 63}}) {
		t.Fatalf("HSS trees %v", parts.shapes())
	}

	top := parts.trees[0].nodes

	same(t, top[len(top)-24:], public[len(public)-24:], "HSS top root")

	same(t, parts.seal(seed), cache, "HSS tag")

	_, _, fresh := key.exported(t, 40, false)

	if before := splitCache(fresh); len(before.trees) != 1 || !bytes.Equal(before.trees[0].nodes, top) || before.shapes()[0] != parts.shapes()[0] {
		t.Fatal("HSS before signing")
	}

	seed = sequence(72)

	pair, _, cache = xmssCacheKey(cryptopq.XMSS_MT, cacheMt, seed).exported(t, 0x12345, true)

	parts, public = splitCache(cache), export(t, pair.PublicKey, cryptopq.RAW)

	if parts.version != 1 || parts.kind != 3 || !bytes.Equal(parts.parameters, []byte{0, 0, 0, 0x22}) || !bytes.Equal(parts.publicKey, public) {
		t.Fatal("XMSS^MT header")
	}

	if !slices.Equal(parts.shapes(), [][6]uint64{{3, 0, 0, 5, 24, 63}, {2, 2, 0, 5, 24, 63}, {1, 72, 0, 5, 24, 63}, {0, 2330, 0, 5, 24, 63}}) {
		t.Fatalf("XMSS^MT trees %v", parts.shapes())
	}

	top = parts.trees[0].nodes

	same(t, top[len(top)-24:], public[4:28], "XMSS^MT top root")

	same(t, parts.seal(seed), cache, "XMSS^MT tag")

	pair, _, cache = xmssCacheKey(cryptopq.XMSS, "XMSS-SHA2_10_192", seed).exported(t, 1000, true)

	parts, public = splitCache(cache), export(t, pair.PublicKey, cryptopq.RAW)

	if parts.version != 1 || parts.kind != 2 || !bytes.Equal(parts.parameters, []byte{0, 0, 0, 0x0d}) || !bytes.Equal(parts.publicKey, public) {
		t.Fatal("XMSS header")
	}

	if !slices.Equal(parts.shapes(), [][6]uint64{{0, 0, 0, 10, 24, 2047}}) {
		t.Fatalf("XMSS trees %v", parts.shapes())
	}

	same(t, parts.seal(seed), cache, "XMSS tag")
}

func TestTreeCacheRejections(t *testing.T) {
	t.Parallel()

	seed := sequence(40)

	key := hssCacheKey(cacheTwo, seed)

	_, state, cache := key.exported(t, 40, true)

	parts := splitCache(cache)

	_, _, another := hssCacheKey(cacheTwo, make([]byte, 40)).exported(t, 40, true)

	// The public key length follows the version, the kind and the parameters.
	keyAt := 2 + len(parts.parameters)

	invalid := []struct {
		name string
		data []byte
	}{
		{"level 0 node changed", flipped(cache, parts.nodesAt(0)+5, 1)},
		{"level 1 node changed", flipped(cache, parts.nodesAt(1)+30, 1)},
		{"first tag byte changed", flipped(cache, len(cache)-32, 1)},
		{"last tag byte changed", flipped(cache, len(cache)-1, 1)},
		{"version 0", replaced(cache, 0, 0)},
		{"version 2", replaced(cache, 0, 2)},
		{"version 2 and kind 2", replaced(cache, 0, 2, 2)},
		{"cut and kind 2", replaced(cache, 1, 2)[:len(cache)-1]},
		{"cut in the parameters", cache[:10]},
		{"one byte appended", append(bytes.Clone(cache), 0)},
		{"a second tag appended", append(bytes.Clone(cache), cache[len(cache)-32:]...)},
		{"another key", another},
		{"empty", []byte{}},
		{"public key length beyond the cache", replaced(cache, keyAt, 0xff, 0xff, 0xff, 0xff)},
		{"node count beyond the cache", replaced(cache, parts.nodesAt(0)-4, 0xff, 0xff, 0xff, 0xff)},
	}

	for _, c := range invalid {
		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, state, c.data, c.name)
	}

	for length := range len(cache) {
		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, state, cache[:length], "cut to "+strconv.Itoa(length))
	}

	// Another kind reads the HSS parameters with its own layout, or with none, and finds the cache
	// malformed; a cache made for another algorithm is ALGORITHM_MISMATCH.
	for _, kind := range []byte{0, 2, 3, 4} {
		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, state, replaced(cache, 1, kind), "kind "+strconv.Itoa(int(kind)))
	}

	_, mtState, mtCache := xmssCacheKey(cryptopq.XMSS_MT, cacheMt, sequence(72)).exported(t, 0x12345, true)

	refuses(t, cryptopq.ALGORITHM_MISMATCH, cryptopq.HSS_LMS, state, mtCache, "an XMSS^MT cache")

	refuses(t, cryptopq.ALGORITHM_MISMATCH, cryptopq.XMSS_MT, mtState, cache, "an HSS cache")

	// The same seed with another type below the top: the public key and the tag key are the same,
	// and only the parameters tell the keys apart.
	for _, lower := range []cryptopq.HssLevel{{"LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"}, {"LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2"}} {
		other := hssCacheKey([]cryptopq.HssLevel{cacheTwo[0], lower}, seed).state(t, 41)

		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, other, cache, lower.Lms+" "+lower.Ots)
	}

	// The same I with another SEED: the public parts match, the tag does not.
	other := hssCacheKey(cacheTwo, append(bytes.Clone(seed[:16]), make([]byte, 24)...)).state(t, 41)

	refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, other, cache, "another SEED")

	// The state is checked before the cache.
	capacity := key.state(t, 1024)

	refuses(t, cryptopq.INVALID_PRIVATE_KEY, cryptopq.HSS_LMS, state[:len(state)-1], cache, "a damaged state")

	refuses(t, cryptopq.INVALID_PRIVATE_KEY, cryptopq.HSS_LMS, hssStateAt(capacity, 1025), cache, "an index beyond the capacity")

	refuses(t, cryptopq.INVALID_PRIVATE_KEY, cryptopq.HSS_LMS, hssStateAt(capacity, 1025), []byte{}, "an index beyond the capacity and an empty cache")

	exhausted, err := loadCached(cryptopq.HSS_LMS, capacity, cache)

	check(t, err)

	if exhausted.RemainingSignatures() != 0 {
		t.Fatal("the key at the capacity")
	}

	// The level-1 tree of index 40 is tree 1, which index 64 has left.
	assertLoads(t, cryptopq.HSS_LMS, key.state(t, 64), cache, "stale level 1")

	// The key reads the cache once: changing it afterwards changes nothing.
	copied := bytes.Clone(cache)

	loaded, err := loadCached(cryptopq.HSS_LMS, state, copied)

	check(t, err)

	clear(copied)

	same(t, exportCache(t, loaded), cache, "the cache changed after the load")

	// Nil is no cache at all, and Reserve still applies with a cache.
	plain, err := cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, &cryptopq.StatefulLoadOptions{})

	check(t, err)

	store := &memoryStore{state: bytes.Clone(state)}

	reserving, err := cryptopq.HSS_LMS.LoadPrivateKey(store, &cryptopq.StatefulLoadOptions{Reserve: 3, TreeCache: cache})

	check(t, err)

	same(t, sign(t, reserving, []byte("m")), sign(t, plain, []byte("m")), "reserve")

	same(t, store.state, hssStateAt(state, 44), "the reserved state")
}

// Changes sealed with the key's seed, which only the checks after the tag can catch.
func TestTreeCacheSealedChanges(t *testing.T) {
	t.Parallel()

	seed := sequence(40)

	key := hssCacheKey(cacheTwo, seed)

	_, state, cache := key.exported(t, 40, true)

	// At the capacity no lower tree is needed, and the top tree is still tree 0.
	later, capacity := key.state(t, 64), key.state(t, 1024)

	w4, w2, w8 := "0000000a00000007", "0000000a00000006", "0000000a00000008"

	cases := []struct {
		name  string
		edits []func(*cacheParts)
		at    []byte
		code  cryptopq.ErrorCode
	}{
		{"level 1 node changed", []func(*cacheParts){changedNode(1, 7)}, state, cryptopq.INVALID_ENCODING},
		{"level 1 root changed", []func(*cacheParts){changedNode(1, 62*24)}, state, cryptopq.INVALID_ENCODING},
		{"level 0 leaf changed", []func(*cacheParts){changedNode(0, 0)}, state, cryptopq.INVALID_ENCODING},
		{"level 0 root changed", []func(*cacheParts){changedNode(0, 62*24+23)}, state, cryptopq.INVALID_ENCODING},
		{"stale level 1 node changed", []func(*cacheParts){changedNode(1, 7)}, later, ""},
		{"level 1 claimed as tree 2", []func(*cacheParts){renumbered(1, 2)}, later, cryptopq.INVALID_ENCODING},
		{"level 1 as tree 2 for index 41", []func(*cacheParts){renumbered(1, 2)}, state, ""},
		{"top tree numbered 1", []func(*cacheParts){renumbered(0, 1)}, state, ""},
		{"top tree of all ones", []func(*cacheParts){renumbered(0, 1<<64-1)}, state, ""},
		{"no trees", []func(*cacheParts){keptTrees()}, state, ""},
		{"top tree only", []func(*cacheParts){keptTrees(0)}, state, ""},
		{"level 1 only", []func(*cacheParts){keptTrees(1)}, state, ""},
		{"levels swapped", []func(*cacheParts){keptTrees(1, 0)}, state, cryptopq.INVALID_ENCODING},
		{"level 0 twice", []func(*cacheParts){keptTrees(0, 0)}, state, cryptopq.INVALID_ENCODING},
		{"level 1 twice", []func(*cacheParts){keptTrees(0, 1, 1)}, state, cryptopq.INVALID_ENCODING},
		{"level 2", []func(*cacheParts){atLevel(1, 2)}, state, cryptopq.INVALID_ENCODING},
		{"level 255", []func(*cacheParts){atLevel(1, 255)}, state, cryptopq.INVALID_ENCODING},
		{"height 6", []func(*cacheParts){reshaped(1, 0, 6, 24, 127)}, state, cryptopq.INVALID_ENCODING},
		{"height 4", []func(*cacheParts){reshaped(1, 0, 4, 24, 31)}, state, cryptopq.INVALID_ENCODING},
		{"n 32", []func(*cacheParts){reshaped(1, 0, 5, 32, 63)}, state, cryptopq.INVALID_ENCODING},
		{"n 0", []func(*cacheParts){reshaped(1, 0, 5, 0, 63)}, state, cryptopq.INVALID_ENCODING},
		{"lowest height 1", []func(*cacheParts){reshaped(1, 1, 5, 24, 31)}, state, cryptopq.INVALID_ENCODING},
		{"one node less", []func(*cacheParts){reshaped(1, 0, 5, 24, 62)}, state, cryptopq.INVALID_ENCODING},
		{"one node more", []func(*cacheParts){reshaped(1, 0, 5, 24, 64)}, state, cryptopq.INVALID_ENCODING},
		{"stale level 1 of another height", []func(*cacheParts){renumbered(1, 0), reshaped(1, 0, 6, 24, 127)}, later, cryptopq.INVALID_ENCODING},
		{"public key one byte longer", []func(*cacheParts){changedKey(func(key []byte) []byte { return append(key, 0) })}, state, cryptopq.INVALID_ENCODING},
		{"public key one byte shorter", []func(*cacheParts){changedKey(func(key []byte) []byte { return key[:len(key)-1] })}, state, cryptopq.INVALID_ENCODING},
		{"public key of three levels", []func(*cacheParts){changedKey(func(key []byte) []byte { return replaced(key, 3, 3) })}, state, cryptopq.INVALID_ENCODING},
		{"public key root changed", []func(*cacheParts){changedKey(func(key []byte) []byte { return flipped(key, len(key)-1, 1) })}, state, cryptopq.INVALID_ENCODING},
		{"public key empty", []func(*cacheParts){changedKey(func([]byte) []byte { return nil })}, state, cryptopq.INVALID_ENCODING},
		{"lower level of another LM-OTS type", []func(*cacheParts){changedParameters(t, "02"+w4+w8)}, state, cryptopq.INVALID_ENCODING},
		{"one level", []func(*cacheParts){changedParameters(t, "01"+w4)}, state, cryptopq.INVALID_ENCODING},
		{"levels in another order", []func(*cacheParts){changedParameters(t, "02"+w2+w4)}, state, cryptopq.INVALID_ENCODING},
		{"no level", []func(*cacheParts){changedParameters(t, "00")}, state, cryptopq.INVALID_ENCODING},
		{"top node changed at the capacity", []func(*cacheParts){changedNode(0, 5)}, capacity, cryptopq.INVALID_ENCODING},
		{"top tree 1 changed at the capacity", []func(*cacheParts){renumbered(0, 1), changedNode(0, 5)}, capacity, ""},
		{"level 1 as tree 32 at the capacity", []func(*cacheParts){renumbered(1, 32), changedNode(1, 5)}, capacity, cryptopq.INVALID_ENCODING},
	}

	for _, c := range cases {
		data := sealed(cache, seed, c.edits...)

		if c.code == "" {
			assertLoads(t, cryptopq.HSS_LMS, c.at, data, c.name)
		} else {
			refuses(t, c.code, cryptopq.HSS_LMS, c.at, data, c.name)
		}
	}
}

func TestXmssMtTreeCacheRejections(t *testing.T) {
	t.Parallel()

	seed := sequence(72)

	key := xmssCacheKey(cryptopq.XMSS_MT, cacheMt, seed)

	_, state, cache := key.exported(t, 0x12345, true)

	// 0x12360 signs with the next tree of layer 0.
	later, capacity := key.state(t, 0x12360), key.state(t, 1<<20)

	parts := splitCache(cache)

	_, _, another := xmssCacheKey(cryptopq.XMSS_MT, cacheMt, make([]byte, 72)).exported(t, 0x12345, true)

	invalid := []struct {
		name string
		data []byte
	}{
		{"layer 0 node changed", flipped(cache, parts.nodesAt(3)+100, 1)},
		{"tag changed", flipped(cache, len(cache)-7, 1)},
		{"one byte appended", append(bytes.Clone(cache), 0)},
		{"cut", cache[:len(cache)-1]},
		{"another key", another},
	}

	for _, c := range invalid {
		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.XMSS_MT, state, c.data, c.name)
	}

	// XMSS shares the layout, so its kind is a mismatch; the HSS layout misreads the OID, and no
	// other kind has a layout.
	refuses(t, cryptopq.ALGORITHM_MISMATCH, cryptopq.XMSS_MT, state, replaced(cache, 1, 2), "kind 2")

	for _, kind := range []byte{0, 1, 4} {
		refuses(t, cryptopq.INVALID_ENCODING, cryptopq.XMSS_MT, state, replaced(cache, 1, kind), "kind "+strconv.Itoa(int(kind)))
	}

	refuses(t, cryptopq.INVALID_ENCODING, cryptopq.XMSS_MT, xmssCacheKey(cryptopq.XMSS_MT, "XMSSMT-SHA2_20/2_192", seed).state(t, 7), cache, "another parameter set")

	// The same PUB_SEED with other secret seeds: the public parts match, the tag does not.
	other := xmssCacheKey(cryptopq.XMSS_MT, cacheMt, append(make([]byte, 48), seed[48:]...)).state(t, 0x12346)

	refuses(t, cryptopq.INVALID_ENCODING, cryptopq.XMSS_MT, other, cache, "other secret seeds")

	cases := []struct {
		name  string
		edits []func(*cacheParts)
		at    []byte
		code  cryptopq.ErrorCode
	}{
		{"layer 0 node changed", []func(*cacheParts){changedNode(3, 40)}, state, cryptopq.INVALID_ENCODING},
		{"layer 2 root changed", []func(*cacheParts){changedNode(1, 62*24)}, state, cryptopq.INVALID_ENCODING},
		{"stale layer 0 node changed", []func(*cacheParts){changedNode(3, 40)}, later, ""},
		{"layer 0 as tree 2331", []func(*cacheParts){renumbered(3, 2331)}, later, cryptopq.INVALID_ENCODING},
		{"layers swapped", []func(*cacheParts){keptTrees(0, 2, 1, 3)}, state, cryptopq.INVALID_ENCODING},
		{"layer 2 twice", []func(*cacheParts){keptTrees(0, 1, 1, 2, 3)}, state, cryptopq.INVALID_ENCODING},
		{"layer 4", []func(*cacheParts){atLevel(0, 4)}, state, cryptopq.INVALID_ENCODING},
		{"top layer only", []func(*cacheParts){keptTrees(0)}, state, ""},
		{"no top layer", []func(*cacheParts){keptTrees(1, 2, 3)}, state, ""},
		{"layer 0 only", []func(*cacheParts){keptTrees(3)}, state, ""},
		{"top node changed at the capacity", []func(*cacheParts){changedNode(0, 9)}, capacity, cryptopq.INVALID_ENCODING},
		{"top tree 1 changed at the capacity", []func(*cacheParts){changedNode(0, 9), renumbered(0, 1)}, capacity, ""},
		{"height 10", []func(*cacheParts){reshaped(2, 0, 10, 24, 2047)}, state, cryptopq.INVALID_ENCODING},
		{"n 32", []func(*cacheParts){reshaped(2, 0, 5, 32, 63)}, state, cryptopq.INVALID_ENCODING},
		{"public seed changed", []func(*cacheParts){changedKey(func(key []byte) []byte { return flipped(key, len(key)-1, 1) })}, state, cryptopq.INVALID_ENCODING},
		{"root changed", []func(*cacheParts){changedKey(func(key []byte) []byte { return flipped(key, 4, 1) })}, state, cryptopq.INVALID_ENCODING},
		{"parameters of another set", []func(*cacheParts){changedParameters(t, "00000021")}, state, cryptopq.INVALID_ENCODING},
	}

	for _, c := range cases {
		data := sealed(cache, seed, c.edits...)

		if c.code == "" {
			assertLoads(t, cryptopq.XMSS_MT, c.at, data, c.name)
		} else {
			refuses(t, c.code, cryptopq.XMSS_MT, c.at, data, c.name)
		}
	}

	assertLoads(t, cryptopq.XMSS_MT, later, cache, "stale layer 0")
}

// Every change of one bit, the lowest or the highest of a byte, gives INVALID_ENCODING and never
// loads: the kind byte becomes 0 or 0x81, no kind at all.
func TestTreeCacheEveryChange(t *testing.T) {
	t.Parallel()

	_, state, cache := hssCacheKey(cacheTwo[:1], sequence(40)).exported(t, 5, true)

	for position := range cache {
		for _, mask := range []byte{0x01, 0x80} {
			refuses(t, cryptopq.INVALID_ENCODING, cryptopq.HSS_LMS, state, flipped(cache, position, mask), "byte "+strconv.Itoa(position))
		}
	}
}

// A load with the cache computes no leaf; the trees that the next index has left are built.
func TestTreeCacheSkipsTheBuild(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key          cacheKey
		index, later uint64
		trees        uint64
	}{
		{hssCacheKey(cacheTwo, sequence(40)), 40, 64, 2},
		{xmssCacheKey(cryptopq.XMSS_MT, cacheMt, sequence(72)), 0x12345, 0x12360, 4},
	}

	for _, c := range cases {
		algorithm := c.key.algorithm

		_, state, cache := c.key.exported(t, c.index, true)

		leaves := func(key *cryptopq.StatefulPrivateKey, err error) uint64 {
			t.Helper()

			check(t, err)

			sign(t, key, []byte("m"))

			return cryptopq.LeavesComputed(key)
		}

		if computed := leaves(loadCached(algorithm, state, cache)); computed != 0 {
			t.Fatalf("%s: %d leaves with the cache", algorithm.Name(), computed)
		}

		if computed := leaves(algorithm.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, nil)); computed != 32*c.trees {
			t.Fatalf("%s: %d leaves without the cache", algorithm.Name(), computed)
		}

		if computed := leaves(loadCached(algorithm, c.key.state(t, c.later), cache)); computed != 32 {
			t.Fatalf("%s: %d leaves with a stale tree", algorithm.Name(), computed)
		}
	}
}

// A store that calls during before every write that replaces a state.
type callbackStore struct {
	memoryStore
	during func()
}

func (s *callbackStore) Update(previous, next []byte) (bool, error) {
	if previous != nil && s.during != nil {
		s.during()
	}

	return s.memoryStore.Update(previous, next)
}

// A sign changes the trees, so an export from inside the store fails at once.
func TestTreeCacheExportWhileSigning(t *testing.T) {
	t.Parallel()

	store := &callbackStore{}

	pair, err := cryptopq.HSS_LMS.GenerateKeyPair(&cryptopq.StatefulKeyGenOptions{Levels: cacheTwo[:1], StateStore: store})

	check(t, err)

	var seen []error

	store.during = func() {
		_, err := pair.PrivateKey.ExportTreeCache()

		seen = append(seen, err)
	}

	if !pair.PublicKey.Verify(sign(t, pair.PrivateKey, []byte("m")), []byte("m")) {
		t.Fatal("verify")
	}

	if len(seen) != 1 || !errors.Is(seen[0], cryptopq.STATE_CONFLICT) {
		t.Fatalf("exports from inside the store: %v", seen)
	}

	same(t, splitCache(exportCache(t, pair.PrivateKey)).publicKey, export(t, pair.PublicKey, cryptopq.RAW), "the export after the signature")
}

// Exports race signatures that replace the lower tree: each call either runs alone or fails at
// once with STATE_CONFLICT, and every cache exported loads.
func TestTreeCacheConcurrentExport(t *testing.T) {
	t.Parallel()

	key := hssCacheKey(cacheTwo, sequence(40))

	pair, store := key.at(t, 28)

	var caches [][]byte

	var group sync.WaitGroup

	group.Go(func() {
		for i := range 8 {
			_, err := pair.PrivateKey.Sign([]byte{byte(i)})

			for errors.Is(err, cryptopq.STATE_CONFLICT) {
				runtime.Gosched()

				_, err = pair.PrivateKey.Sign([]byte{byte(i)})
			}

			if err != nil {
				t.Error(err)
			}
		}
	})

	group.Go(func() {
		for range 32 {
			cache, err := pair.PrivateKey.ExportTreeCache()

			switch {
			case errors.Is(err, cryptopq.STATE_CONFLICT):
				runtime.Gosched()
			case err != nil:
				t.Error(err)
			default:
				caches = append(caches, cache)
			}
		}
	})

	group.Wait()

	state, _ := store.Read()

	for i, cache := range append(caches, exportCache(t, pair.PrivateKey)) {
		assertLoads(t, cryptopq.HSS_LMS, state, cache, "cache "+strconv.Itoa(i))
	}
}

// The load that the cache saves, for one tree of height 15 (20 in a slow run): every leaf against
// the parents only. It runs alone, as a test that does not call t.Parallel.
func TestTreeCacheLoadTime(t *testing.T) {
	height := 15

	if slow {
		height = 20
	}

	key := hssCacheKey([]cryptopq.HssLevel{{"LMS_SHA256_M24_H" + strconv.Itoa(height), "LMOTS_SHA256_N24_W2"}}, make([]byte, 40))

	_, state, cache := key.exported(t, 0, false)

	start := time.Now()

	plain, err := cryptopq.HSS_LMS.LoadPrivateKey(&memoryStore{state: bytes.Clone(state)}, nil)

	middle := time.Now()

	check(t, err)

	cached, err := loadCached(cryptopq.HSS_LMS, state, cache)

	end := time.Now()

	check(t, err)

	if !cached.PublicKey().Equal(plain.PublicKey()) {
		t.Fatal("the keys differ")
	}

	without, with := middle.Sub(start), end.Sub(middle)

	t.Logf("H%d: %v without the cache, %v with it", height, without, with)

	if 4*with >= without {
		t.Fatalf("H%d: %v without the cache, %v with it", height, without, with)
	}
}
