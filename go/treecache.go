package cryptopq

import (
	"bytes"
	"encoding/binary"
)

// Tree caches (export and load of the trees a stateful key holds). A tree cache holds public
// nodes only, but the signer trusts the root of a cached lower tree as the child key that its
// parent signs, and the public key covers only the top root and the top level's types, so the
// cache is authenticated with a key derived from the seed and names every level's parameters.
// All integers are big-endian:
//
//	version (1) || kind || parameters as the state blob encodes them || u32(public key size) ||
//	public key || tree count, then for every tree the key holds, top first:
//	level or layer || u64(tree number) || lowest cached height || height || n ||
//	u32(node count) || nodes, level by level from the lowest, left to right
//
// followed by HMAC-SHA-256 of all of it under K = HMAC-SHA-256("crypto-pq tree cache v1", seed),
// an HKDF-Extract (RFC 5869) with the label as salt, where the seed is I || SEED of the top HSS
// tree or SK_SEED || SK_PRF || PUB_SEED.

const (
	treeCacheVersion = 1
	treeCacheTagSize = 32
)

var treeCacheLabel = []byte("crypto-pq tree cache v1")

// A tree that a signer holds: its level or layer, its number there and its Merkle tree.
type heldTree struct {
	level  int
	number uint64
	merkle *merkleTree
}

// One tree of a tree cache as it reads, its nodes still in the cache.
type cachedTree struct {
	level, low, height, n int
	number                uint64
	count                 uint32
	nodes                 []byte
}

type parsedTreeCache struct {
	version, kind                 byte
	section, publicKey, body, tag []byte
	trees                         []cachedTree
}

// Reads the fields of a tree cache in order; reading past the end marks the reader failed, and
// from then on every field reads as empty.
type cacheReader struct {
	data   []byte
	offset int
	failed bool
}

func (r *cacheReader) take(size uint64) []byte {
	if r.failed || size > uint64(len(r.data)-r.offset) {
		r.failed = true

		return nil
	}

	r.offset += int(size)

	return r.data[r.offset-int(size) : r.offset]
}

func (r *cacheReader) number(size uint64) uint64 {
	var value uint64

	for _, b := range r.take(size) {
		value = value<<8 | uint64(b)
	}

	return value
}

// The structure alone: every field present, the parameters in the layout of the kind that the
// cache names, and exactly the tag after the last tree.
func parseTreeCache(data []byte) (*parsedTreeCache, error) {
	r := &cacheReader{data: data}

	head := r.take(2)

	if r.failed {
		return nil, invalidEncoding("the tree cache is truncated")
	}

	c := &parsedTreeCache{version: head[0], kind: head[1]}

	// An HSS level count and a pair of type codes per level, or an OID: a cache of no known kind
	// cannot be read further.
	switch c.kind {
	case statefulSpecs[HSS_LMS].kind:
		r.take(8 * r.number(1))
	case statefulSpecs[XMSS].kind, statefulSpecs[XMSS_MT].kind:
		r.take(4)
	default:
		return nil, invalidEncoding("the tree cache has an unknown kind")
	}

	c.section = data[2:r.offset]

	c.publicKey = r.take(r.number(4))

	count := int(r.number(1))

	c.trees = make([]cachedTree, 0, count)

	for range count {
		header := r.take(16)

		if r.failed {
			break
		}

		tree := cachedTree{level: int(header[0]), number: binary.BigEndian.Uint64(header[1:]), low: int(header[9]), height: int(header[10]), n: int(header[11]), count: binary.BigEndian.Uint32(header[12:])}

		tree.nodes = r.take(uint64(tree.count) * uint64(tree.n))

		c.trees = append(c.trees, tree)
	}

	c.body = data[:r.offset]

	c.tag = r.take(treeCacheTagSize)

	if r.failed {
		return nil, invalidEncoding("the tree cache is truncated")
	}

	if r.offset != len(data) {
		return nil, invalidEncoding("the tree cache has trailing bytes")
	}

	return c, nil
}

// How many trees a key has on its signing path: one per HSS level or XMSS^MT layer.
func (s statefulParameters) treeCount() int {
	if p := s.xmss; p != nil {
		return p.d
	}

	return len(s.levels)
}

// Where a level or layer comes in the top-first order of a tree cache, or -1 for none of the key.
func (s statefulParameters) treePosition(level int) int {
	switch {
	case level >= s.treeCount():
		return -1
	case s.xmss != nil:
		return s.xmss.d - 1 - level
	default:
		return level
	}
}

// The height and the node size of the trees on a level or layer.
func (s statefulParameters) treeShape(level int) (int, int) {
	if p := s.xmss; p != nil {
		return p.treeHeight(), p.n
	}

	return s.levels[level].lms.h, s.levels[level].lms.m
}

// The number of the tree that index signs with on a level or layer; the top one has one tree,
// numbered 0 even at the capacity.
func (s statefulParameters) treeNumber(index uint64, level int) uint64 {
	if p := s.xmss; p != nil {
		if level == p.d-1 {
			return 0
		}

		return index >> ((level + 1) * p.treeHeight())
	}

	if level == 0 {
		return 0
	}

	below := 0

	for _, l := range s.levels[level:] {
		below += l.lms.h
	}

	return index >> below
}

// The public key around the root, which only the top tree gives: the bytes before the root, its
// size and the bytes after it.
func (s statefulParameters) publicParts(seed []byte) ([]byte, int, []byte) {
	if p := s.xmss; p != nil {
		return binary.BigEndian.AppendUint32(nil, p.oid), p.n, seed[2*p.n:]
	}

	top := s.levels[0]

	before := binary.BigEndian.AppendUint32(nil, uint32(len(s.levels)))

	before = binary.BigEndian.AppendUint32(before, top.lms.code)

	before = binary.BigEndian.AppendUint32(before, top.ots.code)

	return append(before, seed[:16]...), top.lms.m, nil
}

// The body of the tree cache of a signer, with room for the tag after it.
func (a StatefulSignatureAlgorithm) treeCacheBody(parameters statefulParameters, signer statefulSigner) []byte {
	section, publicKey, trees := parameters.appendSection(nil), signer.publicKey(), signer.cached()

	size := 2 + len(section) + 4 + len(publicKey) + 1 + treeCacheTagSize

	for _, held := range trees {
		size += 16 + held.merkle.cachedNodes()*held.merkle.n
	}

	body := make([]byte, 0, size)

	body = append(body, treeCacheVersion, a.spec().kind)

	body = append(body, section...)

	body = binary.BigEndian.AppendUint32(body, uint32(len(publicKey)))

	body = append(body, publicKey...)

	body = append(body, byte(len(trees)))

	for _, held := range trees {
		t := held.merkle

		body = append(body, byte(held.level))

		body = binary.BigEndian.AppendUint64(body, held.number)

		body = append(body, byte(t.low), byte(t.height), byte(t.n))

		body = binary.BigEndian.AppendUint32(body, uint32(t.cachedNodes()))

		body = t.appendNodes(body)
	}

	return body
}

// The checks of a tree cache before any tree is restored, in this order: the structure, the
// version, the kind (ALGORITHM_MISMATCH), the parameters and the parts of the public key that the
// state gives, the tag in constant time, then each tree's level, strictly top first, and its shape,
// stale trees included. Every other failure is INVALID_ENCODING. It returns the cache's public key
// and, by level or layer, the trees that index signs with; those whose number index has left are
// skipped and built again when needed.
func (a StatefulSignatureAlgorithm) openTreeCache(parameters statefulParameters, seed []byte, index uint64, data []byte) ([]byte, []*cachedTree, error) {
	c, err := parseTreeCache(data)

	if err != nil {
		return nil, nil, err
	}

	if c.version != treeCacheVersion {
		return nil, nil, invalidEncoding("the tree cache has an unsupported version")
	}

	if c.kind != a.spec().kind {
		return nil, nil, newError(ALGORITHM_MISMATCH, "the tree cache belongs to another algorithm")
	}

	if !bytes.Equal(c.section, parameters.appendSection(nil)) {
		return nil, nil, invalidEncoding("the tree cache belongs to other parameters")
	}

	before, rootSize, after := parameters.publicParts(seed)

	key := c.publicKey

	if len(key) != len(before)+rootSize+len(after) || !bytes.Equal(key[:len(before)], before) || !bytes.Equal(key[len(before)+rootSize:], after) {
		return nil, nil, invalidEncoding("the tree cache belongs to another key")
	}

	// The expected tag of a refused body is what a forger would need, so it is cleared too.
	tag := treeCacheTag(seed, c.body)

	authentic := equal(tag[:], c.tag)

	clear(tag[:])

	if !authentic {
		return nil, nil, invalidEncoding("the tree cache is not authentic")
	}

	needed := make([]*cachedTree, parameters.treeCount())

	previous := -1

	for i := range c.trees {
		tree := &c.trees[i]

		position := parameters.treePosition(tree.level)

		if position <= previous {
			return nil, nil, invalidEncoding("the tree cache lists an unknown level or its levels out of order")
		}

		previous = position

		height, n := parameters.treeShape(tree.level)

		low := max(0, height-merkleCachedHeight)

		if tree.low != low || tree.height != height || tree.n != n || tree.count != 2<<(height-low)-1 {
			return nil, nil, invalidEncoding("the tree cache does not match the key's parameters")
		}

		if tree.number == parameters.treeNumber(index, tree.level) {
			needed[tree.level] = tree
		}
	}

	return key, needed, nil
}

// HMAC-SHA-256 (RFC 2104) with a key of at most one block, computed on the stack, where its own
// buffers are cleared: the tree cache feeds it the seed and keys it with a value derived from the
// seed, both of which the engines behind HMAC_SHA_256 would leave on the heap until collected.
func hmacSha256(key, data []byte, out *[32]byte) {
	var pad [64]byte

	copy(pad[:], key)

	for i := range pad {
		pad[i] ^= 0x36
	}

	state := iv256

	compress256(&state, pad[:])

	var inner [32]byte

	sha256Finish(state, 64, data, inner[:])

	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}

	state = iv256

	compress256(&state, pad[:])

	sha256Finish(state, 64, inner[:], out[:])

	clear(pad[:])

	clear(state[:])

	clear(inner[:])
}

// The tag of a tree cache body: HMAC-SHA-256 under K, which is cleared once used.
func treeCacheTag(seed, body []byte) [32]byte {
	defer ditLeave(ditEnter())

	var key, tag [32]byte

	hmacSha256(treeCacheLabel, seed, &key)

	hmacSha256(key[:], body, &tag)

	clear(key[:])

	return tag
}
