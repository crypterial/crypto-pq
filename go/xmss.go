package cryptopq

import (
	"encoding/binary"
	"strconv"
)

// XMSS and XMSS^MT (RFC 8391) with the SP 800-208 parameter sets and key generation.

const (
	xmssOts = iota
	xmssLtree
	xmssHashTree
)

const (
	xmssF = iota
	xmssH
	xmssHashMessage
	xmssPRF
	xmssPRFKeygen
)

type xmssParams struct {
	name         string
	oid          uint32
	multi, shake bool
	n, h, d      int
}

func (p *xmssParams) padding() int {
	if p.n == 32 {
		return 32
	}

	return 4
}

func (p *xmssParams) treeHeight() int {
	return p.h / p.d
}

func (p *xmssParams) wotsLength() int {
	return 2*p.n + 3
}

func (p *xmssParams) indexSize() int {
	if p.multi {
		return (p.h + 7) / 8
	}

	return 4
}

func (p *xmssParams) publicKeySize() int {
	return 4 + 2*p.n
}

func (p *xmssParams) signatureSize() int {
	return p.indexSize() + p.n + (p.d*p.wotsLength()+p.h)*p.n
}

// The SP 800-208 parameter sets with their RFC 8391 and NIST code points.
var xmssSets, xmssMtSets = xmssTables()

func xmssTables() (single, multi []xmssParams) {
	families := []struct {
		name          string
		shake         bool
		n             int
		bits          string
		single, multi uint32
	}{
		{"SHA2", false, 32, "256", 0x01, 0x01},
		{"SHA2", false, 24, "192", 0x0d, 0x21},
		{"SHAKE256", true, 32, "256", 0x10, 0x29},
		{"SHAKE256", true, 24, "192", 0x13, 0x31},
	}

	for _, family := range families {
		for j, h := range []int{10, 16, 20} {
			name := "XMSS-" + family.name + "_" + strconv.Itoa(h) + "_" + family.bits

			single = append(single, xmssParams{name: name, oid: family.single + uint32(j), shake: family.shake, n: family.n, h: h, d: 1})
		}

		for j, shape := range [][2]int{{20, 2}, {20, 4}, {40, 2}, {40, 4}, {40, 8}, {60, 3}, {60, 6}, {60, 12}} {
			name := "XMSSMT-" + family.name + "_" + strconv.Itoa(shape[0]) + "/" + strconv.Itoa(shape[1]) + "_" + family.bits

			multi = append(multi, xmssParams{name: name, oid: family.multi + uint32(j), multi: true, shake: family.shake, n: family.n, h: shape[0], d: shape[1]})
		}
	}

	return single, multi
}

func xmssByOid(sets []xmssParams, oid uint32) *xmssParams {
	for i := range sets {
		if sets[i].oid == oid {
			return &sets[i]
		}
	}

	return nil
}

func xmssByName(sets []xmssParams, name string) *xmssParams {
	for i := range sets {
		if sets[i].name == name {
			return &sets[i]
		}
	}

	return nil
}

// The address as its eight big-endian words: layer, two tree words, type, and four words whose
// meaning depends on the type (RFC 8391, section 2.5).
type xmssAddress [8]uint32

func newXmssAddress(layer uint32, tree uint64, kind uint32) xmssAddress {
	return xmssAddress{layer, uint32(tree >> 32), uint32(tree), kind}
}

func (a xmssAddress) bytes() [32]byte {
	var out [32]byte

	for i, word := range a {
		out[4*i], out[4*i+1], out[4*i+2], out[4*i+3] = byte(word>>24), byte(word>>16), byte(word>>8), byte(word)
	}

	return out
}

// The keyed hash functions of one key: toByte(prefix, padding) || key || message, hashed with
// SHA-256 or SHAKE256 and truncated to n bytes. With n = 32 and SHA-256, the first block of PRF
// (prefix and PUB_SEED) and of PRF_keygen (prefix and SK_SEED) is compressed once per key.
type xmssHasher struct {
	p                     *xmssParams
	skSeed, pubSeed       []byte
	prfState, keygenState [8]uint32
	midstates             bool
}

func newXmssHasher(p *xmssParams, skSeed, pubSeed []byte) *xmssHasher {
	x := &xmssHasher{p: p, skSeed: skSeed, pubSeed: pubSeed, midstates: !p.shake && p.n == 32}

	if x.midstates {
		var block [64]byte

		block[31] = xmssPRF

		copy(block[32:], pubSeed)

		x.prfState = iv256

		compress256(&x.prfState, block[:])

		block[31] = xmssPRFKeygen

		copy(block[32:], skSeed)

		x.keygenState = iv256

		compress256(&x.keygenState, block[:])

		clear(block[:])
	}

	return x
}

func (x *xmssHasher) digest(out []byte, prefix byte, key, message []byte) {
	var data [128]byte

	padding := x.p.padding()

	data[padding-1] = prefix

	copy(data[padding:], key)

	copy(data[padding+len(key):], message)

	length := padding + len(key) + len(message)

	if x.p.shake {
		shake256Short(data[:length], out[:x.p.n])
	} else {
		sha256Finish(iv256, 0, data[:length], out[:x.p.n])
	}

	clear(data[:])
}

func (x *xmssHasher) prf(out []byte, adrs *xmssAddress) {
	address := adrs.bytes()

	if x.midstates {
		sha256Finish(x.prfState, 64, address[:], out[:32])

		return
	}

	x.digest(out, xmssPRF, x.pubSeed, address[:])
}

// SP 800-208: PRF_keygen(SK_SEED, PUB_SEED || ADRS).
func (x *xmssHasher) prfKeygen(out []byte, adrs *xmssAddress) {
	var message [64]byte

	copy(message[:], x.pubSeed)

	address := adrs.bytes()

	copy(message[x.p.n:], address[:])

	if x.midstates {
		sha256Finish(x.keygenState, 64, message[:], out[:32])

		return
	}

	x.digest(out, xmssPRFKeygen, x.skSeed, message[:x.p.n+32])
}

// PRF(PUB_SEED, ADRS) with the midstate: the address and the padding form the second block.
func (x *xmssHasher) prfWords(adrs *xmssAddress) [8]uint32 {
	var w [16]uint32

	copy(w[:8], adrs[:])

	w[8], w[15] = 0x80000000, 96*8

	return sha256Block(x.prfState, w)
}

// With the midstates, a chain stays in words: F(KEY, M) = SHA-256(toByte(0, 32) || KEY || M) is a
// block of 32 zero bytes and KEY, then a block of M and the padding.
func (x *xmssHasher) chainWords(value []byte, start, steps int, adrs *xmssAddress) {
	var current, mask [8]uint32

	for i := range current {
		current[i] = binary.BigEndian.Uint32(value[4*i:])
	}

	var keyBlock, messageBlock [16]uint32

	messageBlock[8], messageBlock[15] = 0x80000000, 96*8

	for k := start; k < start+steps; k++ {
		adrs[6], adrs[7] = uint32(k), 0

		key := x.prfWords(adrs)

		adrs[7] = 1

		mask = x.prfWords(adrs)

		copy(keyBlock[8:], key[:])

		for i := range current {
			messageBlock[i] = current[i] ^ mask[i]
		}

		current = sha256Block(sha256Block(iv256, keyBlock), messageBlock)
	}

	for i, word := range current {
		binary.BigEndian.PutUint32(value[4*i:], word)
	}

	clear(current[:])

	clear(mask[:])

	clear(messageBlock[:])
}

func (x *xmssHasher) chain(value []byte, start, steps int, adrs *xmssAddress) {
	if x.midstates {
		x.chainWords(value, start, steps, adrs)

		return
	}

	n := x.p.n

	var current, key, mask [32]byte

	copy(current[:], value)

	for k := start; k < start+steps; k++ {
		adrs[6] = uint32(k)

		adrs[7] = 0

		x.prf(key[:n], adrs)

		adrs[7] = 1

		x.prf(mask[:n], adrs)

		for i := range n {
			mask[i] ^= current[i]
		}

		x.digest(current[:n], xmssF, key[:n], mask[:n])
	}

	copy(value, current[:n])

	clear(current[:])

	clear(mask[:])
}

func (x *xmssHasher) wotsDigits(message []byte) []int {
	digits := make([]int, 0, 2*len(message)+3)

	checksum := 0

	for _, b := range message {
		digits = append(digits, int(b>>4), int(b&0x0f))

		checksum += 30 - int(b>>4) - int(b&0x0f)
	}

	checksum <<= 4

	return append(digits, checksum>>12&0x0f, checksum>>8&0x0f, checksum>>4&0x0f)
}

// A secret chain start, with the hash and key-and-mask words cleared.
func (x *xmssHasher) wotsSecret(out []byte, adrs *xmssAddress, i int) {
	adrs[5] = uint32(i)

	adrs[6] = 0

	adrs[7] = 0

	x.prfKeygen(out, adrs)
}

func (x *xmssHasher) wotsPublic(values []byte, adrs *xmssAddress) {
	n := x.p.n

	for i := range x.p.wotsLength() {
		value := values[i*n : (i+1)*n]

		x.wotsSecret(value, adrs, i)

		x.chain(value, 0, 15, adrs)
	}
}

func (x *xmssHasher) wotsSign(out, message []byte, adrs *xmssAddress) {
	n := x.p.n

	for i, digit := range x.wotsDigits(message) {
		value := out[i*n : (i+1)*n]

		x.wotsSecret(value, adrs, i)

		x.chain(value, 0, digit, adrs)
	}
}

func (x *xmssHasher) wotsPublicFromSignature(values, signature, message []byte, adrs *xmssAddress) {
	n := x.p.n

	copy(values, signature[:len(values)])

	for i, digit := range x.wotsDigits(message) {
		adrs[5] = uint32(i)

		x.chain(values[i*n:(i+1)*n], digit, 15-digit, adrs)
	}
}

// RAND_HASH (RFC 8391, Algorithm 7). out may alias either input.
func (x *xmssHasher) randHash(out, left, right []byte, adrs *xmssAddress) {
	if x.midstates {
		x.randHashWords(out, left, right, adrs)

		return
	}

	n := x.p.n

	var key [32]byte

	var masks [64]byte

	adrs[7] = 0

	x.prf(key[:n], adrs)

	adrs[7] = 1

	x.prf(masks[:n], adrs)

	adrs[7] = 2

	x.prf(masks[n:2*n], adrs)

	for i := range n {
		masks[i] ^= left[i]

		masks[n+i] ^= right[i]
	}

	x.digest(out, xmssH, key[:n], masks[:2*n])
}

// H(KEY, M) = SHA-256(toByte(1, 32) || KEY || M) for the midstate case, as in chainWords: a block
// of the prefix and KEY, a block of the two masked nodes, and a block of padding.
func (x *xmssHasher) randHashWords(out, left, right []byte, adrs *xmssAddress) {
	adrs[7] = 0

	key := x.prfWords(adrs)

	adrs[7] = 1

	leftMask := x.prfWords(adrs)

	adrs[7] = 2

	rightMask := x.prfWords(adrs)

	var w [16]uint32

	w[7] = xmssH

	copy(w[8:], key[:])

	state := sha256Block(iv256, w)

	for i := range 8 {
		w[i], w[8+i] = binary.BigEndian.Uint32(left[4*i:])^leftMask[i], binary.BigEndian.Uint32(right[4*i:])^rightMask[i]
	}

	state = sha256Block(state, w)

	state = sha256Block(state, [16]uint32{0x80000000, 15: 128 * 8})

	for i, word := range state {
		binary.BigEndian.PutUint32(out[4*i:], word)
	}
}

// The L-tree (RFC 8391, Algorithm 8) compresses the WOTS+ public key in place.
func (x *xmssHasher) ltree(out, values []byte, adrs *xmssAddress) {
	n := x.p.n

	count := len(values) / n

	adrs[5] = 0

	for count > 1 {
		half := count / 2

		for i := range half {
			adrs[6] = uint32(i)

			x.randHash(values[i*n:(i+1)*n], values[2*i*n:(2*i+1)*n], values[(2*i+1)*n:(2*i+2)*n], adrs)
		}

		if count%2 == 1 {
			copy(values[half*n:], values[(count-1)*n:count*n])

			half++
		}

		count = half

		adrs[5]++
	}

	copy(out, values[:n])
}

func (x *xmssHasher) leaf(out []byte, layer uint32, tree uint64, index uint32, values []byte) {
	ots := newXmssAddress(layer, tree, xmssOts)

	ots[4] = index

	x.wotsPublic(values, &ots)

	ltree := newXmssAddress(layer, tree, xmssLtree)

	ltree[4] = index

	x.ltree(out, values, &ltree)
}

func (x *xmssHasher) subtree(layer uint32, tree uint64) *merkleTree {
	values := make([]byte, x.p.wotsLength()*x.p.n)

	leaf := func(index uint64, out []byte) {
		x.leaf(out, layer, tree, uint32(index), values)
	}

	combine := func(z int, j uint64, left, right, out []byte) {
		adrs := newXmssAddress(layer, tree, xmssHashTree)

		adrs[5] = uint32(z)

		adrs[6] = uint32(j)

		x.randHash(out, left, right, &adrs)
	}

	return newMerkleTree(x.p.treeHeight(), x.p.n, leaf, combine)
}

func (x *xmssHasher) computeRoot(node []byte, index uint32, auth []byte, layer uint32, tree uint64) {
	n := x.p.n

	adrs := newXmssAddress(layer, tree, xmssHashTree)

	for k := range x.p.treeHeight() {
		adrs[5] = uint32(k)

		adrs[6] = index >> (k + 1)

		sibling := auth[k*n : (k+1)*n]

		if (index>>k)&1 == 1 {
			x.randHash(node, sibling, node, &adrs)
		} else {
			x.randHash(node, node, sibling, &adrs)
		}
	}
}

// H_msg(r || root || toByte(index, n), M).
func xmssMessageDigest(p *xmssParams, r, root []byte, index uint64, message []byte) []byte {
	prefix := make([]byte, p.padding()+2*p.n+p.n)

	prefix[p.padding()-1] = xmssHashMessage

	copy(prefix[p.padding():], r)

	copy(prefix[p.padding()+p.n:], root)

	binary.BigEndian.PutUint64(prefix[len(prefix)-8:], index)

	out := make([]byte, p.n)

	if p.shake {
		shake256Sum(out, prefix, message)

		return out
	}

	engine := newSha256(&iv256, 32)

	engine.update(prefix)

	engine.update(message)

	copy(out, engine.digest())

	return out
}

func xmssVerify(p *xmssParams, publicKey, message, signature []byte) bool {
	n := p.n

	if len(publicKey) != p.publicKeySize() || len(signature) != p.signatureSize() || binary.BigEndian.Uint32(publicKey) != p.oid {
		return false
	}

	root, pubSeed := publicKey[4:4+n], publicKey[4+n:]

	var index uint64

	for _, b := range signature[:p.indexSize()] {
		index = index<<8 | uint64(b)
	}

	if index>>p.h != 0 {
		return false
	}

	x := newXmssHasher(p, nil, pubSeed)

	node := xmssMessageDigest(p, signature[p.indexSize():p.indexSize()+n], root, index, message)

	offset := p.indexSize() + n

	values := make([]byte, p.wotsLength()*n)

	height := p.treeHeight()

	for layer := range uint32(p.d) {
		leafIndex := uint32(index & (1<<height - 1))

		index >>= height

		ots := newXmssAddress(layer, index, xmssOts)

		ots[4] = leafIndex

		x.wotsPublicFromSignature(values, signature[offset:], node, &ots)

		offset += len(values)

		ltree := newXmssAddress(layer, index, xmssLtree)

		ltree[4] = leafIndex

		x.ltree(node, values, &ltree)

		x.computeRoot(node, leafIndex, signature[offset:], layer, index)

		offset += height * n
	}

	return equal(node, root)
}

type xmssLayer struct {
	index uint64
	tree  *merkleTree
}

// The signing side of an XMSS or XMSS^MT key, with one cached tree per layer.
type xmssSigner struct {
	p      *xmssParams
	hasher *xmssHasher
	skPrf  []byte
	root   []byte
	layers []*xmssLayer
}

func newXmssSigner(p *xmssParams, skSeed, skPrf, pubSeed []byte) *xmssSigner {
	s := &xmssSigner{p: p, hasher: newXmssHasher(p, skSeed, pubSeed), skPrf: skPrf, layers: make([]*xmssLayer, p.d)}

	s.root = s.tree(uint32(p.d-1), 0).root()

	return s
}

func (s *xmssSigner) tree(layer uint32, index uint64) *merkleTree {
	cached := s.layers[layer]

	if cached == nil || cached.index != index {
		cached = &xmssLayer{index: index, tree: s.hasher.subtree(layer, index)}

		s.layers[layer] = cached
	}

	return cached.tree
}

func (s *xmssSigner) publicKey() []byte {
	return append(append(binary.BigEndian.AppendUint32(nil, s.p.oid), s.root...), s.hasher.pubSeed...)
}

func (s *xmssSigner) capacity() uint64 {
	return 1 << s.p.h
}

func (s *xmssSigner) sign(index uint64, message []byte) []byte {
	p := s.p

	var counter [32]byte

	binary.BigEndian.PutUint64(counter[24:], index)

	r := make([]byte, p.n)

	s.hasher.digest(r, xmssPRF, s.skPrf, counter[:])

	node := xmssMessageDigest(p, r, s.root, index, message)

	signature := make([]byte, p.indexSize(), p.signatureSize())

	for i := range signature {
		signature[i] = byte(index >> (8 * (len(signature) - 1 - i)))
	}

	signature = append(signature, r...)

	height := p.treeHeight()

	wots := make([]byte, p.wotsLength()*p.n)

	for layer := range uint32(p.d) {
		leafIndex := uint32(index & (1<<height - 1))

		index >>= height

		ots := newXmssAddress(layer, index, xmssOts)

		ots[4] = leafIndex

		s.hasher.wotsSign(wots, node, &ots)

		tree := s.tree(layer, index)

		signature = append(append(signature, wots...), tree.authPath(uint64(leafIndex))...)

		node = tree.root()
	}

	return signature
}

func (s *xmssSigner) wipe() {
	clear(s.hasher.skSeed)

	clear(s.hasher.keygenState[:])

	clear(s.skPrf)
}
