package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// SLH-DSA (FIPS 205). Every tree and chain index is public, so the code branches on them freely.

const (
	slhWotsHash = iota
	slhWotsPublicKey
	slhTree
	slhForsTree
	slhForsRoots
	slhWotsPRF
	slhForsPRF
)

type slhParams struct {
	shake                bool
	n, h, d, hp, a, k, m int
}

func (p *slhParams) wotsLength() int {
	return 2*p.n + 3
}

func (p *slhParams) signatureSize() int {
	return (1 + p.k*(1+p.a) + p.h + p.d*p.wotsLength()) * p.n
}

// SHA2 128s, 128f, 192s, 192f, 256s, 256f, then the same six with SHAKE.
var slhSets = func() (sets [12]slhParams) {
	sizes := [6][7]int{
		{16, 63, 7, 9, 12, 14, 30},
		{16, 66, 22, 3, 6, 33, 34},
		{24, 63, 7, 9, 14, 17, 39},
		{24, 66, 22, 3, 8, 33, 42},
		{32, 64, 8, 8, 14, 22, 47},
		{32, 68, 17, 4, 9, 35, 49},
	}

	for i := range sets {
		s := sizes[i%6]

		sets[i] = slhParams{shake: i >= 6, n: s[0], h: s[1], d: s[2], hp: s[3], a: s[4], k: s[5], m: s[6]}
	}

	return sets
}()

// The address as its eight big-endian words: layer, three tree words, type, key pair, chain
// address or tree height, and hash address or tree index (FIPS 205, section 4.2).
type slhAddress [8]uint32

func (a *slhAddress) setLayer(layer int) {
	a[0] = uint32(layer)
}

func (a *slhAddress) setTree(tree uint64) {
	a[1], a[2], a[3] = 0, uint32(tree>>32), uint32(tree)
}

func (a *slhAddress) setType(kind int) {
	a[4], a[5], a[6], a[7] = uint32(kind), 0, 0, 0
}

func (a *slhAddress) setKeyPair(index uint32) {
	a[5] = index
}

func (a *slhAddress) keyPair() uint32 {
	return a[5]
}

func (a *slhAddress) setChain(index uint32) {
	a[6] = index
}

func (a *slhAddress) setHash(index uint32) {
	a[7] = index
}

func (a *slhAddress) treeIndex() uint32 {
	return a[7]
}

// A copy of the address with another type and the same key pair.
func (a *slhAddress) retyped(kind int) slhAddress {
	copied := *a

	copied.setType(kind)

	copied.setKeyPair(a.keyPair())

	return copied
}

// F, H, T and PRF bound to one public seed (FIPS 205, section 11). For SHA2 the block holding
// PK.seed and its zero padding is compressed once and that state reused for every call; for SHAKE
// PK.seed is kept as Keccak lanes.
type slhContext struct {
	p      *slhParams
	pkSeed []byte
	skSeed []byte
	small  [8]uint32
	large  [8]uint64
	lanes  [4]uint64
	values []byte
	input  []byte
}

func newSlhContext(p *slhParams, pkSeed, skSeed []byte) *slhContext {
	size := max(p.wotsLength(), p.k) * p.n

	c := &slhContext{p: p, pkSeed: pkSeed, skSeed: skSeed, values: make([]byte, size), input: make([]byte, 32+p.n+size)}

	if p.shake {
		for i := range p.n / 8 {
			c.lanes[i] = binary.LittleEndian.Uint64(pkSeed[8*i:])
		}

		return c
	}

	var block [128]byte

	copy(block[:], pkSeed)

	c.small = iv256

	compress256(&c.small, block[:64])

	c.large = iv512

	compress512(&c.large, block[:])

	return c
}

// F, H and PRF hash ADRS with a message of n or 2n bytes, which always fits in a single block, so
// these functions assemble that block directly: for SHAKE, PK.seed || ADRS || M fills whole lanes;
// for SHA2, ADRSc || M (FIPS 205, section 11.2) follows the precomputed PK.seed block, and the
// 22-byte ADRSc puts M two bytes into a word.
func (c *slhContext) shakeShort(out []byte, adrs *slhAddress, message []byte) {
	var s [25]uint64

	k := c.p.n / 8

	for i, lane := range c.lanes[:k] {
		s[i] = lane
	}

	for i := range 4 {
		s[k+i] = uint64(bits.ReverseBytes32(adrs[2*i])) | uint64(bits.ReverseBytes32(adrs[2*i+1]))<<32
	}

	k += 4

	for i := range len(message) / 8 {
		s[k+i] = binary.LittleEndian.Uint64(message[8*i:])
	}

	s[k+len(message)/8] = 0x1f

	s[16] ^= 0x80 << 56

	permute(&s)

	for i := range c.p.n / 8 {
		binary.LittleEndian.PutUint64(out[8*i:], s[i])
	}
}

func (c *slhContext) sha256Short(out []byte, adrs *slhAddress, message []byte) {
	a, m := adrs, len(message)

	var w [16]uint32

	w[0], w[1], w[2] = a[0]<<24|a[2]>>8, a[2]<<24|a[3]>>8, a[3]<<24|a[4]<<16|a[5]>>16

	w[3], w[4], w[5] = a[5]<<16|a[6]>>16, a[6]<<16|a[7]>>16, a[7]<<16|uint32(message[0])<<8|uint32(message[1])

	for i := 1; i < m/4; i++ {
		w[5+i] = binary.BigEndian.Uint32(message[4*i-2:])
	}

	w[5+m/4] = uint32(message[m-2])<<24 | uint32(message[m-1])<<16 | 0x8000

	w[15] = uint32(64+22+m) * 8

	s := sha256Block(c.small, w)

	for i := range c.p.n / 4 {
		binary.BigEndian.PutUint32(out[4*i:], s[i])
	}
}

// H with n = 24 or 32 uses SHA-512 after the 128-byte PK.seed block.
func (c *slhContext) sha512Short(out []byte, adrs *slhAddress, message []byte) {
	a, m := adrs, len(message)

	var w [16]uint64

	w[0] = uint64(a[0])<<56 | uint64(a[2])<<24 | uint64(a[3]>>8)

	w[1] = uint64(a[3])<<56 | uint64(a[4])<<48 | uint64(a[5])<<16 | uint64(a[6]>>16)

	w[2] = uint64(a[6])<<48 | uint64(a[7])<<16 | uint64(message[0])<<8 | uint64(message[1])

	last := (22 + m) / 8

	for j := 3; j < last; j++ {
		w[j] = binary.BigEndian.Uint64(message[8*j-22:])
	}

	w[last] = uint64(binary.BigEndian.Uint32(message[m-6:]))<<32 | uint64(binary.BigEndian.Uint16(message[m-2:]))<<16 | 0x8000

	w[15] = uint64(128+22+m) * 8

	s := sha512Block(c.large, w)

	for i := range c.p.n / 8 {
		binary.BigEndian.PutUint64(out[8*i:], s[i])
	}
}

func (c *slhContext) f(out []byte, adrs *slhAddress, message []byte) {
	if c.p.shake {
		c.shakeShort(out, adrs, message)
	} else {
		c.sha256Short(out, adrs, message)
	}
}

func (c *slhContext) h(out []byte, adrs *slhAddress, message []byte) {
	switch {
	case c.p.shake:
		c.shakeShort(out, adrs, message)
	case c.p.n == 16:
		c.sha256Short(out, adrs, message)
	default:
		c.sha512Short(out, adrs, message)
	}
}

func (c *slhContext) prf(out []byte, adrs *slhAddress) {
	c.f(out, adrs, c.skSeed)
}

// T_l over a message of many blocks, with SHA-512 for SHA2 when n > 16.
func (c *slhContext) t(out []byte, adrs *slhAddress, message []byte) {
	n := c.p.n

	var address [32]byte

	for i, word := range adrs {
		binary.BigEndian.PutUint32(address[4*i:], word)
	}

	if c.p.shake {
		shake256Sum(out[:n], c.pkSeed, address[:], message)

		return
	}

	data := c.input[:22+len(message)]

	data[0], data[9] = address[3], address[19]

	copy(data[1:9], address[8:16])

	copy(data[10:22], address[20:])

	copy(data[22:], message)

	if n > 16 {
		sha512Finish(c.large, 128, data, out[:n])
	} else {
		sha256Finish(c.small, 64, data, out[:n])
	}
}

func (c *slhContext) chain(x []byte, start, steps int, adrs *slhAddress) {
	for j := start; j < start+steps; j++ {
		adrs.setHash(uint32(j))

		c.f(x, adrs, x)
	}
}

// base_2b (FIPS 205, Algorithm 4).
func base2b(out []uint32, data []byte, b int) {
	var total uint32

	bits, offset := 0, 0

	for i := range out {
		for bits < b {
			total = total<<8 | uint32(data[offset])

			offset++

			bits += 8
		}

		bits -= b

		out[i] = (total >> bits) & (1<<b - 1)
	}
}

// The base-16 digits of the message followed by those of its checksum.
func (c *slhContext) wotsDigits(digits []uint32, message []byte) {
	n := c.p.n

	base2b(digits[:2*n], message, 4)

	var checksum uint32

	for _, digit := range digits[:2*n] {
		checksum += 15 - digit
	}

	checksum <<= 4

	base2b(digits[2*n:], []byte{byte(checksum >> 8), byte(checksum)}, 4)
}

func (c *slhContext) wotsPublic(out []byte, adrs *slhAddress, values []byte) {
	public := adrs.retyped(slhWotsPublicKey)

	c.t(out, &public, values)
}

func (c *slhContext) wotsPublicKey(out []byte, adrs *slhAddress) {
	n, length := c.p.n, c.p.wotsLength()

	secret := adrs.retyped(slhWotsPRF)

	values := c.values[:length*n]

	for i := range length {
		value := values[i*n : (i+1)*n]

		secret.setChain(uint32(i))

		c.prf(value, &secret)

		adrs.setChain(uint32(i))

		c.chain(value, 0, 15, adrs)
	}

	c.wotsPublic(out, adrs, values)
}

func (c *slhContext) wotsSign(out, message []byte, adrs *slhAddress) {
	n := c.p.n

	var digits [67]uint32

	c.wotsDigits(digits[:c.p.wotsLength()], message)

	secret := adrs.retyped(slhWotsPRF)

	for i, digit := range digits[:c.p.wotsLength()] {
		value := out[i*n : (i+1)*n]

		secret.setChain(uint32(i))

		c.prf(value, &secret)

		adrs.setChain(uint32(i))

		c.chain(value, 0, int(digit), adrs)
	}
}

func (c *slhContext) wotsPublicKeyFromSignature(out, signature, message []byte, adrs *slhAddress) {
	n, length := c.p.n, c.p.wotsLength()

	var digits [67]uint32

	c.wotsDigits(digits[:length], message)

	values := c.values[:length*n]

	copy(values, signature[:length*n])

	for i, digit := range digits[:length] {
		adrs.setChain(uint32(i))

		c.chain(values[i*n:(i+1)*n], int(digit), 15-int(digit), adrs)
	}

	c.wotsPublic(out, adrs, values)
}

func (c *slhContext) xmssNode(out []byte, i uint32, z int, adrs *slhAddress) {
	if z == 0 {
		adrs.setType(slhWotsHash)

		adrs.setKeyPair(i)

		c.wotsPublicKey(out, adrs)

		return
	}

	n := c.p.n

	var pair [64]byte

	c.xmssNode(pair[:n], 2*i, z-1, adrs)

	c.xmssNode(pair[n:2*n], 2*i+1, z-1, adrs)

	adrs.setType(slhTree)

	adrs.setChain(uint32(z))

	adrs.setHash(i)

	c.h(out, adrs, pair[:2*n])
}

func (c *slhContext) xmssSign(out, message []byte, index uint32, adrs *slhAddress) {
	n, length := c.p.n, c.p.wotsLength()

	for j := range c.p.hp {
		c.xmssNode(out[(length+j)*n:(length+j+1)*n], (index>>j)^1, j, adrs)
	}

	adrs.setType(slhWotsHash)

	adrs.setKeyPair(index)

	c.wotsSign(out[:length*n], message, adrs)
}

// Climbs from a leaf to the root with the authentication path: the node is the left child when
// its index is even.
func (c *slhContext) climb(node []byte, index uint32, auth []byte, height int, adrs *slhAddress) {
	n := c.p.n

	var pair [64]byte

	for j := range height {
		sibling := auth[j*n : (j+1)*n]

		adrs.setChain(uint32(j + 1))

		if (index>>j)&1 == 0 {
			adrs.setHash(adrs.treeIndex() / 2)

			copy(pair[:n], node)

			copy(pair[n:], sibling)
		} else {
			adrs.setHash((adrs.treeIndex() - 1) / 2)

			copy(pair[:n], sibling)

			copy(pair[n:], node)
		}

		c.h(node, adrs, pair[:2*n])
	}
}

func (c *slhContext) xmssPublicKeyFromSignature(out []byte, index uint32, signature, message []byte, adrs *slhAddress) {
	n, length := c.p.n, c.p.wotsLength()

	adrs.setType(slhWotsHash)

	adrs.setKeyPair(index)

	var node [32]byte

	c.wotsPublicKeyFromSignature(node[:n], signature, message, adrs)

	adrs.setType(slhTree)

	adrs.setHash(index)

	c.climb(node[:n], index, signature[length*n:], c.p.hp, adrs)

	copy(out, node[:n])
}

func (c *slhContext) htSign(out, message []byte, tree uint64, leaf uint32) {
	p := c.p

	size := (p.wotsLength() + p.hp) * p.n

	var adrs slhAddress

	adrs.setTree(tree)

	c.xmssSign(out[:size], message, leaf, &adrs)

	var root [32]byte

	c.xmssPublicKeyFromSignature(root[:p.n], leaf, out[:size], message, &adrs)

	for j := 1; j < p.d; j++ {
		leaf = uint32(tree & (1<<p.hp - 1))

		tree >>= p.hp

		adrs.setLayer(j)

		adrs.setTree(tree)

		part := out[j*size : (j+1)*size]

		c.xmssSign(part, root[:p.n], leaf, &adrs)

		if j < p.d-1 {
			c.xmssPublicKeyFromSignature(root[:p.n], leaf, part, root[:p.n], &adrs)
		}
	}
}

func (c *slhContext) htVerify(message, signature []byte, tree uint64, leaf uint32, root []byte) bool {
	p := c.p

	size := (p.wotsLength() + p.hp) * p.n

	var adrs slhAddress

	adrs.setTree(tree)

	var node [32]byte

	c.xmssPublicKeyFromSignature(node[:p.n], leaf, signature[:size], message, &adrs)

	for j := 1; j < p.d; j++ {
		leaf = uint32(tree & (1<<p.hp - 1))

		tree >>= p.hp

		adrs.setLayer(j)

		adrs.setTree(tree)

		c.xmssPublicKeyFromSignature(node[:p.n], leaf, signature[j*size:(j+1)*size], node[:p.n], &adrs)
	}

	return equal(node[:p.n], root)
}

func (c *slhContext) forsSecret(out []byte, adrs *slhAddress, index uint32) {
	secret := adrs.retyped(slhForsPRF)

	secret.setHash(index)

	c.prf(out, &secret)
}

func (c *slhContext) forsNode(out []byte, i uint32, z int, adrs *slhAddress) {
	n := c.p.n

	if z == 0 {
		var secret [32]byte

		c.forsSecret(secret[:n], adrs, i)

		adrs.setChain(0)

		adrs.setHash(i)

		c.f(out, adrs, secret[:n])

		return
	}

	var pair [64]byte

	c.forsNode(pair[:n], 2*i, z-1, adrs)

	c.forsNode(pair[n:2*n], 2*i+1, z-1, adrs)

	adrs.setChain(uint32(z))

	adrs.setHash(i)

	c.h(out, adrs, pair[:2*n])
}

func (c *slhContext) forsSign(out, digest []byte, adrs *slhAddress) {
	n, a := c.p.n, c.p.a

	var indices [35]uint32

	base2b(indices[:c.p.k], digest, a)

	offset := 0

	for i, index := range indices[:c.p.k] {
		c.forsSecret(out[offset:offset+n], adrs, uint32(i<<a)+index)

		offset += n

		for j := range a {
			c.forsNode(out[offset:offset+n], uint32(i<<(a-j))+((index>>j)^1), j, adrs)

			offset += n
		}
	}
}

func (c *slhContext) forsPublicKeyFromSignature(out, signature, digest []byte, adrs *slhAddress) {
	n, a := c.p.n, c.p.a

	var indices [35]uint32

	base2b(indices[:c.p.k], digest, a)

	roots := c.values[:c.p.k*n]

	for i, index := range indices[:c.p.k] {
		offset := i * (a + 1) * n

		node := roots[i*n : (i+1)*n]

		adrs.setChain(0)

		adrs.setHash(uint32(i<<a) + index)

		c.f(node, adrs, signature[offset:offset+n])

		c.climb(node, index, signature[offset+n:], a, adrs)
	}

	public := adrs.retyped(slhForsRoots)

	c.t(out, &public, roots)
}

func slhRoot(p *slhParams, skSeed, pkSeed []byte) []byte {
	var adrs slhAddress

	adrs.setLayer(p.d - 1)

	root := make([]byte, p.n)

	newSlhContext(p, pkSeed, skSeed).xmssNode(root, 0, p.hp, &adrs)

	return root
}

func slhKeyGen(p *slhParams, skSeed, skPrf, pkSeed []byte) (sk, pk []byte) {
	root := slhRoot(p, skSeed, pkSeed)

	sk = make([]byte, 0, 4*p.n)

	sk = append(append(append(append(sk, skSeed...), skPrf...), pkSeed...), root...)

	return sk, append(append([]byte{}, pkSeed...), root...)
}

func slhPrfMessage(p *slhParams, skPrf, optRand, message []byte) []byte {
	out := make([]byte, p.n)

	if p.shake {
		shake256Sum(out, skPrf, optRand, message)

		return out
	}

	algorithm := HMAC_SHA_512

	if p.n == 16 {
		algorithm = HMAC_SHA_256
	}

	hmac := algorithm.Create(skPrf)

	hmac.Update(optRand)

	hmac.Update(message)

	digest := hmac.Digest()

	copy(out, digest)

	clear(digest)

	return out
}

// H_msg: SHAKE256 directly, or MGF1 over R || PK.seed || SHA-x(R || PK.seed || PK.root || M).
func slhHashMessage(p *slhParams, r, pkSeed, pkRoot, message []byte) []byte {
	out := make([]byte, p.m)

	if p.shake {
		shake256Sum(out, r, pkSeed, pkRoot, message)

		return out
	}

	algorithm := SHA_512

	if p.n == 16 {
		algorithm = SHA_256
	}

	hasher := algorithm.Create()

	for _, part := range [][]byte{r, pkSeed, pkRoot, message} {
		hasher.Update(part)
	}

	seed := append(append(append([]byte{}, r...), pkSeed...), hasher.Digest()...)

	var counter [4]byte

	for offset := 0; offset < p.m; {
		hasher = algorithm.Create()

		hasher.Update(seed)

		hasher.Update(counter[:])

		offset += copy(out[offset:], hasher.Digest())

		binary.BigEndian.PutUint32(counter[:], binary.BigEndian.Uint32(counter[:])+1)
	}

	return out
}

// The message digest splits into the FORS digest, the hypertree tree index and the leaf index.
func slhSplitDigest(p *slhParams, digest []byte) (md []byte, tree uint64, leaf uint32) {
	mdSize := (p.k*p.a + 7) / 8

	treeBits := p.h - p.h/p.d

	treeSize := (treeBits + 7) / 8

	leafBits := p.h / p.d

	leafSize := (leafBits + 7) / 8

	for _, b := range digest[mdSize : mdSize+treeSize] {
		tree = tree<<8 | uint64(b)
	}

	if treeBits < 64 {
		tree &= 1<<treeBits - 1
	}

	for _, b := range digest[mdSize+treeSize : mdSize+treeSize+leafSize] {
		leaf = leaf<<8 | uint32(b)
	}

	return digest[:mdSize], tree, leaf & (1<<leafBits - 1)
}

func slhSign(p *slhParams, message, sk, optRand []byte) []byte {
	n := p.n

	skSeed, skPrf, pkSeed, pkRoot := sk[:n], sk[n:2*n], sk[2*n:3*n], sk[3*n:]

	c := newSlhContext(p, pkSeed, skSeed)

	signature := make([]byte, p.signatureSize())

	r := slhPrfMessage(p, skPrf, optRand, message)

	copy(signature, r)

	md, tree, leaf := slhSplitDigest(p, slhHashMessage(p, r, pkSeed, pkRoot, message))

	var adrs slhAddress

	adrs.setTree(tree)

	adrs.setType(slhForsTree)

	adrs.setKeyPair(leaf)

	forsEnd := (1 + p.k*(1+p.a)) * n

	c.forsSign(signature[n:forsEnd], md, &adrs)

	var forsPublicKey [32]byte

	c.forsPublicKeyFromSignature(forsPublicKey[:n], signature[n:forsEnd], md, &adrs)

	c.htSign(signature[forsEnd:], forsPublicKey[:n], tree, leaf)

	return signature
}

func slhVerify(p *slhParams, message, signature, pk []byte) bool {
	n := p.n

	if len(signature) != p.signatureSize() || len(pk) != 2*n {
		return false
	}

	pkSeed, pkRoot := pk[:n], pk[n:]

	c := newSlhContext(p, pkSeed, nil)

	md, tree, leaf := slhSplitDigest(p, slhHashMessage(p, signature[:n], pkSeed, pkRoot, message))

	var adrs slhAddress

	adrs.setTree(tree)

	adrs.setType(slhForsTree)

	adrs.setKeyPair(leaf)

	forsEnd := (1 + p.k*(1+p.a)) * n

	var forsPublicKey [32]byte

	c.forsPublicKeyFromSignature(forsPublicKey[:n], signature[n:forsEnd], md, &adrs)

	return c.htVerify(forsPublicKey[:n], signature[forsEnd:], tree, leaf, pkRoot)
}
