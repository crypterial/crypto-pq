package cryptopq

import (
	"encoding/binary"
	"math/bits"
	"strconv"
)

// LMS and HSS (RFC 8554, with the SHA-256/192 and SHAKE256 sets of SP 800-208 and RFC 9858).

const (
	lmsPublicDomain   = 0x8080
	lmsMessageDomain  = 0x8181
	lmsLeafDomain     = 0x8282
	lmsInteriorDomain = 0x8383
)

// Pseudorandom values derived from a tree's SEED (RFC 8554, Appendix A, and the convention of
// the hash-sigs reference used by the RFC 8554 and RFC 9858 test cases): the signature
// randomizer C, and the SEED and I of a child tree. Chain indices are below 0xFFFD.
const (
	lmsRandomizer = 0xfffd
	lmsChildSeed  = 0xfffe
	lmsChildI     = 0xffff
)

type lmotsType struct {
	code  uint32
	name  string
	shake bool
	n, w  int
	p, ls int
}

func (t *lmotsType) signatureSize() int {
	return 4 + t.n*(t.p+1)
}

type lmsType struct {
	code  uint32
	name  string
	shake bool
	m, h  int
}

func (t *lmsType) publicKeySize() int {
	return 24 + t.m
}

var lmotsTypes, lmsTypes = lmsTables()

func lmsTables() (ots []lmotsType, lms []lmsType) {
	families := []struct {
		shake    bool
		n        int
		ots, lms string
	}{
		{false, 32, "SHA256_N32", "SHA256_M32"},
		{false, 24, "SHA256_N24", "SHA256_M24"},
		{true, 32, "SHAKE_N32", "SHAKE_M32"},
		{true, 24, "SHAKE_N24", "SHAKE_M24"},
	}

	for index, family := range families {
		for j, w := range []int{1, 2, 4, 8} {
			u := (8*family.n + w - 1) / w

			v := (bits.Len(uint((1<<w-1)*u)) + w - 1) / w

			name := "LMOTS_" + family.ots + "_W" + strconv.Itoa(w)

			ots = append(ots, lmotsType{code: uint32(1 + 4*index + j), name: name, shake: family.shake, n: family.n, w: w, p: u + v, ls: 16 - v*w})
		}

		for j, h := range []int{5, 10, 15, 20, 25} {
			name := "LMS_" + family.lms + "_H" + strconv.Itoa(h)

			lms = append(lms, lmsType{code: uint32(5 + 5*index + j), name: name, shake: family.shake, m: family.n, h: h})
		}
	}

	return ots, lms
}

func lmotsByCode(code uint32) *lmotsType {
	for i := range lmotsTypes {
		if lmotsTypes[i].code == code {
			return &lmotsTypes[i]
		}
	}

	return nil
}

func lmsByCode(code uint32) *lmsType {
	for i := range lmsTypes {
		if lmsTypes[i].code == code {
			return &lmsTypes[i]
		}
	}

	return nil
}

func lmotsByName(name string) *lmotsType {
	for i := range lmotsTypes {
		if lmotsTypes[i].name == name {
			return &lmotsTypes[i]
		}
	}

	return nil
}

func lmsByName(name string) *lmsType {
	for i := range lmsTypes {
		if lmsTypes[i].name == name {
			return &lmsTypes[i]
		}
	}

	return nil
}

// SHAKE256 with n output bytes, or SHA-256 truncated to n bytes.
func lmsDigest(shake bool, n int, out []byte, data []byte) {
	switch {
	case shake && len(data) < 136:
		shake256Short(data, out[:n])
	case shake:
		shake256Sum(out[:n], data)
	default:
		sha256Finish(iv256, 0, data, out[:n])
	}
}

func lmsDigestParts(shake bool, n int, out []byte, parts ...[]byte) {
	if shake {
		shake256Sum(out[:n], parts...)

		return
	}

	engine := newSha256(&iv256, 32)

	for _, part := range parts {
		engine.update(part)
	}

	copy(out[:n], engine.digest())
}

// The 22-byte prefix I || u32(q) || u16(value) shared by most LMS hashes.
func lmsPrefix(out []byte, i []byte, q uint32, value uint16) {
	copy(out, i[:16])

	binary.BigEndian.PutUint32(out[16:], q)

	binary.BigEndian.PutUint16(out[20:], value)
}

// H(I || u32(q) || u16(index) || 0xFF || SEED).
func lmsDerive(shake bool, n int, i []byte, q uint32, index uint16, seed, out []byte) {
	var data [55]byte

	lmsPrefix(data[:], i, q, index)

	data[22] = 0xff

	copy(data[23:], seed[:n])

	lmsDigest(shake, n, out, data[:23+n])

	clear(data[:])
}

// Iterates x = H(I || u32(q) || u16(j) || u8(k) || x) for k from start to end - 1.
func lmotsChain(t *lmotsType, i []byte, q uint32, j uint16, start, end int, x []byte) {
	var data [55]byte

	lmsPrefix(data[:], i, q, j)

	for k := start; k < end; k++ {
		data[22] = byte(k)

		copy(data[23:], x[:t.n])

		lmsDigest(t.shake, t.n, x, data[:23+t.n])
	}

	clear(data[:])
}

func lmotsCoefficients(t *lmotsType, data []byte, out []int) {
	perByte := 8 / t.w

	mask := 1<<t.w - 1

	for i := range out {
		out[i] = int(data[i/perByte]>>(8-t.w*(i%perByte+1))) & mask
	}
}

// The base-2^w digits of Q followed by those of its checksum (RFC 8554, section 4.4).
func lmotsDigits(t *lmotsType, qHash []byte) []int {
	digits := make([]int, t.p)

	count := 8 * t.n / t.w

	lmotsCoefficients(t, qHash, digits[:count])

	checksum := 0

	for _, digit := range digits[:count] {
		checksum += 1<<t.w - 1 - digit
	}

	extended := append(append([]byte{}, qHash[:t.n]...), byte(checksum<<t.ls>>8), byte(checksum<<t.ls))

	lmotsCoefficients(t, extended, digits)

	return digits
}

// The LM-OTS public key K = H(I || u32(q) || D_PBLC || y[0] || ... || y[p-1]); scratch holds
// 22 + p * n bytes.
func lmotsPublicKey(t *lmotsType, i []byte, q uint32, seed, out, scratch []byte) {
	n := t.n

	lmsPrefix(scratch, i, q, lmsPublicDomain)

	for j := range t.p {
		y := scratch[22+j*n : 22+(j+1)*n]

		lmsDerive(t.shake, n, i, q, uint16(j), seed, y)

		lmotsChain(t, i, q, uint16(j), 0, 1<<t.w-1, y)
	}

	lmsDigest(t.shake, n, out, scratch[:22+t.p*n])
}

func lmotsMessageHash(t *lmotsType, i []byte, q uint32, c, message []byte) []byte {
	var prefix [22]byte

	lmsPrefix(prefix[:], i, q, lmsMessageDomain)

	qHash := make([]byte, t.n)

	lmsDigestParts(t.shake, t.n, qHash, prefix[:], c, message)

	return qHash
}

func lmotsSign(t *lmotsType, i []byte, q uint32, seed, message []byte) []byte {
	n := t.n

	signature := make([]byte, t.signatureSize())

	binary.BigEndian.PutUint32(signature, t.code)

	c := signature[4 : 4+n]

	lmsDerive(t.shake, n, i, q, lmsRandomizer, seed, c)

	for j, digit := range lmotsDigits(t, lmotsMessageHash(t, i, q, c, message)) {
		y := signature[4+n*(j+1) : 4+n*(j+2)]

		lmsDerive(t.shake, n, i, q, uint16(j), seed, y)

		lmotsChain(t, i, q, uint16(j), 0, digit, y)
	}

	return signature
}

// The public key candidate Kc computed from an LM-OTS signature (RFC 8554, Algorithm 4b).
func lmotsCandidate(t *lmotsType, i []byte, q uint32, signature, message []byte) []byte {
	n := t.n

	scratch := make([]byte, 22+t.p*n)

	lmsPrefix(scratch, i, q, lmsPublicDomain)

	for j, digit := range lmotsDigits(t, lmotsMessageHash(t, i, q, signature[4:4+n], message)) {
		z := scratch[22+j*n : 22+(j+1)*n]

		copy(z, signature[4+n*(j+1):4+n*(j+2)])

		lmotsChain(t, i, q, uint16(j), digit, 1<<t.w-1, z)
	}

	candidate := make([]byte, n)

	lmsDigest(t.shake, n, candidate, scratch)

	return candidate
}

func lmsSignatureSize(lms *lmsType, ots *lmotsType) int {
	return 8 + ots.signatureSize() + lms.h*lms.m
}

// u32(lms type) || u32(ots type) || I || T[1], with matching hash functions and sizes.
func lmsParsePublicKey(data []byte) (*lmsType, *lmotsType, bool) {
	if len(data) < 8 {
		return nil, nil, false
	}

	lms := lmsByCode(binary.BigEndian.Uint32(data))

	ots := lmotsByCode(binary.BigEndian.Uint32(data[4:]))

	if lms == nil || ots == nil || lms.shake != ots.shake || lms.m != ots.n || len(data) != lms.publicKeySize() {
		return nil, nil, false
	}

	return lms, ots, true
}

// RFC 8554, Algorithm 6a.
func lmsVerify(publicKey, message, signature []byte) bool {
	lms, ots, ok := lmsParsePublicKey(publicKey)

	if !ok || len(signature) < 8 {
		return false
	}

	i, root := publicKey[8:24], publicKey[24:]

	q := binary.BigEndian.Uint32(signature)

	if binary.BigEndian.Uint32(signature[4:]) != ots.code || len(signature) != lmsSignatureSize(lms, ots) {
		return false
	}

	offset := 4 + ots.signatureSize()

	if binary.BigEndian.Uint32(signature[offset:]) != lms.code || uint64(q) >= 1<<lms.h {
		return false
	}

	node := uint32(1)<<lms.h | q

	var data [86]byte

	lmsPrefix(data[:], i, node, lmsLeafDomain)

	copy(data[22:], lmotsCandidate(ots, i, q, signature[4:offset], message))

	candidate := make([]byte, lms.m)

	lmsDigest(lms.shake, lms.m, candidate, data[:22+lms.m])

	for level := range lms.h {
		sibling := signature[offset+4+level*lms.m : offset+4+(level+1)*lms.m]

		left, right := candidate, sibling

		if node&1 == 1 {
			left, right = sibling, candidate
		}

		node >>= 1

		lmsPrefix(data[:], i, node, lmsInteriorDomain)

		copy(data[22:], left)

		copy(data[22+lms.m:], right)

		lmsDigest(lms.shake, lms.m, candidate, data[:22+2*lms.m])
	}

	return equal(candidate, root)
}

func hssCheckPublicKey(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	levels := binary.BigEndian.Uint32(data)

	_, _, ok := lmsParsePublicKey(data[4:])

	return levels >= 1 && levels <= 8 && ok
}

// RFC 8554, Algorithm 6: each signed child public key is verified with its parent key.
func hssVerify(publicKey, message, signature []byte) bool {
	if !hssCheckPublicKey(publicKey) || len(signature) < 4 {
		return false
	}

	levels := binary.BigEndian.Uint32(publicKey)

	if binary.BigEndian.Uint32(signature) != levels-1 {
		return false
	}

	key := publicKey[4:]

	offset := 4

	for range levels - 1 {
		lms, ots, _ := lmsParsePublicKey(key)

		end := offset + lmsSignatureSize(lms, ots)

		if len(signature) < end+8 {
			return false
		}

		childLms := lmsByCode(binary.BigEndian.Uint32(signature[end:]))

		if childLms == nil || len(signature) < end+childLms.publicKeySize() {
			return false
		}

		child := signature[end : end+childLms.publicKeySize()]

		if _, _, ok := lmsParsePublicKey(child); !ok || !lmsVerify(key, child, signature[offset:end]) {
			return false
		}

		key = child

		offset = end + len(child)
	}

	return lmsVerify(key, message, signature[offset:])
}

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys.
type lmsTree struct {
	lms       *lmsType
	ots       *lmotsType
	i         []byte
	seed      []byte
	merkle    *merkleTree
	publicKey []byte
}

func newLmsTree(lms *lmsType, ots *lmotsType, i, seed []byte) *lmsTree {
	t := &lmsTree{lms: lms, ots: ots, i: i, seed: seed}

	scratch := make([]byte, 22+ots.p*ots.n)

	leaf := func(q uint64, out []byte) {
		var data [54]byte

		lmsPrefix(data[:], i, uint32(1<<lms.h+q), lmsLeafDomain)

		lmotsPublicKey(ots, i, uint32(q), seed, data[22:], scratch)

		lmsDigest(lms.shake, lms.m, out, data[:22+ots.n])
	}

	combine := func(z int, j uint64, left, right, out []byte) {
		var data [86]byte

		lmsPrefix(data[:], i, uint32(1<<(lms.h-z-1)+j), lmsInteriorDomain)

		copy(data[22:], left)

		copy(data[22+lms.m:], right)

		lmsDigest(lms.shake, lms.m, out, data[:22+2*lms.m])
	}

	t.merkle = newMerkleTree(lms.h, lms.m, leaf, combine)

	t.publicKey = binary.BigEndian.AppendUint32(nil, lms.code)

	t.publicKey = binary.BigEndian.AppendUint32(t.publicKey, ots.code)

	t.publicKey = append(append(t.publicKey, i...), t.merkle.root()...)

	return t
}

func (t *lmsTree) sign(q uint32, message []byte) []byte {
	signature := binary.BigEndian.AppendUint32(nil, q)

	signature = append(signature, lmotsSign(t.ots, t.i, q, t.seed, message)...)

	signature = binary.BigEndian.AppendUint32(signature, t.lms.code)

	return append(signature, t.merkle.authPath(uint64(q))...)
}

func (t *lmsTree) child(lms *lmsType, ots *lmotsType, q uint32) *lmsTree {
	seed := make([]byte, t.lms.m)

	lmsDerive(t.lms.shake, t.lms.m, t.i, q, lmsChildSeed, t.seed, seed)

	i := make([]byte, t.lms.m)

	lmsDerive(t.lms.shake, t.lms.m, t.i, q, lmsChildI, t.seed, i)

	return newLmsTree(lms, ots, i[:16], seed)
}

type hssLevel struct {
	lms *lmsType
	ots *lmotsType
}

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
// index leaves a tree, and each child public key signed by its parent.
type hssSigner struct {
	levels   []hssLevel
	trees    []*lmsTree
	signed   [][]byte
	prefixes []uint64
}

func newHssSigner(levels []hssLevel, i, seed []byte) *hssSigner {
	top := newLmsTree(levels[0].lms, levels[0].ots, i, seed)

	return &hssSigner{levels: levels, trees: []*lmsTree{top}, prefixes: []uint64{0}}
}

func (s *hssSigner) publicKey() []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s.levels))), s.trees[0].publicKey...)
}

// The total height of the given level and every level below it.
func (s *hssSigner) heightFrom(level int) int {
	total := 0

	for _, l := range s.levels[level:] {
		total += l.lms.h
	}

	return total
}

func (s *hssSigner) capacity() uint64 {
	return 1 << s.heightFrom(0)
}

func (s *hssSigner) leafIndex(index uint64, level int) uint32 {
	return uint32((index >> s.heightFrom(level+1)) & (1<<s.levels[level].lms.h - 1))
}

func (s *hssSigner) sign(index uint64, message []byte) []byte {
	for level := 1; level < len(s.levels); level++ {
		prefix := index >> s.heightFrom(level)

		if level < len(s.trees) && s.prefixes[level] == prefix {
			continue
		}

		for _, old := range s.trees[level:] {
			clear(old.seed)
		}

		s.trees, s.signed, s.prefixes = s.trees[:level], s.signed[:level-1], s.prefixes[:level]

		parent := s.trees[level-1]

		q := s.leafIndex(index, level-1)

		tree := parent.child(s.levels[level].lms, s.levels[level].ots, q)

		s.trees = append(s.trees, tree)

		s.signed = append(s.signed, append(parent.sign(q, tree.publicKey), tree.publicKey...))

		s.prefixes = append(s.prefixes, prefix)
	}

	last := len(s.levels) - 1

	signature := binary.BigEndian.AppendUint32(nil, uint32(last))

	for _, part := range s.signed {
		signature = append(signature, part...)
	}

	return append(signature, s.trees[last].sign(s.leafIndex(index, last), message)...)
}

func (s *hssSigner) wipe() {
	for _, tree := range s.trees {
		clear(tree.seed)
	}
}
