package cryptopq

import (
	"encoding/binary"
	"math/bits"
	"slices"
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

// SHA-256 of I || u32(q) || u16(index) || u8(j) || x, truncated to n = len(x) bytes. The 23 + n
// bytes always fit in one block, which is assembled here directly as words, so chains and seed
// derivations avoid the byte-oriented padding of sha256Finish.
func lmsSha256Short(i []byte, q uint32, index uint16, j byte, x, out []byte) {
	n := len(x)

	var w [16]uint32

	w[0], w[1], w[2], w[3] = binary.BigEndian.Uint32(i), binary.BigEndian.Uint32(i[4:]), binary.BigEndian.Uint32(i[8:]), binary.BigEndian.Uint32(i[12:])

	w[4], w[5] = q, uint32(index)<<16|uint32(j)<<8|uint32(x[0])

	for k := 1; k < n/4; k++ {
		w[5+k] = binary.BigEndian.Uint32(x[4*k-3:])
	}

	w[5+n/4] = uint32(x[n-3])<<24 | uint32(x[n-2])<<16 | uint32(x[n-1])<<8 | 0x80

	w[15] = uint32(23+n) * 8

	s := iv256

	sha256Block(&s, &w)

	for k := range n / 4 {
		binary.BigEndian.PutUint32(out[4*k:], s[k])
	}

	clear(w[:])
}

// H(I || u32(q) || u16(index) || 0xFF || SEED).
func lmsDerive(shake bool, n int, i []byte, q uint32, index uint16, seed, out []byte) {
	if !shake {
		lmsSha256Short(i, q, index, 0xff, seed[:n], out)

		return
	}

	var data [55]byte

	lmsPrefix(data[:], i, q, index)

	data[22] = 0xff

	copy(data[23:], seed[:n])

	lmsDigest(shake, n, out, data[:23+n])

	clear(data[:])
}

// The most LM-OTS hashes in one batch; a key has up to 265 chains, which go in groups.
const lmsMaxLanes = 64

// One-block hashes H(I || u32(q) || u16(index) || u8(j) || x) of n-byte x, the chain steps and
// derivations of LM-OTS, batched for the lane kernels: SHA-256 blocks from the IV assembled as words,
// or SHAKE256 states. Their values derive from a tree's SEED, so wipe clears them after use.
type lmsLanes struct {
	shake   bool
	n       int
	blocks  []uint32
	digests []uint32
	records []uint32
	order   []int
	states  [][25]uint64
}

// The buffers exist only where the lane kernels are fast; for SHA-256, records holds one
// sha256Chains lane per chain of a key of type t.
func newLmsLanes(t *lmotsType) *lmsLanes {
	l := &lmsLanes{shake: t.shake, n: t.n}

	switch {
	case !l.fast():
	case t.shake:
		l.states = make([][25]uint64, lmsMaxLanes)
	default:
		l.blocks, l.digests = make([]uint32, 16*lmsMaxLanes), make([]uint32, 8*lmsMaxLanes)

		l.records, l.order = make([]uint32, chainRecord*t.p), make([]int, 0, t.p)
	}

	return l
}

// The 23 + n bytes fit in one block, with the padding of SHA-256 or of SHAKE256 after them.
func (l *lmsLanes) set(k int, i []byte, q uint32, index uint16, j byte, x []byte) {
	n := l.n

	if l.shake {
		var data [136]byte

		lmsPrefix(data[:], i, q, index)

		data[22] = j

		copy(data[23:], x[:n])

		data[23+n] = 0x1f

		data[135] ^= 0x80

		s := &l.states[k]

		*s = [25]uint64{}

		for m := range 17 {
			s[m] = binary.LittleEndian.Uint64(data[8*m:])
		}

		clear(data[:])

		return
	}

	w := (*[16]uint32)(l.blocks[16*k : 16*k+16])

	*w = [16]uint32{}

	w[0], w[1], w[2], w[3] = binary.BigEndian.Uint32(i), binary.BigEndian.Uint32(i[4:]), binary.BigEndian.Uint32(i[8:]), binary.BigEndian.Uint32(i[12:])

	w[4], w[5] = q, uint32(index)<<16|uint32(j)<<8|uint32(x[0])

	for m := 1; m < n/4; m++ {
		w[5+m] = binary.BigEndian.Uint32(x[4*m-3:])
	}

	w[5+n/4] = uint32(x[n-3])<<24 | uint32(x[n-2])<<16 | uint32(x[n-1])<<8 | 0x80

	w[15] = uint32(23+n) * 8
}

func (l *lmsLanes) run(count int) {
	if l.shake {
		permuteLanes(l.states[:count])
	} else {
		sha256Lanes(&iv256, l.blocks[:16*count], 1, l.digests[:8*count])
	}
}

// The n-byte result of lane k.
func (l *lmsLanes) result(k int, out []byte) {
	if l.shake {
		for m := range l.n / 8 {
			binary.LittleEndian.PutUint64(out[8*m:], l.states[k][m])
		}

		return
	}

	for m := range l.n / 4 {
		binary.BigEndian.PutUint32(out[4*m:], l.digests[8*k+m])
	}
}

// Whether the lane kernels beat hashing one call at a time.
func (l *lmsLanes) fast() bool {
	if l.shake {
		return permuteLanesFast()
	}

	return sha256LanesFast()
}

func (l *lmsLanes) wipe() {
	clear(l.blocks)

	clear(l.digests)

	clear(l.records)

	clear(l.states)
}

// The chain starts y[j] = H(I || u32(q) || u16(j) || 0xFF || SEED) of every chain j, values holding
// them one after another.
func (l *lmsLanes) derive(i []byte, q uint32, seed, values []byte) {
	n := l.n

	chains := len(values) / n

	if !l.fast() {
		for j := range chains {
			lmsDerive(l.shake, n, i, q, uint16(j), seed, values[j*n:(j+1)*n])
		}

		return
	}

	for first := 0; first < chains; first += lmsMaxLanes {
		count := min(lmsMaxLanes, chains-first)

		for k := range count {
			l.set(k, i, q, uint16(first+k), 0xff, seed)
		}

		l.run(count)

		for k := range count {
			l.result(k, values[(first+k)*n:])
		}
	}
}

// Iterates x = H(I || u32(q) || u16(j) || u8(k) || x) on the value of chain j, at values[n j:], for k
// from starts[j] to ends[j] - 1. Where the lane kernels are fast, every SHA-256 chain is a lane of
// sha256Chains, in the order of decreasing step count, and the SHAKE256 chains go in lockstep,
// group by group, so that those taking a step form one batch; otherwise the chains run one after
// another. The steps follow from the message digest, which the signature reveals.
func (l *lmsLanes) chains(i []byte, q uint32, values []byte, starts, ends []int) {
	n := l.n

	if !l.fast() {
		for j := range starts {
			lmotsChain(l.shake, n, i, q, uint16(j), starts[j], ends[j], values[j*n:(j+1)*n])
		}

		return
	}

	if !l.shake {
		order := l.order[:0]

		for j := range starts {
			if ends[j] > starts[j] {
				order = append(order, j)
			}
		}

		slices.SortStableFunc(order, func(x, y int) int { return ends[y] - starts[y] - (ends[x] - starts[x]) })

		var zero [32]byte

		for r, j := range order {
			record := l.records[chainRecord*r : chainRecord*(r+1)]

			l.set(0, i, q, uint16(j), 0, zero[:n])

			copy(record, l.blocks[:16])

			clear(record[16:])

			for k := range n / 4 {
				record[16+k] = binary.BigEndian.Uint32(values[j*n+4*k:])
			}

			record[24], record[25] = uint32(starts[j]), uint32(ends[j]-starts[j])
		}

		records := l.records[:chainRecord*len(order)]

		sha256Chains(&iv256, records, n/4, 24)

		for r, j := range order {
			for k := range n / 4 {
				binary.BigEndian.PutUint32(values[j*n+4*k:], records[chainRecord*r+16+k])
			}
		}

		return
	}

	var active [lmsMaxLanes]int

	for first := 0; first < len(starts); first += lmsMaxLanes {
		last := min(first+lmsMaxLanes, len(starts))

		low, high := slices.Min(starts[first:last]), slices.Max(ends[first:last])

		for step := low; step < high; step++ {
			count := 0

			for j := first; j < last; j++ {
				if starts[j] <= step && step < ends[j] {
					l.set(count, i, q, uint16(j), byte(step), values[j*n:(j+1)*n])

					active[count] = j

					count++
				}
			}

			l.run(count)

			for k, j := range active[:count] {
				l.result(k, values[j*n:])
			}
		}
	}
}

// Iterates x = H(I || u32(q) || u16(j) || u8(k) || x) for k from start to end - 1, one hash at a time.
func lmotsChain(shake bool, n int, i []byte, q uint32, j uint16, start, end int, x []byte) {
	if !shake {
		for k := start; k < end; k++ {
			lmsSha256Short(i, q, j, byte(k), x[:n], x)
		}

		return
	}

	var data [55]byte

	lmsPrefix(data[:], i, q, j)

	for k := start; k < end; k++ {
		data[22] = byte(k)

		copy(data[23:], x[:n])

		lmsDigest(shake, n, x, data[:23+n])
	}

	clear(data[:])
}

// The step counts of chains that start at 0 or end at 2^w - 1, for up to 265 chains.
var lmotsZeros [265]int

func lmotsEnds(t *lmotsType) []int {
	ends := make([]int, t.p)

	for j := range ends {
		ends[j] = 1<<t.w - 1
	}

	return ends
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
// 22 + p * n bytes, and ends the step counts of lmotsEnds.
func lmotsPublicKey(t *lmotsType, i []byte, q uint32, seed, out, scratch []byte, lanes *lmsLanes, ends []int) {
	n := t.n

	lmsPrefix(scratch, i, q, lmsPublicDomain)

	values := scratch[22 : 22+t.p*n]

	lanes.derive(i, q, seed, values)

	lanes.chains(i, q, values, lmotsZeros[:t.p], ends)

	lmsDigest(t.shake, n, out, scratch[:22+t.p*n])
}

func lmotsMessageHash(t *lmotsType, i []byte, q uint32, c, message []byte) []byte {
	var prefix [22]byte

	lmsPrefix(prefix[:], i, q, lmsMessageDomain)

	qHash := make([]byte, t.n)

	lmsDigestParts(t.shake, t.n, qHash, prefix[:], c, message)

	return qHash
}

func lmotsSign(t *lmotsType, i []byte, q uint32, seed, message []byte, lanes *lmsLanes) []byte {
	n := t.n

	signature := make([]byte, t.signatureSize())

	binary.BigEndian.PutUint32(signature, t.code)

	c := signature[4 : 4+n]

	lmsDerive(t.shake, n, i, q, lmsRandomizer, seed, c)

	digits := lmotsDigits(t, lmotsMessageHash(t, i, q, c, message))

	values := signature[4+n : 4+n*(t.p+1)]

	lanes.derive(i, q, seed, values)

	lanes.chains(i, q, values, lmotsZeros[:t.p], digits)

	return signature
}

// The public key candidate Kc computed from an LM-OTS signature (RFC 8554, Algorithm 4b).
func lmotsCandidate(t *lmotsType, i []byte, q uint32, signature, message []byte) []byte {
	n := t.n

	scratch := make([]byte, 22+t.p*n)

	lmsPrefix(scratch, i, q, lmsPublicDomain)

	digits := lmotsDigits(t, lmotsMessageHash(t, i, q, signature[4:4+n], message))

	values := scratch[22:]

	copy(values, signature[4+n:4+n*(t.p+1)])

	newLmsLanes(t).chains(i, q, values, digits, lmotsEnds(t))

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

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys, with the
// lanes its one-time keys hash in.
type lmsTree struct {
	lms       *lmsType
	ots       *lmotsType
	i         []byte
	seed      []byte
	merkle    *merkleTree
	publicKey []byte
	lanes     *lmsLanes
}

// The Merkle tree is built, or restored from nodes, its cached levels in a tree cache; a restored
// tree is nil when those do not hold together.
func newLmsTree(lms *lmsType, ots *lmotsType, i, seed, nodes []byte) *lmsTree {
	t := &lmsTree{lms: lms, ots: ots, i: i, seed: seed, lanes: newLmsLanes(ots)}

	scratch, ends := make([]byte, 22+ots.p*ots.n), lmotsEnds(ots)

	leaf := func(q uint64, out []byte) {
		var data [54]byte

		lmsPrefix(data[:], i, uint32(1<<lms.h+q), lmsLeafDomain)

		lmotsPublicKey(ots, i, uint32(q), seed, data[22:], scratch, t.lanes, ends)

		lmsDigest(lms.shake, lms.m, out, data[:22+ots.n])
	}

	combine := func(z int, j uint64, left, right, out []byte) {
		var data [86]byte

		lmsPrefix(data[:], i, uint32(1<<(lms.h-z-1)+j), lmsInteriorDomain)

		copy(data[22:], left)

		copy(data[22+lms.m:], right)

		lmsDigest(lms.shake, lms.m, out, data[:22+2*lms.m])
	}

	if nodes == nil {
		t.merkle = newMerkleTree(lms.h, lms.m, leaf, combine)
	} else if t.merkle = restoreMerkleTree(lms.h, lms.m, leaf, combine, nodes); t.merkle == nil {
		return nil
	}

	t.lanes.wipe()

	t.publicKey = binary.BigEndian.AppendUint32(nil, lms.code)

	t.publicKey = binary.BigEndian.AppendUint32(t.publicKey, ots.code)

	t.publicKey = append(append(t.publicKey, i...), t.merkle.root()...)

	return t
}

func (t *lmsTree) sign(q uint32, message []byte) []byte {
	signature := binary.BigEndian.AppendUint32(nil, q)

	signature = append(signature, lmotsSign(t.ots, t.i, q, t.seed, message, t.lanes)...)

	signature = binary.BigEndian.AppendUint32(signature, t.lms.code)

	signature = append(signature, t.merkle.authPath(uint64(q))...)

	t.lanes.wipe()

	return signature
}

// The I and SEED of the child tree that leaf q signs, from the I and SEED of its parent, a tree of
// type lms.
func lmsChildKeys(lms *lmsType, i, seed []byte, q uint32) ([]byte, []byte) {
	childSeed := make([]byte, lms.m)

	lmsDerive(lms.shake, lms.m, i, q, lmsChildSeed, seed, childSeed)

	childI := make([]byte, lms.m)

	lmsDerive(lms.shake, lms.m, i, q, lmsChildI, seed, childI)

	return childI[:16], childSeed
}

func (t *lmsTree) child(lms *lmsType, ots *lmotsType, q uint32) *lmsTree {
	i, seed := lmsChildKeys(t.lms, t.i, t.seed, q)

	return newLmsTree(lms, ots, i, seed, nil)
}

type hssLevel struct {
	lms *lmsType
	ots *lmotsType
}

// A lower tree of a tree cache and its number on its level.
type hssRestored struct {
	prefix uint64
	tree   *lmsTree
}

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
// index leaves a tree, and each child public key signed by its parent. restored holds, by level,
// the lower trees of a tree cache until the first signature needs them.
type hssSigner struct {
	levels   []hssLevel
	trees    []*lmsTree
	signed   [][]byte
	prefixes []uint64
	restored []hssRestored
}

// cached holds, by level, the trees of an authentic tree cache that the next index signs with: the
// top one replaces the build and the lower ones wait in restored. Each is checked against its own
// nodes before the top tree is built, and the result is nil, with every seed wiped, when one does
// not hold together.
func newHssSigner(levels []hssLevel, i, seed []byte, cached []*cachedTree) *hssSigner {
	s := &hssSigner{levels: levels, prefixes: []uint64{0}, restored: make([]hssRestored, len(levels))}

	var nodes []byte

	for level, tree := range cached {
		switch {
		case tree == nil:
		case level == 0:
			nodes = tree.nodes
		default:
			restored := s.pathTree(level, tree.number, i, seed, tree.nodes)

			if restored == nil {
				s.wipe()

				clear(seed)

				return nil
			}

			s.restored[level] = hssRestored{tree.number, restored}
		}
	}

	top := newLmsTree(levels[0].lms, levels[0].ots, i, seed, nodes)

	if top == nil {
		s.wipe()

		clear(seed)

		return nil
	}

	s.trees = []*lmsTree{top}

	return s
}

// Tree number prefix of a lower level, restored from nodes: the leaves that sign it on the levels
// above follow from its number, and with them its I and SEED, derived from the top tree's i and
// seed. Nil, with the SEED wiped, when the nodes do not hold together.
func (s *hssSigner) pathTree(level int, prefix uint64, i, seed, nodes []byte) *lmsTree {
	for upper := range level {
		below := s.heightFrom(upper+1) - s.heightFrom(level)

		q := uint32((prefix >> below) & (1<<s.levels[upper].lms.h - 1))

		childI, childSeed := lmsChildKeys(s.levels[upper].lms, i, seed, q)

		// The SEED of a tree between the top and this one served only this derivation.
		if upper > 0 {
			clear(seed)
		}

		i, seed = childI, childSeed
	}

	tree := newLmsTree(s.levels[level].lms, s.levels[level].ots, i, seed, nodes)

	if tree == nil {
		clear(seed)
	}

	return tree
}

// Every tree the signer holds, top first: those on the path of the last signature, then the
// trees of a tree cache that wait for the first one.
func (s *hssSigner) cached() []heldTree {
	held := make([]heldTree, 0, len(s.levels))

	for level, tree := range s.trees {
		held = append(held, heldTree{level, s.prefixes[level], tree.merkle})
	}

	for level, waiting := range s.restored {
		if waiting.tree != nil {
			held = append(held, heldTree{level, waiting.prefix, waiting.tree.merkle})
		}
	}

	return held
}

// The tree of a tree cache that waits on level, if it is tree prefix there; it waits no longer
// either way.
func (s *hssSigner) takeRestored(level int, prefix uint64) *lmsTree {
	waiting := s.restored[level]

	s.restored[level] = hssRestored{}

	if waiting.tree != nil && waiting.prefix != prefix {
		clear(waiting.tree.seed)

		return nil
	}

	return waiting.tree
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

		tree := s.takeRestored(level, prefix)

		if tree == nil {
			tree = parent.child(s.levels[level].lms, s.levels[level].ots, q)
		}

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

	for _, waiting := range s.restored {
		if waiting.tree != nil {
			clear(waiting.tree.seed)
		}
	}
}
