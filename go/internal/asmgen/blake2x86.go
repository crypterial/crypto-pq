package main

import "fmt"

// BLAKE2b with AVX2 and BLAKE2s with 128-bit AVX2: one row of the working vector per register (a in
// 0, b in 1, c in 2, d in 3), so that each step of four G functions is one instruction per
// operation. A block is one chain of dependent instructions through b, whose length sets the speed:
// for the diagonal step rows a, c and d are rotated against b and back after it, rather than b, c
// and d against a, so that the lane permutations (three cycles for VPERMQ on Intel cores) overlap
// the instructions that compute b. Each message vector is built from broadcast loads of the block's
// words merged with VPBLENDD, which leaves the shuffle port to the rotations. The chaining value
// stays in 8 and 9 from block to block, the IV in 10 and 11 (BLAKE2s, which needs 10 as scratch,
// reads its first half from memory once a block), the byte-shuffle rotations in 12 and 13, the
// message vectors in 4-7, and 14 and 15 are scratch. Right rotations by whole bytes are VPSHUFB, by
// 32 bits within a 64-bit element VPSHUFD, by 63 bits the element added to itself, a shift and an
// XOR, and the others two shifts and an OR.

// One flavor of the vector code: the element width in bits, the register prefix, the broadcast load
// of one word, the add and the lane permutation.
type blake2Vector struct {
	flavor    blake2Flavor
	width     int
	reg       string
	broadcast string
	add       string
	permute   string
}

var (
	blake2bVector = blake2Vector{blake2bFlavor, 64, "Y", "VPBROADCASTQ", "VPADDQ", "VPERMQ"}
	blake2sVector = blake2Vector{blake2sFlavor, 32, "X", "VPBROADCASTD", "VPADDD", "VPSHUFD"}
)

func blake2Amd64(a *asm) {
	blake2BlocksAmd(a, blake2bVector)

	blake2BlocksAmd(a, blake2sVector)

	a.table("blake2bIVx86", 8, sha512InitialValues())

	a.table("blake2sIVx86", 4, sha256InitialValues())

	// VPSHUFB patterns that rotate each 64-bit element right by 24 and 16 bits, and each 32-bit
	// element right by 16 and 8 bits.
	a.table("blake2bRotate24", 8, []uint64{0x0201000706050403, 0x0a09080f0e0d0c0b, 0x0201000706050403, 0x0a09080f0e0d0c0b})

	a.table("blake2bRotate16", 8, []uint64{0x0100070605040302, 0x09080f0e0d0c0b0a, 0x0100070605040302, 0x09080f0e0d0c0b0a})

	a.table("blake2sRotate16", 8, []uint64{0x0504070601000302, 0x0d0c0f0e09080b0a})

	a.table("blake2sRotate8", 8, []uint64{0x0407060500030201, 0x0c0f0e0d080b0a09})
}

func (v blake2Vector) r(i int) string {
	return fmt.Sprintf("%s%d", v.reg, i)
}

// Element-wise right rotation of register i by bits, with 15 as scratch. A rotation by two shifts,
// which only BLAKE2s has, leaves its halves in 10 and 15 as well, and reports it: they have no bit
// in common, so that the next half can add both to a instead of waiting for the OR. Haswell shifts
// vectors on one port only, so there the second shift waits a cycle and the OR would add one more.
func (v blake2Vector) rotate(a *asm, i, bits int) (split bool) {
	x, t := v.r(i), v.r(15)

	shift := map[int]string{64: "Q", 32: "D"}[v.width]

	switch {
	case v.width == 64 && bits == 32:
		a.op("VPSHUFD\t$0xb1, %s, %s", x, x)
	case v.width == 64 && (bits == 24 || bits == 16):
		a.op("VPSHUFB\t%s, %s, %s", v.r(12+(24-bits)/8), x, x)
	case v.width == 32 && (bits == 16 || bits == 8):
		a.op("VPSHUFB\t%s, %s, %s", v.r(12+(16-bits)/8), x, x)
	case bits == v.width-1:
		a.op("%s\t%s, %s, %s", v.add, x, x, t)

		a.op("VPSRL%s\t$%d, %s, %s", shift, bits, x, x)

		a.op("VPXOR\t%s, %s, %s", t, x, x)
	default:
		a.op("VPSRL%s\t$%d, %s, %s", shift, bits, x, v.r(10))

		a.op("VPSLL%s\t$%d, %s, %s", shift, v.width-bits, x, t)

		a.op("VPOR\t%s, %s, %s", v.r(10), t, x)

		return true
	}

	return false
}

// Builds in register i the vector of the message words at the schedule positions words, one per
// lane: a broadcast of each word, blended into its lane, with 14 as scratch.
func (v blake2Vector) gather(a *asm, i int, words [4]int) {
	size := v.width / 8

	x, t := v.r(i), v.r(14)

	a.op("%s\t%d(SI), %s", v.broadcast, size*words[0], x)

	for lane := 1; lane < 4; lane++ {
		mask := 1 << lane

		if v.width == 64 {
			mask = 3 << (2 * lane)
		}

		a.op("%s\t%d(SI), %s", v.broadcast, size*words[lane], t)

		a.op("VPBLENDD\t$%#x, %s, %s, %s", mask, t, x, x)
	}
}

// The schedule positions of message vector i of round r, one per lane: the column step's halves,
// then the diagonal step's in the lane order of diagonalize.
func blake2Words(r, i int) [4]int {
	s := blake2Sigma[r%10]

	switch i {
	case 0:
		return [4]int{s[0], s[2], s[4], s[6]}
	case 1:
		return [4]int{s[1], s[3], s[5], s[7]}
	case 2:
		return [4]int{s[14], s[8], s[10], s[12]}
	default:
		return [4]int{s[15], s[9], s[11], s[13]}
	}
}

// Half of a step: the four G halves with message register m and the rotations, b taken from its
// split halves when the previous half left them; reports whether this one does.
func (v blake2Vector) half(a *asm, m int, rotations [2]int, split bool) bool {
	a.op("%s\t%s, %s, %s", v.add, v.r(m), v.r(0), v.r(0))

	if split {
		a.op("%s\t%s, %s, %s", v.add, v.r(10), v.r(0), v.r(0))

		a.op("%s\t%s, %s, %s", v.add, v.r(15), v.r(0), v.r(0))
	} else {
		a.op("%s\t%s, %s, %s", v.add, v.r(1), v.r(0), v.r(0))
	}

	a.op("VPXOR\t%s, %s, %s", v.r(0), v.r(3), v.r(3))

	v.rotate(a, 3, rotations[0])

	a.op("%s\t%s, %s, %s", v.add, v.r(3), v.r(2), v.r(2))

	a.op("VPXOR\t%s, %s, %s", v.r(2), v.r(1), v.r(1))

	return v.rotate(a, 1, rotations[1])
}

// For the diagonal step, lane i holds the G function of b's element i, which is diagonal function
// (i + 3) mod 4: rows a, c and d move by three, one and two lanes, and back after the step.
var blake2DiagonalShifts = [3]int{3, 1, 2}

// Rotates rows a, c and d for the diagonal step, or back.
func (v blake2Vector) diagonalize(a *asm, back bool) {
	for k, row := range [3]int{0, 2, 3} {
		shift := blake2DiagonalShifts[k]

		if back {
			shift = (4 - shift) % 4
		}

		order := 0

		for lane := range 4 {
			order |= (lane + shift) % 4 << (2 * lane)
		}

		a.op("%s\t$%#x, %s, %s", v.permute, order, v.r(row), v.r(row))
	}
}

func blake2BlocksAmd(a *asm, v blake2Vector) {
	f := v.flavor

	name := f.name + "BlocksAVX"

	word := map[int]string{8: "uint64", 4: "uint32"}[f.word]

	a.function(name, fmt.Sprintf("func %s(h *[8]%s, counter *[2]%s, flag %s, blocks []byte)", name, word, word, word), 48,
		fmt.Sprintf("Compresses every %d-byte block of blocks into h, adding the block size to the counter", 16*f.word),
		"before each, and flag into v14 of the last; len(blocks) is a multiple of the block size.")

	move := map[int]string{8: "MOVQ", 4: "MOVL"}[f.word]

	a.op("MOVQ\th+0(FP), AX")

	a.op("MOVQ\tcounter+8(FP), BX")

	a.op("%s\tflag+16(FP), CX", move)

	a.op("MOVQ\tblocks_base+24(FP), SI")

	a.op("MOVQ\tblocks_len+32(FP), DI")

	a.op("TESTQ\tDI, DI")

	a.op("JZ\tdone")

	a.op("%s\t(BX), R8", move)

	a.op("%s\t%d(BX), R9", move, f.word)

	if v.width == 64 {
		a.op("VMOVDQU\t(AX), Y8")

		a.op("VMOVDQU\t32(AX), Y9")

		a.op("VMOVDQU\tblake2bIVx86<>+0(SB), Y10")

		a.op("VMOVDQU\tblake2bIVx86<>+32(SB), Y11")

		a.op("VMOVDQU\tblake2bRotate24<>(SB), Y12")

		a.op("VMOVDQU\tblake2bRotate16<>(SB), Y13")
	} else {
		a.op("VMOVDQU\t(AX), X8")

		a.op("VMOVDQU\t16(AX), X9")

		a.op("VMOVDQU\tblake2sIVx86<>+16(SB), X11")

		a.op("VMOVDQU\tblake2sRotate16<>(SB), X12")

		a.op("VMOVDQU\tblake2sRotate8<>(SB), X13")
	}

	a.label("loop")

	suffix := map[int]string{8: "Q", 4: "L"}[f.word]

	a.op("ADD%s\t$%d, R8", suffix, 16*f.word)

	a.op("ADC%s\t$0, R9", suffix)

	a.op("XORQ\tR10, R10")

	a.op("CMPQ\tDI, $%d", 16*f.word)

	a.op("CMOVQEQ\tCX, R10")

	if v.width == 64 {
		a.op("VMOVQ\tR8, X14")

		a.op("VPINSRQ\t$1, R9, X14, X14")

		a.op("VMOVQ\tR10, X15")

		a.op("VINSERTI128\t$1, X15, Y14, Y14")
	} else {
		a.op("VMOVD\tR8, X14")

		a.op("VPINSRD\t$1, R9, X14, X14")

		a.op("VPINSRD\t$2, R10, X14, X14")
	}

	a.op("VPXOR\t%s, %s, %s", v.r(11), v.r(14), v.r(3))

	a.op("VMOVDQA\t%s, %s", v.r(8), v.r(0))

	a.op("VMOVDQA\t%s, %s", v.r(9), v.r(1))

	if v.width == 64 {
		a.op("VMOVDQA\tY10, Y2")
	} else {
		a.op("VMOVDQU\tblake2sIVx86<>+0(SB), X2")
	}

	split := false

	for r := range f.rounds {
		for i := range 4 {
			v.gather(a, 4+i, blake2Words(r, i))
		}

		split = v.half(a, 4, [2]int{f.rotations[0], f.rotations[1]}, split)

		split = v.half(a, 5, [2]int{f.rotations[2], f.rotations[3]}, split)

		v.diagonalize(a, false)

		split = v.half(a, 6, [2]int{f.rotations[0], f.rotations[1]}, split)

		split = v.half(a, 7, [2]int{f.rotations[2], f.rotations[3]}, split)

		v.diagonalize(a, true)
	}

	a.comment("h ^= v[0:8] ^ v[8:16], with b, the last row to settle, XORed last.")

	a.op("VPXOR\t%s, %s, %s", v.r(0), v.r(8), v.r(8))

	a.op("VPXOR\t%s, %s, %s", v.r(2), v.r(8), v.r(8))

	a.op("VPXOR\t%s, %s, %s", v.r(3), v.r(9), v.r(9))

	a.op("VPXOR\t%s, %s, %s", v.r(1), v.r(9), v.r(9))

	a.op("ADDQ\t$%d, SI", 16*f.word)

	a.op("SUBQ\t$%d, DI", 16*f.word)

	a.op("JNZ\tloop")

	if v.width == 64 {
		a.op("VMOVDQU\tY8, (AX)")

		a.op("VMOVDQU\tY9, 32(AX)")
	} else {
		a.op("VMOVDQU\tX8, (AX)")

		a.op("VMOVDQU\tX9, 16(AX)")
	}

	a.op("%s\tR8, (BX)", move)

	a.op("%s\tR9, %d(BX)", move, f.word)

	a.op("VZEROUPPER")

	a.label("done")

	a.op("RET")
}
