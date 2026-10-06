package main

import "fmt"

// BLAKE2b with AVX2 and BLAKE2s with 128-bit AVX: one row of the working vector per register (a in
// 0, b in 1, c in 2, d in 3), so that each step of four G functions is one instruction per
// operation. The rows are rotated against each other between the column and the diagonal step and
// back. Each round's four message vectors are gathered from the block with VMOVQ/VMOVD and inserts
// into 4-7, the chaining value stays in 8 and 9 from block to block, the IV in 10 and 11, the
// byte-shuffle rotations in 12 and 13, and 14 and 15 are scratch. Right rotations by whole bytes
// are VPSHUFB, by 32 bits within a 64-bit element VPSHUFD, and the others two shifts and an OR.

// One flavor of the vector code: the element width in bits, the register prefix, the word load and
// insert, and the lane permutation.
type blake2Vector struct {
	flavor  blake2Flavor
	width   int
	reg     string
	load    string
	insert  string
	permute string
}

var (
	blake2bVector = blake2Vector{blake2bFlavor, 64, "Y", "VMOVQ", "VPINSRQ", "VPERMQ"}
	blake2sVector = blake2Vector{blake2sFlavor, 32, "X", "VMOVD", "VPINSRD", "VPSHUFD"}
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

// Element-wise right rotation of register i by bits, with 15 as scratch.
func (v blake2Vector) rotate(a *asm, i, bits int) {
	x, t := v.r(i), v.r(15)

	switch {
	case v.width == 64 && bits == 32:
		a.op("VPSHUFD\t$0xb1, %s, %s", x, x)
	case v.width == 64 && (bits == 24 || bits == 16):
		a.op("VPSHUFB\t%s, %s, %s", v.r(12+(24-bits)/8), x, x)
	case v.width == 32 && (bits == 16 || bits == 8):
		a.op("VPSHUFB\t%s, %s, %s", v.r(12+(16-bits)/8), x, x)
	default:
		a.op("VPSRL%s\t$%d, %s, %s", map[int]string{64: "Q", 32: "D"}[v.width], bits, x, t)

		a.op("VPSLL%s\t$%d, %s, %s", map[int]string{64: "Q", 32: "D"}[v.width], v.width-bits, x, x)

		a.op("VPOR\t%s, %s, %s", t, x, x)
	}
}

// Gathers the message words at the schedule positions words into register i, the upper half of a
// 256-bit register through 14.
func (v blake2Vector) gather(a *asm, i int, words [4]int) {
	size := v.width / 8

	x := fmt.Sprintf("X%d", i)

	if v.width == 64 {
		a.op("%s\t%d(SI), %s", v.load, size*words[0], x)

		a.op("%s\t$1, %d(SI), %s, %s", v.insert, size*words[1], x, x)

		a.op("%s\t%d(SI), X14", v.load, size*words[2])

		a.op("%s\t$1, %d(SI), X14, X14", v.insert, size*words[3])

		a.op("VINSERTI128\t$1, X14, Y%d, Y%d", i, i)

		return
	}

	a.op("%s\t%d(SI), %s", v.load, size*words[0], x)

	for lane := 1; lane < 4; lane++ {
		a.op("%s\t$%d, %d(SI), %s, %s", v.insert, lane, size*words[lane], x, x)
	}
}

// Half of a step: the four G halves with message register m and the rotations.
func (v blake2Vector) half(a *asm, m int, rotations [2]int) {
	add := map[int]string{64: "VPADDQ", 32: "VPADDD"}[v.width]

	a.op("%s\t%s, %s, %s", add, v.r(m), v.r(0), v.r(0))

	a.op("%s\t%s, %s, %s", add, v.r(1), v.r(0), v.r(0))

	a.op("VPXOR\t%s, %s, %s", v.r(0), v.r(3), v.r(3))

	v.rotate(a, 3, rotations[0])

	a.op("%s\t%s, %s, %s", add, v.r(3), v.r(2), v.r(2))

	a.op("VPXOR\t%s, %s, %s", v.r(2), v.r(1), v.r(1))

	v.rotate(a, 1, rotations[1])
}

// Rotates rows b, c and d left by one, two and three elements, or back.
func (v blake2Vector) diagonalize(a *asm, back bool) {
	shifts := [3]int{1, 2, 3}

	if back {
		shifts = [3]int{3, 2, 1}
	}

	for row, shift := range shifts {
		order := 0

		for lane := range 4 {
			order |= (lane + shift) % 4 << (2 * lane)
		}

		a.op("%s\t$%#x, %s, %s", v.permute, order, v.r(1+row), v.r(1+row))
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

		a.op("VMOVDQU\tblake2sIVx86<>+0(SB), X10")

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

	a.op("VMOVDQA\t%s, %s", v.r(10), v.r(2))

	for r := range f.rounds {
		s := blake2Sigma[r%10]

		v.gather(a, 4, [4]int{s[0], s[2], s[4], s[6]})

		v.gather(a, 5, [4]int{s[1], s[3], s[5], s[7]})

		v.gather(a, 6, [4]int{s[8], s[10], s[12], s[14]})

		v.gather(a, 7, [4]int{s[9], s[11], s[13], s[15]})

		v.half(a, 4, [2]int{f.rotations[0], f.rotations[1]})

		v.half(a, 5, [2]int{f.rotations[2], f.rotations[3]})

		v.diagonalize(a, false)

		v.half(a, 6, [2]int{f.rotations[0], f.rotations[1]})

		v.half(a, 7, [2]int{f.rotations[2], f.rotations[3]})

		v.diagonalize(a, true)
	}

	a.op("VPXOR\t%s, %s, %s", v.r(0), v.r(8), v.r(8))

	a.op("VPXOR\t%s, %s, %s", v.r(2), v.r(8), v.r(8))

	a.op("VPXOR\t%s, %s, %s", v.r(1), v.r(9), v.r(9))

	a.op("VPXOR\t%s, %s, %s", v.r(3), v.r(9), v.r(9))

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
