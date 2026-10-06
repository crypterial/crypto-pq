package main

import "fmt"

// BLAKE2b and BLAKE2s compression on the general registers: the four G functions of a step are
// four independent dependency chains, which the integer pipes overlap.
//
// The working vector v0-v15 lives in R2-R17, R0 points at the block and R1 counts its bytes down,
// R19-R22 are scratch, R23 and R24 hold the counter, R25 the final-block flag, which goes into the
// last block of the call only, and R26 the chaining value's address. Each message word is loaded
// where the schedule uses it, and added to a before b, which arrives last. On Apple M3, an EOR with
// a rotated operand takes two cycles where EOR and ROR take one each, and emitting each half of a G
// function whole measured faster than interleaving the four functions instruction by instruction
// (689 against 724 ns for 1 KiB of BLAKE2b).

var blake2Sigma = [10][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// One flavor of BLAKE2: the word size in bytes, the instruction suffix, load and pair load of that
// width, the rounds and the four rotations.
type blake2Flavor struct {
	name      string
	word      int
	suffix    string
	load      string
	pair      string
	rounds    int
	rotations [4]int
}

var (
	blake2bFlavor = blake2Flavor{"blake2b", 8, "", "MOVD", "LDP", 12, [4]int{32, 24, 16, 63}}
	blake2sFlavor = blake2Flavor{"blake2s", 4, "W", "MOVWU", "LDPW", 10, [4]int{16, 12, 8, 7}}
)

var (
	blake2Columns   = [4][4]int{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}}
	blake2Diagonals = [4][4]int{{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}
)

func blake2Arm64(a *asm) {
	blake2BlocksArm(a, blake2bFlavor)

	blake2BlocksArm(a, blake2sFlavor)

	a.table("blake2bIV", 8, sha512InitialValues())

	a.table("blake2sIV", 4, sha256InitialValues())
}

func blake2V(i int) string {
	return fmt.Sprintf("R%d", 2+i)
}

// Half of G on the words q = (a, b, c, d) with message word m and the given rotations, the word
// loaded into scratch register R19 + g.
func blake2HalfG(a *asm, f blake2Flavor, g int, q [4]int, m int, rotations [2]int) {
	va, vb, vc, vd := blake2V(q[0]), blake2V(q[1]), blake2V(q[2]), blake2V(q[3])

	a.op("%s\t%d(R0), R%d", f.load, f.word*m, 19+g)

	a.op("ADD%s\tR%d, %s, %s", f.suffix, 19+g, va, va)

	a.op("ADD%s\t%s, %s, %s", f.suffix, vb, va, va)

	a.op("EOR%s\t%s, %s, %s", f.suffix, va, vd, vd)

	a.op("ROR%s\t$%d, %s, %s", f.suffix, rotations[0], vd, vd)

	a.op("ADD%s\t%s, %s, %s", f.suffix, vd, vc, vc)

	a.op("EOR%s\t%s, %s, %s", f.suffix, vc, vb, vb)

	a.op("ROR%s\t$%d, %s, %s", f.suffix, rotations[1], vb, vb)
}

// A step on the columns or the diagonals: the first halves of the four G functions, then the
// second halves.
func blake2Step(a *asm, f blake2Flavor, quads [4][4]int, s [16]int, offset int) {
	for g, q := range quads {
		blake2HalfG(a, f, g, q, s[offset+2*g], [2]int{f.rotations[0], f.rotations[1]})
	}

	for g, q := range quads {
		blake2HalfG(a, f, g, q, s[offset+2*g+1], [2]int{f.rotations[2], f.rotations[3]})
	}
}

func blake2BlocksArm(a *asm, f blake2Flavor) {
	name := f.name + "BlocksARM"

	word := map[int]string{8: "uint64", 4: "uint32"}[f.word]

	a.function(name, fmt.Sprintf("func %s(h *[8]%s, counter *[2]%s, flag %s, blocks []byte)", name, word, word, word), 48,
		fmt.Sprintf("Compresses every %d-byte block of blocks into h, adding the block size to the counter", 16*f.word),
		"before each, and flag into v14 of the last; len(blocks) is a multiple of the block size.")

	a.op("MOVD\th+0(FP), R26")

	a.op("MOVD\tcounter+8(FP), R19")

	a.op("%s\t(R19), (R23, R24)", f.pair)

	a.op("%s\tflag+16(FP), R25", f.load)

	a.op("MOVD\tblocks_base+24(FP), R0")

	a.op("MOVD\tblocks_len+32(FP), R1")

	a.op("CBZ\tR1, done")

	for i := 0; i < 8; i += 2 {
		a.op("%s\t%d(R26), (%s, %s)", f.pair, f.word*i, blake2V(i), blake2V(i+1))
	}

	a.label("loop")

	a.op("ADDS%s\t$%d, R23, R23", f.suffix, 16*f.word)

	a.op("ADC%s\tZR, R24, R24", f.suffix)

	a.op("MOVD\t$%sIV<>(SB), R19", f.name)

	for i := 0; i < 8; i += 2 {
		a.op("%s\t%d(R19), (%s, %s)", f.pair, f.word*i, blake2V(8+i), blake2V(9+i))
	}

	a.op("EOR%s\tR23, %s, %s", f.suffix, blake2V(12), blake2V(12))

	a.op("EOR%s\tR24, %s, %s", f.suffix, blake2V(13), blake2V(13))

	a.op("CMP\t$%d, R1", 16*f.word)

	a.op("CSEL\tEQ, R25, ZR, R20")

	a.op("EOR%s\tR20, %s, %s", f.suffix, blake2V(14), blake2V(14))

	for r := range f.rounds {
		s := blake2Sigma[r%10]

		blake2Step(a, f, blake2Columns, s, 0)

		blake2Step(a, f, blake2Diagonals, s, 8)
	}

	for i := 0; i < 8; i += 2 {
		a.op("%s\t%d(R26), (R19, R20)", f.pair, f.word*i)

		for j := range 2 {
			a.op("EOR%s\tR%d, %s, %s", f.suffix, 19+j, blake2V(i+j), blake2V(i+j))

			a.op("EOR%s\t%s, %s, %s", f.suffix, blake2V(8+i+j), blake2V(i+j), blake2V(i+j))
		}

		a.op("STP%s\t(%s, %s), %d(R26)", f.suffix, blake2V(i), blake2V(i+1), f.word*i)
	}

	a.op("ADD\t$%d, R0, R0", 16*f.word)

	a.op("SUBS\t$%d, R1, R1", 16*f.word)

	a.op("BNE\tloop")

	a.op("MOVD\tcounter+8(FP), R19")

	a.op("STP%s\t(R23, R24), (R19)", f.suffix)

	a.label("done")

	a.op("RET")
}
