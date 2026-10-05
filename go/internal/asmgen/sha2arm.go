package main

import "fmt"

// SHA-256 and SHA-512 with the ARMv8 SHA2 and SHA512 instructions.

func sha2Arm64(a *asm) {
	sha256BlocksArm(a)

	sha256WordsArm(a)

	sha256LanesArm(a)

	sha256ChainsArm(a, 16)

	sha256ChainsArm(a, 24)

	sha512BlocksArm(a)

	sha512WordsArm(a)

	a.table("k256", 4, sha256Constants())

	a.table("k512", 8, sha512Constants())
}

// One SHA-256 computation in vector registers: abcd and efgh, a copy of abcd for SHA256H2, which
// needs the value SHA256H replaces, W + K, and the sixteen schedule words in four registers.
type sha256Stream struct {
	abcd, efgh, saved, wk int
	w                     [4]int
}

// Rounds 4g to 4g + 3 with the round constants in register k; the four schedule words they use
// are then replaced by the words of rounds 4g + 16 to 4g + 19.
func (s *sha256Stream) group(a *asm, g, k int) {
	a.op("VADD\tV%d.S4, V%d.S4, V%d.S4", k, s.w[g%4], s.wk)

	a.op("VMOV\tV%d.B16, V%d.B16", s.abcd, s.saved)

	a.op("SHA256H\tV%d.S4, V%d, V%d", s.wk, s.efgh, s.abcd)

	a.op("SHA256H2\tV%d.S4, V%d, V%d", s.wk, s.saved, s.efgh)

	if g < 12 {
		a.op("SHA256SU0\tV%d.S4, V%d.S4", s.w[(g+1)%4], s.w[g%4])

		a.op("SHA256SU1\tV%d.S4, V%d.S4, V%d.S4", s.w[(g+3)%4], s.w[(g+2)%4], s.w[g%4])
	}
}

// The state in V0 and V1, working copies in V2 and V3, the schedule in V4-V7.
var sha256Single = sha256Stream{abcd: 2, efgh: 3, saved: 8, wk: 9, w: [4]int{4, 5, 6, 7}}

// The second computation of a pair: state V10 and V11, working copies V12 and V13.
var sha256Second = sha256Stream{abcd: 12, efgh: 13, saved: 18, wk: 19, w: [4]int{14, 15, 16, 17}}

// One block on the state in V0 and V1, whose schedule words are in V4-V7, with the round
// constants loaded group by group into V20 through R8; holding all of them in registers measured
// no faster. A block depends on the one before it, so a stream runs at the instructions' latency:
// 23 ns per block on Apple M3, against 17.4 ns for independent blocks, which overlap.
func sha256Block(a *asm) {
	a.op("MOVD\t$k256<>(SB), R8")

	a.op("VMOV\tV0.B16, V2.B16")

	a.op("VMOV\tV1.B16, V3.B16")

	for g := range 16 {
		a.op("VLD1.P\t16(R8), [V20.S4]")

		sha256Single.group(a, g, 20)
	}

	a.op("VADD\tV2.S4, V0.S4, V0.S4")

	a.op("VADD\tV3.S4, V1.S4, V1.S4")
}

func sha256BlocksArm(a *asm) {
	a.function("sha256BlocksARM", "func sha256BlocksARM(state *[8]uint32, p []byte)", 32,
		"Compresses every 64-byte block of p into state; len(p) is a multiple of 64.")

	a.op("MOVD\tstate+0(FP), R0")

	a.op("MOVD\tp_base+8(FP), R1")

	a.op("MOVD\tp_len+16(FP), R2")

	a.op("CBZ\tR2, done")

	a.op("VLD1\t(R0), [V0.S4, V1.S4]")

	a.label("loop")

	a.op("VLD1.P\t64(R1), [V4.B16, V5.B16, V6.B16, V7.B16]")

	for i := 4; i < 8; i++ {
		a.op("VREV32\tV%d.B16, V%d.B16", i, i)
	}

	sha256Block(a)

	a.op("SUBS\t$64, R2, R2")

	a.op("BNE\tloop")

	a.op("VST1\t[V0.S4, V1.S4], (R0)")

	a.label("done")

	a.op("RET")
}

func sha256WordsArm(a *asm) {
	a.function("sha256WordsARM", "func sha256WordsARM(state *[8]uint32, w *[16]uint32)", 16,
		"Compresses one block, given as its sixteen big-endian words, into state.")

	a.op("MOVD\tstate+0(FP), R0")

	a.op("MOVD\tw+8(FP), R1")

	a.op("VLD1\t(R0), [V0.S4, V1.S4]")

	a.op("VLD1\t(R1), [V4.S4, V5.S4, V6.S4, V7.S4]")

	sha256Block(a)

	a.op("VST1\t[V0.S4, V1.S4], (R0)")

	a.op("RET")
}

// The lanes go in pairs, whose rounds interleave so that one computation's instructions run
// while the other's wait on their results; an odd last lane goes alone. The round constants are
// loaded group by group into V20, since the pair needs most of the registers.
func sha256LanesArm(a *asm) {
	a.function("sha256LanesARM", "func sha256LanesARM(init *[8]uint32, blocks []uint32, nb int, out []uint32)", 64,
		"Hashes len(out) / 8 independent lanes: lane i starts from init and compresses nb blocks of",
		"big-endian words, blocks[16 nb i:16 nb (i + 1)], and its state goes to out[8i:8i + 8].")

	a.op("MOVD\tinit+0(FP), R0")

	a.op("MOVD\tblocks_base+8(FP), R1")

	a.op("MOVD\tnb+32(FP), R2")

	a.op("MOVD\tout_base+40(FP), R3")

	a.op("MOVD\tout_len+48(FP), R4")

	a.op("CBZ\tR2, done")

	a.op("LSR\t$3, R4, R4")

	a.op("LSL\t$6, R2, R5")

	a.label("pair")

	a.op("CMP\t$2, R4")

	a.op("BLT\tsingle")

	a.op("ADD\tR1, R5, R6")

	a.op("VLD1\t(R0), [V0.S4, V1.S4]")

	a.op("VMOV\tV0.B16, V10.B16")

	a.op("VMOV\tV1.B16, V11.B16")

	a.op("MOVD\tR2, R7")

	a.label("pairBlock")

	a.op("VLD1.P\t64(R1), [V4.S4, V5.S4, V6.S4, V7.S4]")

	a.op("VLD1.P\t64(R6), [V14.S4, V15.S4, V16.S4, V17.S4]")

	a.op("MOVD\t$k256<>(SB), R8")

	a.op("VMOV\tV0.B16, V2.B16")

	a.op("VMOV\tV1.B16, V3.B16")

	a.op("VMOV\tV10.B16, V12.B16")

	a.op("VMOV\tV11.B16, V13.B16")

	for g := range 16 {
		a.op("VLD1.P\t16(R8), [V20.S4]")

		sha256Single.group(a, g, 20)

		sha256Second.group(a, g, 20)
	}

	a.op("VADD\tV2.S4, V0.S4, V0.S4")

	a.op("VADD\tV3.S4, V1.S4, V1.S4")

	a.op("VADD\tV12.S4, V10.S4, V10.S4")

	a.op("VADD\tV13.S4, V11.S4, V11.S4")

	a.op("SUBS\t$1, R7, R7")

	a.op("BNE\tpairBlock")

	a.op("VST1.P\t[V0.S4, V1.S4], 32(R3)")

	a.op("VST1.P\t[V10.S4, V11.S4], 32(R3)")

	a.op("MOVD\tR6, R1")

	a.op("SUB\t$2, R4, R4")

	a.op("B\tpair")

	a.label("single")

	a.op("CBZ\tR4, done")

	a.op("VLD1\t(R0), [V0.S4, V1.S4]")

	a.op("MOVD\tR2, R7")

	a.label("singleBlock")

	a.op("VLD1.P\t64(R1), [V4.S4, V5.S4, V6.S4, V7.S4]")

	a.op("MOVD\t$k256<>(SB), R8")

	a.op("VMOV\tV0.B16, V2.B16")

	a.op("VMOV\tV1.B16, V3.B16")

	for g := range 16 {
		a.op("VLD1.P\t16(R8), [V20.S4]")

		sha256Single.group(a, g, 20)
	}

	a.op("VADD\tV2.S4, V0.S4, V0.S4")

	a.op("VADD\tV3.S4, V1.S4, V1.S4")

	a.op("SUBS\t$1, R7, R7")

	a.op("BNE\tsingleBlock")

	a.op("VST1\t[V0.S4, V1.S4], (R3)")

	a.label("done")

	a.op("RET")
}

// One computation of a chain kernel: the lane record at the register record (a 16-word block
// template, then the 8-word value, then the first step and the step count), the step counter, the
// value in two registers, a vector for the step and two temporaries, and the SHA-256 registers.
type chainLane struct {
	record, step, shifted string
	value                 [2]int
	stepVector, x, y      int
	stream                sha256Stream
}

var (
	chainFirst = chainLane{record: "R1", step: "R5", shifted: "R12", value: [2]int{0, 1}, stepVector: 24, x: 10, y: 11, stream: sha256Single}

	chainSecond = chainLane{record: "R11", step: "R6", shifted: "R13", value: [2]int{12, 13}, stepVector: 25, x: 22, y: 23, stream: sha256Second}
)

// The block of the next step: the template with the step counter just above the value, and the
// value's words shifted right by shift bits from word 5 on, so that word 5 + m receives the low
// bits of value word m - 1 and the high bits of word m. V31 is zero, V28 and V29 the initial state.
func (l *chainLane) build(a *asm, shift int) {
	w := l.stream.w

	a.op("VLD1\t(%s), [V%d.S4, V%d.S4, V%d.S4, V%d.S4]", l.record, w[0], w[1], w[2], w[3])

	a.op("LSL\t$%d, %s, %s", 32-shift, l.step, l.shifted)

	a.op("VMOV\t%s, V%d.S[1]", l.shifted, l.stepVector)

	a.op("VORR\tV%d.B16, V%d.B16, V%d.B16", l.stepVector, w[1], w[1])

	v0, v1 := l.value[0], l.value[1]

	for i, pair := range [3][2]int{{v0, 31}, {v1, v0}, {31, v1}} {
		a.op("VEXT\t$12, V%d.B16, V%d.B16, V%d.B16", pair[0], pair[1], l.x)

		a.op("VEXT\t$8, V%d.B16, V%d.B16, V%d.B16", pair[0], pair[1], l.y)

		a.op("VUSHR\t$%d, V%d.S4, V%d.S4", shift, l.x, l.x)

		a.op("VSHL\t$%d, V%d.S4, V%d.S4", 32-shift, l.y, l.y)

		a.op("VORR\tV%d.B16, V%d.B16, V%d.B16", l.x, w[1+i], w[1+i])

		a.op("VORR\tV%d.B16, V%d.B16, V%d.B16", l.y, w[1+i], w[1+i])
	}

	a.op("VMOV\tV28.B16, V%d.B16", l.stream.abcd)

	a.op("VMOV\tV29.B16, V%d.B16", l.stream.efgh)
}

// The new value: the state after the block, with the words beyond the value's length cleared
// through the mask in V27.
func (l *chainLane) finish(a *asm) {
	a.op("VADD\tV28.S4, V%d.S4, V%d.S4", l.stream.abcd, l.value[0])

	a.op("VADD\tV29.S4, V%d.S4, V%d.S4", l.stream.efgh, l.value[1])

	a.op("VAND\tV27.B16, V%d.B16, V%d.B16", l.value[1], l.value[1])

	a.op("ADD\t$1, %s, %s", l.step, l.step)
}

// Steps of the lanes given, as many as the counter register holds (at least one), in a loop named
// label; with two lanes their rounds interleave.
func chainSteps(a *asm, shift int, label, counter string, lanes ...*chainLane) {
	a.label(label)

	for _, l := range lanes {
		l.build(a, shift)
	}

	a.op("MOVD\t$k256<>(SB), R4")

	for g := range 16 {
		a.op("VLD1.P\t16(R4), [V30.S4]")

		for _, l := range lanes {
			l.stream.group(a, g, 30)
		}
	}

	for _, l := range lanes {
		l.finish(a)
	}

	a.op("SUBS\t$1, %s, %s", counter, counter)

	a.op("BNE\t%s", label)
}

// The value of a lane sits at byte 64 of its 128-byte record, its first step at 96, its step count
// at 100.
func chainLoad(a *asm, l *chainLane) {
	a.op("ADD\t$64, %s, R10", l.record)

	a.op("VLD1\t(R10), [V%d.S4, V%d.S4]", l.value[0], l.value[1])

	a.op("VEOR\tV%d.B16, V%d.B16, V%d.B16", l.stepVector, l.stepVector, l.stepVector)
}

func chainStore(a *asm, l *chainLane) {
	a.op("ADD\t$64, %s, R10", l.record)

	a.op("VST1\t[V%d.S4, V%d.S4], (R10)", l.value[0], l.value[1])
}

// Hash chains whose steps hash one block from the same state, as in SLH-DSA (shift 16: ADRSc puts
// the value two bytes into word 5) and LM-OTS (shift 24, three bytes in). Lanes go in pairs, which
// run their common steps with interleaved rounds; then the longer one finishes alone. The caller
// orders the lanes by step count, so that the counts in a pair are close.
func sha256ChainsArm(a *asm, shift int) {
	name := fmt.Sprintf("sha256Chains%dARM", shift)

	a.function(name, "func "+name+"(init *[8]uint32, lanes []uint32, mask *[8]uint32)", 40,
		"Runs the chains of the 32-word lane records in lanes, each from init through its steps:",
		"words 0-15 hold the block template, 16-23 the value (in and out), 24 the first step and 25",
		"the number of steps. mask clears the value words beyond its length.")

	a.op("MOVD\tinit+0(FP), R0")

	a.op("MOVD\tlanes_base+8(FP), R1")

	a.op("MOVD\tlanes_len+16(FP), R2")

	a.op("MOVD\tmask+32(FP), R3")

	a.op("LSR\t$5, R2, R2")

	a.op("VLD1\t(R0), [V28.S4, V29.S4]")

	a.op("VLD1\t(R3), [V26.S4, V27.S4]")

	a.op("VEOR\tV31.B16, V31.B16, V31.B16")

	a.label("pair")

	a.op("CMP\t$2, R2")

	a.op("BLT\tsingle")

	a.op("ADD\t$128, R1, R11")

	a.op("MOVWU\t96(R1), R5")

	a.op("MOVWU\t100(R1), R7")

	a.op("MOVWU\t96(R11), R6")

	a.op("MOVWU\t100(R11), R8")

	a.op("CMP\tR8, R7")

	a.op("CSEL\tLT, R7, R8, R9")

	a.op("SUB\tR9, R7, R7")

	a.op("SUB\tR9, R8, R8")

	chainLoad(a, &chainFirst)

	chainLoad(a, &chainSecond)

	a.op("CBZ\tR9, firstRest")

	chainSteps(a, shift, "pairStep", "R9", &chainFirst, &chainSecond)

	a.label("firstRest")

	a.op("CBZ\tR7, secondRest")

	chainSteps(a, shift, "firstStep", "R7", &chainFirst)

	a.label("secondRest")

	a.op("CBZ\tR8, pairDone")

	chainSteps(a, shift, "secondStep", "R8", &chainSecond)

	a.label("pairDone")

	chainStore(a, &chainFirst)

	chainStore(a, &chainSecond)

	a.op("ADD\t$256, R1, R1")

	a.op("SUB\t$2, R2, R2")

	a.op("B\tpair")

	a.label("single")

	a.op("CBZ\tR2, done")

	a.op("MOVWU\t96(R1), R5")

	a.op("MOVWU\t100(R1), R7")

	chainLoad(a, &chainFirst)

	a.op("CBZ\tR7, singleDone")

	chainSteps(a, shift, "singleStep", "R7", &chainFirst)

	a.label("singleDone")

	chainStore(a, &chainFirst)

	a.label("done")

	a.op("RET")
}

// SHA-512 keeps the state as the pairs ab, cd, ef and gh. SHA512H and SHA512H2 do two rounds
// on five working vectors, which take turns as ab, cd, ef, gh and a free one: the new ab replaces
// gh, the new ef lands in the free vector, and the old cd becomes free. The schedule holds sixteen
// words as pairs in V12-V19.
type sha512Working struct {
	ab, cd, ef, gh, free int
}

func (w sha512Working) next() sha512Working {
	return sha512Working{ab: w.gh, cd: w.ab, ef: w.free, gh: w.ef, free: w.cd}
}

// The rounds of one block on the state in V8-V11 with the schedule in V12-V19, the round
// constants read through R3. Pair i of the schedule holds the words of rounds 2i and 2i + 1;
// double round r uses pair r mod 8 and, before round 64, turns it into the pair of 16 rounds
// later: SHA512SU0 adds sigma0 of the next words and SHA512SU1 sigma1 of the previous pair and
// the words of seven rounds earlier, which straddle two pairs.
func sha512Block(a *asm) {
	w := sha512Working{ab: 0, cd: 1, ef: 2, gh: 3, free: 4}

	for i := range 4 {
		a.op("VMOV\tV%d.B16, V%d.B16", 8+i, i)
	}

	for r := range 40 {
		m := func(offset int) int { return 12 + (r+offset)%8 }

		a.op("VLD1.P\t16(R3), [V20.D2]")

		a.op("VADD\tV20.D2, V%d.D2, V5.D2", m(0))

		a.op("VEXT\t$8, V5.B16, V5.B16, V5.B16")

		a.op("VEXT\t$8, V%d.B16, V%d.B16, V6.B16", w.gh, w.ef)

		a.op("VEXT\t$8, V%d.B16, V%d.B16, V7.B16", w.ef, w.cd)

		a.op("VADD\tV5.D2, V%d.D2, V%d.D2", w.gh, w.gh)

		if r < 32 {
			a.op("VEXT\t$8, V%d.B16, V%d.B16, V28.B16", m(5), m(4))

			a.op("SHA512SU0\tV%d.D2, V%d.D2", m(1), m(0))
		}

		a.op("SHA512H\tV7.D2, V6, V%d", w.gh)

		if r < 32 {
			a.op("SHA512SU1\tV28.D2, V%d.D2, V%d.D2", m(7), m(0))
		}

		a.op("VADD\tV%d.D2, V%d.D2, V%d.D2", w.gh, w.cd, w.free)

		a.op("SHA512H2\tV%d.D2, V%d, V%d", w.ab, w.cd, w.gh)

		w = w.next()
	}

	for i, reg := range []int{w.ab, w.cd, w.ef, w.gh} {
		a.op("VADD\tV%d.D2, V%d.D2, V%d.D2", reg, 8+i, 8+i)
	}
}

func sha512BlocksArm(a *asm) {
	a.function("sha512BlocksARM", "func sha512BlocksARM(state *[8]uint64, p []byte)", 32,
		"Compresses every 128-byte block of p into state; len(p) is a multiple of 128.")

	a.op("MOVD\tstate+0(FP), R0")

	a.op("MOVD\tp_base+8(FP), R1")

	a.op("MOVD\tp_len+16(FP), R2")

	a.op("CBZ\tR2, done")

	a.op("VLD1\t(R0), [V8.D2, V9.D2, V10.D2, V11.D2]")

	a.label("loop")

	a.op("VLD1.P\t64(R1), [V12.B16, V13.B16, V14.B16, V15.B16]")

	a.op("VLD1.P\t64(R1), [V16.B16, V17.B16, V18.B16, V19.B16]")

	for i := 12; i < 20; i++ {
		a.op("VREV64\tV%d.B16, V%d.B16", i, i)
	}

	a.op("MOVD\t$k512<>(SB), R3")

	sha512Block(a)

	a.op("SUBS\t$128, R2, R2")

	a.op("BNE\tloop")

	a.op("VST1\t[V8.D2, V9.D2, V10.D2, V11.D2], (R0)")

	a.label("done")

	a.op("RET")
}

func sha512WordsArm(a *asm) {
	a.function("sha512WordsARM", "func sha512WordsARM(state *[8]uint64, w *[16]uint64)", 16,
		"Compresses one block, given as its sixteen big-endian words, into state.")

	a.op("MOVD\tstate+0(FP), R0")

	a.op("MOVD\tw+8(FP), R1")

	a.op("VLD1\t(R0), [V8.D2, V9.D2, V10.D2, V11.D2]")

	a.op("VLD1.P\t64(R1), [V12.D2, V13.D2, V14.D2, V15.D2]")

	a.op("VLD1\t(R1), [V16.D2, V17.D2, V18.D2, V19.D2]")

	a.op("MOVD\t$k512<>(SB), R3")

	sha512Block(a)

	a.op("VST1\t[V8.D2, V9.D2, V10.D2, V11.D2], (R0)")

	a.op("RET")
}
