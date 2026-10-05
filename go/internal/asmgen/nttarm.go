package main

// The NTT and inverse NTT of ML-DSA with NEON: 256 coefficients modulo q = 8380417 as 64 vectors
// of four 32-bit lanes. They repeat the portable code's arithmetic step for step: the same zetas,
// Shoup's multiplication with its exact quotient estimate (the high half of b * shoup, from UMULL),
// the same lazy offsets and the same final reductions, so the outputs are identical.

const (
	dsaQ    = 8380417
	dsaNInv = 8347681
)

func nttArm64(a *asm) {
	zetas, shoups := dsaZetaTables()

	dsaNTTArm(a)

	dsaInverseNTTArm(a)

	a.table("dsaZetas", 4, zetas)

	a.table("dsaShoups", 4, shoups)

	var reversedZetas, reversedShoups []uint64

	for i := range 256 {
		reversedZetas = append(reversedZetas, zetas[255-i])

		reversedShoups = append(reversedShoups, shoups[255-i])
	}

	a.table("dsaZetasReversed", 4, reversedZetas)

	a.table("dsaShoupsReversed", 4, reversedShoups)

	// The zetas of the forward pass 1 (indices 1-7), and of pass 2 for block b: 8 + b, 16 + 2b, 17
	// + 2b and 32 + 4b to 35 + 4b; each list padded to eight, with its Shoup companions after it.
	var forward []uint64

	pick := func(indices ...int) {
		for _, table := range [][]uint64{zetas, shoups} {
			for i := range 8 {
				value := uint64(0)

				if i < len(indices) {
					value = table[indices[i]]
				}

				forward = append(forward, value)
			}
		}
	}

	pick(1, 2, 3, 4, 5, 6, 7)

	for b := range 8 {
		pick(8+b, 16+2*b, 17+2*b, 32+4*b, 33+4*b, 34+4*b, 35+4*b)
	}

	a.table("dsaForwardZetas", 4, forward)

	// The inverse's layers 4, 8 and 16 of block b use the reversed zetas 192 + 4b to 195 + 4b, 224 +
	// 2b, 225 + 2b and 240 + b; its pass 2 the reversed 248-253, then zeta_1 / 256 and 1 / 256.
	var inverse []uint64

	pickReversed := func(values ...uint64) {
		for _, table := range [][]uint64{values, shoupsOf(values)} {
			for i := range 8 {
				value := uint64(0)

				if i < len(table) {
					value = table[i]
				}

				inverse = append(inverse, value)
			}
		}
	}

	for b := range 8 {
		pickReversed(reversedZetas[192+4*b], reversedZetas[193+4*b], reversedZetas[194+4*b], reversedZetas[195+4*b], reversedZetas[224+2*b], reversedZetas[225+2*b], reversedZetas[240+b])
	}

	lastZeta := zetas[1] * dsaNInv % dsaQ

	pickReversed(reversedZetas[248], reversedZetas[249], reversedZetas[250], reversedZetas[251], reversedZetas[252], reversedZetas[253], lastZeta, dsaNInv)

	a.table("dsaInverseZetas", 4, inverse)

	var constants []uint64

	for _, c := range []uint64{dsaQ, 2 * dsaQ} {
		constants = append(constants, c, c, c, c)
	}

	for shift := range 8 {
		c := uint64(dsaQ) << shift

		constants = append(constants, c, c, c, c)
	}

	a.table("dsaConstants", 4, constants)
}

func bitReverse8(i int) int {
	r := 0

	for range 8 {
		r = r<<1 | i&1

		i >>= 1
	}

	return r
}

// zeta_i = 1753^BitRev8(i) mod q and its Shoup companion floor(zeta_i 2^32 / q), as in mldsa.go.
func dsaZetaTables() (zetas, shoups []uint64) {
	for i := range 256 {
		z := uint64(1)

		for range bitReverse8(i) {
			z = z * 1753 % dsaQ
		}

		zetas = append(zetas, z)
	}

	return zetas, shoupsOf(zetas)
}

func shoupsOf(values []uint64) []uint64 {
	var out []uint64

	for _, v := range values {
		out = append(out, v<<32/dsaQ)
	}

	return out
}

// Registers: V0-V7 the data, V8-V10 temporaries, V11-V14 zetas and companions for by-element use,
// V16 = q in every lane, V17 = 2q, V18-V21 transposition temporaries, V22-V29 the zetas of the
// intra-vector layers, V30 a layer's offset.
const (
	nttQ, nttTwoQ, nttOffset = 16, 17, 30
)

// t = b * zeta mod q, or that plus q, into V8 (Shoup's multiplication): b * zeta minus q times
// the high half of b * shoup; z and s are the zeta and companion, as elements or, with vector
// set, as the four lanes of whole registers.
func shoupMul(a *asm, b int, z, s element, vector bool) {
	if vector {
		a.mulVector32(8, b, z.reg)

		a.umullVector32(9, b, s.reg, false)

		a.umullVector32(10, b, s.reg, true)
	} else {
		a.mulElement32(8, b, z)

		a.umullElement32(9, b, s, false)

		a.umullElement32(10, b, s, true)
	}

	a.op("VUZP2\tV10.S4, V9.S4, V9.S4")

	a.mlsElement32(8, 9, element{nttQ, 0})
}

// The forward butterfly: (a, b) = (a + t, a - t + 2q) with t = zeta b.
func forwardButterfly(a *asm, x, y int, z, s element, vector bool) {
	shoupMul(a, y, z, s, vector)

	a.op("VSUB\tV8.S4, V%d.S4, V%d.S4", x, y)

	a.op("VADD\tV%d.S4, V%d.S4, V%d.S4", nttTwoQ, y, y)

	a.op("VADD\tV8.S4, V%d.S4, V%d.S4", x, x)
}

// The inverse butterfly with offset Lq in V30: (a, b) = (a + b, zeta (b - a + Lq)).
func inverseButterfly(a *asm, x, y int, z, s element, vector bool) {
	a.op("VSUB\tV%d.S4, V%d.S4, V8.S4", x, y)

	a.op("VADD\tV%d.S4, V%d.S4, V%d.S4", y, x, x)

	a.op("VADD\tV%d.S4, V8.S4, V%d.S4", nttOffset, y)

	shoupMul(a, y, z, s, vector)

	a.op("VMOV\tV8.B16, V%d.B16", y)
}

// x mod q for x < 2q: x - q when that does not wrap, the smaller of the two as unsigned values.
func reduceOnce(a *asm, x int) {
	a.op("VSUB\tV%d.S4, V%d.S4, V8.S4", nttQ, x)

	a.op("VUMIN\tV8.S4, V%d.S4, V%d.S4", x, x)
}

// Transposes the 4x4 lanes of V0-V3 (or V4-V7 from first = 4) in place, through V18-V21.
func transpose4x4(a *asm, first int) {
	r := func(i int) int { return first + i }

	a.op("VTRN1\tV%d.S4, V%d.S4, V18.S4", r(1), r(0))

	a.op("VTRN2\tV%d.S4, V%d.S4, V19.S4", r(1), r(0))

	a.op("VTRN1\tV%d.S4, V%d.S4, V20.S4", r(3), r(2))

	a.op("VTRN2\tV%d.S4, V%d.S4, V21.S4", r(3), r(2))

	a.op("VTRN1\tV20.D2, V18.D2, V%d.D2", r(0))

	a.op("VTRN2\tV20.D2, V18.D2, V%d.D2", r(2))

	a.op("VTRN1\tV21.D2, V19.D2, V%d.D2", r(1))

	a.op("VTRN2\tV21.D2, V19.D2, V%d.D2", r(3))
}

func loadConstants(a *asm) {
	a.op("MOVD\t$dsaConstants<>(SB), R4")

	a.op("VLD1\t(R4), [V%d.S4, V%d.S4]", nttQ, nttTwoQ)
}

// Loads eight words at the pointer register into two registers, the zetas, and the next eight
// into two more, their companions.
func loadZetas(a *asm, pointer string, zetas, shoups int) {
	a.op("VLD1.P\t32(%s), [V%d.S4, V%d.S4]", pointer, zetas, zetas+1)

	a.op("VLD1.P\t32(%s), [V%d.S4, V%d.S4]", pointer, shoups, shoups+1)
}

// The element i of a list of eight loaded into two registers from reg.
func listElement(reg, i int) element {
	return element{reg + i/4, i % 4}
}

// The three butterfly layers on V0-V7 whose zetas are the eight-element list at V11-V14: one
// zeta for the pairs at distance four, two for distance two, four for distance one, in the
// forward order, or the reverse for the inverse.
func threeLayers(a *asm, inverse bool, offsets [3]int) {
	z := func(i int) element { return listElement(11, i) }

	s := func(i int) element { return listElement(13, i) }

	far := func(index int) {
		for i := range 4 {
			butterfly(a, inverse, i, i+4, z(index), s(index))
		}
	}

	middle := func(index int) {
		for _, pair := range [][3]int{{0, 2, 0}, {1, 3, 0}, {4, 6, 1}, {5, 7, 1}} {
			butterfly(a, inverse, pair[0], pair[1], z(index+pair[2]), s(index+pair[2]))
		}
	}

	near := func(index int) {
		for i := range 4 {
			butterfly(a, inverse, 2*i, 2*i+1, z(index+i), s(index+i))
		}
	}

	if !inverse {
		far(0)

		middle(1)

		near(3)

		return
	}

	setOffset(a, offsets[0])

	near(0)

	setOffset(a, offsets[1])

	middle(4)

	setOffset(a, offsets[2])

	far(6)
}

func butterfly(a *asm, inverse bool, x, y int, z, s element) {
	if inverse {
		inverseButterfly(a, x, y, z, s, false)
	} else {
		forwardButterfly(a, x, y, z, s, false)
	}
}

// V30 = 2^log q in every lane, from the table of offsets after q and 2q.
func setOffset(a *asm, log int) {
	a.op("MOVD\t$dsaConstants<>+%d(SB), R4", 32+16*log)

	a.op("VLD1\t(R4), [V%d.S4]", nttOffset)
}

// Loads the eight vectors j, j + 8, ..., j + 56 at R2, or stores them.
func strided(a *asm, store bool) {
	if store {
		for i := 7; i >= 0; i-- {
			a.op("VST1\t[V%d.S4], (R2)", i)

			if i > 0 {
				a.op("SUB\t$128, R2, R2")
			}
		}

		return
	}

	for i := range 8 {
		a.op("VLD1\t(R2), [V%d.S4]", i)

		if i < 7 {
			a.op("ADD\t$128, R2, R2")
		}
	}
}

// The zetas of the two layers inside the vectors of a transposed group of four: the four for
// the pairs of lanes two apart from the pointers in R5 (zetas) and R6 (companions) into V22 and
// V23; the eight for adjacent lanes from R8 and R9, split into the even ones (V24, V26) and the
// odd ones (V25, V27).
func groupZetas(a *asm) {
	a.op("VLD1.P\t16(R5), [V22.S4]")

	a.op("VLD1.P\t16(R6), [V23.S4]")

	a.op("VLD1.P\t32(R8), [V28.S4, V29.S4]")

	a.op("VUZP1\tV29.S4, V28.S4, V24.S4")

	a.op("VUZP2\tV29.S4, V28.S4, V25.S4")

	a.op("VLD1.P\t32(R9), [V28.S4, V29.S4]")

	a.op("VUZP1\tV29.S4, V28.S4, V26.S4")

	a.op("VUZP2\tV29.S4, V28.S4, V27.S4")
}

// Lanes of the transposed group: in register first + l is lane l of the group's four vectors.
func dsaNTTArm(a *asm) {
	a.function("dsaNTTARM", "func dsaNTTARM(w *[256]uint32)", 8,
		"The NTT of ML-DSA (FIPS 204, Algorithm 41) of canonical coefficients, left canonical.")

	a.op("MOVD\tw+0(FP), R0")

	loadConstants(a)

	a.comment("Pass 1: layers 128, 64 and 32 on the vectors j, j + 8, ..., j + 56.")

	a.op("MOVD\t$dsaForwardZetas<>(SB), R1")

	loadZetas(a, "R1", 11, 13)

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$8, R3")

	a.label("outer")

	strided(a, false)

	threeLayers(a, false, [3]int{})

	strided(a, true)

	a.op("ADD\t$16, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\touter")

	a.comment("Pass 2: layers 16, 8 and 4 on blocks of eight vectors, then 2 and 1 inside the",
		"vectors, transposed four at a time, the final reduction below q, and back.")

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$dsaZetas<>+256(SB), R5")

	a.op("MOVD\t$dsaShoups<>+256(SB), R6")

	a.op("MOVD\t$dsaZetas<>+512(SB), R8")

	a.op("MOVD\t$dsaShoups<>+512(SB), R9")

	a.op("MOVD\t$8, R3")

	a.label("inner")

	a.op("ADD\t$64, R2, R7")

	a.op("VLD1\t(R2), [V0.S4, V1.S4, V2.S4, V3.S4]")

	a.op("VLD1\t(R7), [V4.S4, V5.S4, V6.S4, V7.S4]")

	loadZetas(a, "R1", 11, 13)

	threeLayers(a, false, [3]int{})

	for _, first := range []int{0, 4} {
		transpose4x4(a, first)

		groupZetas(a)

		forwardButterfly(a, first, first+2, element{22, 0}, element{23, 0}, true)

		forwardButterfly(a, first+1, first+3, element{22, 0}, element{23, 0}, true)

		forwardButterfly(a, first, first+1, element{24, 0}, element{26, 0}, true)

		forwardButterfly(a, first+2, first+3, element{25, 0}, element{27, 0}, true)

		for i := range 4 {
			a.op("VUSHR\t$23, V%d.S4, V9.S4", first+i)

			a.mlsElement32(first+i, 9, element{nttQ, 0})

			reduceOnce(a, first+i)
		}

		transpose4x4(a, first)
	}

	a.op("VST1\t[V0.S4, V1.S4, V2.S4, V3.S4], (R2)")

	a.op("VST1\t[V4.S4, V5.S4, V6.S4, V7.S4], (R7)")

	a.op("ADD\t$128, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\tinner")

	a.op("RET")
}

// The inverse runs the forward's passes backwards: layers 1 and 2 inside the transposed vectors
// and 4, 8 and 16 on blocks of eight, then 32, 64 and 128 on the strided vectors, where the last
// layer also multiplies by 1/256 and reduces below q.
func dsaInverseNTTArm(a *asm) {
	a.function("dsaInverseNTTARM", "func dsaInverseNTTARM(w *[256]uint32)", 8,
		"The inverse NTT of ML-DSA (FIPS 204, Algorithm 42) of canonical coefficients, left canonical.")

	a.op("MOVD\tw+0(FP), R0")

	loadConstants(a)

	a.op("MOVD\t$dsaInverseZetas<>(SB), R1")

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$dsaZetasReversed<>+512(SB), R5")

	a.op("MOVD\t$dsaShoupsReversed<>+512(SB), R6")

	a.op("MOVD\t$dsaZetasReversed<>(SB), R8")

	a.op("MOVD\t$dsaShoupsReversed<>(SB), R9")

	a.op("MOVD\t$8, R3")

	a.label("inner")

	a.op("ADD\t$64, R2, R7")

	a.op("VLD1\t(R2), [V0.S4, V1.S4, V2.S4, V3.S4]")

	a.op("VLD1\t(R7), [V4.S4, V5.S4, V6.S4, V7.S4]")

	for _, first := range []int{0, 4} {
		transpose4x4(a, first)

		groupZetas(a)

		setOffset(a, 0)

		inverseButterfly(a, first, first+1, element{24, 0}, element{26, 0}, true)

		inverseButterfly(a, first+2, first+3, element{25, 0}, element{27, 0}, true)

		setOffset(a, 1)

		inverseButterfly(a, first, first+2, element{22, 0}, element{23, 0}, true)

		inverseButterfly(a, first+1, first+3, element{22, 0}, element{23, 0}, true)

		transpose4x4(a, first)
	}

	loadZetas(a, "R1", 11, 13)

	threeLayers(a, true, [3]int{2, 3, 4})

	a.op("VST1\t[V0.S4, V1.S4, V2.S4, V3.S4], (R2)")

	a.op("VST1\t[V4.S4, V5.S4, V6.S4, V7.S4], (R7)")

	a.op("ADD\t$128, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\tinner")

	a.comment("Pass 2: layers 32 and 64, then 128 with the factor 1/256 folded into its zetas.")

	loadZetas(a, "R1", 11, 13)

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$8, R3")

	a.label("outer")

	strided(a, false)

	z := func(i int) element { return listElement(11, i) }

	s := func(i int) element { return listElement(13, i) }

	setOffset(a, 5)

	for i := range 4 {
		inverseButterfly(a, 2*i, 2*i+1, z(i), s(i), false)
	}

	setOffset(a, 6)

	for _, pair := range [][3]int{{0, 2, 4}, {1, 3, 4}, {4, 6, 5}, {5, 7, 5}} {
		inverseButterfly(a, pair[0], pair[1], z(pair[2]), s(pair[2]), false)
	}

	setOffset(a, 7)

	for i := range 4 {
		x, y := i, i+4

		a.op("VSUB\tV%d.S4, V%d.S4, V31.S4", x, y)

		a.op("VADD\tV%d.S4, V%d.S4, V%d.S4", y, x, x)

		a.op("VADD\tV%d.S4, V31.S4, V%d.S4", nttOffset, y)

		shoupMul(a, x, z(7), s(7), false)

		a.op("VMOV\tV8.B16, V%d.B16", x)

		reduceOnce(a, x)

		shoupMul(a, y, z(6), s(6), false)

		a.op("VMOV\tV8.B16, V%d.B16", y)

		reduceOnce(a, y)
	}

	strided(a, true)

	a.op("ADD\t$16, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\touter")

	a.op("RET")
}

// The NTT and inverse NTT of ML-KEM with NEON: 256 coefficients modulo q = 3329 as 32 vectors of
// eight 16-bit lanes, repeating kemNTT and kemInverseNTT of mlkem.go step for step. The data sits
// in V16-V23, since by-element operands of 16-bit instructions must be in V0-V15: V0 and V1 hold
// a list of eight zetas and companions, V2 = q and floor(2^26 / q) in lanes 0 and 1, V3 = 2q and
// V4 = q in every lane. V24-V27 are temporaries, V12-V15 hold transposed lanes and V28-V31 the zetas
// of the layers inside the vectors.

const kemQ = 3329

func kemNTTArm64(a *asm) {
	zetas, _ := kemZetaTables()

	kemNTTArm(a)

	kemInverseNTTArm(a)

	var lists []uint64

	list := func(values ...uint64) {
		for _, table := range [][]uint64{values, kemShoupsOf(values)} {
			for i := range 8 {
				value := uint64(0)

				if i < len(table) {
					value = table[i]
				}

				lists = append(lists, value)
			}
		}
	}

	z := func(i int) uint64 { return zetas[i] }

	list(z(1), z(2), z(3), z(4), z(5), z(6), z(7))

	for b := range 4 {
		list(z(8+2*b), z(9+2*b), z(16+4*b), z(17+4*b), z(18+4*b), z(19+4*b))
	}

	for b := range 4 {
		list(z(31-4*b), z(30-4*b), z(29-4*b), z(28-4*b), z(15-2*b), z(14-2*b))
	}

	lastZeta := zetas[1] * 3303 % kemQ

	list(z(7), z(6), z(5), z(4), z(3), z(2), lastZeta, 3303)

	a.table("kemZetaLists", 2, lists)

	// Per pair of vectors v, v + 1: the zetas of layer 4 and of layer 2, each lane's own, with
	// their companions, forward then inverse.
	var lanes []uint64

	spread := func(values []uint64, each int) {
		for _, table := range [][]uint64{values, kemShoupsOf(values)} {
			for _, value := range table {
				for range each {
					lanes = append(lanes, value)
				}
			}
		}
	}

	for v := 0; v < 32; v += 2 {
		spread([]uint64{z(32 + v), z(33 + v)}, 4)

		spread([]uint64{z(64 + 2*v), z(65 + 2*v), z(66 + 2*v), z(67 + 2*v)}, 2)
	}

	for v := 0; v < 32; v += 2 {
		spread([]uint64{z(127 - 2*v), z(126 - 2*v), z(125 - 2*v), z(124 - 2*v)}, 2)

		spread([]uint64{z(63 - v), z(62 - v)}, 4)
	}

	a.table("kemZetaLanes", 2, lanes)

	a.table("kemConstants", 2, []uint64{kemQ, 1 << 26 / kemQ, 0, 0, 0, 0, 0, 0,
		2 * kemQ, 2 * kemQ, 2 * kemQ, 2 * kemQ, 2 * kemQ, 2 * kemQ, 2 * kemQ, 2 * kemQ,
		kemQ, kemQ, kemQ, kemQ, kemQ, kemQ, kemQ, kemQ})
}

func bitReverse7(i int) int {
	return bitReverse8(i) >> 1
}

// zeta_i = 17^BitRev7(i) mod q and its companion floor(zeta_i 2^16 / q), as in mlkem.go.
func kemZetaTables() (zetas, shoups []uint64) {
	for i := range 128 {
		z := uint64(1)

		for range bitReverse7(i) {
			z = z * 17 % kemQ
		}

		zetas = append(zetas, z)
	}

	return zetas, kemShoupsOf(zetas)
}

func kemShoupsOf(values []uint64) []uint64 {
	var out []uint64

	for _, v := range values {
		out = append(out, v<<16/kemQ)
	}

	return out
}

// t = b * zeta mod q, or that plus q, into V24, as shoupMul does with 32-bit lanes.
func kemShoupMul(a *asm, b int, z, s element, vector bool) {
	if vector {
		a.mulVector16(24, b, z.reg)

		a.umullVector16(25, b, s.reg, false)

		a.umullVector16(26, b, s.reg, true)
	} else {
		a.mulElement16(24, b, z)

		a.umullElement16(25, b, s, false)

		a.umullElement16(26, b, s, true)
	}

	a.op("VUZP2\tV26.H8, V25.H8, V25.H8")

	a.mlsElement16(24, 25, element{2, 0})
}

// (a, b) = (a + t, a - t + 2q) with t = zeta b.
func kemForwardButterfly(a *asm, x, y int, z, s element, vector bool) {
	kemShoupMul(a, y, z, s, vector)

	a.op("VSUB\tV24.H8, V%d.H8, V%d.H8", x, y)

	a.op("VADD\tV3.H8, V%d.H8, V%d.H8", y, y)

	a.op("VADD\tV24.H8, V%d.H8, V%d.H8", x, x)
}

// (a, b) = (a + b, zeta (b - a + 2q)), with the sum reduced below 2q unless keep is set.
func kemInverseButterfly(a *asm, x, y int, z, s element, vector, keep bool) {
	a.op("VSUB\tV%d.H8, V%d.H8, V27.H8", x, y)

	a.op("VADD\tV%d.H8, V%d.H8, V%d.H8", y, x, x)

	if !keep {
		a.op("VSUB\tV3.H8, V%d.H8, V24.H8", x)

		a.op("VUMIN\tV24.H8, V%d.H8, V%d.H8", x, x)
	}

	a.op("VADD\tV3.H8, V27.H8, V%d.H8", y)

	kemShoupMul(a, y, z, s, vector)

	a.op("VMOV\tV24.B16, V%d.B16", y)
}

// x mod q for x < 2q.
func kemReduceOnce(a *asm, x int) {
	a.op("VSUB\tV4.H8, V%d.H8, V24.H8", x)

	a.op("VUMIN\tV24.H8, V%d.H8, V%d.H8", x, x)
}

// x mod q for any 16-bit x (kemReduce16): x - q floor(x floor(2^26 / q) / 2^26), then once more.
func kemReduce16(a *asm, x int) {
	a.umullElement16(25, x, element{2, 1}, false)

	a.umullElement16(26, x, element{2, 1}, true)

	a.op("VUZP2\tV26.H8, V25.H8, V25.H8")

	a.op("VUSHR\t$10, V25.H8, V25.H8")

	a.mlsElement16(x, 25, element{2, 0})

	kemReduceOnce(a, x)
}

func kemLoadList(a *asm) {
	a.op("VLD1.P\t32(R1), [V0.H8, V1.H8]")
}

// The vectors j, j + 4, ..., j + 28 at R2 into V16-V23, or back.
func kemStrided(a *asm, store bool) {
	if store {
		for i := 7; i >= 0; i-- {
			a.op("VST1\t[V%d.H8], (R2)", 16+i)

			if i > 0 {
				a.op("SUB\t$64, R2, R2")
			}
		}

		return
	}

	for i := range 8 {
		a.op("VLD1\t(R2), [V%d.H8]", 16+i)

		if i < 7 {
			a.op("ADD\t$64, R2, R2")
		}
	}
}

func kemElement(i int) (element, element) {
	return element{0, i}, element{1, i}
}

func kemForward(a *asm, x, y, i int) {
	z, s := kemElement(i)

	kemForwardButterfly(a, 16+x, 16+y, z, s, false)
}

func kemInverse(a *asm, x, y, i int) {
	z, s := kemElement(i)

	kemInverseButterfly(a, 16+x, 16+y, z, s, false, false)
}

// Splits the pair V[16 + 2m], V[17 + 2m] into the halves layer 4 pairs (V12, V13), or joins them.
func kemHalves(a *asm, m int, join bool) {
	if join {
		a.op("VTRN1\tV13.D2, V12.D2, V%d.D2", 16+2*m)

		a.op("VTRN2\tV13.D2, V12.D2, V%d.D2", 17+2*m)

		return
	}

	a.op("VTRN1\tV%d.D2, V%d.D2, V12.D2", 17+2*m, 16+2*m)

	a.op("VTRN2\tV%d.D2, V%d.D2, V13.D2", 17+2*m, 16+2*m)
}

// Splits V12, V13 into the pairs of lanes layer 2 pairs (V14, V15), or joins them back.
func kemQuarters(a *asm, join bool) {
	if join {
		a.op("VTRN1\tV15.S4, V14.S4, V12.S4")

		a.op("VTRN2\tV15.S4, V14.S4, V13.S4")

		return
	}

	a.op("VTRN1\tV13.S4, V12.S4, V14.S4")

	a.op("VTRN2\tV13.S4, V12.S4, V15.S4")
}

func kemConstants(a *asm) {
	a.op("MOVD\t$kemConstants<>(SB), R4")

	a.op("VLD1\t(R4), [V2.H8, V3.H8, V4.H8]")

	a.op("MOVD\t$kemZetaLists<>(SB), R1")
}

func kemNTTArm(a *asm) {
	a.function("kemNTTARM", "func kemNTTARM(f *[256]uint16)", 8,
		"The NTT of ML-KEM (FIPS 203, Algorithm 9) of canonical coefficients, left canonical.")

	a.op("MOVD\tf+0(FP), R0")

	kemConstants(a)

	a.comment("Pass 1: layers 128, 64 and 32 on the vectors j, j + 4, ..., j + 28.")

	kemLoadList(a)

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$4, R3")

	a.label("outer")

	kemStrided(a, false)

	for i := range 4 {
		kemForward(a, i, i+4, 0)
	}

	for _, p := range [][3]int{{0, 2, 1}, {1, 3, 1}, {4, 6, 2}, {5, 7, 2}} {
		kemForward(a, p[0], p[1], p[2])
	}

	for i := range 4 {
		kemForward(a, 2*i, 2*i+1, 3+i)
	}

	kemStrided(a, true)

	a.op("ADD\t$16, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\touter")

	a.comment("Pass 2: layers 16 and 8 on blocks of eight vectors, then 4 and 2 inside pairs of",
		"vectors, rearranged by 64-bit and 32-bit transpositions, and the final reduction.")

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$kemZetaLanes<>(SB), R5")

	a.op("MOVD\t$4, R3")

	a.label("inner")

	a.op("ADD\t$64, R2, R7")

	a.op("VLD1\t(R2), [V16.H8, V17.H8, V18.H8, V19.H8]")

	a.op("VLD1\t(R7), [V20.H8, V21.H8, V22.H8, V23.H8]")

	kemLoadList(a)

	for _, p := range [][3]int{{0, 2, 0}, {1, 3, 0}, {4, 6, 1}, {5, 7, 1}} {
		kemForward(a, p[0], p[1], p[2])
	}

	for i := range 4 {
		kemForward(a, 2*i, 2*i+1, 2+i)
	}

	for m := range 4 {
		a.op("VLD1.P\t64(R5), [V28.H8, V29.H8, V30.H8, V31.H8]")

		kemHalves(a, m, false)

		kemForwardButterfly(a, 12, 13, element{28, 0}, element{29, 0}, true)

		kemQuarters(a, false)

		kemForwardButterfly(a, 14, 15, element{30, 0}, element{31, 0}, true)

		kemReduce16(a, 14)

		kemReduce16(a, 15)

		kemQuarters(a, true)

		kemHalves(a, m, true)
	}

	a.op("VST1\t[V16.H8, V17.H8, V18.H8, V19.H8], (R2)")

	a.op("VST1\t[V20.H8, V21.H8, V22.H8, V23.H8], (R7)")

	a.op("ADD\t$128, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\tinner")

	a.op("RET")
}

func kemInverseNTTArm(a *asm) {
	a.function("kemInverseNTTARM", "func kemInverseNTTARM(f *[256]uint16)", 8,
		"The inverse NTT of ML-KEM (FIPS 203, Algorithm 10) of canonical coefficients, left canonical.")

	a.op("MOVD\tf+0(FP), R0")

	kemConstants(a)

	a.op("ADD\t$%d, R1, R1", 5*32)

	a.op("MOVD\t$kemZetaLanes<>+%d(SB), R5", 16*64)

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$4, R3")

	a.label("inner")

	a.op("ADD\t$64, R2, R7")

	a.op("VLD1\t(R2), [V16.H8, V17.H8, V18.H8, V19.H8]")

	a.op("VLD1\t(R7), [V20.H8, V21.H8, V22.H8, V23.H8]")

	for m := range 4 {
		a.op("VLD1.P\t64(R5), [V28.H8, V29.H8, V30.H8, V31.H8]")

		kemHalves(a, m, false)

		kemQuarters(a, false)

		kemInverseButterfly(a, 14, 15, element{28, 0}, element{29, 0}, true, true)

		kemQuarters(a, true)

		kemInverseButterfly(a, 12, 13, element{30, 0}, element{31, 0}, true, false)

		kemHalves(a, m, true)
	}

	kemLoadList(a)

	for i := range 4 {
		kemInverse(a, 2*i, 2*i+1, i)
	}

	for _, p := range [][3]int{{0, 2, 4}, {1, 3, 4}, {4, 6, 5}, {5, 7, 5}} {
		kemInverse(a, p[0], p[1], p[2])
	}

	a.op("VST1\t[V16.H8, V17.H8, V18.H8, V19.H8], (R2)")

	a.op("VST1\t[V20.H8, V21.H8, V22.H8, V23.H8], (R7)")

	a.op("ADD\t$128, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\tinner")

	a.comment("Pass 2: layers 32 and 64, then 128 with the factor 1/128 folded into its zetas.")

	kemLoadList(a)

	a.op("MOVD\tR0, R2")

	a.op("MOVD\t$4, R3")

	a.label("outer")

	kemStrided(a, false)

	for i := range 4 {
		kemInverse(a, 2*i, 2*i+1, i)
	}

	for _, p := range [][3]int{{0, 2, 4}, {1, 3, 4}, {4, 6, 5}, {5, 7, 5}} {
		kemInverse(a, p[0], p[1], p[2])
	}

	zLast, sLast := kemElement(6)

	zInverse, sInverse := kemElement(7)

	for i := range 4 {
		x, y := 16+i, 20+i

		a.op("VSUB\tV%d.H8, V%d.H8, V27.H8", x, y)

		a.op("VADD\tV%d.H8, V%d.H8, V%d.H8", y, x, x)

		a.op("VADD\tV3.H8, V27.H8, V%d.H8", y)

		kemShoupMul(a, x, zInverse, sInverse, false)

		a.op("VMOV\tV24.B16, V%d.B16", x)

		kemReduceOnce(a, x)

		kemShoupMul(a, y, zLast, sLast, false)

		a.op("VMOV\tV24.B16, V%d.B16", y)

		kemReduceOnce(a, y)
	}

	kemStrided(a, true)

	a.op("ADD\t$16, R2, R2")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\touter")

	a.op("RET")
}
