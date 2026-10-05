package main

import "fmt"

// The NTTs of ML-KEM and ML-DSA with AVX2, repeating kemNTT, kemInverseNTT, dsaNTT and
// dsaInverseNTT of the portable code step for step, so that the outputs are identical.
//
// ML-KEM keeps sixteen 16-bit coefficients per Y register. Shoup's multiplication is VPMULLW for b
// zeta, VPMULHUW for the exact quotient estimate (the high half of b shoup), VPMULLW by q and
// VPSUBW. The last three layers pair lanes inside the registers, after the shuffles of Kyber's AVX2
// implementations: 128-bit halves (VPERM2I128), quadwords (VPUNPCKLQDQ, VPUNPCKHQDQ) and
// doublewords (VMOVSLDUP, VPSRLQ, VPBLENDD); each shuffle undoes itself.

func nttAmd64(a *asm) {
	kemNTTAVX2(a)

	kemInverseNTTAVX2(a)

	dsaNTTsAmd64(a)

	zetas, _ := kemZetaTables()

	z := func(i int) uint64 { return zetas[i] }

	// Broadcast zetas and companions of the layers between registers: the forward ones for
	// layers 128 and 64 (1, 2, 3), then per block of four registers b those of layers 32 and 16
	// (4 + b, 8 + 2b, 9 + 2b); the inverse ones per block (15 - 2b, 14 - 2b, 7 - b), then those of
	// layers 64 and 128 (3, 2, zeta_1 / 128, 1 / 128).
	var broadcast []uint64

	put := func(values ...uint64) {
		for _, v := range values {
			for range 16 {
				broadcast = append(broadcast, v)
			}

			for range 16 {
				broadcast = append(broadcast, v<<16/kemQ)
			}
		}
	}

	put(z(1), z(2), z(3))

	for b := range 4 {
		put(z(4+b), z(8+2*b), z(9+2*b))
	}

	for b := range 4 {
		put(z(15-2*b), z(14-2*b), z(7-b))
	}

	put(z(3), z(2), z(1)*3303%kemQ, 3303)

	a.table("kemBroadcast", 2, broadcast)

	// Per pair of registers v, v + 1 (32 coefficients), each lane's zeta and companion for layers
	// 8, 4 and 2, forward; then 2, 4 and 8 for the inverse.
	var lanes []uint64

	spread := func(values []uint64, each int) {
		for _, table := range [][]uint64{values, kemShoupsOf(values)} {
			for _, v := range table {
				for range each {
					lanes = append(lanes, v)
				}
			}
		}
	}

	for v := 0; v < 16; v += 2 {
		spread([]uint64{z(16 + v), z(17 + v)}, 8)

		spread([]uint64{z(32 + 2*v), z(33 + 2*v), z(34 + 2*v), z(35 + 2*v)}, 4)

		var two []uint64

		for i := range 8 {
			two = append(two, z(64+4*v+i))
		}

		spread(two, 2)
	}

	for v := 0; v < 16; v += 2 {
		var two []uint64

		for i := range 8 {
			two = append(two, z(127-4*v-i))
		}

		spread(two, 2)

		spread([]uint64{z(63 - 2*v), z(62 - 2*v), z(61 - 2*v), z(60 - 2*v)}, 4)

		spread([]uint64{z(31 - v), z(30 - v)}, 8)
	}

	a.table("kemLanes", 2, lanes)

	var constants []uint64

	for _, c := range []uint64{kemQ, 2 * kemQ, 1 << 26 / kemQ} {
		for range 16 {
			constants = append(constants, c)
		}
	}

	a.table("kemAVX2Constants", 2, constants)
}

// Registers: Y0-Y3 the data, Y4-Y6 temporaries, Y7-Y10 shuffled lanes, Y11 a zeta and Y12 its
// companion, Y13 = q, Y14 = 2q and Y15 = floor(2^26 / q) in every lane.

// t = b * zeta mod q, or that plus q, into Y4, the zeta in Y11 and the companion in Y12.
func kemShoupAVX2(a *asm, b string) {
	a.op("VPMULLW\tY11, %s, Y4", b)

	a.op("VPMULHUW\tY12, %s, Y5", b)

	a.op("VPMULLW\tY13, Y5, Y5")

	a.op("VPSUBW\tY5, Y4, Y4")
}

// (a, b) = (a + t, a - t + 2q) with t = zeta b.
func kemForwardAVX2(a *asm, x, y string) {
	kemShoupAVX2(a, y)

	a.op("VPSUBW\tY4, %s, %s", x, y)

	a.op("VPADDW\tY14, %s, %s", y, y)

	a.op("VPADDW\tY4, %s, %s", x, x)
}

// (a, b) = (a + b, zeta (b - a + 2q)), with the sum reduced below 2q unless keep is set.
func kemInverseAVX2(a *asm, x, y string, keep bool) {
	a.op("VPSUBW\t%s, %s, Y6", x, y)

	a.op("VPADDW\t%s, %s, %s", y, x, x)

	if !keep {
		a.op("VPSUBW\tY14, %s, Y4", x)

		a.op("VPMINUW\tY4, %s, %s", x, x)
	}

	a.op("VPADDW\tY14, Y6, %s", y)

	kemShoupAVX2(a, y)

	a.op("VMOVDQA\tY4, %s", y)
}

func kemReduceOnceAVX2(a *asm, x string) {
	a.op("VPSUBW\tY13, %s, Y4", x)

	a.op("VPMINUW\tY4, %s, %s", x, x)
}

// x mod q for any 16-bit x, as kemReduce16.
func kemReduce16AVX2(a *asm, x string) {
	a.op("VPMULHUW\tY15, %s, Y5", x)

	a.op("VPSRLW\t$10, Y5, Y5")

	a.op("VPMULLW\tY13, Y5, Y5")

	a.op("VPSUBW\tY5, %s, %s", x, x)

	kemReduceOnceAVX2(a, x)
}

// Loads the next broadcast zeta and companion from R8.
func kemNextBroadcast(a *asm) {
	a.op("VMOVDQU\t(R8), Y11")

	a.op("VMOVDQU\t32(R8), Y12")

	a.op("ADDQ\t$64, R8")
}

// Loads the next per-lane zeta and companion from R9.
func kemNextLanes(a *asm) {
	a.op("VMOVDQU\t(R9), Y11")

	a.op("VMOVDQU\t32(R9), Y12")

	a.op("ADDQ\t$64, R9")
}

// The 128-bit halves of x and y: (x.low, y.low) and (x.high, y.high) into Y7 and Y8, or back.
func shuffle8(a *asm, x, y, low, high string) {
	a.op("VPERM2I128\t$0x20, %s, %s, %s", y, x, low)

	a.op("VPERM2I128\t$0x31, %s, %s, %s", y, x, high)
}

// Quadwords: the even ones of each 128-bit lane of x and y, interleaved, and the odd ones.
func shuffle4(a *asm, x, y, even, odd string) {
	a.op("VPUNPCKLQDQ\t%s, %s, %s", y, x, even)

	a.op("VPUNPCKHQDQ\t%s, %s, %s", y, x, odd)
}

// Doublewords: the even ones of x and y, interleaved, and the odd ones; Y4 is a temporary.
func shuffle2(a *asm, x, y, even, odd string) {
	a.op("VMOVSLDUP\t%s, Y4", y)

	a.op("VPBLENDD\t$0xaa, Y4, %s, %s", x, even)

	a.op("VPSRLQ\t$32, %s, Y4", x)

	a.op("VPBLENDD\t$0xaa, %s, Y4, %s", y, odd)
}

func kemAVX2Constants(a *asm) {
	a.op("LEAQ\tkemAVX2Constants<>(SB), AX")

	a.op("VMOVDQU\t(AX), Y13")

	a.op("VMOVDQU\t32(AX), Y14")

	a.op("VMOVDQU\t64(AX), Y15")

	a.op("LEAQ\tkemBroadcast<>(SB), R8")

	a.op("LEAQ\tkemLanes<>(SB), R9")
}

func data(i int) string {
	return fmt.Sprintf("Y%d", i)
}

func kemNTTAVX2(a *asm) {
	a.function("kemNTTAVX2", "func kemNTTAVX2(f *[256]uint16)", 8,
		"The NTT of ML-KEM (FIPS 203, Algorithm 9) of canonical coefficients, left canonical.")

	a.op("MOVQ\tf+0(FP), DI")

	kemAVX2Constants(a)

	a.comment("Pass 1: layers 128 and 64 on the registers j, j + 4, j + 8 and j + 12.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("outer")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 128*i, data(i))
	}

	a.op("MOVQ\tR8, R10")

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y0", "Y2")

	kemForwardAVX2(a, "Y1", "Y3")

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y0", "Y1")

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y2", "Y3")

	a.op("MOVQ\tR10, R8")

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 128*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\touter")

	a.comment("Pass 2: layers 32 and 16 on blocks of four registers, then 8, 4 and 2 inside pairs",
		"of registers, and the final reduction.")

	a.op("ADDQ\t$%d, R8", 3*64)

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("inner")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 32*i, data(i))
	}

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y0", "Y2")

	kemForwardAVX2(a, "Y1", "Y3")

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y0", "Y1")

	kemNextBroadcast(a)

	kemForwardAVX2(a, "Y2", "Y3")

	for _, pair := range [][2]string{{"Y0", "Y1"}, {"Y2", "Y3"}} {
		shuffle8(a, pair[0], pair[1], "Y7", "Y8")

		kemNextLanes(a)

		kemForwardAVX2(a, "Y7", "Y8")

		shuffle4(a, "Y7", "Y8", "Y9", "Y10")

		kemNextLanes(a)

		kemForwardAVX2(a, "Y9", "Y10")

		shuffle2(a, "Y9", "Y10", "Y7", "Y8")

		kemNextLanes(a)

		kemForwardAVX2(a, "Y7", "Y8")

		kemReduce16AVX2(a, "Y7")

		kemReduce16AVX2(a, "Y8")

		shuffle2(a, "Y7", "Y8", "Y9", "Y10")

		shuffle4(a, "Y9", "Y10", "Y7", "Y8")

		shuffle8(a, "Y7", "Y8", pair[0], pair[1])
	}

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 32*i)
	}

	a.op("ADDQ\t$128, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tinner")

	a.op("VZEROUPPER")

	a.op("RET")
}

func kemInverseNTTAVX2(a *asm) {
	a.function("kemInverseNTTAVX2", "func kemInverseNTTAVX2(f *[256]uint16)", 8,
		"The inverse NTT of ML-KEM (FIPS 203, Algorithm 10) of canonical coefficients, left canonical.")

	a.op("MOVQ\tf+0(FP), DI")

	kemAVX2Constants(a)

	a.op("ADDQ\t$%d, R8", 15*64)

	a.op("ADDQ\t$%d, R9", 8*3*64)

	a.comment("Pass 1: layers 2, 4 and 8 inside pairs of registers, then 16 and 32 on blocks of",
		"four registers.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("inner")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 32*i, data(i))
	}

	for _, pair := range [][2]string{{"Y0", "Y1"}, {"Y2", "Y3"}} {
		shuffle8(a, pair[0], pair[1], "Y7", "Y8")

		shuffle4(a, "Y7", "Y8", "Y9", "Y10")

		shuffle2(a, "Y9", "Y10", "Y7", "Y8")

		kemNextLanes(a)

		kemInverseAVX2(a, "Y7", "Y8", true)

		shuffle2(a, "Y7", "Y8", "Y9", "Y10")

		kemNextLanes(a)

		kemInverseAVX2(a, "Y9", "Y10", false)

		shuffle4(a, "Y9", "Y10", "Y7", "Y8")

		kemNextLanes(a)

		kemInverseAVX2(a, "Y7", "Y8", false)

		shuffle8(a, "Y7", "Y8", pair[0], pair[1])
	}

	kemNextBroadcast(a)

	kemInverseAVX2(a, "Y0", "Y1", false)

	kemNextBroadcast(a)

	kemInverseAVX2(a, "Y2", "Y3", false)

	kemNextBroadcast(a)

	kemInverseAVX2(a, "Y0", "Y2", false)

	kemInverseAVX2(a, "Y1", "Y3", false)

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 32*i)
	}

	a.op("ADDQ\t$128, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tinner")

	a.comment("Pass 2: layers 64, then 128 with the factor 1/128 folded into its zetas.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("outer")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 128*i, data(i))
	}

	a.op("MOVQ\tR8, R10")

	kemNextBroadcast(a)

	kemInverseAVX2(a, "Y0", "Y1", false)

	kemNextBroadcast(a)

	kemInverseAVX2(a, "Y2", "Y3", false)

	for i := range 2 {
		x, y := data(i), data(i+2)

		a.op("VPSUBW\t%s, %s, Y6", x, y)

		a.op("VPADDW\t%s, %s, %s", y, x, x)

		a.op("VPADDW\tY14, Y6, %s", y)

		a.op("VMOVDQU\t64(R8), Y11")

		a.op("VMOVDQU\t96(R8), Y12")

		kemShoupAVX2(a, x)

		a.op("VMOVDQA\tY4, %s", x)

		kemReduceOnceAVX2(a, x)

		a.op("VMOVDQU\t(R8), Y11")

		a.op("VMOVDQU\t32(R8), Y12")

		kemShoupAVX2(a, y)

		a.op("VMOVDQA\tY4, %s", y)

		kemReduceOnceAVX2(a, y)
	}

	a.op("MOVQ\tR10, R8")

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 128*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\touter")

	a.op("VZEROUPPER")

	a.op("RET")
}

// ML-DSA keeps eight 32-bit coefficients per Y register. AVX2 has no high half of a 32-bit
// product for all lanes, so Shoup's quotient estimate takes VPMULUDQ of the even lanes and of the
// odd lanes shifted down, whose high halves VPBLENDD gathers. Registers: Y0-Y7 the data, Y8-Y10
// temporaries, Y11 a zeta, Y12 its companion, Y15 the companion's odd lanes shifted down (equal to
// Y12 for a broadcast companion), Y13 = q, Y14 = 2q in the forward transform and a layer's offset
// in the inverse.

func dsaNTTsAmd64(a *asm) {
	dsaNTTAVX2(a)

	dsaInverseNTTAVX2(a)

	zetas, _ := dsaZetaTables()

	z := func(i int) uint64 { return zetas[i] }

	reversed := func(i int) uint64 { return zetas[255-i] }

	var broadcast []uint64

	put := func(values ...uint64) {
		for _, v := range values {
			for range 8 {
				broadcast = append(broadcast, v)
			}

			for range 8 {
				broadcast = append(broadcast, v<<32/dsaQ)
			}
		}
	}

	// Forward: layers 128, 64, 32 (zetas 1-7), then per block b layers 16 and 8 (8 + b, 16 + 2b,
	// 17 + 2b). Inverse: per block b layers 8 and 16 (reversed 224 + 2b, 225 + 2b, 240 + b), then
	// layers 32 and 64 (reversed 248-253) and the last layer's zeta_1 / 256 and 1 / 256.
	put(z(1), z(2), z(3), z(4), z(5), z(6), z(7))

	for b := range 8 {
		put(z(8+b), z(16+2*b), z(17+2*b))
	}

	for b := range 8 {
		put(reversed(224+2*b), reversed(225+2*b), reversed(240+b))
	}

	put(reversed(248), reversed(249), reversed(250), reversed(251), reversed(252), reversed(253), z(1)*dsaNInv%dsaQ, dsaNInv)

	a.table("dsaBroadcast", 4, broadcast)

	var lanes []uint64

	spread := func(values []uint64, each int) {
		for _, table := range [][]uint64{values, shoupsOf(values)} {
			for _, v := range table {
				for range each {
					lanes = append(lanes, v)
				}
			}
		}
	}

	for v := 0; v < 32; v += 2 {
		spread([]uint64{z(32 + v), z(33 + v)}, 4)

		spread([]uint64{z(64 + 2*v), z(65 + 2*v), z(66 + 2*v), z(67 + 2*v)}, 2)

		var one []uint64

		for i := range 8 {
			one = append(one, z(128+4*v+i))
		}

		spread(one, 1)
	}

	for v := 0; v < 32; v += 2 {
		var one []uint64

		for i := range 8 {
			one = append(one, reversed(4*v+i))
		}

		spread(one, 1)

		spread([]uint64{reversed(128 + 2*v), reversed(129 + 2*v), reversed(130 + 2*v), reversed(131 + 2*v)}, 2)

		spread([]uint64{reversed(192 + v), reversed(193 + v)}, 4)
	}

	a.table("dsaLanes", 4, lanes)

	var constants []uint64

	for _, c := range []uint64{dsaQ, 2 * dsaQ} {
		for range 8 {
			constants = append(constants, c)
		}
	}

	for shift := range 8 {
		for range 8 {
			constants = append(constants, dsaQ<<shift)
		}
	}

	a.table("dsaAVX2Constants", 4, constants)
}

// t = b * zeta mod q, or that plus q, into Y10.
func dsaShoupAVX2(a *asm, b string) {
	a.op("VPMULUDQ\tY12, %s, Y8", b)

	a.op("VPSRLQ\t$32, %s, Y9", b)

	a.op("VPMULUDQ\tY15, Y9, Y10")

	a.op("VPSRLQ\t$32, Y8, Y8")

	a.op("VPBLENDD\t$0xaa, Y10, Y8, Y9")

	a.op("VPMULLD\tY11, %s, Y10", b)

	a.op("VPMULLD\tY13, Y9, Y9")

	a.op("VPSUBD\tY9, Y10, Y10")
}

func dsaForwardAVX2(a *asm, x, y string) {
	dsaShoupAVX2(a, y)

	a.op("VPSUBD\tY10, %s, %s", x, y)

	a.op("VPADDD\tY14, %s, %s", y, y)

	a.op("VPADDD\tY10, %s, %s", x, x)
}

// (a, b) = (a + b, zeta (b - a + offset)) with the offset in Y14; the difference waits in Y8,
// which the multiplication uses only after.
func dsaInverseAVX2(a *asm, x, y string) {
	a.op("VPSUBD\t%s, %s, Y8", x, y)

	a.op("VPADDD\t%s, %s, %s", y, x, x)

	a.op("VPADDD\tY14, Y8, %s", y)

	dsaShoupAVX2(a, y)

	a.op("VMOVDQA\tY10, %s", y)
}

func dsaReduceOnceAVX2(a *asm, x string) {
	a.op("VPSUBD\tY13, %s, Y8", x)

	a.op("VPMINUD\tY8, %s, %s", x, x)
}

// x mod q for x below 2^32 + ... as dsaReduce32: x - q (x >> 23), then once more.
func dsaReduce32AVX2(a *asm, x string) {
	a.op("VPSRLD\t$23, %s, Y8", x)

	a.op("VPMULLD\tY13, Y8, Y8")

	a.op("VPSUBD\tY8, %s, %s", x, x)

	dsaReduceOnceAVX2(a, x)
}

// The next broadcast zeta and companion from R8; the companion's odd lanes are the same.
func dsaNextBroadcast(a *asm) {
	a.op("VMOVDQU\t(R8), Y11")

	a.op("VMOVDQU\t32(R8), Y12")

	a.op("VMOVDQA\tY12, Y15")

	a.op("ADDQ\t$64, R8")
}

func dsaNextLanes(a *asm) {
	a.op("VMOVDQU\t(R9), Y11")

	a.op("VMOVDQU\t32(R9), Y12")

	a.op("VPSRLQ\t$32, Y12, Y15")

	a.op("ADDQ\t$64, R9")
}

// Y14 = 2^log q in every lane.
func dsaOffsetAVX2(a *asm, log int) {
	a.op("VMOVDQU\t%d(AX), Y14", 64+32*log)
}

// Doublewords of x and y as shuffle2, with the temporary given.
func shuffle2With(a *asm, x, y, even, odd, temporary string) {
	a.op("VMOVSLDUP\t%s, %s", y, temporary)

	a.op("VPBLENDD\t$0xaa, %s, %s, %s", temporary, x, even)

	a.op("VPSRLQ\t$32, %s, %s", x, temporary)

	a.op("VPBLENDD\t$0xaa, %s, %s, %s", y, temporary, odd)
}

func dsaAVX2Constants(a *asm) {
	a.op("LEAQ\tdsaAVX2Constants<>(SB), AX")

	a.op("VMOVDQU\t(AX), Y13")

	a.op("VMOVDQU\t32(AX), Y14")

	a.op("LEAQ\tdsaBroadcast<>(SB), R8")

	a.op("LEAQ\tdsaLanes<>(SB), R9")
}

// The forward layers 128, 64 and 32 on Y0-Y7 with the broadcast zetas at R8 (seven entries).
func dsaOuterForward(a *asm) {
	dsaNextBroadcast(a)

	for i := range 4 {
		dsaForwardAVX2(a, data(i), data(i+4))
	}

	dsaNextBroadcast(a)

	dsaForwardAVX2(a, "Y0", "Y2")

	dsaForwardAVX2(a, "Y1", "Y3")

	dsaNextBroadcast(a)

	dsaForwardAVX2(a, "Y4", "Y6")

	dsaForwardAVX2(a, "Y5", "Y7")

	for i := range 4 {
		dsaNextBroadcast(a)

		dsaForwardAVX2(a, data(2*i), data(2*i+1))
	}
}

func dsaNTTAVX2(a *asm) {
	a.function("dsaNTTAVX2", "func dsaNTTAVX2(w *[256]uint32)", 8,
		"The NTT of ML-DSA (FIPS 204, Algorithm 41) of canonical coefficients, left canonical.")

	a.op("MOVQ\tw+0(FP), DI")

	dsaAVX2Constants(a)

	a.comment("Pass 1: layers 128, 64 and 32 on the registers j, j + 4, ..., j + 28.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("outer")

	for i := range 8 {
		a.op("VMOVDQU\t%d(SI), %s", 128*i, data(i))
	}

	a.op("MOVQ\tR8, R10")

	dsaOuterForward(a)

	a.op("MOVQ\tR10, R8")

	for i := range 8 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 128*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\touter")

	a.comment("Pass 2: layers 16 and 8 on blocks of four registers, then 4, 2 and 1 inside pairs",
		"of registers, and the final reduction.")

	a.op("ADDQ\t$%d, R8", 7*64)

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$8, CX")

	a.label("inner")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 32*i, data(i))
	}

	dsaNextBroadcast(a)

	dsaForwardAVX2(a, "Y0", "Y2")

	dsaForwardAVX2(a, "Y1", "Y3")

	dsaNextBroadcast(a)

	dsaForwardAVX2(a, "Y0", "Y1")

	dsaNextBroadcast(a)

	dsaForwardAVX2(a, "Y2", "Y3")

	for _, pair := range [][2]string{{"Y0", "Y1"}, {"Y2", "Y3"}} {
		shuffle8(a, pair[0], pair[1], "Y4", "Y5")

		dsaNextLanes(a)

		dsaForwardAVX2(a, "Y4", "Y5")

		shuffle4(a, "Y4", "Y5", "Y6", "Y7")

		dsaNextLanes(a)

		dsaForwardAVX2(a, "Y6", "Y7")

		shuffle2With(a, "Y6", "Y7", "Y4", "Y5", "Y8")

		dsaNextLanes(a)

		dsaForwardAVX2(a, "Y4", "Y5")

		dsaReduce32AVX2(a, "Y4")

		dsaReduce32AVX2(a, "Y5")

		shuffle2With(a, "Y4", "Y5", "Y6", "Y7", "Y8")

		shuffle4(a, "Y6", "Y7", "Y4", "Y5")

		shuffle8(a, "Y4", "Y5", pair[0], pair[1])
	}

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 32*i)
	}

	a.op("ADDQ\t$128, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tinner")

	a.op("VZEROUPPER")

	a.op("RET")
}

func dsaInverseNTTAVX2(a *asm) {
	a.function("dsaInverseNTTAVX2", "func dsaInverseNTTAVX2(w *[256]uint32)", 8,
		"The inverse NTT of ML-DSA (FIPS 204, Algorithm 42) of canonical coefficients, left canonical.")

	a.op("MOVQ\tw+0(FP), DI")

	dsaAVX2Constants(a)

	a.op("ADDQ\t$%d, R8", (7+8*3)*64)

	a.op("ADDQ\t$%d, R9", 16*3*64)

	a.comment("Pass 1: layers 1, 2 and 4 inside pairs of registers, then 8 and 16 on blocks of",
		"four registers.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$8, CX")

	a.label("inner")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 32*i, data(i))
	}

	for _, pair := range [][2]string{{"Y0", "Y1"}, {"Y2", "Y3"}} {
		shuffle8(a, pair[0], pair[1], "Y4", "Y5")

		shuffle4(a, "Y4", "Y5", "Y6", "Y7")

		shuffle2With(a, "Y6", "Y7", "Y4", "Y5", "Y8")

		dsaOffsetAVX2(a, 0)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y4", "Y5")

		shuffle2With(a, "Y4", "Y5", "Y6", "Y7", "Y8")

		dsaOffsetAVX2(a, 1)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y6", "Y7")

		shuffle4(a, "Y6", "Y7", "Y4", "Y5")

		dsaOffsetAVX2(a, 2)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y4", "Y5")

		shuffle8(a, "Y4", "Y5", pair[0], pair[1])
	}

	dsaOffsetAVX2(a, 3)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y1")

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y2", "Y3")

	dsaOffsetAVX2(a, 4)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y2")

	dsaInverseAVX2(a, "Y1", "Y3")

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 32*i)
	}

	a.op("ADDQ\t$128, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tinner")

	a.comment("Pass 2: layers 32 and 64, then 128 with the factor 1/256 folded into its zetas, on the",
		"registers j, j + 4, ..., j + 28.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("outer")

	for i := range 8 {
		a.op("VMOVDQU\t%d(SI), %s", 128*i, data(i))
	}

	a.op("MOVQ\tR8, R10")

	dsaOffsetAVX2(a, 5)

	for i := range 4 {
		dsaNextBroadcast(a)

		dsaInverseAVX2(a, data(2*i), data(2*i+1))
	}

	dsaOffsetAVX2(a, 6)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y2")

	dsaInverseAVX2(a, "Y1", "Y3")

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y4", "Y6")

	dsaInverseAVX2(a, "Y5", "Y7")

	dsaOffsetAVX2(a, 7)

	for i := range 4 {
		x, y := data(i), data(i+4)

		a.op("VPSUBD\t%s, %s, Y15", x, y)

		a.op("VPADDD\t%s, %s, %s", y, x, x)

		a.op("VPADDD\tY14, Y15, %s", y)

		a.op("VMOVDQU\t64(R8), Y11")

		a.op("VMOVDQU\t96(R8), Y12")

		a.op("VMOVDQA\tY12, Y15")

		dsaShoupAVX2(a, x)

		a.op("VMOVDQA\tY10, %s", x)

		dsaReduceOnceAVX2(a, x)

		a.op("VMOVDQU\t(R8), Y11")

		a.op("VMOVDQU\t32(R8), Y12")

		a.op("VMOVDQA\tY12, Y15")

		dsaShoupAVX2(a, y)

		a.op("VMOVDQA\tY10, %s", y)

		dsaReduceOnceAVX2(a, y)
	}

	a.op("MOVQ\tR10, R8")

	for i := range 8 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 128*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\touter")

	a.op("VZEROUPPER")

	a.op("RET")
}
