package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// ML-DSA (FIPS 204). Coefficients stay in [0, q); products are reduced with a Barrett estimate
// from a 64x64-bit multiplication, and the functions on secret coefficients use masks instead of
// branches. Only the final accept or reject decision of the signing loop branches.

const (
	dsaQ = 8380417
	dsaD = 13
)

type mldsaParams struct {
	k, l, eta, tau, lambda, omega int
	gamma1, gamma2                uint32
}

var (
	mldsa44 = mldsaParams{k: 4, l: 4, eta: 2, tau: 39, lambda: 128, omega: 80, gamma1: 1 << 17, gamma2: (dsaQ - 1) / 88}
	mldsa65 = mldsaParams{k: 6, l: 5, eta: 4, tau: 49, lambda: 192, omega: 55, gamma1: 1 << 19, gamma2: (dsaQ - 1) / 32}
	mldsa87 = mldsaParams{k: 8, l: 7, eta: 2, tau: 60, lambda: 256, omega: 75, gamma1: 1 << 19, gamma2: (dsaQ - 1) / 32}
)

func (p *mldsaParams) beta() uint32 {
	return uint32(p.tau * p.eta)
}

func (p *mldsaParams) etaBits() int {
	return bits.Len(uint(2 * p.eta))
}

func (p *mldsaParams) gamma1Bits() int {
	return 1 + bits.Len32(p.gamma1-1)
}

func (p *mldsaParams) w1Bits() int {
	return bits.Len32((dsaQ-1)/(2*p.gamma2) - 1)
}

func (p *mldsaParams) publicKeySize() int {
	return 32 + 320*p.k
}

func (p *mldsaParams) privateKeySize() int {
	return 128 + 32*((p.k+p.l)*p.etaBits()+dsaD*p.k)
}

func (p *mldsaParams) signatureSize() int {
	return p.lambda/4 + 32*p.l*p.gamma1Bits() + p.omega + p.k
}

type dsaPoly [256]uint32

// The twiddle factors zeta = 1753^BitRev8(i) with their Shoup companions floor(zeta * 2^32 / q).
var dsaZetas, dsaShoup = func() (zetas, shoup [256]uint32) {
	for i := range zetas {
		zetas[i] = uint32(powMod(1753, uint64(bitReverse(i, 8)), dsaQ))

		shoup[i] = uint32((uint64(zetas[i]) << 32) / dsaQ)
	}

	return zetas, shoup
}()

// a < 2q: subtracts q when a >= q. A negative a - q wraps to at least 2^32 - q, setting bit 31.
func dsaReduceOnce(a uint32) uint32 {
	a -= dsaQ

	return a + dsaQ&-(a>>31)
}

// x mod q for any 64-bit x: the estimate x * floor(2^64 / q) / 2^64 is the quotient or one less.
func dsaReduce(x uint64) uint32 {
	quotient, _ := bits.Mul64(x, (1<<64)/dsaQ)

	return dsaReduceOnce(uint32(x - quotient*dsaQ))
}

// x mod q for any 32-bit x: q < 2^23, and x / 2^23 is below x / q by less than one.
func dsaReduce32(x uint32) uint32 {
	return dsaReduceOnce(x - (x>>23)*dsaQ)
}

// a * zeta mod q, or that plus q, for any 32-bit a, where shoup = floor(zeta * 2^32 / q): the
// quotient estimate a * shoup / 2^32 is exact or one too small (Shoup's modular multiplication).
func dsaMulShoup(a, zeta, shoup uint32) uint32 {
	return a*zeta - uint32((uint64(a)*uint64(shoup))>>32)*dsaQ
}

func dsaAdd(a, b uint32) uint32 {
	return dsaReduceOnce(a + b)
}

func dsaSub(a, b uint32) uint32 {
	return dsaReduceOnce(a - b + dsaQ)
}

func dsaMul(a, b uint32) uint32 {
	return dsaReduce(uint64(a) * uint64(b))
}

// v in (-q, q) as a field element.
func dsaFromSigned(v int32) uint32 {
	return uint32(v) + dsaQ&uint32(v>>31)
}

// The representative in (-(q-1)/2, (q-1)/2].
func dsaCentered(x uint32) int32 {
	return int32(x) - int32(dsaQ&-(((dsaQ-1)/2-x)>>31))
}

// 1 when the centered absolute value of x is at least bound (both below 2^31), otherwise 0.
func dsaAtLeast(x uint32, bound uint32) uint32 {
	v := dsaCentered(x)

	sign := v >> 31

	return (bound - 1 - uint32((v^sign)-sign)) >> 31
}

// NTT (FIPS 204, Algorithm 41) of canonical coefficients. A butterfly adds less than 2q to its
// outputs, so after eight layers they stay below 17q and one reduction at the end suffices. The
// layers go in pairs over groups of four coefficients held in locals, which halves the memory
// traffic; the last pair also reduces.
func dsaNTT(w *dsaPoly) {
	for length := 128; length >= 8; length /= 4 {
		half := length / 2

		for k := range 128 / length {
			block := w[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zeta, shoup := dsaZetas[128/length+k], dsaShoup[128/length+k]

			zetaLow, shoupLow := dsaZetas[256/length+2*k], dsaShoup[256/length+2*k]

			zetaHigh, shoupHigh := dsaZetas[256/length+2*k+1], dsaShoup[256/length+2*k+1]

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				t0, t1 := dsaMulShoup(a2, zeta, shoup), dsaMulShoup(a3, zeta, shoup)

				a0, a1, a2, a3 = a0+t0, a1+t1, a0-t0+2*dsaQ, a1-t1+2*dsaQ

				t0, t1 = dsaMulShoup(a1, zetaLow, shoupLow), dsaMulShoup(a3, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = a0+t0, a0-t0+2*dsaQ, a2+t1, a2-t1+2*dsaQ
			}
		}
	}

	for k := range 64 {
		f := (*[4]uint32)(w[4*k : 4*k+4])

		zeta, shoup := dsaZetas[64+k], dsaShoup[64+k]

		t0, t1 := dsaMulShoup(f[2], zeta, shoup), dsaMulShoup(f[3], zeta, shoup)

		a0, a1, a2, a3 := f[0]+t0, f[1]+t1, f[0]-t0+2*dsaQ, f[1]-t1+2*dsaQ

		t0, t1 = dsaMulShoup(a1, dsaZetas[128+2*k], dsaShoup[128+2*k]), dsaMulShoup(a3, dsaZetas[129+2*k], dsaShoup[129+2*k])

		f[0], f[1], f[2], f[3] = dsaReduce32(a0+t0), dsaReduce32(a0-t0+2*dsaQ), dsaReduce32(a2+t1), dsaReduce32(a2-t1+2*dsaQ)
	}
}

// The last layer of the inverse NTT multiplies by zeta_1 and then by 1/256; the factors are folded.
var dsaLastZeta = dsaMul(dsaZetas[1], 8347681)

// Inverse NTT (FIPS 204, Algorithm 42) of canonical coefficients, with zeta (w[j + len] - w[j]) in
// place of -zeta (w[j] - w[j + len]). The sums at most double per layer and stay below 256q < 2^32
// without reduction, while the differences, offset by a multiple of q to stay positive, are
// multiplied back below 2q. As in dsaNTT the layers go in pairs; the last pair also applies the
// factor 1/256 and reduces.
func dsaInverseNTT(w *dsaPoly) {
	for k := range 64 {
		f := (*[4]uint32)(w[4*k : 4*k+4])

		a0, a1 := f[0]+f[1], dsaMulShoup(f[1]-f[0]+dsaQ, dsaZetas[255-2*k], dsaShoup[255-2*k])

		a2, a3 := f[2]+f[3], dsaMulShoup(f[3]-f[2]+dsaQ, dsaZetas[254-2*k], dsaShoup[254-2*k])

		zeta, shoup := dsaZetas[127-k], dsaShoup[127-k]

		f[0], f[1], f[2], f[3] = a0+a2, a1+a3, dsaMulShoup(a2-a0+2*dsaQ, zeta, shoup), dsaMulShoup(a3-a1+2*dsaQ, zeta, shoup)
	}

	offset := uint32(4 * dsaQ)

	for length := 8; length <= 32; length *= 4 {
		half := length / 2

		for k := range 128 / length {
			block := w[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zetaLow, shoupLow := dsaZetas[512/length-1-2*k], dsaShoup[512/length-1-2*k]

			zetaHigh, shoupHigh := dsaZetas[512/length-2-2*k], dsaShoup[512/length-2-2*k]

			zeta, shoup := dsaZetas[256/length-1-k], dsaShoup[256/length-1-k]

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				a0, a1 = a0+a1, dsaMulShoup(a1-a0+offset, zetaLow, shoupLow)

				a2, a3 = a2+a3, dsaMulShoup(a3-a2+offset, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = a0+a2, a1+a3, dsaMulShoup(a2-a0+2*offset, zeta, shoup), dsaMulShoup(a3-a1+2*offset, zeta, shoup)
			}
		}

		offset *= 4
	}

	q0, q1, q2, q3 := w[:64], w[64:128], w[128:192], w[192:]

	zeta, shoup := dsaLastZeta, uint32((uint64(dsaLastZeta)<<32)/dsaQ)

	for j, a0 := range q0 {
		a1, a2, a3 := q1[j], q2[j], q3[j]

		a0, a1 = a0+a1, dsaMulShoup(a1-a0+64*dsaQ, dsaZetas[3], dsaShoup[3])

		a2, a3 = a2+a3, dsaMulShoup(a3-a2+64*dsaQ, dsaZetas[2], dsaShoup[2])

		q0[j], q1[j] = dsaReduceOnce(dsaMulShoup(a0+a2, 8347681, (8347681<<32)/dsaQ)), dsaReduceOnce(dsaMulShoup(a1+a3, 8347681, (8347681<<32)/dsaQ))

		q2[j], q3[j] = dsaReduceOnce(dsaMulShoup(a2-a0+128*dsaQ, zeta, shoup)), dsaReduceOnce(dsaMulShoup(a3-a1+128*dsaQ, zeta, shoup))
	}
}

// out = sum of a[j] * b[j] in the NTT domain; at most eight products stay far below 2^64.
func dsaDot(out *dsaPoly, a, b []dsaPoly) {
	for x := range out {
		var sum uint64

		for j := range a {
			sum += uint64(a[j][x]) * uint64(b[j][x])
		}

		out[x] = dsaReduce(sum)
	}
}

// acc += a * b in the NTT domain, unreduced, for a matrix row sampled one entry at a time.
func dsaMultiplyAdd(acc *[256]uint64, a, b *dsaPoly) {
	for x, c := range a {
		acc[x] += uint64(c) * uint64(b[x])
	}
}

func dsaPointwise(out, a, b *dsaPoly) {
	for x := range out {
		out[x] = dsaMul(a[x], b[x])
	}
}

// BitPack (FIPS 204, Algorithm 17): stores b - w for coefficients w in [-a, b].
func dsaPack(out []byte, w *dsaPoly, b uint32, width int) {
	var values [256]uint32

	for i, x := range w {
		values[i] = uint32(int32(b) - dsaCentered(x))
	}

	packBits(out, values[:], width)

	clear(values[:])
}

func dsaUnpack(w *dsaPoly, in []byte, b uint32, width int) {
	unpackBits(w[:], in[:32*width], width)

	for i, x := range w {
		w[i] = dsaFromSigned(int32(b) - int32(x))
	}
}

// RejNTTPoly (FIPS 204, Algorithm 30) over public data.
func dsaSampleUniform(f *dsaPoly, rho []byte, s, r byte) {
	sponge := keccak{rate: 168, suffix: 0x1f}

	sponge.update(rho)

	sponge.update([]byte{s, r})

	var block [168]byte

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for rest := block[:]; len(rest) >= 3 && count < 256; rest = rest[3:] {
			z := uint32(rest[0]) | uint32(rest[1])<<8 | uint32(rest[2]&0x7f)<<16

			if z < dsaQ {
				f[count] = z

				count++
			}
		}
	}
}

// RejBoundedPoly (FIPS 204, Algorithm 31). Each candidate is stored and then kept or overwritten by
// advancing the count or not, so that no branch depends on a secret nibble; the kept value is
// computed without division (half mod 5 by a multiply-shift). The slot after the last one absorbs a
// candidate beyond the 256th.
func dsaSampleBounded(f *dsaPoly, seed []byte, eta int) {
	sponge := keccak{rate: 136, suffix: 0x1f}

	sponge.update(seed)

	var block [136]byte

	var accepted [257]uint32

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for _, b := range block {
			if count >= 256 {
				break
			}

			low, high := uint32(b)&15, uint32(b)>>4

			if eta == 2 {
				accepted[count] = dsaFromSigned(2 - int32(low-5*((low*205)>>10)))

				count += int((low - 15) >> 31)

				accepted[count] = dsaFromSigned(2 - int32(high-5*((high*205)>>10)))

				count += int((high - 15) >> 31)
			} else {
				accepted[count] = dsaFromSigned(4 - int32(low))

				count += int((low - 9) >> 31)

				accepted[count] = dsaFromSigned(4 - int32(high))

				count += int((high - 9) >> 31)
			}
		}
	}

	copy(f[:], accepted[:256])

	clear(block[:])

	clear(accepted[:])

	clear(sponge.state[:])
}

// Entry r * l + s is A[r][s] = RejNTTPoly(rho || s || r). Only signing, which reuses the matrix
// in every attempt, stores it; elsewhere each row is folded into the result as it is sampled.
func dsaExpandA(a []dsaPoly, rho []byte, p *mldsaParams) {
	for r := range p.k {
		for s := range p.l {
			dsaSampleUniform(&a[r*p.l+s], rho, byte(s), byte(r))
		}
	}
}

func dsaExpandS(s []dsaPoly, rhoPrime []byte, p *mldsaParams) {
	var seed [66]byte

	copy(seed[:], rhoPrime)

	for r := range s {
		binary.LittleEndian.PutUint16(seed[64:], uint16(r))

		dsaSampleBounded(&s[r], seed[:], p.eta)
	}

	clear(seed[:])
}

func dsaExpandMask(y []dsaPoly, rhoPrime []byte, kappa int, p *mldsaParams) {
	width := p.gamma1Bits()

	var stream [640]byte

	var nonce [2]byte

	for r := range y {
		binary.LittleEndian.PutUint16(nonce[:], uint16(kappa+r))

		shake256Sum(stream[:32*width], rhoPrime, nonce[:])

		dsaUnpack(&y[r], stream[:], p.gamma1, width)
	}

	clear(stream[:])
}

// SampleInBall (FIPS 204, Algorithm 29) from the commitment hash, which the signature reveals.
func dsaSampleInBall(c *dsaPoly, seed []byte, tau int) {
	sponge := keccak{rate: 136, suffix: 0x1f}

	sponge.update(seed)

	var signBytes [8]byte

	sponge.read(signBytes[:])

	signs := binary.LittleEndian.Uint64(signBytes[:])

	clear(c[:])

	var j [1]byte

	for i := 256 - tau; i < 256; i++ {
		sponge.read(j[:])

		for int(j[0]) > i {
			sponge.read(j[:])
		}

		c[i] = c[j[0]]

		c[j[0]] = dsaFromSigned(1 - 2*int32(signs&1))

		signs >>= 1
	}
}

// Power2Round (FIPS 204, Algorithm 35) for r in [0, q).
func dsaPower2Round(r uint32) (r1 uint32, r0 int32) {
	low := int32(r & (1<<dsaD - 1))

	low -= (1 << dsaD) & ((1<<(dsaD-1) - low) >> 31)

	return uint32((int32(r) - low) >> dsaD), low
}

// Decompose (FIPS 204, Algorithm 36) for r in [0, q), as in the reference implementation: r1 =
// round(r / 2 gamma2) comes from a multiply-shift fitted to each gamma2, with the value
// (q - 1) / 2 gamma2 wrapped to 0, and r0 = r - 2 gamma2 r1 is then centered modulo q, which turns
// the wrapped case into the r0 - 1 the standard prescribes.
func dsaDecompose(r, gamma2 uint32) (r1, r0 int32) {
	r1 = (int32(r) + 127) >> 7

	if gamma2 == (dsaQ-1)/32 {
		r1 = (r1*1025 + 1<<21) >> 22 & 15
	} else {
		r1 = (r1*11275 + 1<<23) >> 24

		r1 ^= (43 - r1) >> 31 & r1
	}

	r0 = int32(r) - r1*2*int32(gamma2)

	r0 -= ((dsaQ-1)/2 - r0) >> 31 & dsaQ

	return r1, r0
}

// MakeHint (FIPS 204, Algorithm 39) as 1 when the high bits of r and r + z differ.
func dsaMakeHint(z, r, gamma2 uint32) uint32 {
	a, _ := dsaDecompose(r, gamma2)

	b, _ := dsaDecompose(dsaAdd(r, z), gamma2)

	difference := uint32(a ^ b)

	return (difference | -difference) >> 31
}

// UseHint (FIPS 204, Algorithm 40) with m = (q - 1) / 2 gamma2; verification works on public data
// only.
func dsaUseHint(h, r, gamma2 uint32, m int32) uint32 {
	r1, r0 := dsaDecompose(r, gamma2)

	switch {
	case h == 0:
		return uint32(r1)
	case r0 > 0 && r1 == m-1:
		return 0
	case r0 > 0:
		return uint32(r1 + 1)
	case r1 == 0:
		return uint32(m - 1)
	default:
		return uint32(r1 - 1)
	}
}

// t = NTT^-1(A * NTT(s1)) + s2, with each entry of A sampled just before its product is added.
func dsaPublicT(t []dsaPoly, rho []byte, s1Hat, s2 []dsaPoly, p *mldsaParams) {
	var a dsaPoly

	var acc [256]uint64

	for i := range t {
		clear(acc[:])

		for j := range s1Hat {
			dsaSampleUniform(&a, rho, byte(j), byte(i))

			dsaMultiplyAdd(&acc, &a, &s1Hat[j])
		}

		for x, sum := range acc {
			t[i][x] = dsaReduce(sum)
		}

		dsaInverseNTT(&t[i])

		for x := range t[i] {
			t[i][x] = dsaAdd(t[i][x], s2[i][x])
		}
	}

	clear(acc[:])
}

func dsaEncodePublicKey(rho []byte, t []dsaPoly, p *mldsaParams) []byte {
	pk := make([]byte, p.publicKeySize())

	copy(pk, rho)

	var t1 [256]uint32

	for i := range t {
		for x := range t1 {
			t1[x], _ = dsaPower2Round(t[i][x])
		}

		packBits(pk[32+320*i:], t1[:], 10)
	}

	return pk
}

// The vectors below have the largest parameter set's capacity, so that they live on the stack.
const dsaMaxK, dsaMaxL = 8, 7

func mldsaKeyGen(p *mldsaParams, xi []byte) (pk, sk []byte) {
	var expanded [128]byte

	shake256Sum(expanded[:], xi, []byte{byte(p.k), byte(p.l)})

	rho, rhoPrime, key := expanded[:32], expanded[32:96], expanded[96:]

	s := make([]dsaPoly, p.l+p.k, dsaMaxL+dsaMaxK)

	dsaExpandS(s, rhoPrime, p)

	s1Hat := make([]dsaPoly, p.l, dsaMaxL)

	copy(s1Hat, s)

	for i := range s1Hat {
		dsaNTT(&s1Hat[i])
	}

	t := make([]dsaPoly, p.k, dsaMaxK)

	dsaPublicT(t, rho, s1Hat, s[p.l:], p)

	pk = dsaEncodePublicKey(rho, t, p)

	sk = make([]byte, p.privateKeySize())

	copy(sk, rho)

	copy(sk[32:], key)

	shake256Sum(sk[64:128], pk)

	width := p.etaBits()

	offset := 128

	for i := range s {
		dsaPack(sk[offset:], &s[i], uint32(p.eta), width)

		offset += 32 * width
	}

	var t0 dsaPoly

	for i := range t {
		for x := range t0 {
			_, low := dsaPower2Round(t[i][x])

			t0[x] = dsaFromSigned(low)
		}

		dsaPack(sk[offset:], &t0, 1<<(dsaD-1), dsaD)

		offset += 32 * dsaD
	}

	clear(expanded[:])

	clear(s)

	clear(s1Hat)

	clear(t)

	clear(t0[:])

	return pk, sk
}

// s1 and s2 in one slice, then t0; out of range is 1 when an s coefficient lies outside
// [-eta, eta], which only a malformed key can contain.
func dsaDecodePrivateKey(s, t0 []dsaPoly, sk []byte, p *mldsaParams) (outOfRange uint32) {
	width := p.etaBits()

	offset := 128

	var raw [256]uint32

	for i := range s {
		unpackBits(raw[:], sk[offset:offset+32*width], width)

		for x, value := range raw {
			outOfRange |= (uint32(2*p.eta) - value) >> 31

			s[i][x] = dsaFromSigned(int32(p.eta) - int32(value))
		}

		offset += 32 * width
	}

	for i := range t0 {
		dsaUnpack(&t0[i], sk[offset:], 1<<(dsaD-1), dsaD)

		offset += 32 * dsaD
	}

	clear(raw[:])

	return outOfRange
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Returns the
// public key, or nil.
func mldsaCheckPrivateKey(p *mldsaParams, sk []byte) []byte {
	s, t0 := make([]dsaPoly, p.l+p.k, dsaMaxL+dsaMaxK), make([]dsaPoly, p.k, dsaMaxK)

	invalid := dsaDecodePrivateKey(s, t0, sk, p)

	s1Hat := make([]dsaPoly, p.l, dsaMaxL)

	copy(s1Hat, s)

	for i := range s1Hat {
		dsaNTT(&s1Hat[i])
	}

	t := make([]dsaPoly, p.k, dsaMaxK)

	dsaPublicT(t, sk[:32], s1Hat, s[p.l:], p)

	var difference uint32

	for i := range t {
		for x := range t[i] {
			_, low := dsaPower2Round(t[i][x])

			difference |= dsaFromSigned(low) ^ t0[i][x]
		}
	}

	pk := dsaEncodePublicKey(sk[:32], t, p)

	var tr [64]byte

	shake256Sum(tr[:], pk)

	invalid |= (difference | -difference) >> 31

	invalid |= uint32(1 - equalBit(tr[:], sk[64:128]))

	clear(s)

	clear(s1Hat)

	clear(t0)

	clear(t)

	if invalid != 0 {
		return nil
	}

	return pk
}

func mldsaSign(p *mldsaParams, sk, message, rnd []byte) []byte {
	k, l := p.k, p.l

	s, t0 := make([]dsaPoly, l+k, dsaMaxL+dsaMaxK), make([]dsaPoly, k, dsaMaxK)

	dsaDecodePrivateKey(s, t0, sk, p)

	for i := range s {
		dsaNTT(&s[i])
	}

	for i := range t0 {
		dsaNTT(&t0[i])
	}

	s1Hat, s2Hat := s[:l], s[l:]

	a := make([]dsaPoly, k*l, dsaMaxK*dsaMaxL)

	dsaExpandA(a, sk[:32], p)

	var mu, rhoPrime [64]byte

	shake256Sum(mu[:], sk[64:128], message)

	shake256Sum(rhoPrime[:], sk[32:64], rnd, mu[:])

	y, yHat, z := make([]dsaPoly, l, dsaMaxL), make([]dsaPoly, l, dsaMaxL), make([]dsaPoly, l, dsaMaxL)

	w, hints := make([]dsaPoly, k, dsaMaxK), make([][256]byte, k, dsaMaxK)

	w1 := make([]byte, 32*k*p.w1Bits(), 32*dsaMaxK*6)

	cTilde := make([]byte, p.lambda/4, 64)

	var high, c, product dsaPoly

	gamma1Bound, gamma2Bound := p.gamma1-p.beta(), p.gamma2-p.beta()

	for kappa := 0; ; kappa += l {
		dsaExpandMask(y, rhoPrime[:], kappa, p)

		copy(yHat, y)

		for i := range yHat {
			dsaNTT(&yHat[i])
		}

		for i := range w {
			dsaDot(&w[i], a[i*l:(i+1)*l], yHat)

			dsaInverseNTT(&w[i])

			for x := range high {
				r1, _ := dsaDecompose(w[i][x], p.gamma2)

				high[x] = uint32(r1)
			}

			packBits(w1[32*p.w1Bits()*i:], high[:], p.w1Bits())
		}

		shake256Sum(cTilde, mu[:], w1)

		dsaSampleInBall(&c, cTilde, p.tau)

		dsaNTT(&c)

		var reject uint32

		for r := range z {
			dsaPointwise(&product, &c, &s1Hat[r])

			dsaInverseNTT(&product)

			for x := range product {
				z[r][x] = dsaAdd(y[r][x], product[x])

				reject |= dsaAtLeast(z[r][x], gamma1Bound)
			}
		}

		for i := range w {
			dsaPointwise(&product, &c, &s2Hat[i])

			dsaInverseNTT(&product)

			for x := range product {
				w[i][x] = dsaSub(w[i][x], product[x])

				_, r0 := dsaDecompose(w[i][x], p.gamma2)

				reject |= dsaAtLeast(dsaFromSigned(r0), gamma2Bound)
			}
		}

		if reject != 0 {
			continue
		}

		var count uint32

		for i := range w {
			dsaPointwise(&product, &c, &t0[i])

			dsaInverseNTT(&product)

			for x := range product {
				reject |= dsaAtLeast(product[x], p.gamma2)

				hint := dsaMakeHint(dsaSub(0, product[x]), dsaAdd(w[i][x], product[x]), p.gamma2)

				hints[i][x] = byte(hint)

				count += hint
			}
		}

		// The ct0 bound and the hint count make one restart decision, as in the Rust and Zig
		// implementations, so which of the two failed stays hidden.
		if reject|((uint32(p.omega)-count)>>31) != 0 {
			continue
		}

		signature := make([]byte, p.signatureSize())

		copy(signature, cTilde)

		offset := len(cTilde)

		for r := range z {
			dsaPack(signature[offset:], &z[r], p.gamma1, p.gamma1Bits())

			offset += 32 * p.gamma1Bits()
		}

		dsaPackHints(signature[offset:], hints, p)

		clear(s)

		clear(t0)

		clear(y)

		clear(yHat)

		clear(z)

		clear(w)

		clear(rhoPrime[:])

		clear(product[:])

		return signature
	}
}

// HintBitPack (FIPS 204, Algorithm 20) of an accepted signature, whose hints are public.
func dsaPackHints(out []byte, hints [][256]byte, p *mldsaParams) {
	index := 0

	for i := range hints {
		for j, bit := range hints[i] {
			if bit != 0 {
				out[index] = byte(j)

				index++
			}
		}

		out[p.omega+i] = byte(index)
	}
}

// HintBitUnpack (FIPS 204, Algorithm 21): the encoding must be canonical, with strictly
// increasing indices and zero padding, or the signature is rejected.
func dsaUnpackHints(hints [][256]byte, data []byte, p *mldsaParams) bool {
	index := 0

	for i := range hints {
		end := int(data[p.omega+i])

		if end < index || end > p.omega {
			return false
		}

		for first := index; index < end; index++ {
			if index > first && data[index-1] >= data[index] {
				return false
			}

			hints[i][data[index]] = 1
		}
	}

	for _, b := range data[index:p.omega] {
		if b != 0 {
			return false
		}
	}

	return true
}

func mldsaVerify(p *mldsaParams, pk, message, signature []byte) bool {
	k, l := p.k, p.l

	if len(pk) != p.publicKeySize() || len(signature) != p.signatureSize() {
		return false
	}

	cTilde := signature[:p.lambda/4]

	z := make([]dsaPoly, l, dsaMaxL)

	offset := len(cTilde)

	var notBelow uint32

	for r := range z {
		dsaUnpack(&z[r], signature[offset:], p.gamma1, p.gamma1Bits())

		offset += 32 * p.gamma1Bits()

		for _, x := range z[r] {
			notBelow |= dsaAtLeast(x, p.gamma1-p.beta())
		}
	}

	hints := make([][256]byte, k, dsaMaxK)

	if !dsaUnpackHints(hints, signature[offset:], p) || notBelow != 0 {
		return false
	}

	var tr, mu [64]byte

	shake256Sum(tr[:], pk)

	shake256Sum(mu[:], tr[:], message)

	var a, c, t1, product, w dsaPoly

	dsaSampleInBall(&c, cTilde, p.tau)

	dsaNTT(&c)

	for r := range z {
		dsaNTT(&z[r])
	}

	w1 := make([]byte, 32*k*p.w1Bits(), 32*dsaMaxK*6)

	var high [256]uint32

	var acc [256]uint64

	m := int32((dsaQ - 1) / (2 * p.gamma2))

	for i := range k {
		clear(acc[:])

		for j := range z {
			dsaSampleUniform(&a, pk[:32], byte(j), byte(i))

			dsaMultiplyAdd(&acc, &a, &z[j])
		}

		unpackBits(t1[:], pk[32+320*i:32+320*(i+1)], 10)

		for x := range t1 {
			t1[x] <<= dsaD
		}

		dsaNTT(&t1)

		dsaPointwise(&product, &c, &t1)

		for x, sum := range acc {
			w[x] = dsaSub(dsaReduce(sum), product[x])
		}

		dsaInverseNTT(&w)

		for x := range w {
			high[x] = dsaUseHint(uint32(hints[i][x]), w[x], p.gamma2, m)
		}

		packBits(w1[32*p.w1Bits()*i:], high[:], p.w1Bits())
	}

	expected := make([]byte, len(cTilde), 64)

	shake256Sum(expected, mu[:], w1)

	return equal(expected, cTilde)
}
