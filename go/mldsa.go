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

var dsaZetas = func() (zetas [256]uint32) {
	for i := range zetas {
		zetas[i] = uint32(powMod(1753, uint64(bitReverse(i, 8)), dsaQ))
	}

	return zetas
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

func dsaNTT(w *dsaPoly) {
	m := 0

	for length := 128; length >= 1; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			m++

			zeta := dsaZetas[m]

			for j := start; j < start+length; j++ {
				t := dsaMul(zeta, w[j+length])

				w[j+length] = dsaSub(w[j], t)

				w[j] = dsaAdd(w[j], t)
			}
		}
	}
}

func dsaInverseNTT(w *dsaPoly) {
	m := 256

	for length := 1; length < 256; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			m--

			zeta := dsaQ - dsaZetas[m]

			for j := start; j < start+length; j++ {
				t := w[j]

				w[j] = dsaAdd(t, w[j+length])

				w[j+length] = dsaMul(zeta, dsaSub(t, w[j+length]))
			}
		}
	}

	for j := range w {
		w[j] = dsaMul(w[j], 8347681)
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

		for offset := 0; offset < len(block) && count < 256; offset += 3 {
			z := uint32(block[offset]) | uint32(block[offset+1])<<8 | uint32(block[offset+2]&0x7f)<<16

			if z < dsaQ {
				f[count] = z

				count++
			}
		}
	}
}

// RejBoundedPoly (FIPS 204, Algorithm 31). Whether a nibble is kept depends only on that
// nibble; the kept value is computed without division (half mod 5 by a multiply-shift).
func dsaSampleBounded(f *dsaPoly, seed []byte, eta int) {
	sponge := keccak{rate: 136, suffix: 0x1f}

	sponge.update(seed)

	var block [136]byte

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for _, b := range block {
			for _, half := range [2]uint32{uint32(b) & 15, uint32(b) >> 4} {
				if count == 256 {
					break
				}

				if eta == 2 && half < 15 {
					f[count] = dsaFromSigned(2 - int32(half-5*((half*205)>>10)))

					count++
				} else if eta == 4 && half < 9 {
					f[count] = dsaFromSigned(4 - int32(half))

					count++
				}
			}
		}
	}

	clear(block[:])

	clear(sponge.state[:])
}

// Entry r * l + s is A[r][s] = RejNTTPoly(rho || s || r).
func dsaExpandA(rho []byte, p *mldsaParams) []dsaPoly {
	a := make([]dsaPoly, p.k*p.l)

	for r := range p.k {
		for s := range p.l {
			dsaSampleUniform(&a[r*p.l+s], rho, byte(s), byte(r))
		}
	}

	return a
}

func dsaExpandS(rhoPrime []byte, p *mldsaParams) []dsaPoly {
	s := make([]dsaPoly, p.l+p.k)

	var seed [66]byte

	copy(seed[:], rhoPrime)

	for r := range s {
		binary.LittleEndian.PutUint16(seed[64:], uint16(r))

		dsaSampleBounded(&s[r], seed[:], p.eta)
	}

	clear(seed[:])

	return s
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

// The constants of Decompose for one gamma2, derived once per operation rather than per
// coefficient: alpha = 2 gamma2, m = (q - 1) / alpha and factor = floor(2^32 / alpha).
type decomposition struct {
	gamma2, alpha, m uint32
	factor           uint64
}

func (p *mldsaParams) decomposition() decomposition {
	alpha := 2 * p.gamma2

	return decomposition{gamma2: p.gamma2, alpha: alpha, m: (dsaQ - 1) / alpha, factor: (1 << 32) / uint64(alpha)}
}

// Decompose (FIPS 204, Algorithm 36) for r in [0, q). floor(r / alpha) comes from a Barrett
// estimate that is exact or one too small and is then corrected with a mask.
func dsaDecompose(r uint32, d *decomposition) (r1, r0 int32) {
	quotient := uint32((uint64(r) * d.factor) >> 32)

	remainder := r - quotient*d.alpha

	fix := (d.alpha - 1 - remainder) >> 31

	quotient += fix

	remainder -= d.alpha & -fix

	over := (int32(d.gamma2) - int32(remainder)) >> 31

	r0 = int32(remainder) - int32(d.alpha)&over

	r1 = int32(quotient) - over

	top := int32((uint64(uint32(r1)^d.m) - 1) >> 63)

	return r1 &^ -top, r0 - top
}

// MakeHint (FIPS 204, Algorithm 39) as 1 when the high bits of r and r + z differ.
func dsaMakeHint(z, r uint32, d *decomposition) uint32 {
	a, _ := dsaDecompose(r, d)

	b, _ := dsaDecompose(dsaAdd(r, z), d)

	difference := uint32(a ^ b)

	return (difference | -difference) >> 31
}

// UseHint (FIPS 204, Algorithm 40); verification works on public data only.
func dsaUseHint(h uint32, r uint32, d *decomposition) uint32 {
	m := int32(d.m)

	r1, r0 := dsaDecompose(r, d)

	if h == 0 {
		return uint32(r1)
	}

	if r0 > 0 {
		return uint32((r1 + 1) % m)
	}

	return uint32((r1 - 1 + m) % m)
}

// t = NTT^-1(A * NTT(s1)) + s2.
func dsaPublicT(a, s []dsaPoly, p *mldsaParams) []dsaPoly {
	s1Hat := make([]dsaPoly, p.l)

	copy(s1Hat, s[:p.l])

	for i := range s1Hat {
		dsaNTT(&s1Hat[i])
	}

	t := make([]dsaPoly, p.k)

	for i := range t {
		dsaDot(&t[i], a[i*p.l:(i+1)*p.l], s1Hat)

		dsaInverseNTT(&t[i])

		for x := range t[i] {
			t[i][x] = dsaAdd(t[i][x], s[p.l+i][x])
		}
	}

	clear(s1Hat)

	return t
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

func mldsaKeyGen(p *mldsaParams, xi []byte) (pk, sk []byte) {
	var expanded [128]byte

	shake256Sum(expanded[:], xi, []byte{byte(p.k), byte(p.l)})

	rho, rhoPrime, key := expanded[:32], expanded[32:96], expanded[96:]

	s := dsaExpandS(rhoPrime, p)

	t := dsaPublicT(dsaExpandA(rho, p), s, p)

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

	clear(t)

	clear(t0[:])

	return pk, sk
}

// s1 and s2 in one slice, then t0; out of range is 1 when an s coefficient lies outside
// [-eta, eta], which only a malformed key can contain.
func dsaDecodePrivateKey(sk []byte, p *mldsaParams) (s, t0 []dsaPoly, outOfRange uint32) {
	width := p.etaBits()

	s = make([]dsaPoly, p.l+p.k)

	t0 = make([]dsaPoly, p.k)

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

	return s, t0, outOfRange
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Returns the
// public key, or nil.
func mldsaCheckPrivateKey(p *mldsaParams, sk []byte) []byte {
	s, t0, invalid := dsaDecodePrivateKey(sk, p)

	t := dsaPublicT(dsaExpandA(sk[:32], p), s, p)

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

	clear(t0)

	clear(t)

	if invalid != 0 {
		return nil
	}

	return pk
}

func mldsaSign(p *mldsaParams, sk, message, rnd []byte) []byte {
	k, l := p.k, p.l

	s, t0, _ := dsaDecodePrivateKey(sk, p)

	for i := range s {
		dsaNTT(&s[i])
	}

	for i := range t0 {
		dsaNTT(&t0[i])
	}

	s1Hat, s2Hat := s[:l], s[l:]

	a := dsaExpandA(sk[:32], p)

	var mu, rhoPrime [64]byte

	shake256Sum(mu[:], sk[64:128], message)

	shake256Sum(rhoPrime[:], sk[32:64], rnd, mu[:])

	y := make([]dsaPoly, l)

	yHat := make([]dsaPoly, l)

	z := make([]dsaPoly, l)

	w := make([]dsaPoly, k)

	hints := make([]dsaPoly, k)

	w1 := make([]byte, 32*k*p.w1Bits())

	cTilde := make([]byte, p.lambda/4)

	var high, c, product dsaPoly

	d := p.decomposition()

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
				r1, _ := dsaDecompose(w[i][x], &d)

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

				_, r0 := dsaDecompose(w[i][x], &d)

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

				hints[i][x] = dsaMakeHint(dsaSub(0, product[x]), dsaAdd(w[i][x], product[x]), &d)

				count += hints[i][x]
			}
		}

		if reject != 0 || count > uint32(p.omega) {
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
func dsaPackHints(out []byte, hints []dsaPoly, p *mldsaParams) {
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
func dsaUnpackHints(data []byte, p *mldsaParams) ([]dsaPoly, bool) {
	hints := make([]dsaPoly, p.k)

	index := 0

	for i := range hints {
		end := int(data[p.omega+i])

		if end < index || end > p.omega {
			return nil, false
		}

		for first := index; index < end; index++ {
			if index > first && data[index-1] >= data[index] {
				return nil, false
			}

			hints[i][data[index]] = 1
		}
	}

	for _, b := range data[index:p.omega] {
		if b != 0 {
			return nil, false
		}
	}

	return hints, true
}

func mldsaVerify(p *mldsaParams, pk, message, signature []byte) bool {
	k, l := p.k, p.l

	if len(pk) != p.publicKeySize() || len(signature) != p.signatureSize() {
		return false
	}

	cTilde := signature[:p.lambda/4]

	z := make([]dsaPoly, l)

	offset := len(cTilde)

	var notBelow uint32

	for r := range z {
		dsaUnpack(&z[r], signature[offset:], p.gamma1, p.gamma1Bits())

		offset += 32 * p.gamma1Bits()

		for _, x := range z[r] {
			notBelow |= dsaAtLeast(x, p.gamma1-p.beta())
		}
	}

	hints, ok := dsaUnpackHints(signature[offset:], p)

	if !ok || notBelow != 0 {
		return false
	}

	a := dsaExpandA(pk[:32], p)

	var tr, mu [64]byte

	shake256Sum(tr[:], pk)

	shake256Sum(mu[:], tr[:], message)

	var c, t1, product, w dsaPoly

	dsaSampleInBall(&c, cTilde, p.tau)

	dsaNTT(&c)

	for r := range z {
		dsaNTT(&z[r])
	}

	w1 := make([]byte, 32*k*p.w1Bits())

	var high [256]uint32

	d := p.decomposition()

	for i := range k {
		unpackBits(t1[:], pk[32+320*i:32+320*(i+1)], 10)

		for x := range t1 {
			t1[x] <<= dsaD
		}

		dsaNTT(&t1)

		dsaDot(&w, a[i*l:(i+1)*l], z)

		dsaPointwise(&product, &c, &t1)

		for x := range w {
			w[x] = dsaSub(w[x], product[x])
		}

		dsaInverseNTT(&w)

		for x := range w {
			high[x] = dsaUseHint(hints[i][x], w[x], &d)
		}

		packBits(w1[32*p.w1Bits()*i:], high[:], p.w1Bits())
	}

	expected := make([]byte, len(cTilde))

	shake256Sum(expected, mu[:], w1)

	return equal(expected, cTilde)
}
