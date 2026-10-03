package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// X25519 (RFC 7748) over GF(2^255 - 19) with five 51-bit limbs, a masked conditional swap and
// inversion by exponentiation: no branch or memory index depends on the scalar.

const mask51 = 1<<51 - 1

type fieldElement [5]uint64

var x25519Base = [32]byte{9}

func feLoad(b []byte) fieldElement {
	w0 := binary.LittleEndian.Uint64(b[0:])

	w1 := binary.LittleEndian.Uint64(b[8:])

	w2 := binary.LittleEndian.Uint64(b[16:])

	w3 := binary.LittleEndian.Uint64(b[24:])

	return fieldElement{
		w0 & mask51,
		(w0>>51 | w1<<13) & mask51,
		(w1>>38 | w2<<26) & mask51,
		(w2>>25 | w3<<39) & mask51,
		w3 >> 12 & mask51,
	}
}

// Limbs below 2^64 become limbs below 2^51 + 2^18.
func (v *fieldElement) carry() {
	c0, c1, c2, c3, c4 := v[0]>>51, v[1]>>51, v[2]>>51, v[3]>>51, v[4]>>51

	v[0] = v[0]&mask51 + c4*19

	v[1] = v[1]&mask51 + c0

	v[2] = v[2]&mask51 + c1

	v[3] = v[3]&mask51 + c2

	v[4] = v[4]&mask51 + c3
}

// The canonical little-endian encoding: after a carry the value is below 2p, and adding 19 shows
// whether it reaches p (the carry out of bit 255).
func (v *fieldElement) bytes() [32]byte {
	t := *v

	t.carry()

	c := (t[0] + 19) >> 51

	c = (t[1] + c) >> 51

	c = (t[2] + c) >> 51

	c = (t[3] + c) >> 51

	c = (t[4] + c) >> 51

	t[0] += 19 * c

	t[1] += t[0] >> 51

	t[0] &= mask51

	t[2] += t[1] >> 51

	t[1] &= mask51

	t[3] += t[2] >> 51

	t[2] &= mask51

	t[4] += t[3] >> 51

	t[3] &= mask51

	t[4] &= mask51

	var out [32]byte

	binary.LittleEndian.PutUint64(out[0:], t[0]|t[1]<<51)

	binary.LittleEndian.PutUint64(out[8:], t[1]>>13|t[2]<<38)

	binary.LittleEndian.PutUint64(out[16:], t[2]>>26|t[3]<<25)

	binary.LittleEndian.PutUint64(out[24:], t[3]>>39|t[4]<<12)

	return out
}

// The sum without a carry: limbs below 2^52 + 2^19, which feMul and feSquare accept.
func feAdd(a, b *fieldElement) fieldElement {
	return fieldElement{a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]}
}

// a + 2p - b for a carried b, so that no limb goes below zero, then carried.
func feSub(a, b *fieldElement) fieldElement {
	v0, v1, v2 := a[0]+0xfffffffffffda-b[0], a[1]+0xffffffffffffe-b[1], a[2]+0xffffffffffffe-b[2]

	v3, v4 := a[3]+0xffffffffffffe-b[3], a[4]+0xffffffffffffe-b[4]

	return fieldElement{v0&mask51 + (v4>>51)*19, v1&mask51 + v0>>51, v2&mask51 + v1>>51, v3&mask51 + v2>>51, v4&mask51 + v3>>51}
}

// hi:lo + a * b, for a sum below 2^128.
func mulAdd(hi, lo, a, b uint64) (uint64, uint64) {
	h, l := bits.Mul64(a, b)

	lo, c := bits.Add64(lo, l, 0)

	return hi + h + c, lo
}

// Schoolbook product with 2^255 = 19. With limbs below 2^52 + 2^19, as feAdd leaves them, every
// column stays below 2^111, so its carry fits in 64 bits even after the multiplication by 19 that
// folds the top one back; a second carry pass then gives limbs below 2^51 + 2^18.
func feMul(a, b *fieldElement) fieldElement {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]

	b0, b1, b2, b3, b4 := b[0], b[1], b[2], b[3], b[4]

	b1x19, b2x19, b3x19, b4x19 := b1*19, b2*19, b3*19, b4*19

	h0, l0 := bits.Mul64(a0, b0)

	h0, l0 = mulAdd(h0, l0, a1, b4x19)

	h0, l0 = mulAdd(h0, l0, a2, b3x19)

	h0, l0 = mulAdd(h0, l0, a3, b2x19)

	h0, l0 = mulAdd(h0, l0, a4, b1x19)

	h1, l1 := bits.Mul64(a0, b1)

	h1, l1 = mulAdd(h1, l1, a1, b0)

	h1, l1 = mulAdd(h1, l1, a2, b4x19)

	h1, l1 = mulAdd(h1, l1, a3, b3x19)

	h1, l1 = mulAdd(h1, l1, a4, b2x19)

	h2, l2 := bits.Mul64(a0, b2)

	h2, l2 = mulAdd(h2, l2, a1, b1)

	h2, l2 = mulAdd(h2, l2, a2, b0)

	h2, l2 = mulAdd(h2, l2, a3, b4x19)

	h2, l2 = mulAdd(h2, l2, a4, b3x19)

	h3, l3 := bits.Mul64(a0, b3)

	h3, l3 = mulAdd(h3, l3, a1, b2)

	h3, l3 = mulAdd(h3, l3, a2, b1)

	h3, l3 = mulAdd(h3, l3, a3, b0)

	h3, l3 = mulAdd(h3, l3, a4, b4x19)

	h4, l4 := bits.Mul64(a0, b4)

	h4, l4 = mulAdd(h4, l4, a1, b3)

	h4, l4 = mulAdd(h4, l4, a2, b2)

	h4, l4 = mulAdd(h4, l4, a3, b1)

	h4, l4 = mulAdd(h4, l4, a4, b0)

	v0, v1, v2 := l0&mask51+(h4<<13|l4>>51)*19, l1&mask51+(h0<<13|l0>>51), l2&mask51+(h1<<13|l1>>51)

	v3, v4 := l3&mask51+(h2<<13|l2>>51), l4&mask51+(h3<<13|l3>>51)

	return fieldElement{v0&mask51 + (v4>>51)*19, v1&mask51 + v0>>51, v2&mask51 + v1>>51, v3&mask51 + v2>>51, v4&mask51 + v3>>51}
}

// The square needs 15 products instead of 25: the cross terms appear twice.
func feSquare(a *fieldElement) fieldElement {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]

	a0x2, a1x2, a1x38, a2x38, a3x38, a3x19, a4x19 := 2*a0, 2*a1, 38*a1, 38*a2, 38*a3, 19*a3, 19*a4

	h0, l0 := bits.Mul64(a0, a0)

	h0, l0 = mulAdd(h0, l0, a1x38, a4)

	h0, l0 = mulAdd(h0, l0, a2x38, a3)

	h1, l1 := bits.Mul64(a0x2, a1)

	h1, l1 = mulAdd(h1, l1, a2x38, a4)

	h1, l1 = mulAdd(h1, l1, a3x19, a3)

	h2, l2 := bits.Mul64(a0x2, a2)

	h2, l2 = mulAdd(h2, l2, a1, a1)

	h2, l2 = mulAdd(h2, l2, a3x38, a4)

	h3, l3 := bits.Mul64(a0x2, a3)

	h3, l3 = mulAdd(h3, l3, a1x2, a2)

	h3, l3 = mulAdd(h3, l3, a4x19, a4)

	h4, l4 := bits.Mul64(a0x2, a4)

	h4, l4 = mulAdd(h4, l4, a1x2, a3)

	h4, l4 = mulAdd(h4, l4, a2, a2)

	v0, v1, v2 := l0&mask51+(h4<<13|l4>>51)*19, l1&mask51+(h0<<13|l0>>51), l2&mask51+(h1<<13|l1>>51)

	v3, v4 := l3&mask51+(h2<<13|l2>>51), l4&mask51+(h3<<13|l3>>51)

	return fieldElement{v0&mask51 + (v4>>51)*19, v1&mask51 + v0>>51, v2&mask51 + v1>>51, v3&mask51 + v2>>51, v4&mask51 + v3>>51}
}

// a * 121665 for a carried a; the limbs of the result stay below 2^51 + 2^24.
func feMulA24(a *fieldElement) fieldElement {
	h0, l0 := bits.Mul64(a[0], 121665)

	h1, l1 := bits.Mul64(a[1], 121665)

	h2, l2 := bits.Mul64(a[2], 121665)

	h3, l3 := bits.Mul64(a[3], 121665)

	h4, l4 := bits.Mul64(a[4], 121665)

	return fieldElement{
		l0&mask51 + (h4<<13|l4>>51)*19,
		l1&mask51 + (h0<<13 | l0>>51),
		l2&mask51 + (h1<<13 | l1>>51),
		l3&mask51 + (h2<<13 | l2>>51),
		l4&mask51 + (h3<<13 | l3>>51),
	}
}

func feSquareTimes(a *fieldElement, n int) fieldElement {
	v := feSquare(a)

	for range n - 1 {
		v = feSquare(&v)
	}

	return v
}

// z^(p - 2) = z^(2^255 - 21) through the usual chain of 254 squarings and 11 multiplications.
func feInvert(z *fieldElement) fieldElement {
	z2 := feSquare(z)

	t := feSquareTimes(&z2, 2)

	z9 := feMul(&t, z)

	z11 := feMul(&z9, &z2)

	t = feSquare(&z11)

	z2to5 := feMul(&t, &z9)

	t = feSquareTimes(&z2to5, 5)

	z2to10 := feMul(&t, &z2to5)

	t = feSquareTimes(&z2to10, 10)

	z2to20 := feMul(&t, &z2to10)

	t = feSquareTimes(&z2to20, 20)

	t = feMul(&t, &z2to20)

	t = feSquareTimes(&t, 10)

	z2to50 := feMul(&t, &z2to10)

	t = feSquareTimes(&z2to50, 50)

	z2to100 := feMul(&t, &z2to50)

	t = feSquareTimes(&z2to100, 100)

	t = feMul(&t, &z2to100)

	t = feSquareTimes(&t, 50)

	t = feMul(&t, &z2to50)

	t = feSquareTimes(&t, 5)

	return feMul(&t, &z11)
}

// Swaps a and b when swap is 1, leaves them when it is 0.
func feSwap(a, b *fieldElement, swap uint64) {
	mask := -swap

	for i := range a {
		t := mask & (a[i] ^ b[i])

		a[i] ^= t

		b[i] ^= t
	}
}

// RFC 7748, section 5: the Montgomery ladder on u-coordinates. The top bit of u is ignored and
// non-canonical values are reduced, as the RFC requires.
func x25519(scalar, u []byte) [32]byte {
	var k [32]byte

	copy(k[:], scalar)

	k[0] &= 248

	k[31] &= 127

	k[31] |= 64

	x1 := feLoad(u)

	x2, z2, x3, z3 := fieldElement{1}, fieldElement{}, x1, fieldElement{1}

	var swap uint64

	for t := 254; t >= 0; t-- {
		bit := uint64(k[t/8]>>(t%8)) & 1

		swap ^= bit

		feSwap(&x2, &x3, swap)

		feSwap(&z2, &z3, swap)

		swap = bit

		a := feAdd(&x2, &z2)

		aa := feSquare(&a)

		b := feSub(&x2, &z2)

		bb := feSquare(&b)

		e := feSub(&aa, &bb)

		c := feAdd(&x3, &z3)

		d := feSub(&x3, &z3)

		da := feMul(&d, &a)

		cb := feMul(&c, &b)

		sum := feAdd(&da, &cb)

		difference := feSub(&da, &cb)

		x3 = feSquare(&sum)

		difference = feSquare(&difference)

		z3 = feMul(&x1, &difference)

		x2 = feMul(&aa, &bb)

		scaled := feMulA24(&e)

		scaled = feAdd(&aa, &scaled)

		z2 = feMul(&e, &scaled)
	}

	feSwap(&x2, &x3, swap)

	feSwap(&z2, &z3, swap)

	inverse := feInvert(&z2)

	result := feMul(&x2, &inverse)

	clear(k[:])

	return result.bytes()
}
