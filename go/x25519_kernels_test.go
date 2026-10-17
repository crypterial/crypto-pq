package cryptopq

import (
	"encoding/hex"
	"math/rand/v2"
	"os"
	"testing"
)

// Every X25519 kernel this CPU can run, against the portable ladder and the portable comb, on
// random scalars and points, on the u values at the edges and on the points of small order. On
// amd64 both tiers run where the CPU has both, not only the one the dispatch picks.

type x25519Kernel struct {
	name string
	run  func(scalar, u []byte) [32]byte
}

type x25519BaseKernel struct {
	name string
	run  func(scalar []byte) [32]byte
}

// u = 0, 1, the two points of order 8, p - 1, p and p + 1, and the non-canonical forms of the
// last ones and of 2^255 - 1, also with bit 255 set (it is ignored).
var x25519EdgePoints = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0900000000000000000000000000000000000000000000000000000000000000",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	"4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// Scalars whose digits and bits are all extreme or all zero, before the random ones.
var x25519EdgeScalars = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"8888888888888888888888888888888888888888888888888888888888888888",
	"7777777777777777777777777777777777777777777777777777777777777777",
	"5555555555555555555555555555555555555555555555555555555555555555",
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"0800000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
}

// CRYPTO_PQ_SLOW raises the count of random cases a hundredfold.
func x25519TierCases() int {
	if os.Getenv("CRYPTO_PQ_SLOW") != "" {
		return 100000
	}

	return 1000
}

func x25519Hex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)

	if err != nil || len(b) != 32 {
		t.Fatalf("bad test value %q", s)
	}

	return b
}

func checkX25519Tiers(t *testing.T, scalar, u []byte) {
	want := x25519Generic(scalar, u)

	for _, k := range x25519Kernels() {
		if got := k.run(scalar, u); got != want {
			t.Fatalf("%s: x25519(%x, %x) = %x, want %x", k.name, scalar, u, got, want)
		}
	}

	wantBase := x25519BaseGeneric(scalar)

	for _, k := range x25519BaseKernels() {
		if got := k.run(scalar); got != wantBase {
			t.Fatalf("%s: x25519Base(%x) = %x, want %x", k.name, scalar, got, wantBase)
		}
	}
}

func TestX25519Tiers(t *testing.T) {
	for _, k := range x25519Kernels() {
		t.Log("ladder:", k.name)
	}

	for _, k := range x25519BaseKernels() {
		t.Log("fixed base:", k.name)
	}

	r := rand.New(rand.NewPCG(25519, 2))

	var scalar, u [32]byte

	for _, s := range x25519EdgeScalars {
		for _, p := range x25519EdgePoints {
			checkX25519Tiers(t, x25519Hex(t, s), x25519Hex(t, p))
		}
	}

	for i := range x25519TierCases() {
		fillBytes(r, scalar[:])

		fillBytes(r, u[:])

		if i < len(x25519EdgePoints) {
			copy(u[:], x25519Hex(t, x25519EdgePoints[i]))
		}

		checkX25519Tiers(t, scalar[:], u[:])
	}
}

// The first 32 bytes are the scalar, the next 32 the point.
func FuzzX25519Tiers(f *testing.F) {
	f.Add(make([]byte, 64))

	seed := make([]byte, 64)

	for i := range seed {
		seed[i] = 0xff
	}

	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 64 {
			return
		}

		checkX25519Tiers(t, data[:32], data[32:64])
	})
}

// Each kernel's time per scalar multiplication, so that the tiers can be compared on one CPU.
func BenchmarkX25519Tiers(b *testing.B) {
	scalar := make([]byte, 32)

	for i := range scalar {
		scalar[i] = byte(7*i + 1)
	}

	u := x25519BaseGeneric(scalar)

	ladders := append([]x25519Kernel{{"portable", x25519Generic}}, x25519Kernels()...)

	for _, k := range ladders {
		b.Run("ladder/"+k.name, func(b *testing.B) {
			for b.Loop() {
				u = k.run(scalar, u[:])
			}
		})
	}

	bases := append([]x25519BaseKernel{{"portable", x25519BaseGeneric}}, x25519BaseKernels()...)

	for _, k := range bases {
		b.Run("base/"+k.name, func(b *testing.B) {
			for b.Loop() {
				u = k.run(scalar)

				scalar[0] ^= u[0]
			}
		})
	}
}

// The kernels work on the stack: no heap per call, in any tier.
func TestX25519AllocatesNothing(t *testing.T) {
	scalar, u := make([]byte, 32), make([]byte, 32)

	scalar[0], u[0] = 1, 9

	for _, k := range x25519Kernels() {
		if n := testing.AllocsPerRun(10, func() { k.run(scalar, u) }); n != 0 {
			t.Errorf("%s ladder: %v allocations per call", k.name, n)
		}
	}

	for _, k := range x25519BaseKernels() {
		if n := testing.AllocsPerRun(10, func() { k.run(scalar) }); n != 0 {
			t.Errorf("%s fixed base: %v allocations per call", k.name, n)
		}
	}
}
