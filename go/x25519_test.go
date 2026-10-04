package cryptopq_test

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

func x25519(scalar, u []byte) []byte {
	out := cryptopq.X25519(scalar, u)

	return out[:]
}

func x25519Base(scalar []byte) []byte {
	out := cryptopq.X25519Base(scalar)

	return out[:]
}

func TestX25519Rfc7748(t *testing.T) {
	t.Parallel()

	base := make([]byte, 32)

	base[0] = 9

	for _, r := range records(t, "rfc/x25519.txt", "output") {
		output := decode(t, r.values["output"])

		switch r.header["kind"] {
		case "multiply":
			same(t, x25519(decode(t, r.values["scalar"]), decode(t, r.values["u"])), output, "multiply")
		case "iterate":
			count := number(t, r.values["iterations"])

			if count > 1000 && os.Getenv("CRYPTO_PQ_SLOW") == "" {
				continue
			}

			k, u := base, base

			for range count {
				k, u = x25519(k, u), k
			}

			same(t, k, output, strconv.Itoa(count)+" iterations")
		case "exchange":
			alice, bob := decode(t, r.values["alicePrivate"]), decode(t, r.values["bobPrivate"])

			alicePublic, bobPublic := decode(t, r.values["alicePublic"]), decode(t, r.values["bobPublic"])

			shared := decode(t, r.values["shared"])

			same(t, x25519(alice, base), alicePublic, "alice")

			same(t, x25519(bob, base), bobPublic, "bob")

			same(t, x25519Base(alice), alicePublic, "alice, fixed base")

			same(t, x25519Base(bob), bobPublic, "bob, fixed base")

			same(t, x25519(alice, bobPublic), shared, "alice shared")

			same(t, x25519(bob, alicePublic), shared, "bob shared")
		default:
			t.Fatalf("kind %q", r.header["kind"])
		}
	}
}

// Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
func TestX25519Wycheproof(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "wycheproof/x25519.txt", "tcId") {
		got := x25519(decode(t, r.values["private"]), decode(t, r.values["public"]))

		same(t, got, decode(t, r.values["shared"]), "tcId "+r.values["tcId"])
	}
}

// The fixed-base multiplication must give the ladder's result from u = 9 for every scalar: here
// repeated bytes and single bits, which give runs of extreme and zero digits, the Wycheproof private
// keys and pseudorandom scalars.
func TestX25519Base(t *testing.T) {
	t.Parallel()

	base := make([]byte, 32)

	base[0] = 9

	var scalars [][]byte

	for _, fill := range []byte{0x00, 0xff, 0x88, 0x77, 0x80, 0x08, 0xf0, 0x0f, 0x7f, 0xf7} {
		scalars = append(scalars, bytes.Repeat([]byte{fill}, 32))
	}

	for bit := range 256 {
		scalar := make([]byte, 32)

		scalar[bit/8] = 1 << (bit % 8)

		scalars = append(scalars, scalar)
	}

	for _, r := range records(t, "wycheproof/x25519.txt", "tcId") {
		scalars = append(scalars, decode(t, r.values["private"]))
	}

	stream := cryptopq.SHAKE256.Digest([]byte("crypto-pq fixed-base X25519"), 32*2000)

	for i := 0; i < len(stream); i += 32 {
		scalars = append(scalars, stream[i:i+32])
	}

	for i, scalar := range scalars {
		same(t, x25519Base(scalar), x25519(scalar, base), "scalar "+strconv.Itoa(i))
	}
}
