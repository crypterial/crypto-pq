package cryptopq_test

import (
	"os"
	"strconv"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

func x25519(scalar, u []byte) []byte {
	out := cryptopq.X25519(scalar, u)

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
