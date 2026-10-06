package cryptopq_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

var hashes = []struct {
	file      string
	name      string
	algorithm cryptopq.HashAlgorithm
}{
	{"SHA224", "SHA-224", cryptopq.SHA_224},
	{"SHA256", "SHA-256", cryptopq.SHA_256},
	{"SHA384", "SHA-384", cryptopq.SHA_384},
	{"SHA512", "SHA-512", cryptopq.SHA_512},
	{"SHA512_224", "SHA-512/224", cryptopq.SHA_512_224},
	{"SHA512_256", "SHA-512/256", cryptopq.SHA_512_256},
	{"SHA3_224", "SHA3-224", cryptopq.SHA3_224},
	{"SHA3_256", "SHA3-256", cryptopq.SHA3_256},
	{"SHA3_384", "SHA3-384", cryptopq.SHA3_384},
	{"SHA3_512", "SHA3-512", cryptopq.SHA3_512},
}

var xofs = []struct {
	file      string
	algorithm cryptopq.XofAlgorithm
}{
	{"SHAKE128", cryptopq.SHAKE128},
	{"SHAKE256", cryptopq.SHAKE256},
}

// HMAC.rsp labels each group by digest length in bytes; L=20 is SHA-1, which is out of scope.
var hmacs = map[string]struct {
	name      string
	algorithm cryptopq.HmacAlgorithm
}{
	"28": {"HMAC-SHA-224", cryptopq.HMAC_SHA_224},
	"32": {"HMAC-SHA-256", cryptopq.HMAC_SHA_256},
	"48": {"HMAC-SHA-384", cryptopq.HMAC_SHA_384},
	"64": {"HMAC-SHA-512", cryptopq.HMAC_SHA_512},
}

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
var sizes = []int{0, 1, 3, 64, 7, 136, 128, 168, 0, 200}

func message(t *testing.T, values fields) []byte {
	t.Helper()

	bits := number(t, values["Len"])

	if bits%8 != 0 {
		t.Fatal("bit-oriented message")
	}

	return decode(t, values["Msg"])[:bits/8]
}

func pieces(data []byte) [][]byte {
	var out [][]byte

	for offset, index := 0, 0; offset < len(data); index++ {
		end := min(offset+sizes[index%len(sizes)], len(data))

		out = append(out, data[offset:end])

		offset = end
	}

	return out
}

func TestHashVectors(t *testing.T) {
	for _, h := range hashes {
		for _, kind := range []string{"ShortMsg", "LongMsg"} {
			for _, r := range records(t, "cavp/"+h.file+kind+".rsp", "MD") {
				data := message(t, r.values)

				expected := decode(t, r.values["MD"])

				context := fmt.Sprintf("%s%s Len = %s", h.file, kind, r.values["Len"])

				if got := h.algorithm.Digest(data); !bytes.Equal(got, expected) {
					t.Fatalf("%s: got %x", context, got)
				}

				hasher := h.algorithm.Create()

				for _, piece := range pieces(data) {
					hasher.Update(piece)
				}

				if got := hasher.Digest(); !bytes.Equal(got, expected) {
					t.Fatalf("%s streamed: got %x", context, got)
				}
			}
		}
	}
}

// SHAVS 6.4 and SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
func TestHashMonteCarlo(t *testing.T) {
	for _, h := range hashes {
		found := records(t, "cavp/"+h.file+"Monte.rsp", "MD")

		seed := decode(t, found[0].values["Seed"])

		for _, r := range found[1:] {
			if strings.HasPrefix(h.file, "SHA3_") {
				for range 1000 {
					seed = h.algorithm.Digest(seed)
				}
			} else {
				md := [3][]byte{seed, seed, seed}

				for range 1000 {
					md = [3][]byte{md[1], md[2], h.algorithm.Digest(slices.Concat(md[0], md[1], md[2]))}
				}

				seed = md[2]
			}

			if !bytes.Equal(seed, decode(t, r.values["MD"])) {
				t.Fatalf("%sMonte COUNT = %s: got %x", h.file, r.values["COUNT"], seed)
			}
		}
	}
}

func TestHashDigestIsRepeatable(t *testing.T) {
	for _, h := range hashes {
		hasher := h.algorithm.Create()

		hasher.Update([]byte("abc"))

		first := hasher.Digest()

		if !bytes.Equal(hasher.Digest(), first) || !bytes.Equal(first, h.algorithm.Digest([]byte("abc"))) {
			t.Fatalf("%s: digest changed the state", h.name)
		}

		hasher.Update([]byte("def"))

		if !bytes.Equal(hasher.Digest(), h.algorithm.Digest([]byte("abcdef"))) {
			t.Fatalf("%s: update after digest", h.name)
		}
	}
}

func TestHashProperties(t *testing.T) {
	for _, h := range hashes {
		if h.algorithm.Name() != h.name || h.algorithm.String() != h.name {
			t.Fatalf("name %q, want %q", h.algorithm.Name(), h.name)
		}

		if len(h.algorithm.Digest(nil)) != h.algorithm.DigestSize() {
			t.Fatalf("%s: digest size", h.name)
		}
	}
}

func TestXofVectors(t *testing.T) {
	for _, x := range xofs {
		for _, kind := range []string{"ShortMsg", "LongMsg"} {
			for _, r := range records(t, "cavp/"+x.file+kind+".rsp", "Output") {
				data := message(t, r.values)

				expected := decode(t, r.values["Output"])

				context := fmt.Sprintf("%s%s Len = %s", x.file, kind, r.values["Len"])

				if number(t, r.header["Outputlen"]) != 8*len(expected) {
					t.Fatalf("%s: output length", context)
				}

				if got := x.algorithm.Digest(data, len(expected)); !bytes.Equal(got, expected) {
					t.Fatalf("%s: got %x", context, got)
				}

				xof := x.algorithm.Create()

				for _, piece := range pieces(data) {
					xof.Update(piece)
				}

				got := append(xof.Read(1), xof.Read(len(expected)-1)...)

				if !bytes.Equal(got, expected) {
					t.Fatalf("%s streamed: got %x", context, got)
				}
			}
		}

		for _, r := range records(t, "cavp/"+x.file+"VariableOut.rsp", "Output") {
			expected := decode(t, r.values["Output"])

			if number(t, r.values["Outputlen"]) != 8*len(expected) {
				t.Fatalf("%s VariableOut COUNT = %s: output length", x.file, r.values["COUNT"])
			}

			if got := x.algorithm.Digest(decode(t, r.values["Msg"]), len(expected)); !bytes.Equal(got, expected) {
				t.Fatalf("%s VariableOut COUNT = %s: got %x", x.file, r.values["COUNT"], got)
			}
		}
	}
}

// SHA3VS 6.3.3: the next input is the first 16 output bytes, zero-padded, and the last two
// output bytes pick the next output length.
func TestXofMonteCarlo(t *testing.T) {
	for _, x := range xofs {
		found := records(t, "cavp/"+x.file+"Monte.rsp", "Output")

		minimum := number(t, found[0].header["Minimum Output Length (bits)"]) / 8

		maximum := number(t, found[0].header["Maximum Output Length (bits)"]) / 8

		output := decode(t, found[0].values["Msg"])

		length := maximum

		for _, r := range found[1:] {
			for range 1000 {
				var message [16]byte

				copy(message[:], output)

				output = x.algorithm.Digest(message[:], length)

				length = minimum + int(binary.BigEndian.Uint16(output[len(output)-2:]))%(maximum-minimum+1)
			}

			if !bytes.Equal(output, decode(t, r.values["Output"])) || 8*len(output) != number(t, r.values["Outputlen"]) {
				t.Fatalf("%sMonte COUNT = %s: got %x", x.file, r.values["COUNT"], output)
			}
		}
	}
}

func TestXofStreamingRead(t *testing.T) {
	for _, x := range xofs {
		xof := x.algorithm.Create()

		xof.Update([]byte("abc"))

		var got []byte

		for _, n := range []int{0, 1, 135, 1, 167, 200, 496} {
			got = append(got, xof.Read(n)...)
		}

		if !bytes.Equal(got, x.algorithm.Digest([]byte("abc"), 1000)) {
			t.Fatalf("%s: streamed output differs", x.file)
		}
	}
}

func panics(t *testing.T, code string, f func()) {
	t.Helper()

	defer func() {
		if message := fmt.Sprint(recover()); !strings.Contains(message, code) {
			t.Fatalf("panic %q, want %s", message, code)
		}
	}()

	f()
}

func TestXofErrors(t *testing.T) {
	xof := cryptopq.SHAKE128.Create()

	xof.Read(1)

	panics(t, "UNSUPPORTED", func() { xof.Update([]byte("x")) })

	panics(t, "INVALID_LENGTH", func() { cryptopq.SHAKE256.Digest(nil, -1) })

	if len(cryptopq.SHAKE256.Digest(nil, 0)) != 0 {
		t.Fatal("zero length")
	}
}

func TestXofProperties(t *testing.T) {
	if cryptopq.SHAKE128.Name() != "SHAKE128" || cryptopq.SHAKE256.String() != "SHAKE256" {
		t.Fatal("names")
	}
}

func TestInvalidAlgorithm(t *testing.T) {
	panics(t, "invalid HashAlgorithm", func() { cryptopq.HashAlgorithm(0).Create() })

	panics(t, "invalid XofAlgorithm", func() { cryptopq.XofAlgorithm(9).Create() })

	panics(t, "invalid HmacAlgorithm", func() { cryptopq.HmacAlgorithm(0).Create(nil) })
}

func TestHmacVectors(t *testing.T) {
	tested := 0

	for _, r := range records(t, "cavp/HMAC.rsp", "Mac") {
		if r.header["L"] == "20" {
			continue
		}

		h, ok := hmacs[r.header["L"]]

		if !ok {
			t.Fatalf("digest length %s", r.header["L"])
		}

		key := decode(t, r.values["Key"])

		data := decode(t, r.values["Msg"])

		mac := decode(t, r.values["Mac"])

		context := fmt.Sprintf("L = %s Count = %s", r.header["L"], r.values["Count"])

		if len(key) != number(t, r.values["Klen"]) || len(mac) != number(t, r.values["Tlen"]) {
			t.Fatalf("%s: lengths", context)
		}

		tag := h.algorithm.Digest(key, data)

		if !bytes.Equal(tag[:len(mac)], mac) {
			t.Fatalf("%s: got %x", context, tag)
		}

		hmac := h.algorithm.Create(key)

		for _, piece := range pieces(data) {
			hmac.Update(piece)
		}

		if !bytes.Equal(hmac.Digest(), tag) || !hmac.Verify(tag) || !h.algorithm.Verify(key, data, tag) {
			t.Fatalf("%s: streamed or verify", context)
		}

		tested++
	}

	if tested != 1275 {
		t.Fatalf("tested %d", tested)
	}
}

func TestHmacVerifyRejects(t *testing.T) {
	key := []byte("key")

	data := []byte("data")

	tag := cryptopq.HMAC_SHA_256.Digest(key, data)

	if cryptopq.HMAC_SHA_256.Verify(key, data, tag[:len(tag)-1]) {
		t.Fatal("truncated tag")
	}

	if cryptopq.HMAC_SHA_256.Verify(key, data, append(bytes.Clone(tag), 0)) {
		t.Fatal("extended tag")
	}

	if cryptopq.HMAC_SHA_256.Verify([]byte("kez"), data, tag) {
		t.Fatal("wrong key")
	}

	for index := range tag {
		flipped := bytes.Clone(tag)

		flipped[index] ^= 0x80

		if cryptopq.HMAC_SHA_256.Verify(key, data, flipped) {
			t.Fatalf("flipped byte %d", index)
		}
	}
}

func TestHmacProperties(t *testing.T) {
	for _, h := range hmacs {
		if h.algorithm.Name() != h.name || h.algorithm.String() != h.name {
			t.Fatalf("name %q, want %q", h.algorithm.Name(), h.name)
		}

		if len(h.algorithm.Digest([]byte("k"), nil)) != h.algorithm.DigestSize() {
			t.Fatalf("%s: digest size", h.name)
		}
	}
}

// The Into forms write what the allocating forms return, for messages around every block size.
func TestDigestIntoMatchesDigest(t *testing.T) {
	data := sequence(300)

	key := []byte("key")

	for _, length := range []int{0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 167, 168, 300} {
		message := data[:length]

		for _, h := range hashes {
			out := make([]byte, h.algorithm.DigestSize())

			h.algorithm.DigestInto(message, out)

			if !bytes.Equal(out, h.algorithm.Digest(message)) {
				t.Fatalf("%s, %d bytes: DigestInto differs from Digest", h.name, length)
			}

			hasher := h.algorithm.Create()

			hasher.Update(message)

			streamed := make([]byte, h.algorithm.DigestSize())

			hasher.DigestInto(streamed)

			if !bytes.Equal(streamed, out) {
				t.Fatalf("%s, %d bytes: Hasher.DigestInto differs from Digest", h.name, length)
			}
		}

		for _, x := range xofs {
			out := make([]byte, 200)

			x.algorithm.DigestInto(message, out)

			if !bytes.Equal(out, x.algorithm.Digest(message, 200)) {
				t.Fatalf("%s, %d bytes: DigestInto differs from Digest", x.file, length)
			}

			xof := x.algorithm.Create()

			xof.Update(message)

			read := make([]byte, 200)

			xof.ReadInto(read[:77])

			xof.ReadInto(read[77:])

			if !bytes.Equal(read, out) {
				t.Fatalf("%s, %d bytes: ReadInto differs from Digest", x.file, length)
			}
		}

		for _, h := range hmacs {
			out := make([]byte, h.algorithm.DigestSize())

			h.algorithm.DigestInto(key, message, out)

			if !bytes.Equal(out, h.algorithm.Digest(key, message)) {
				t.Fatalf("%s, %d bytes: DigestInto differs from Digest", h.name, length)
			}

			hmac := h.algorithm.Create(key)

			hmac.Update(message)

			streamed := make([]byte, h.algorithm.DigestSize())

			hmac.DigestInto(streamed)

			if !bytes.Equal(streamed, out) {
				t.Fatalf("%s, %d bytes: Hmac.DigestInto differs from Digest", h.name, length)
			}
		}
	}
}

func TestDigestIntoRejectsAnotherLength(t *testing.T) {
	for _, call := range []func(){
		func() { cryptopq.SHA_256.DigestInto(nil, make([]byte, 31)) },
		func() { cryptopq.SHA3_512.Create().DigestInto(make([]byte, 65)) },
		func() { cryptopq.HMAC_SHA_512.DigestInto(nil, nil, make([]byte, 63)) },
	} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "INVALID_LENGTH") {
					t.Fatalf("want an INVALID_LENGTH panic, got %v", r)
				}
			}()

			call()
		}()
	}
}

// With the output on the caller's side, the one-shot digests allocate nothing.
func TestDigestIntoAllocatesNothing(t *testing.T) {
	data := sequence(1000)

	var out [64]byte

	for _, h := range hashes {
		allocations := testing.AllocsPerRun(20, func() {
			h.algorithm.DigestInto(data, out[:h.algorithm.DigestSize()])
		})

		if allocations != 0 {
			t.Errorf("%s: %v allocations", h.name, allocations)
		}
	}

	allocations := testing.AllocsPerRun(20, func() {
		cryptopq.SHAKE256.DigestInto(data, out[:])
	})

	if allocations != 0 {
		t.Errorf("SHAKE256: %v allocations", allocations)
	}
}

// HMAC's one-shot forms allocate nothing either, for keys up to a block and longer ones, which are
// hashed first.
func TestHmacDigestIntoAllocatesNothing(t *testing.T) {
	data := sequence(1000)

	var out [64]byte

	for _, algorithm := range []cryptopq.HmacAlgorithm{cryptopq.HMAC_SHA_224, cryptopq.HMAC_SHA_256, cryptopq.HMAC_SHA_384, cryptopq.HMAC_SHA_512} {
		for _, keySize := range []int{0, 32, 64, 128, 200} {
			key := data[:keySize]

			tag := out[:algorithm.DigestSize()]

			allocations := testing.AllocsPerRun(20, func() {
				algorithm.DigestInto(key, data, tag)
			})

			if allocations != 0 {
				t.Errorf("%s, %d-byte key: %v allocations", algorithm, keySize, allocations)
			}

			allocations = testing.AllocsPerRun(20, func() {
				algorithm.Verify(key, data, tag)
			})

			if allocations != 0 {
				t.Errorf("%s verify, %d-byte key: %v allocations", algorithm, keySize, allocations)
			}
		}
	}
}
