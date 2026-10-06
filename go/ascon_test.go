package cryptopq_test

import (
	"bytes"
	"fmt"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

// An XOF output checked through every form: one-shot, Into, and streamed in uneven pieces with
// reads split in two.
func checkXof(t *testing.T, context string, algorithm cryptopq.XofAlgorithm, data, want []byte) {
	t.Helper()

	same(t, algorithm.Digest(data, len(want)), want, context)

	out := make([]byte, len(want))

	algorithm.DigestInto(data, out)

	same(t, out, want, context+" DigestInto")

	xof := algorithm.Create()

	for _, piece := range pieces(data) {
		xof.Update(piece)
	}

	split := len(want) / 3

	streamed := append(xof.Read(split), xof.Read(len(want)-split)...)

	same(t, streamed, want, context+" streamed")
}

func checkHash(t *testing.T, context string, algorithm cryptopq.HashAlgorithm, data, want []byte) {
	t.Helper()

	same(t, algorithm.Digest(data), want, context)

	out := make([]byte, algorithm.DigestSize())

	algorithm.DigestInto(data, out)

	same(t, out, want, context+" DigestInto")

	hasher := algorithm.Create()

	for _, piece := range pieces(data) {
		hasher.Update(piece)
	}

	same(t, hasher.Digest(), want, context+" streamed")
}

func asconCxof(t *testing.T, customization []byte) cryptopq.XofAlgorithm {
	t.Helper()

	algorithm, err := cryptopq.ASCON_CXOF128.Configure(&cryptopq.XofOptions{Customization: customization})

	check(t, err)

	return algorithm
}

// The designers' KATs: messages of 0 to 1024 bytes, and for Ascon-CXOF128 messages and
// customizations of 0 to 32 bytes each.
func TestAsconKat(t *testing.T) {
	files := []struct {
		name  string
		count int
	}{{"LWC_HASH_KAT_128_256", 1025}, {"LWC_XOF_KAT_128_512", 1025}, {"LWC_CXOF_KAT_128_512", 1089}}

	for _, file := range files {
		tested := 0

		for _, r := range records(t, "ascon/"+file.name+".txt", "MD") {
			context := fmt.Sprintf("%s Count = %s", file.name, r.values["Count"])

			data, want := decode(t, r.values["Msg"]), decode(t, r.values["MD"])

			switch file.name {
			case "LWC_HASH_KAT_128_256":
				checkHash(t, context, cryptopq.ASCON_HASH256, data, want)
			case "LWC_XOF_KAT_128_512":
				checkXof(t, context, cryptopq.ASCON_XOF128, data, want)
			default:
				checkXof(t, context, asconCxof(t, decode(t, r.values["Z"])), data, want)
			}

			tested++
		}

		if tested != file.count {
			t.Fatalf("%s: tested %d", file.name, tested)
		}
	}
}

// The ACVP tests with whole-byte lengths.
func TestAsconAcvp(t *testing.T) {
	counts := map[string]int{}

	for _, r := range records(t, "acvp/Ascon.txt", "md") {
		set := r.header["parameterSet"]

		context := fmt.Sprintf("%s tcId %s", set, r.values["tcId"])

		data, want := decode(t, r.values["msg"]), decode(t, r.values["md"])

		switch set {
		case "Ascon-Hash256":
			checkHash(t, context, cryptopq.ASCON_HASH256, data, want)
		case "Ascon-XOF128":
			checkXof(t, context, cryptopq.ASCON_XOF128, data, want)
		case "Ascon-CXOF128":
			checkXof(t, context, asconCxof(t, decode(t, r.values["cs"])), data, want)
		default:
			t.Fatalf("unknown parameter set %s", set)
		}

		counts[set]++
	}

	if counts["Ascon-Hash256"] != 12 || counts["Ascon-XOF128"] != 3 || counts["Ascon-CXOF128"] != 1 {
		t.Fatalf("tested %v", counts)
	}
}

func TestAsconOptions(t *testing.T) {
	longest := sequence(256)

	if _, err := cryptopq.ASCON_CXOF128.Configure(&cryptopq.XofOptions{Customization: longest}); err != nil {
		t.Fatal(err)
	}

	_, err := cryptopq.ASCON_CXOF128.Configure(&cryptopq.XofOptions{Customization: sequence(257)})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.ASCON_XOF128.Configure(&cryptopq.XofOptions{Customization: []byte{0}})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	_, err = cryptopq.ASCON_HASH256.Configure(&cryptopq.HashOptions{Salt: []byte{0}})

	expectCode(t, err, cryptopq.INVALID_OPTION)

	for _, algorithm := range []cryptopq.XofAlgorithm{cryptopq.ASCON_XOF128, cryptopq.ASCON_CXOF128} {
		unchanged, err := algorithm.Configure(&cryptopq.XofOptions{})

		check(t, err)

		if unchanged != algorithm {
			t.Fatalf("%s: empty options changed the algorithm", algorithm)
		}
	}

	// The empty customization still goes through the customization blocks, so CXOF differs from
	// XOF, and the length of the customization is bound.
	if bytes.Equal(cryptopq.ASCON_CXOF128.Digest(nil, 32), cryptopq.ASCON_XOF128.Digest(nil, 32)) {
		t.Fatal("Ascon-CXOF128 without customization equals Ascon-XOF128")
	}

	if asconCxof(t, []byte{0}) == cryptopq.ASCON_CXOF128 {
		t.Fatal("a zero byte of customization changed nothing")
	}
}
