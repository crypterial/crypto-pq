package cryptopq

import "math/bits"

const (
	tagInteger             = 0x02
	tagBitString           = 0x03
	tagOctetString         = 0x04
	tagObjectIdentifier    = 0x06
	tagSequence            = 0x30
	tagContext0            = 0x80
	tagContext1            = 0x81
	tagContext0Constructed = 0xa0
)

type KeyFormat string

const (
	RAW KeyFormat = "raw"
	DER KeyFormat = "der"
	PEM KeyFormat = "pem"
)

func checkFormat(format KeyFormat) error {
	if format != RAW && format != DER && format != PEM {
		return invalidOption("format must be raw, der or pem")
	}

	return nil
}

// The content octets of an OBJECT IDENTIFIER.
func objectIdentifier(arcs ...uint64) []byte {
	content := []byte{byte(40*arcs[0] + arcs[1])}

	for _, arc := range arcs[2:] {
		var chunk [10]byte

		i := len(chunk) - 1

		chunk[i] = byte(arc & 0x7f)

		for arc >>= 7; arc > 0; arc >>= 7 {
			i--

			chunk[i] = 0x80 | byte(arc&0x7f)
		}

		content = append(content, chunk[i:]...)
	}

	return content
}

func derElement(tag byte, parts ...[]byte) []byte {
	length := 0

	for _, part := range parts {
		length += len(part)
	}

	out := make([]byte, 0, length+6)

	out = append(out, tag)

	if length < 0x80 {
		out = append(out, byte(length))
	} else {
		size := (bits.Len(uint(length)) + 7) / 8

		out = append(out, 0x80|byte(size))

		for i := size - 1; i >= 0; i-- {
			out = append(out, byte(length>>(8*i)))
		}
	}

	for _, part := range parts {
		out = append(out, part...)
	}

	return out
}

type derReader struct {
	data   []byte
	offset int
}

// DER only: a single-byte tag and the shortest definite length.
func (r *derReader) read(tag byte) ([]byte, error) {
	data := r.data

	if r.offset+2 > len(data) || data[r.offset] != tag {
		return nil, invalidEncoding("unexpected DER element")
	}

	first := data[r.offset+1]

	offset := r.offset + 2

	length := uint64(first)

	if first >= 0x80 {
		size := int(first & 0x7f)

		if size == 0 || size > 4 || offset+size > len(data) || data[offset] == 0 {
			return nil, invalidEncoding("invalid DER length")
		}

		length = 0

		for _, b := range data[offset : offset+size] {
			length = length<<8 | uint64(b)
		}

		offset += size

		if length < 0x80 {
			return nil, invalidEncoding("invalid DER length")
		}
	}

	if length > uint64(len(data)-offset) {
		return nil, invalidEncoding("truncated DER element")
	}

	r.offset = offset + int(length)

	return data[offset:r.offset], nil
}

func (r *derReader) peek() int {
	if r.offset < len(r.data) {
		return int(r.data[r.offset])
	}

	return -1
}

func (r *derReader) finish() error {
	if r.offset != len(r.data) {
		return invalidEncoding("trailing data after DER element")
	}

	return nil
}

func derOnly(data []byte, tag byte) ([]byte, error) {
	reader := derReader{data: data}

	content, err := reader.read(tag)

	if err != nil {
		return nil, err
	}

	return content, reader.finish()
}

func algorithmIdentifier(oid []byte) []byte {
	return derElement(tagSequence, derElement(tagObjectIdentifier, oid))
}

func readAlgorithm(reader *derReader) ([]byte, error) {
	sequence, err := reader.read(tagSequence)

	if err != nil {
		return nil, err
	}

	return derOnly(sequence, tagObjectIdentifier)
}

func encodePublicKey(oid, key []byte) []byte {
	return derElement(tagSequence, algorithmIdentifier(oid), derElement(tagBitString, []byte{0}, key))
}

func decodePublicKey(data []byte) (oid, key []byte, err error) {
	content, err := derOnly(data, tagSequence)

	if err != nil {
		return nil, nil, err
	}

	reader := derReader{data: content}

	if oid, err = readAlgorithm(&reader); err != nil {
		return nil, nil, err
	}

	bitString, err := reader.read(tagBitString)

	if err != nil {
		return nil, nil, err
	}

	if err = reader.finish(); err != nil {
		return nil, nil, err
	}

	if len(bitString) == 0 || bitString[0] != 0 {
		return nil, nil, invalidEncoding("public key BIT STRING must have no unused bits")
	}

	return oid, bitString[1:], nil
}

func encodePrivateKey(oid, key []byte) []byte {
	inner := derElement(tagOctetString, key)

	der := derElement(tagSequence, derElement(tagInteger, []byte{0}), algorithmIdentifier(oid), inner)

	clear(inner)

	return der
}

// PKCS#8 OneAsymmetricKey (RFC 5958): version 0 or 1, attributes ignored, and the optional
// public key returned so that the caller can check that it matches.
func decodePrivateKey(data []byte) (oid, key, publicKey []byte, err error) {
	content, err := derOnly(data, tagSequence)

	if err != nil {
		return nil, nil, nil, err
	}

	reader := derReader{data: content}

	version, err := reader.read(tagInteger)

	if err != nil {
		return nil, nil, nil, err
	}

	if len(version) != 1 || version[0] > 1 {
		return nil, nil, nil, invalidEncoding("unsupported PKCS#8 version")
	}

	if oid, err = readAlgorithm(&reader); err != nil {
		return nil, nil, nil, err
	}

	if key, err = reader.read(tagOctetString); err != nil {
		return nil, nil, nil, err
	}

	if reader.peek() == tagContext0Constructed {
		if _, err = reader.read(tagContext0Constructed); err != nil {
			return nil, nil, nil, err
		}
	}

	if reader.peek() == tagContext1 {
		if version[0] != 1 {
			return nil, nil, nil, invalidEncoding("a PKCS#8 public key requires version 1")
		}

		bitString, err := reader.read(tagContext1)

		if err != nil {
			return nil, nil, nil, err
		}

		if len(bitString) == 0 || bitString[0] != 0 {
			return nil, nil, nil, invalidEncoding("public key BIT STRING must have no unused bits")
		}

		publicKey = bitString[1:]
	}

	if err = reader.finish(); err != nil {
		return nil, nil, nil, err
	}

	return oid, key, publicKey, nil
}

func base64Character(value int32) byte {
	character := value + 65

	character += ((25 - value) >> 8) & 6

	character -= ((51 - value) >> 8) & 75

	character -= ((61 - value) >> 8) & 15

	character += ((62 - value) >> 8) & 3

	return byte(character)
}

// Arithmetic instead of table lookups, so that decoding a private key does not index memory
// with secret values; -1 marks a character outside the alphabet.
func base64Value(character byte) int32 {
	c := int32(character)

	value := int32(-1)

	value += (((0x40 - c) & (c - 0x5b)) >> 8) & (c - 64)

	value += (((0x60 - c) & (c - 0x7b)) >> 8) & (c - 70)

	value += (((0x2f - c) & (c - 0x3a)) >> 8) & (c + 5)

	value += (((0x2a - c) & (c - 0x2c)) >> 8) & 63

	value += (((0x2e - c) & (c - 0x30)) >> 8) & 64

	return value
}

func base64Encode(data []byte) []byte {
	out := make([]byte, 0, (len(data)+2)/3*4)

	for offset := 0; offset < len(data); offset += 3 {
		chunk := data[offset:min(offset+3, len(data))]

		var value int32

		for i, b := range chunk {
			value |= int32(b) << (16 - 8*i)
		}

		used := len(chunk) + 1

		for i, shift := range [4]int{18, 12, 6, 0} {
			if i < used {
				out = append(out, base64Character((value>>shift)&0x3f))
			} else {
				out = append(out, '=')
			}
		}
	}

	return out
}

func base64Decode(text []byte) ([]byte, error) {
	if len(text)%4 != 0 {
		return nil, invalidEncoding("invalid base64 length")
	}

	out := make([]byte, 0, len(text)/4*3)

	for offset := 0; offset < len(text); offset += 4 {
		chunk := text[offset : offset+4]

		padding := 0

		if offset+4 == len(text) {
			if chunk[2] == '=' && chunk[3] == '=' {
				padding = 2
			} else if chunk[3] == '=' {
				padding = 1
			}
		}

		var value, invalid int32

		for _, character := range chunk[:4-padding] {
			item := base64Value(character)

			invalid |= item

			value = value<<6 | (item & 0x3f)
		}

		if invalid < 0 {
			return nil, invalidEncoding("invalid base64 character")
		}

		value <<= 6 * padding

		if value&(1<<(8*padding)-1) != 0 {
			return nil, invalidEncoding("non-canonical base64 padding")
		}

		decoded := [3]byte{byte(value >> 16), byte(value >> 8), byte(value)}

		out = append(out, decoded[:3-padding]...)
	}

	return out, nil
}

func pemEncode(label string, der []byte) []byte {
	body := base64Encode(der)

	out := make([]byte, 0, len(body)+len(body)/64+2*len(label)+32)

	out = append(out, "-----BEGIN "+label+"-----\n"...)

	for offset := 0; offset < len(body); offset += 64 {
		out = append(out, body[offset:min(offset+64, len(body))]...)

		out = append(out, '\n')
	}

	clear(body)

	return append(out, "-----END "+label+"-----\n"...)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func pemDecode(label string, data []byte) ([]byte, error) {
	start, end := 0, len(data)

	for start < end && isSpace(data[start]) {
		start++
	}

	for end > start && isSpace(data[end-1]) {
		end--
	}

	data = data[start:end]

	begin := "-----BEGIN " + label + "-----"

	finish := "-----END " + label + "-----"

	if len(data) < len(begin)+len(finish) || string(data[:len(begin)]) != begin || string(data[len(data)-len(finish):]) != finish {
		return nil, invalidEncoding("expected a " + label + " PEM block")
	}

	body := make([]byte, 0, len(data))

	for _, c := range data[len(begin) : len(data)-len(finish)] {
		if c > 0x7f {
			clear(body)

			return nil, invalidEncoding("PEM must be ASCII")
		}

		if !isSpace(c) {
			body = append(body, c)
		}
	}

	der, err := base64Decode(body)

	clear(body)

	return der, err
}
