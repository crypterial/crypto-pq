package cryptopq

import (
	"bytes"
	"strconv"
)

const (
	pemPublic  = "PUBLIC KEY"
	pemPrivate = "PRIVATE KEY"
)

func lengthError(name string, length int) error {
	return newError(INVALID_LENGTH, name+" must be "+strconv.Itoa(length)+" bytes")
}

func noDer() error {
	return newError(UNSUPPORTED, "this algorithm has no standard DER encoding")
}

func exportPublic(format KeyFormat, oid, raw []byte) ([]byte, error) {
	if err := checkFormat(format); err != nil {
		return nil, err
	}

	if format == RAW {
		return bytes.Clone(raw), nil
	}

	if oid == nil {
		return nil, noDer()
	}

	der := encodePublicKey(oid, raw)

	if format == DER {
		return der, nil
	}

	return pemEncode(pemPublic, der), nil
}

// size is the required key length, or -1 when the caller validates the key itself. A wrong
// length is INVALID_LENGTH in raw input and INVALID_ENCODING inside DER or PEM.
func importPublic(format KeyFormat, data, oid []byte, size int) ([]byte, error) {
	if err := checkFormat(format); err != nil {
		return nil, err
	}

	if format == RAW {
		if size >= 0 && len(data) != size {
			return nil, lengthError("public key", size)
		}

		return bytes.Clone(data), nil
	}

	if oid == nil {
		return nil, noDer()
	}

	der := data

	if format == PEM {
		var err error

		if der, err = pemDecode(pemPublic, data); err != nil {
			return nil, err
		}
	}

	found, key, err := decodePublicKey(der)

	if err != nil {
		return nil, err
	}

	if !bytes.Equal(found, oid) {
		return nil, newError(ALGORITHM_MISMATCH, "the key belongs to another algorithm")
	}

	if size >= 0 && len(key) != size {
		return nil, invalidEncoding("the public key has the wrong length")
	}

	return bytes.Clone(key), nil
}

func exportPrivate(format KeyFormat, oid, octets, raw []byte) ([]byte, error) {
	if err := checkFormat(format); err != nil {
		return nil, err
	}

	if format == RAW {
		return bytes.Clone(raw), nil
	}

	if oid == nil {
		return nil, noDer()
	}

	der := encodePrivateKey(oid, octets)

	if format == DER {
		return der, nil
	}

	pem := pemEncode(pemPrivate, der)

	clear(der)

	return pem, nil
}

// Returns a copy of raw input, or copies of the privateKey octets and of the optional public key
// of PKCS#8 input whose algorithm matches.
func importPrivate(format KeyFormat, data, oid []byte) (raw, octets, publicKey []byte, err error) {
	if err := checkFormat(format); err != nil {
		return nil, nil, nil, err
	}

	if format == RAW {
		return bytes.Clone(data), nil, nil, nil
	}

	if oid == nil {
		return nil, nil, nil, noDer()
	}

	der := data

	if format == PEM {
		if der, err = pemDecode(pemPrivate, data); err != nil {
			return nil, nil, nil, err
		}

		defer clear(der)
	}

	found, key, public, err := decodePrivateKey(der)

	if err != nil {
		return nil, nil, nil, err
	}

	if !bytes.Equal(found, oid) {
		return nil, nil, nil, newError(ALGORITHM_MISMATCH, "the key belongs to another algorithm")
	}

	return nil, bytes.Clone(key), bytes.Clone(public), nil
}

// ML-KEM and ML-DSA private keys: CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET
// STRING, both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }.
func encodeSeedChoice(seed, expanded []byte) []byte {
	if seed != nil {
		return derElement(tagContext0, seed)
	}

	return derElement(tagOctetString, expanded)
}

// Exports the seed when it is known and the expanded key otherwise.
func exportSeedChoice(format KeyFormat, oid, seed, expanded []byte) ([]byte, error) {
	raw := expanded

	if seed != nil {
		raw = seed
	}

	if format != DER && format != PEM {
		return exportPrivate(format, oid, nil, raw)
	}

	octets := encodeSeedChoice(seed, expanded)

	defer clear(octets)

	return exportPrivate(format, oid, octets, raw)
}

func decodeSeedChoice(octets []byte, seedSize, expandedSize int) (seed, expanded []byte, err error) {
	tag := -1

	if len(octets) > 0 {
		tag = int(octets[0])
	}

	switch tag {
	case tagContext0:
		seed, err = derOnly(octets, tagContext0)
	case tagOctetString:
		expanded, err = derOnly(octets, tagOctetString)
	case tagSequence:
		seed, expanded, err = decodeBoth(octets)
	default:
		err = invalidEncoding("unknown private key form")
	}

	if err != nil {
		return nil, nil, err
	}

	if seed != nil && len(seed) != seedSize {
		return nil, nil, invalidEncoding("the seed has the wrong length")
	}

	if expanded != nil && len(expanded) != expandedSize {
		return nil, nil, invalidEncoding("the expanded key has the wrong length")
	}

	return seed, expanded, nil
}

func decodeBoth(octets []byte) (seed, expanded []byte, err error) {
	content, err := derOnly(octets, tagSequence)

	if err != nil {
		return nil, nil, err
	}

	reader := derReader{data: content}

	if seed, err = reader.read(tagOctetString); err != nil {
		return nil, nil, err
	}

	if expanded, err = reader.read(tagOctetString); err != nil {
		return nil, nil, err
	}

	return seed, expanded, reader.finish()
}
