package cryptopq

// KdfAlgorithm names a key derivation function: HKDF (RFC 5869) over HMAC-SHA-256, -384 or -512.
type KdfAlgorithm uint8

const (
	HKDF_SHA_256 KdfAlgorithm = iota + 1
	HKDF_SHA_384
	HKDF_SHA_512
)

// KdfOptions are the inputs of a derivation besides the key material: the salt of Extract (empty
// means HashLen zero bytes, which gives the same key) and the info of Expand.
type KdfOptions struct {
	Salt []byte
	Info []byte
}

type kdfSpec struct {
	name string
	hash HashAlgorithm
}

var kdfSpecs = [...]kdfSpec{
	HKDF_SHA_256: {"HKDF-SHA-256", SHA_256},
	HKDF_SHA_384: {"HKDF-SHA-384", SHA_384},
	HKDF_SHA_512: {"HKDF-SHA-512", SHA_512},
}

func (a KdfAlgorithm) spec() *kdfSpec {
	if a == 0 || int(a) >= len(kdfSpecs) {
		panic("cryptopq: invalid KdfAlgorithm")
	}

	return &kdfSpecs[a]
}

func (a KdfAlgorithm) Name() string {
	return a.spec().name
}

func (a KdfAlgorithm) String() string {
	return a.Name()
}

func kdfInputs(options *KdfOptions) (salt, info []byte) {
	if options == nil {
		return nil, nil
	}

	return options.Salt, options.Info
}

// RFC 5869 bounds the output by 255 blocks of the hash; an empty output is refused as well.
func (a KdfAlgorithm) checkLength(length int) error {
	if length <= 0 || length > 255*a.spec().hash.DigestSize() {
		return newError(INVALID_LENGTH, "the output of "+a.Name()+" is 1 to 255 hash lengths")
	}

	return nil
}

// Derive returns length bytes of Expand(Extract(salt, ikm), info).
func (a KdfAlgorithm) Derive(ikm []byte, length int, options *KdfOptions) ([]byte, error) {
	if err := a.checkLength(length); err != nil {
		return nil, err
	}

	out := make([]byte, length)

	if err := a.DeriveInto(ikm, out, options); err != nil {
		return nil, err
	}

	return out, nil
}

// DeriveInto fills out without allocating; the pseudorandom key stays on the stack and is cleared.
func (a KdfAlgorithm) DeriveInto(ikm, out []byte, options *KdfOptions) error {
	if err := a.checkLength(len(out)); err != nil {
		return err
	}

	hash := a.spec().hash

	salt, info := kdfInputs(options)

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	var prk [64]byte

	size := hash.DigestSize()

	hmacInto(hash, salt, ikm, prk[:size])

	hkdfExpand(hash, prk[:size], info, out)

	clear(prk[:])

	return nil
}

// Extract returns the pseudorandom key, HashLen bytes; options.Info is not used.
func (a KdfAlgorithm) Extract(ikm []byte, options *KdfOptions) []byte {
	prk := make([]byte, a.spec().hash.DigestSize())

	a.ExtractInto(ikm, prk, options)

	return prk
}

// ExtractInto writes the pseudorandom key into prk, which must be HashLen bytes long.
func (a KdfAlgorithm) ExtractInto(ikm, prk []byte, options *KdfOptions) {
	hash := a.spec().hash

	checkDigestLength(len(prk), hash.DigestSize())

	salt, _ := kdfInputs(options)

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	hmacInto(hash, salt, ikm, prk)
}

// Expand returns length bytes from a pseudorandom key of at least HashLen bytes; options.Salt is
// not used.
func (a KdfAlgorithm) Expand(prk []byte, length int, options *KdfOptions) ([]byte, error) {
	if err := a.checkLength(length); err != nil {
		return nil, err
	}

	out := make([]byte, length)

	if err := a.ExpandInto(prk, out, options); err != nil {
		return nil, err
	}

	return out, nil
}

func (a KdfAlgorithm) ExpandInto(prk, out []byte, options *KdfOptions) error {
	hash := a.spec().hash

	if len(prk) < hash.DigestSize() {
		return newError(INVALID_LENGTH, "the pseudorandom key of "+a.Name()+" is at least the hash length")
	}

	if err := a.checkLength(len(out)); err != nil {
		return err
	}

	_, info := kdfInputs(options)

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	hkdfExpand(hash, prk, info, out)

	return nil
}

// The message of T(i) when T(i - 1), info and the counter fit on the stack together.
const hkdfMessageLimit = 256

// HKDF-Expand: T(i) = HMAC(PRK, T(i - 1) || info || i), with the keyed inner and outer states
// computed once. With a short info the message of each T(i) is laid out once on the stack,
// T(i - 1) then info then the counter, so that each hash is finished in one call; a longer info
// streams through an engine on the stack. Every buffer is cleared; the callers decide on DIT.
func hkdfExpand(hash HashAlgorithm, prk, info, out []byte) {
	spec := hashSpecOf(hash.id)

	size := spec.digestSize

	var block [128]byte

	hmacKey(hash, prk, &block)

	var message [hkdfMessageLimit]byte

	var t [64]byte

	var inner [64]byte

	var counter [1]byte

	short := size+len(info)+1 <= len(message)

	if short {
		copy(message[size:], info)
	}

	end := size + len(info) + 1

	if spec.blockSize == 64 {
		keyed := hmacKeys256(hashIV256(hash), &block)

		innerState, outerState := [8]uint32(keyed[:8]), [8]uint32(keyed[8:])

		for i := 1; len(out) > 0; i++ {
			counter[0] = byte(i)

			if short {
				message[end-1] = byte(i)

				start := size

				if i > 1 {
					copy(message[:size], t[:size])

					start = 0
				}

				sha256FinishSecret(innerState, 64, message[start:end], inner[:size])
			} else {
				e := sha256Engine{state: innerState, length: 64, size: size}

				if i > 1 {
					e.update(t[:size])
				}

				e.update(info)

				e.update(counter[:])

				e.digestInto(inner[:size])

				clear(e.state[:])

				clear(e.buffer[:])
			}

			sha256FinishSecret(outerState, 64, inner[:size], t[:size])

			out = out[copy(out, t[:size]):]
		}

		clear(keyed[:])

		clear(innerState[:])

		clear(outerState[:])
	} else {
		keyed := hmacKeys512(hashIV512(hash), &block)

		for i := 1; len(out) > 0; i++ {
			counter[0] = byte(i)

			if short {
				message[end-1] = byte(i)

				start := size

				if i > 1 {
					copy(message[:size], t[:size])

					start = 0
				}

				sha512FinishSecret(keyed[0], 128, message[start:end], inner[:size])
			} else {
				e := sha512Engine{state: keyed[0], length: 128, size: size}

				if i > 1 {
					e.update(t[:size])
				}

				e.update(info)

				e.update(counter[:])

				e.digestInto(inner[:size])

				clear(e.state[:])

				clear(e.buffer[:])
			}

			sha512FinishSecret(keyed[1], 128, inner[:size], t[:size])

			out = out[copy(out, t[:size]):]
		}

		clear(keyed[0][:])

		clear(keyed[1][:])
	}

	clear(block[:])

	clear(message[:])

	clear(t[:])

	clear(inner[:])
}
