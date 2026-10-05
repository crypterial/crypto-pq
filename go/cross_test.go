package cryptopq_test

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	cryptopq "github.com/crypterial/crypto-pq-go"
)

// The vectors under vectors/cross were computed by the Python reference: keys and their
// encodings, hazmat signatures with every pre-hash, implicit rejection, state blobs, and the
// error code of every malformed input.

var crossKems = []cryptopq.KemAlgorithm{cryptopq.ML_KEM_512, cryptopq.ML_KEM_768, cryptopq.ML_KEM_1024, cryptopq.X_WING}

var crossStateful = []cryptopq.StatefulSignatureAlgorithm{cryptopq.HSS_LMS, cryptopq.XMSS, cryptopq.XMSS_MT}

var crossEncodings = []struct {
	format cryptopq.KeyFormat
	suffix string
}{{cryptopq.DER, "Der"}, {cryptopq.PEM, "Pem"}}

func crossKem(t *testing.T, name string) cryptopq.KemAlgorithm {
	t.Helper()

	for _, algorithm := range crossKems {
		if algorithm.Name() == name {
			return algorithm
		}
	}

	t.Fatalf("unknown KEM %s", name)

	return 0
}

func crossSignature(name string) (cryptopq.SignatureAlgorithm, bool) {
	if algorithm, ok := dsaAlgorithms[name]; ok {
		return algorithm, true
	}

	algorithm, ok := slhAlgorithms[name]

	return algorithm, ok
}

func crossStatefulAlgorithm(name string) (cryptopq.StatefulSignatureAlgorithm, bool) {
	for _, algorithm := range crossStateful {
		if algorithm.Name() == name {
			return algorithm, true
		}
	}

	return 0, false
}

func crossPreHash(name string) cryptopq.PreHash {
	if name == "none" || name == "" {
		return nil
	}

	return preHashes[name]
}

// The decoded value of a field, or nothing when the record has no such field.
func crossField(t *testing.T, values fields, name string) []byte {
	t.Helper()

	return decode(t, values[name])
}

func crossOptions(values fields) *cryptopq.StatefulKeyGenOptions {
	options := &cryptopq.StatefulKeyGenOptions{Parameters: values["parameters"], StateStore: &memoryStore{}}

	if values["lms"] != "" {
		lms, ots := strings.Split(values["lms"], ","), strings.Split(values["ots"], ",")

		for i := range lms {
			options.Levels = append(options.Levels, cryptopq.HssLevel{Lms: lms[i], Ots: ots[i]})
		}
	}

	return options
}

func TestCrossKem(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "cross/kem.txt", "seed") {
		algorithm := crossKem(t, r.header["algorithm"])

		context := algorithm.Name() + " tcId " + r.values["tcId"]

		seed, public := crossField(t, r.values, "seed"), crossField(t, r.values, "publicKey")

		pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

		check(t, err)

		same(t, export(t, pair.PublicKey, cryptopq.RAW), public, context)

		same(t, export(t, pair.PrivateKey, cryptopq.RAW), seed, context)

		imported, err := algorithm.ImportPublicKey(public, cryptopq.RAW)

		check(t, err)

		if !imported.Equal(pair.PublicKey) {
			t.Fatalf("%s: the imported public key differs", context)
		}

		fromSeed, err := algorithm.ImportPrivateKey(seed, cryptopq.RAW)

		check(t, err)

		keys := []*cryptopq.KemPrivateKey{pair.PrivateKey, fromSeed}

		if r.values["expandedKey"] != "" {
			for _, encoding := range crossEncodings {
				encoded := crossField(t, r.values, "publicKey"+encoding.suffix)

				same(t, export(t, pair.PublicKey, encoding.format), encoded, context)

				importedPublic, err := algorithm.ImportPublicKey(encoded, encoding.format)

				check(t, err)

				same(t, export(t, importedPublic, cryptopq.RAW), public, context)

				encoded = crossField(t, r.values, "privateKey"+encoding.suffix)

				same(t, export(t, pair.PrivateKey, encoding.format), encoded, context)

				importedPrivate, err := algorithm.ImportPrivateKey(encoded, encoding.format)

				check(t, err)

				same(t, export(t, importedPrivate, cryptopq.RAW), seed, context)
			}

			expanded := crossField(t, r.values, "expandedKey")

			key, err := algorithm.ImportPrivateKey(expanded, cryptopq.RAW)

			check(t, err)

			same(t, export(t, key, cryptopq.RAW), expanded, context)

			same(t, export(t, key.PublicKey(), cryptopq.RAW), public, context)

			for _, encoding := range crossEncodings {
				encoded := crossField(t, r.values, "expandedKey"+encoding.suffix)

				same(t, export(t, key, encoding.format), encoded, context)

				importedPrivate, err := algorithm.ImportPrivateKey(encoded, encoding.format)

				check(t, err)

				same(t, export(t, importedPrivate, cryptopq.RAW), expanded, context)
			}

			both, err := algorithm.ImportPrivateKey(crossField(t, r.values, "bothKeyDer"), cryptopq.DER)

			check(t, err)

			same(t, export(t, both, cryptopq.DER), crossField(t, r.values, "privateKeyDer"), context)

			keys = append(keys, key)
		}

		encapsulation, err := cryptopq.Hazmat.Encapsulate(pair.PublicKey, crossField(t, r.values, "randomness"))

		check(t, err)

		same(t, encapsulation.Ciphertext, crossField(t, r.values, "ciphertext"), context)

		same(t, encapsulation.SharedSecret, crossField(t, r.values, "sharedSecret"), context)

		for _, key := range keys {
			sharedSecret, err := key.Decapsulate(encapsulation.Ciphertext)

			check(t, err)

			same(t, sharedSecret, encapsulation.SharedSecret, context)

			rejected, err := key.Decapsulate(crossField(t, r.values, "tamperedCiphertext"))

			check(t, err)

			same(t, rejected, crossField(t, r.values, "rejectedSecret"), context)
		}
	}
}

func TestCrossMlDsa(t *testing.T) {
	t.Parallel()

	crossSignatures(t, "cross/mldsa.txt")
}

func TestCrossSlhDsa(t *testing.T) {
	t.Parallel()

	crossSignatures(t, "cross/slhdsa.txt")
}

func crossSignatures(t *testing.T, name string) {
	for i, r := range records(t, name, "signature") {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			algorithm, _ := crossSignature(r.header["algorithm"])

			seed := crossField(t, r.header, "seed")

			pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, seed)

			check(t, err)

			if r.values["signature"] == "" {
				crossSignatureKey(t, algorithm, pair, seed, r.values)

				return
			}

			context := algorithm.Name() + " " + r.values["mode"] + " " + r.values["preHash"]

			message, contextBytes := crossField(t, r.values, "message"), crossField(t, r.values, "context")

			preHash := crossPreHash(r.values["preHash"])

			options := &cryptopq.SignOptions{Context: contextBytes, Deterministic: true, PreHash: preHash}

			var signature []byte

			if r.values["mode"] == "hazmat" {
				signature, err = cryptopq.Hazmat.Sign(pair.PrivateKey, message, crossField(t, r.values, "randomness"), options)
			} else {
				signature, err = pair.PrivateKey.Sign(message, options)
			}

			check(t, err)

			same(t, signature, crossField(t, r.values, "signature"), context)

			verifyOptions := &cryptopq.VerifyOptions{Context: contextBytes, PreHash: preHash}

			if !cryptopq.Hazmat.Verify(pair.PublicKey, signature, message, verifyOptions) {
				t.Fatalf("%s: hazmat verification failed", context)
			}

			if pair.PublicKey.Verify(signature, message, verifyOptions) != (r.values["publicVerify"] == "true") {
				t.Fatalf("%s: verify should answer %s", context, r.values["publicVerify"])
			}
		})
	}
}

func crossSignatureKey(t *testing.T, algorithm cryptopq.SignatureAlgorithm, pair *cryptopq.SignatureKeyPair, seed []byte, values fields) {
	context := algorithm.Name() + " key"

	public := crossField(t, values, "publicKey")

	same(t, export(t, pair.PublicKey, cryptopq.RAW), public, context)

	// ML-DSA keeps its seed as the raw private key; SLH-DSA has the 4n-byte key.
	private := seed

	if values["privateKey"] != "" {
		private = crossField(t, values, "privateKey")
	}

	same(t, export(t, pair.PrivateKey, cryptopq.RAW), private, context)

	imported, err := algorithm.ImportPrivateKey(private, cryptopq.RAW)

	check(t, err)

	same(t, export(t, imported.PublicKey(), cryptopq.RAW), public, context)

	for _, encoding := range crossEncodings {
		encoded := crossField(t, values, "publicKey"+encoding.suffix)

		same(t, export(t, pair.PublicKey, encoding.format), encoded, context)

		importedPublic, err := algorithm.ImportPublicKey(encoded, encoding.format)

		check(t, err)

		same(t, export(t, importedPublic, cryptopq.RAW), public, context)

		encoded = crossField(t, values, "privateKey"+encoding.suffix)

		same(t, export(t, pair.PrivateKey, encoding.format), encoded, context)

		importedPrivate, err := algorithm.ImportPrivateKey(encoded, encoding.format)

		check(t, err)

		same(t, export(t, importedPrivate, cryptopq.RAW), private, context)
	}

	if values["expandedKey"] == "" {
		return
	}

	expanded := crossField(t, values, "expandedKey")

	key, err := algorithm.ImportPrivateKey(expanded, cryptopq.RAW)

	check(t, err)

	same(t, export(t, key, cryptopq.RAW), expanded, context)

	same(t, export(t, key.PublicKey(), cryptopq.RAW), public, context)

	for _, encoding := range crossEncodings {
		encoded := crossField(t, values, "expandedKey"+encoding.suffix)

		same(t, export(t, key, encoding.format), encoded, context)

		importedPrivate, err := algorithm.ImportPrivateKey(encoded, encoding.format)

		check(t, err)

		same(t, export(t, importedPrivate, cryptopq.RAW), expanded, context)
	}

	both, err := algorithm.ImportPrivateKey(crossField(t, values, "bothKeyDer"), cryptopq.DER)

	check(t, err)

	same(t, export(t, both, cryptopq.DER), crossField(t, values, "privateKeyDer"), context)
}

func TestCrossHss(t *testing.T) {
	t.Parallel()

	crossStatefulKeys(t, "cross/hss.txt")
}

func TestCrossXmss(t *testing.T) {
	t.Parallel()

	crossStatefulKeys(t, "cross/xmss.txt")
}

func crossStatefulKeys(t *testing.T, name string) {
	for _, r := range records(t, name, "stateAfter") {
		t.Run(r.values["tcId"], func(t *testing.T) {
			t.Parallel()

			algorithm, _ := crossStatefulAlgorithm(r.header["algorithm"])

			context := algorithm.Name() + " tcId " + r.values["tcId"]

			public, message := crossField(t, r.values, "publicKey"), crossField(t, r.values, "message")

			signature, state, after := crossField(t, r.values, "signature"), crossField(t, r.values, "state"), crossField(t, r.values, "stateAfter")

			index, err := strconv.ParseUint(r.values["index"], 10, 64)

			check(t, err)

			remaining, err := strconv.ParseUint(r.values["remaining"], 10, 64)

			check(t, err)

			options := crossOptions(r.values)

			store := options.StateStore.(*memoryStore)

			pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(algorithm, options, crossField(t, r.values, "seed"), index)

			check(t, err)

			same(t, store.state, state, context)

			same(t, export(t, pair.PublicKey, cryptopq.RAW), public, context)

			for _, encoding := range crossEncodings {
				encoded := crossField(t, r.values, "publicKey"+encoding.suffix)

				same(t, export(t, pair.PublicKey, encoding.format), encoded, context)

				imported, err := algorithm.ImportPublicKey(encoded, encoding.format)

				check(t, err)

				same(t, export(t, imported, cryptopq.RAW), public, context)
			}

			if pair.PrivateKey.RemainingSignatures() != remaining {
				t.Fatalf("%s: %d signatures remain, want %d", context, pair.PrivateKey.RemainingSignatures(), remaining)
			}

			signed, err := pair.PrivateKey.Sign(message)

			check(t, err)

			same(t, signed, signature, context)

			same(t, store.state, after, context)

			if !pair.PublicKey.Verify(signature, message) {
				t.Fatalf("%s: the signature does not verify", context)
			}

			// The key loaded from the first state signs at the same index, the same way.
			store = &memoryStore{state: state}

			loaded, err := algorithm.LoadPrivateKey(store, nil)

			check(t, err)

			same(t, export(t, loaded.PublicKey(), cryptopq.RAW), public, context)

			if loaded.RemainingSignatures() != remaining {
				t.Fatalf("%s: %d signatures remain after loading, want %d", context, loaded.RemainingSignatures(), remaining)
			}

			signed, err = loaded.Sign(message)

			check(t, err)

			same(t, signed, signature, context)

			same(t, store.state, after, context)

			if loaded.RemainingSignatures() != remaining-1 {
				t.Fatalf("%s: %d signatures remain after signing, want %d", context, loaded.RemainingSignatures(), remaining-1)
			}
		})
	}
}

// Each export is made again, and every cache loads, or fails to, as the reference decided; a key
// that loads signs as the reference did.
func TestCrossTreeCache(t *testing.T) {
	t.Parallel()

	for _, r := range records(t, "cross/treecache.txt", "treeCache") {
		t.Run(r.header["algorithm"]+"/"+r.values["name"], func(t *testing.T) {
			t.Parallel()

			algorithm, _ := crossStatefulAlgorithm(r.header["algorithm"])

			context := algorithm.Name() + ": " + r.values["name"]

			// An empty cache is a cache that fails, where nil would load without one.
			state, cache := crossField(t, r.values, "state"), append([]byte{}, crossField(t, r.values, "treeCache")...)

			if r.values["operation"] == "export" {
				index, err := strconv.ParseUint(r.values["index"], 10, 64)

				check(t, err)

				options := crossOptions(r.values)

				pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(algorithm, options, crossField(t, r.values, "seed"), index)

				check(t, err)

				if r.values["signed"] == "true" {
					sign(t, pair.PrivateKey, crossField(t, r.values, "message"))
				}

				exported, err := pair.PrivateKey.ExportTreeCache()

				check(t, err)

				same(t, exported, cache, context)

				same(t, options.StateStore.(*memoryStore).state, state, context)
			}

			key, err := algorithm.LoadPrivateKey(&memoryStore{state: state}, &cryptopq.StatefulLoadOptions{TreeCache: cache})

			if outcome := crossFinished(nil, err); outcome.result != r.values["result"] {
				t.Fatalf("%s: got %s, want %s", context, outcome.result, r.values["result"])
			}

			if err != nil {
				return
			}

			same(t, export(t, key.PublicKey(), cryptopq.RAW), crossField(t, r.values, "publicKey"), context)

			if remaining := strconv.FormatUint(key.RemainingSignatures(), 10); remaining != r.values["remaining"] {
				t.Fatalf("%s: %s signatures remain, want %s", context, remaining, r.values["remaining"])
			}

			if r.values["signature"] != "" {
				same(t, sign(t, key, crossField(t, r.values, "message")), crossField(t, r.values, "signature"), context)
			}
		})
	}
}

// The result of one error-table record: "ok", "true", "false" or an error code, with the output
// and the remaining signatures it produced.
type crossOutcome struct {
	result       string
	output       []byte
	remaining    uint64
	hasRemaining bool
}

func crossFinished(output []byte, err error) crossOutcome {
	if err == nil {
		return crossOutcome{result: "ok", output: output}
	}

	var failure *cryptopq.Error

	if errors.As(err, &failure) {
		return crossOutcome{result: string(failure.Code)}
	}

	var code cryptopq.ErrorCode

	if errors.As(err, &code) {
		return crossOutcome{result: string(code)}
	}

	return crossOutcome{result: "unexpected error " + err.Error()}
}

func crossAnswered(value bool) crossOutcome {
	return crossOutcome{result: strconv.FormatBool(value)}
}

func crossCounted(output []byte, remaining uint64, err error) crossOutcome {
	outcome := crossFinished(output, err)

	outcome.remaining, outcome.hasRemaining = remaining, err == nil

	return outcome
}

func crossExecute(t *testing.T, r record) crossOutcome {
	values := r.values

	data, key, message := crossField(t, values, "input"), crossField(t, values, "key"), crossField(t, values, "message")

	randomness, format := crossField(t, values, "randomness"), cryptopq.KeyFormat(values["format"])

	contextBytes, preHash := crossField(t, values, "context"), crossPreHash(values["preHash"])

	signOptions := &cryptopq.SignOptions{Context: contextBytes, Deterministic: true, PreHash: preHash}

	verifyOptions := &cryptopq.VerifyOptions{Context: contextBytes, PreHash: preHash}

	name, operation := r.header["algorithm"], values["operation"]

	if algorithm, ok := crossStatefulAlgorithm(name); ok {
		switch operation {
		case "importPublicKey":
			publicKey, err := algorithm.ImportPublicKey(data, format)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(publicKey.ExportKey(cryptopq.RAW))
		case "generate":
			index, err := strconv.ParseUint(values["index"], 10, 64)

			check(t, err)

			pair, err := cryptopq.Hazmat.GenerateStatefulKeyPair(algorithm, crossOptions(values), data, index)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossCounted(export(t, pair.PublicKey, cryptopq.RAW), pair.PrivateKey.RemainingSignatures(), nil)
		case "loadPrivateKey":
			privateKey, err := algorithm.LoadPrivateKey(&memoryStore{state: data}, nil)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossCounted(export(t, privateKey.PublicKey(), cryptopq.RAW), privateKey.RemainingSignatures(), nil)
		case "sign":
			privateKey, err := algorithm.LoadPrivateKey(&memoryStore{state: data}, nil)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(privateKey.Sign(message))
		case "verify":
			publicKey, err := algorithm.ImportPublicKey(key, cryptopq.RAW)

			check(t, err)

			return crossAnswered(publicKey.Verify(data, message))
		}
	} else if algorithm, ok := crossSignature(name); ok {
		switch operation {
		case "importPublicKey":
			publicKey, err := algorithm.ImportPublicKey(data, format)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(publicKey.ExportKey(cryptopq.RAW))
		case "importPrivateKey":
			privateKey, err := algorithm.ImportPrivateKey(data, format)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(privateKey.PublicKey().ExportKey(cryptopq.RAW))
		case "generate":
			pair, err := cryptopq.Hazmat.GenerateSignatureKeyPair(algorithm, data)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(pair.PublicKey.ExportKey(cryptopq.RAW))
		case "sign", "hazmatSign":
			privateKey, err := algorithm.ImportPrivateKey(key, cryptopq.RAW)

			if err != nil {
				return crossFinished(nil, err)
			}

			if operation == "sign" {
				return crossFinished(privateKey.Sign(message, signOptions))
			}

			return crossFinished(cryptopq.Hazmat.Sign(privateKey, message, randomness, signOptions))
		case "verify", "hazmatVerify":
			publicKey, err := algorithm.ImportPublicKey(key, cryptopq.RAW)

			check(t, err)

			if operation == "verify" {
				return crossAnswered(publicKey.Verify(data, message, verifyOptions))
			}

			return crossAnswered(cryptopq.Hazmat.Verify(publicKey, data, message, verifyOptions))
		}
	} else {
		algorithm := crossKem(t, name)

		switch operation {
		case "importPublicKey":
			publicKey, err := algorithm.ImportPublicKey(data, format)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(publicKey.ExportKey(cryptopq.RAW))
		case "importPrivateKey":
			privateKey, err := algorithm.ImportPrivateKey(data, format)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(privateKey.PublicKey().ExportKey(cryptopq.RAW))
		case "exportPublicKey", "exportPrivateKey", "generate":
			seed := key

			if operation == "generate" {
				seed = data
			}

			pair, err := cryptopq.Hazmat.GenerateKemKeyPair(algorithm, seed)

			switch {
			case err != nil:
				return crossFinished(nil, err)
			case operation == "exportPublicKey":
				return crossFinished(pair.PublicKey.ExportKey(format))
			case operation == "exportPrivateKey":
				return crossFinished(pair.PrivateKey.ExportKey(format))
			default:
				return crossFinished(pair.PublicKey.ExportKey(cryptopq.RAW))
			}
		case "encapsulate":
			publicKey, err := algorithm.ImportPublicKey(key, cryptopq.RAW)

			if err != nil {
				return crossFinished(nil, err)
			}

			encapsulation, err := cryptopq.Hazmat.Encapsulate(publicKey, randomness)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(append(encapsulation.SharedSecret, encapsulation.Ciphertext...), nil)
		case "decapsulate":
			privateKey, err := algorithm.ImportPrivateKey(key, cryptopq.RAW)

			if err != nil {
				return crossFinished(nil, err)
			}

			return crossFinished(privateKey.Decapsulate(data))
		}
	}

	t.Fatalf("unknown operation %s for %s", operation, name)

	return crossOutcome{}
}

// The records of each algorithm run in their own subtest; every disagreement is reported.
func TestCrossErrors(t *testing.T) {
	t.Parallel()

	groups := map[string][]record{}

	var names []string

	for _, r := range records(t, "cross/errors.txt", "result") {
		name := r.header["algorithm"]

		if groups[name] == nil {
			names = append(names, name)
		}

		groups[name] = append(groups[name], r)
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, r := range groups[name] {
				outcome := crossExecute(t, r)

				mismatched := outcome.result != r.values["result"]

				if output, ok := r.values["output"]; ok {
					mismatched = mismatched || !bytes.Equal(outcome.output, decode(t, output))
				}

				if remaining, ok := r.values["remaining"]; ok {
					mismatched = mismatched || !outcome.hasRemaining || strconv.FormatUint(outcome.remaining, 10) != remaining
				}

				if mismatched {
					t.Errorf("%s: got %s, want %s", r.values["name"], outcome.result, r.values["result"])
				}
			}
		})
	}
}
