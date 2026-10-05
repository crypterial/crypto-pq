package cryptopq

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
)

const stateVersion = 1

// Read returns the stored state, or nil when there is none, in a slice that the caller then
// owns. Update is a compare-and-swap: it replaces the stored state with next only if the store
// still holds previous (nil when empty), and reports whether it did. States hold the secret seed,
// so a key wipes what Read returned and both arguments of Update once they have served: a store
// copies whatever it keeps.
type StateStore interface {
	Read() ([]byte, error)
	Update(previous, next []byte) (bool, error)
}

type HssLevel struct {
	Lms, Ots string
}

// Reserve is how many indices one write to the store claims: the key then signs that many times
// per write, and indices claimed but unused when the key is dropped are skipped, never reused.
// Zero means 1. StatefulLoadOptions.Reserve is the same option for a loaded key.
type StatefulKeyGenOptions struct {
	Parameters string
	Levels     []HssLevel
	StateStore StateStore
	Reserve    uint64
}

type StatefulLoadOptions struct {
	Reserve uint64
}

type StatefulSignatureAlgorithm uint8

const (
	HSS_LMS StatefulSignatureAlgorithm = iota + 1
	XMSS
	XMSS_MT
)

type statefulSpec struct {
	name string
	kind byte
	oid  []byte
	sets []xmssParams
}

var statefulSpecs = [...]statefulSpec{
	HSS_LMS: {name: "HSS/LMS", kind: 1, oid: objectIdentifier(1, 2, 840, 113549, 1, 9, 16, 3, 17)},
	XMSS:    {name: "XMSS", kind: 2, oid: objectIdentifier(1, 3, 6, 1, 5, 5, 7, 6, 34), sets: xmssSets},
	XMSS_MT: {name: "XMSS^MT", kind: 3, oid: objectIdentifier(1, 3, 6, 1, 5, 5, 7, 6, 35), sets: xmssMtSets},
}

func (a StatefulSignatureAlgorithm) spec() *statefulSpec {
	if a == 0 || int(a) >= len(statefulSpecs) {
		panic("cryptopq: invalid StatefulSignatureAlgorithm")
	}

	return &statefulSpecs[a]
}

func (a StatefulSignatureAlgorithm) Name() string {
	return a.spec().name
}

func (a StatefulSignatureAlgorithm) String() string {
	return a.Name()
}

// HSS levels, or one XMSS or XMSS^MT parameter set.
type statefulParameters struct {
	levels []hssLevel
	xmss   *xmssParams
}

type statefulSigner interface {
	sign(index uint64, message []byte) []byte
	publicKey() []byte
	capacity() uint64
	wipe()
}

func hssParameters(levels []HssLevel) ([]hssLevel, error) {
	parsed := make([]hssLevel, len(levels))

	for i, level := range levels {
		lms, ots := lmsByName(level.Lms), lmotsByName(level.Ots)

		if lms == nil || ots == nil {
			return nil, invalidOption("unknown LMS or LM-OTS type " + level.Lms + ", " + level.Ots)
		}

		parsed[i] = hssLevel{lms, ots}
	}

	if len(parsed) < 1 || len(parsed) > 8 {
		return nil, invalidOption("HSS needs between 1 and 8 levels")
	}

	height := 0

	for _, level := range parsed {
		if level.lms.shake != parsed[0].lms.shake || level.ots.shake != parsed[0].lms.shake || level.lms.m != parsed[0].lms.m || level.ots.n != parsed[0].lms.m {
			return nil, invalidOption("every level must use the same hash function and output size")
		}

		height += level.lms.h
	}

	if height > 60 {
		return nil, invalidOption("the total tree height must not exceed 60")
	}

	return parsed, nil
}

func (a StatefulSignatureAlgorithm) parameters(options *StatefulKeyGenOptions) (statefulParameters, error) {
	spec := a.spec()

	if options == nil {
		return statefulParameters{}, invalidOption("StatefulKeyGenOptions are required")
	}

	if spec.sets == nil {
		if options.Parameters != "" {
			return statefulParameters{}, invalidOption("HSS/LMS takes Levels, a list of LMS and LM-OTS type names")
		}

		levels, err := hssParameters(options.Levels)

		return statefulParameters{levels: levels}, err
	}

	p := xmssByName(spec.sets, options.Parameters)

	if p == nil || len(options.Levels) > 0 {
		names := make([]string, len(spec.sets))

		for i := range spec.sets {
			names[i] = spec.sets[i].name
		}

		return statefulParameters{}, invalidOption("Parameters must be one of " + strings.Join(names, ", "))
	}

	return statefulParameters{xmss: p}, nil
}

func (s statefulParameters) seedSize() int {
	if s.xmss != nil {
		return 3 * s.xmss.n
	}

	return 16 + s.levels[0].lms.m
}

func (s statefulParameters) capacity() uint64 {
	if s.xmss != nil {
		return 1 << s.xmss.h
	}

	height := 0

	for _, level := range s.levels {
		height += level.lms.h
	}

	return 1 << height
}

// Seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS. Building the
// trees works on the seed, so it runs under PSTATE.DIT.
func (s statefulParameters) signer(seed []byte) statefulSigner {
	defer ditLeave(ditEnter())

	if p := s.xmss; p != nil {
		n := p.n

		return newXmssSigner(p, bytes.Clone(seed[:n]), bytes.Clone(seed[n:2*n]), bytes.Clone(seed[2*n:]))
	}

	return newHssSigner(s.levels, bytes.Clone(seed[:16]), bytes.Clone(seed[16:]))
}

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused. The buffer
// has room for either layout from the start, so append never leaves a partial copy of the seed
// behind.
//
//	HSS:     01 01 L {u32 lms u32 ots}*L I SEED u64(index) checksum
//	XMSS:    01 02 u32(oid) u64(index) SK_SEED SK_PRF PUB_SEED checksum (XMSS^MT: kind 03)
//
// The checksum covers the seeds, so encoding and decoding run under PSTATE.DIT.
func (a StatefulSignatureAlgorithm) encode(parameters statefulParameters, seed []byte, index uint64) []byte {
	defer ditLeave(ditEnter())

	body := make([]byte, 0, 2+1+8*len(parameters.levels)+4+len(seed)+8+16)

	body = append(body, stateVersion, a.spec().kind)

	if p := parameters.xmss; p != nil {
		body = binary.BigEndian.AppendUint32(body, p.oid)

		body = binary.BigEndian.AppendUint64(body, index)

		body = append(body, seed...)
	} else {
		body = append(body, byte(len(parameters.levels)))

		for _, level := range parameters.levels {
			body = binary.BigEndian.AppendUint32(body, level.lms.code)

			body = binary.BigEndian.AppendUint32(body, level.ots.code)
		}

		body = append(body, seed...)

		body = binary.BigEndian.AppendUint64(body, index)
	}

	var checksum [32]byte

	sha256Finish(iv256, 0, body, checksum[:])

	return append(body, checksum[:16]...)
}

func (a StatefulSignatureAlgorithm) decode(state []byte) (statefulParameters, []byte, uint64, error) {
	defer ditLeave(ditEnter())

	var none statefulParameters

	if len(state) < 18 {
		return none, nil, 0, mismatch("the state store holds no valid key")
	}

	body, checksum := state[:len(state)-16], state[len(state)-16:]

	var expected [32]byte

	sha256Finish(iv256, 0, body, expected[:])

	if !equal(expected[:16], checksum) || body[0] != stateVersion {
		return none, nil, 0, mismatch("the stored key state is damaged or unsupported")
	}

	if body[1] != a.spec().kind {
		return none, nil, 0, newError(ALGORITHM_MISMATCH, "the stored key belongs to another algorithm")
	}

	body = body[2:]

	if spec := a.spec(); spec.sets != nil {
		var p *xmssParams

		if len(body) >= 4 {
			p = xmssByOid(spec.sets, binary.BigEndian.Uint32(body))
		}

		if p == nil || len(body) != 12+3*p.n {
			return none, nil, 0, mismatch("the stored key has invalid parameters")
		}

		return statefulParameters{xmss: p}, bytes.Clone(body[12:]), binary.BigEndian.Uint64(body[4:]), nil
	}

	if len(body) < 1 || len(body) < 1+8*int(body[0]) {
		return none, nil, 0, mismatch("the stored key has invalid parameters")
	}

	levels := make([]HssLevel, body[0])

	for i := range levels {
		lms := lmsByCode(binary.BigEndian.Uint32(body[1+8*i:]))

		ots := lmotsByCode(binary.BigEndian.Uint32(body[5+8*i:]))

		if lms == nil || ots == nil {
			return none, nil, 0, mismatch("the stored key has invalid parameters")
		}

		levels[i] = HssLevel{lms.name, ots.name}
	}

	parsed, err := hssParameters(levels)

	if err != nil {
		return none, nil, 0, mismatch("the stored key has invalid parameters")
	}

	parameters := statefulParameters{levels: parsed}

	rest := body[1+8*len(levels):]

	size := parameters.seedSize()

	if len(rest) != size+8 {
		return none, nil, 0, mismatch("the stored key has the wrong length")
	}

	return parameters, bytes.Clone(rest[:size]), binary.BigEndian.Uint64(rest[size:]), nil
}

type StatefulKeyPair struct {
	PublicKey  *StatefulPublicKey
	PrivateKey *StatefulPrivateKey
}

func (a StatefulSignatureAlgorithm) GenerateKeyPair(options *StatefulKeyGenOptions) (*StatefulKeyPair, error) {
	parameters, err := a.parameters(options)

	if err != nil {
		return nil, err
	}

	if options.StateStore == nil {
		return nil, invalidOption("a StateStore is required")
	}

	seed, err := randomBytes(parameters.seedSize())

	if err != nil {
		return nil, err
	}

	return a.create(parameters, seed, 0, options.StateStore, options.Reserve)
}

// Replaces previous with next in the store, then wipes both.
func writeState(store StateStore, previous, next []byte) (bool, error) {
	defer clear(previous)

	defer clear(next)

	return store.Update(previous, next)
}

// The seed becomes part of the key. As in the Python reference, the trees are built before the
// store is written. The new state holds index itself: the first signature claims the reserve.
func (a StatefulSignatureAlgorithm) create(parameters statefulParameters, seed []byte, index uint64, store StateStore, reserve uint64) (*StatefulKeyPair, error) {
	signer := parameters.signer(seed)

	created, err := writeState(store, nil, a.encode(parameters, seed, index))

	if err != nil || !created {
		signer.wipe()

		clear(seed)

		if err != nil {
			return nil, newError(STATE_PERSIST_FAILED, "the state store failed to save the new key")
		}

		return nil, newError(STATE_CONFLICT, "the state store already holds a key")
	}

	privateKey := a.newPrivateKey(parameters, seed, signer, store, index, reserve)

	return &StatefulKeyPair{privateKey.PublicKey(), privateKey}, nil
}

// The key starts at the stored index, so indices that an earlier key reserved but did not use
// are skipped.
func (a StatefulSignatureAlgorithm) LoadPrivateKey(store StateStore, options *StatefulLoadOptions) (*StatefulPrivateKey, error) {
	if store == nil {
		return nil, invalidOption("a StateStore is required")
	}

	state, err := store.Read()

	defer clear(state)

	if err != nil {
		return nil, newError(STATE_PERSIST_FAILED, "the state store failed to read the key state")
	}

	parameters, seed, index, err := a.decode(state)

	if err != nil {
		return nil, err
	}

	if index > parameters.capacity() {
		clear(seed)

		return nil, mismatch("the stored index is beyond the key's capacity")
	}

	var reserve uint64

	if options != nil {
		reserve = options.Reserve
	}

	return a.newPrivateKey(parameters, seed, parameters.signer(seed), store, index, reserve), nil
}

func (s *statefulSpec) validPublicKey(key []byte) bool {
	if s.sets == nil {
		return hssCheckPublicKey(key)
	}

	if len(key) < 4 {
		return false
	}

	p := xmssByOid(s.sets, binary.BigEndian.Uint32(key))

	return p != nil && len(key) == p.publicKeySize()
}

func (a StatefulSignatureAlgorithm) ImportPublicKey(data []byte, format KeyFormat) (*StatefulPublicKey, error) {
	spec := a.spec()

	key, err := importPublic(format, data, spec.oid, -1)

	if err != nil {
		return nil, err
	}

	if !spec.validPublicKey(key) {
		return nil, newError(INVALID_PUBLIC_KEY, "the public key is malformed")
	}

	return &StatefulPublicKey{algorithm: a, key: key}, nil
}

type StatefulPublicKey struct {
	algorithm StatefulSignatureAlgorithm
	key       []byte
}

func (k *StatefulPublicKey) Algorithm() StatefulSignatureAlgorithm {
	return k.algorithm
}

func (k *StatefulPublicKey) Verify(signature, message []byte) bool {
	spec := k.algorithm.spec()

	if spec.sets == nil {
		return hssVerify(k.key, message, signature)
	}

	return xmssVerify(xmssByOid(spec.sets, binary.BigEndian.Uint32(k.key)), k.key, message, signature)
}

func (k *StatefulPublicKey) ExportKey(format KeyFormat) ([]byte, error) {
	return exportPublic(format, k.algorithm.spec().oid, k.key)
}

func (k *StatefulPublicKey) Equal(other *StatefulPublicKey) bool {
	if k == nil || other == nil {
		return k == other
	}

	return k.algorithm == other.algorithm && bytes.Equal(k.key, other.key)
}

func (k *StatefulPublicKey) String() string {
	return "<StatefulPublicKey " + k.algorithm.Name() + ">"
}

// index is the next index to sign with and reserved the one the store holds, never below it.
// signing is set while a Sign call runs, which alone reads and writes reserved and the signer's
// caches; index is atomic so that RemainingSignatures needs no lock.
type StatefulPrivateKey struct {
	algorithm  StatefulSignatureAlgorithm
	parameters statefulParameters
	seed       []byte
	signer     statefulSigner
	public     []byte
	store      StateStore
	reserve    uint64
	reserved   uint64
	index      atomic.Uint64
	signing    atomic.Bool
}

type statefulSecrets struct {
	seed   []byte
	signer statefulSigner
}

func (a StatefulSignatureAlgorithm) newPrivateKey(parameters statefulParameters, seed []byte, signer statefulSigner, store StateStore, index, reserve uint64) *StatefulPrivateKey {
	key := &StatefulPrivateKey{algorithm: a, parameters: parameters, seed: seed, signer: signer, public: signer.publicKey(), store: store, reserve: max(reserve, 1), reserved: index}

	key.index.Store(index)

	runtime.AddCleanup(key, func(secrets statefulSecrets) {
		clear(secrets.seed)

		secrets.signer.wipe()
	}, statefulSecrets{seed, signer})

	return key
}

func (k *StatefulPrivateKey) Algorithm() StatefulSignatureAlgorithm {
	return k.algorithm
}

func (k *StatefulPrivateKey) PublicKey() *StatefulPublicKey {
	return &StatefulPublicKey{algorithm: k.algorithm, key: k.public}
}

func (k *StatefulPrivateKey) RemainingSignatures() uint64 {
	capacity := k.signer.capacity()

	return capacity - min(k.index.Load(), capacity)
}

// A call made while another Sign on the same key runs, from another goroutine or from inside the
// store's Update, fails at once with STATE_CONFLICT: waiting would deadlock the second case and
// stall callers behind the rebuild of a large tree.
//
// Before an index is used, the store holds a later one, so a crash or a failed write can waste
// indices but never use one twice. When the claimed indices run out, one write replaces the
// stored state, the encoding of reserved, with one that claims up to Reserve more.
func (k *StatefulPrivateKey) Sign(message []byte) ([]byte, error) {
	defer runtime.KeepAlive(k)

	if !k.signing.CompareAndSwap(false, true) {
		return nil, newError(STATE_CONFLICT, "the key is signing in another call")
	}

	defer k.signing.Store(false)

	index, capacity := k.index.Load(), k.signer.capacity()

	if index >= capacity {
		return nil, newError(KEY_EXHAUSTED, "every one-time key has been used")
	}

	if index == k.reserved {
		reserved := index + min(k.reserve, capacity-index)

		updated, err := writeState(k.store, k.algorithm.encode(k.parameters, k.seed, index), k.algorithm.encode(k.parameters, k.seed, reserved))

		if err != nil {
			return nil, newError(STATE_PERSIST_FAILED, "the state store failed to save the key state")
		}

		if !updated {
			return nil, newError(STATE_CONFLICT, "the stored key state changed; load the key again")
		}

		k.reserved = reserved
	}

	k.index.Store(index + 1)

	return k.signAt(index, message), nil
}

// The signature itself runs under PSTATE.DIT, which the calls to the store, user code, stay out of.
func (k *StatefulPrivateKey) signAt(index uint64, message []byte) []byte {
	defer ditLeave(ditEnter())

	return k.signer.sign(index, message)
}

// Formatting shows only the algorithm, never key material.
func (k *StatefulPrivateKey) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "<StatefulPrivateKey %s>", k.algorithm.Name())
}
