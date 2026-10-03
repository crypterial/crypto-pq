package cryptopq

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

const stateVersion = 1

type StateStore interface {
	Read() ([]byte, error)
	Update(previous, next []byte) (bool, error)
}

type HssLevel struct {
	Lms, Ots string
}

type StatefulKeyGenOptions struct {
	Parameters string
	Levels     []HssLevel
	StateStore StateStore
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

// Seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS.
func (s statefulParameters) signer(seed []byte) statefulSigner {
	if p := s.xmss; p != nil {
		n := p.n

		return newXmssSigner(p, bytes.Clone(seed[:n]), bytes.Clone(seed[n:2*n]), bytes.Clone(seed[2*n:]))
	}

	return newHssSigner(s.levels, bytes.Clone(seed[:16]), bytes.Clone(seed[16:]))
}

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
//
//	HSS:     01 01 L {u32 lms u32 ots}*L I SEED u64(index) checksum
//	XMSS:    01 02 u32(oid) u64(index) SK_SEED SK_PRF PUB_SEED checksum (XMSS^MT: kind 03)
func (a StatefulSignatureAlgorithm) encode(parameters statefulParameters, seed []byte, index uint64) []byte {
	body := []byte{stateVersion, a.spec().kind}

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

	return a.create(parameters, seed, 0, options.StateStore)
}

// The seed becomes part of the key. As in the Python reference, the trees are built before the
// store is written.
func (a StatefulSignatureAlgorithm) create(parameters statefulParameters, seed []byte, index uint64, store StateStore) (*StatefulKeyPair, error) {
	signer := parameters.signer(seed)

	state := a.encode(parameters, seed, index)

	created, err := store.Update(nil, state)

	if err != nil || !created {
		signer.wipe()

		clear(seed)

		if err != nil {
			return nil, newError(STATE_PERSIST_FAILED, "the state store failed to save the new key")
		}

		return nil, newError(STATE_CONFLICT, "the state store already holds a key")
	}

	privateKey := a.newPrivateKey(parameters, seed, signer, store, index)

	return &StatefulKeyPair{privateKey.PublicKey(), privateKey}, nil
}

func (a StatefulSignatureAlgorithm) LoadPrivateKey(store StateStore) (*StatefulPrivateKey, error) {
	if store == nil {
		return nil, invalidOption("a StateStore is required")
	}

	state, err := store.Read()

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

	return a.newPrivateKey(parameters, seed, parameters.signer(seed), store, index), nil
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

type StatefulPrivateKey struct {
	algorithm  StatefulSignatureAlgorithm
	parameters statefulParameters
	seed       []byte
	signer     statefulSigner
	store      StateStore
	mutex      sync.Mutex
	index      uint64
}

type statefulSecrets struct {
	seed   []byte
	signer statefulSigner
}

func (a StatefulSignatureAlgorithm) newPrivateKey(parameters statefulParameters, seed []byte, signer statefulSigner, store StateStore, index uint64) *StatefulPrivateKey {
	key := &StatefulPrivateKey{algorithm: a, parameters: parameters, seed: seed, signer: signer, store: store, index: index}

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
	return &StatefulPublicKey{algorithm: k.algorithm, key: k.signer.publicKey()}
}

func (k *StatefulPrivateKey) RemainingSignatures() uint64 {
	k.mutex.Lock()

	defer k.mutex.Unlock()

	return k.signer.capacity() - min(k.index, k.signer.capacity())
}

// The next index is written to the store before the signature exists, so a crash or a failed
// write can waste an index but never use one twice. The state the store must hold is the
// encoding of the current index, which is exactly what was loaded or last written.
func (k *StatefulPrivateKey) Sign(message []byte) ([]byte, error) {
	defer runtime.KeepAlive(k)

	k.mutex.Lock()

	defer k.mutex.Unlock()

	index := k.index

	if index >= k.signer.capacity() {
		return nil, newError(KEY_EXHAUSTED, "every one-time key has been used")
	}

	previous := k.algorithm.encode(k.parameters, k.seed, index)

	updated, err := k.store.Update(previous, k.algorithm.encode(k.parameters, k.seed, index+1))

	if err != nil {
		return nil, newError(STATE_PERSIST_FAILED, "the state store failed to save the key state")
	}

	if !updated {
		return nil, newError(STATE_CONFLICT, "the stored key state changed; load the key again")
	}

	k.index = index + 1

	return k.signer.sign(index, message), nil
}

// Formatting shows only the algorithm, never key material.
func (k *StatefulPrivateKey) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "<StatefulPrivateKey %s>", k.algorithm.Name())
}
