# Changelog

All notable changes to the `crypto-pq` crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and its MAJOR.MINOR is the version of
the [crypto-pq specification](spec/00-contents.md) that it implements
([Section 20.1](spec/20-versioning.md)).

## [2.0.0] - 2026-11-20

Implements specification 2.0. It is not compatible with 1.x: it removes the WebAssembly and 32-bit
targets ([decision D-105](spec/decisions.md#decision-d-105-revised-by-d-120)) and needs Rust 1.89
or later.

### Added

- `MacAlgorithm::key`, which returns a `MacKey`, and `MacKey::create`, which returns a `Mac` in its
  state right after `MacAlgorithm::create` under the same key and options, for every MAC algorithm
  ([decision D-77](spec/decisions.md#decision-d-77)). The tags of many messages under one key pay
  for the key setup once: HMAC and KMAC process no key block again. A `MacKey` may be used from
  several threads at once, does not implement `Clone`, and wipes its keyed state when dropped.
  `Mac` is unchanged.
- `KECCAK_256`, in the `sha3` feature ([decision D-87](spec/decisions.md#decision-d-87)): Keccak-256,
  as Ethereum uses it, on the code and the kernels of SHA-3. Its padding differs from that of
  `SHA3_256`, so the two give different digests. It is refused as a pre-hash.
- The Cargo feature `stack-zeros`, not a default feature ([decision
  D-118](spec/decisions.md#decision-d-118), [decision D-119](spec/decisions.md#decision-d-119)):
  with it a MAC and a KDF in one call, the key setup of an incremental MAC or of a MAC key and the
  end of an incremental MAC end by writing zeros over the stack under them at opt-level 3 too, as
  the operations on private keys always do. At the opt-levels 1, 2, s and z they end with 16 KiB of
  zeros in every build, with the feature and without it, and at opt-level 0 with none. Without the
  feature, at opt-level 3, they wipe the buffers that they name, as the standards ask, and what the
  compiler saved of a key or of a keyed state in a stack frame of a MAC or a KDF stays until later
  calls write over it: a BLAKE2b MAC leaves the chaining value after its key block, and after an
  empty message its key; a BLAKE2s MAC of an empty message 8 to 20 bytes of its key; HMAC-SHA-512
  the state after its outer key block on x86-64 and on ARM64 cores without the SHA-512
  instructions; HKDF-SHA-512 its output with fat LTO on ARM64; KMAC up to 120 bytes of its final
  state and 96 of its state after the key; BLAKE3-KDF 12 bytes of its input keying material on
  ARM64; a keyed BLAKE3 of more than a chunk 12 to 20 bytes of its key on ARM64, and with debug
  assertions the state of a compression or its whole key; and an incremental MAC its keyed state in
  frames of the library. With the feature the zeros at opt-level 3 are 64 bytes to 12 KiB, by the
  hash, by the lengths of the key and of the tag for HMAC, and for BLAKE3 by the length of the data
  and by the code that ran. Their sizes are the depths measured in a list of builds with a tenth
  more: eight builds at opt-level 3 on x86-64 under seven processor models, five on ARM64 under
  three, first and later calls, over grids of lengths; a build setting outside that list can take
  more, as fat LTO, one codegen unit and x86-64-v3 did, alone and together, before they were in
  it. The test of the dead stack covers these calls at opt-level 3 with the feature, in the release
  build and in the test profile. With the feature a MAC in one call takes 1 to 23 ns more on the
  server processors measured (EPYC 7763, 9V45 and 9V74, Xeon Platinum 8573C, Xeon 6975P-C,
  Neoverse N2), up to 15 percent for HMAC-SHA-256 of 64 bytes, a keyed BLAKE3 of 16 KiB 38 to 96 ns
  more, a derivation of 32 bytes 20 to 86 ns more with HKDF and a MAC made with `create` 44 to 92
  ns more, measured with the sizes of decision D-117; the sizes that have grown since were not
  timed. Without it the machine code of a MAC and of a KDF in one call at opt-level 3 is what it
  was before these zeros. A `Mac` and a `MacKey` are returned by value: the compiler leaves a copy
  of their keyed state in the caller's own frame, which the library cannot wipe and the
  documentation states. Outputs are unchanged.

### Changed

- BLAKE2b, BLAKE2s and BLAKE3 on x86-64 CPUs with AVX-512F and AVX-512VL: the kernels for one
  message take their rotations by 63 (BLAKE2b), 12 and 7 (BLAKE2s) and all four (BLAKE3) as one
  VPRORD or VPRORQ, on 128-bit and 256-bit registers, in inline assembly within the AVX2 code. On
  AMD family 1Ah (Zen 5) the kernels for one message give way to the portable code, which takes less
  time there; on other AMD
  processors with AVX-512 (Zen 4) BLAKE2 keeps its AVX2 code. Outputs are unchanged.
- BLAKE3 on x86-64 processors of AMD families 19h and 1Ah (Zen 4, Zen 5) and on Intel's Ice Lake
  Xeon, Sapphire Rapids, Emerald Rapids and Granite Rapids: inputs of sixteen chunks or more hash
  sixteen chunks or parents at a time, and extended outputs compute sixteen blocks at a time, in
  512-bit registers
  ([decision D-44](spec/decisions.md#decision-d-44)). Other processors keep 256-bit registers. The
  AVX-512VL kernel for one message swaps the halves of its d row with the integer VPSHUFD. On ARM64
  the NEON kernels rotate by 12 and 7 with USHR and SLI. Outputs are unchanged.
- BLAKE3 on those processors: the five to eight inputs left after the groups of sixteen hash on
  eight lanes in 256-bit registers with AVX-512VL, in place of the AVX2 kernels, the sixteen-lane
  kernel loads each block in 256-bit halves, and an extended output computes all of its groups of
  sixteen blocks in one loop. With the AVX-512VL kernels for one message, the blocks of one chunk,
  such as those of a 1 KiB hash, and single blocks run the row form for one input, in which each
  rotation is one VPRORD. Outputs are unchanged.
- BLAKE3 on x86-64: two to four inputs, parents or blocks of an extended output run in the row form,
  each 128-bit lane holding one row of one input ([decision D-84](spec/decisions.md#decision-d-84)):
  with AVX-512 on the processors above, on 512-bit registers for three or four and 256-bit registers
  for two, and with AVX2 on 256-bit registers, `hash_many` with two inputs to each of two sets of
  state registers and the message vectors of the round in registers, unless the core runs a 256-bit
  instruction as two operations. The chaining values of a
  tree of up to the width of the kernels go straight into the block of the top parent, with no copy
  between levels, and five to eight blocks of an extended output run on eight lanes. An extended
  output from an input of at most one block skips the chunk buffer. Outputs are unchanged.
- BLAKE3 on x86-64 with AVX2 or SSE4.1: the groups of an extended output on eight or four lanes
  broadcast the message and the chaining value once for all groups, with one scratch state. Outputs
  are unchanged.
- SHA-384 and SHA-512 on ARM64 with the SHA-512 instructions: the loop over the blocks of an update
  takes the same one-loop form of the rounds as the loop over the blocks of a one-shot input, which
  took less time per block on Neoverse N2. Outputs are unchanged.
- BLAKE2b on ARM64 cores that run it on the general registers: the compression reads the IV from
  memory, not from constants in its code. Outputs are unchanged.
- The MAC entry ([decision D-90](spec/decisions.md#decision-d-90)): `MacAlgorithm::digest_into` is
  inlined into the caller and reaches BLAKE2 and BLAKE3 by calls of their own functions. Keyed
  BLAKE3 of at most a block takes up to 3% less time on x86-64. Outputs are unchanged.
- SHA-384 and SHA-512 on x86-64 with AVX-512 ([decision D-93](spec/decisions.md#decision-d-93)):
  the message schedule computes its sigma functions with AVX-512VL. SHA-384, SHA-512, HMAC and HKDF
  take 3.5% to 6.9% less time on Ice Lake, Emerald Rapids, Granite Rapids, Zen 4 and Zen 5, as a
  geometric mean, and SLH-DSA over SHA2 at the 192-bit and 256-bit levels up to 2.7% less.
  Processors without AVX-512 run the AVX2 form as before, and the machine code of other targets is
  unchanged. Outputs are unchanged.
- BLAKE2b on x86-64 with AVX2 ([decision D-98](spec/decisions.md#decision-d-98)): in a digest or
  MAC in one call, the vector that holds the last bytes of a key or of a final block whose length
  is not a multiple of 16 is written with one 32-byte store, from which the loads of the rounds
  take their bytes. Over the rows whose input ends in a partial 16-byte piece, the time drops by
  2.1% to 8.2% as a geometric mean on Ice Lake, Emerald Rapids, Granite Rapids, Zen 3 and Zen 4,
  while seven rows on Zen 3 and Zen 4 take 0.6% to 1.3% more, which the decision lists. The machine
  code of other targets is unchanged. Outputs are unchanged.
- BLAKE2b on ARM64 on Neoverse N2 ([decision D-101](spec/decisions.md#decision-d-101)): a call
  that compresses two or more blocks, as a digest of more than 128 bytes or a MAC of a message of
  at least one byte does, runs them in one loop of assembly, out of line, with the state and words
  0 to 8 of the block in registers. On Neoverse N2, a digest of 255 bytes takes 0.7% less time, one
  of 1 KiB 2.5% less and one of 16 KiB 2.4% less, and MACs of 1 byte to 16 KiB 0.9% to 2.7% less.
  A call of one block, BLAKE2s and other cores run the code before. The machine code of other
  targets is unchanged. Outputs are unchanged.
- BLAKE3 on ARM64 on Neoverse N2 ([decision D-102](spec/decisions.md#decision-d-102)): a hash, a
  keyed hash or `derive_key` of at most 64 bytes with an output of at most 32 bytes reads the
  message, and a key given in bytes, straight into the registers of its one compression and writes
  the output words straight into the caller's buffer, with no copy of the block, the key or the
  output on the stack. On Neoverse N2 such a hash takes 1.3% to 8.3% less time, a keyed hash 6.1%
  to 12.5% less and `derive_key` of 32 bytes 2.1% less. Other cores and the machine code of other
  targets are unchanged. Outputs are unchanged.
- SHA-224 and SHA-256 on x86-64 CPUs with the SHA extensions
  ([decision D-103](spec/decisions.md#decision-d-103)): a `Hasher` and an HMAC-SHA-224 or
  HMAC-SHA-256 `Mac` keep their state in the order of the SHA256RNDS2 registers from the first block
  they compress to the digest, so an update no longer shuffles the state into that order and back,
  and an update whose bytes leave the block unfilled is buffered with no stack frame, in line below
  32 bytes. Without AVX, the loop of the new kernel is inline assembly with the instructions of the
  kernel it replaces, in their order, from a 64-byte boundary. On Zen 3, Zen 4, Zen 5, Ice Lake,
  Emerald Rapids and Granite Rapids, 1 KiB hashed in updates of 1 byte takes 10% to 35% less time,
  in updates of 8 bytes 11% to 15% less, of 16 bytes 4% to 18% less and of 32 or 64 bytes 2% to 6%
  less, an update of 16, 64 or 129 bytes and the digest up to 4.6% less, and HMAC-SHA-256 of 64
  bytes under a key from `MacAlgorithm::key` up to 2.4% less, with longer messages unchanged. On Zen
  3, an update of 63 bytes and the digest take the same time or, in about a quarter of the processes
  measured, 2% more, depending on where its data lies in memory. One-shot digests, the SHA-256 of
  ML-DSA, SLH-DSA, LMS and XMSS, CPUs without the SHA extensions and other targets are unchanged.
  Outputs are unchanged.
- SHA-384, SHA-512, SHA-512/224 and SHA-512/256, and SHA-224 and SHA-256 on the targets other than
  x86-64, where D-103 did this outside SGX and the portable build ([decision
  D-104](spec/decisions.md#decision-d-104)): the update of a `Hasher` and of an HMAC `Mac` is a
  function of its own that buffers bytes which leave the block unfilled with no stack frame, in line
  below 32 bytes and on ARM64 at every length, passes whole blocks into an empty buffer straight to
  the kernel, and fills a block without the tests that the paths before it decide. On Neoverse N2, 1
  KiB hashed in updates of 1 byte takes 38% less time with SHA-256 and 31% less with SHA-512, in
  updates of 8 bytes 31% and 21% less, of 16 bytes 10% and 8% less and of 32 bytes 13% and 4% less.
  On Zen 3, Zen 4, Zen 5, Ice Lake and Emerald Rapids, SHA-512 in updates of 1 byte takes 10% to 39%
  less time, of 8 bytes 5% to 17% less, of 16 bytes 7% to 9% less and of 32 or 64 bytes up to 3%
  less. On Zen 3, a SHA-512 of 16 or 128 bytes in one update and the digest takes 0.2% to 0.3% more
  time. One-shot digests and the SHA-2 of ML-DSA, SLH-DSA, LMS, XMSS and HKDF are unchanged. Outputs
  are unchanged.
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 on ARM64, and HMAC-SHA-224 and
  HMAC-SHA-256 under a key from `MacAlgorithm::key` on x86-64 with the SHA extensions
  ([decision D-106](spec/decisions.md#decision-d-106)): the digest, and the tag of a MAC from a
  `MacKey`, are stored from the registers of the kernel that runs the padding blocks, with no copy
  of the state on the stack, and on ARM64 the compressions of a stream reach their kernel with no
  stack frame. On x86-64 without AVX at compile time, the whole blocks of a kept state and of such a
  MAC run the loop of D-103 with the first round of a block reading the state from the register of
  the rounds; the one-shot digests are unchanged. On Neoverse N2, a SHA-256 of 64 bytes takes 21%
  less time, one of no data 12% less, SHA-224 up to 22% less, the other digests of at most 64 bytes
  3% to 4% less, updates up to 9% less and an HMAC of 64 bytes under a key set up once 7% to 14%
  less. On x86-64, HMAC-SHA-256 of 64 bytes under a key set up once takes 3% to 9% less time, and
  23% less on Ice Lake. Outputs are unchanged.
- BLAKE2s on AMD processors with AVX-512 that run the vector kernels for one message (Zen 4)
  ([decision D-107](spec/decisions.md#decision-d-107)): each rotation that follows an XOR is split
  into a VPRORD of the earlier value, two shifts and one three-input XOR, which takes one cycle off
  each half step of the rounds. On Zen 4, BLAKE2s digests take 2% to 9% less time and its MACs 2% to
  5% less. BLAKE2b and other processors run the code before. Outputs are unchanged.
- BLAKE3 on x86-64 ([decision D-108](spec/decisions.md#decision-d-108)): a hash, keyed hash or
  `derive_key` of at most 64 bytes with at most 32 bytes of output reads the message and the key
  straight into the registers of its kernel and stores the output from them, with no buffer on the
  stack and one read of the feature word. On Zen 4 the chain over a chunk takes the split rotations
  of D-107, and on Zen 5 and processors without AVX2 and SSE4.1 the portable code of a keyed hash
  takes the form of D-102. Off x86-64, `HashAlgorithm::digest_into` and `XofAlgorithm::digest_into`
  reach BLAKE3 with no dispatcher frame. A hash or keyed hash of at most 64 bytes takes up to 3.6%
  less time on Zen 3, Zen 4, Emerald Rapids and Granite Rapids and up to 9% less on Ice Lake, on Zen
  5 a keyed hash of at most 63 bytes 3.1% to 7.1% less and a `derive_key` of 32 bytes 2.9% to 3.2%
  less, a hash of 1 KiB 2% less on Zen 4, and on Neoverse N2 a hash of at most 64 bytes 1.6% to 3.1%
  less. Outputs are unchanged.
- Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128
  ([decision D-109](spec/decisions.md#decision-d-109)): off x86-64, `HashAlgorithm::digest_into` and
  `XofAlgorithm::digest_into` reach Ascon with no dispatcher frame and `XofAlgorithm::configure` is
  inline; on x86-64 with AVX2 the customization string of Ascon-CXOF128 is absorbed with the state
  in registers. On Neoverse N2, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 take up to 3.4% less
  time, and on x86-64 Ascon-CXOF128 up to 2.3% less. Outputs are unchanged.
- Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 on x86-64 with BMI1 and BMI2
  ([decision D-113](spec/decisions.md#decision-d-113)): each round of the permutation is one block
  of inline assembly, with the 24 copies between registers a permutation that two-operand
  instructions need, and the one-shot digest writes a partial output word from its register. On
  Zen 5, Emerald Rapids and Granite Rapids they take 4.1% to 6.7% less time, and on Zen 3 and Zen 4
  up to 8.3% and 7.3% less. Outputs are unchanged.
- One-shot SHA3-224, SHA3-256, SHA3-384, SHA3-512 and Keccak-256 digests
  ([decision D-110](spec/decisions.md#decision-d-110)): on x86-64, the dispatcher of
  `HashAlgorithm::digest_into` reaches the kernel of the rate, the scalar one or the one-state
  AVX-512VL one, through a one-shot digest with one read of the feature word and no frame of its
  own, and an output of at most the rate is copied from the state without the loop of the squeeze.
  Off x86-64, `HashAlgorithm::digest_into` and `XofAlgorithm::digest_into` are always inline and
  reach SHA-3, Keccak-256, BLAKE3 and Ascon with no dispatcher frame. SHA-3 digests of 64 bytes take
  up to 1.7% less time on Zen 4 and Emerald Rapids, and on Neoverse N2 the digests take up to 2.2%
  less and Keccak-256 up to 1.6% less. Outputs are unchanged.
- BLAKE2s on x86-64, and BLAKE2b and BLAKE2s in the portable code
  ([decision D-111](spec/decisions.md#decision-d-111)): the last block of a digest in one call that
  has no block before it, the last block of a MAC and the key are built from moves of whole words,
  so that each word the kernels load comes from one store. BLAKE2s digests of at most 64 bytes take
  up to 14% less time on Emerald Rapids and Granite Rapids and up to 3% less on Zen 3, and one of 63
  bytes 23% less on Ice Lake. Outputs are unchanged.
- BLAKE2b on x86-64 with AVX2 and AVX-512VL
  ([decision D-114](spec/decisions.md#decision-d-114)): in a digest or MAC in one call, the padding
  of a final block or of the key writes each vector of message words once, a single block and two
  blocks or more run in functions of their own, and a MAC pads its key block before the loop over
  the blocks. A digest of at most 128 bytes or a MAC of no data takes 16% to 18% less time on Zen 4
  when the input ends in a partial 16-byte piece and 2.1% to 4% less otherwise, 6.6% to 10% less on
  Zen 3 and 1.7% to 5.6% less on Granite Rapids and Ice Lake; a MAC of 1 to 128 bytes takes 2.1% to
  4.9% less on all four. Other targets are unchanged. Outputs are unchanged.
- BLAKE3 on x86-64 with AVX2: each call of the eight-lane and four-lane kernels sets up its lanes'
  inputs with one bounds check and its counters with no loop state on the stack, and a whole group
  of eight writes its chaining values straight into the caller's buffer. On every architecture a
  group of inputs that the kernels finish skips the scalar loop for the inputs left. Outputs are
  unchanged.
- BLAKE3 on x86-64 with AVX2 or SSE4.1: the kernels for one message keep the message in four
  registers and build each round's words from the previous round's with shuffles, unpacks and
  blends, instead of loading each word again from the block.
  A digest of less than a block loads its words from the input, with no zeroed copy. Outputs are
  unchanged.
- BLAKE2b's MAC on x86-64 with AVX2 runs in one call of the digest kernel, which pads the key
  block in registers and puts the key length into the chaining value. Outputs are unchanged.
- BLAKE3 digests of at most one block with at most 32 bytes of output reach their kernel from the
  call with one load of the feature word and no frame, and the kernel for one compression is reached
  the same way. A digest of at most one chunk with 33 to 64 bytes of output reads a full last block
  where it lies, without a copy, and BLAKE3 output words go straight into the output. `derive_key`
  no longer wipes the context key, which is a hash of the public context (D-76). Outputs are
  unchanged.
- BLAKE3 on Intel x86-64 processors with Golden Cove or later cores that run without AVX-512, by a
  table of models ([decision D-78](spec/decisions.md#decision-d-78)): a one-shot hash, keyed hash
  or key derivation of at most 1 KiB with at most 64 bytes of output keeps the AVX2 kernels that
  load each message word from the block and the one-shot path that calls them, which take less
  time there than the four-register kernels and the short path. Outputs are unchanged.
- One-shot SHA-224, SHA-256, SHA-384 and SHA-512 hashes on ARM64 branch from the algorithm
  dispatch to their code before the stack frame that the paths of the other algorithms need.
  Outputs are unchanged.
- SHA-224 and SHA-256 on x86-64 CPUs with the SHA extensions: one-shot digests, the digests of a
  `Hasher` and the tags of HMAC-SHA-224 and HMAC-SHA-256 are stored from the kernel's registers,
  with no copy of the state to swap and wipe, and a digest reaches the kernel with no stack frame.
  On x86-64, `HashAlgorithm::create` builds each kind of `Hasher` in a function of its own, in the
  caller's slot, the digest of a `Hasher` reaches its engine with no stack frame, and
  `Hasher::update`, `Hasher::digest_into` and the wipe of a SHA-2 state on drop are inline.
  Outputs are unchanged.
- BLAKE2b, BLAKE2s and BLAKE3 on Arm Neoverse N2: one message runs in general registers with each
  rotation taken off the chain as an EOR with a rotated operand, and BLAKE3's vector code runs one
  group of four inputs, reading each round's message words where they are. Other cores keep their
  code. Outputs are unchanged.
- BLAKE2b and BLAKE2s in the portable code compress whole blocks in one loop with the chaining value
  in registers. BLAKE3 sizes the buffers of a subtree of at most 16 chunks to it, and wipes only the
  values written. Outputs are unchanged.
- Keccak-f[1600] on x86-64 CPUs with AVX-512F and AVX-512VL: a kernel for four states side by side
  and, on the CPUs that run it in less time than the scalar code (AMD Zen 4 and Zen 5, Intel Ice
  Lake Xeon), one for a single state, selected at run time, use the EVEX instructions on 256-bit
  registers only (three-input logic and 64-bit rotations, 32 registers); in a build for the baseline
  target, no code uses a 512-bit register. Sponges squeezed side by side, as in ML-KEM, ML-DSA and
  SLH-DSA, stay in the kernel's vector layout from one block to the next. The kernels serve SHA-3,
  SHAKE, cSHAKE, KMAC and the Keccak of ML-KEM, ML-DSA, SLH-DSA and FrodoKEM. The AVX2 kernels and
  the portable code stay their twins, and outputs are unchanged.
- Keccak-f[1600] on x86-64 CPUs with AVX2 and without AVX-512: the kernel for up to four states
  loads and stores the lanes of each state four at a time, with transposes, in place of loops over
  the states, so that its state array is indexed with constants only and, at opt-level 3, stays in
  registers. Outputs are unchanged.
- Keccak-f[1600] on x86-64 CPUs with AVX2 and without AVX-512: the four-state kernels copy the rho
  shuffle masks and the round constants into their own frame once per call and read them there, in
  place of loading the masks from read-only data in every round. In processes whose stack began at
  some addresses, those loads shared the low 12 address bits with stack stores made just before
  them and waited for the stores. Outputs are unchanged.
- SLH-DSA-SHAKE on x86-64 CPUs with AVX2: F and PRF of up to four nodes, whose input fits one
  block, are padded, permuted and read in the four-state kernel's vector layout, from the parts of
  each message (the public seed shared by all four is broadcast), with no sponge object and no
  copy of the states, and only the output lanes are read back; with AVX-512VL the kernel's rounds
  are the AVX-512VL ones. Other CPUs keep the sponges side by side. Outputs are unchanged.
- SLH-DSA: the WOTS+ chains of the SHA2 sets keep the SHA-256 state words from one step to the
  next, H of the 128-bit SHA2 sets is one packed SHA-256 block, H of the 192-bit and 256-bit SHA2
  sets runs two SHA-512 blocks at a time, and FORS builds its trees in blocks of 128 leaves. In the
  SHAKE sets H runs side by side in the sponges, and in builds without the x86-64 one-block Keccak
  kernel the chains write Keccak lanes into the sponges directly. Outputs are unchanged.
- ML-KEM key generation hashes the encapsulation key beside the sampling of the matrix: each run
  of entries leaves a slot in the group of sponges for the blocks of the key that the rows of t
  encoded so far complete. ML-KEM-1024 with groups of four samples a first row of four and then
  runs of three; ML-KEM-512 samples all four entries in one group where the CPU's group has four,
  and then hashes the key. Outputs are unchanged.
- An ML-KEM encapsulation key decoded from bytes is hashed beside the sampling of its matrix, in
  the slot that runs of one entry less than the group of sponges leave. On Neoverse N2, which
  permutes three states at a time and the rest one by one, the runs are chosen so that the hash
  takes the third or sixth state of a call, except beside the last entry of ML-KEM-1024, where it
  takes the second. Its modulus check is ByteEncode_12(ByteDecode_12(ek)) = ek in the CPU's
  kernels, as FIPS 203 states it, and elsewhere one loop over the whole key. Outputs and the keys
  accepted are unchanged.
- ML-KEM-512 encryption samples y, e1 and e2 in two permutation calls in place of three: e1[1]
  and then e2 are squeezed beside the sponges of y and e1[0]. Outputs are unchanged.
- ML-KEM on x86-64 with AVX2: the sampling of the matrix reads its 12-bit candidates from the
  Keccak lanes in place, without a copy into a byte buffer, and the NTT and inverse NTT take the
  layers within each block of 32 coefficients four blocks at a time, so that four independent
  butterflies are in flight. The inverse stores each block, transposed, in its output first, so
  that the compiler keeps no block of secret coefficients on the stack. Outputs are unchanged.
- ML-KEM on ARM64: ByteDecode_12 runs in a NEON kernel, which splits the three bytes of each pair
  of coefficients with one deinterleaving load and reduces each value modulo q with one
  subtraction. It decodes an encapsulation key imported from bytes and the secret vector of an
  expanded decapsulation key, and the modulus check of the encapsulation key,
  ByteEncode_12(ByteDecode_12(ek)) = ek, runs in the NEON kernels as on x86-64 with AVX2. An
  encapsulation with a key imported from bytes takes 1.7 to 2.0% less time on Neoverse N2. Outputs
  and the keys accepted are unchanged.
- ML-DSA verification samples the challenge of the signature it is given by plain rejection, as
  FIPS 204 Algorithm 29 is written, since that signature, c̃ with it, is public
  ([decision D-72](spec/decisions.md#decision-d-72), revised for specification 2.0). Signing, and
  the verification in the pairwise test of key generation, whose signature is never output, keep
  the constant-time form. Outputs are unchanged.
- ML-DSA: the products of the matrix and a vector are summed exactly in 64 bits for each
  coefficient and reduced once, in the portable code and in the x86-64 and ARM64 kernels. Key
  generation computes each row of t, and packs it into the public key, as soon as the entries of Â
  that it needs are sampled, and hashes the blocks of the key filled so far beside the sampling of
  the later entries, in an order chosen for the CPU's Keccak kernels. UseHint takes the modulus of
  HighBits as a constant. Outputs are unchanged.
- ML-DSA on x86-64 with AVX2: the NTT and the inverse NTT take their layers in two passes over
  eight registers, with four independent butterflies in each layer and the factors loaded in lane
  order, and the inverse NTT folds its final scaling into its last layer. The sampling of the
  matrix reads the Keccak lanes one at a time. Kernels decode t1 from a public key and encode w1
  with the hints in verification, s1 and s2 are packed 32 values at a time, and the z of a
  signature is decoded as the mask is and its norm is checked on the centered values.
  SampleInBall in signing is compiled for AVX2 where the CPU has it. On ARM64 the NEON kernel
  encodes w1 with the hints too. Outputs are unchanged.
- Keccak-f[1600] on Arm Neoverse N2: one state takes scalar rounds whose rotations fold into the
  operands of EOR and BIC, and three states take two in vector registers with the SHA3 instructions
  beside one in general registers, in place of the portable code. Other Arm cores keep the kernels
  they had. Outputs are unchanged.
- One-shot SHA-3, SHAKE, cSHAKE and KMAC on Apple cores have one copy of the kernel for a start
  from zero and one for the precomputed state of cSHAKE and KMAC, so that LLVM no longer joins the
  two starts through a copy of the state on the stack. A state permuted or absorbed alone is loaded
  into one half of each vector register by plain loads. Outputs are unchanged.
- BLAKE3-MAC on x86-64 with AVX2 or SSE4.1: a message of at most 64 bytes is hashed by the one-block
  kernel from the key's bytes, so that no converted copy of the key is stored. Outputs are
  unchanged.
- Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128: the portable rounds and the x86-64 kernel for
  BMI1 and BMI2 take the S-box circuit of Zhang and Huang (ePrint 2023/1721), and the portable
  linear layer is written so that ARM64 folds its rotations into the XORs. The portable digest
  keeps the state in registers, and the x86-64 digest keeps one state word complemented from the
  start state to the wipe. The customization of Ascon-CXOF128 runs through the CPU kernels at run
  time, and the state for the empty string is a constant. The ARM64 kernel for Apple cores is
  unchanged. Outputs are unchanged.
- SHA-256 and SHA-224 on x86-64 CPUs with the SHA extensions: a one-shot hash, the digest of a
  hash object, and HMAC-SHA-256 and HMAC-SHA-224 each take one call that keeps the state in
  registers from one block to the next and builds the padding in registers, without copying the
  last bytes into a block buffer; HMAC hashes its two key blocks side by side, and the expansion of
  HKDF-SHA-256 starts from the keyed states. Outputs are unchanged.
- SHA-512 and SHA-384, their truncated forms, and HMAC and HKDF over them, on Arm cores with the
  SHA-512 instructions: the rounds of the blocks that a hash object absorbs and of HMAC's key and
  outer blocks run as four groups of sixteen with the message schedule and a last group without
  it, in place of one loop that tested for the schedule at every double round. One-shot hashes and
  the data of a one-shot HMAC, which the final call takes whole, keep the loop. Outputs are
  unchanged.
- SHA-512 and SHA-384, their truncated forms, and HMAC over them, on x86-64: a hash object holds up
  to two blocks before it compresses them, so that the AVX2 kernel, which schedules both blocks of
  a pair in the same vector instructions, takes the blocks of small updates in pairs too, and a
  digest compresses a held block together with the padding. Outputs are unchanged.
- SHA-256 on x86-64 CPUs with AVX-512F and AVX-512VL: the messages hashed side by side, eight at a
  time, in the chains and trees of LMS and XMSS and in the SHA-2 sets of SLH-DSA take a kernel,
  selected at run time, that keeps one message in each element of a 256-bit register and uses
  rotations and three-input logic for Ch, Maj and the sigma functions; no code uses a 512-bit
  register. AMD processors with the SHA extensions keep the SHA-NI kernel, which runs these hashes
  in less time there. The SHA-NI and AVX2 kernels and the portable code stay its twins, and outputs
  are unchanged.
- AES in the portable code, which the AES sets of FrodoKEM use for the matrix A on CPUs without AES
  instructions: the rounds are fixsliced (Adomnicai and Peyrin, ePrint 2020/1123), with four blocks
  in eight 64-bit planes, plane b holding bit b of every byte. The round keys are converted to
  match at key setup, and the S-box runs without its NOTs. The paths that use the AES instructions
  are unchanged. Outputs are unchanged.
- ML-KEM and ML-DSA where the NTT has no AVX2 or NEON kernel (RISC-V, s390x and the portable
  builds): the NTT and its inverse take three passes on eight coefficients held in registers, with
  the twiddle factors and their products by QINV from static tables, in place of one pass through
  memory for each layer. The inverse reduces in its first pass and folds its final scaling into its
  last layer. Outputs are unchanged.
- ML-KEM on the same targets: the first pass of the NTT reads the coefficients where they are, with
  no pass to widen them first, and key generation transforms e inside the sums of t, which start
  from NTT(e), with no canonical form of it and no loop to add it. The array of the sums is wiped
  after use. Outputs are unchanged.
- ML-DSA signing on the targets other than x86-64 and ARM64, RISC-V and s390x among them, runs the
  constant-time passes of SampleInBall on 64-bit words, eight lanes an operation, with the mask of
  each lane taken from its byte of a word by arithmetic that no single bit decides ([decision
  D-79](spec/decisions.md#decision-d-79)). Outputs are unchanged.
- SHA-224, SHA-256, SHA-384 and SHA-512 in the portable code, which runs on RISC-V, s390x and the
  CPUs without the SHA-2 kernels: one group of 16 rounds is written out and run in a loop over the
  groups, and the message schedule and the working variables are arrays indexed with constants only,
  so that they stay in registers. On targets without vector registers by default (RISC-V without the
  V extension and s390x), the messages that LMS, XMSS, SLH-DSA and HMAC hash side by side run
  through the rounds one at a time, and HMAC's key blocks and the padding of a hash enter the
  schedule word by word from the key and from the last bytes of the message, with no block built in
  memory. On every target HMAC hashes a key longer than a block out of line, and a shorter key needs
  no buffer. Outputs are unchanged.
- LMS and HSS over SHA-256 and SHA-256/192 on targets without vector registers by default: each
  step of a Winternitz chain is one compression whose block is built from words, those of I and q
  fixed for a key, the chain value entering the schedule as big-endian words and the padding as
  constants, and the secret chain starts are derived from the words of SEED the same way. The
  chains run one after the other, and their ends are hashed with one update. On every target the
  digits of the message hash are taken by shifts, as the width is a power of two, in place of a
  division. Outputs are unchanged.
- The minimum supported Rust version is 1.89, the first in which the AVX-512 target features and
  intrinsics are stable.

### Removed

- Support for WebAssembly and 32-bit targets
  ([decision D-105](spec/decisions.md#decision-d-105-revised-by-d-120)): the crate builds for
  64-bit targets only, and a build for WebAssembly or a 32-bit target stops with a compile error.
  CI no longer builds or tests them. Every other 64-bit target keeps the portable code, big-endian
  s390x among them. This is not compatible with 1.x, so this release implements specification 2.0;
  1.0.x stays the release for those targets.

### Fixed

- SLH-DSA key generation, signing and the import of a private key: the lanes of the F chains were
  moved before their wipe, so that the wipe cleared the copy and the original stayed on the stack
  ([decision D-76](spec/decisions.md#decision-d-76)). After a signature it held the secret values
  of the last sixteen leaves of the last FORS tree, with every parameter set on x86-64 and with
  the SHA-2 sets on ARM64, and with SLH-DSA-SHAKE-128f and SLH-DSA-SHAKE-192f on ARM64 and in
  builds without the CPU kernels it held SK.seed, after key generation too. The lanes are now
  wiped where they are. rust-v1.0.0 and rust-v1.0.1 do not have the flaw. Outputs are unchanged.
- SLH-DSA key generation, signing and the import of a private key end by writing zeros over the
  stack under them, 16 KiB at opt-level 3, 48 KiB at opt-level 0 and 24 KiB at the other levels
  ([decision D-115](spec/decisions.md#decision-d-115)): a kernel of the hashes can leave a secret
  value that it held in a register in its frame, where no wipe of a buffer reaches. In the test
  profile on a processor with AVX-512VL, a signature with SLH-DSA-SHAKE-256f or
  SLH-DSA-SHAKE-256s left the last secret value of FORS that way, and at opt-levels 1, s and z on
  x86-64 a signature with SLH-DSA-SHA2-128f or SLH-DSA-SHA2-128s left the outer HMAC state of
  PRF_msg under SK.prf. A test paints the stack, runs key generation and signing for the twelve
  parameter sets, searches the stack for SK.seed, SK.prf and the secret values of the last
  sixteen leaves of the last FORS tree, and checks that the zeros lie where the operation went
  deepest; CI runs it in the release build, in the test profile and at opt-level z. At opt-level
  3 a signature takes about 30 KB of stack on x86-64 and 32 KB on ARM64, where it took 30 to 34
  before the lanes were wiped in place, and key generation 18 KB, 4 to 7 KB more than before.
  Outputs are unchanged.
- ML-KEM, ML-DSA and FrodoKEM: key generation, encapsulation, decapsulation, signing and the
  import of a private key end by writing zeros over the stack under them, as SLH-DSA does, and so
  do a MAC or a KDF in one call, the key setup of an incremental MAC or of a MAC key and the end of
  an incremental MAC in every build at opt-level 1, 2, s or z ([decision
  D-116](spec/decisions.md#decision-d-116), [decision D-119](spec/decisions.md#decision-d-119)). At
  opt-level 3, FrodoKEM left its shared secret on the stack after encapsulation and after
  decapsulation on x86-64 and in builds without the CPU kernels, and with FrodoKEM-1344 on ARM64
  cores without the SHA-3 instructions; ML-KEM left its shared secret and the coins of the
  encryption when built for x86-64-v3, and the noise seed and the coins with fat LTO on ARM64;
  ML-DSA left rho' and K after key generation in builds without the CPU kernels. Below opt-level 3,
  HMAC, HKDF and BLAKE2b left their key, the states after its blocks or the derived key in the
  frames of their kernels, and an incremental MAC its keyed state in frames of the library. The
  test of the dead stack covers these operations, in the release build, in the test profile and at
  opt-level z in CI, where it covers a MAC and a KDF in one call with the default and with every
  feature. An operation of ML-KEM takes 19 to 72 ns more on a Neoverse N2, at most 1 percent, and
  42 to 119 ns more on the x86-64 server processors measured (EPYC 7763, Xeon Platinum 8573C, Xeon
  6975P-C), 0.3 to 4.4 percent; key generation of ML-DSA takes 0.1 to 0.3 us more, up to 2.1
  percent. At opt-level 3 on x86-64 an operation takes about 2 KB more stack with ML-KEM, 4.5 KB
  more with ML-DSA and 4.4 to 8 KB more with FrodoKEM. Outputs are unchanged.
- HMAC-SHA-256 and HKDF-SHA-256 on x86-64 with the SHA extensions, in builds at opt-level 2: the
  copy of both streams that the feed-forward of a block kept was a call to memcpy, around which
  the registers with the words of the two key blocks were saved on the stack, where nothing wiped
  them. Below opt-level 3 the feed-forward keeps the two state vectors of each stream alone. At
  opt-level 3 the machine code is unchanged. Outputs are unchanged.
- BLAKE3 in builds below opt-level 3: the portable compression wipes its state, which derives
  from the key in the keyed modes, and the message words with their permutations, which hold the
  key material of `derive_key`. A keyed hash of at most 64 bytes on an ARM64 core that takes the
  portable code left the state after the rounds on the stack at opt-levels s and z. At opt-level 3
  the machine code is unchanged. Outputs are unchanged.
- Constant time on RISC-V and s390x: the compiler turned the masked reductions of ML-DSA and ML-KEM
  into a choice between two values, which these targets computed with a branch on secret
  coefficients. On RISC-V without the Zicond extension, ML-DSA signing, ML-DSA key generation from a
  seed, the import of expanded ML-DSA keys and the check of expanded ML-KEM decapsulation keys
  branched at every opt-level; on s390x, the norm checks of ML-DSA signing and the ML-KEM noise
  sampler at opt-levels 1, 2 and 3. Every mask computed from secret data now passes an optimization
  barrier ([decision D-79](spec/decisions.md#decision-d-79)), an empty inline assembly block, or
  `core::hint::black_box` on the targets without stable inline assembly. The machine code for x86-64
  and ARM64 is unchanged. rust-v1.0.0 and rust-v1.0.1 have the same flaw.
- BLAKE2s and BLAKE3 on x86-64 and BLAKE3 on ARM64: the broadcasts of message and key words are
  written out, so that no broadcast word stays in a frame of `array::map` that nothing wipes
  (D-76): BLAKE3's extended output on ARM64 copied the root block by value, BLAKE2s's AVX2 kernel
  left its last message word, and BLAKE3's AVX2 and SSE4.1 hash_many their last key word.
- Secret buffers on the stack are wiped before each function returns, on every path, as
  specification 14.5 requires ([decision D-76](spec/decisions.md#decision-d-76)): the SHA-2 message
  schedules, the paired SHA-256 streams of the SHA-NI kernels, the buffers of the Keccak, BLAKE2,
  BLAKE3 and NTT kernels on x86-64, copies of partial lanes and words, the base64 buffers of private
  keys, and the chain values of SLH-DSA, LMS and XMSS. Secrets that were returned by value, such as
  KEM shared secrets, ML-KEM and ML-DSA polynomials, the chaining values and outputs of BLAKE3, the
  key states of one-shot HMAC, HKDF and KMAC, and the FrodoKEM noise sponge keyed with seedSE, are
  written into storage that their owner wipes. ML-DSA signing wipes w1 and the products with s1 and
  s2 of rejected attempts.
  In builds below opt-level 3, where the compiler keeps the register arrays of the kernels in
  memory, those arrays are wiped too; a build script reads the opt-level for this. Copies that the
  compiler makes in registers and spill slots remain, as the documentation states. Outputs are
  unchanged.
- Keccak-f[1600] in builds below opt-level 3: the arrays of theta and of rho and pi in the rounds
  of the portable code, of the AVX2 kernel for four states and of the ARM64 kernel with the SHA3
  instructions, which the compiler kept on the stack, are wiped before each round returns, and the
  temporaries in which it built some of them are no longer made. At opt-level 3 the machine code is
  unchanged. Outputs are unchanged.
- ML-DSA key generation sampled s1 and s2 from the SHAKE256 output through iterators that left a
  lane of that output and its half-bytes on the stack, unwiped, in the portable code and in the
  x86-64 and ARM64 kernels. The half-bytes are now taken in plain loops over the lanes, and no
  iterator or array holds the secret values. Outputs are unchanged.
- The hash engines of LMS, HSS and XMSS that have absorbed input are finished in the storage
  that wipes them on drop. The last call on a truncated SHA-256 or SHAKE256 hash took the engine
  by value and wiped only its copy, so that the input it had absorbed stayed on the stack: SEED
  where LMS derives the randomizer C and the SEED and I of a child tree, and with SHAKE256 the
  LM-OTS chain starts; SK_PRF where XMSS derives its randomizer; and with SHAKE256 SK_SEED and
  the secret chain values of XMSS. The XMSS PRF_keygen state, keyed with SK_SEED, was copied
  when it was moved into the hashes of a tree. Outputs are unchanged.
- Builds for a 64-bit target without compare-and-swap of pointer width, such as RV64IM
  (`riscv64im-unknown-none-elf`), the instruction set of zkVMs
  ([decision D-112](spec/decisions.md#decision-d-112)): the form of the key caches for such a
  target, which fills them when a key is made, did not compile with ML-KEM, FrodoKEM or ML-DSA. It
  builds now, `--cfg crypto_pq_eager` takes it on any target, and CI builds the library for RV64IM
  and runs the tests in that form. The machine code of other targets is unchanged. rust-v1.0.0 and
  rust-v1.0.1 have the same flaw.

### Security

- The source audit of November 2026, its findings and its fixes are recorded in
  [security/audit-2026-11.md](security/audit-2026-11.md); the entries under Changed and Fixed above
  give each change in full.
- Finding F1, the FORS secret values and SK.seed that SLH-DSA left on the stack, came in after
  rust-v1.0.1 and was never released.
- Values that rust-v1.0.1 leaves on the stack, measured on that tag with the audit's harness
  ([Released versions](security/audit-2026-11.md#released-versions)): at opt-level 3, FrodoKEM
  its whole shared secret after encapsulation and decapsulation (F9), ML-KEM its shared secret and
  the coins of the encryption (F4), and KMAC256 its state after the key; at opt-levels s and z,
  HMAC and HKDF their key XORed with the pads, their key states, the PRK and the output (F3); and
  at opt-level 3, the keyed hashes in one call parts of their key or keyed state, and an
  incremental MAC its keyed state. 1.0.0 was not measured: between the two tags the code of ML-KEM
  changed in visibility only and that of HMAC, HKDF, KMAC and BLAKE2 did not change, while that of
  FrodoKEM, BLAKE3 and the CPU dispatch did.
- This release ends the operations on secret values with zeros over the stack under them: SLH-DSA
  ([decision D-115](spec/decisions.md#decision-d-115)); ML-KEM, ML-DSA and FrodoKEM at every
  opt-level ([decision D-116](spec/decisions.md#decision-d-116)); a MAC and a KDF at the
  opt-levels 1, 2, s and z in every build ([decision D-119](spec/decisions.md#decision-d-119)),
  and at opt-level 3 with the feature `stack-zeros`
  ([decision D-117](spec/decisions.md#decision-d-117),
  [decision D-118](spec/decisions.md#decision-d-118)).
- The 1.0.x line receives no patch. This release removes the WebAssembly and 32-bit targets, so
  their users stay on 1.0.x, which keeps these residues.

## [1.0.1] - 2026-10-26

Implements specification 1.0, as 1.0.0 does. The API and every output are unchanged.

### Changed

- FrodoKEM: matrix A and its products with the secret matrices use CPU kernels selected at run
  time, each with its portable twin: on ARM64, AES-128 rows with the ARMv8 AES instructions
  (eight blocks in flight) and the products with NEON; on x86-64, AES-128 rows with AES-NI and,
  on AVX2 CPUs, four SHAKE128 rows at a time and the products with AVX2. Noise sampling and the
  SHAKE128 rows of the portable code run on whole blocks. Outputs are unchanged.
- BLAKE3, BLAKE3-256, BLAKE3-MAC and BLAKE3-KDF hash several chunks, and several parents, at a
  time with CPU kernels selected at run time, each with its portable twin: NEON on ARM64, AVX2 or
  SSE4.1 on x86-64. The extended output is computed several blocks at a time. Outputs are
  unchanged.
- Ascon on ARM64: the scalar kernel runs on Apple cores only, where it takes less time than the
  portable code; other cores, such as Neoverse N2, on which the portable code takes less time,
  run it. Outputs are unchanged.

## [1.0.0] - 2026-10-23

The first release that implements specification 1.0.

### Added

- Key encapsulation: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203); FrodoKEM-976 and
  FrodoKEM-1344 and their ephemeral eFrodoKEM forms, each with AES or SHAKE
  (ISO/IEC 18033-2:2006/Amd 2:2026).
- Signatures: ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) and the 12 SLH-DSA sets (FIPS 205), in
  pure and pre-hash (HashML-DSA, HashSLH-DSA) modes, with hedged or deterministic signing and a
  context string; the 12 HashSLH-DSA values of RFC 9909.
- Stateful hash-based signatures: HSS/LMS (RFC 8554, RFC 9858) and XMSS and XMSS^MT (RFC 8391), with
  the parameter sets of NIST SP 800-208, an application-provided `StateStore`, an authenticated tree
  cache, a `reserve` option and erasure of the secrets when a key is exhausted.
- Hash functions and XOFs: SHA-2 (FIPS 180-4); SHA-3, SHAKE and cSHAKE (FIPS 202, NIST SP 800-185);
  BLAKE2b and BLAKE2s (RFC 7693); BLAKE3; Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128
  (NIST SP 800-232).
- MACs: HMAC with SHA-2 (FIPS 198-1), KMAC128 and KMAC256, BLAKE2b-MAC, BLAKE2s-MAC and BLAKE3-MAC.
- KDFs: HKDF with SHA-2 (RFC 5869) and BLAKE3-KDF.
- Key formats: raw, DER (SubjectPublicKeyInfo and PKCS #8) and PEM for ML-KEM, ML-DSA and SLH-DSA
  keys and for HSS/LMS and XMSS public keys; raw for FrodoKEM.
- One Cargo feature per algorithm family, all enabled by default, and the opt-in `hazmat` feature
  with the deterministic operations for known-answer and interoperability tests.
- `no_std` with `alloc`, no dependencies, Rust 1.88 or later.
- CPU-specific code for x86-64 (AVX2, SSE4.1, SHA-NI, AES-NI) and ARM64 (NEON, AES, SHA-2, SHA-3,
  SHA-512), selected at run time, with portable code on every target.
- Constant-time code for secret data, checked in CI with valgrind memcheck on x86-64 and ARM64, and
  the ARM64 data-independent timing mode (DIT) around asymmetric secret operations.
- `SecretBytes` for every secret output, wiped on drop; private keys wiped on drop.
- Pairwise consistency tests at key generation (on by default) and in the ML-KEM and FrodoKEM
  private-key import checks, and verification of every stateful signature before its release.
- Operating-system randomness only, with `Error::RngFailure` on targets without a source.
- `enable_data_independent_timing()`, which extends DIT to MACs and KDFs.

### Usage requirements

These rules are part of the API contract:

- **Pre-hash policy** ([9.1.3](spec/09-signatures.md)). HashML-DSA and HashSLH-DSA accept only
  SHA-2, SHA-3, SHAKE128 and SHAKE256, and only a function with at least the collision strength of
  the signature (128, 192 or 256 bits by category). SHA-224, SHA-512/224 and SHA3-224 are never
  accepted. Signing with a refused pre-hash fails with `Error::InvalidOption`; verification returns
  `false`. The policy is fixed, and only the hazmat functions skip the strength rule.
- **No external μ** ([9.1.5](spec/09-signatures.md)). No public function accepts μ, the message
  representative or a precomputed digest in place of the message. Only the hazmat test functions
  take the message representative, for the ACVP test groups.
- **State store contract** ([11.6](spec/11-stateful-signatures.md)). `StateStore::update` must be an
  atomic compare-and-swap and must make the new record durable before it returns `true`. The record
  contains secrets and must be protected like a private key. It must never be restored from a copy
  or a backup, cloned, or used by two key objects or processes at once; compare-and-swap cannot
  detect a rollback of the storage itself.
- **eFrodoKEM usage limit** ([8.2.6](spec/08-key-encapsulation.md)). An eFrodoKEM public key must be
  used for fewer than 2^8 ciphertexts. The crate does not enforce the limit and never chooses an
  eFrodoKEM set by default.
- **Hazmat** ([13](spec/13-hazmat.md)). The `hazmat` operations are for test vectors only; a seed
  or randomness must never be reused with a different key, message or ciphertext.
- **One key, one mode** ([9.1.2](spec/09-signatures.md)). Each ML-DSA or SLH-DSA key is used with
  only one of the hedged and deterministic variants, and only one of the pure and pre-hash modes.

[2.0.0]: https://github.com/crypterial/crypto-pq/tree/rust-v2.0.0
[1.0.1]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.1
[1.0.0]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.0
