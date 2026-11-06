# Changelog

All notable changes to the `crypto-pq` crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and its MAJOR.MINOR is the version of
the [crypto-pq specification](spec/00-contents.md) that it implements
([Section 20.1](spec/20-versioning.md)).

## [Unreleased]

Implements specification 1.1 (draft).

### Added

- `MacAlgorithm::key`, which returns a `MacKey`, and `MacKey::create`, which returns a `Mac` in its
  state right after `MacAlgorithm::create` under the same key and options, for every MAC algorithm
  ([decision D-77](spec/decisions.md#decision-d-77)). The tags of many messages under one key pay
  for the key setup once: HMAC and KMAC process no key block again. A `MacKey` may be used from
  several threads at once, does not implement `Clone`, and wipes its keyed state when dropped.
  `Mac` is unchanged.

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
  such as those of a 1 KiB hash, and single blocks run the row form of the blake3 crate's assembly
  for one input. Outputs are unchanged.
- BLAKE3 on x86-64: two to four inputs, parents or blocks of an extended output run in the row form,
  each 128-bit lane holding one row of one input ([decision D-84](spec/decisions.md#decision-d-84)):
  with AVX-512 on the processors above, on 512-bit registers for three or four and 256-bit registers
  for two, and with AVX2 on 256-bit registers, `hash_many` in the register plan of the blake3 crate's
  assembly, unless the core runs a 256-bit instruction as two operations. The chaining values of a
  tree of up to the width of the kernels go straight into the block of the top parent, with no copy
  between levels, and five to eight blocks of an extended output run on eight lanes. An extended
  output from an input of at most one block skips the chunk buffer. Outputs are unchanged.
- BLAKE3 on x86-64 with AVX2 or SSE4.1: the groups of an extended output on eight or four lanes
  broadcast the message and the chaining value once for all groups, with one scratch state. Outputs
  are unchanged.
- SHA-224 and SHA-256 on WebAssembly: the compression runs the first group of rounds ahead of a loop
  over the other three, and padding blocks, HMAC key blocks and one-shot inputs of under four blocks
  share one copy of it out of line ([decision D-85](spec/decisions.md#decision-d-85)). Outputs are
  unchanged.
- SHA-384 and SHA-512 on ARM64 with the SHA-512 instructions: the loop over the blocks of an update
  takes the same one-loop form of the rounds as the loop over the blocks of a one-shot input, which
  took less time per block on Neoverse N2. Outputs are unchanged.
- BLAKE2b on ARM64 cores that run it on the general registers: the compression reads the IV from
  memory, not from constants in its code. Outputs are unchanged.
- BLAKE3 on WebAssembly: the last two inputs of `hash_many` run one after the other, and the whole
  blocks of an extended output go straight into the output, as on 32-bit x86
  ([decision D-84](spec/decisions.md#decision-d-84)). Outputs are unchanged.
- BLAKE3 on x86-64 with AVX2: each call of the eight-lane and four-lane kernels sets up its lanes'
  inputs with one bounds check and its counters with no loop state on the stack, and a whole group
  of eight writes its chaining values straight into the caller's buffer. On every architecture a
  group of inputs that the kernels finish skips the scalar loop for the inputs left. Outputs are
  unchanged.
- BLAKE3 on x86-64 with AVX2 or SSE4.1: the kernels for one message keep the message in four
  registers and build each round's words from the previous round's with shuffles, unpacks and
  blends, as the reference SSE4.1 code does, instead of loading each word again from the block.
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
- ML-DSA verification samples the challenge of the signature it is given by plain rejection, as
  FIPS 204 Algorithm 29 is written, since that signature, c̃ with it, is public
  ([decision D-72](spec/decisions.md#decision-d-72), revised for specification 1.1). Signing, and
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
- SHA-512, SHA-384 and their truncated forms on 32-bit x86 with SSE2, with HMAC and HKDF over them
  and the SHA2 sets of SLH-DSA at security categories 3 and 5
  ([decision D-83](spec/decisions.md#decision-d-83)): the message schedule computes its words two at
  a time, so that each of its steps is one SSE2 operation on both words of a pair, where a word
  alone takes two general registers. Outputs are unchanged.
- SHA-256 on x86-64 CPUs with AVX-512F and AVX-512VL: the messages hashed side by side, eight at a
  time, in the chains and trees of LMS and XMSS and in the SHA-2 sets of SLH-DSA take a kernel,
  selected at run time, that keeps one message in each element of a 256-bit register and uses
  rotations and three-input logic for Ch, Maj and the sigma functions; no code uses a 512-bit
  register. AMD processors with the SHA extensions keep the SHA-NI kernel, which runs these hashes
  in less time there. The SHA-NI and AVX2 kernels and the portable code stay its twins, and outputs
  are unchanged.
- Keccak-f[1600] on 32-bit targets other than WebAssembly: the state holds each lane
  bit-interleaved, as XKCP's inplace32BI does, so that a lane rotation is one 32-bit rotation of
  each word, and lanes are converted only where they are absorbed and read. On 32-bit x86 with SSE2
  the states are instead permuted two at a time, the same lane of both in one SSE2 register, and a
  state alone beside the zero state ([decision D-80](spec/decisions.md#decision-d-80)). Outputs are
  unchanged.
- Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 on 32-bit Arm: the state holds its words
  bit-interleaved, so that each rotation is one 32-bit rotation of each half, and words are
  converted only where they are absorbed and read
  ([decision D-81](spec/decisions.md#decision-d-81)). Outputs are unchanged.
- One-shot Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 on WebAssembly and 32-bit x86: the hash
  and XOF dispatchers branch to the Ascon code before they set up the stack frame that the other
  algorithms need, `XofAlgorithm::configure` and `XofAlgorithm::digest_into` are inline, and the
  customization of Ascon-CXOF128 runs the rounds inline in place of a call of the permutation per
  block. On 32-bit x86 the digest also stores whole output words as they are, and the linear layer
  takes the two rotations of each word side by side, as the specification writes it, which leaves
  one dependent step less in each round. Outputs are unchanged.
- BLAKE2b and BLAKE3 on 32-bit x86 ([decision D-82](spec/decisions.md#decision-d-82)): with SSE2,
  BLAKE2b's state holds the words of each row in pairs, so that each step of a round is one SSE2
  operation on both words of a pair; BLAKE3 compresses each block of a chain in a call of its own,
  and writes the whole blocks of an extended output from the registers of their compression
  straight into the output. Outputs are unchanged.
- AES in the portable code, which the AES sets of FrodoKEM use for the matrix A on CPUs without AES
  instructions: the rounds are fixsliced (Adomnicai and Peyrin, ePrint 2020/1123), with four blocks
  in 64-bit planes on 64-bit targets and WebAssembly and two in 32-bit planes on the other 32-bit
  targets, in the layouts of BearSSL's aes_ct64 and aes_ct. The round keys are converted to match
  at key setup, and the S-box runs without its NOTs. The paths that use the AES instructions are
  unchanged. Outputs are unchanged.
- ML-KEM and ML-DSA where the NTT has no AVX2 or NEON kernel (32-bit Arm and x86, WebAssembly,
  RISC-V, s390x and the portable builds): the NTT and its inverse take three passes on eight
  coefficients held in registers, with the twiddle factors and their products by QINV from static
  tables, in place of one pass through memory for each layer. The inverse reduces in its first
  pass and folds its final scaling into its last layer. Outputs are unchanged.
- ML-DSA signing on 32-bit Arm and x86, WebAssembly, RISC-V and s390x runs the constant-time
  passes of SampleInBall on 64-bit words, eight lanes an operation, with the mask of each lane
  taken from its byte of a word by arithmetic that no single bit decides
  ([decision D-79](spec/decisions.md#decision-d-79)). Outputs are unchanged.
- SHA-224, SHA-256, SHA-384 and SHA-512 in the portable code, which runs on 32-bit Arm and x86,
  WebAssembly, RISC-V, s390x and the CPUs without the SHA-2 kernels: one group of 16 rounds is
  written out and run in a loop over the groups, and the message schedule and the working
  variables are arrays indexed with constants only, so that they stay in registers. On targets
  without vector registers by default (32-bit Arm, RISC-V without the V extension, s390x and
  WebAssembly without simd128), the messages that LMS, XMSS, SLH-DSA and HMAC hash side by side
  run through the rounds one at a time, and HMAC's key blocks and the padding of a hash enter the
  schedule word by word from the key and from the last bytes of the message, with no block built
  in memory; SHA-512 on 32-bit Arm keeps its padding block. On WebAssembly each of the two slices
  of an update reaches the loop over its blocks in a call of its own. On 32-bit Arm the sigma
  functions of SHA-512 are computed on the 32-bit halves of each word. On every target HMAC hashes
  a key longer than a block out of line, and a shorter key needs no buffer. Outputs are unchanged.
- LMS and HSS over SHA-256 and SHA-256/192 on targets without vector registers by default: each
  step of a Winternitz chain is one compression whose block is built from words, those of I and q
  fixed for a key, the chain value entering the schedule as big-endian words and the padding as
  constants, and the secret chain starts are derived from the words of SEED the same way. The
  chains run one after the other, and their ends are hashed with one update. On every target the
  digits of the message hash are taken by shifts, as the width is a power of two, in place of a
  division. Outputs are unchanged.
- The minimum supported Rust version is 1.89, the first in which the AVX-512 target features and
  intrinsics are stable.

- FrodoKEM with AES on WebAssembly: the bitsliced rounds of AES run in one loop over the round
  keys, with the state in memory once per cycle, where LLVM made three copies of the body of the
  loop. FrodoKEM-976-AES takes 18% less time on AMD Zen 3 under wasmtime and 14% less under Node.js,
  and about 14% less on Zen 4 under wasmtime; under wasmtime on Emerald Rapids it takes 1.5% more.
  The machine code of other targets is unchanged. Outputs are unchanged.

### Fixed

- Constant time on RISC-V and s390x: the compiler turned the masked reductions of ML-DSA and
  ML-KEM into a choice between two values, which these targets computed with a branch on secret
  coefficients. On RISC-V without the Zicond extension, ML-DSA signing, ML-DSA key generation from
  a seed, the import of expanded ML-DSA keys and the check of expanded ML-KEM decapsulation keys
  branched at every opt-level; on s390x, the norm checks of ML-DSA signing and the ML-KEM noise
  sampler at opt-levels 1, 2 and 3. Every mask computed from secret data now passes an
  optimization barrier ([decision D-79](spec/decisions.md#decision-d-79)), an empty inline
  assembly block, or `core::hint::black_box` on WebAssembly and the other targets without stable
  inline assembly. The machine code for x86-64 and ARM64 is unchanged. rust-v1.0.0 and
  rust-v1.0.1 have the same flaw.
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

[1.0.1]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.1
[1.0.0]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.0
