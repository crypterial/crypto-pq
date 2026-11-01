// The one-message kernels of BLAKE2 and BLAKE3, called directly against the portable code on the
// same inputs, whatever the core tables choose for the dispatch: the AVX-512VL ones on every CPU
// with AVX512 (the dispatch runs the portable code on AMD Zen 5 and BLAKE2's AVX2 forms on AMD's
// other cores), the AVX2 ones, which take the same arguments, on every CPU with AVX2. Messages of
// 0 to 65, 128 and 1025 bytes where a kernel takes them, keyed and unkeyed, and several output
// lengths. CI's AVX-512 runners look for the line that the test prints. The references are the
// portable compressions with RFC 7693's and the BLAKE3 specification's framing, checked against
// the library's own functions first. BLAKE3's 512-bit kernels for sixteen inputs are called the
// same way, on every CPU with AVX512.

use alloc::vec;
use alloc::vec::Vec;

use super::super::testing::Inputs;
use super::blake3_zmm::{Table16, hash16_zmm, xof16_zmm};
use super::{AVX2, AVX512, Blake2sKernel, blake2, blake3, has};
use crate::blake2::{Word, compress, start32, start64};
use crate::blake3::{CHUNK_END, CHUNK_START, Last, PERMUTATION, ROOT};
use crate::sha2::IV_256;

const KEYED_HASH: u32 = 16;

type Blake2bKernel =
    unsafe fn(&mut [u64; 8], Option<&[u64; 16]>, &[[u8; 128]], u128, Option<(&[u64; 16], u128)>);

type Blake2bDigest = unsafe fn(&[u64; 8], &[u8], &[u8], &mut [u8]);

type Chain = unsafe fn(&mut [u32; 8], &[[u8; 64]], u64, u32, [u32; 2], Last<'_>);

type Compress = unsafe fn(&[u32; 8], &[u8; 64], u64, u32, u32, &mut [u32; 16]);

type Digest1Words = unsafe fn(&[u32; 8], u32, &[u8], &mut [u8]);

type Digest1Bytes = unsafe fn(&[u8; 32], u32, &[u8], &mut [u8]);

// One tier's kernels for one message.
struct Kernels {
    blake2b: Blake2bKernel,
    blake2b_digest: Blake2bDigest,
    blake2s: Blake2sKernel,
    chain: Chain,
    compress: Compress,
    digest1_words: Digest1Words,
    digest1_bytes: Digest1Bytes,
}

const COUNT: usize = 7;

fn lengths() -> impl Iterator<Item = usize> {
    (0..=65).chain([128, 1025])
}

fn random(inputs: &mut Inputs, length: usize) -> Vec<u8> {
    (0..length).map(|_| inputs.next() as u8).collect()
}

// The words of at most a block of bytes, zero-padded.
fn block_words<W: Word>(bytes: &[u8]) -> [W; 16] {
    let mut padded = [0; 128];

    padded[..bytes.len()].copy_from_slice(bytes);

    core::array::from_fn(|i| W::from_le(&padded[i * W::BYTES..]))
}

fn state_bytes<W: Word>(h: &[W; 8]) -> Vec<u8> {
    let mut bytes = vec![0; 8 * W::BYTES];

    for (chunk, word) in bytes.chunks_exact_mut(W::BYTES).zip(h) {
        word.write_le(chunk);
    }

    bytes
}

// RFC 7693, 3.3: the key block first, the counter the bytes so far, the last block final.
fn rfc<W: Word>(h: &[W; 8], key: &[u8], data: &[u8], length: usize) -> Vec<u8> {
    let size = 16 * W::BYTES;

    let mut h = *h;

    let mut message = Vec::new();

    if !key.is_empty() {
        h[0] = h[0] ^ W::key_length(key.len());

        message.extend_from_slice(key);

        message.resize(size, 0);
    }

    message.extend_from_slice(data);

    let count = message.len().div_ceil(size).max(1);

    for i in 0..count {
        let last = i + 1 == count;

        let end = message.len().min((i + 1) * size);

        let counter = if last { message.len() } else { (i + 1) * size };

        compress(
            &mut h,
            &block_words(&message[i * size..end]),
            counter as u128,
            last,
        );
    }

    state_bytes(&h)[..length].to_vec()
}

// A message as BLAKE2's process kernels take it: the key block, the whole blocks and the final
// block with its counter, each block zero-padded; without `final_block`, the whole blocks of data
// alone after the key block.
struct Plan {
    first: Option<Vec<u8>>,
    blocks: Vec<u8>,
    last: Option<(Vec<u8>, u128)>,
}

fn plan(size: usize, key: &[u8], data: &[u8], base: u128, final_block: bool) -> Plan {
    let pad = |bytes: &[u8]| {
        let mut block = bytes.to_vec();

        block.resize(size, 0);

        block
    };

    let first = (!key.is_empty()).then(|| pad(key));

    if !final_block {
        return Plan {
            first,
            blocks: data[..data.len() / size * size].to_vec(),
            last: None,
        };
    }

    // A key alone is the final block.
    if data.is_empty() && first.is_some() {
        return Plan {
            first: None,
            blocks: Vec::new(),
            last: first.map(|block| (block, base + size as u128)),
        };
    }

    let lead = data.len().saturating_sub(1) / size * size;

    let total = base + u128::from(first.is_some()) * size as u128 + data.len() as u128;

    Plan {
        first,
        blocks: data[..lead].to_vec(),
        last: Some((pad(&data[lead..]), total)),
    }
}

// The plan on the portable compression, counter the bytes before its first block.
fn process<W: Word>(h: &mut [W; 8], plan: &Plan, base: u128) {
    let size = 16 * W::BYTES;

    let mut counter = base;

    if let Some(block) = &plan.first {
        counter += size as u128;

        compress(h, &block_words(block), counter, false);
    }

    for block in plan.blocks.chunks_exact(size) {
        counter += size as u128;

        compress(h, &block_words(block), counter, false);
    }

    if let Some((block, total)) = &plan.last {
        compress(h, &block_words(block), *total, true);
    }
}

fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);

    v[d] = (v[d] ^ v[a]).rotate_right(16);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(12);

    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);

    v[d] = (v[d] ^ v[a]).rotate_right(8);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

// The BLAKE3 compression function of the specification, 2.2, all sixteen output words.
fn compress3(cv: &[u32; 8], block: &[u8; 64], counter: u64, length: u32, flags: u32) -> [u32; 16] {
    let mut m: [u32; 16] = block_words(block);

    let mut v = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV_256[0],
        IV_256[1],
        IV_256[2],
        IV_256[3],
        counter as u32,
        (counter >> 32) as u32,
        length,
        flags,
    ];

    for round in 0..7 {
        g(&mut v, [0, 4, 8, 12], m[0], m[1]);

        g(&mut v, [1, 5, 9, 13], m[2], m[3]);

        g(&mut v, [2, 6, 10, 14], m[4], m[5]);

        g(&mut v, [3, 7, 11, 15], m[6], m[7]);

        g(&mut v, [0, 5, 10, 15], m[8], m[9]);

        g(&mut v, [1, 6, 11, 12], m[10], m[11]);

        g(&mut v, [2, 7, 8, 13], m[12], m[13]);

        g(&mut v, [3, 4, 9, 14], m[14], m[15]);

        if round < 6 {
            m = core::array::from_fn(|i| m[PERMUTATION[i]]);
        }
    }

    core::array::from_fn(|i| {
        if i < 8 {
            v[i] ^ v[i + 8]
        } else {
            v[i] ^ cv[i - 8]
        }
    })
}

fn padded64(data: &[u8]) -> [u8; 64] {
    let mut block = [0; 64];

    block[..data.len()].copy_from_slice(data);

    block
}

// The first `length` bytes of the root output of one block.
fn digest1(key: &[u32; 8], flags: u32, data: &[u8], length: usize) -> Vec<u8> {
    let v = compress3(key, &padded64(data), 0, data.len() as u32, flags);

    let bytes: Vec<u8> = v[..8].iter().flat_map(|word| word.to_le_bytes()).collect();

    bytes[..length].to_vec()
}

fn key_bytes(key: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];

    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(key) {
        *chunk = word.to_le_bytes();
    }

    bytes
}

// The references against the library, whichever code its dispatch runs.
fn references_match_library(inputs: &mut Inputs) {
    for length in lengths() {
        let data = random(inputs, length);

        let key = random(inputs, 1 + length % 64);

        for size in [1, 20, 32, 64] {
            let h = start64(size, &[], &[]);

            let mut out = vec![0; size];

            crate::blake2::digest(&h, &data, &mut out);

            assert_eq!(out, rfc(&h, &[], &data, size), "BLAKE2b {length} {size}");

            crate::blake2::mac(&h, &key, &data, &mut out);

            assert_eq!(
                out,
                rfc(&h, &key, &data, size),
                "BLAKE2b MAC {length} {size}"
            );
        }

        for size in [1, 16, 32] {
            let h = start32(size, &[], &[]);

            let key = &key[..1 + length % 32];

            let mut out = vec![0; size];

            crate::blake2::digest(&h, &data, &mut out);

            assert_eq!(out, rfc(&h, &[], &data, size), "BLAKE2s {length} {size}");

            crate::blake2::mac(&h, key, &data, &mut out);

            assert_eq!(
                out,
                rfc(&h, key, &data, size),
                "BLAKE2s MAC {length} {size}"
            );
        }

        if length <= 64 {
            let mut out = [0; 32];

            crate::blake3::digest(&data, &mut out);

            let flags = CHUNK_START | CHUNK_END | ROOT;

            assert_eq!(
                out[..],
                digest1(&IV_256, flags, &data, 32),
                "BLAKE3 {length}"
            );

            let words: [u32; 8] = core::array::from_fn(|_| inputs.next() as u32);

            crate::blake3::keyed_hash(&key_bytes(&words), &data, &mut out);

            let expected = digest1(&words, flags | KEYED_HASH, &data, 32);

            assert_eq!(out[..], expected, "BLAKE3 keyed {length}");
        }
    }
}

// Every kernel of the tier against the references.
//
// SAFETY: the caller passes kernels whose instructions the CPU has and whose registers the
// operating system saves.
#[allow(unsafe_code)]
unsafe fn kernels_match(kernels: &Kernels, inputs: &mut Inputs, tier: &str) {
    for length in lengths() {
        let data = random(inputs, length);

        let words: [u32; 8] = core::array::from_fn(|_| inputs.next() as u32);

        let base = match length % 3 {
            0 => 0,
            1 => u128::from(u64::MAX) - 200,
            _ => u128::from(inputs.next()),
        };

        for keyed in [false, true] {
            let key = if keyed {
                random(inputs, 1 + length % 64)
            } else {
                Vec::new()
            };

            // BLAKE2b's process kernel, with a final block and without one.
            for final_block in [true, false] {
                let mut h = start64(64, &[], &[]);

                if keyed {
                    h[0] ^= u64::key_length(key.len());
                }

                let plan = plan(128, &key, &data, base, final_block);

                let mut expected = h;

                process(&mut expected, &plan, base);

                let first = plan.first.as_deref().map(block_words::<u64>);

                let last = plan.last.as_ref().map(|(b, t)| (block_words::<u64>(b), *t));

                // SAFETY: as for kernels_match, here and below.
                unsafe {
                    (kernels.blake2b)(
                        &mut h,
                        first.as_ref(),
                        plan.blocks.as_chunks::<128>().0,
                        base,
                        last.as_ref().map(|(m, t)| (m, *t)),
                    )
                };

                assert_eq!(
                    state_bytes(&h),
                    state_bytes(&expected),
                    "{tier} blake2b {length} keyed {keyed} final {final_block}"
                );
            }

            // BLAKE2b's one-call digest and MAC, from the unkeyed chaining value.
            for size in [1, 7, 20, 32, 33, 48, 64] {
                let h = start64(size, &[], &[]);

                let mut out = vec![0; size];

                unsafe { (kernels.blake2b_digest)(&h, &key, &data, &mut out) };

                assert_eq!(
                    out,
                    rfc(&h, &key, &data, size),
                    "{tier} blake2b digest {length} keyed {keyed} size {size}"
                );
            }

            // BLAKE2s's kernel into h, and into out with h kept.
            let key = &key[..key.len().min(1 + length % 32)];

            for final_block in [true, false] {
                let size = [1, 16, 20, 31, 32][length % 5];

                let mut h = start32(size, &[], &[]);

                if keyed {
                    h[0] ^= u32::key_length(key.len());
                }

                let start = h;

                let base = base as u64 as u128;

                let plan = plan(64, key, &data, base, final_block);

                let mut expected = h;

                process(&mut expected, &plan, base);

                let first: Option<[u8; 64]> = plan.first.as_deref().map(padded64);

                let last = plan.last.as_ref().map(|(b, t)| (padded64(b), *t as u64));

                let blocks = plan.blocks.as_chunks::<64>().0;

                unsafe {
                    (kernels.blake2s)(
                        &mut h,
                        first.as_ref(),
                        blocks,
                        last.as_ref().map(|(b, t)| (b, *t)),
                        base as u64,
                        None,
                    )
                };

                assert_eq!(
                    state_bytes(&h),
                    state_bytes(&expected),
                    "{tier} blake2s {length} keyed {keyed} final {final_block}"
                );

                if final_block {
                    let mut h = start;

                    let mut out = vec![0; size];

                    unsafe {
                        (kernels.blake2s)(
                            &mut h,
                            first.as_ref(),
                            blocks,
                            last.as_ref().map(|(b, t)| (b, *t)),
                            base as u64,
                            Some(&mut out),
                        )
                    };

                    assert_eq!(
                        out,
                        state_bytes(&expected)[..size],
                        "{tier} blake2s out {length} keyed {keyed} size {size}"
                    );

                    assert_eq!(
                        state_bytes(&h),
                        state_bytes(&start),
                        "{tier} blake2s h kept"
                    );
                }
            }

            // BLAKE3: the chain of the message's blocks, a partial one last.
            let (cv, flags) = if keyed {
                (words, KEYED_HASH)
            } else {
                (IV_256, 0)
            };

            let counter = base as u64;

            let (blocks, tail) = data.as_chunks::<64>();

            let tail_block = padded64(tail);

            let edges = [CHUNK_START, if tail.is_empty() { CHUNK_END } else { 0 }];

            let last_flags = flags | CHUNK_END | if blocks.is_empty() { CHUNK_START } else { 0 };

            let last = (!tail.is_empty()).then_some((&tail_block, tail.len() as u32, last_flags));

            let mut expected = cv;

            for (i, block) in blocks.iter().enumerate() {
                let mut f = flags;

                if i == 0 {
                    f |= edges[0];
                }

                if i + 1 == blocks.len() {
                    f |= edges[1];
                }

                let v = compress3(&expected, block, counter, 64, f);

                expected = *v.first_chunk().expect("sixteen words");
            }

            if let Some((block, length, f)) = last {
                let v = compress3(&expected, block, counter, length, f);

                expected = *v.first_chunk().expect("sixteen words");
            }

            let mut h = cv;

            unsafe { (kernels.chain)(&mut h, blocks, counter, flags, edges, last) };

            assert_eq!(h, expected, "{tier} blake3 chain {length} keyed {keyed}");

            if length > 64 {
                continue;
            }

            // One compression, and the digest of one block from the key's words and bytes.
            let block = padded64(&data);

            let mut out = [0; 16];

            unsafe { (kernels.compress)(&cv, &block, counter, length as u32, flags, &mut out) };

            assert_eq!(
                out,
                compress3(&cv, &block, counter, length as u32, flags),
                "{tier} blake3 compress {length} keyed {keyed}"
            );

            let root = flags | CHUNK_START | CHUNK_END | ROOT;

            for size in [1, 4, 7, 16, 31, 32] {
                let expected = digest1(&cv, root, &data, size);

                let mut out = vec![0; size];

                unsafe { (kernels.digest1_words)(&cv, root, &data, &mut out) };

                assert_eq!(
                    out, expected,
                    "{tier} blake3 digest1 {length} keyed {keyed}"
                );

                unsafe { (kernels.digest1_bytes)(&key_bytes(&cv), root, &data, &mut out) };

                assert_eq!(
                    out, expected,
                    "{tier} blake3 digest1 bytes {length} {keyed}"
                );
            }
        }
    }
}

#[test]
#[allow(unsafe_code)]
fn blake_vl_kernels_match_portable() {
    let mut inputs = Inputs::new(76);

    references_match_library(&mut inputs);

    let mut avx2_run = 0;

    if has(AVX2) {
        let avx2 = Kernels {
            blake2b: blake2::blake2b_avx2,
            blake2b_digest: blake2::blake2b_digest_avx2,
            blake2s: blake2::blake2s_avx2,
            chain: blake3::chain_avx2,
            compress: blake3::compress_avx2,
            digest1_words: blake3::digest1_avx2::<u32, 8>,
            digest1_bytes: blake3::digest1_avx2::<u8, 32>,
        };

        // SAFETY: the CPU has AVX2, and the operating system saves its registers.
        unsafe { kernels_match(&avx2, &mut inputs, "AVX2") };

        avx2_run = COUNT;
    }

    let mut run = 0;

    if has(AVX512) {
        let vl = Kernels {
            blake2b: blake2::blake2b_vl,
            blake2b_digest: blake2::blake2b_digest_vl,
            blake2s: blake2::blake2s_vl,
            chain: blake3::chain_vl,
            compress: blake3::compress_vl,
            digest1_words: blake3::digest1_vl::<u32, 8>,
            digest1_bytes: blake3::digest1_vl::<u8, 32>,
        };

        // SAFETY: the CPU has AVX-512F and AVX-512VL with AVX2, and the operating system saves
        // their registers.
        unsafe { kernels_match(&vl, &mut inputs, "AVX-512VL") };

        run = COUNT;
    }

    std::eprintln!("BLAKE VL kernels: {run} of {COUNT} run (AVX2 kernels: {avx2_run})");
}

// The cases of blake3_zmm_kernels_match_portable, hash16_zmm's and then xof16_zmm's.
const ZMM_COUNT: usize = 9;

// The counters of the sixteen lanes of table from counter on, one more each if increment.
fn lane_counters(table: &mut Table16, counter: u64, increment: bool) {
    for (l, (low, high)) in table.low.iter_mut().zip(table.high.iter_mut()).enumerate() {
        let lane = if increment {
            counter.wrapping_add(l as u64)
        } else {
            counter
        };

        *low = lane as u32;

        *high = (lane >> 32) as u32;
    }
}

// BLAKE3's 512-bit kernels on sixteen inputs and sixteen output blocks, called directly against
// compress3 on every CPU with AVX512, whatever zmm_lanes() chooses for the dispatch. The counters
// cross 2^32 and 2^64 within the sixteen lanes. CI's AVX-512 runners look for the line that the
// test prints.
#[test]
#[allow(unsafe_code)]
fn blake3_zmm_kernels_match_portable() {
    let mut inputs = Inputs::new(77);

    let mut run = 0;

    if has(AVX512) {
        for (blocks, counter, increment, flags) in [
            (1, 0, false, 0),
            (2, 0xFFFF_FFF8, true, KEYED_HASH),
            (3, 5, true, 0),
            (15, u64::MAX - 7, true, KEYED_HASH),
            (16, 0, false, 0),
        ] {
            let words: [u32; 16] = block_words(&random(&mut inputs, 32));

            let key: [u32; 8] = core::array::from_fn(|i| words[i]);

            let data = random(&mut inputs, 16 * 64 * blocks);

            let mut table = Table16::new();

            lane_counters(&mut table, counter, increment);

            table.flags[..blocks].fill(flags);

            table.flags[0] |= CHUNK_START;

            table.flags[blocks - 1] |= CHUNK_END;

            let mut out = [[0; 32]; 16];

            // SAFETY: the CPU has AVX-512F and AVX-512VL, and the operating system saves their
            // registers; 1 <= blocks <= 16, and data holds sixteen inputs of `blocks` blocks.
            unsafe { hash16_zmm(data.as_ptr(), blocks, &key, &table, &mut out) };

            for (l, got) in out.iter().enumerate() {
                let lane = if increment {
                    counter.wrapping_add(l as u64)
                } else {
                    counter
                };

                let mut cv = key;

                let input = &data[64 * blocks * l..][..64 * blocks];

                for (b, block) in input.as_chunks::<64>().0.iter().enumerate() {
                    let v = compress3(&cv, block, lane, 64, table.flags[b]);

                    cv = core::array::from_fn(|i| v[i]);
                }

                assert_eq!(
                    *got,
                    key_bytes(&cv),
                    "hash16_zmm, {blocks} blocks, lane {l}"
                );
            }

            run += 1;
        }

        for (length, counter) in [(0, 0), (1, 0xFFFF_FFF0), (63, u64::MAX - 7), (64, 3)] {
            let words: [u32; 16] = block_words(&random(&mut inputs, 32));

            let cv: [u32; 8] = core::array::from_fn(|i| words[i]);

            let bytes = padded64(&random(&mut inputs, length as usize));

            let block: [u32; 16] = block_words(&bytes);

            let flags = ROOT | CHUNK_START | CHUNK_END | KEYED_HASH;

            let mut table = Table16::new();

            lane_counters(&mut table, counter, true);

            table.length = length;

            table.flags[0] = flags;

            let mut out = [[0; 64]; 16];

            // SAFETY: the CPU has AVX-512F and AVX-512VL, and the operating system saves their
            // registers.
            unsafe { xof16_zmm(&cv, &block, &table, &mut out) };

            for (l, got) in out.iter().enumerate() {
                let v = compress3(&cv, &bytes, counter.wrapping_add(l as u64), length, flags);

                let expected: Vec<u8> = v.iter().flat_map(|word| word.to_le_bytes()).collect();

                assert_eq!(
                    got[..],
                    expected[..],
                    "xof16_zmm, length {length}, block {l}"
                );
            }

            run += 1;
        }
    }

    std::eprintln!("BLAKE3 zmm kernels: {run} of {ZMM_COUNT} run");
}
