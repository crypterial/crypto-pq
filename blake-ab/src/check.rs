// Cross-check: every length 0..=2048 and some large ones, each operation of new, main, the A/A copy
// and x against each other and against the reference rivals (blake2b_simd, blake2s_simd, blake3),
// one-shot and incremental in uneven pieces. Prints the count per operation, panics on a mismatch.
use crate::data;

fn lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=2048).collect();

    v.extend([4095, 4096, 4097, 8191, 8193, 16384, 16385, 65536, 65537, 100_003, 1 << 20, (1 << 20) + 65]);

    v
}

fn same(label: &str, n: usize, outs: &[(&str, Vec<u8>)]) {
    for (name, out) in &outs[1..] {
        assert_eq!(out, &outs[0].1, "{label} length {n}: {name} differs from {}", outs[0].0);
    }
}

// Pieces of 1, 7, 64, 65, 128, 129, 1000 bytes in turn.
fn pieces(d: &[u8]) -> Vec<&[u8]> {
    let sizes = [1, 7, 64, 65, 128, 129, 1000];

    let mut v = Vec::new();

    let mut rest = d;

    let mut i = 0;

    while !rest.is_empty() {
        let k = sizes[i % sizes.len()].min(rest.len());

        v.push(&rest[..k]);

        rest = &rest[k..];

        i += 1;
    }

    v
}

macro_rules! ours {
    ($f:ident) => {
        [
            ("new", $f!(cpq)),
            ("main", $f!(cpq_main)),
            ("aa", $f!(cpq_aa)),
        ]
    };
}

pub fn run() {
    let mut count = [0usize; 10];

    for n in lengths() {
        let d = data(n, (n % 251) as u8);

        let key64: Vec<u8> = (0..1 + n % 64).map(|i| (i as u8).wrapping_mul(29) ^ n as u8).collect();

        let key32: Vec<u8> = (0..1 + n % 32).map(|i| (i as u8).wrapping_mul(53) ^ (n >> 3) as u8).collect();

        let key3: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11) ^ (n >> 1) as u8);

        let xof_len = 1 + (n * 37) % 1500;

        let ctx = format!("blake-ab check context {}", n % 7);

        macro_rules! b2b512 {
            ($c:ident) => {{
                let mut o = vec![0; 64];

                $c::BLAKE2B_512.digest_into(&d, &mut o).unwrap();

                o
            }};
        }

        macro_rules! b2b512_inc {
            ($c:ident) => {{
                let mut h = $c::BLAKE2B_512.create();

                for p in pieces(&d) {
                    h.update(p);
                }

                h.digest()
            }};
        }

        macro_rules! b2b256 {
            ($c:ident) => {{
                let mut o = vec![0; 32];

                $c::BLAKE2B_256.digest_into(&d, &mut o).unwrap();

                o
            }};
        }

        macro_rules! b2b_mac {
            ($c:ident) => {{
                let mut o = vec![0; 64];

                $c::BLAKE2B_MAC.digest_into(&key64, &d, &mut o).unwrap();

                let mut m = $c::BLAKE2B_MAC.create(&key64).unwrap();

                for p in pieces(&d) {
                    m.update(p);
                }

                let mut o2 = vec![0; 64];

                m.digest_into(&mut o2).unwrap();

                assert_eq!(o, o2, "blake2b-mac incremental length {n}");

                o
            }};
        }

        macro_rules! b2s256 {
            ($c:ident) => {{
                let mut o = vec![0; 32];

                $c::BLAKE2S_256.digest_into(&d, &mut o).unwrap();

                let mut h = $c::BLAKE2S_256.create();

                for p in pieces(&d) {
                    h.update(p);
                }

                assert_eq!(o, h.digest(), "blake2s incremental length {n}");

                o
            }};
        }

        macro_rules! b2s_mac {
            ($c:ident) => {{
                let mut o = vec![0; 32];

                $c::BLAKE2S_MAC.digest_into(&key32, &d, &mut o).unwrap();

                let mut m = $c::BLAKE2S_MAC.create(&key32).unwrap();

                for p in pieces(&d) {
                    m.update(p);
                }

                let mut o2 = vec![0; 32];

                m.digest_into(&mut o2).unwrap();

                assert_eq!(o, o2, "blake2s-mac incremental length {n}");

                o
            }};
        }

        macro_rules! b3 {
            ($c:ident) => {{
                let mut o = vec![0; 32];

                $c::BLAKE3_256.digest_into(&d, &mut o).unwrap();

                let mut h = $c::BLAKE3_256.create();

                for p in pieces(&d) {
                    h.update(p);
                }

                assert_eq!(o, h.digest(), "blake3 incremental length {n}");

                o
            }};
        }

        macro_rules! b3_keyed {
            ($c:ident) => {{
                let mut o = vec![0; 32];

                $c::BLAKE3_MAC.digest_into(&key3, &d, &mut o).unwrap();

                o
            }};
        }

        macro_rules! b3_derive {
            ($c:ident) => {{
                let mut o = vec![0; 32 + n % 97];

                $c::BLAKE3_KDF.derive_into(&d, &mut o, &$c::KdfOptions::default().with_info(ctx.as_bytes())).unwrap();

                o
            }};
        }

        macro_rules! b3_xof {
            ($c:ident) => {{
                let mut o = vec![0; xof_len];

                $c::BLAKE3.digest_into(&d, &mut o).unwrap();

                o
            }};
        }

        let mut v = ours!(b2b512).to_vec();

        v.push(("blake2b_simd", blake2b_simd::blake2b(&d).as_bytes().to_vec()));

        v.extend(ours!(b2b512_inc));

        same("blake2b-512", n, &v);

        count[0] += 1;

        let mut v = ours!(b2b256).to_vec();

        v.push(("blake2b_simd", blake2b_simd::Params::new().hash_length(32).hash(&d).as_bytes().to_vec()));

        same("blake2b-256", n, &v);

        count[1] += 1;

        let mut v = ours!(b2b_mac).to_vec();

        v.push(("blake2b_simd", blake2b_simd::Params::new().key(&key64).hash(&d).as_bytes().to_vec()));

        same("blake2b-mac", n, &v);

        count[2] += 1;

        let mut v = ours!(b2s256).to_vec();

        v.push(("blake2s_simd", blake2s_simd::blake2s(&d).as_bytes().to_vec()));

        same("blake2s-256", n, &v);

        count[3] += 1;

        let mut v = ours!(b2s_mac).to_vec();

        v.push(("blake2s_simd", blake2s_simd::Params::new().key(&key32).hash(&d).as_bytes().to_vec()));

        same("blake2s-mac", n, &v);

        count[4] += 1;

        let mut v = ours!(b3).to_vec();

        v.push(("blake3", blake3::hash(&d).as_bytes().to_vec()));

        same("blake3", n, &v);

        count[5] += 1;

        let mut v = ours!(b3_keyed).to_vec();

        v.push(("blake3", blake3::keyed_hash(&key3, &d).as_bytes().to_vec()));

        same("blake3-keyed", n, &v);

        count[6] += 1;

        let mut v = ours!(b3_derive).to_vec();

        let mut o = vec![0; 32 + n % 97];

        let mut kdf = blake3::Hasher::new_derive_key(&ctx);

        kdf.update(&d);

        kdf.finalize_xof().fill(&mut o);

        v.push(("blake3", o));

        same("blake3-derive", n, &v);

        count[7] += 1;

        let mut v = ours!(b3_xof).to_vec();

        let mut o = vec![0; xof_len];

        let mut h = blake3::Hasher::new();

        h.update(&d);

        h.finalize_xof().fill(&mut o);

        v.push(("blake3", o));

        same("blake3-xof", n, &v);

        count[8] += 1;
    }

    // Extended output past many blocks, read in uneven pieces, from short inputs.
    for n in [0usize, 1, 63, 64, 65, 1024, 1025] {
        let d = data(n, 77);

        let mut expect = vec![0; 20_000];

        let mut h = blake3::Hasher::new();

        h.update(&d);

        h.finalize_xof().fill(&mut expect);

        macro_rules! reader {
            ($c:ident) => {{
                let mut x = $c::BLAKE3.create();

                x.update(&d).unwrap();

                let mut got = Vec::new();

                let mut k = 1;

                while got.len() < expect.len() {
                    let take = k.min(expect.len() - got.len());

                    got.extend(x.read(take).unwrap());

                    k = k * 3 + 1;
                }

                got
            }};
        }

        let mut v = vec![("blake3", expect.clone())];

        v.extend(ours!(reader));

        same("blake3-xof-reader", n, &v);

        count[9] += 1;
    }


    println!(
        "CHECK OK: blake2b-512 {} blake2b-256 {} blake2b-mac {} blake2s-256 {} blake2s-mac {} blake3 {} keyed {} derive {} xof {} xof-reader {}",
        count[0], count[1], count[2], count[3], count[4], count[5], count[6], count[7], count[8], count[9]
    );
}
