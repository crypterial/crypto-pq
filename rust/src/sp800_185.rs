// NIST SP 800-185: cSHAKE (3) and KMAC (4) on whole bytes (7.2). The prefix block of the function
// name N and the customization S is absorbed once, when the algorithm is configured (7.1), and
// every computation starts from that state.

use crate::keccak::{self, Keccak, permute_const};

pub(crate) const SUFFIX: u8 = 0x04;

// left_encode and right_encode of x (2.3.1): its big-endian bytes, at least one, preceded or
// followed by their count.
pub(crate) struct Encoding {
    bytes: [u8; 17],
    length: usize,
}

impl Encoding {
    fn new(x: u128, left: bool) -> Self {
        let count = (16 - x.leading_zeros() as usize / 8).max(1);

        let value = &x.to_be_bytes()[16 - count..];

        let mut bytes = [0; 17];

        if left {
            bytes[0] = count as u8;

            bytes[1..=count].copy_from_slice(value);
        } else {
            bytes[..count].copy_from_slice(value);

            bytes[count] = count as u8;
        }

        Self {
            bytes,
            length: count + 1,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

pub(crate) fn left_encode(x: u128) -> Encoding {
    Encoding::new(x, true)
}

pub(crate) fn right_encode(x: u128) -> Encoding {
    Encoding::new(x, false)
}

// The state after bytepad(encode_string(N) || encode_string(S), rate), or None when N and S are
// both empty, which makes cSHAKE equal to SHAKE (3.3). A prefix of one block, the usual case, is
// built in a buffer whose words are the state before its permutation; a longer one goes through
// the sponge.
pub(crate) fn prefix(rate: usize, name: &[u8], customization: &[u8]) -> Option<[u64; 25]> {
    if name.is_empty() && customization.is_empty() {
        return None;
    }

    let encodings = [
        left_encode(rate as u128),
        left_encode(8 * name.len() as u128),
        left_encode(8 * customization.len() as u128),
    ];

    let length = encodings.iter().map(|e| e.as_slice().len()).sum::<usize>()
        + name.len()
        + customization.len();

    if length <= rate {
        let mut block = [0; 200];

        let mut position = 0;

        for part in [
            encodings[0].as_slice(),
            encodings[1].as_slice(),
            name,
            encodings[2].as_slice(),
            customization,
        ] {
            block[position..position + part.len()].copy_from_slice(part);

            position += part.len();
        }

        let mut state = [0; 25];

        for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
            *lane = u64::from_le_bytes(*bytes);
        }

        keccak::permute_one(&mut state);

        return Some(state);
    }

    let mut engine = Keccak::new(rate, SUFFIX);

    engine.update(left_encode(rate as u128).as_slice());

    for string in [name, customization] {
        engine.update(left_encode(8 * string.len() as u128).as_slice());

        engine.update(string);
    }

    engine.pad_block();

    Some(engine.state())
}

// prefix(rate, "KMAC", "") at compile time: left_encode(rate), encode_string("KMAC") and
// encode_string(""), one block.
pub(crate) const fn kmac_prefix(rate: usize) -> [u64; 25] {
    let bytes = [1, rate as u8, 1, 32, b'K', b'M', b'A', b'C', 1, 0];

    let mut state = [0; 25];

    let mut i = 0;

    while i < bytes.len() {
        state[i / 8] ^= (bytes[i] as u64) << (8 * (i % 8));

        i += 1;
    }

    permute_const(&mut state);

    state
}

// The KMAC sponge after its key: the prefix of N = "KMAC" and S, then bytepad(encode_string(K),
// rate) (4.3). The state holds the key from here on; dropping the engine wipes it.
pub(crate) fn keyed(prefix: &[u64; 25], rate: usize, key: &[u8]) -> Keccak {
    let mut engine = Keccak::resume(*prefix, rate, SUFFIX);

    engine.update(left_encode(rate as u128).as_slice());

    engine.update(left_encode(8 * key.len() as u128).as_slice());

    engine.update(key);

    engine.pad_block();

    engine
}

// right_encode(L) with L in bits, or right_encode(0) for KMACXOF (4.3.1).
pub(crate) fn output_length(xof: bool, length: usize) -> Encoding {
    right_encode(if xof { 0 } else { 8 * length as u128 })
}

// KMAC or KMACXOF of data under key, out.len() bytes.
pub(crate) fn kmac(
    prefix: &[u64; 25],
    rate: usize,
    key: &[u8],
    data: &[u8],
    xof: bool,
    out: &mut [u8],
) {
    let mut engine = keyed(prefix, rate, key);

    engine.update(data);

    engine.update(output_length(xof, out.len()).as_slice());

    engine.read(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    // SP 800-185, 2.3.1, and values at the byte boundaries.
    #[test]
    fn encodings() {
        for (x, left, right) in [
            (0, &[1, 0][..], &[0, 1][..]),
            (1, &[1, 1], &[1, 1]),
            (255, &[1, 255], &[255, 1]),
            (256, &[2, 1, 0], &[1, 0, 2]),
            (168, &[1, 168], &[168, 1]),
            (65_536, &[3, 1, 0, 0], &[1, 0, 0, 3]),
        ] {
            assert_eq!(left_encode(x).as_slice(), left, "{x}");

            assert_eq!(right_encode(x).as_slice(), right, "{x}");
        }

        let max = left_encode(u128::MAX);

        assert_eq!(max.as_slice()[0], 16);

        assert_eq!(max.as_slice().len(), 17);

        assert_eq!(right_encode(u128::MAX).as_slice()[16], 16);
    }

    // The one-block construction against the sponge, for names and customizations whose prefix
    // ends inside, at and after the end of a block.
    #[test]
    fn prefixes_match_the_sponge() {
        let bytes = [0x5A; 400];

        for rate in [168, 136] {
            for name in [&b""[..], b"KMAC", b"TupleHash"] {
                for length in (0..300).step_by(7).chain(rate - 12..rate + 4) {
                    let customization = &bytes[..length];

                    let mut engine = Keccak::new(rate, SUFFIX);

                    engine.update(left_encode(rate as u128).as_slice());

                    for string in [name, customization] {
                        engine.update(left_encode(8 * string.len() as u128).as_slice());

                        engine.update(string);
                    }

                    engine.pad_block();

                    let expected = (!name.is_empty() || length > 0).then(|| engine.state());

                    assert_eq!(
                        prefix(rate, name, customization),
                        expected,
                        "rate {rate}, name {name:?}, length {length}"
                    );
                }
            }
        }
    }

    #[test]
    fn compile_time_prefixes_match() {
        for rate in [168, 136] {
            assert_eq!(Some(kmac_prefix(rate)), prefix(rate, b"KMAC", b""));
        }
    }
}
