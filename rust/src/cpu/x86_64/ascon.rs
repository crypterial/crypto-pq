// The Ascon permutation on the scalar pipes built for BMI1 and BMI2: ANDN takes a complement and
// AND in one instruction and RORX rotates into another register, so the linear layer's two
// rotations of a word need no copies of it. The digest keeps the state in registers
// from one block to the next, without a call per permutation.

use crate::sha2::last_bytes;
use crate::wipe::wipe_unless_optimized;

const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

// crate::ascon's S-box layer after the round constant {c}, with the output word x2 complemented,
// which saves the NOT of the circuit there: x4 & !x3 is one ANDN. The complement passes through
// the linear layer, which XORs three rotations of a word, and the next round takes it into its
// constant. The fifteen operations of the circuit and two copies, the fewest that two-operand
// instructions allow: every input word has two uses or more, and so do both inputs of t3 = x1 ^ x2
// and of t0 | x1. Out: y0 in {x1}, y1 in {x3}, y2 in {t}, y3 in {x0} and y4 in {x4}; {x2} is free.
macro_rules! sbox {
    () => {
        concat!(
            "xor {x2}, {c}\n",
            "mov {v}, {x1}\n",
            "mov {u}, {x3}\n",
            "andn {t}, {x3}, {x4}\n",
            "xor {u}, {x4}\n",
            "xor {x4}, {x0}\n",
            "xor {v}, {x2}\n",
            "xor {x3}, {x2}\n",
            "or {x0}, {u}\n",
            "or {x1}, {x4}\n",
            "and {x2}, {v}\n",
            "or {x3}, {v}\n",
            "xor {x1}, {u}\n",
            "xor {t}, {v}\n",
            "xor {x0}, {v}\n",
            "xor {x3}, {x4}\n",
            "xor {x4}, {x1}\n",
            "xor {x1}, {x2}\n",
        )
    };
}

// One round in one block of assembly, so that no copy moves the state between registers (D-109):
// the S-box layer, then each word's x ^ ror(x, a) ^ ror(x, b) into a free register. x2's word goes
// first, as the next round needs it first, and x1's new word goes into {t}, whose register holds x1
// in the next round, so that every word has a free register to go to.
macro_rules! round {
    ($s:ident, $i:literal) => {{
        let x1 = $s[1];

        // SAFETY: arithmetic on registers only, with BMI1 and BMI2, which the callers of
        // permute_complemented enable; it reads and writes no memory and leaves the stack alone.
        #[allow(unsafe_code)]
        unsafe {
            core::arch::asm!(
                sbox!(),
                "rorx {x2}, {t}, 1",
                "rorx {u}, {t}, 6",
                "xor {x2}, {u}",
                "xor {x2}, {t}",
                "rorx {u}, {x4}, 7",
                "rorx {v}, {x4}, 41",
                "xor {x4}, {u}",
                "xor {x4}, {v}",
                "rorx {t}, {x3}, 61",
                "rorx {u}, {x3}, 39",
                "xor {t}, {u}",
                "xor {t}, {x3}",
                "rorx {x3}, {x0}, 10",
                "rorx {u}, {x0}, 17",
                "xor {x3}, {u}",
                "xor {x3}, {x0}",
                "rorx {x0}, {x1}, 19",
                "rorx {u}, {x1}, 28",
                "xor {x0}, {u}",
                "xor {x0}, {x1}",
                x0 = inout(reg) $s[0],
                x1 = inout(reg) x1 => _,
                x2 = inout(reg) $s[2],
                x3 = inout(reg) $s[3],
                x4 = inout(reg) $s[4],
                t = out(reg) $s[1],
                u = out(reg) _,
                v = out(reg) _,
                c = const !CONSTANTS[$i] as i64,
                options(pure, nomem, nostack),
            );
        }
    }};
}

// The rounds written out, so that each constant is an immediate (a loop of three rounds per step
// took 3 to 10% more time), on a state whose x2 is complemented before and after: each round
// takes the complement of its constant.
#[inline(always)]
fn permute_complemented(s: &mut [u64; 5]) {
    round!(s, 0);

    round!(s, 1);

    round!(s, 2);

    round!(s, 3);

    round!(s, 4);

    round!(s, 5);

    round!(s, 6);

    round!(s, 7);

    round!(s, 8);

    round!(s, 9);

    round!(s, 10);

    round!(s, 11);
}

#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn ascon_bmi(s: &mut [u64; 5]) {
    s[2] = !s[2];

    permute_complemented(s);

    s[2] = !s[2];
}

// The whole eight-byte blocks of data and its padded last block, absorbed into a state whose x2 is
// complemented.
#[inline(always)]
fn absorb(s: &mut [u64; 5], data: &[u8]) {
    let (blocks, tail) = data.as_chunks::<8>();

    for block in blocks {
        s[0] ^= u64::from_le_bytes(*block);

        permute_complemented(s);
    }

    s[0] ^= last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    permute_complemented(s);
}

// crate::ascon's absorb with the state in registers from the first block to the last: the block
// `first`, then data and its padding.
#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn absorb_bmi(s: &mut [u64; 5], first: u64, data: &[u8]) {
    let mut x = *s;

    x[0] ^= first;

    x[2] = !x[2];

    permute_complemented(&mut x);

    absorb(&mut x, data);

    x[2] = !x[2];

    *s = x;

    wipe_unless_optimized!(&mut x);
}

// crate::ascon's digest with the state in registers throughout and x2 complemented from the start
// state to the end: the whole eight-byte blocks of data, its padded last block, then out.len()
// bytes. The first output word needs no permutation, so the loop over the others has one branch,
// and the bytes of a partial word come from its register, not from an array of them (D-109). The
// state is an array indexed with constants only, register values under D-76.
#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn digest_bmi(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    let mut s = *start;

    s[2] = !s[2];

    absorb(&mut s, data);

    let (words, rest) = out.as_chunks_mut::<8>();

    if let Some((first, others)) = words.split_first_mut() {
        *first = s[0].to_le_bytes();

        for word in others {
            permute_complemented(&mut s);

            *word = s[0].to_le_bytes();
        }

        if !rest.is_empty() {
            permute_complemented(&mut s);
        }
    }

    let mut word = s[0];

    for byte in rest {
        *byte = word as u8;

        word >>= 8;
    }

    wipe_unless_optimized!(&mut s);
}

#[cfg(test)]
mod tests {
    // The S-box layer's instructions alone, with no constant, against the S-box table.
    #[target_feature(enable = "bmi1")]
    #[allow(unsafe_code)]
    fn sbox(s: &mut [u64; 5]) {
        let [x0, x1, x2, x3, x4] = *s;

        let (y0, y1, y2, y3, y4): (u64, u64, u64, u64, u64);

        // SAFETY: as in round, with BMI1, which the caller checks.
        unsafe {
            core::arch::asm!(
                sbox!(),
                x0 = inout(reg) x0 => y3,
                x1 = inout(reg) x1 => y0,
                x2 = inout(reg) x2 => _,
                x3 = inout(reg) x3 => y1,
                x4 = inout(reg) x4 => y4,
                t = out(reg) y2,
                u = out(reg) _,
                v = out(reg) _,
                c = const 0,
                options(pure, nomem, nostack),
            );
        }

        *s = [y0, y1, !y2, y3, y4];
    }

    #[test]
    fn sbox_matches_table() {
        if !std::is_x86_feature_detected!("bmi1") {
            return;
        }

        // SAFETY: the CPU has BMI1.
        #[allow(unsafe_code)]
        crate::ascon::check_sbox(|s| unsafe { sbox(s) });
    }
}
