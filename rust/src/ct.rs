use core::hint::black_box;

pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;

    for (x, y) in a.iter().zip(b) {
        difference = black_box(difference | (x ^ y));
    }

    difference == 0
}

// 0xFF when the equally long inputs match, 0 otherwise, without a branch on their contents.
pub(crate) fn equal_mask(a: &[u8], b: &[u8]) -> u8 {
    let mut difference = 0u8;

    for (x, y) in a.iter().zip(b) {
        difference = black_box(difference | (x ^ y));
    }

    (u16::from(difference).wrapping_sub(1) >> 8) as u8
}

// out = a where mask is 0xFF, b where it is 0.
pub(crate) fn select(mask: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let mask = black_box(mask);

    for ((target, x), y) in out.iter_mut().zip(a).zip(b) {
        *target = (x & mask) | (y & !mask);
    }
}
