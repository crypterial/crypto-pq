pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;

    for (x, y) in a.iter().zip(b) {
        difference = core::hint::black_box(difference | (x ^ y));
    }

    difference == 0
}
