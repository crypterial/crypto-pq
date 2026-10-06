mod vectors;

use crypto_pq::{ASCON_CXOF128, ASCON_HASH256, ASCON_XOF128, Error, XofAlgorithm, XofOptions};
use vectors::{records, unhex};

// Uneven sizes reach every buffering path: empty updates, partial words and whole words.
const PIECES: [usize; 7] = [0, 1, 7, 8, 9, 3, 16];

fn pieces(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();

    let mut offset = 0;

    for size in PIECES.iter().cycle() {
        if offset >= data.len() {
            break;
        }

        let end = (offset + size).min(data.len());

        out.push(&data[offset..end]);

        offset = end;
    }

    out
}

fn check_xof(algorithm: XofAlgorithm, data: &[u8], expected: &[u8], context: &str) {
    assert_eq!(
        algorithm.digest(data, expected.len()),
        expected,
        "{context}"
    );

    let mut xof = algorithm.create();

    for piece in pieces(data) {
        xof.update(piece);
    }

    let mut out = Vec::new();

    for piece in pieces(expected) {
        out.extend(xof.read(piece.len()));
    }

    assert_eq!(out, expected, "{context} streamed");
}

// The designers' KATs (ascon-c), which match the final SP 800-232: 1025 hashes and XOF outputs of
// 0 to 1024 bytes, and 1089 CXOF outputs over 0 to 32 bytes of message and customization.
#[test]
fn designers_kats() {
    let mut tested = 0;

    for (_, record) in records("ascon/LWC_HASH_KAT_128_256.txt", "MD") {
        let data = unhex(&record["Msg"]);

        let expected = unhex(&record["MD"]);

        let context = format!("Ascon-Hash256 Count = {}", record["Count"]);

        assert_eq!(ASCON_HASH256.digest(&data), expected, "{context}");

        let mut hasher = ASCON_HASH256.create();

        for piece in pieces(&data) {
            hasher.update(piece);
        }

        assert_eq!(hasher.digest(), expected, "{context} streamed");

        tested += 1;
    }

    for (_, record) in records("ascon/LWC_XOF_KAT_128_512.txt", "MD") {
        check_xof(
            ASCON_XOF128,
            &unhex(&record["Msg"]),
            &unhex(&record["MD"]),
            &format!("Ascon-XOF128 Count = {}", record["Count"]),
        );

        tested += 1;
    }

    for (_, record) in records("ascon/LWC_CXOF_KAT_128_512.txt", "MD") {
        let customization = unhex(&record["Z"]);

        let algorithm = ASCON_CXOF128
            .configure(&XofOptions {
                customization: &customization,
            })
            .unwrap();

        check_xof(
            algorithm,
            &unhex(&record["Msg"]),
            &unhex(&record["MD"]),
            &format!("Ascon-CXOF128 Count = {}", record["Count"]),
        );

        tested += 1;
    }

    assert_eq!(tested, 1025 + 1025 + 1089);
}

// The ACVP SP 800-232 tests whose lengths are whole bytes.
#[test]
fn acvp() {
    let mut counts = [0; 3];

    for (header, record) in records("acvp/Ascon.txt", "md") {
        let data = unhex(&record["msg"]);

        let expected = unhex(&record["md"]);

        let context = format!("{} tcId {}", header["parameterSet"], record["tcId"]);

        match header["parameterSet"].as_str() {
            "Ascon-Hash256" => {
                assert_eq!(ASCON_HASH256.digest(&data), expected, "{context}");

                counts[0] += 1;
            }
            "Ascon-XOF128" => {
                check_xof(ASCON_XOF128, &data, &expected, &context);

                counts[1] += 1;
            }
            "Ascon-CXOF128" => {
                let customization = unhex(&record["cs"]);

                let algorithm = ASCON_CXOF128
                    .configure(&XofOptions {
                        customization: &customization,
                    })
                    .unwrap();

                check_xof(algorithm, &data, &expected, &context);

                counts[2] += 1;
            }
            other => panic!("unknown parameter set {other}"),
        }
    }

    assert_eq!(counts, [12, 3, 1]);
}

// SP 800-232, 5.3: at most 2048 bits of customization; the empty one is the default.
#[test]
fn customization_limit() {
    let z = [0x5A; 257];

    let at_limit = ASCON_CXOF128
        .configure(&XofOptions {
            customization: &z[..256],
        })
        .unwrap();

    assert_ne!(at_limit.digest(b"", 32), ASCON_CXOF128.digest(b"", 32));

    assert_eq!(
        ASCON_CXOF128.configure(&XofOptions { customization: &z }),
        Err(Error::InvalidOption)
    );

    assert_eq!(
        at_limit.configure(&XofOptions::default()),
        Ok(ASCON_CXOF128)
    );

    assert_eq!(
        ASCON_XOF128.configure(&XofOptions {
            customization: b"x"
        }),
        Err(Error::InvalidOption)
    );

    assert_eq!(
        ASCON_XOF128.configure(&XofOptions::default()),
        Ok(ASCON_XOF128)
    );
}

#[test]
fn properties() {
    assert_eq!(ASCON_HASH256.name(), "Ascon-Hash256");

    assert_eq!(ASCON_HASH256.digest_size(), 32);

    assert_eq!(ASCON_XOF128.name(), "Ascon-XOF128");

    assert_eq!(ASCON_CXOF128.name(), "Ascon-CXOF128");

    // XOF outputs are prefixes of one another, and an empty one is allowed.
    assert_eq!(ASCON_XOF128.digest(b"abc", 0), Vec::<u8>::new());

    assert_eq!(
        ASCON_XOF128.digest(b"abc", 100)[..33],
        ASCON_XOF128.digest(b"abc", 33)
    );

    let mut hasher = ASCON_HASH256.create();

    hasher.update(b"abc");

    let first = hasher.digest();

    assert_eq!(hasher.digest(), first);

    hasher.update(b"def");

    assert_eq!(hasher.digest(), ASCON_HASH256.digest(b"abcdef"));
}

#[test]
#[should_panic(expected = "UNSUPPORTED")]
fn update_after_read() {
    let mut xof = ASCON_XOF128.create();

    xof.read(1);

    xof.update(b"x");
}
