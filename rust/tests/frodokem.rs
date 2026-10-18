mod vectors;

use crypto_pq::{
    EFRODOKEM_976_AES, EFRODOKEM_976_SHAKE, EFRODOKEM_1344_AES, EFRODOKEM_1344_SHAKE, Error,
    FRODOKEM_976_AES, FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE, KemAlgorithm,
    KeyFormat, KeyGenOptions, SHA_256, SHAKE256, hazmat,
};
use vectors::{parallel, records, unhex};

// The eight ISO sets with the sizes of draft-longa-cfrg-frodokem-03, Table 6: public key, private
// key, ciphertext and shared secret, then the draws of 7.1 and 7.2.
const SETS: [(KemAlgorithm, [usize; 6]); 8] = [
    (FRODOKEM_976_AES, [15632, 31296, 15792, 24, 88, 72]),
    (FRODOKEM_976_SHAKE, [15632, 31296, 15792, 24, 88, 72]),
    (FRODOKEM_1344_AES, [21520, 43088, 21696, 32, 112, 96]),
    (FRODOKEM_1344_SHAKE, [21520, 43088, 21696, 32, 112, 96]),
    (EFRODOKEM_976_AES, [15632, 31296, 15744, 24, 64, 24]),
    (EFRODOKEM_976_SHAKE, [15632, 31296, 15744, 24, 64, 24]),
    (EFRODOKEM_1344_AES, [21520, 43088, 21632, 32, 80, 32]),
    (EFRODOKEM_1344_SHAKE, [21520, 43088, 21632, 32, 80, 32]),
];

fn sha256(data: &[u8]) -> Vec<u8> {
    SHA_256.digest(data).to_vec()
}

// The rejection secret SHAKE256(c1 || c2 || salt || s) of a ciphertext under sk.
fn rejection(ciphertext: &[u8], sk: &[u8], size: usize) -> Vec<u8> {
    SHAKE256
        .digest(&[ciphertext, &sk[..size]].concat(), size)
        .unwrap()
}

// Every KAT entry of the reference implementation for the eight ISO sets: the key pair from the
// key generation draw, encapsulation with its draw, decapsulation, and the implicit rejection of
// the ciphertext with one bit flipped.
#[test]
fn known_answers() {
    let entries = records("frodokem/kat.txt", "ss");

    assert_eq!(entries.len(), 800);

    parallel(&entries, |(header, record)| {
        let name = &header["parameterSet"];

        let (algorithm, _) = SETS
            .iter()
            .find(|(algorithm, _)| algorithm.name() == name)
            .unwrap_or_else(|| panic!("unknown parameter set {name}"));

        let context = format!("{name} count {}", record["count"]);

        let seed = [
            unhex(&record["s"]),
            unhex(&record["seedSE"]),
            unhex(&record["z"]),
        ]
        .concat();

        let randomness = [
            unhex(&record["u"]),
            record.get("salt").map_or_else(Vec::new, |salt| unhex(salt)),
        ]
        .concat();

        let ss = unhex(&record["ss"]);

        let pair = hazmat::generate_kem_key_pair(*algorithm, &seed).expect("key pair");

        let pk = pair.public_key.export_key(KeyFormat::Raw).expect("export");

        let sk = pair.private_key.export_key(KeyFormat::Raw).expect("export");

        assert_eq!(sha256(&pk), unhex(&record["pkSha256"]), "{context} pk");

        assert_eq!(sha256(&sk), unhex(&record["skSha256"]), "{context} sk");

        let encapsulation = hazmat::encapsulate(&pair.public_key, &randomness).expect("encaps");

        assert_eq!(
            sha256(&encapsulation.ciphertext),
            unhex(&record["ctSha256"]),
            "{context} ct"
        );

        assert_eq!(
            *encapsulation.shared_secret, *ss,
            "{context} encapsulated ss"
        );

        let decapsulated = pair
            .private_key
            .decapsulate(&encapsulation.ciphertext)
            .expect("decaps");

        assert_eq!(*decapsulated, *ss, "{context} decapsulated ss");

        let mut changed = encapsulation.ciphertext.clone();

        let position = changed.len() / 3;

        changed[position] ^= 0x10;

        let rejected = pair.private_key.decapsulate(&changed).expect("decaps");

        assert_eq!(
            *rejected,
            *rejection(&changed, &sk, ss.len()),
            "{context} rejection"
        );
    });
}

// The public API of every set: fresh key pairs with the self-test, raw keys only, the exact
// lengths, the pkh check of private key import, and an altered S^T, which the import cannot see
// and which leads decapsulation to the implicit rejection.
#[test]
fn api() {
    for (algorithm, sizes) in SETS {
        let [
            public_size,
            private_size,
            ciphertext_size,
            secret_size,
            seed_size,
            randomness_size,
        ] = sizes;

        assert_eq!(algorithm.public_key_size(), public_size);

        assert_eq!(algorithm.ciphertext_size(), ciphertext_size);

        assert_eq!(algorithm.shared_secret_size(), secret_size);

        let pair = algorithm
            .generate_key_pair(&KeyGenOptions::default())
            .expect("key pair");

        let pk = pair.public_key.export_key(KeyFormat::Raw).expect("export");

        let sk = pair.private_key.export_key(KeyFormat::Raw).expect("export");

        assert_eq!((pk.len(), sk.len()), (public_size, private_size));

        assert_eq!(&sk[secret_size..secret_size + public_size], &pk[..]);

        for format in [KeyFormat::Der, KeyFormat::Pem] {
            assert_eq!(pair.public_key.export_key(format), Err(Error::Unsupported));

            assert_eq!(
                pair.private_key.export_key(format).err(),
                Some(Error::Unsupported)
            );

            assert_eq!(
                algorithm.import_public_key(&pk, format).err(),
                Some(Error::Unsupported)
            );

            assert_eq!(
                algorithm.import_private_key(&sk, format).err(),
                Some(Error::Unsupported)
            );
        }

        let public = algorithm
            .import_public_key(&pk, KeyFormat::Raw)
            .expect("import");

        let private = algorithm
            .import_private_key(&sk, KeyFormat::Raw)
            .expect("import");

        assert!(public == pair.public_key && private.public_key() == pair.public_key);

        assert_eq!(*private.export_key(KeyFormat::Raw).expect("export"), *sk);

        let encapsulation = public.encapsulate().expect("encaps");

        assert_eq!(encapsulation.ciphertext.len(), ciphertext_size);

        assert_eq!(
            *private
                .decapsulate(&encapsulation.ciphertext)
                .expect("decaps"),
            *encapsulation.shared_secret
        );

        for size in [0, seed_size, private_size - 1, private_size + 1] {
            assert_eq!(
                algorithm
                    .import_private_key(&vec![0; size], KeyFormat::Raw)
                    .err(),
                Some(Error::InvalidLength)
            );
        }

        for size in [0, public_size - 1, public_size + 1] {
            assert_eq!(
                algorithm
                    .import_public_key(&vec![0; size], KeyFormat::Raw)
                    .err(),
                Some(Error::InvalidLength)
            );
        }

        // A changed public key fails the pkh check, and a changed S^T, which passes it, the
        // pairwise test (SPEC 8.2.4 item 3).
        for position in [
            secret_size,
            secret_size + public_size - 1,
            private_size - 1,
            secret_size + public_size,
        ] {
            let mut changed = sk.to_vec();

            changed[position] ^= 1;

            assert_eq!(
                algorithm.import_private_key(&changed, KeyFormat::Raw).err(),
                Some(Error::InvalidPrivateKey)
            );
        }

        for size in [0, ciphertext_size - 1, ciphertext_size + 1] {
            assert_eq!(
                pair.private_key.decapsulate(&vec![0; size]).err(),
                Some(Error::InvalidLength)
            );
        }

        assert_eq!(
            hazmat::generate_kem_key_pair(algorithm, &vec![0; seed_size - 1]).err(),
            Some(Error::InvalidLength)
        );

        assert_eq!(
            hazmat::encapsulate(&pair.public_key, &vec![0; randomness_size + 1]).err(),
            Some(Error::InvalidLength)
        );
    }
}
