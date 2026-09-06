//! C2SP/CCTV ML-KEM vectors that do not depend on key generation: bad encapsulation keys
//! (modulus check) and the strcmp edge case in implicit rejection. See vectors/SOURCES.md
//! for why the key-generation vectors of that collection are not used.

use std::collections::HashMap;
use std::fs;
use std::io::Read;

fn path(name: &str) -> String {
    format!("{}/../../vectors/cctv/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn read_kv(name: &str) -> HashMap<String, String> {
    fs::read_to_string(path(name))
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn read_gz_lines(name: &str) -> Vec<String> {
    let file = fs::File::open(path(name)).unwrap();
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

macro_rules! cctv_suite {
    ($module:ident, $suffix:literal) => {
        mod $module {
            use super::*;
            use crypto_pq_ml_kem::$module::*;
            use crypto_pq_ml_kem::Error;

            #[test]
            fn strcmp_edge_case_in_implicit_rejection() {
                let kv = read_kv(concat!("strcmp-ML-KEM-", $suffix, ".txt"));
                let dk = DecapsulationKey::from_bytes(&hex::decode(&kv["dk"]).unwrap()).unwrap();
                let c = Ciphertext::from_bytes(&hex::decode(&kv["c"]).unwrap()).unwrap();
                assert_eq!(hex::encode(dk.decapsulate(&c).as_bytes()), kv["K"]);
            }

            #[test]
            fn every_out_of_range_coefficient_is_rejected() {
                let lines = read_gz_lines(concat!("modulus-ML-KEM-", $suffix, ".txt.gz"));
                assert!(lines.len() > 700);
                for (i, line) in lines.iter().enumerate() {
                    let ek = hex::decode(line).unwrap();
                    assert_eq!(ek.len(), ENCAPSULATION_KEY_LEN);
                    assert_eq!(
                        EncapsulationKey::from_bytes(&ek).unwrap_err(),
                        Error::InvalidEncapsulationKey,
                        "line {i}"
                    );
                }
            }
        }
    };
}

cctv_suite!(ml_kem_512, "512");
cctv_suite!(ml_kem_768, "768");
cctv_suite!(ml_kem_1024, "1024");
