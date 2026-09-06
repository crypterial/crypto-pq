//! NIST ACVP vectors for FIPS 203 (final), from usnistgov/ACVP-Server. See vectors/SOURCES.md.

use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    function: Option<String>,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: Option<String>,
    z: Option<String>,
    m: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    c: Option<String>,
    k: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

fn load(name: &str) -> VectorFile {
    let path = format!("{}/../../vectors/acvp/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn bytes(field: &Option<String>) -> Vec<u8> {
    hex::decode(field.as_deref().unwrap()).unwrap()
}

fn seed(field: &Option<String>) -> [u8; 32] {
    bytes(field).try_into().unwrap()
}

macro_rules! acvp_suite {
    ($module:ident, $set:literal) => {
        mod $module {
            use super::*;
            use crypto_pq_ml_kem::$module::*;

            #[test]
            fn key_generation() {
                let file = load("ML-KEM-keyGen-FIPS203.internalProjection.json");
                let mut count = 0;
                for group in file.test_groups.iter().filter(|g| g.parameter_set == $set) {
                    for t in &group.tests {
                        let (dk, ek) = keypair_from_seed(&seed(&t.d), &seed(&t.z));
                        assert_eq!(ek.as_bytes()[..], bytes(&t.ek)[..], "tcId {}", t.tc_id);
                        assert_eq!(dk.as_bytes()[..], bytes(&t.dk)[..], "tcId {}", t.tc_id);
                        count += 1;
                    }
                }
                assert_eq!(count, 25);
            }

            #[test]
            fn encapsulation_and_decapsulation() {
                let file = load("ML-KEM-encapDecap-FIPS203.internalProjection.json");
                let mut counts = [0usize; 4];
                for group in file.test_groups.iter().filter(|g| g.parameter_set == $set) {
                    match group.function.as_deref().unwrap() {
                        "encapsulation" => {
                            for t in &group.tests {
                                let ek = EncapsulationKey::from_bytes(&bytes(&t.ek)).unwrap();
                                let (k, c) = ek.encapsulate_with_seed(&seed(&t.m));
                                assert_eq!(c.as_bytes()[..], bytes(&t.c)[..], "tcId {}", t.tc_id);
                                assert_eq!(k.as_bytes()[..], bytes(&t.k)[..], "tcId {}", t.tc_id);
                                let dk = DecapsulationKey::from_bytes(&bytes(&t.dk)).unwrap();
                                assert_eq!(dk.encapsulation_key(), ek);
                                assert_eq!(
                                    dk.decapsulate(&c).as_bytes()[..],
                                    bytes(&t.k)[..],
                                    "tcId {}",
                                    t.tc_id
                                );
                                counts[0] += 1;
                            }
                        }
                        "decapsulation" => {
                            for t in &group.tests {
                                let dk = DecapsulationKey::from_bytes(&bytes(&t.dk)).unwrap();
                                let c = Ciphertext::from_bytes(&bytes(&t.c)).unwrap();
                                assert_eq!(
                                    dk.decapsulate(&c).as_bytes()[..],
                                    bytes(&t.k)[..],
                                    "tcId {}",
                                    t.tc_id
                                );
                                counts[1] += 1;
                            }
                        }
                        "encapsulationKeyCheck" => {
                            for t in &group.tests {
                                let accepted = EncapsulationKey::from_bytes(&bytes(&t.ek)).is_ok();
                                assert_eq!(accepted, t.test_passed.unwrap(), "tcId {}", t.tc_id);
                                counts[2] += 1;
                            }
                        }
                        "decapsulationKeyCheck" => {
                            for t in &group.tests {
                                let accepted = DecapsulationKey::from_bytes(&bytes(&t.dk)).is_ok();
                                assert_eq!(accepted, t.test_passed.unwrap(), "tcId {}", t.tc_id);
                                counts[3] += 1;
                            }
                        }
                        other => panic!("unexpected function {other}"),
                    }
                }
                assert_eq!(counts, [25, 10, 10, 10]);
            }
        }
    };
}

acvp_suite!(ml_kem_512, "ML-KEM-512");
acvp_suite!(ml_kem_768, "ML-KEM-768");
acvp_suite!(ml_kem_1024, "ML-KEM-1024");
