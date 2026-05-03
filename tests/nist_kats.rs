// official nist acvp test vectors for ml-kem (fips 203).
// vectors copied from rustcrypto/KEMs/ml-kem/tests/, which in turn pulls
// them from https://github.com/usnistgov/ACVP-Server.
//
// totals: 75 keygen + 75 encap + 30 decap = 180 official test cases.

use mlkem::{
    Ciphertext1024, Ciphertext512, Ciphertext768, MlKem1024, MlKem512, MlKem768, PublicKey1024,
    PublicKey512, PublicKey768, SecretKey1024, SecretKey512, SecretKey768,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

fn read_json(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/nist-kats")
        .join(name);
    let bytes = fs::read(&p).expect("missing kat file");
    serde_json::from_slice(&bytes).expect("invalid json")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn nist_keygen_kats() {
    let v = read_json("key-gen.json");
    let mut count = 0;
    for g in v["testGroups"].as_array().unwrap() {
        let p = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let d_bytes = h(&t["d"]);
            let z_bytes = h(&t["z"]);
            let ek = h(&t["ek"]);
            let dk = h(&t["dk"]);
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(&d_bytes);
            seed[32..].copy_from_slice(&z_bytes);

            match p {
                "ML-KEM-512" => {
                    let (pk, sk) = MlKem512::keygen_deterministic(&seed);
                    assert_eq!(
                        pk.as_bytes().as_slice(),
                        ek.as_slice(),
                        "{} keygen ek tcId={}",
                        p,
                        t["tcId"]
                    );
                    assert_eq!(
                        sk.as_bytes().as_slice(),
                        dk.as_slice(),
                        "{} keygen dk tcId={}",
                        p,
                        t["tcId"]
                    );
                }
                "ML-KEM-768" => {
                    let (pk, sk) = MlKem768::keygen_deterministic(&seed);
                    assert_eq!(
                        pk.as_bytes().as_slice(),
                        ek.as_slice(),
                        "{} keygen ek tcId={}",
                        p,
                        t["tcId"]
                    );
                    assert_eq!(
                        sk.as_bytes().as_slice(),
                        dk.as_slice(),
                        "{} keygen dk tcId={}",
                        p,
                        t["tcId"]
                    );
                }
                "ML-KEM-1024" => {
                    let (pk, sk) = MlKem1024::keygen_deterministic(&seed);
                    assert_eq!(
                        pk.as_bytes().as_slice(),
                        ek.as_slice(),
                        "{} keygen ek tcId={}",
                        p,
                        t["tcId"]
                    );
                    assert_eq!(
                        sk.as_bytes().as_slice(),
                        dk.as_slice(),
                        "{} keygen dk tcId={}",
                        p,
                        t["tcId"]
                    );
                }
                _ => panic!("unknown parameter set {}", p),
            }
            count += 1;
        }
    }
    assert_eq!(count, 75, "expected 75 keygen vectors, got {}", count);
}

#[test]
fn nist_encap_decap_kats() {
    let v = read_json("encap-decap.json");
    let mut encap_count = 0usize;
    let mut decap_count = 0usize;

    for g in v["testGroups"].as_array().unwrap() {
        let p = g["parameterSet"].as_str().unwrap();
        let func = g["function"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            match func {
                "encapsulation" => {
                    let ek = h(&t["ek"]);
                    let m = h(&t["m"]);
                    let c = h(&t["c"]);
                    let k_expected = h(&t["k"]);
                    let mut m_arr = [0u8; 32];
                    m_arr.copy_from_slice(&m);

                    match p {
                        "ML-KEM-512" => {
                            let pk = PublicKey512::from_bytes(&ek.as_slice().try_into().unwrap());
                            let (ct, ss) = MlKem512::encapsulate_deterministic(&pk, &m_arr);
                            assert_eq!(
                                ct.as_bytes().as_slice(),
                                c.as_slice(),
                                "{} encap ct tcId={}",
                                p,
                                t["tcId"]
                            );
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} encap ss tcId={}",
                                p,
                                t["tcId"]
                            );
                        }
                        "ML-KEM-768" => {
                            let pk = PublicKey768::from_bytes(&ek.as_slice().try_into().unwrap());
                            let (ct, ss) = MlKem768::encapsulate_deterministic(&pk, &m_arr);
                            assert_eq!(
                                ct.as_bytes().as_slice(),
                                c.as_slice(),
                                "{} encap ct tcId={}",
                                p,
                                t["tcId"]
                            );
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} encap ss tcId={}",
                                p,
                                t["tcId"]
                            );
                        }
                        "ML-KEM-1024" => {
                            let pk = PublicKey1024::from_bytes(&ek.as_slice().try_into().unwrap());
                            let (ct, ss) = MlKem1024::encapsulate_deterministic(&pk, &m_arr);
                            assert_eq!(
                                ct.as_bytes().as_slice(),
                                c.as_slice(),
                                "{} encap ct tcId={}",
                                p,
                                t["tcId"]
                            );
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} encap ss tcId={}",
                                p,
                                t["tcId"]
                            );
                        }
                        _ => panic!("unknown {}", p),
                    }
                    encap_count += 1;
                }
                "decapsulation" => {
                    let dk = h(&g["dk"]);
                    let c = h(&t["c"]);
                    let k_expected = h(&t["k"]);

                    match p {
                        "ML-KEM-512" => {
                            let sk = SecretKey512::from_bytes(&dk.as_slice().try_into().unwrap());
                            let ct = Ciphertext512::from_bytes(&c.as_slice().try_into().unwrap());
                            let ss = MlKem512::decapsulate(&sk, &ct);
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} decap tcId={} reason={}",
                                p,
                                t["tcId"],
                                t["reason"]
                            );
                        }
                        "ML-KEM-768" => {
                            let sk = SecretKey768::from_bytes(&dk.as_slice().try_into().unwrap());
                            let ct = Ciphertext768::from_bytes(&c.as_slice().try_into().unwrap());
                            let ss = MlKem768::decapsulate(&sk, &ct);
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} decap tcId={} reason={}",
                                p,
                                t["tcId"],
                                t["reason"]
                            );
                        }
                        "ML-KEM-1024" => {
                            let sk = SecretKey1024::from_bytes(&dk.as_slice().try_into().unwrap());
                            let ct = Ciphertext1024::from_bytes(&c.as_slice().try_into().unwrap());
                            let ss = MlKem1024::decapsulate(&sk, &ct);
                            assert_eq!(
                                ss.as_bytes().as_slice(),
                                k_expected.as_slice(),
                                "{} decap tcId={} reason={}",
                                p,
                                t["tcId"],
                                t["reason"]
                            );
                        }
                        _ => panic!("unknown {}", p),
                    }
                    decap_count += 1;
                }
                _ => panic!("unknown function {}", func),
            }
        }
    }
    assert_eq!(encap_count, 75, "expected 75 encap vectors");
    assert_eq!(decap_count, 30, "expected 30 decap vectors");
}
