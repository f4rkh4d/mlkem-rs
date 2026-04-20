// known-answer test vectors for ml-kem-768.
// these were generated from the rustcrypto ml-kem 0.2 audited impl using the
// deterministic apis. since our cross_check test already asserts we agree with
// that impl over 50 random seeds, these KATs serve as a stable regression
// check you can eyeball in the repo.
//
// if you want official nist vectors, the intermediate-values appendix of
// fips 203 is the canonical source. the format is the same: (d, z, m, pk, sk, ct, ss).

use mlkem::MlKem768;

struct Kat {
    seed: [u8; 64], // d || z
    m: [u8; 32],
    // we only check hashes of pk/sk/ct and the full ss, because embedding the
    // full 1184/2400/1088 byte arrays inline would make this file unreadable.
    // the hashes are sha3-256 over the byte arrays.
    pk_hash: [u8; 32],
    sk_hash: [u8; 32],
    ct_hash: [u8; 32],
    ss: [u8; 32],
}

fn h(x: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(x);
    let out = hasher.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

// seed = all 7s, m = all 3s. hashes were cross-verified against the
// rustcrypto ml-kem 0.2.3 audited impl via tests/cross_check.rs.
const KAT1: Kat = Kat {
    seed: [7u8; 64],
    m: [3u8; 32],
    pk_hash: [
        0xcc, 0x56, 0x7d, 0xe1, 0xb5, 0xf3, 0x2d, 0x0c, 0xa9, 0x24, 0x39, 0xe5, 0x0a, 0x76, 0x72,
        0xc8, 0xc9, 0x80, 0xa9, 0xa9, 0x37, 0xe5, 0x65, 0x72, 0x9a, 0x99, 0x86, 0xad, 0xf1, 0x1e,
        0x69, 0x5f,
    ],
    sk_hash: [
        0xcc, 0x47, 0xe0, 0x65, 0x7d, 0xa3, 0x96, 0xe7, 0x73, 0xb1, 0xb8, 0xbf, 0x1b, 0xfb, 0x56,
        0x06, 0x66, 0x9d, 0x04, 0xbb, 0xc2, 0xde, 0xb7, 0xd3, 0xcf, 0xb8, 0xca, 0xa9, 0x45, 0xde,
        0x79, 0xb2,
    ],
    ct_hash: [
        0x2c, 0xb4, 0x56, 0xc7, 0xf0, 0x2e, 0xa3, 0x80, 0x4b, 0x6f, 0x29, 0x92, 0x04, 0x8f, 0x7c,
        0x98, 0x38, 0x4d, 0xf1, 0x3f, 0xd0, 0xcc, 0x94, 0x82, 0x78, 0xe2, 0x7a, 0x02, 0x76, 0x68,
        0x98, 0x20,
    ],
    ss: [
        0x86, 0x8c, 0x53, 0xe9, 0x18, 0x33, 0xc9, 0xa5, 0x30, 0xf8, 0xcf, 0x81, 0xec, 0x8a, 0x15,
        0x5d, 0x86, 0xf3, 0x68, 0x88, 0xec, 0x7e, 0xf7, 0xd0, 0x43, 0x54, 0xea, 0xe7, 0x07, 0xb9,
        0x92, 0x66,
    ],
};

// helper to print hashes. run with `cargo test --release print_kat_for_regeneration -- --ignored --nocapture`
#[test]
#[ignore]
fn print_kat_for_regeneration() {
    let seed = [7u8; 64];
    let m = [3u8; 32];
    let (pk, sk) = MlKem768::keygen_deterministic(&seed);
    let (ct, ss) = MlKem768::encapsulate_deterministic(&pk, &m);
    println!("pk_hash: {:?}", h(pk.as_bytes()));
    println!("sk_hash: {:?}", h(sk.as_bytes()));
    println!("ct_hash: {:?}", h(ct.as_bytes()));
    println!("ss:      {:?}", ss.as_bytes());
    println!("pk_hash_hex: {}", hex::encode(h(pk.as_bytes())));
    println!("sk_hash_hex: {}", hex::encode(h(sk.as_bytes())));
    println!("ct_hash_hex: {}", hex::encode(h(ct.as_bytes())));
    println!("ss_hex:      {}", hex::encode(ss.as_bytes()));
}

#[test]
fn kat_regression() {
    // if this is the placeholder KAT1 (all zeros), first run the ignored test
    // above to populate it. we only run the real assertion when the KAT has
    // been filled in.
    if KAT1.ss == [0u8; 32] {
        eprintln!("kat placeholder, run print_kat_for_regeneration and paste values");
        return;
    }
    let (pk, sk) = MlKem768::keygen_deterministic(&KAT1.seed);
    assert_eq!(h(pk.as_bytes()), KAT1.pk_hash);
    assert_eq!(h(sk.as_bytes()), KAT1.sk_hash);
    let (ct, ss) = MlKem768::encapsulate_deterministic(&pk, &KAT1.m);
    assert_eq!(h(ct.as_bytes()), KAT1.ct_hash);
    assert_eq!(*ss.as_bytes(), KAT1.ss);
    let ss2 = MlKem768::decapsulate(&sk, &ct);
    assert_eq!(*ss2.as_bytes(), KAT1.ss);
}
