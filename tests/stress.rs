// stable-rust stress tests. these cover the same surface as the cargo-fuzz
// targets in fuzz/ but run in plain `cargo test` and exit deterministically.
// fixed seed means any regression is reproducible without saving a corpus.

use mlkem::{
    Ciphertext1024, Ciphertext512, Ciphertext768, MlKem1024, MlKem512, MlKem768, SecretKey1024,
    SecretKey512, SecretKey768,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const ROUND_TRIPS: usize = 5000;
const TAMPER_ROUNDS: usize = 2000;
const ARBITRARY_DECAP_ROUNDS: usize = 1000;
const RNG_SEED: [u8; 32] = *b"mlkem-rs stress test, 2026-05-03";

macro_rules! stress_for {
    ($mod:ident, $kem:ident, $sk:ty, $ct:ty, $sk_size:expr, $ct_size:expr) => {
        mod $mod {
            use super::*;

            #[test]
            fn round_trip_many() {
                let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
                for i in 0..ROUND_TRIPS {
                    let mut seed = [0u8; 64];
                    rng.fill_bytes(&mut seed);
                    let mut m = [0u8; 32];
                    rng.fill_bytes(&mut m);

                    let (pk, sk) = $kem::keygen_deterministic(&seed);
                    let (ct, ss_a) = $kem::encapsulate_deterministic(&pk, &m);
                    let ss_b = $kem::decapsulate(&sk, &ct);
                    assert_eq!(ss_a, ss_b, "{} round-trip iter {}", stringify!($kem), i);
                }
            }

            #[test]
            fn random_tamper_reaches_implicit_reject() {
                let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
                for i in 0..TAMPER_ROUNDS {
                    let mut seed = [0u8; 64];
                    rng.fill_bytes(&mut seed);
                    let mut m = [0u8; 32];
                    rng.fill_bytes(&mut m);

                    let (pk, sk) = $kem::keygen_deterministic(&seed);
                    let (ct, ss_honest) = $kem::encapsulate_deterministic(&pk, &m);

                    let mut tampered = *ct.as_bytes();
                    let pos = (rng.next_u32() as usize) % tampered.len();
                    let mut x = (rng.next_u32() & 0xff) as u8;
                    if x == 0 {
                        x = 1;
                    }
                    tampered[pos] ^= x;

                    let bad_ct = <$ct>::from_bytes(&tampered);
                    let ss_bad = $kem::decapsulate(&sk, &bad_ct);
                    assert_ne!(
                        ss_honest,
                        ss_bad,
                        "{} tampered ct reproduced honest ss at iter {}",
                        stringify!($kem),
                        i
                    );
                }
            }

            #[test]
            fn arbitrary_bytes_decap_no_panic() {
                let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
                for _ in 0..ARBITRARY_DECAP_ROUNDS {
                    let mut sk_arr = [0u8; $sk_size];
                    rng.fill_bytes(&mut sk_arr);
                    let mut ct_arr = [0u8; $ct_size];
                    rng.fill_bytes(&mut ct_arr);

                    let sk = <$sk>::from_bytes(&sk_arr);
                    let ct = <$ct>::from_bytes(&ct_arr);
                    let _ = $kem::decapsulate(&sk, &ct);
                }
            }
        }
    };
}

stress_for!(s512, MlKem512, SecretKey512, Ciphertext512, 1632, 768);
stress_for!(s768, MlKem768, SecretKey768, Ciphertext768, 2400, 1088);
stress_for!(s1024, MlKem1024, SecretKey1024, Ciphertext1024, 3168, 1568);
