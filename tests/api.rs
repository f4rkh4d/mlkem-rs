// basic usability: alice/bob handshake, roundtrip, size sanity.
// runs across all three parameter sets via macro.

use rand::thread_rng;

macro_rules! api_tests {
    ($mod:ident, $kem:ident, $pk:ty, $sk:ty, $ct:ty, $pk_size:expr, $sk_size:expr, $ct_size:expr) => {
        mod $mod {
            use super::*;
            use mlkem::{$ct, $kem, $pk, $sk};

            #[test]
            fn alice_bob_handshake() {
                let mut rng = thread_rng();
                let (bob_pk, bob_sk) = $kem::keygen(&mut rng);
                let (ct, alice_ss) = $kem::encapsulate(&bob_pk, &mut rng);
                let bob_ss = $kem::decapsulate(&bob_sk, &ct);
                assert_eq!(alice_ss, bob_ss);
            }

            #[test]
            fn sizes() {
                assert_eq!($kem::PUBLIC_KEY_SIZE, $pk_size);
                assert_eq!($kem::SECRET_KEY_SIZE, $sk_size);
                assert_eq!($kem::CIPHERTEXT_SIZE, $ct_size);
                assert_eq!($kem::SHARED_SECRET_SIZE, 32);
            }

            #[test]
            fn deterministic_is_deterministic() {
                let seed = [42u8; 64];
                let (pk1, sk1) = $kem::keygen_deterministic(&seed);
                let (pk2, sk2) = $kem::keygen_deterministic(&seed);
                assert_eq!(pk1, pk2);
                assert_eq!(sk1, sk2);

                let m = [17u8; 32];
                let (ct1, ss1) = $kem::encapsulate_deterministic(&pk1, &m);
                let (ct2, ss2) = $kem::encapsulate_deterministic(&pk2, &m);
                assert_eq!(ct1, ct2);
                assert_eq!(ss1, ss2);
            }

            #[test]
            fn implicit_reject_on_tampered_ct() {
                let mut rng = thread_rng();
                let (pk, sk) = $kem::keygen(&mut rng);
                let (ct, ss_good) = $kem::encapsulate(&pk, &mut rng);

                let mut bad_bytes = *ct.as_bytes();
                bad_bytes[0] ^= 0x01;
                let bad_ct = <$ct>::from_bytes(&bad_bytes);
                let ss_bad = $kem::decapsulate(&sk, &bad_ct);

                assert_ne!(ss_good, ss_bad);
            }

            #[test]
            fn serialization_roundtrip() {
                let mut rng = thread_rng();
                let (pk, sk) = $kem::keygen(&mut rng);
                let pk2 = <$pk>::from_bytes(pk.as_bytes());
                let sk2 = <$sk>::from_bytes(sk.as_bytes());
                assert_eq!(pk, pk2);
                assert_eq!(sk, sk2);
            }
        }
    };
}

api_tests!(
    kem512,
    MlKem512,
    PublicKey512,
    SecretKey512,
    Ciphertext512,
    800,
    1632,
    768
);
api_tests!(
    kem768,
    MlKem768,
    PublicKey768,
    SecretKey768,
    Ciphertext768,
    1184,
    2400,
    1088
);
api_tests!(
    kem1024,
    MlKem1024,
    PublicKey1024,
    SecretKey1024,
    Ciphertext1024,
    1568,
    3168,
    1568
);
