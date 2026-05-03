// cross-check against rustcrypto's audited ml-kem impl.
// same seeds in = same bytes out, byte-for-byte, on pk/sk/ct/ss.
// 1000 iterations per parameter set across all three levels = 3000 tests.
// seeds come from a chacha rng seeded with a fixed constant so reruns are
// deterministic but the seed space is wide.

use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, B32};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const ITERS: usize = 1000;
const RNG_SEED: [u8; 32] = *b"mlkem-rs cross-check, 2026-05-03";

macro_rules! cross_check_one {
    ($fn_name:ident, $ours:ident, $rc:ty, $iters:expr) => {
        #[test]
        fn $fn_name() {
            use mlkem::$ours;
            let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
            for iter in 0..$iters {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);

                // ours
                let (pk, sk) = $ours::keygen_deterministic(&seed);
                let (ct, ss) = $ours::encapsulate_deterministic(&pk, &m);
                let ss2 = $ours::decapsulate(&sk, &ct);
                assert_eq!(
                    ss.as_bytes(),
                    ss2.as_bytes(),
                    "{} self-consistency iter {iter}",
                    stringify!($ours)
                );

                // reference
                let d: &B32 = (&seed[..32]).try_into().unwrap();
                let z: &B32 = (&seed[32..]).try_into().unwrap();
                let (rc_dk, rc_ek) = <$rc as KemCore>::generate_deterministic(d, z);

                let rc_ek_bytes = rc_ek.as_bytes();
                assert_eq!(
                    pk.as_bytes().as_slice(),
                    rc_ek_bytes.as_slice(),
                    "{} pk mismatch iter {iter}",
                    stringify!($ours)
                );

                let rc_dk_bytes = rc_dk.as_bytes();
                assert_eq!(
                    sk.as_bytes().as_slice(),
                    rc_dk_bytes.as_slice(),
                    "{} sk mismatch iter {iter}",
                    stringify!($ours)
                );

                let m_b32: &B32 = (&m).into();
                let (rc_ct, rc_ss) = rc_ek.encapsulate_deterministic(m_b32).unwrap();
                assert_eq!(
                    ct.as_bytes().as_slice(),
                    rc_ct.as_slice(),
                    "{} ct mismatch iter {iter}",
                    stringify!($ours)
                );
                assert_eq!(
                    ss.as_bytes().as_slice(),
                    rc_ss.as_slice(),
                    "{} ss mismatch iter {iter}",
                    stringify!($ours)
                );

                let rc_recovered = rc_dk.decapsulate(&rc_ct).unwrap();
                assert_eq!(
                    ss2.as_bytes().as_slice(),
                    rc_recovered.as_slice(),
                    "{} decap mismatch iter {iter}",
                    stringify!($ours)
                );
            }
        }
    };
}

cross_check_one!(cross_check_512, MlKem512, ml_kem::MlKem512, ITERS);
cross_check_one!(cross_check_768, MlKem768, ml_kem::MlKem768, ITERS);
cross_check_one!(cross_check_1024, MlKem1024, ml_kem::MlKem1024, ITERS);
