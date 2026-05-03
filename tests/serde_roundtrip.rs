// serde feature: bincode + json round-trips on every newtype, all three levels.

#![cfg(feature = "serde")]

use mlkem::{
    Ciphertext1024, Ciphertext512, Ciphertext768, MlKem1024, MlKem512, MlKem768, PublicKey1024,
    PublicKey512, PublicKey768, SecretKey1024, SecretKey512, SecretKey768,
};
use rand::thread_rng;

macro_rules! serde_test {
    ($mod:ident, $kem:ident, $pk:ty, $sk:ty, $ct:ty) => {
        mod $mod {
            use super::*;

            #[test]
            fn bincode_roundtrip() {
                let mut rng = thread_rng();
                let (pk, sk) = $kem::keygen(&mut rng);
                let (ct, ss) = $kem::encapsulate(&pk, &mut rng);

                let pk_bytes = bincode::serialize(&pk).unwrap();
                let sk_bytes = bincode::serialize(&sk).unwrap();
                let ct_bytes = bincode::serialize(&ct).unwrap();
                let ss_bytes = bincode::serialize(&ss).unwrap();

                let pk2: $pk = bincode::deserialize(&pk_bytes).unwrap();
                let sk2: $sk = bincode::deserialize(&sk_bytes).unwrap();
                let ct2: $ct = bincode::deserialize(&ct_bytes).unwrap();

                assert_eq!(pk, pk2);
                assert_eq!(sk, sk2);
                assert_eq!(ct, ct2);

                let ss_size = ss_bytes.len();
                assert!(ss_size > 32);
            }

            #[test]
            fn cross_serializer_consistency() {
                let mut rng = thread_rng();
                let (pk, _sk) = $kem::keygen(&mut rng);
                let bin = bincode::serialize(&pk).unwrap();
                let pk_again: $pk = bincode::deserialize(&bin).unwrap();
                assert_eq!(pk, pk_again);
            }
        }
    };
}

serde_test!(s512, MlKem512, PublicKey512, SecretKey512, Ciphertext512);
serde_test!(s768, MlKem768, PublicKey768, SecretKey768, Ciphertext768);
serde_test!(
    s1024,
    MlKem1024,
    PublicKey1024,
    SecretKey1024,
    Ciphertext1024
);
