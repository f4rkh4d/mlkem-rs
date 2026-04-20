// cross-check against rustcrypto's audited ml-kem impl.
// same seeds in = same bytes out. 50 iterations.

use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768 as RcKem, B32};
use mlkem::MlKem768;
use rand::RngCore;

#[test]
fn cross_check_keygen_encap_decap() {
    let mut rng = rand::thread_rng();
    for iter in 0..50 {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);

        // ours
        let (pk, sk) = MlKem768::keygen_deterministic(&seed);
        let (ct, ss) = MlKem768::encapsulate_deterministic(&pk, &m);
        let ss2 = MlKem768::decapsulate(&sk, &ct);
        assert_eq!(
            ss.as_bytes(),
            ss2.as_bytes(),
            "self-consistency iter {iter}"
        );

        // reference
        let d: &B32 = (&seed[..32]).try_into().unwrap();
        let z: &B32 = (&seed[32..]).try_into().unwrap();
        let (rc_dk, rc_ek) = <RcKem as KemCore>::generate_deterministic(d, z);

        // compare pk bytes
        let rc_ek_bytes = rc_ek.as_bytes();
        assert_eq!(
            pk.as_bytes().as_slice(),
            rc_ek_bytes.as_slice(),
            "pk mismatch iter {iter}"
        );

        // compare sk bytes
        let rc_dk_bytes = rc_dk.as_bytes();
        assert_eq!(
            sk.as_bytes().as_slice(),
            rc_dk_bytes.as_slice(),
            "sk mismatch iter {iter}"
        );

        // encapsulate deterministically
        let m_b32: &B32 = (&m).into();
        let (rc_ct, rc_ss) = rc_ek.encapsulate_deterministic(m_b32).unwrap();
        assert_eq!(
            ct.as_bytes().as_slice(),
            rc_ct.as_slice(),
            "ct mismatch iter {iter}"
        );
        assert_eq!(
            ss.as_bytes().as_slice(),
            rc_ss.as_slice(),
            "ss mismatch iter {iter}"
        );

        // decapsulate reference with our ct
        let rc_recovered = rc_dk.decapsulate(&rc_ct).unwrap();
        assert_eq!(
            ss2.as_bytes().as_slice(),
            rc_recovered.as_slice(),
            "decap mismatch iter {iter}"
        );
    }
}
