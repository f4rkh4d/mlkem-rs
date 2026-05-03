// ml-kem kem wrapper over k-pke, with fo-transform and implicit rejection.
// fips 203 section 6. alg 16 keygen, alg 17 encaps, alg 18 decaps.
// generic over the Params trait.

extern crate alloc;
use alloc::vec::Vec;

use core::marker::PhantomData;

use crate::hash::{g, h, j as j_hash};
use crate::kpke::Kpke;
use crate::params::Params;
use subtle::ConstantTimeEq;

pub struct MlKem<P: Params>(PhantomData<P>);

impl<P: Params> MlKem<P> {
    pub const PUBLIC_KEY_SIZE: usize = Kpke::<P>::EK_PKE_BYTES;
    pub const SECRET_KEY_SIZE: usize =
        Kpke::<P>::DK_PKE_BYTES + Kpke::<P>::EK_PKE_BYTES + 32 + 32;
    pub const CIPHERTEXT_SIZE: usize = Kpke::<P>::CIPHERTEXT_SIZE;

    pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let (ek_pke, dk_pke) = Kpke::<P>::keygen(d);

        let pk = ek_pke.clone();
        let mut sk = Vec::with_capacity(Self::SECRET_KEY_SIZE);
        sk.extend_from_slice(&dk_pke);
        sk.extend_from_slice(&ek_pke);
        let h_ek = h(&ek_pke);
        sk.extend_from_slice(&h_ek);
        sk.extend_from_slice(z);

        (pk, sk)
    }

    pub fn encapsulate(pk: &[u8], m: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        debug_assert_eq!(pk.len(), Self::PUBLIC_KEY_SIZE);
        let h_pk = h(pk);
        let mut gin = [0u8; 64];
        gin[..32].copy_from_slice(m);
        gin[32..].copy_from_slice(&h_pk);
        let (k_shared, r) = g(&gin);

        let c = Kpke::<P>::encrypt(pk, m, &r);
        debug_assert_eq!(c.len(), Self::CIPHERTEXT_SIZE);
        (c, k_shared)
    }

    pub fn decapsulate(sk: &[u8], ct: &[u8]) -> [u8; 32] {
        debug_assert_eq!(sk.len(), Self::SECRET_KEY_SIZE);
        debug_assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let dk_bytes = Kpke::<P>::DK_PKE_BYTES;
        let ek_bytes = Kpke::<P>::EK_PKE_BYTES;
        let dk_pke = &sk[..dk_bytes];
        let ek_pke = &sk[dk_bytes..dk_bytes + ek_bytes];
        let h_ek: &[u8] = &sk[dk_bytes + ek_bytes..dk_bytes + ek_bytes + 32];
        let z: &[u8] = &sk[dk_bytes + ek_bytes + 32..];

        let m_prime = Kpke::<P>::decrypt(dk_pke, ct);
        let mut gin = [0u8; 64];
        gin[..32].copy_from_slice(&m_prime);
        gin[32..].copy_from_slice(h_ek);
        let (k_prime, r_prime) = g(&gin);

        // k_bar = J(z || ct)
        let mut jin = Vec::with_capacity(32 + ct.len());
        jin.extend_from_slice(z);
        jin.extend_from_slice(ct);
        let k_bar = j_hash(&jin);

        let c_prime = Kpke::<P>::encrypt(ek_pke, &m_prime, &r_prime);

        let eq = ct.ct_eq(c_prime.as_slice());
        let mut out = [0u8; 32];
        let mask = eq.unwrap_u8().wrapping_neg();
        for i in 0..32 {
            out[i] = (k_prime[i] & mask) | (k_bar[i] & !mask);
        }
        out
    }
}
