// ml-kem-768 kem wrapper over k-pke, with fo-transform and implicit rejection.
// fips 203 section 6. alg 16 keygen, alg 17 encaps, alg 18 decaps.

use crate::hash::{g, h, j};
use crate::kpke;
use crate::params::{
    CIPHERTEXT_SIZE, DK_PKE_BYTES, EK_PKE_BYTES, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
    SHARED_SECRET_SIZE,
};
use subtle::ConstantTimeEq;

// keygen from (d, z). returns (pk, sk) bytes.
pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; PUBLIC_KEY_SIZE], [u8; SECRET_KEY_SIZE]) {
    let (ek_pke, dk_pke) = kpke::keygen(d);

    let pk = ek_pke;
    let mut sk = [0u8; SECRET_KEY_SIZE];
    sk[..DK_PKE_BYTES].copy_from_slice(&dk_pke);
    sk[DK_PKE_BYTES..DK_PKE_BYTES + EK_PKE_BYTES].copy_from_slice(&ek_pke);
    let h_ek = h(&ek_pke);
    sk[DK_PKE_BYTES + EK_PKE_BYTES..DK_PKE_BYTES + EK_PKE_BYTES + 32].copy_from_slice(&h_ek);
    sk[DK_PKE_BYTES + EK_PKE_BYTES + 32..].copy_from_slice(z);

    (pk, sk)
}

pub fn encapsulate(
    pk: &[u8; PUBLIC_KEY_SIZE],
    m: &[u8; 32],
) -> ([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]) {
    let h_pk = h(pk);
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(m);
    gin[32..].copy_from_slice(&h_pk);
    let (k_shared, r) = g(&gin);

    let c = kpke::encrypt(pk, m, &r);
    assert_eq!(c.len(), CIPHERTEXT_SIZE);
    let mut ct = [0u8; CIPHERTEXT_SIZE];
    ct.copy_from_slice(&c);

    (ct, k_shared)
}

pub fn decapsulate(
    sk: &[u8; SECRET_KEY_SIZE],
    ct: &[u8; CIPHERTEXT_SIZE],
) -> [u8; SHARED_SECRET_SIZE] {
    let dk_pke: &[u8; DK_PKE_BYTES] = sk[..DK_PKE_BYTES].try_into().unwrap();
    let ek_pke: &[u8; EK_PKE_BYTES] = sk[DK_PKE_BYTES..DK_PKE_BYTES + EK_PKE_BYTES]
        .try_into()
        .unwrap();
    let h_ek: &[u8; 32] = sk[DK_PKE_BYTES + EK_PKE_BYTES..DK_PKE_BYTES + EK_PKE_BYTES + 32]
        .try_into()
        .unwrap();
    let z: &[u8; 32] = sk[DK_PKE_BYTES + EK_PKE_BYTES + 32..].try_into().unwrap();

    let m_prime = kpke::decrypt(dk_pke, ct);
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(&m_prime);
    gin[32..].copy_from_slice(h_ek);
    let (k_prime, r_prime) = g(&gin);

    // k_bar = J(z || ct)
    let mut jin = Vec::with_capacity(32 + CIPHERTEXT_SIZE);
    jin.extend_from_slice(z);
    jin.extend_from_slice(ct);
    let k_bar = j(&jin);

    let c_prime = kpke::encrypt(ek_pke, &m_prime, &r_prime);

    // constant-time select
    let eq = ct.as_slice().ct_eq(c_prime.as_slice());
    // if eq, return k_prime, else k_bar. branchless.
    let mut out = [0u8; 32];
    let mask = eq.unwrap_u8().wrapping_neg(); // 0xff if eq, 0x00 otherwise
    for i in 0..32 {
        out[i] = (k_prime[i] & mask) | (k_bar[i] & !mask);
    }
    out
}
