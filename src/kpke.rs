// K-PKE, the cpa-secure building block under ml-kem.
// fips 203 section 5. alg 12 (keygen), alg 13 (encrypt), alg 14 (decrypt).

use crate::compress::{compress_poly, decompress_poly};
use crate::hash::g;
use crate::params::{DK_PKE_BYTES, DU, DV, EK_PKE_BYTES, ETA1, ETA2, K, POLY_BYTES};
use crate::poly::{MatrixNtt, Poly, PolyNtt, PolyVec, PolyVecNtt};
use crate::sample::{sample_cbd_poly, sample_ntt};
use crate::serialize::{byte_decode, byte_encode, message_to_poly, poly_to_message};

// build matrix a_hat (k x k) directly in ntt domain.
// xof(rho, j, i): row i, col j, spec order.
fn sample_matrix_a(rho: &[u8; 32], transpose: bool) -> MatrixNtt {
    let mut m = MatrixNtt::zero();
    for i in 0..K {
        for j in 0..K {
            let (jj, ii) = if transpose {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            m.0[i][j] = sample_ntt(rho, jj, ii);
        }
    }
    m
}

// encode / decode a vector of K polynomials, each at d=12 (raw Z_q).
pub fn polyvec_to_bytes(v: &PolyVecNtt) -> Vec<u8> {
    let mut out = Vec::with_capacity(POLY_BYTES * K);
    for i in 0..K {
        out.extend(byte_encode(&Poly(v.0[i].0), 12));
    }
    out
}

pub fn polyvec_from_bytes(b: &[u8]) -> PolyVecNtt {
    assert_eq!(b.len(), POLY_BYTES * K);
    let mut v = PolyVecNtt::default();
    for i in 0..K {
        let p = byte_decode(&b[i * POLY_BYTES..(i + 1) * POLY_BYTES], 12);
        v.0[i] = PolyNtt(p.0);
    }
    v
}

// keygen, alg 12. d is the 32-byte seed for the pke layer.
pub fn keygen(d: &[u8; 32]) -> ([u8; EK_PKE_BYTES], [u8; DK_PKE_BYTES]) {
    // fips 203 v1.0: G(d || k_byte), where k_byte = K as u8.
    let mut gin = [0u8; 33];
    gin[..32].copy_from_slice(d);
    gin[32] = K as u8;
    let (rho, sigma) = g(&gin);

    let a_hat = sample_matrix_a(&rho, false);

    // sample s, e from CBD_eta1 using sigma, counters 0..k and k..2k.
    let mut s_vec = PolyVec::default();
    let mut e_vec = PolyVec::default();
    for i in 0..K {
        s_vec.0[i] = sample_cbd_poly(&sigma, i as u8, ETA1);
    }
    for i in 0..K {
        e_vec.0[i] = sample_cbd_poly(&sigma, (K + i) as u8, ETA1);
    }

    let s_hat = s_vec.ntt();
    let e_hat = e_vec.ntt();

    // t_hat = A s + e (in ntt domain throughout)
    let as_hat = a_hat.mul_vec(&s_hat);
    let t_hat = as_hat.add(&e_hat);

    // ek = byte_encode_12(t_hat) || rho
    let mut ek = [0u8; EK_PKE_BYTES];
    ek[..POLY_BYTES * K].copy_from_slice(&polyvec_to_bytes(&t_hat));
    ek[POLY_BYTES * K..].copy_from_slice(&rho);

    // dk = byte_encode_12(s_hat)
    let mut dk = [0u8; DK_PKE_BYTES];
    dk.copy_from_slice(&polyvec_to_bytes(&s_hat));

    (ek, dk)
}

// encrypt, alg 13. m is 32-byte message, r is 32-byte randomness.
pub fn encrypt(ek: &[u8; EK_PKE_BYTES], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let t_hat = polyvec_from_bytes(&ek[..POLY_BYTES * K]);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[POLY_BYTES * K..]);

    let a_hat = sample_matrix_a(&rho, true); // transpose for encrypt

    let mut r_vec = PolyVec::default();
    let mut e1_vec = PolyVec::default();
    for i in 0..K {
        r_vec.0[i] = sample_cbd_poly(r, i as u8, ETA1);
    }
    for i in 0..K {
        e1_vec.0[i] = sample_cbd_poly(r, (K + i) as u8, ETA2);
    }
    let e2 = sample_cbd_poly(r, (2 * K) as u8, ETA2);

    let r_hat = r_vec.ntt();

    // u = ntt^{-1}(A^T r_hat) + e1
    let u_ntt = a_hat.mul_vec(&r_hat); // note: a_hat here is already A^T
    let u_nont = u_ntt.ntt_inverse();
    let u = u_nont.add(&e1_vec);

    // v = ntt^{-1}(t_hat . r_hat) + e2 + decompress_1(m)
    let tr = t_hat.dot(&r_hat);
    let tr_nont = tr.ntt_inverse();
    let mu = message_to_poly(m);
    let v = tr_nont.add(&e2).add(&mu);

    // compress and encode
    let mut c1 = Vec::with_capacity(crate::params::CT_C1_BYTES);
    for i in 0..K {
        let cc = compress_poly(&u.0[i], DU as u32);
        c1.extend(byte_encode(&cc, DU as u32));
    }
    let cv = compress_poly(&v, DV as u32);
    let c2 = byte_encode(&cv, DV as u32);

    let mut out = Vec::with_capacity(c1.len() + c2.len());
    out.extend(c1);
    out.extend(c2);
    out
}

// decrypt, alg 14.
pub fn decrypt(dk: &[u8; DK_PKE_BYTES], c: &[u8]) -> [u8; 32] {
    let du_bytes = 32 * DU;
    let c1 = &c[..du_bytes * K];
    let c2 = &c[du_bytes * K..];

    let mut u = PolyVec::default();
    for i in 0..K {
        let comp = byte_decode(&c1[i * du_bytes..(i + 1) * du_bytes], DU as u32);
        u.0[i] = decompress_poly(&comp, DU as u32);
    }
    let comp_v = byte_decode(c2, DV as u32);
    let v = decompress_poly(&comp_v, DV as u32);

    let s_hat = polyvec_from_bytes(dk);
    let u_hat = u.ntt();
    let sv = s_hat.dot(&u_hat).ntt_inverse();
    let w = v.sub(&sv);

    poly_to_message(&w)
}
