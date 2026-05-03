// K-PKE, the cpa-secure building block under ml-kem.
// fips 203 section 5. alg 12 (keygen), alg 13 (encrypt), alg 14 (decrypt).
// generic over the Params trait so the same code covers k=2/3/4.

extern crate alloc;
use alloc::vec::Vec;

use core::marker::PhantomData;

use crate::compress::{compress_poly, decompress_poly};
use crate::hash::g;
use crate::params::{Params, POLY_BYTES};
use crate::poly::{MatrixNtt, Poly, PolyNtt, PolyVec, PolyVecNtt};
use crate::sample::{sample_cbd_poly, sample_ntt};
use crate::serialize::{byte_decode, byte_encode, message_to_poly, poly_to_message};

pub struct Kpke<P: Params>(PhantomData<P>);

impl<P: Params> Kpke<P> {
    pub const POLYVEC_BYTES: usize = POLY_BYTES * P::K;
    pub const EK_PKE_BYTES: usize = Self::POLYVEC_BYTES + 32;
    pub const DK_PKE_BYTES: usize = Self::POLYVEC_BYTES;
    pub const CT_C1_BYTES: usize = P::DU * 32 * P::K;
    pub const CT_C2_BYTES: usize = P::DV * 32;
    pub const CIPHERTEXT_SIZE: usize = Self::CT_C1_BYTES + Self::CT_C2_BYTES;

    fn sample_matrix_a(rho: &[u8; 32], transpose: bool) -> MatrixNtt {
        let k = P::K;
        let mut m = MatrixNtt::zero(k);
        for i in 0..k {
            for j in 0..k {
                let (jj, ii) = if transpose {
                    (i as u8, j as u8)
                } else {
                    (j as u8, i as u8)
                };
                m.data[i][j] = sample_ntt(rho, jj, ii);
            }
        }
        m
    }

    fn polyvec_to_bytes(v: &PolyVecNtt) -> Vec<u8> {
        let k = v.k();
        let mut out = Vec::with_capacity(POLY_BYTES * k);
        for i in 0..k {
            out.extend(byte_encode(&Poly(v.data[i].0), 12));
        }
        out
    }

    fn polyvec_from_bytes(b: &[u8]) -> PolyVecNtt {
        let k = P::K;
        debug_assert_eq!(b.len(), POLY_BYTES * k);
        let mut v = PolyVecNtt::zero(k);
        for i in 0..k {
            let p = byte_decode(&b[i * POLY_BYTES..(i + 1) * POLY_BYTES], 12);
            v.data[i] = PolyNtt(p.0);
        }
        v
    }

    pub fn keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        // fips 203 v1.0: G(d || k_byte), where k_byte = K as u8.
        let mut gin = [0u8; 33];
        gin[..32].copy_from_slice(d);
        gin[32] = P::K as u8;
        let (rho, sigma) = g(&gin);

        let a_hat = Self::sample_matrix_a(&rho, false);

        let k = P::K;
        let mut s_vec = PolyVec::zero(k);
        let mut e_vec = PolyVec::zero(k);
        for i in 0..k {
            s_vec.data[i] = sample_cbd_poly(&sigma, i as u8, P::ETA1);
        }
        for i in 0..k {
            e_vec.data[i] = sample_cbd_poly(&sigma, (k + i) as u8, P::ETA1);
        }

        let s_hat = s_vec.ntt();
        let e_hat = e_vec.ntt();

        let as_hat = a_hat.mul_vec(&s_hat);
        let t_hat = as_hat.add(&e_hat);

        // ek = byte_encode_12(t_hat) || rho
        let mut ek = Vec::with_capacity(Self::EK_PKE_BYTES);
        ek.extend(Self::polyvec_to_bytes(&t_hat));
        ek.extend_from_slice(&rho);

        // dk = byte_encode_12(s_hat)
        let dk = Self::polyvec_to_bytes(&s_hat);

        (ek, dk)
    }

    pub fn encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
        debug_assert_eq!(ek.len(), Self::EK_PKE_BYTES);
        let t_hat = Self::polyvec_from_bytes(&ek[..POLY_BYTES * P::K]);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&ek[POLY_BYTES * P::K..]);

        let a_hat = Self::sample_matrix_a(&rho, true); // transpose for encrypt

        let k = P::K;
        let mut r_vec = PolyVec::zero(k);
        let mut e1_vec = PolyVec::zero(k);
        for i in 0..k {
            r_vec.data[i] = sample_cbd_poly(r, i as u8, P::ETA1);
        }
        for i in 0..k {
            e1_vec.data[i] = sample_cbd_poly(r, (k + i) as u8, P::ETA2);
        }
        let e2 = sample_cbd_poly(r, (2 * k) as u8, P::ETA2);

        let r_hat = r_vec.ntt();

        let u_ntt = a_hat.mul_vec(&r_hat);
        let u_nont = u_ntt.ntt_inverse();
        let u = u_nont.add(&e1_vec);

        let tr = t_hat.dot(&r_hat);
        let tr_nont = tr.ntt_inverse();
        let mu = message_to_poly(m);
        let v = tr_nont.add(&e2).add(&mu);

        let mut c1 = Vec::with_capacity(Self::CT_C1_BYTES);
        for i in 0..k {
            let cc = compress_poly(&u.data[i], P::DU as u32);
            c1.extend(byte_encode(&cc, P::DU as u32));
        }
        let cv = compress_poly(&v, P::DV as u32);
        let c2 = byte_encode(&cv, P::DV as u32);

        let mut out = Vec::with_capacity(Self::CIPHERTEXT_SIZE);
        out.extend(c1);
        out.extend(c2);
        out
    }

    pub fn decrypt(dk: &[u8], c: &[u8]) -> [u8; 32] {
        debug_assert_eq!(dk.len(), Self::DK_PKE_BYTES);
        debug_assert_eq!(c.len(), Self::CIPHERTEXT_SIZE);
        let k = P::K;
        let du_bytes = 32 * P::DU;
        let c1 = &c[..du_bytes * k];
        let c2 = &c[du_bytes * k..];

        let mut u = PolyVec::zero(k);
        for i in 0..k {
            let comp = byte_decode(&c1[i * du_bytes..(i + 1) * du_bytes], P::DU as u32);
            u.data[i] = decompress_poly(&comp, P::DU as u32);
        }
        let comp_v = byte_decode(c2, P::DV as u32);
        let v = decompress_poly(&comp_v, P::DV as u32);

        let s_hat = Self::polyvec_from_bytes(dk);
        let u_hat = u.ntt();
        let sv = s_hat.dot(&u_hat).ntt_inverse();
        let w = v.sub(&sv);

        poly_to_message(&w)
    }
}
