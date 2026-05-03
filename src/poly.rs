// polynomials in R_q = Z_3329[X] / (X^256 + 1).
// two forms: Poly (standard) and PolyNtt (ntt-domain, incomplete basis).
// PolyVec / MatrixNtt carry their dimension at runtime so the same code
// covers ml-kem-512, -768 and -1024.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::field::{fqadd, fqsub, Fe};
use crate::ntt::{basemul, ntt_forward, ntt_inverse, GAMMAS};
use crate::params::N;

#[derive(Clone, Copy)]
pub struct Poly(pub [Fe; N]);

#[derive(Clone, Copy)]
pub struct PolyNtt(pub [Fe; N]);

impl Default for Poly {
    fn default() -> Self {
        Poly([0; N])
    }
}
impl Default for PolyNtt {
    fn default() -> Self {
        PolyNtt([0; N])
    }
}

impl Poly {
    pub fn zero() -> Self {
        Self([0; N])
    }
    pub fn add(&self, other: &Poly) -> Poly {
        let mut r = [0u16; N];
        for i in 0..N {
            r[i] = fqadd(self.0[i], other.0[i]);
        }
        Poly(r)
    }
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut r = [0u16; N];
        for i in 0..N {
            r[i] = fqsub(self.0[i], other.0[i]);
        }
        Poly(r)
    }
    pub fn ntt(&self) -> PolyNtt {
        let mut a = self.0;
        ntt_forward(&mut a);
        PolyNtt(a)
    }
}

impl PolyNtt {
    pub fn zero() -> Self {
        Self([0; N])
    }
    pub fn add(&self, other: &PolyNtt) -> PolyNtt {
        let mut r = [0u16; N];
        for i in 0..N {
            r[i] = fqadd(self.0[i], other.0[i]);
        }
        PolyNtt(r)
    }
    pub fn ntt_inverse(&self) -> Poly {
        let mut a = self.0;
        ntt_inverse(&mut a);
        Poly(a)
    }
    pub fn basemul(&self, other: &PolyNtt) -> PolyNtt {
        let mut r = [0u16; N];
        for i in 0..128 {
            let (c0, c1) = basemul(
                self.0[2 * i],
                self.0[2 * i + 1],
                other.0[2 * i],
                other.0[2 * i + 1],
                GAMMAS[i],
            );
            r[2 * i] = c0;
            r[2 * i + 1] = c1;
        }
        PolyNtt(r)
    }
}

#[derive(Clone)]
pub struct PolyVec(pub Vec<Poly>);

#[derive(Clone)]
pub struct PolyVecNtt(pub Vec<PolyNtt>);

impl PolyVec {
    pub fn zero(k: usize) -> Self {
        Self(vec![Poly::zero(); k])
    }
    pub fn k(&self) -> usize {
        self.0.len()
    }
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        let k = self.k();
        debug_assert_eq!(k, other.k());
        let mut r = vec![Poly::zero(); k];
        for i in 0..k {
            r[i] = self.0[i].add(&other.0[i]);
        }
        PolyVec(r)
    }
    pub fn ntt(&self) -> PolyVecNtt {
        let k = self.k();
        let mut r = vec![PolyNtt::zero(); k];
        for i in 0..k {
            r[i] = self.0[i].ntt();
        }
        PolyVecNtt(r)
    }
}

impl PolyVecNtt {
    pub fn zero(k: usize) -> Self {
        Self(vec![PolyNtt::zero(); k])
    }
    pub fn k(&self) -> usize {
        self.0.len()
    }
    pub fn add(&self, other: &PolyVecNtt) -> PolyVecNtt {
        let k = self.k();
        debug_assert_eq!(k, other.k());
        let mut r = vec![PolyNtt::zero(); k];
        for i in 0..k {
            r[i] = self.0[i].add(&other.0[i]);
        }
        PolyVecNtt(r)
    }
    pub fn ntt_inverse(&self) -> PolyVec {
        let k = self.k();
        let mut r = vec![Poly::zero(); k];
        for i in 0..k {
            r[i] = self.0[i].ntt_inverse();
        }
        PolyVec(r)
    }
    pub fn dot(&self, other: &PolyVecNtt) -> PolyNtt {
        let k = self.k();
        debug_assert_eq!(k, other.k());
        let mut acc = PolyNtt::zero();
        for i in 0..k {
            acc = acc.add(&self.0[i].basemul(&other.0[i]));
        }
        acc
    }
}

// kxk matrix in ntt domain. row-major.
#[derive(Clone)]
pub struct MatrixNtt(pub Vec<Vec<PolyNtt>>);

impl MatrixNtt {
    pub fn zero(k: usize) -> Self {
        let row = vec![PolyNtt::zero(); k];
        Self(vec![row; k])
    }
    pub fn k(&self) -> usize {
        self.0.len()
    }
    pub fn mul_vec(&self, v: &PolyVecNtt) -> PolyVecNtt {
        let k = self.k();
        debug_assert_eq!(k, v.k());
        let mut out = vec![PolyNtt::zero(); k];
        for i in 0..k {
            let mut acc = PolyNtt::zero();
            for j in 0..k {
                acc = acc.add(&self.0[i][j].basemul(&v.0[j]));
            }
            out[i] = acc;
        }
        PolyVecNtt(out)
    }
}
