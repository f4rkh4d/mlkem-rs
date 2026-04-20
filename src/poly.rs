// polynomials in R_q = Z_3329[X] / (X^256 + 1).
// two forms: Poly (standard) and PolyNtt (ntt-domain, incomplete basis).
// add/sub are identical either way; multiplication only makes sense in ntt form.

use crate::field::{fqadd, fqsub, Fe};
use crate::ntt::{basemul, ntt_forward, ntt_inverse, GAMMAS};
use crate::params::{K, N};

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
    // pointwise multiply in ntt (incomplete) domain.
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

// vector of K polynomials
#[derive(Clone, Copy)]
pub struct PolyVec(pub [Poly; K]);
#[derive(Clone, Copy)]
pub struct PolyVecNtt(pub [PolyNtt; K]);

impl Default for PolyVec {
    fn default() -> Self {
        Self([Poly::zero(); K])
    }
}
impl Default for PolyVecNtt {
    fn default() -> Self {
        Self([PolyNtt::zero(); K])
    }
}

impl PolyVec {
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        let mut r = [Poly::zero(); K];
        for i in 0..K {
            r[i] = self.0[i].add(&other.0[i]);
        }
        PolyVec(r)
    }
    pub fn ntt(&self) -> PolyVecNtt {
        let mut r = [PolyNtt::zero(); K];
        for i in 0..K {
            r[i] = self.0[i].ntt();
        }
        PolyVecNtt(r)
    }
}

impl PolyVecNtt {
    pub fn add(&self, other: &PolyVecNtt) -> PolyVecNtt {
        let mut r = [PolyNtt::zero(); K];
        for i in 0..K {
            r[i] = self.0[i].add(&other.0[i]);
        }
        PolyVecNtt(r)
    }
    pub fn ntt_inverse(&self) -> PolyVec {
        let mut r = [Poly::zero(); K];
        for i in 0..K {
            r[i] = self.0[i].ntt_inverse();
        }
        PolyVec(r)
    }
    // dot product: sum_i self[i] * other[i] in ntt domain.
    pub fn dot(&self, other: &PolyVecNtt) -> PolyNtt {
        let mut acc = PolyNtt::zero();
        for i in 0..K {
            acc = acc.add(&self.0[i].basemul(&other.0[i]));
        }
        acc
    }
}

// kxk matrix in ntt domain. stored row-major.
#[derive(Clone)]
pub struct MatrixNtt(pub [[PolyNtt; K]; K]);

impl MatrixNtt {
    pub fn zero() -> Self {
        Self([[PolyNtt::zero(); K]; K])
    }
    // matrix times vector, in ntt domain.
    pub fn mul_vec(&self, v: &PolyVecNtt) -> PolyVecNtt {
        let mut out = [PolyNtt::zero(); K];
        for i in 0..K {
            let mut acc = PolyNtt::zero();
            for j in 0..K {
                acc = acc.add(&self.0[i][j].basemul(&v.0[j]));
            }
            out[i] = acc;
        }
        PolyVecNtt(out)
    }
}
