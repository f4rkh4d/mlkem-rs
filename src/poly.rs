// polynomials in R_q = Z_3329[X] / (X^256 + 1).
// two forms: Poly (standard) and PolyNtt (ntt-domain, incomplete basis).
// PolyVec / MatrixNtt are stack-allocated with capacity MAX_K (= 4) and
// carry an active length `k`. covers ml-kem-512 (k=2), -768 (k=3), -1024 (k=4)
// without any heap allocation in the algebraic hot path.

use crate::field::{fqadd, fqsub, Fe};
use crate::ntt::{basemul, ntt_forward, ntt_inverse, GAMMAS_MONT};
use crate::params::N;

/// upper bound on the rank used by any ml-kem parameter set.
pub const MAX_K: usize = 4;

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
                GAMMAS_MONT[i],
            );
            r[2 * i] = c0;
            r[2 * i + 1] = c1;
        }
        PolyNtt(r)
    }
}

/// vector of up to MAX_K polynomials in R_q. `k` tracks how many slots
/// are active; entries `[k..]` are zero and ignored.
#[derive(Clone, Copy)]
pub struct PolyVec {
    pub data: [Poly; MAX_K],
    pub k: usize,
}

#[derive(Clone, Copy)]
pub struct PolyVecNtt {
    pub data: [PolyNtt; MAX_K],
    pub k: usize,
}

impl PolyVec {
    pub fn zero(k: usize) -> Self {
        Self {
            data: [Poly::zero(); MAX_K],
            k,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        debug_assert_eq!(self.k, other.k);
        let mut r = PolyVec::zero(self.k);
        for i in 0..self.k {
            r.data[i] = self.data[i].add(&other.data[i]);
        }
        r
    }
    pub fn ntt(&self) -> PolyVecNtt {
        let mut r = PolyVecNtt::zero(self.k);
        for i in 0..self.k {
            r.data[i] = self.data[i].ntt();
        }
        r
    }
}

impl PolyVecNtt {
    pub fn zero(k: usize) -> Self {
        Self {
            data: [PolyNtt::zero(); MAX_K],
            k,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn add(&self, other: &PolyVecNtt) -> PolyVecNtt {
        debug_assert_eq!(self.k, other.k);
        let mut r = PolyVecNtt::zero(self.k);
        for i in 0..self.k {
            r.data[i] = self.data[i].add(&other.data[i]);
        }
        r
    }
    pub fn ntt_inverse(&self) -> PolyVec {
        let mut r = PolyVec::zero(self.k);
        for i in 0..self.k {
            r.data[i] = self.data[i].ntt_inverse();
        }
        r
    }
    pub fn dot(&self, other: &PolyVecNtt) -> PolyNtt {
        debug_assert_eq!(self.k, other.k);
        let mut acc = PolyNtt::zero();
        for i in 0..self.k {
            acc = acc.add(&self.data[i].basemul(&other.data[i]));
        }
        acc
    }
}

/// kxk matrix in ntt domain, stack-allocated with MAX_K x MAX_K.
#[derive(Clone, Copy)]
pub struct MatrixNtt {
    pub data: [[PolyNtt; MAX_K]; MAX_K],
    pub k: usize,
}

impl MatrixNtt {
    pub fn zero(k: usize) -> Self {
        Self {
            data: [[PolyNtt::zero(); MAX_K]; MAX_K],
            k,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn mul_vec(&self, v: &PolyVecNtt) -> PolyVecNtt {
        debug_assert_eq!(self.k, v.k);
        let mut out = PolyVecNtt::zero(self.k);
        for i in 0..self.k {
            let mut acc = PolyNtt::zero();
            for j in 0..self.k {
                acc = acc.add(&self.data[i][j].basemul(&v.data[j]));
            }
            out.data[i] = acc;
        }
        out
    }
}
