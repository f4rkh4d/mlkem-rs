// ntt for R_q = Z_3329[X] / (X^256 + 1).
// since 256 does not divide q-1 = 3328 but 128 does, we get an
// "incomplete" ntt: 128 length-2 polys indexed by bit-reversed roots.
// zeta = 17 is a primitive 256th root of unity mod 3329.
//
// zetas[k] = zeta^{brev7(k)} mod q, for k in 1..128.
// gammas[k] = zeta^{2*brev7(k)+1} mod q, used in basecase multiply.
// constants cross-checked against the kyber reference.

use crate::field::{barrett_reduce, fqadd, fqmul, fqsub, Fe};
use crate::params::N;

pub const ZETAS: [Fe; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// gammas[i] = zeta^{2*brev7(i)+1} mod q. 128 entries. computed at const-eval.
pub const GAMMAS: [Fe; 128] = {
    let mut g = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        let zpr = ZETAS[i] as u64;
        g[i] = ((zpr * zpr * 17) % crate::params::Q as u64) as u16;
        i += 1;
    }
    g
};

// forward ntt, cooley-tukey, in place.
pub fn ntt_forward(a: &mut [Fe; N]) {
    let mut k: usize = 1;
    for &len in &[128usize, 64, 32, 16, 8, 4, 2] {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fqmul(zeta, a[j + len]);
                a[j + len] = fqsub(a[j], t);
                a[j] = fqadd(a[j], t);
            }
            start += 2 * len;
        }
    }
}

// inverse ntt, gentleman-sande. final scale by n^-1 = 128^-1 = 3303 mod q.
// uses -zeta (q - zeta) since inverse of X ↦ X*zeta has inverse root.
pub fn ntt_inverse(a: &mut [Fe; N]) {
    const F: Fe = 3303;
    let mut k: usize = 127;
    for &len in &[2usize, 4, 8, 16, 32, 64, 128] {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..(start + len) {
                let tmp = a[j];
                a[j] = barrett_reduce(tmp as i32 + a[j + len] as i32);
                a[j + len] = fqsub(a[j + len], tmp);
                a[j + len] = fqmul(zeta, a[j + len]);
            }
            start += 2 * len;
        }
    }
    for coef in a.iter_mut() {
        *coef = fqmul(*coef, F);
    }
}

// basecase multiply: in the incomplete ntt each coeff pair (a0, a1)
// represents a0 + a1 X mod (X^2 - gamma). multiply two such pairs.
#[inline]
pub fn basemul(a0: Fe, a1: Fe, b0: Fe, b1: Fe, gamma: Fe) -> (Fe, Fe) {
    let c0 = fqmul(fqmul(a1, b1), gamma) as i32 + fqmul(a0, b0) as i32;
    let c0 = barrett_reduce(c0);
    let c1 = fqmul(a0, b1) as i32 + fqmul(a1, b0) as i32;
    let c1 = barrett_reduce(c1);
    (c0, c1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Q;

    #[test]
    fn ntt_roundtrip() {
        let mut a: [Fe; N] = [0; N];
        for (i, x) in a.iter_mut().enumerate() {
            *x = (i as u16) % 3329;
        }
        let orig = a;
        ntt_forward(&mut a);
        ntt_inverse(&mut a);
        for i in 0..N {
            assert_eq!(a[i], orig[i], "mismatch at {i}");
        }
    }

    // naive polynomial multiplication in R_q = Z_q[X]/(X^256+1)
    fn naive_mul(a: &[Fe; N], b: &[Fe; N]) -> [Fe; N] {
        let mut out = [0u32; 2 * N];
        for i in 0..N {
            for j in 0..N {
                out[i + j] = (out[i + j] + (a[i] as u32) * (b[j] as u32)) % Q as u32;
            }
        }
        let mut r = [0u16; N];
        for i in 0..N {
            // X^N = -1, so out[N+i] wraps with a sign flip
            let v = (out[i] + Q as u32 - (out[N + i] % Q as u32)) % Q as u32;
            r[i] = v as u16;
        }
        r
    }

    #[test]
    fn ntt_mul_matches_naive() {
        let mut a = [0u16; N];
        let mut b = [0u16; N];
        for i in 0..N {
            a[i] = ((i * 7 + 3) % Q as usize) as u16;
            b[i] = ((i * 13 + 5) % Q as usize) as u16;
        }
        let expected = naive_mul(&a, &b);

        let mut af = a;
        let mut bf = b;
        ntt_forward(&mut af);
        ntt_forward(&mut bf);

        use crate::poly::PolyNtt;
        let ap = PolyNtt(af);
        let bp = PolyNtt(bf);
        let cp = ap.basemul(&bp);
        let mut cc = cp.0;
        ntt_inverse(&mut cc);

        for i in 0..N {
            assert_eq!(cc[i], expected[i], "mismatch at {i}");
        }
    }
}
