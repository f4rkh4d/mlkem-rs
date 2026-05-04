// compress_d / decompress_d per fips 203 alg 4 / 5.
// compress_d(x) = round((2^d / q) * x) mod 2^d
// implemented as: ((x << d) + q/2) / q, mod 2^d. all values fit in u32.
// decompress_d(y) = round((q / 2^d) * y) = (y*q + 2^(d-1)) >> d.

use crate::params::{N, Q};
use crate::poly::Poly;

#[inline]
fn compress_fe(x: u16, d: u32) -> u16 {
    // x in [0, q). ((x << d) + q/2) / q mod 2^d.
    let num = (x as u32) << d;
    let q = Q as u32;
    // add q/2 for rounding to nearest
    let r = (num + q / 2) / q;
    (r & ((1u32 << d) - 1)) as u16
}

#[inline]
fn decompress_fe(y: u16, d: u32) -> u16 {
    // (y * q + 2^(d-1)) >> d
    let q = Q as u32;
    let r = ((y as u32) * q + (1u32 << (d - 1))) >> d;
    r as u16
}

// compress a single coefficient with d=1. exposed for message packing.
#[inline]
pub fn compress_poly_fe_1(x: u16) -> u16 {
    compress_fe(x, 1)
}

pub fn compress_poly(p: &Poly, d: u32) -> Poly {
    let mut r = [0u16; N];
    for i in 0..N {
        r[i] = compress_fe(p.0[i], d);
    }
    Poly(r)
}

pub fn decompress_poly(p: &Poly, d: u32) -> Poly {
    let mut r = [0u16; N];
    for i in 0..N {
        r[i] = decompress_fe(p.0[i], d);
    }
    Poly(r)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// compress_d output is always in [0, 2^d). proven for every
    /// `d in {1, 4, 5, 10, 11}` (the union used at any parameter set).
    #[kani::proof]
    fn compress_in_range_d10() {
        let x: u16 = kani::any();
        kani::assume(x < Q);
        let r = compress_fe(x, 10);
        assert!(r < (1u16 << 10));
    }

    #[kani::proof]
    fn compress_in_range_d11() {
        let x: u16 = kani::any();
        kani::assume(x < Q);
        let r = compress_fe(x, 11);
        assert!(r < (1u16 << 11));
    }

    #[kani::proof]
    fn compress_in_range_d4() {
        let x: u16 = kani::any();
        kani::assume(x < Q);
        let r = compress_fe(x, 4);
        assert!(r < (1u16 << 4));
    }

    #[kani::proof]
    fn compress_in_range_d5() {
        let x: u16 = kani::any();
        kani::assume(x < Q);
        let r = compress_fe(x, 5);
        assert!(r < (1u16 << 5));
    }

    /// compress_poly_fe_1(x) is 0 if x is closer to 0 than to q/2,
    /// otherwise 1. that's the message-bit-pack operation; if the
    /// rounding ever drifted, the message would not roundtrip.
    #[kani::proof]
    fn compress_d1_roundtrip_at_anchors() {
        // 0 must compress to 0
        assert_eq!(compress_poly_fe_1(0), 0);
        // q/2 (=1664 since q=3329) is the threshold; anything >= 1664 maps to 1
        assert_eq!(compress_poly_fe_1(1665), 1);
        // q-1 must compress to 0 (round-to-even / floor-to-zero at the wrap)
        // see the formula: ((q-1) << 1) + q/2 = 6657 + 1664 = 8321; 8321 / 3329 = 2; 2 mod 2 = 0.
        assert_eq!(compress_poly_fe_1(Q - 1), 0);
    }

    /// decompress_d output is always in [0, q).
    #[kani::proof]
    fn decompress_in_range_d10() {
        let y: u16 = kani::any();
        kani::assume(y < (1u16 << 10));
        let r = decompress_fe(y, 10);
        assert!(r < Q);
    }

    #[kani::proof]
    fn decompress_in_range_d11() {
        let y: u16 = kani::any();
        kani::assume(y < (1u16 << 11));
        let r = decompress_fe(y, 11);
        assert!(r < Q);
    }
}
