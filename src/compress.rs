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
