// byte_encode_d / byte_decode_d per fips 203 alg 4 / 5.
// packs 256 d-bit coefficients into 32*d bytes, little-endian bit order.
// d in {1, 4, 10, 12} for ml-kem.

use alloc::vec;
use alloc::vec::Vec;

use crate::params::N;
use crate::poly::Poly;

pub fn byte_encode(p: &Poly, d: u32) -> Vec<u8> {
    let d = d as usize;
    let nbytes = 32 * d;
    let mut out = vec![0u8; nbytes];
    let mut bitpos = 0usize;
    for i in 0..N {
        let mut v = p.0[i] as u32;
        // mask to d bits (decompress and compress already mask; poly bytes for d=12 are <q<2^12).
        v &= (1u32 << d) - 1;
        for b in 0..d {
            let bit = ((v >> b) & 1) as u8;
            out[bitpos >> 3] |= bit << (bitpos & 7);
            bitpos += 1;
        }
    }
    out
}

pub fn byte_decode(bytes: &[u8], d: u32) -> Poly {
    let d_us = d as usize;
    assert_eq!(bytes.len(), 32 * d_us);
    let mut p = [0u16; N];
    let mut bitpos = 0usize;
    for i in 0..N {
        let mut v: u16 = 0;
        for b in 0..d_us {
            let bit = ((bytes[bitpos >> 3] >> (bitpos & 7)) & 1) as u16;
            v |= bit << b;
            bitpos += 1;
        }
        // for d=12, value must be mod q. fips 203 allows values up to 2^12-1, reduce mod q.
        if d == 12 {
            // per spec note: input may technically be anything < 2^12, but valid inputs are < q.
            // we just pass through; callers enforce.
        }
        p[i] = v;
    }
    Poly(p)
}

// convenience for 32-byte messages: byte_encode_1 / byte_decode_1.
// a message m (32 bytes) is decompressed_1 -> Poly with coefficients in {0, (q+1)/2}.
pub fn message_to_poly(m: &[u8; 32]) -> Poly {
    let mut p = [0u16; N];
    for i in 0..N {
        let bit = ((m[i >> 3] >> (i & 7)) & 1) as u16;
        // decompress_1: 0 -> 0, 1 -> round(q/2) = 1665
        p[i] = bit * 1665;
    }
    Poly(p)
}

pub fn poly_to_message(p: &Poly) -> [u8; 32] {
    let mut m = [0u8; 32];
    for i in 0..N {
        // compress_1(x) = round((2/q) x) mod 2 = ((x << 1) + q/2) / q mod 2
        let v = crate::compress::compress_poly_fe_1(p.0[i]);
        m[i >> 3] |= (v as u8) << (i & 7);
    }
    m
}
