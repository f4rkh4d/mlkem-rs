// sampling: uniform rejection (for matrix A) and centered binomial (CBD) for noise.
// fips 203 alg 6 (sampleNTT) and alg 7 (sampleCBD).

use crate::hash::{prf, xof_init};
use crate::params::{N, Q};
use crate::poly::{Poly, PolyNtt};
use sha3::digest::XofReader;

// alg 6. samples a polynomial in R_q directly in ntt domain from a squeezing xof.
// read 3 bytes at a time, parse two 12-bit candidates, accept if < q.
pub fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> PolyNtt {
    let mut reader = xof_init(rho, j, i);
    let mut out = [0u16; N];
    let mut count = 0;
    let mut buf = [0u8; 168]; // shake128 rate = 168 bytes
    while count < N {
        reader.read(&mut buf);
        let mut k = 0;
        while k + 3 <= buf.len() && count < N {
            let d1 = (buf[k] as u16) | (((buf[k + 1] as u16) & 0x0f) << 8);
            let d2 = ((buf[k + 1] as u16) >> 4) | ((buf[k + 2] as u16) << 4);
            if d1 < Q {
                out[count] = d1;
                count += 1;
            }
            if d2 < Q && count < N {
                out[count] = d2;
                count += 1;
            }
            k += 3;
        }
    }
    PolyNtt(out)
}

// alg 7. sample CBD_eta from 64*eta bytes. coefficients in {-eta, .., eta},
// returned in Z_q (so negatives become q-|x|).
fn cbd(bytes: &[u8], eta: usize) -> Poly {
    assert_eq!(bytes.len(), 64 * eta);
    let mut out = [0u16; N];
    // read as a bit stream. for each coefficient, sum eta bits then subtract sum of eta bits.
    // we do it via chunks of 4 bytes = 32 bits for eta=2, 3 bytes for eta=3.
    if eta == 2 {
        // each coeff uses 4 bits: 2 bits a, 2 bits b, coeff = popcount(a) - popcount(b).
        // 8 coeffs per 4 bytes.
        for i in 0..(N / 8) {
            let chunk = u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
            // split into even and odd bits
            let t = (chunk & 0x55555555) + ((chunk >> 1) & 0x55555555);
            // now t has 2-bit popcounts in each 2-bit slot
            for k in 0..8 {
                let a = (t >> (4 * k)) & 0x3;
                let b = (t >> (4 * k + 2)) & 0x3;
                let c = a as i32 - b as i32;
                let v = if c < 0 { Q as i32 + c } else { c };
                out[8 * i + k] = v as u16;
            }
        }
    } else if eta == 3 {
        // 6 bits per coeff, 4 coeffs per 3 bytes.
        for i in 0..(N / 4) {
            let chunk = (bytes[3 * i] as u32)
                | ((bytes[3 * i + 1] as u32) << 8)
                | ((bytes[3 * i + 2] as u32) << 16);
            let t = (chunk & 0x249249) + ((chunk >> 1) & 0x249249) + ((chunk >> 2) & 0x249249);
            for k in 0..4 {
                let a = (t >> (6 * k)) & 0x7;
                let b = (t >> (6 * k + 3)) & 0x7;
                let c = a as i32 - b as i32;
                let v = if c < 0 { Q as i32 + c } else { c };
                out[4 * i + k] = v as u16;
            }
        }
    } else {
        panic!("unsupported eta");
    }
    Poly(out)
}

pub fn sample_cbd_poly(s: &[u8; 32], b: u8, eta: usize) -> Poly {
    let bytes = prf(eta, s, b);
    cbd(&bytes, eta)
}
