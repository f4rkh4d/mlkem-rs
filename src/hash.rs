// fips 203 names the sha-3 primitives H, J, G, XOF, PRF. this file wraps them.
// H  = SHA3-256
// J  = SHAKE256(., 32)
// G  = SHA3-512
// XOF(rho, j, i) = SHAKE128(rho || j || i)
// PRF_eta(s, b) = SHAKE256(s || b), squeezing 64*eta bytes

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake128Reader, Shake256};

pub fn h(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    let out = hasher.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn j(input: &[u8]) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(input);
    let mut reader = xof.finalize_xof();
    let mut r = [0u8; 32];
    reader.read(&mut r);
    r
}

pub fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    let out = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

// xof with prefix rho || j || i (single bytes j, i).
pub fn xof_init(rho: &[u8; 32], j: u8, i: u8) -> Shake128Reader {
    let mut x = Shake128::default();
    x.update(rho);
    x.update(&[j, i]);
    x.finalize_xof()
}

// prf_eta(s, b) returns 64*eta bytes from SHAKE256(s || b).
pub fn prf(eta: usize, s: &[u8; 32], b: u8) -> Vec<u8> {
    let mut x = Shake256::default();
    x.update(s);
    x.update(&[b]);
    let mut reader = x.finalize_xof();
    let mut out = vec![0u8; 64 * eta];
    reader.read(&mut out);
    out
}
