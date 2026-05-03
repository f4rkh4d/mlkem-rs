// fips 203 parameter sets. ml-kem-512, -768, -1024 (security categories 1, 3, 5).
// internal code is generic over the Params trait; concrete byte sizes live on the
// public api types.

pub const N: usize = 256;
pub const Q: u16 = 3329;
pub const POLY_BYTES: usize = 384; // 256 * 12 / 8

pub trait Params: 'static {
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
}

pub struct Params512;
impl Params for Params512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

pub struct Params768;
impl Params for Params768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

pub struct Params1024;
impl Params for Params1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}
