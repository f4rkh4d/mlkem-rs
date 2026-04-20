//! ml-kem-768 (fips 203). wip.
//!
//! q = 3329, n = 256, k = 3. foundations only at this commit:
//! field arithmetic in z_q, polynomials in r_q, and the ntt.

pub mod field;
pub mod ntt;
pub mod params;
pub mod poly;
