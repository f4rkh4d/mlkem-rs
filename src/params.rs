// fips 203 parameter constants. ml-kem-768 only for now.
// leaves k/eta/du/dv as module consts so swapping a param file
// gets you 512 or 1024 later.

pub const N: usize = 256;
pub const Q: u16 = 3329;

// ml-kem-768
pub const K: usize = 3;
pub const ETA1: usize = 2;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;

// derived sizes per fips 203 table 3
pub const POLY_BYTES: usize = 384; // 256 * 12 / 8
pub const POLYVEC_BYTES: usize = POLY_BYTES * K;

pub const EK_PKE_BYTES: usize = POLYVEC_BYTES + 32; // t_hat + rho
pub const DK_PKE_BYTES: usize = POLYVEC_BYTES;

pub const PUBLIC_KEY_SIZE: usize = EK_PKE_BYTES;
// sk = dk_pke || ek_pke || H(ek_pke) || z
pub const SECRET_KEY_SIZE: usize = DK_PKE_BYTES + EK_PKE_BYTES + 32 + 32;

pub const CT_C1_BYTES: usize = DU * N / 8 * K; // 32 * du * k
pub const CT_C2_BYTES: usize = DV * N / 8; // 32 * dv
pub const CIPHERTEXT_SIZE: usize = CT_C1_BYTES + CT_C2_BYTES;

pub const SHARED_SECRET_SIZE: usize = 32;
