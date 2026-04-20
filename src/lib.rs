// ml-kem-768 (fips 203) in pure rust.
// public api lives here. everything else is module-private but accessible via crate::.

#![warn(clippy::all)]
#![allow(clippy::needless_range_loop)]

mod compress;
mod field;
mod hash;
mod kpke;
mod mlkem;
mod ntt;
mod params;
mod poly;
mod sample;
mod serialize;

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct MlKem768;

impl MlKem768 {
    pub const PUBLIC_KEY_SIZE: usize = params::PUBLIC_KEY_SIZE;
    pub const SECRET_KEY_SIZE: usize = params::SECRET_KEY_SIZE;
    pub const CIPHERTEXT_SIZE: usize = params::CIPHERTEXT_SIZE;
    pub const SHARED_SECRET_SIZE: usize = params::SHARED_SECRET_SIZE;

    /// deterministic keygen from a 64-byte seed (d || z).
    pub fn keygen_deterministic(seed: &[u8; 64]) -> (PublicKey, SecretKey) {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (pk, sk) = mlkem::keygen(&d, &z);
        (PublicKey(pk), SecretKey(sk))
    }

    /// random keygen using a CSPRNG.
    pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicKey, SecretKey) {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self::keygen_deterministic(&seed)
    }

    pub fn encapsulate_deterministic(pk: &PublicKey, m: &[u8; 32]) -> (Ciphertext, SharedSecret) {
        let (ct, ss) = mlkem::encapsulate(&pk.0, m);
        (Ciphertext(ct), SharedSecret(ss))
    }

    pub fn encapsulate<R: RngCore + CryptoRng>(
        pk: &PublicKey,
        rng: &mut R,
    ) -> (Ciphertext, SharedSecret) {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        Self::encapsulate_deterministic(pk, &m)
    }

    pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
        SharedSecret(mlkem::decapsulate(&sk.0, &ct.0))
    }
}

#[derive(Clone)]
pub struct PublicKey(pub(crate) [u8; params::PUBLIC_KEY_SIZE]);
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; params::SECRET_KEY_SIZE]);
#[derive(Clone)]
pub struct Ciphertext(pub(crate) [u8; params::CIPHERTEXT_SIZE]);
#[derive(Clone, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; params::PUBLIC_KEY_SIZE] {
        &self.0
    }
    pub fn from_bytes(b: &[u8; params::PUBLIC_KEY_SIZE]) -> Self {
        Self(*b)
    }
}

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; params::SECRET_KEY_SIZE] {
        &self.0
    }
    pub fn from_bytes(b: &[u8; params::SECRET_KEY_SIZE]) -> Self {
        Self(*b)
    }
}

impl Ciphertext {
    pub fn as_bytes(&self) -> &[u8; params::CIPHERTEXT_SIZE] {
        &self.0
    }
    pub fn from_bytes(b: &[u8; params::CIPHERTEXT_SIZE]) -> Self {
        Self(*b)
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ct-eq for sensitive types. pk/ct equality is public but harmless to also ct-eq.
impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for PublicKey {}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}
impl Eq for SecretKey {}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Ciphertext {}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for SharedSecret {}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey(..{} bytes..)", self.0.len())
    }
}
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(_f, "SecretKey(..REDACTED..)")
    }
}
impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ciphertext(..{} bytes..)", self.0.len())
    }
}
impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(_f, "SharedSecret(..REDACTED..)")
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
