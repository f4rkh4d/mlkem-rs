// ml-kem (fips 203) in pure rust. all three security levels.
// public api lives here, internal modules are crate-private.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all)]
#![allow(clippy::needless_range_loop)]

extern crate alloc;

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

pub use params::{Params, Params1024, Params512, Params768};

/// returned when a slice handed to a `TryFrom` impl on a key, ciphertext, or
/// shared secret newtype has the wrong length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthError {
    pub expected: usize,
    pub got: usize,
}

impl core::fmt::Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "wrong byte length: expected {}, got {}",
            self.expected, self.got
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

/// generic interface implemented by `MlKem512`, `MlKem768` and `MlKem1024`.
/// lets you write code that picks a parameter set at instantiation time.
///
/// ```
/// use mlkem::{Kem, MlKem768};
/// use rand::thread_rng;
///
/// fn handshake<K: Kem>() -> bool {
///     let mut rng = thread_rng();
///     let (pk, sk) = K::keygen(&mut rng);
///     let (ct, ss_a) = K::encapsulate(&pk, &mut rng);
///     let ss_b = K::decapsulate(&sk, &ct);
///     ss_a.as_ref() == ss_b.as_ref()
/// }
///
/// assert!(handshake::<MlKem768>());
/// ```
pub trait Kem {
    type PublicKey: Clone + AsRef<[u8]>;
    type SecretKey: Clone;
    type Ciphertext: Clone + AsRef<[u8]>;
    type SharedSecret: Clone + AsRef<[u8]>;

    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;
    const SHARED_SECRET_SIZE: usize = 32;

    fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate<R: RngCore + CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> (Self::Ciphertext, Self::SharedSecret);
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}

// macro that defines a public api type for one parameter set.
// `$name` is the entry point (MlKem512 etc), `$pk/$sk/$ct` are the byte sizes.
macro_rules! mlkem_api {
    ($name:ident, $params:ty, $pkty:ident, $skty:ident, $ctty:ident, $ssty:ident,
     $pk:expr, $sk:expr, $ct:expr) => {
        pub struct $name;

        impl $name {
            pub const PUBLIC_KEY_SIZE: usize = $pk;
            pub const SECRET_KEY_SIZE: usize = $sk;
            pub const CIPHERTEXT_SIZE: usize = $ct;
            pub const SHARED_SECRET_SIZE: usize = 32;

            /// deterministic keygen from a 64-byte seed (d || z).
            pub fn keygen_deterministic(seed: &[u8; 64]) -> ($pkty, $skty) {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                d.copy_from_slice(&seed[..32]);
                z.copy_from_slice(&seed[32..]);
                let (pk, sk) = mlkem::MlKem::<$params>::keygen(&d, &z);
                let mut pk_arr = [0u8; $pk];
                let mut sk_arr = [0u8; $sk];
                pk_arr.copy_from_slice(&pk);
                sk_arr.copy_from_slice(&sk);
                ($pkty(pk_arr), $skty(sk_arr))
            }

            pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> ($pkty, $skty) {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                Self::keygen_deterministic(&seed)
            }

            pub fn encapsulate_deterministic(pk: &$pkty, m: &[u8; 32]) -> ($ctty, $ssty) {
                let (ct, ss) = mlkem::MlKem::<$params>::encapsulate(&pk.0, m);
                let mut ct_arr = [0u8; $ct];
                ct_arr.copy_from_slice(&ct);
                ($ctty(ct_arr), $ssty(ss))
            }

            pub fn encapsulate<R: RngCore + CryptoRng>(pk: &$pkty, rng: &mut R) -> ($ctty, $ssty) {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                Self::encapsulate_deterministic(pk, &m)
            }

            pub fn decapsulate(sk: &$skty, ct: &$ctty) -> $ssty {
                $ssty(mlkem::MlKem::<$params>::decapsulate(&sk.0, &ct.0))
            }
        }

        #[derive(Clone)]
        pub struct $pkty(pub(crate) [u8; $pk]);

        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $skty(pub(crate) [u8; $sk]);

        #[derive(Clone)]
        pub struct $ctty(pub(crate) [u8; $ct]);

        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $ssty(pub(crate) [u8; 32]);

        #[cfg(feature = "serde")]
        const _: () = {
            use serde::de::{Error as DeError, SeqAccess, Visitor};
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            macro_rules! serde_byte_array {
                ($t:ident, $n:expr) => {
                    impl Serialize for $t {
                        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                            s.serialize_bytes(&self.0)
                        }
                    }
                    impl<'de> Deserialize<'de> for $t {
                        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                            struct BytesVisitor;
                            impl<'de> Visitor<'de> for BytesVisitor {
                                type Value = [u8; $n];
                                fn expecting(
                                    &self,
                                    f: &mut core::fmt::Formatter,
                                ) -> core::fmt::Result {
                                    write!(f, concat!("a byte sequence of length ", stringify!($n)))
                                }
                                fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<[u8; $n], E> {
                                    if v.len() != $n {
                                        return Err(E::invalid_length(v.len(), &self));
                                    }
                                    let mut a = [0u8; $n];
                                    a.copy_from_slice(v);
                                    Ok(a)
                                }
                                fn visit_seq<A: SeqAccess<'de>>(
                                    self,
                                    mut seq: A,
                                ) -> Result<[u8; $n], A::Error> {
                                    let mut a = [0u8; $n];
                                    for i in 0..$n {
                                        a[i] = seq
                                            .next_element()?
                                            .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                                    }
                                    Ok(a)
                                }
                            }
                            d.deserialize_bytes(BytesVisitor).map($t)
                        }
                    }
                };
            }

            serde_byte_array!($pkty, $pk);
            serde_byte_array!($skty, $sk);
            serde_byte_array!($ctty, $ct);
            serde_byte_array!($ssty, 32);
        };

        impl $pkty {
            pub fn as_bytes(&self) -> &[u8; $pk] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $pk]) -> Self {
                Self(*b)
            }
        }
        impl $skty {
            pub fn as_bytes(&self) -> &[u8; $sk] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $sk]) -> Self {
                Self(*b)
            }
        }
        impl $ctty {
            pub fn as_bytes(&self) -> &[u8; $ct] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $ct]) -> Self {
                Self(*b)
            }
        }
        impl $ssty {
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl PartialEq for $pkty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $pkty {}
        impl PartialEq for $skty {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_slice().ct_eq(other.0.as_slice()).into()
            }
        }
        impl Eq for $skty {}
        impl PartialEq for $ctty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $ctty {}
        impl PartialEq for $ssty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $ssty {}

        impl core::fmt::Debug for $pkty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($pkty), "(..{} bytes..)"),
                    self.0.len()
                )
            }
        }
        impl core::fmt::Debug for $skty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($skty), "(..REDACTED..)"))
            }
        }
        impl core::fmt::Debug for $ctty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($ctty), "(..{} bytes..)"),
                    self.0.len()
                )
            }
        }
        impl core::fmt::Debug for $ssty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($ssty), "(..REDACTED..)"))
            }
        }

        impl Zeroize for $skty {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        impl Zeroize for $ssty {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl TryFrom<&[u8]> for $pkty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $pk {
                    return Err(LengthError {
                        expected: $pk,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $pk];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }
        impl TryFrom<&[u8]> for $skty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $sk {
                    return Err(LengthError {
                        expected: $sk,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $sk];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }
        impl TryFrom<&[u8]> for $ctty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $ct {
                    return Err(LengthError {
                        expected: $ct,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $ct];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }

        impl AsRef<[u8]> for $pkty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $ctty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $skty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $ssty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Kem for $name {
            type PublicKey = $pkty;
            type SecretKey = $skty;
            type Ciphertext = $ctty;
            type SharedSecret = $ssty;
            const PUBLIC_KEY_SIZE: usize = $pk;
            const SECRET_KEY_SIZE: usize = $sk;
            const CIPHERTEXT_SIZE: usize = $ct;

            fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> ($pkty, $skty) {
                <$name>::keygen(rng)
            }
            fn encapsulate<R: RngCore + CryptoRng>(pk: &$pkty, rng: &mut R) -> ($ctty, $ssty) {
                <$name>::encapsulate(pk, rng)
            }
            fn decapsulate(sk: &$skty, ct: &$ctty) -> $ssty {
                <$name>::decapsulate(sk, ct)
            }
        }
    };
}

// ml-kem-512: pk 800, sk 1632, ct 768. fips 203 table 3, security category 1.
mlkem_api!(
    MlKem512,
    Params512,
    PublicKey512,
    SecretKey512,
    Ciphertext512,
    SharedSecret512,
    800,
    1632,
    768
);

// ml-kem-768: pk 1184, sk 2400, ct 1088. security category 3 (default if you must pick one).
mlkem_api!(
    MlKem768,
    Params768,
    PublicKey768,
    SecretKey768,
    Ciphertext768,
    SharedSecret768,
    1184,
    2400,
    1088
);

// ml-kem-1024: pk 1568, sk 3168, ct 1568. security category 5.
mlkem_api!(
    MlKem1024,
    Params1024,
    PublicKey1024,
    SecretKey1024,
    Ciphertext1024,
    SharedSecret1024,
    1568,
    3168,
    1568
);

// back-compat aliases for the old 0.1 api.
pub type PublicKey = PublicKey768;
pub type SecretKey = SecretKey768;
pub type Ciphertext = Ciphertext768;
pub type SharedSecret = SharedSecret768;
