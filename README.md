# mlkem

post-quantum kem (ml-kem, formerly kyber) in pure rust. all three security levels. passes all 180 official nist acvp test vectors and is byte-for-byte cross-checked against the audited rustcrypto reference on 3000 random seeds. ~700 lines of code, sha3 is the only crypto dependency.

[![crates.io](https://img.shields.io/crates/v/mlkem-rs.svg)](https://crates.io/crates/mlkem-rs)
[![docs.rs](https://img.shields.io/docsrs/mlkem-rs)](https://docs.rs/mlkem-rs)
[![downloads](https://img.shields.io/crates/d/mlkem-rs.svg)](https://crates.io/crates/mlkem-rs)
[![ci](https://github.com/f4rkh4d/mlkem-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/f4rkh4d/mlkem-rs/actions)
[![msrv](https://img.shields.io/badge/msrv-1.70-blue.svg)](#)
[![no_std](https://img.shields.io/badge/no__std-yes-success.svg)](#)
[![license](https://img.shields.io/crates/l/mlkem-rs.svg)](#license)

## what this is

an implementation of [fips 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), the nist standard for post-quantum key encapsulation that replaced kyber. all three parameter sets (security categories 1, 3, 5):

| variant      | k | pk      | sk      | ct      | nist category |
|--------------|---|---------|---------|---------|---------------|
| ml-kem-512   | 2 | 800 B   | 1632 B  | 768 B   | 1 (aes-128)   |
| ml-kem-768   | 3 | 1184 B  | 2400 B  | 1088 B  | 3 (aes-192)   |
| ml-kem-1024  | 4 | 1568 B  | 3168 B  | 1568 B  | 5 (aes-256)   |

written from the spec. only crypto dependency is `sha3`. no `unsafe`. no c bindings. `no_std` compatible (default feature `std` is on; turn it off for embedded).

this is my implementation. it is not audited. if you need audited crypto for production, use [`ml-kem`](https://crates.io/crates/ml-kem) from rustcrypto. if you want to read 700 lines of post-quantum code top to bottom, this one was written for that.

## install

```sh
cargo add mlkem-rs
```

## usage

```rust
use mlkem::{MlKem768, PublicKey768, SecretKey768};
use rand::thread_rng;

let mut rng = thread_rng();

// bob generates a keypair
let (bob_pk, bob_sk) = MlKem768::keygen(&mut rng);

// alice encapsulates to bob's public key
let (ct, alice_ss) = MlKem768::encapsulate(&bob_pk, &mut rng);

// bob decapsulates and recovers the same shared secret
let bob_ss = MlKem768::decapsulate(&bob_sk, &ct);
assert_eq!(alice_ss, bob_ss);
```

`MlKem512` and `MlKem1024` have the same surface. deterministic apis (`keygen_deterministic`, `encapsulate_deterministic`) are available if you need to feed your own seeds, e.g. for testing.

## correctness

- **nist acvp vectors.** `tests/nist_kats.rs` runs all 180 official ml-kem test cases from the [nist algorithm validation program](https://github.com/usnistgov/ACVP-Server) (75 keygen + 75 encapsulation + 30 decapsulation), spread evenly across the three parameter sets. every byte of every output matches.
- **cross-check.** `tests/cross_check.rs` runs 1000 deterministic seeds **per parameter set** through both this crate and the audited [rustcrypto `ml-kem`](https://crates.io/crates/ml-kem). it asserts byte-equality on pk, sk, ciphertext, and the recovered shared secret. 3000 round-trips total. if anything drifts, the test breaks.
- **api tests.** `tests/api.rs` covers handshake, determinism, sizes, implicit-reject on tampered ciphertext, and serialization roundtrip. macro-instantiated for all three levels.
- **stress.** `tests/stress.rs` runs 24000 fixed-seed iterations on every `cargo test`: 5000 honest round-trips, 2000 random-tamper implicit-reject checks, 1000 garbage-input decap calls, all per parameter set. ~1 second total.
- **fuzz.** `fuzz/` ships a `cargo-fuzz` harness with four targets (decap-no-panic, encap-no-panic, tampered-ct-implicit-reject, round-trip). nightly only; see `fuzz/README.md`.
- **constant time.** shared-secret equality, the fo-transform ciphertext check, and key comparisons use [`subtle`](https://crates.io/crates/subtle). secret keys and shared secrets are `ZeroizeOnDrop`. compiler-level constant-time guarantees beyond that have not been measured. see "things flagged" below.
- **memory.** internal buffers go through `Vec`. wipe-on-drop applies to the public `SecretKey*` and `SharedSecret*` types, not to internal scratch. if you need a stronger story, audit before relying.

## performance

apple m-series, `cargo bench` with `opt-level = 3, lto = "thin"`, no simd, plain barrett:

| op           | ml-kem-512 | ml-kem-768 | ml-kem-1024 |
|--------------|-----------:|-----------:|------------:|
| keygen       | 26 µs      | 40 µs      | 57 µs       |
| encapsulate  | 25 µs      | 38 µs      | 60 µs       |
| decapsulate  | 33 µs      | 50 µs      | 77 µs       |

for reference, [rustcrypto `ml-kem`](https://crates.io/crates/ml-kem) on the same machine: 13 / 12 / 17 µs at 512, 23 / 20 / 25 at 768, 36 / 31 / 38 at 1024. so this crate sits at roughly 1.7-2x the cycles of the audited reference, consistently across all three levels. the gap is from no montgomery and no simd. enough for tooling and study, not enough if you serve a million handshakes a second.

heap-allocation-wise, the algebraic core (matrix sample, polyvecs, ntt, basemul) is allocation-free since 0.5.0. the only allocations left are the byte-encoded outputs `Vec<u8>` returned by `kpke::keygen` / `encrypt`, which are then copied into the public api's fixed-size arrays.

## what is missing

- no hardware acceleration paths (no avx2, no neon, no aarch64 sve).
- not audited. cross-checks against the audited rustcrypto crate are byte-equal on every byte we have ever tested, but "agrees on 3000 seeds" is not "is correct on every seed."

## things flagged

- `field::barrett_reduce` reduces to `i32` arithmetic with sign-mask normalize. branch-free in source, trusting llvm not to lower the masks to branches. asm has not been verified for every target.
- `sample::sample_ntt` has variable runtime due to rejection sampling, but it operates only on the public seed `rho`. no secret-dependent timing channel.
- `kpke::sample_matrix_a` similarly only touches public data.
- internal scratch is now stack-allocated since 0.5.0 (`MAX_K = 4` upper bound). allocation timing is no longer a side channel for the algebraic ops; only the byte-encode outputs go through `Vec<u8>`.

## features

- `std` (default). standard-library hooks (`std::error::Error` on `LengthError`, std versions of crypto deps).
- `serde`. `Serialize` / `Deserialize` on every key, ciphertext, and shared-secret newtype across all three parameter sets.

## examples

```sh
cargo run --release --example handshake
cargo run --release --example serde_save_restore --features serde
```

## links

- [fips 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [rustcrypto ml-kem](https://github.com/RustCrypto/KEMs)
- [pq-crystals/kyber reference](https://github.com/pq-crystals/kyber)
- [nist acvp test vectors](https://github.com/usnistgov/ACVP-Server)
- tests: [`nist_kats`](tests/nist_kats.rs), [`cross_check`](tests/cross_check.rs), [`api`](tests/api.rs), [`stress`](tests/stress.rs), [`serde_roundtrip`](tests/serde_roundtrip.rs)
- examples: [`handshake`](examples/handshake.rs), [`serde_save_restore`](examples/serde_save_restore.rs)
- changelog: [CHANGELOG.md](CHANGELOG.md)

## license

dual-licensed under MIT or Apache-2.0, at your option.
