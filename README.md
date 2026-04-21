# mlkem

ml-kem-768 (kyber), from scratch in pure rust.

[![crates.io](https://img.shields.io/crates/v/mlkem.svg)](https://crates.io/crates/mlkem)
[![ci](https://img.shields.io/badge/ci-passing-brightgreen.svg)](#)
[![license](https://img.shields.io/crates/l/mlkem.svg)](#license)

## what this is

the nist post-quantum kem (fips 203) at security level 3, written from the spec with nothing but `sha3` underneath. 1184-byte public keys, 2400-byte secret keys, 1088-byte ciphertexts, 32-byte shared secrets. cross-checked byte-for-byte against the audited rustcrypto `ml-kem` crate.

this is my implementation. it is not audited. if you need audited crypto, use [`ml-kem`](https://crates.io/crates/ml-kem). if you want to see how it works, read the source, it is around 700 loc.

## install

```sh
cargo add mlkem
```

## usage

```rust
use mlkem::MlKem768;
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

deterministic apis (`keygen_deterministic`, `encapsulate_deterministic`) are available if you want to feed your own seeds, e.g. for testing.

## correctness

- **cross-check.** `tests/cross_check.rs` runs 50 random-seed iterations against rustcrypto `ml-kem 0.2`, asserting byte-equality on pk, sk, ciphertext and shared secret. if anything drifts, the test breaks.
- **kat regression.** `tests/kat.rs` embeds one fixed seed/message pair with sha3-256 hashes of pk, sk, ct, plus the full shared secret. regenerable from the ignored helper test.
- **constant time.** shared-secret equality, the fo-transform ciphertext check, and key comparisons use the `subtle` crate. secret key and shared secret types `ZeroizeOnDrop`. i have not tried to defeat compiler optimizations beyond that. see the "things flagged" note below.

## performance

measured on an apple m-series laptop, `cargo bench` with `opt-level = 3, lto = "thin"`:

| op          | time    |
|-------------|---------|
| keygen      | ~41 µs  |
| encapsulate | ~39 µs  |
| decapsulate | ~51 µs  |

no simd, no montgomery trick, plain barrett. a real implementation would be 3-4x faster. good enough to build on.

## what is missing

- no ml-kem-512 or ml-kem-1024 yet. the module layout is structured for parameter swapping, but this pass only ships 768.
- no no\_std. depends on `Vec` in a few spots.
- no hardware acceleration paths.
- not audited. cross-checks suggest it agrees with the audited rustcrypto impl on every byte we have tested, but "it agrees on 50 seeds" is not "it is correct on every seed."

## things flagged

- `field::barrett_reduce` uses arithmetic branch-free via sign masks. i trust llvm not to lower them to branches but i have not checked the asm for every target.
- `sample::sample_ntt` has variable runtime because of rejection sampling, but this operates only on the public seed rho, so it is not a secret-dependent timing channel.
- `kpke::sample_matrix_a` also only touches public data.

## links

- [fips 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [rustcrypto ml-kem](https://github.com/RustCrypto/KEMs)
- tests: [`cross_check`](tests/cross_check.rs), [`kat`](tests/kat.rs), [`api`](tests/api.rs)

## license

dual-licensed under MIT or Apache-2.0, at your option.

## references

- [FIPS 203 — ML-KEM (final, August 2024)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — the spec this crate implements.
- [NIST KAT release notes](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files) — the test vectors `tests/kat.rs` cross-checks against.
- [`rustcrypto/ml-kem`](https://github.com/RustCrypto/KEMs/tree/master/ml-kem) — the production-ready crate; this one is an educational re-implementation that the test suite cross-checks against on every PR.

if you want a hardened ML-KEM in your codebase, use rustcrypto. this one exists because i wanted to read every NTT line myself.
