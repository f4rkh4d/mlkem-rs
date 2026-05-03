# changelog

format follows [keep-a-changelog](https://keepachangelog.com).
this project uses [semver](https://semver.org/).

## [0.4.0]

### added
- `no_std` support. `default-features = ["std"]` keeps existing users on the std path; disable defaults to compile against `core` + `alloc`. embedded users get the kem with `cargo add mlkem-rs --no-default-features`.
- ci now builds for `thumbv7em-none-eabihf` (cortex-m4) and `wasm32-unknown-unknown` on every push.

### changed
- `sha3`, `rand_core`, `subtle`, `zeroize` are pulled with `default-features = false`. our `std` feature flips theirs back on.
- internal modules use `core::` / `alloc::` paths instead of `std::`.

## [0.3.0]

### added
- `tests/nist_kats.rs` runs all 180 official nist acvp test vectors for ml-kem (75 keygen, 75 encapsulation, 30 decapsulation, all three parameter sets). every byte matches.
- vectors live in `tests/nist-kats/key-gen.json` and `tests/nist-kats/encap-decap.json`, sourced from the [acvp server reference dump](https://github.com/usnistgov/ACVP-Server) via the rustcrypto mirror.
- new dev-dep `serde_json` to parse the acvp test files.

### notes
- this is a *correctness* release. the implementation did not move; we just got hit with the official ground truth and it held up. the 3000-seed cross-check from 0.2.0 turned out to be a pretty accurate predictor.

## [0.2.0]

### added
- `MlKem512` and `MlKem1024` alongside the existing `MlKem768`. all three fips 203 parameter sets, distinct newtypes per level (`PublicKey512` etc).
- `tests/api.rs` and `tests/cross_check.rs` are now macro-instantiated across all three levels.
- `Params` trait + `Params512` / `Params768` / `Params1024` impls in the public api so external code can write code generic over a parameter set.

### changed
- internal `kpke` and `mlkem` are generic over `P: Params`. `PolyVec` / `MatrixNtt` now carry their dimension at runtime; the same code covers k=2/3/4.
- cross-check vs the audited rustcrypto `ml-kem` runs 1000 deterministic seeds per parameter set (3000 total) instead of 50, with a fixed rng seed for reproducibility.
- `[lib].name = "mlkem"` so user code stays `use mlkem::...` even though the crate publishes as `mlkem-rs`.

## [0.1.0]

### added
- initial release.