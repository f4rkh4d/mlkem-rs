# changelog

format follows [keep-a-changelog](https://keepachangelog.com).
this project uses [semver](https://semver.org/).

## [0.10.0]

### added
- [`FORMAL_VERIFICATION.md`](FORMAL_VERIFICATION.md): documentation of every kani-checked proof in the crate.
- 10 [`kani`](https://model-checking.github.io/kani/) formal-verification harnesses. they live behind `#[cfg(kani)]` so normal builds are unaffected. all ten verify successfully on apple m-series in under 60 seconds total. exhaustively check the field-arithmetic and compression invariants:
  - `src/field.rs`: barrett_reduce matches naive mod for every `a` in `[0, Q*Q)`; fqadd/fqsub/fqmul stay in the field for every legal input pair.
  - `src/compress.rs`: compress_d output is always in `[0, 2^d)` for d in {4, 5, 10, 11}; decompress_d output is always in `[0, Q)` for d in {10, 11}; the 1-bit message-pack hits the spec values at 0, q/2, q-1.
- run with `cargo install --locked kani-verifier && cargo kani setup && cargo kani`.

### notes
- the field-arithmetic and bit-pack layer is exactly where rust ML-KEM implementations tend to ship subtle bugs (wrong barrett constant, compress rounding off-by-one, unchecked overflow). closing those edges with a bounded model check removes a whole category of failure from the audit checklist.

## [0.9.0]

### added
- [`SECURITY.md`](SECURITY.md): public threat model, scope, audit-readiness statement, vulnerability disclosure path, what we promise to fix on the spot vs what we do not.
- [`SIDE_CHANNELS.md`](SIDE_CHANNELS.md): line-by-line inventory of every secret-dependent operation in the crate plus its protection. designed to match what an auditor expects to see on hand-review pass one.
- [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md): one-page scope-suggestion document for anyone commissioning a third-party audit. lists in-scope, out-of-scope, and a suggested 8.5 person-day methodology.
- [`tests/timing.rs`](tests/timing.rs): a [dudect](https://github.com/oreparaz/dudect)-style statistical timing test. interleaves decapsulation on honest vs tampered ciphertexts and computes the welch t-statistic. on apple m-series with 20000 samples we see `|t|=1.232` (well under dudect's strict threshold of 4.5). a smoke version runs on every `cargo test`; a longer campaign is available with `MLKEM_TIMING_SAMPLES=200000 cargo test --release --test timing -- --ignored`.

### notes
- this is a "industry-readiness" release. no algorithm changes. the work is in making it cheap and credible to audit, both by humans and statistically.
- the artifacts in this release lower the cost-floor for a real third-party audit by roughly half: an auditor can start from the inventory rather than discovering it from cold source.

## [0.8.11]

### fixed
- `pub use poly::MAX_K;` so the `MAX_K` const promised by the 0.5.0 changelog is actually reachable from outside the crate. previously the const lived in a private module and was unreachable. thanks to @wholovesalife for catching this in [#3](https://github.com/f4rkh4d/mlkem-rs/pull/3).
- regression test in `tests/api.rs` asserts `mlkem::MAX_K == 4` and that it stays `>=` every parameter set's `K`.

## [0.8.10]

### fixed
- removed `#![cfg_attr(docsrs, feature(doc_auto_cfg))]`. the `doc_auto_cfg` rustdoc feature was stabilized and the unstable opt-in was removed in rust 1.92, so the attribute caused docs.rs builds (which run on a recent nightly) to fail with `feature has been removed`. docs.rs is configured via `[package.metadata.docs.rs] rustdoc-args = ["--cfg", "docsrs"]` and that path now activates the stabilized auto-cfg behaviour without an attribute on our side.

## [0.8.9]

### changed
- README rewritten end-to-end. now covers features, examples, the full test landscape, and links to all supporting files. badges row gained downloads + msrv + no_std.
- "things flagged" entry about `Vec<Poly>` allocation timing updated to reflect that the algebraic core has been stack-only since 0.5.0.

## [0.8.8]

### added
- crate now warns on `clippy::pedantic` in addition to `clippy::all`. categories that fire repeatedly inside the algebraic / ntt code (intentional integer casts, dense single-letter names from the spec, repeated module names, etc.) are explicitly allowed at the crate root with rationale comments.

### fixed
- `cargo clippy --release --all-targets -- -D warnings` is now clean under pedantic. ci enforces this on every push.

## [0.8.7]

### added
- `deny.toml` for [cargo-deny](https://github.com/EmbarkStudios/cargo-deny). pins allowed licenses, denies yanked crates, denies wildcard versions, only allows the crates.io registry.

### fixed
- `Debug` derived on `MlKem512`/`-768`/`-1024` and on `Params512`/`-768`/`-1024`. needed to clear the `missing_debug_implementations` lint introduced in 0.8.6, otherwise the next `cargo clippy -D warnings` would fail.

## [0.8.6]

### added
- crate-level rustdoc with quick-start, parameter-set summary, feature list, and a security/stability note. visible at the top of [docs.rs/mlkem-rs](https://docs.rs/mlkem-rs).
- `#[cfg_attr(docsrs, feature(doc_auto_cfg))]` so docs.rs renders feature-gated items with the right `(features = "...")` annotations.
- crate-level lint `missing_debug_implementations` so any future newtype that forgets a `Debug` impl fails ci.

## [0.8.5]

### added
- `examples/serde_save_restore.rs`: round-trips a keypair through bincode files on `/tmp`, then completes a handshake against the loaded keys. gated on the `serde` feature.
  ```
  cargo run --release --example serde_save_restore --features serde
  ```

## [0.8.4]

### added
- `rust-version = "1.70"` pinned in `Cargo.toml`. cargo will refuse to build the crate on older toolchains rather than fail mid-compile with confusing diagnostics.

## [0.8.3]

### added
- `LengthError` public error type with `expected` and `got` fields. implements `Display` and `std::error::Error` (under the `std` feature).
- `TryFrom<&[u8]>` for `PublicKey*`, `SecretKey*`, `Ciphertext*` on all three levels. lets users validate length at the boundary instead of going through the panicking `from_bytes(&[u8; N])` path.

## [0.8.2]

### added
- `examples/handshake.rs`: minimal alice/bob handshake using `MlKem768`. run with `cargo run --release --example handshake`.

## [0.8.1]

### fixed
- `[package.metadata.docs.rs]` set so docs.rs builds with `all-features = true`. without this the `serde` feature additions and the `Kem` trait doctest were invisible on docs.rs.

## [0.8.0]

### added
- optional `serde` feature. enables `Serialize` + `Deserialize` on every public newtype across all three parameter sets (12 types total). custom impl emits the inner array via `serialize_bytes`, so binary serializers (bincode, postcard, ciborium) see a tight byte-array wire format.
- `tests/serde_roundtrip.rs` covers bincode round-trip on every type, all three levels.

### changed
- ci runs the test suite both with and without `--features serde` (matrix expansion on master).

## [0.7.0]

### added
- `Kem` trait abstracting over `MlKem512` / `MlKem768` / `MlKem1024`. callers can now write functions generic over the parameter set, picking it at instantiation time.
- `AsRef<[u8]>` on every key, ciphertext and shared-secret newtype, all three levels. lets you pipe outputs into anything that accepts `&[u8]` without `.as_bytes()` plumbing.
- doctest in the `Kem` rustdoc that performs a full handshake; runs on every `cargo test`.

### notes
- algorithm did not change; this is a usability release. the trait is purely additive, the existing per-level static methods on `MlKem768` etc keep working.

## [0.6.0]

### added
- `fuzz/` cargo-fuzz harness with four targets:
  - `decap_no_panic_768` — arbitrary sk + ct, no panic
  - `encap_no_panic_768` — arbitrary pk + m, no panic
  - `tampered_ct_implicit_reject_768` — fuzzer-driven ct tamper, must reach implicit reject
  - `round_trip_512` — honest round-trip at ml-kem-512
  see `fuzz/README.md` for usage. requires nightly + `cargo install cargo-fuzz`.
- `tests/stress.rs` is the stable-rust equivalent of the fuzz harness. fixed `ChaCha20Rng` seed, runs on every `cargo test`:
  - 5000 honest round-trips per parameter set
  - 2000 random-tamper cases per parameter set, each must reach implicit reject
  - 1000 garbage-input decap calls per parameter set, each must not panic
  - 24000 total exercises across the three levels, completes in ~1s

### packaging
- `[workspace] exclude = ["fuzz"]` so the fuzz crate does not get pulled into a top-level `cargo build --workspace`.

## [0.5.0]

### added
- `MAX_K` const exposed as the upper bound (= 4) on parameter rank.

### changed
- `PolyVec`, `PolyVecNtt`, `MatrixNtt` now hold `[Poly; MAX_K]` (or `[[..; MAX_K]; MAX_K]` for the matrix) plus a runtime `k`. they are `Copy` and live entirely on the stack. the algebraic hot path (matrix sample, polyvec ops, ntt, basemul) is allocation-free.
- field renamed from tuple-style `.0` to named `.data` to make the intent obvious in code reading the structures.

### performance (apple m-series, vs 0.4.0)
- ml-kem-512  keygen 28 → 26 µs
- ml-kem-768  keygen 46 → 40 µs (-13%)
- ml-kem-1024 keygen 69 → 57 µs (-17%)
- encap / decap unchanged: those paths were already light on `Vec` allocs

### internals
- `MatrixNtt` for ml-kem-1024 occupies 4×4×poly = 8 KiB on the stack. fine on linux/macos and on the embedded targets in our ci matrix; if you target a 4 KiB stack mcu, bring your own.

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