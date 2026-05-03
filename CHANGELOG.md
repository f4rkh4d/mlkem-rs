# changelog

format follows [keep-a-changelog](https://keepachangelog.com).
this project uses [semver](https://semver.org/).

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