# supply chain

every crate `mlkem-rs` depends on, what it provides, and how we treat it.

## philosophy

cryptographic primitives sit at a different supply-chain bar than
ordinary libraries. a malicious update to any crate inside the
permission boundary of the keccak permutation, the side-channel
guards, or the rng plumbing would be game-over. we keep the dep tree
small on purpose, prefer audited crates from RustCrypto, and pin
permissive licenses only.

## runtime dependencies (release builds)

| crate         | role                                  | who maintains   | audit history                                                                |
|---------------|---------------------------------------|-----------------|-------------------------------------------------------------------------------|
| `sha3`        | SHA3-256/512, SHAKE128/256            | RustCrypto      | NCC Group (2020), part of broader RustCrypto review                          |
| `rand_core`   | `RngCore` + `CryptoRng` traits only   | rust-random     | trait surface; no crypto impl in this crate                                  |
| `subtle`      | constant-time primitives              | dalek-crypto    | constant-time hardening reviewed informally; widely used in audited stacks   |
| `zeroize`     | wipe-on-drop                          | RustCrypto      | small surface; widely audited transitively                                   |
| `serde`       | feature-gated, serialize/deserialize  | dtolnay         | not crypto-sensitive; only touches public byte arrays                        |

dev-dependencies (`rand`, `rand_chacha`, `hex`, `criterion`,
`serde_json`, `bincode`, `ml-kem`) are not part of any release artifact
and do not affect downstream users.

## license discipline

`deny.toml` enumerates the allowed licenses (MIT, Apache-2.0, BSD-2/3,
ISC, Unicode-DFS-2016, Unicode-3.0, Zlib, CC0-1.0). a new transitive
crate with a non-allowed license fails CI immediately. wildcards in
version specs are denied; any-version dep is denied. only the
`crates-io` registry is allowed; no git deps.

## reproducible installation

the recommended install path is:

```sh
cargo install --locked mlkem-rs --version 0.11.0
```

`--locked` makes `cargo` honor the lockfile shipped in the published
crate, so the build resolves to the exact dep versions tested in CI.

`rust-toolchain.toml` pins the toolchain to stable and includes
rustfmt + clippy as required components, so anyone running
`cargo install --locked --offline` gets the same compiler we used.

## what we will not do

- pull in pre-1.0 cryptographic crates beyond sha3.
- add `lazy_static` / `once_cell` style globals that a future
  attacker could replace via a private path with a faulty rng.
- add `git` deps. only published crates.io versions.
- add `unsafe` blocks. zero today, zero planned.

## what we still need

- a third-party audit. see [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md) for the
  one-page brief.
- `cargo audit` in CI. enabled in 0.11.0; the [advisory database][1]
  is checked on every push.
- `cargo deny check` in CI. enabled in 0.11.0; the rules in
  [`deny.toml`](deny.toml) are enforced on every push.
- signed git tags + signed crates.io releases. planned for the next
  pass when we set up the release GPG key.

## reporting a supply-chain compromise

if you suspect an upstream crate we depend on has been compromised,
email **hello@frkhd.com** with the subject `mlkem-rs supply chain` and
a description of the indicator. we will pin around the affected
version within hours and ship a patch release, with attribution and a
post-incident note in the changelog.

[1]: https://github.com/RustSec/advisory-db
