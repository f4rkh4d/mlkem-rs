# security

## reporting a vulnerability

email **hello@frkhd.com** with the subject line `mlkem-rs security`.
GPG key is fingerprinted in this repo's release notes once it lands. for
sensitive disclosures we will move to a private channel within 24 hours.

i prefer coordinated disclosure with a mutually-agreed embargo. please
do not file a public github issue for cryptographic findings.

## scope and threat model

`mlkem-rs` implements [FIPS 203 ML-KEM][1]. it is a **stand-alone
implementation written from the spec**. the post-quantum literature it
must defend against:

- a passive adversary observing public keys, ciphertexts, and shared-secret
  hashes derived from them, attempting to recover the secret key or the
  shared secret. ML-KEM's IND-CCA2 security claim covers this.
- an active adversary that can submit chosen ciphertexts to the
  decapsulation oracle. the FO-transform with implicit-reject (FIPS 203
  alg 18) covers this; this implementation uses constant-time ciphertext
  comparison via the [`subtle`][2] crate to avoid leaking branch state on
  reject.
- a passive timing-side-channel adversary that measures wall-clock or
  cycle-level latency of decapsulation. see `SIDE_CHANNELS.md` for the
  inventory of secret-dependent operations and their protections.

things **explicitly out of scope** for v0.x:

- **physical side-channels** (power analysis, EM, fault injection).
  this is a software library; mitigations live at the hardware and
  os level.
- **microarchitectural attacks** that depend on the cpu's branch predictor
  state, cache lines, port contention. we trust llvm and the cpu within
  reason; we have not used `Spectre` or `LVI` mitigations.
- **storage of long-term secret keys**. callers must place `SecretKey*`
  values in memory they trust. `ZeroizeOnDrop` is implemented but page-
  level mlock/mprotect is the caller's responsibility.
- **rng quality**. we accept any `rand_core::CryptoRng + RngCore`. if you
  pass a broken rng, the resulting keys are broken.

## what is and is not audited

- **not audited.** no third-party security audit has been performed on
  this crate.
- behavioral correctness is established by a 180-vector NIST ACVP test
  suite (`tests/nist_kats.rs`) plus a 3000-seed cross-check against the
  audited [rustcrypto `ml-kem`][3] crate (`tests/cross_check.rs`). every
  byte of every output matches.
- timing-side-channel correctness for the ciphertext comparison and
  shared-secret equality is established by use of [`subtle`][2]. for
  the polynomial hot path see `SIDE_CHANNELS.md`.

if you need an audited ML-KEM in production, use [`ml-kem`][3] from
RustCrypto. that crate has been audited by Trail of Bits.

this crate exists for stacks that want the implementation readable end-
to-end (it is roughly 700 lines of rust) and for tooling, study, and
test fixtures.

## what we promise to fix immediately

- any divergence from the FIPS 203 spec (you find one byte the audited
  reference disagrees with us on). fixed in a patch release within 24h.
- any panic on attacker-controlled input through the public api.
- any place a secret-dependent value reaches a branch, an array index,
  or a non-`subtle` comparison.

## what we do not promise

- bit-for-bit stability across versions. the wire format is defined
  by FIPS 203, not by us; the rust-side type names and methods may
  evolve. semver-bump on breaking changes.
- interop with implementations that pre-date the FIPS 203 finalization
  (e.g. CRYSTALS-Kyber Round 3 KATs). FIPS 203 is the only spec we track.

## audit readiness

if you are about to commission an audit of this crate, a one-page scope
suggestion lives at [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md). the inventory of
secret-dependent operations lives at [`SIDE_CHANNELS.md`](SIDE_CHANNELS.md).
both are kept up to date with each release.

## contact

- email: hello@frkhd.com
- github: [@f4rkh4d](https://github.com/f4rkh4d)

[1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
[2]: https://crates.io/crates/subtle
[3]: https://crates.io/crates/ml-kem
