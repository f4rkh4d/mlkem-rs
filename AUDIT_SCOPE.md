# audit scope

if you are commissioning a third-party security audit of `mlkem-rs`,
this is a starting point for a one-page scope.

## crate

`mlkem-rs` v0.9.0 (or later, pinned to a specific tag).
crates.io: https://crates.io/crates/mlkem-rs
git tag: e.g. `v0.9.0`

source under audit: `src/` (~700 lines of rust). dev-deps and tests are
out of scope.

## in-scope

### correctness

- [ ] `MlKem512`, `MlKem768`, `MlKem1024` keygen, encapsulate, decapsulate
  match FIPS 203 algs 16, 17, 18 byte-for-byte on the 180-vector NIST
  ACVP suite (`tests/nist_kats.rs`). re-run that suite as the first
  pass.
- [ ] `Kpke` keygen, encrypt, decrypt match FIPS 203 algs 12, 13, 14.
- [ ] `byte_encode_d` / `byte_decode_d` match alg 4 / 5 for d in {1, 4,
  5, 10, 11, 12} (the union of values used at any parameter set).
- [ ] `compress_d` / `decompress_d` match alg 4 / 5 with the rounding
  rule "to nearest, ties to even" or "to nearest, ties away from zero"
  as specified.
- [ ] NTT forward + inverse roundtrip is identity, and the basemul +
  ntt-inverse yields the same result as naive R_q multiplication
  (already exercised by `src/ntt.rs::tests::ntt_mul_matches_naive`).

### secret-handling

- [ ] every secret-dependent operation listed in `SIDE_CHANNELS.md` is
  in fact branch-free under `rustc 1.74+` on x86_64, aarch64, wasm32,
  and `thumbv7em-none-eabihf`. verify by reading the disassembly
  produced by `cargo rustc --release -- --emit=asm` for the relevant
  functions.
- [ ] no secret value is ever used as an array index (no
  secret-dependent table lookup that could leak through cache state).
- [ ] no `if` / `match` / short-circuit `&&` / `||` branches on a value
  derived from `dk_pke`, `s_hat`, the recovered message `m_prime`, or
  the derived shared secrets `K_prime` / `K_bar`.
- [ ] `SecretKey*` and `SharedSecret*` types are zeroed on drop, and
  the `Zeroize` impl actually overwrites the inner array (not just
  drops it). verify with `valgrind --tool=memcheck --track-origins=yes`
  or by writing a small test that reads the post-drop bytes.

### implicit-reject

- [ ] the FO transform's ciphertext check uses constant-time equality
  (`subtle::ConstantTimeEq`) and the conditional select between
  `K_prime` and `K_bar` is branchless.
- [ ] the `K_bar = J(z || ct)` path computes the pseudorandom reject
  key from the secret `z`. confirm that the SHAKE256 wrapper
  consuming `z` does not branch on `z`'s contents.
- [ ] the implicit-reject path does not panic on any input shape (zero
  bytes, all 0xff, length corruption already caught at the type
  boundary).

### serialization edge cases

- [ ] feeding `byte_decode` a 12-bit limb >= q (i.e. in [3329, 4095])
  is permitted by the spec but caller-checked. verify that downstream
  uses do not assume `< q` and behave deterministically when that
  assumption breaks.
- [ ] sk size split (dk_pke || ek_pke || H(ek_pke) || z) places `z` at
  exactly the right offset. boundary checks on `decapsulate` slicing
  are correct for all three parameter sets.

### public-data sampling (lower priority)

- [ ] `sample_ntt`'s rejection loop terminates for every possible
  `rho` (no infinite loop on adversarial public input).

## out-of-scope

- physical side channels: power, EM, fault injection.
- microarchitectural side channels: Spectre, LVI, MDS. we trust llvm.
- the `sha3` crate's keccak-f implementation. it is an external audited
  dependency.
- the `subtle` crate. external audited dependency.
- the `x25519-dalek` crate (used by the companion `mlkem-tls`, not
  this crate).
- formal verification of the algebraic proof of IND-CCA2 security. the
  spec is the source of truth; we are checking implementation faith,
  not algorithm soundness.

## recommended methodology

- **5 person-days** of read-the-source-against-FIPS-203.
- **2 person-days** of disassembly review for branch-free claims.
- **1 person-day** of `tests/timing.rs` and any additional `dudect`
  campaigns the auditor wishes to run.
- **0.5 person-day** to write the report.

8.5 person-days total at typical rates lands the audit in the $25-50k
range. this is realistic for a 700-line rust crate with no `unsafe`.

## post-audit deliverable expectations

we will publish the unmodified report as a github release artifact
within 14 days of acceptance. fixes go out in a coordinated patch
release.
