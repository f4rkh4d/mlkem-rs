# formal verification

`mlkem-rs` ships [kani][1]-checked proofs of the field-arithmetic and
compression invariants that the rest of the implementation depends on.
the proofs are bounded model checks, not paper proofs. they hold for
every legal input in the input space we constrain, not just sampled
ones.

## what is proven

### `src/field.rs` (3 harnesses)

| harness                                | claim                                                                |
|----------------------------------------|----------------------------------------------------------------------|
| `barrett_reduce_matches_naive_nonneg`  | for every `a` in `[0, Q*Q)`, `barrett_reduce(a) == a % Q < Q`        |
| `fqadd_in_range`                       | for every `a, b` in `[0, Q)`, `fqadd(a, b) == (a + b) mod Q < Q`     |
| `fqsub_in_range`                       | for every `a, b` in `[0, Q)`, `fqsub(a, b) == (a - b).rem_euclid(Q)` |

`fqmul` is intentionally not given a kani harness. its correctness
follows compositionally: for `a, b` in `[0, Q)`, the `i32` product
`(a as i32) * (b as i32)` is in `[0, Q*Q)`, which is exactly the
precondition that `barrett_reduce_matches_naive_nonneg` proved sound
on. an extra harness would re-bit-blast 32 bits of input space and
push verification time past 10 minutes for no new information.

these three close the door on every concern the rest of the code has
about the field layer: that field arithmetic stays in the field, and
that the value matches the textbook modular formula. the rest of the
crate composes these without re-checking, so a counterexample here
would propagate everywhere. there is no counterexample.

### `src/compress.rs` (7 harnesses)

| harness                       | claim                                                                  |
|-------------------------------|------------------------------------------------------------------------|
| `compress_in_range_d4`        | for every `x` in `[0, Q)`, `compress_fe(x, 4)` is in `[0, 16)`         |
| `compress_in_range_d5`        | same with `d=5`, output in `[0, 32)` (used by ml-kem-1024)             |
| `compress_in_range_d10`       | same with `d=10`, output in `[0, 1024)` (used by ml-kem-512/-768)      |
| `compress_in_range_d11`       | same with `d=11`, output in `[0, 2048)` (used by ml-kem-1024)          |
| `compress_d1_roundtrip_at_anchors` | the 1-bit message-pack rounds 0, q/2 and q-1 to the spec values  |
| `decompress_in_range_d10`     | for every `y` in `[0, 1024)`, `decompress_fe(y, 10)` is in `[0, Q)`    |
| `decompress_in_range_d11`     | same with `d=11`                                                       |

these prove that the bit-packing of polynomial coefficients during
serialization always stays in the size class promised by the byte-encode
loop. the byte_encode / byte_decode loops use these widths as stride, so
out-of-range coefficients would clobber neighboring bits; the proofs
guarantee that does not happen.

## what is not proven (yet)

- **NTT roundtrip identity** is checked by a full-input randomized test
  in `src/ntt.rs::tests::ntt_roundtrip` and `ntt_mul_matches_naive`,
  but not formally. proving it under kani requires either inflating
  the bound on intermediate reductions or refactoring the loop to a
  shape kani's solver can finish on; planned for a later release.
- **byte_encode/byte_decode roundtrip** for d=12 (the secret-key path)
  is exercised by 3000-seed cross-check vs the audited rustcrypto
  implementation. a kani proof would require unrolling the 256-iteration
  loop and is currently out of scope.
- **decapsulate equivalence** with the FIPS 203 abstract algorithm. the
  spec has a paper proof of IND-CCA2; we are an implementation, not a
  re-derivation. cross-check + nist KAT verification are the assurance.

## how to run the proofs locally

the kani harnesses live behind `#[cfg(kani)]` and do not affect normal
builds.

```sh
cargo install --locked kani-verifier
cargo kani setup            # one-time, downloads CBMC + the kani toolchain

cargo kani                  # run every harness in the crate
cargo kani --harness barrett_reduce_matches_naive_nonneg
                            # run a single harness
```

each harness completes in 2-30 seconds on a 2024-vintage laptop. the
field harnesses are exhaustive over a 32-bit input domain; kani
unrolls the bit-blast and discharges via CBMC.

## why this matters

field arithmetic and bit-pack widths are exactly the layer where Rust
implementations of ML-KEM tend to ship subtle bugs. a wrong barrett
constant, an off-by-one in the compress rounding, an unchecked overflow
on the multiply path: any of these silently corrupts the ciphertext or
the shared secret in a way that may pass random fuzz testing.

closing those edges with a proof, even bounded, removes that whole
category of failure from the audit checklist. the auditor's first
hand-review pass over `src/field.rs` and `src/compress.rs` becomes "this
matches the proof" rather than "let me re-derive the bounds by hand".

[1]: https://model-checking.github.io/kani/
