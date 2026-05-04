# side channels

an inventory of every secret-dependent operation in this crate, and how
it is protected. updated per release. an auditor's first hand-review pass
should match this document exactly.

terminology used below:

- **secret-dependent**: the operation's runtime, branch direction, memory
  access pattern, or arithmetic depends on a value that ML-KEM treats as
  secret (the `dk_pke` polynomial vector `s`, the message `m`, the shared
  key `K`, or the FO-rejected key `K_bar`).
- **public-dependent**: the operation depends only on `rho`, `ek_pke`,
  the ciphertext `c`, or any value derived purely from public inputs.
  side-channel exposure here does not leak secrets and is not a concern.

## operations on secret-dependent values

### `mlkem::decapsulate` -> ciphertext-equality check (`subtle::ConstantTimeEq`)

`MlKem::decapsulate` re-encrypts `m_prime` using the public ek_pke and
compares the resulting `c_prime` against the user-supplied `c`. the result
of that comparison decides whether the returned shared secret is `K_prime`
(honest path) or `K_bar` (implicit-reject path).

protection: `ct.ct_eq(c_prime.as_slice())` followed by a branchless mask
`mask = eq.unwrap_u8().wrapping_neg()` then `out[i] = (k_prime[i] & mask) | (k_bar[i] & !mask)`.
no `if` branch is taken on the comparison result. the `unwrap_u8()` of a
`Choice` is documented as constant-time.

source: `src/mlkem.rs:decapsulate`

### `kpke::decrypt` -> shared-secret derivation

decrypt uses `s_hat` (the deserialized secret-key polynomial vector) to
compute `s_hat . u_hat`, then ntt-inverts and subtracts. the dot product
is a sum of `basemul` calls; basemul is a fixed pattern of 256 fqmul +
fqadd / fqsub operations with no data-dependent branches.

protection: barrett reduction (`field::barrett_reduce`) is implemented
branch-free using sign-mask normalize. `fqadd` / `fqsub` are likewise
branch-free conditional add via sign mask. ntt forward + inverse loop
structure is a fixed schedule (the `len` and `start` values are determined
at compile time). only the polynomial *values* depend on the secret;
positions, branch directions, and memory accesses do not.

source: `src/field.rs`, `src/ntt.rs`, `src/kpke.rs:decrypt`

### `serialize::byte_decode` / `byte_encode` for d=12

these handle the polynomial-vector serialization of `s_hat` (secret) into
12-bit limbs. the loop walks 256 coefficients in order, writes/reads
`d=12` bits per coefficient. no branch depends on the coefficient value;
the bit-extraction is `(byte >> (bitpos & 7)) & 1` per bit.

protection: the loop is unconditionally bit-streamed. no `match` or `if`
branches on coefficient values.

source: `src/serialize.rs:byte_decode`, `byte_encode`

### `compress::compress_poly_fe_1` for the message bit-pack

`poly_to_message` calls `compress_poly_fe_1` on each coefficient of the
decrypted polynomial `w`. this is the path where the secret message
finally becomes 32 bytes. it computes `((x << 1) + q/2) / q mod 2`.

protection: the `compress_fe(x, 1)` formula is a u32 multiply, add, and
divide. integer division by a constant is compiled to a multiply + shift
on every architecture rust supports; no data-dependent branch. the
output bit goes into `m[i >> 3] |= bit << (i & 7)` which is positional
on a public index.

source: `src/compress.rs`, `src/serialize.rs:poly_to_message`

### `mlkem::keygen` and `kpke::keygen` -> secret seed -> sigma

the keygen path consumes a secret seed `d` and derives `sigma` via
`G(d || k)`. `G` is SHA3-512. the implementation uses the `sha3` crate.
sha3 is itself constant-time; the keccak-f permutation is a fixed
schedule of bitwise ops on a 1600-bit state with no data-dependent
branches.

protection: provided by the upstream `sha3` crate.

source: `src/hash.rs`, `src/kpke.rs:keygen`

### `sample::sample_cbd_poly` -> CBD on PRF output

CBD samples the secret polynomial `s` from the output of `PRF_eta(sigma, b)`.
the bit-tricks (`(t & 0x55555555) + ((t >> 1) & 0x55555555)` for eta=2)
are constant-time integer arithmetic. the output of `cbd` depends on
secret bits, but the operations are fixed-shape.

protection: 32-bit / 24-bit popcount via SWAR. no branches, no data-
dependent table lookups.

source: `src/sample.rs:cbd`

## operations on public-dependent values

these are listed for completeness; they are *not* a concern.

### `sample::sample_ntt` (alg 6, rejection sampling on rho)

rejection-samples the matrix A from the public seed rho. the runtime
varies because we draw 168 bytes at a time and accept only candidates
< q. since rho is public, the timing leak is over public data.

source: `src/sample.rs:sample_ntt`

### `kpke::sample_matrix_a`

calls `sample_ntt` 9 / 16 / 25 times (k=2/3/4). same situation as above:
operates only on rho.

source: `src/kpke.rs:sample_matrix_a`

### NIST ACVP and cross-check tests

operate only on test vectors. no secret data. no concern.

## what we are NOT defending against

- **microarchitectural side channels** that depend on cache state or
  branch-predictor history. we trust llvm + the cpu's instruction
  decoder within reason and have not added `Spectre`/`LVI` mitigations.
- **physical side channels** (power, EM). this is software.
- **adversarially-controlled rngs**. if you pass a broken rng, the
  generated keys are broken.

## reproducible timing tests

`tests/timing.rs` (added in 0.9.0) runs a [`dudect`][1]-style statistical
test that compares decapsulation latency on two classes of inputs and
asserts the welch t-statistic stays under a threshold. see that file for
the methodology and the threshold rationale.

[1]: https://github.com/oreparaz/dudect
