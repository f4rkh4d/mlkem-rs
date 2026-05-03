# fuzz

cargo-fuzz harness for mlkem-rs. requires nightly rust.

## install

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## targets

- `decap_no_panic_768` — feeds arbitrary bytes as sk + ct, asserts no panic.
- `encap_no_panic_768` — feeds arbitrary bytes as pk + 32-byte m, asserts no panic.
- `tampered_ct_implicit_reject_768` — generates an honest keypair, encapsulates, asks the fuzzer to xor-tamper the ciphertext. asserts the resulting shared secret differs from the honest one (or matches, when the xor mask is all-zero).
- `round_trip_512` — generates an honest keypair at ml-kem-512, encapsulates, decapsulates, asserts the recovered shared secret matches.

## run

```sh
cd fuzz
cargo +nightly fuzz run decap_no_panic_768
```

stop with ctrl-c. corpus + crash artifacts land in `fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/` respectively, both gitignored.

## stable-rust equivalent

`tests/stress.rs` covers the same property surface using a fixed `ChaCha20Rng` seed and runs on every `cargo test` (~24000 round-trips total across the three parameter sets, ~1 second).
