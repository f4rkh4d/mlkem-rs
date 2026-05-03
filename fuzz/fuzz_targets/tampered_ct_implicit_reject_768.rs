// generate a real keypair from the fuzzer-controlled seed, encapsulate
// honestly, then ask the fuzzer to flip arbitrary bits in the ciphertext.
// the resulting ss must differ from the honest one without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mlkem::{Ciphertext768, MlKem768};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 + 32 + MlKem768::CIPHERTEXT_SIZE {
        return;
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&data[..64]);
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[64..96]);
    let mask = &data[96..96 + MlKem768::CIPHERTEXT_SIZE];

    let (pk, sk) = MlKem768::keygen_deterministic(&seed);
    let (ct, ss_honest) = MlKem768::encapsulate_deterministic(&pk, &m);

    let mut tampered = *ct.as_bytes();
    for i in 0..tampered.len() {
        tampered[i] ^= mask[i];
    }
    let bad_ct = Ciphertext768::from_bytes(&tampered);
    let ss_implicit = MlKem768::decapsulate(&sk, &bad_ct);

    // if the fuzzer happened to xor 0s, ss must equal ss_honest. otherwise
    // implicit reject kicks in and ss differs. either way, no panic.
    let any_flipped = mask.iter().any(|&b| b != 0);
    if any_flipped {
        assert_ne!(ss_honest, ss_implicit, "tamper produced same ss");
    } else {
        assert_eq!(ss_honest, ss_implicit, "no-op tamper diverged");
    }
});
