// honest keygen + encapsulate + decapsulate round-trip at ml-kem-512.
// the recovered shared secret must match the encapsulated one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mlkem::MlKem512;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&data[..64]);
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[64..96]);

    let (pk, sk) = MlKem512::keygen_deterministic(&seed);
    let (ct, ss_a) = MlKem512::encapsulate_deterministic(&pk, &m);
    let ss_b = MlKem512::decapsulate(&sk, &ct);
    assert_eq!(ss_a, ss_b, "round-trip mismatch");
});
