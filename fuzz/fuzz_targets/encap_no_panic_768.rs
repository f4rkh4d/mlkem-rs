// arbitrary public-key bytes plus an arbitrary 32-byte message must not
// panic. valid public keys are 1184 bytes; we feed it any 1184 bytes,
// including bytes that would not satisfy the t_hat reduction check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mlkem::{MlKem768, PublicKey768};

fuzz_target!(|data: &[u8]| {
    if data.len() < MlKem768::PUBLIC_KEY_SIZE + 32 {
        return;
    }
    let mut pk_bytes = [0u8; MlKem768::PUBLIC_KEY_SIZE];
    pk_bytes.copy_from_slice(&data[..MlKem768::PUBLIC_KEY_SIZE]);
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[MlKem768::PUBLIC_KEY_SIZE..MlKem768::PUBLIC_KEY_SIZE + 32]);

    let pk = PublicKey768::from_bytes(&pk_bytes);
    let _ = MlKem768::encapsulate_deterministic(&pk, &m);
});
