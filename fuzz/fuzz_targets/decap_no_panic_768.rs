// arbitrary bytes in the secret-key and ciphertext slots must never panic.
// the implicit-reject branch should silently produce a junk shared secret.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mlkem::{Ciphertext768, MlKem768, SecretKey768};

fuzz_target!(|data: &[u8]| {
    if data.len() < MlKem768::SECRET_KEY_SIZE + MlKem768::CIPHERTEXT_SIZE {
        return;
    }
    let mut sk_bytes = [0u8; MlKem768::SECRET_KEY_SIZE];
    let mut ct_bytes = [0u8; MlKem768::CIPHERTEXT_SIZE];
    sk_bytes.copy_from_slice(&data[..MlKem768::SECRET_KEY_SIZE]);
    ct_bytes.copy_from_slice(
        &data[MlKem768::SECRET_KEY_SIZE..MlKem768::SECRET_KEY_SIZE + MlKem768::CIPHERTEXT_SIZE],
    );

    let sk = SecretKey768::from_bytes(&sk_bytes);
    let ct = Ciphertext768::from_bytes(&ct_bytes);
    let _ = MlKem768::decapsulate(&sk, &ct);
});
