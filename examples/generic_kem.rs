// run any of the three parameter sets through one generic function via the
// Kem trait. shows that the trait shipped in 0.7.0 actually delivers what
// it advertises: write the handshake once, pick the security level at the
// call site.
//
//   cargo run --release --example generic_kem

use mlkem::{Kem, MlKem1024, MlKem512, MlKem768};
use rand::thread_rng;

fn round_trip<K: Kem>(label: &str) {
    let mut rng = thread_rng();
    let (pk, sk) = K::keygen(&mut rng);
    let (ct, ss_alice) = K::encapsulate(&pk, &mut rng);
    let ss_bob = K::decapsulate(&sk, &ct);
    assert_eq!(ss_alice.as_ref(), ss_bob.as_ref(), "{label} round-trip");
    println!(
        "{:>11}  pk {:>4} B   sk {:>4} B   ct {:>4} B   ss {} B   ok",
        label,
        K::PUBLIC_KEY_SIZE,
        K::SECRET_KEY_SIZE,
        K::CIPHERTEXT_SIZE,
        K::SHARED_SECRET_SIZE,
    );
}

fn main() {
    round_trip::<MlKem512>("ml-kem-512");
    round_trip::<MlKem768>("ml-kem-768");
    round_trip::<MlKem1024>("ml-kem-1024");
}
