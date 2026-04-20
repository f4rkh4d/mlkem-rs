// basic usability: alice/bob handshake, roundtrip, size sanity.

use mlkem::MlKem768;
use rand::thread_rng;

#[test]
fn alice_bob_handshake() {
    let mut rng = thread_rng();
    // bob generates a keypair.
    let (bob_pk, bob_sk) = MlKem768::keygen(&mut rng);
    // alice encapsulates to bob's public key.
    let (ct, alice_ss) = MlKem768::encapsulate(&bob_pk, &mut rng);
    // bob decapsulates to recover the same shared secret.
    let bob_ss = MlKem768::decapsulate(&bob_sk, &ct);
    assert_eq!(alice_ss, bob_ss);
}

#[test]
fn sizes() {
    assert_eq!(MlKem768::PUBLIC_KEY_SIZE, 1184);
    assert_eq!(MlKem768::SECRET_KEY_SIZE, 2400);
    assert_eq!(MlKem768::CIPHERTEXT_SIZE, 1088);
    assert_eq!(MlKem768::SHARED_SECRET_SIZE, 32);
}

#[test]
fn deterministic_is_deterministic() {
    let seed = [42u8; 64];
    let (pk1, sk1) = MlKem768::keygen_deterministic(&seed);
    let (pk2, sk2) = MlKem768::keygen_deterministic(&seed);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);

    let m = [17u8; 32];
    let (ct1, ss1) = MlKem768::encapsulate_deterministic(&pk1, &m);
    let (ct2, ss2) = MlKem768::encapsulate_deterministic(&pk2, &m);
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
}

#[test]
fn implicit_reject_on_tampered_ct() {
    // flip a bit in the ciphertext. decap should still succeed (returning the
    // implicit-reject key), NOT panic, and the resulting shared secret should
    // differ from the original one.
    let mut rng = thread_rng();
    let (pk, sk) = MlKem768::keygen(&mut rng);
    let (ct, ss_good) = MlKem768::encapsulate(&pk, &mut rng);

    let mut bad_bytes = *ct.as_bytes();
    bad_bytes[0] ^= 0x01;
    let bad_ct = mlkem::Ciphertext::from_bytes(&bad_bytes);
    let ss_bad = MlKem768::decapsulate(&sk, &bad_ct);

    assert_ne!(ss_good, ss_bad);
}

#[test]
fn serialization_roundtrip() {
    let mut rng = thread_rng();
    let (pk, sk) = MlKem768::keygen(&mut rng);
    let pk2 = mlkem::PublicKey::from_bytes(pk.as_bytes());
    let sk2 = mlkem::SecretKey::from_bytes(sk.as_bytes());
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
}
