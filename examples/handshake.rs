// minimal alice/bob handshake using ml-kem-768.
//
//   cargo run --release --example handshake

use mlkem::MlKem768;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();

    // bob: generate a long-term keypair, hand the public key to alice.
    let (bob_pk, bob_sk) = MlKem768::keygen(&mut rng);
    println!("bob pk:  {} bytes", bob_pk.as_bytes().len());
    println!("bob sk:  {} bytes", bob_sk.as_bytes().len());

    // alice: encapsulate against bob's public key. result is a 1088-byte
    // ciphertext (sent over the wire) and a 32-byte shared secret (kept).
    let (ct, alice_ss) = MlKem768::encapsulate(&bob_pk, &mut rng);
    println!("alice ct: {} bytes", ct.as_bytes().len());

    // bob: decapsulate to recover the same shared secret.
    let bob_ss = MlKem768::decapsulate(&bob_sk, &ct);

    // they now hold the same 32 bytes.
    let alice_hex: String = alice_ss
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let bob_hex: String = bob_ss
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("alice ss: {}", alice_hex);
    println!("bob ss:   {}", bob_hex);
    assert_eq!(alice_hex, bob_hex);
    println!("ok, shared secrets match");
}
