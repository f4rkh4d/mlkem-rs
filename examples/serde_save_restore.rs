// generate a keypair, write it to /tmp via bincode, read it back, finish the
// handshake. demonstrates the optional `serde` feature.
//
//   cargo run --release --example serde_save_restore --features serde

#[cfg(not(feature = "serde"))]
fn main() {
    eprintln!("rerun with --features serde");
    std::process::exit(2);
}

#[cfg(feature = "serde")]
fn main() {
    use mlkem::{MlKem768, PublicKey768, SecretKey768};
    use rand::thread_rng;
    use std::fs;
    use std::path::Path;

    let mut rng = thread_rng();
    let (pk, sk) = MlKem768::keygen(&mut rng);

    let pk_path = Path::new("/tmp/mlkem_pk.bin");
    let sk_path = Path::new("/tmp/mlkem_sk.bin");

    fs::write(pk_path, bincode::serialize(&pk).unwrap()).unwrap();
    fs::write(sk_path, bincode::serialize(&sk).unwrap()).unwrap();
    println!(
        "wrote {} ({}b) and {} ({}b)",
        pk_path.display(),
        fs::metadata(pk_path).unwrap().len(),
        sk_path.display(),
        fs::metadata(sk_path).unwrap().len(),
    );

    let pk_loaded: PublicKey768 = bincode::deserialize(&fs::read(pk_path).unwrap()).unwrap();
    let sk_loaded: SecretKey768 = bincode::deserialize(&fs::read(sk_path).unwrap()).unwrap();
    assert_eq!(pk, pk_loaded);
    assert_eq!(sk, sk_loaded);

    let (ct, ss_a) = MlKem768::encapsulate(&pk_loaded, &mut rng);
    let ss_b = MlKem768::decapsulate(&sk_loaded, &ct);
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());

    let _ = fs::remove_file(pk_path);
    let _ = fs::remove_file(sk_path);
    println!("ok, save -> restore -> handshake completed");
}
