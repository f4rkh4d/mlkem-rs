// criterion benches across all three levels, compared against rustcrypto's
// audited ml-kem crate.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::KemCore;
use rand::thread_rng;

macro_rules! bench_set {
    ($c:expr, $label:expr, $ours:ident, $rc:ty) => {{
        let mut rng = thread_rng();

        // ours
        $c.bench_function(concat!("ours-", $label, "-keygen"), |b| {
            b.iter(|| {
                let kp = mlkem::$ours::keygen(&mut rng);
                black_box(kp);
            })
        });
        let (pk, sk) = mlkem::$ours::keygen(&mut rng);
        $c.bench_function(concat!("ours-", $label, "-encapsulate"), |b| {
            b.iter(|| {
                let r = mlkem::$ours::encapsulate(black_box(&pk), &mut rng);
                black_box(r);
            })
        });
        let (ct, _) = mlkem::$ours::encapsulate(&pk, &mut rng);
        $c.bench_function(concat!("ours-", $label, "-decapsulate"), |b| {
            b.iter(|| {
                let ss = mlkem::$ours::decapsulate(black_box(&sk), black_box(&ct));
                black_box(ss);
            })
        });

        // rustcrypto
        $c.bench_function(concat!("rustcrypto-", $label, "-keygen"), |b| {
            b.iter(|| {
                let kp = <$rc as KemCore>::generate(&mut rng);
                black_box(kp);
            })
        });
        let (rc_dk, rc_ek) = <$rc as KemCore>::generate(&mut rng);
        $c.bench_function(concat!("rustcrypto-", $label, "-encapsulate"), |b| {
            b.iter(|| {
                let r = rc_ek.encapsulate(&mut rng).unwrap();
                black_box(r);
            })
        });
        let (rc_ct, _) = rc_ek.encapsulate(&mut rng).unwrap();
        $c.bench_function(concat!("rustcrypto-", $label, "-decapsulate"), |b| {
            b.iter(|| {
                let ss = rc_dk.decapsulate(black_box(&rc_ct)).unwrap();
                black_box(ss);
            })
        });
    }};
}

fn run_benches(c: &mut Criterion) {
    bench_set!(c, "512", MlKem512, ml_kem::MlKem512);
    bench_set!(c, "768", MlKem768, ml_kem::MlKem768);
    bench_set!(c, "1024", MlKem1024, ml_kem::MlKem1024);
}

criterion_group!(benches, run_benches);
criterion_main!(benches);
