// criterion benches for keygen / encapsulate / decapsulate.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mlkem::MlKem768;
use rand::thread_rng;

fn bench_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("ml-kem-768 keygen", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::keygen(&mut rng);
            black_box((pk, sk));
        })
    });
}

fn bench_encapsulate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (pk, _sk) = MlKem768::keygen(&mut rng);
    c.bench_function("ml-kem-768 encapsulate", |b| {
        b.iter(|| {
            let (ct, ss) = MlKem768::encapsulate(black_box(&pk), &mut rng);
            black_box((ct, ss));
        })
    });
}

fn bench_decapsulate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (pk, sk) = MlKem768::keygen(&mut rng);
    let (ct, _ss) = MlKem768::encapsulate(&pk, &mut rng);
    c.bench_function("ml-kem-768 decapsulate", |b| {
        b.iter(|| {
            let ss = MlKem768::decapsulate(black_box(&sk), black_box(&ct));
            black_box(ss);
        })
    });
}

criterion_group!(benches, bench_keygen, bench_encapsulate, bench_decapsulate);
criterion_main!(benches);
