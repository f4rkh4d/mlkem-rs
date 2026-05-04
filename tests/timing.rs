// dudect-style constant-time test for `MlKem768::decapsulate`.
//
// methodology mirrors oreparaz/dudect:
//
//   1. choose two classes of input. class A: honest ciphertexts (decap
//      hits the happy path). class B: adversarially-tampered ciphertexts
//      (decap hits the implicit-reject path).
//   2. interleave random samples from the two classes, measure latency.
//   3. compute the welch t-statistic of the two latency distributions.
//      if it stays below a threshold across N samples, the
//      implementation passes.
//
// the absolute t-stat threshold dudect uses is 4.5 (corresponds to a
// p-value < 1e-5 for non-toy sample counts). we use 6.0 here because
// macos's mach timebase is noisier than linux's clock_monotonic_raw and
// we want to keep the test stable across local hardware.
//
// this is a smoke test, not a proof. for a serious campaign, run
// `cargo +stable test --release --test timing -- --nocapture --ignored`
// with `MLKEM_TIMING_SAMPLES=2000000` against a quiet machine.
//
// the test is `#[ignore]` by default because it takes 10-30 seconds even
// at the small sample size and would slow CI. CI runs a tiny smoke
// version that just verifies the harness compiles and produces a
// reasonable t-stat.

use mlkem::{Ciphertext768, MlKem768};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

const RNG_SEED: [u8; 32] = *b"mlkem-rs timing harness 20260504";
const T_THRESHOLD_ABS: f64 = 6.0;

#[derive(Debug, Default, Clone, Copy)]
struct Welch {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Welch {
    fn push(&mut self, x: f64) {
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / (self.n as f64);
        let d2 = x - self.mean;
        self.m2 += d * d2;
    }
    fn variance(&self) -> f64 {
        if self.n < 2 {
            return 0.0;
        }
        self.m2 / (self.n as f64 - 1.0)
    }
}

fn welch_t(a: &Welch, b: &Welch) -> f64 {
    if a.n < 2 || b.n < 2 {
        return 0.0;
    }
    let va = a.variance();
    let vb = b.variance();
    let denom = ((va / a.n as f64) + (vb / b.n as f64)).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / denom
}

// ms-precision time samples are too coarse for ML-KEM-768 decapsulation
// (~50 microseconds on M-series). we use Instant::elapsed_nanos via a
// chained Instant::now / now-A pair. this is the most portable thing
// available on stable rust without `core_arch` rdtsc shenanigans.
fn timed<F: FnOnce()>(f: F) -> u64 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos() as u64
}

fn drop_outliers(mut samples: Vec<u64>) -> Vec<u64> {
    samples.sort_unstable();
    let lo = samples.len() / 100;
    let hi = samples.len() - samples.len() / 100;
    samples[lo..hi].to_vec()
}

fn run_dudect(n_samples: usize) -> f64 {
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED);

    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    let (pk, sk) = MlKem768::keygen_deterministic(&seed);

    let mut samples_a: Vec<u64> = Vec::with_capacity(n_samples);
    let mut samples_b: Vec<u64> = Vec::with_capacity(n_samples);

    for _ in 0..n_samples {
        // class a: honest ciphertext, hits the happy path.
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let (ct_honest, _) = MlKem768::encapsulate_deterministic(&pk, &m);

        // class b: tampered ciphertext, hits the implicit-reject path.
        let mut tampered_bytes = *ct_honest.as_bytes();
        let pos = (rng.next_u32() as usize) % tampered_bytes.len();
        let mut x = (rng.next_u32() & 0xff) as u8;
        if x == 0 {
            x = 1;
        }
        tampered_bytes[pos] ^= x;
        let ct_tampered = Ciphertext768::from_bytes(&tampered_bytes);

        // interleave samples to avoid systematic bias from cpu warmup,
        // thermal throttling, or background noise.
        if rng.next_u32() & 1 == 0 {
            let t_a = timed(|| {
                std::hint::black_box(MlKem768::decapsulate(&sk, &ct_honest));
            });
            let t_b = timed(|| {
                std::hint::black_box(MlKem768::decapsulate(&sk, &ct_tampered));
            });
            samples_a.push(t_a);
            samples_b.push(t_b);
        } else {
            let t_b = timed(|| {
                std::hint::black_box(MlKem768::decapsulate(&sk, &ct_tampered));
            });
            let t_a = timed(|| {
                std::hint::black_box(MlKem768::decapsulate(&sk, &ct_honest));
            });
            samples_a.push(t_a);
            samples_b.push(t_b);
        }
    }

    // drop the top and bottom 1% to absorb scheduler tail noise.
    let samples_a = drop_outliers(samples_a);
    let samples_b = drop_outliers(samples_b);

    let mut wa = Welch::default();
    let mut wb = Welch::default();
    for &x in &samples_a {
        wa.push(x as f64);
    }
    for &x in &samples_b {
        wb.push(x as f64);
    }

    let t = welch_t(&wa, &wb);
    eprintln!(
        "dudect: n={} a.mean={:.0}ns a.var={:.0} b.mean={:.0}ns b.var={:.0} |t|={:.3}",
        wa.n,
        wa.mean,
        wa.variance(),
        wb.mean,
        wb.variance(),
        t.abs()
    );
    t.abs()
}

#[test]
fn timing_smoke() {
    // tiny sample, just verifies the harness runs and produces a
    // statistically-meaningful number under a generous threshold.
    let t = run_dudect(2_000);
    assert!(t.is_finite(), "welch t-stat must be finite, got {}", t);
    // smoke threshold is intentionally loose; serious runs use 6.0.
    assert!(
        t < 12.0,
        "smoke test exceeded sanity threshold: |t|={t} (smoke=12.0)"
    );
}

#[test]
#[ignore]
fn timing_serious() {
    // run with: cargo test --release --test timing -- --ignored --nocapture
    let n: usize = std::env::var("MLKEM_TIMING_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let t = run_dudect(n);
    assert!(
        t < T_THRESHOLD_ABS,
        "constant-time test failed: |t|={t} (threshold={T_THRESHOLD_ABS}). \
         either there is a real timing leak or the run was too noisy. retry on a quiet machine."
    );
}
