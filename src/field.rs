// z_q arithmetic, q = 3329.
// barrett reduction for the multiply path. q is small so this is cheap.

use crate::params::Q;

pub type Fe = u16;

// barrett: for 0 <= a < 2^26 roughly, compute a mod q.
// m = floor(2^26 / q). pick it so t = (a*m) >> 26 is either correct or 1 too big.
#[inline(always)]
pub fn barrett_reduce(a: i32) -> u16 {
    // barrett: v = floor(2^26 / q). shifts by 26.
    // 64-bit product to avoid overflow. branchless normalize via sign mask.
    const V: i64 = (1i64 << 26) / (Q as i64);
    let t = ((V * a as i64) >> 26) as i32 * (Q as i32);
    let r = a - t;
    // r in (-q, 2q]. bring up if negative, bring down if >= q.
    let r = r + ((r >> 31) & Q as i32);
    let r = r - ((((Q as i32 - 1 - r) >> 31) & 1) * Q as i32);
    r as u16
}

#[inline(always)]
pub fn fqadd(a: Fe, b: Fe) -> Fe {
    let s = a as i32 + b as i32 - Q as i32;
    (s + (((s >> 15) & 1) * Q as i32)) as u16
}

#[inline(always)]
pub fn fqsub(a: Fe, b: Fe) -> Fe {
    let s = a as i32 - b as i32;
    (s + (((s >> 15) & 1) * Q as i32)) as u16
}

#[inline(always)]
pub fn fqmul(a: Fe, b: Fe) -> Fe {
    barrett_reduce(a as i32 * b as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn barrett_matches_naive() {
        for a in 0..(Q as i32 * Q as i32) {
            assert_eq!(barrett_reduce(a), (a % Q as i32) as u16);
            if a > 100000 {
                break;
            } // sanity spot, not full
        }
        for a in [0, 1, Q as i32 - 1, Q as i32, Q as i32 * (Q as i32 - 1)] {
            assert_eq!(barrett_reduce(a), (a % Q as i32) as u16);
        }
    }
    #[test]
    fn ops() {
        assert_eq!(fqadd(3000, 500), 3500 - Q);
        assert_eq!(fqsub(10, 20), (Q as i32 - 10) as u16);
        assert_eq!(fqmul(17, 17), 289);
    }
}
