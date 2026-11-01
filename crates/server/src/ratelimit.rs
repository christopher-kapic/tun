//! Fixed-window per-IP rate limiter.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
/// Above this many tracked addresses, stale windows are dropped, at most once per `PRUNE_EVERY`.
const PRUNE_ABOVE: usize = 10_000;
const PRUNE_EVERY: Duration = Duration::from_secs(10);
/// Hard cap on tracked addresses. When it is full of live windows, new
/// addresses are refused (fail closed) rather than growing without bound.
const MAX_TRACKED: usize = 100_000;

pub struct RateLimiter {
    per_min: u32,
    windows: Mutex<Windows>,
}

struct Windows {
    map: HashMap<IpAddr, (Instant, u32)>,
    last_prune: Instant,
}

impl RateLimiter {
    /// `per_min == 0` disables limiting.
    pub fn new(per_min: u32) -> Self {
        Self { per_min, windows: Mutex::new(Windows { map: HashMap::new(), last_prune: Instant::now() }) }
    }

    /// Count one attempt from `ip`; `false` if it exceeds the per-minute budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.per_min == 0 {
            return true;
        }
        let key = bucket(ip);
        let now = Instant::now();
        let mut guard = self.windows.lock().expect("ratelimit lock");
        let w = &mut *guard;
        if w.map.len() > PRUNE_ABOVE && now.duration_since(w.last_prune) >= PRUNE_EVERY {
            w.map.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            w.last_prune = now;
        }
        if w.map.len() >= MAX_TRACKED && !w.map.contains_key(&key) {
            return false;
        }
        let entry = w.map.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_min {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// IPv4-mapped addresses count as IPv4 (the listener binds `[::]`), and IPv6
/// clients are bucketed per /64 since one host typically owns the whole prefix.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut seg = v6.segments();
            seg[4..].fill(0);
            IpAddr::V6(seg.into())
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_window() {
        let rl = RateLimiter::new(2);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
        assert!(rl.check("203.0.113.6".parse().unwrap()));
    }

    #[test]
    fn zero_is_unlimited() {
        let rl = RateLimiter::new(0);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..1000 {
            assert!(rl.check(ip));
        }
    }

    #[test]
    fn ipv6_shares_a_64() {
        let rl = RateLimiter::new(1);
        assert!(rl.check("2001:db8::1".parse().unwrap()));
        assert!(!rl.check("2001:db8::2".parse().unwrap()));
        assert!(rl.check("2001:db8:0:1::1".parse().unwrap()));
    }
}
