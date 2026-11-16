use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited,
    Saturated,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    count: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    enabled: bool,
    limit: u64,
    window: Duration,
    capacity: usize,
    clients: Mutex<HashMap<IpAddr, Window>>,
}

impl RateLimiter {
    pub fn new(enabled: bool, limit: u64, window: Duration, capacity: usize) -> Self {
        Self {
            enabled,
            limit,
            window,
            capacity,
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, address: IpAddr) -> RateLimitDecision {
        if !self.enabled {
            return RateLimitDecision::Allowed;
        }

        let now = Instant::now();
        let mut clients = self.clients.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("rate limiter lock was poisoned; continuing with its state");
            poisoned.into_inner()
        });
        if let Some(window) = clients.get_mut(&address) {
            if now.duration_since(window.started) >= self.window {
                *window = Window {
                    started: now,
                    count: 0,
                };
            }
            if window.count >= self.limit {
                return RateLimitDecision::Limited;
            }
            window.count += 1;
            return RateLimitDecision::Allowed;
        }

        if clients.len() >= self.capacity {
            clients.retain(|_, window| now.duration_since(window.started) < self.window);
            if clients.len() >= self.capacity {
                return RateLimitDecision::Saturated;
            }
        }
        clients.insert(
            address,
            Window {
                started: now,
                count: 1,
            },
        );
        RateLimitDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_only_the_address_over_budget() {
        let limiter = RateLimiter::new(true, 2, Duration::from_secs(60), 8);
        let first: IpAddr = "192.0.2.1".parse().expect("address");
        let second: IpAddr = "192.0.2.2".parse().expect("address");
        assert_eq!(limiter.check(first), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(first), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(first), RateLimitDecision::Limited);
        assert_eq!(limiter.check(second), RateLimitDecision::Allowed);
    }

    #[test]
    fn rejects_new_clients_at_capacity() {
        let limiter = RateLimiter::new(true, 2, Duration::from_secs(60), 1);
        limiter.check("192.0.2.1".parse().expect("address"));
        assert_eq!(
            limiter.check("192.0.2.2".parse().expect("address")),
            RateLimitDecision::Saturated
        );
    }

    #[test]
    fn window_expiry_restores_budget() {
        let limiter = RateLimiter::new(true, 1, Duration::from_millis(10), 1);
        let address = "192.0.2.1".parse().expect("address");
        assert_eq!(limiter.check(address), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(address), RateLimitDecision::Limited);
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(limiter.check(address), RateLimitDecision::Allowed);
    }

    #[test]
    fn disabled_limiter_is_open() {
        let limiter = RateLimiter::new(false, 0, Duration::ZERO, 0);
        assert_eq!(
            limiter.check("192.0.2.1".parse().expect("address")),
            RateLimitDecision::Allowed
        );
    }
}
