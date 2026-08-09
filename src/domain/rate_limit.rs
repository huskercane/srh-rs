use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ports::Clock;

pub const MAX_BUCKETS: usize = 100_000;
const IDLE_EVICTION: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitExceeded {
    pub retry_after_secs: u64,
}

struct Bucket {
    balance: f64,
    updated: Instant,
    last_access: Instant,
    order: u64,
}

type LruKey = (Instant, u64, String);

#[derive(Default)]
struct Buckets {
    entries: HashMap<String, Bucket>,
    credit_lru: BTreeSet<LruKey>,
    debt_lru: BTreeSet<LruKey>,
    next_order: u64,
}

pub struct RateLimiter {
    rate: u64,
    capacity: f64,
    clock: Arc<dyn Clock>,
    max_buckets: usize,
    buckets: Mutex<Buckets>,
    debt_forgiven_evictions: AtomicU64,
}

impl RateLimiter {
    /// Creates a bounded per-credential token bucket. A zero rate disables limiting.
    pub fn new(rate: u64, clock: Arc<dyn Clock>) -> Self {
        Self::with_max_buckets(rate, clock, MAX_BUCKETS)
    }

    fn with_max_buckets(rate: u64, clock: Arc<dyn Clock>, max_buckets: usize) -> Self {
        Self {
            rate,
            capacity: rate.saturating_mul(2) as f64,
            clock,
            max_buckets: max_buckets.max(1),
            buckets: Mutex::new(Buckets::default()),
            debt_forgiven_evictions: AtomicU64::new(0),
        }
    }

    /// Rejects an already-indebted identity without charging it.
    pub fn probe(&self, key: &str) -> Result<(), RateLimitExceeded> {
        if self.rate == 0 {
            return Ok(());
        }
        let now = self.clock.instant();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bucket = self.take_bucket(&mut buckets, key, now);
        refill(&mut bucket, now, self.rate, self.capacity);
        bucket.last_access = now;
        let result = if bucket.balance <= 0.0 {
            Err(self.exceeded(bucket.balance))
        } else {
            Ok(())
        };
        finish_access(&mut buckets, key, bucket);
        result
    }

    /// Charges a parsed request in full whenever its balance is positive before charging.
    pub fn charge(&self, key: &str, command_count: usize) -> Result<(), RateLimitExceeded> {
        if self.rate == 0 {
            return Ok(());
        }
        let now = self.clock.instant();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bucket = self.take_bucket(&mut buckets, key, now);
        refill(&mut bucket, now, self.rate, self.capacity);
        bucket.last_access = now;
        let result = if bucket.balance <= 0.0 {
            Err(self.exceeded(bucket.balance))
        } else {
            bucket.balance -= command_count.max(1) as f64;
            Ok(())
        };
        finish_access(&mut buckets, key, bucket);
        result
    }

    /// Evicts non-indebted buckets that have been idle for at least fifteen minutes.
    pub fn sweep_idle(&self) -> usize {
        if self.rate == 0 {
            return 0;
        }
        let now = self.clock.instant();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys = buckets.entries.keys().cloned().collect::<Vec<_>>();
        let mut evicted = 0;
        for key in keys {
            let Some(mut bucket) = buckets.entries.remove(&key) else {
                continue;
            };
            remove_order(&mut buckets, &key, &bucket);
            refill(&mut bucket, now, self.rate, self.capacity);
            if bucket.balance >= 0.0
                && now.saturating_duration_since(bucket.last_access) >= IDLE_EVICTION
            {
                evicted += 1;
            } else {
                insert_order(&mut buckets, &key, &bucket);
                buckets.entries.insert(key, bucket);
            }
        }
        evicted
    }

    /// Returns the number of currently retained identity buckets.
    pub fn bucket_count(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }

    /// Drains the number of hard-bound evictions that forgave an identity's live debt.
    pub fn take_debt_forgiven_evictions(&self) -> u64 {
        self.debt_forgiven_evictions.swap(0, Ordering::AcqRel)
    }

    fn take_bucket(&self, buckets: &mut Buckets, key: &str, now: Instant) -> Bucket {
        if let Some(bucket) = buckets.entries.remove(key) {
            remove_order(buckets, key, &bucket);
            return bucket;
        }
        if buckets.entries.len() >= self.max_buckets && evict_one(buckets) {
            self.debt_forgiven_evictions.fetch_add(1, Ordering::Relaxed);
        }
        Bucket {
            balance: self.capacity,
            updated: now,
            last_access: now,
            order: 0,
        }
    }

    fn exceeded(&self, balance: f64) -> RateLimitExceeded {
        let deficit = (-balance).max(0.0);
        RateLimitExceeded {
            retry_after_secs: (deficit / self.rate as f64).ceil().max(1.0) as u64,
        }
    }
}

fn refill(bucket: &mut Bucket, now: Instant, rate: u64, capacity: f64) {
    let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
    bucket.balance = (bucket.balance + elapsed * rate as f64).min(capacity);
    bucket.updated = now;
}

fn finish_access(buckets: &mut Buckets, key: &str, mut bucket: Bucket) {
    bucket.order = buckets.next_order;
    buckets.next_order = buckets.next_order.wrapping_add(1);
    insert_order(buckets, key, &bucket);
    buckets.entries.insert(key.to_owned(), bucket);
}

fn order_key(key: &str, bucket: &Bucket) -> LruKey {
    (bucket.last_access, bucket.order, key.to_owned())
}

fn insert_order(buckets: &mut Buckets, key: &str, bucket: &Bucket) {
    let index = if bucket.balance < 0.0 {
        &mut buckets.debt_lru
    } else {
        &mut buckets.credit_lru
    };
    index.insert(order_key(key, bucket));
}

fn remove_order(buckets: &mut Buckets, key: &str, bucket: &Bucket) {
    let index = if bucket.balance < 0.0 {
        &mut buckets.debt_lru
    } else {
        &mut buckets.credit_lru
    };
    index.remove(&order_key(key, bucket));
}

fn evict_one(buckets: &mut Buckets) -> bool {
    let (candidate, forgave_debt) = if let Some(candidate) = buckets.credit_lru.pop_first() {
        (Some(candidate), false)
    } else {
        // At the hard bound, all retained identities may be indebted. Forgiving the oldest debt
        // is the deliberate bounded-memory fallback; normal idle sweeping never forgives debt.
        (buckets.debt_lru.pop_first(), true)
    };
    if let Some((_, _, key)) = candidate {
        buckets.entries.remove(&key);
        forgave_debt
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct ManualClock {
        base: Instant,
        millis: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.millis
                .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn unix_secs(&self) -> u64 {
            0
        }
        fn instant(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::Relaxed))
        }
    }

    fn limiter(rate: u64) -> (RateLimiter, Arc<ManualClock>) {
        limiter_with_bound(rate, MAX_BUCKETS)
    }

    fn limiter_with_bound(rate: u64, max_buckets: usize) -> (RateLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        let clock_port: Arc<dyn Clock> = clock.clone();
        (
            RateLimiter::with_max_buckets(rate, clock_port, max_buckets),
            clock,
        )
    }

    #[test]
    fn oversized_batch_is_admitted_then_debt_sets_retry_after() {
        let (limiter, clock) = limiter(10);
        limiter.probe("token").unwrap();
        limiter.charge("token", 100).unwrap();
        assert_eq!(
            limiter.probe("token"),
            Err(RateLimitExceeded {
                retry_after_secs: 8
            })
        );
        clock.advance(Duration::from_secs(8));
        assert!(limiter.probe("token").is_err());
        clock.advance(Duration::from_millis(1));
        limiter.probe("token").unwrap();
    }

    #[test]
    fn rejected_requests_are_not_charged() {
        let (limiter, clock) = limiter(1);
        limiter.charge("token", 2).unwrap();
        assert_eq!(
            limiter.charge("token", 1),
            Err(RateLimitExceeded {
                retry_after_secs: 1
            })
        );
        assert_eq!(
            limiter.charge("token", 100),
            Err(RateLimitExceeded {
                retry_after_secs: 1
            })
        );
        clock.advance(Duration::from_secs(1));
        limiter.charge("token", 1).unwrap();
    }

    #[test]
    fn sequential_commands_spend_the_two_second_burst_without_deepening_debt() {
        let (limiter, _) = limiter(10);
        for _ in 0..20 {
            limiter.charge("token", 1).unwrap();
        }
        assert_eq!(
            limiter.charge("token", 1),
            Err(RateLimitExceeded {
                retry_after_secs: 1
            })
        );
        assert_eq!(
            limiter.charge("token", 100),
            Err(RateLimitExceeded {
                retry_after_secs: 1
            })
        );
    }

    #[test]
    fn full_bucket_keys_are_isolated() {
        let (limiter, _) = limiter(10);
        limiter.charge("deadbeef-rest-of-first", 100).unwrap();
        assert!(limiter.probe("deadbeef-rest-of-first").is_err());
        limiter.probe("deadbeef-rest-of-second").unwrap();
    }

    #[test]
    fn disabled_limiter_never_allocates_or_rejects() {
        let (limiter, _) = limiter(0);
        limiter.probe("token").unwrap();
        limiter.charge("token", usize::MAX).unwrap();
        assert_eq!(limiter.bucket_count(), 0);
    }

    #[test]
    fn sweep_evicts_idle_credit_but_never_live_debt() {
        let (limiter, clock) = limiter(1);
        limiter.charge("credit", 1).unwrap();
        limiter.charge("debt", 10_000).unwrap();
        clock.advance(Duration::from_secs(901));
        assert_eq!(limiter.sweep_idle(), 1);
        let buckets = limiter.buckets.lock().unwrap();
        assert!(!buckets.entries.contains_key("credit"));
        assert!(buckets.entries.contains_key("debt"));
    }

    #[test]
    fn refill_never_accumulates_more_than_two_seconds_of_credit() {
        let (limiter, clock) = limiter(10);
        limiter.charge("token", 20).unwrap();
        clock.advance(Duration::from_secs(3_600));
        limiter.charge("token", 21).unwrap();
        assert_eq!(
            limiter.probe("token"),
            Err(RateLimitExceeded {
                retry_after_secs: 1
            })
        );
    }

    #[test]
    fn bucket_map_stays_bounded_and_prefers_evicting_credit() {
        let (limiter, _) = limiter_with_bound(10, 2);
        limiter.charge("debt", 100).unwrap();
        limiter.charge("credit", 1).unwrap();
        limiter.charge("new", 1).unwrap();

        let buckets = limiter.buckets.lock().unwrap();
        assert_eq!(buckets.entries.len(), 2);
        assert!(buckets.entries.contains_key("debt"));
        assert!(buckets.entries.contains_key("new"));
        assert!(!buckets.entries.contains_key("credit"));
    }

    #[test]
    fn all_debt_at_the_hard_bound_evicts_only_the_oldest_bucket() {
        let (limiter, _) = limiter_with_bound(10, 2);
        limiter.charge("old-debt", 100).unwrap();
        limiter.charge("new-debt", 100).unwrap();
        limiter.charge("arrival", 100).unwrap();

        let buckets = limiter.buckets.lock().unwrap();
        assert_eq!(buckets.entries.len(), 2);
        assert!(!buckets.entries.contains_key("old-debt"));
        assert!(buckets.entries.contains_key("new-debt"));
        assert!(buckets.entries.contains_key("arrival"));
        drop(buckets);
        assert_eq!(limiter.take_debt_forgiven_evictions(), 1);
        assert_eq!(limiter.take_debt_forgiven_evictions(), 0);
    }
}
