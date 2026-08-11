use std::collections::{BTreeMap, HashMap};
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

/// One credential's token balance.
///
/// `key` is a second handle to the map key, so re-indexing a bucket for recency costs a
/// refcount bump instead of a key clone: the credential digest is allocated once and
/// shared by the map entry, the bucket, and the LRU index.
struct Bucket {
    balance: f64,
    updated: Instant,
    last_access: Instant,
    order: u64,
    key: Arc<str>,
    /// Which index currently holds `order`. Recorded when the bucket is linked rather
    /// than derived from `balance` on read, so an in-place refill can never unlink from
    /// the wrong index.
    indebted: bool,
}

/// Recency index over bucket keys, split so eviction can prefer non-indebted identities.
///
/// Ordering is by `order`, a monotonic access counter. That is the same ordering the
/// previous `(last_access, order)` composite key produced — `last_access` is set to `now`
/// on the very access that assigns `order`, so the two agree on every pair — but a `u64`
/// key is `Copy`, which is what removes the per-access key clone and the string
/// comparisons from the critical section.
#[derive(Default)]
struct Lru {
    credit: BTreeMap<u64, Arc<str>>,
    debt: BTreeMap<u64, Arc<str>>,
    next_order: u64,
}

impl Lru {
    fn unlink(&mut self, bucket: &Bucket) {
        if bucket.indebted {
            self.debt.remove(&bucket.order);
        } else {
            self.credit.remove(&bucket.order);
        }
    }

    fn link(&mut self, bucket: &mut Bucket) {
        bucket.order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        bucket.indebted = bucket.balance < 0.0;
        let index = if bucket.indebted {
            &mut self.debt
        } else {
            &mut self.credit
        };
        index.insert(bucket.order, Arc::clone(&bucket.key));
    }
}

#[derive(Default)]
struct Buckets {
    entries: HashMap<Arc<str>, Bucket>,
    lru: Lru,
}

/// What an admitted access does to the balance.
#[derive(Clone, Copy)]
enum Access {
    Probe,
    Charge(usize),
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
        self.access(key, Access::Probe)
    }

    /// Charges a parsed request in full whenever its balance is positive before charging.
    pub fn charge(&self, key: &str, command_count: usize) -> Result<(), RateLimitExceeded> {
        self.access(key, Access::Charge(command_count))
    }

    /// Admits or rejects one access, updating the bucket in place.
    ///
    /// This is the whole per-request cost of rate limiting, and it runs twice per request
    /// under one global lock, so the length of this critical section — not its throughput
    /// in isolation — is what bounds concurrency for a single hot credential. It is one
    /// hash lookup plus two `u64`-keyed index operations, and it allocates only when a
    /// credential is seen for the first time.
    fn access(&self, key: &str, access: Access) -> Result<(), RateLimitExceeded> {
        if self.rate == 0 {
            return Ok(());
        }
        let now = self.clock.instant();
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Buckets { entries, lru } = &mut *guard;
        if let Some(bucket) = entries.get_mut(key) {
            // Unlink before refilling: `indebted` describes where `order` is indexed
            // right now, and refilling may change which index the bucket belongs in.
            lru.unlink(bucket);
            refill(bucket, now, self.rate, self.capacity);
            bucket.last_access = now;
            let result = self.settle(bucket, access);
            lru.link(bucket);
            return result;
        }
        if entries.len() >= self.max_buckets && evict_one(entries, lru) {
            self.debt_forgiven_evictions.fetch_add(1, Ordering::Relaxed);
        }
        let key = Arc::<str>::from(key);
        // A bucket created at `now` has nothing to refill and is in no index yet.
        let mut bucket = Bucket {
            balance: self.capacity,
            updated: now,
            last_access: now,
            order: 0,
            key: Arc::clone(&key),
            indebted: false,
        };
        let result = self.settle(&mut bucket, access);
        lru.link(&mut bucket);
        entries.insert(key, bucket);
        result
    }

    fn settle(&self, bucket: &mut Bucket, access: Access) -> Result<(), RateLimitExceeded> {
        if bucket.balance <= 0.0 {
            return Err(self.exceeded(bucket.balance));
        }
        if let Access::Charge(command_count) = access {
            bucket.balance -= command_count.max(1) as f64;
        }
        Ok(())
    }

    /// Evicts non-indebted buckets that have been idle for at least fifteen minutes.
    ///
    /// Runs from pool maintenance once a minute, so it stays a full scan; only the
    /// per-request path above is on the hot path.
    pub fn sweep_idle(&self) -> usize {
        if self.rate == 0 {
            return 0;
        }
        let now = self.clock.instant();
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Buckets { entries, lru } = &mut *guard;
        let mut idle = Vec::new();
        for (key, bucket) in entries.iter_mut() {
            refill(bucket, now, self.rate, self.capacity);
            // Refilling can lift a bucket out of debt with no access of its own, so
            // re-index it before deciding: an identity that repaid its debt by waiting is
            // an ordinary idle bucket again.
            if bucket.indebted && bucket.balance >= 0.0 {
                lru.debt.remove(&bucket.order);
                lru.credit.insert(bucket.order, Arc::clone(key));
                bucket.indebted = false;
            }
            if bucket.balance >= 0.0
                && now.saturating_duration_since(bucket.last_access) >= IDLE_EVICTION
            {
                idle.push(Arc::clone(key));
            }
        }
        for key in &idle {
            if let Some(bucket) = entries.remove(key) {
                lru.unlink(&bucket);
            }
        }
        idle.len()
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

fn evict_one(entries: &mut HashMap<Arc<str>, Bucket>, lru: &mut Lru) -> bool {
    let (candidate, forgave_debt) = if let Some(candidate) = lru.credit.pop_first() {
        (Some(candidate), false)
    } else {
        // At the hard bound, all retained identities may be indebted. Forgiving the oldest debt
        // is the deliberate bounded-memory fallback; normal idle sweeping never forgives debt.
        (lru.debt.pop_first(), true)
    };
    if let Some((_, key)) = candidate {
        entries.remove(&key);
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
    fn a_debt_repaid_by_idling_is_swept_and_leaves_no_stale_index_entry() {
        let (limiter, clock) = limiter(1);
        // Deliberately a small debt: unlike the live-debt case above, fifteen minutes of
        // refill clears it, so the sweep must move the bucket out of the debt index
        // before evicting it.
        limiter.charge("repaid", 5).unwrap();
        {
            let buckets = limiter.buckets.lock().unwrap();
            assert_eq!(buckets.lru.debt.len(), 1, "the bucket starts indebted");
        }
        clock.advance(Duration::from_secs(901));

        assert_eq!(limiter.sweep_idle(), 1);
        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.entries.is_empty());
        assert!(
            buckets.lru.credit.is_empty() && buckets.lru.debt.is_empty(),
            "eviction must unlink from whichever index the refill left the bucket in"
        );
    }

    #[test]
    fn every_retained_bucket_is_indexed_exactly_once() {
        let (limiter, clock) = limiter(10);
        // Drives buckets back and forth across the credit/debt boundary: an unlink from
        // the wrong index orphans an entry, which would silently break eviction.
        for round in 0..4 {
            for name in ["a", "b", "c"] {
                let _ = limiter.probe(name);
                let _ = limiter.charge(name, round * 9 + 1);
            }
            clock.advance(Duration::from_millis(400));
        }

        let buckets = limiter.buckets.lock().unwrap();
        assert_eq!(
            buckets.lru.credit.len() + buckets.lru.debt.len(),
            buckets.entries.len(),
            "index entries must not be orphaned or duplicated"
        );
        for bucket in buckets.entries.values() {
            let index = if bucket.indebted {
                &buckets.lru.debt
            } else {
                &buckets.lru.credit
            };
            assert_eq!(
                index.get(&bucket.order).map(AsRef::as_ref),
                Some(&*bucket.key),
                "a bucket must be indexed under the list its recorded state names"
            );
        }
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
