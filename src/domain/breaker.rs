use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ports::Clock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BreakerState {
    Closed,
    HalfOpen,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BreakerPermit {
    generation: u64,
    probe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BreakerTransition {
    Opened,
    ProbeStarted,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BreakerAdmission {
    pub permit: BreakerPermit,
    pub transition: Option<BreakerTransition>,
}

#[derive(Debug)]
struct Inner {
    state: BreakerState,
    consecutive_failures: usize,
    opened_at: Option<Instant>,
    generation: u64,
}

/// A clock-injected circuit-breaker state machine with one half-open probe.
pub struct Breaker {
    clock: Arc<dyn Clock>,
    failure_threshold: usize,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

impl Breaker {
    pub fn new(clock: Arc<dyn Clock>, failure_threshold: usize, cooldown: Duration) -> Self {
        Self {
            clock,
            failure_threshold,
            cooldown,
            inner: Mutex::new(Inner {
                state: BreakerState::Closed,
                consecutive_failures: 0,
                opened_at: None,
                generation: 0,
            }),
        }
    }

    /// Checks admission before any pool waiter or request permit is consumed.
    pub fn admit(&self) -> Result<BreakerAdmission, u64> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.state {
            BreakerState::Closed => Ok(BreakerAdmission {
                permit: BreakerPermit {
                    generation: inner.generation,
                    probe: false,
                },
                transition: None,
            }),
            BreakerState::HalfOpen => Err(seconds_ceil(self.cooldown)),
            BreakerState::Open => {
                let elapsed = inner
                    .opened_at
                    .map_or(Duration::ZERO, |opened| self.clock.instant() - opened);
                if elapsed >= self.cooldown {
                    inner.state = BreakerState::HalfOpen;
                    inner.generation = inner.generation.wrapping_add(1);
                    Ok(BreakerAdmission {
                        permit: BreakerPermit {
                            generation: inner.generation,
                            probe: true,
                        },
                        transition: Some(BreakerTransition::ProbeStarted),
                    })
                } else {
                    Err(seconds_ceil(self.cooldown - elapsed))
                }
            }
        }
    }

    /// Records an executor outcome associated with a prior admission permit.
    pub fn record(&self, permit: BreakerPermit, failed: bool) -> Option<BreakerTransition> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if permit.generation != inner.generation {
            return None;
        }
        if permit.probe {
            if inner.state != BreakerState::HalfOpen {
                return None;
            }
            inner.generation = inner.generation.wrapping_add(1);
            if failed {
                inner.state = BreakerState::Open;
                inner.opened_at = Some(self.clock.instant());
                Some(BreakerTransition::Opened)
            } else {
                inner.state = BreakerState::Closed;
                inner.consecutive_failures = 0;
                inner.opened_at = None;
                Some(BreakerTransition::Closed)
            }
        } else if inner.state != BreakerState::Closed {
            None
        } else if failed {
            inner.consecutive_failures += 1;
            if inner.consecutive_failures >= self.failure_threshold {
                inner.state = BreakerState::Open;
                inner.opened_at = Some(self.clock.instant());
                inner.generation = inner.generation.wrapping_add(1);
                Some(BreakerTransition::Opened)
            } else {
                None
            }
        } else {
            inner.consecutive_failures = 0;
            None
        }
    }

    /// Releases an unused half-open permit so another request can probe.
    pub fn cancel(&self, permit: BreakerPermit) {
        if !permit.probe {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.state == BreakerState::HalfOpen && permit.generation == inner.generation {
            inner.state = BreakerState::Open;
            inner.generation = inner.generation.wrapping_add(1);
        }
    }

    pub fn state(&self) -> BreakerState {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
    }
}

fn seconds_ceil(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakeClock {
        now: Mutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Mutex::new(Instant::now()),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().unwrap();
            *now += duration;
        }
    }

    impl Clock for FakeClock {
        fn unix_secs(&self) -> u64 {
            0
        }

        fn instant(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    #[test]
    fn opens_after_consecutive_failures_and_allows_exactly_one_probe() {
        let clock = Arc::new(FakeClock::new());
        let breaker = Breaker::new(clock.clone(), 2, Duration::from_millis(500));

        let first = breaker.admit().unwrap().permit;
        assert_eq!(breaker.record(first, true), None);
        let second = breaker.admit().unwrap().permit;
        assert_eq!(
            breaker.record(second, true),
            Some(BreakerTransition::Opened)
        );
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.admit(), Err(1));

        clock.advance(Duration::from_millis(500));
        let probe = breaker.admit().unwrap();
        assert_eq!(probe.transition, Some(BreakerTransition::ProbeStarted));
        assert!(probe.permit.probe);
        assert_eq!(breaker.admit(), Err(1));
        assert_eq!(
            breaker.record(probe.permit, false),
            Some(BreakerTransition::Closed)
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[test]
    fn an_in_flight_probe_reports_the_configured_cooldown() {
        let clock = Arc::new(FakeClock::new());
        let breaker = Breaker::new(clock.clone(), 1, Duration::from_millis(1_500));
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, true);
        clock.advance(Duration::from_millis(1_500));
        let _probe = breaker.admit().unwrap();
        assert_eq!(breaker.admit(), Err(2));
    }

    #[test]
    fn canceling_an_unused_probe_allows_another_probe_immediately() {
        let clock = Arc::new(FakeClock::new());
        let breaker = Breaker::new(clock.clone(), 1, Duration::from_secs(1));
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, true);
        clock.advance(Duration::from_secs(1));
        let probe = breaker.admit().unwrap().permit;
        breaker.cancel(probe);
        assert!(breaker.admit().is_ok());
    }

    #[test]
    fn success_resets_failures_and_failed_probe_restarts_cooldown() {
        let clock = Arc::new(FakeClock::new());
        let breaker = Breaker::new(clock.clone(), 2, Duration::from_secs(2));
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, true);
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, false);
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, true);
        assert_eq!(breaker.state(), BreakerState::Closed);
        let permit = breaker.admit().unwrap().permit;
        breaker.record(permit, true);

        clock.advance(Duration::from_secs(2));
        let probe = breaker.admit().unwrap().permit;
        assert_eq!(breaker.record(probe, true), Some(BreakerTransition::Opened));
        assert_eq!(breaker.admit(), Err(2));
    }
}
