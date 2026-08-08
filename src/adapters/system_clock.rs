use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::ports::Clock;

pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}
