use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub trait Clock {
    // Told the machine how long it had been since the clock began.
    fn now(&self) -> Duration;
}

pub struct SystemClock(Instant);

impl SystemClock {
    // Started a wall clock at this very moment.
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemClock {
    // Started a default clock at this very moment.
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    // Measured the time since this clock was created.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Clone, Default)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    // Pushed the hands forward by hand so tests could skip the waiting.
    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    // Read whatever time the test had set.
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
