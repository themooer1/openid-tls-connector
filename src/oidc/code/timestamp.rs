use thiserror::Error;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

#[derive(Debug, Error)]
pub enum TimestampError
{
    #[error("data is not fresh")]
    NotFresh,
}

// Stores data and only allows it to be extracted if it is fresh.
#[derive(Debug, Deserialize, Serialize)]
pub struct TimestampedContainer<T>
{
    content: T,
    timestamp: SystemTime,
}

impl<T> TimestampedContainer<T>
{
    pub fn new(content: T) -> Self
    {
        Self {
            content,
            timestamp: SystemTime::now()
        }
    }

    pub fn extract(self, max_age: Duration) -> Result<T, TimestampError>
    {
        // Check that the data is not older than max_age.
        // If the current time is somehow older than the timestamp, just assume an error occurred
        // and the data is not fresh.
        let fresh = SystemTime::now()
            .duration_since(self.timestamp)
            .map(|elapsed| elapsed < max_age)
            .unwrap_or(false);

        if fresh {
            Ok(self.content)
        }
        else {
            Err(TimestampError::NotFresh)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_container_extracts() {
        let container = TimestampedContainer::new(42u32);
        let result = container.extract(Duration::from_secs(60));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_expired_container_returns_error() {
        let mut container = TimestampedContainer::new(42u32);
        // Set timestamp to 2 minutes ago
        container.timestamp = SystemTime::now() - Duration::from_secs(120);
        let result = container.extract(Duration::from_secs(60));
        assert!(matches!(result, Err(TimestampError::NotFresh)));
    }

    #[test]
    fn test_exactly_at_max_age() {
        let mut container = TimestampedContainer::new(42u32);
        // Set timestamp to exactly max_age ago (plus a tiny margin for test stability)
        container.timestamp = SystemTime::now() - Duration::from_secs(60);
        // With exactly max_age, elapsed >= max_age so it should be not fresh
        let result = container.extract(Duration::from_secs(60));
        assert!(matches!(result, Err(TimestampError::NotFresh)));
    }
}