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