use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Expiration(u64);

impl Expiration {
    #[must_use]
    pub const fn never() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn from_timestamp(ts: u64) -> Self {
        Self(ts)
    }

    #[must_use]
    pub fn from_duration(duration: std::time::Duration) -> Self {
        let ts = SystemTime::now()
            .checked_add(duration)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        Self(ts)
    }

    #[must_use]
    pub const fn as_timestamp(&self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_never(&self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        if self.0 == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.0 <= now
    }
}

impl From<u64> for Expiration {
    fn from(ts: u64) -> Self {
        Self(ts)
    }
}

impl From<Expiration> for u64 {
    fn from(exp: Expiration) -> Self {
        exp.0
    }
}

impl fmt::Display for Expiration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Expiration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for Expiration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ts = u64::deserialize(deserializer)?;
        Ok(Self(ts))
    }
}

/// Deserializes an Expiration and validates it is in the future or never.
/// Used for incoming requests where past expirations are not allowed.
pub fn deserialize_future_expiration<'de, D>(deserializer: D) -> Result<Expiration, D::Error>
where
    D: Deserializer<'de>,
{
    let exp = Expiration::deserialize(deserializer)?;

    if !exp.is_never() && exp.is_expired() {
        return Err(de::Error::custom(
            "expiration timestamp must be in the future or zero",
        ));
    }

    Ok(exp)
}
