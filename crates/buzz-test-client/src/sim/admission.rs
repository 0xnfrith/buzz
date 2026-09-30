//! Publish that tells the relay's per-key rate limiter apart from a lost OK.
//!
//! An over-quota `EVENT` gets a `NOTICE` ("rate-limited: …"), not an `OK`, so
//! `BuzzTestClient::send_event` would wait out its full 30 s OK timeout. The
//! notice carries no event id; it is attributable only because callers keep
//! one event in flight per socket. Use this on sockets with no subscriptions
//! (owner provisioning, seed writers): other frames are skipped, not queued.

use std::time::Duration;

use buzz_test_client::{BuzzTestClient, OkResponse, RelayMessage, TestClientError};
use nostr::Event;
use serde_json::json;

/// Fallback wait when the notice does not say when the window resets.
const DEFAULT_RETRY: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum Publish {
    Ok(OkResponse),
    RateLimited { retry_in: Duration },
}

/// Parse a relay `NOTICE` into a retry delay if it is a rate-limit rejection.
///
/// relay-v0.2.1 sends `rate-limited: quota exceeded; retry in {n}s` or
/// `rate-limited: shared admission unavailable`.
pub fn rate_limit_retry(notice: &str) -> Option<Duration> {
    let rest = notice.strip_prefix("rate-limited:")?;
    let secs = rest
        .split("retry in ")
        .nth(1)
        .and_then(|s| s.trim_end().strip_suffix('s'))
        .and_then(|n| n.trim().parse::<u64>().ok());
    Some(match secs {
        Some(0) | None => DEFAULT_RETRY,
        Some(n) => Duration::from_secs(n),
    })
}

/// Send one event and wait for its `OK` or a rate-limit `NOTICE`.
pub async fn publish(
    client: &mut BuzzTestClient,
    event: &Event,
    ok_timeout: Duration,
) -> Result<Publish, TestClientError> {
    let id = event.id.to_hex();
    client.send_raw(&json!(["EVENT", event])).await?;
    let deadline = tokio::time::Instant::now() + ok_timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(TestClientError::Timeout);
        }
        match client.recv_event(remaining).await? {
            RelayMessage::Ok(ok) if ok.event_id == id => return Ok(Publish::Ok(ok)),
            RelayMessage::Notice { message } => {
                if let Some(retry_in) = rate_limit_retry(&message) {
                    return Ok(Publish::RateLimited { retry_in });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quota_notice() {
        assert_eq!(
            rate_limit_retry("rate-limited: quota exceeded; retry in 42s"),
            Some(Duration::from_secs(42))
        );
    }

    #[test]
    fn zero_or_missing_reset_falls_back() {
        assert_eq!(
            rate_limit_retry("rate-limited: quota exceeded; retry in 0s"),
            Some(DEFAULT_RETRY)
        );
        assert_eq!(
            rate_limit_retry("rate-limited: shared admission unavailable"),
            Some(DEFAULT_RETRY)
        );
    }

    #[test]
    fn other_notices_are_not_rate_limits() {
        assert_eq!(rate_limit_retry("auth-required: please authenticate"), None);
        assert_eq!(rate_limit_retry(""), None);
    }
}
