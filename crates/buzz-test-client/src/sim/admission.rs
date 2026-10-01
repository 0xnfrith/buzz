//! Publish that tells the relay's per-key rate limiter apart from a lost OK.
//!
//! An over-quota `EVENT` gets a `NOTICE` ("rate-limited: …"), not an `OK`, so
//! `BuzzTestClient::send_event` would wait out its full 30 s OK timeout. The
//! notice carries no event id; it is attributable only because callers keep
//! one event in flight per socket. [`send_tracked`] returns the other frames
//! that arrive meanwhile, for a socket with subscriptions (an identity in a
//! band); [`publish`] drops them, for a socket with none (owner
//! provisioning, seed writers).

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

/// Sends `event` and waits up to `ok_timeout` for its answer: its OK, or the
/// relay's per-key rate-limit NOTICE (relay-v0.2.1 sends that NOTICE instead
/// of an OK, so waiting for the OK alone times out). Every other message
/// that arrives meanwhile (a subscription's events, other notices) is
/// returned, in order, for the caller to handle; none is dropped.
pub async fn send_tracked(
    client: &mut BuzzTestClient,
    event: &Event,
    ok_timeout: Duration,
) -> Result<(Publish, Vec<RelayMessage>), TestClientError> {
    let id = event.id.to_hex();
    client.send_raw(&json!(["EVENT", event])).await?;
    let deadline = tokio::time::Instant::now() + ok_timeout;
    let mut others = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(TestClientError::Timeout);
        }
        match client.recv_event(remaining).await? {
            RelayMessage::Ok(ok) if ok.event_id == id => return Ok((Publish::Ok(ok), others)),
            RelayMessage::Notice { message } if rate_limit_retry(&message).is_some() => {
                let retry_in = rate_limit_retry(&message).unwrap_or(DEFAULT_RETRY);
                return Ok((Publish::RateLimited { retry_in }, others));
            }
            other => others.push(other),
        }
    }
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
/// [`send_tracked`] for setup and the seed, whose sockets subscribe to
/// nothing: any other message is dropped.
pub async fn publish(
    client: &mut BuzzTestClient,
    event: &Event,
    ok_timeout: Duration,
) -> Result<Publish, TestClientError> {
    Ok(send_tracked(client, event, ok_timeout).await?.0)
}

/// A fake relay for the rows that need a socket.
#[cfg(test)]
pub(crate) mod testrelay {
    /// How a test relay answers an EVENT of a given kind.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Answer {
        Accept,
        /// OK false, with this message.
        Reject(&'static str),
        /// No answer: the socket is closed.
        Close,
        /// The per-key rate limit's NOTICE, no OK.
        RateLimit,
    }

    /// A test relay; `kill` drops it: every open socket closes, and new
    /// connections are refused.
    pub(crate) struct TestRelay {
        pub(crate) url: String,
        kill: tokio::sync::watch::Sender<bool>,
    }

    impl TestRelay {
        pub(crate) fn kill(&self) {
            let _ = self.kill.send(true);
        }
    }

    /// A relay that takes every connection: an AUTH challenge on connect,
    /// OK for every AUTH, EOSE for every REQ, and for each EVENT what
    /// `answer` says for its kind.
    pub(crate) async fn relay_with(answer: fn(u64) -> Answer) -> TestRelay {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (kill, killed) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let mut stop = killed.clone();
            loop {
                let (tcp, _) = tokio::select! {
                    r = listener.accept() => match r { Ok(c) => c, Err(_) => return },
                    _ = stop.changed() => return, // the listener drops: refused
                };
                let mut stop = killed.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    let challenge = serde_json::json!(["AUTH", "test-challenge"]).to_string();
                    if ws.send(Message::Text(challenge.into())).await.is_err() {
                        return;
                    }
                    loop {
                        let msg = tokio::select! {
                            m = ws.next() => match m { Some(Ok(m)) => m, _ => return },
                            _ = stop.changed() => return, // the socket drops
                        };
                        let Ok(text) = msg.into_text() else { continue };
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let reply = match v[0].as_str() {
                            Some("AUTH") => serde_json::json!(["OK", v[1]["id"], true, ""]),
                            Some("EVENT") => match answer(v[1]["kind"].as_u64().unwrap_or(0)) {
                                Answer::Accept => serde_json::json!(["OK", v[1]["id"], true, ""]),
                                Answer::Reject(m) => {
                                    serde_json::json!(["OK", v[1]["id"], false, m])
                                }
                                Answer::Close => return,
                                Answer::RateLimit => serde_json::json!([
                                    "NOTICE",
                                    "rate-limited: quota exceeded; retry in 60s"
                                ]),
                            },
                            Some("REQ") => serde_json::json!(["EOSE", v[1]]),
                            _ => continue,
                        };
                        if ws
                            .send(Message::Text(reply.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        TestRelay {
            url: format!("ws://{addr}"),
            kill,
        }
    }

    /// A relay that accepts everything. For a whole run without a real
    /// relay.
    pub(crate) async fn accepting_relay() -> String {
        // The relay outlives the test: its kill switch is never used.
        let r = relay_with(|_| Answer::Accept).await;
        std::mem::forget(r.kill);
        r.url
    }

    /// A one-connection relay that answers the first EVENT with `replies`,
    /// each a JSON frame; `{id}` is the event's id.
    pub(crate) async fn fake_relay(replies: Vec<String>) -> String {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut ws = tokio_tungstenite::accept_async(tcp).await.expect("ws");
            while let Some(Ok(msg)) = ws.next().await {
                let Ok(text) = msg.into_text() else { continue };
                let v: serde_json::Value = serde_json::from_str(&text).expect("json");
                let id = v[1]["id"].as_str().expect("event id").to_string();
                for r in &replies {
                    let frame = r.replace("{id}", &id);
                    ws.send(tokio_tungstenite::tungstenite::Message::Text(frame.into()))
                        .await
                        .expect("send");
                }
            }
        });
        format!("ws://{addr}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testrelay::fake_relay;

    fn event() -> Event {
        nostr::EventBuilder::new(nostr::Kind::Custom(9), "hi")
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign")
    }

    /// relay-v0.2.1 answers an over-quota EVENT with a NOTICE and no OK. In
    /// a band, that is a rate limit, not a send that failed; and the
    /// subscription's events that came first are kept, not dropped.
    #[tokio::test]
    async fn a_rate_limit_notice_is_its_own_answer_and_keeps_the_other_frames() {
        let other = event();
        let url = fake_relay(vec![
            serde_json::json!(["EVENT", "sub-1", other]).to_string(),
            r#"["NOTICE","slow down a little"]"#.to_string(),
            r#"["NOTICE","rate-limited: quota exceeded; retry in 7s"]"#.to_string(),
        ])
        .await;
        let mut client = BuzzTestClient::connect_unauthenticated(&url)
            .await
            .expect("connect");
        let (answer, others) = send_tracked(&mut client, &event(), Duration::from_secs(5))
            .await
            .expect("an answer");
        assert!(
            matches!(answer, Publish::RateLimited { retry_in } if retry_in == Duration::from_secs(7)),
            "{answer:?}"
        );
        assert_eq!(others.len(), 2, "{others:?}");
        assert!(
            matches!(&others[0], RelayMessage::Event { event, .. } if event.id == other.id),
            "{others:?}"
        );
        assert!(
            matches!(&others[1], RelayMessage::Notice { message } if message == "slow down a little"),
            "{others:?}"
        );
    }

    #[tokio::test]
    async fn an_ok_is_the_answer() {
        let url = fake_relay(vec![r#"["OK","{id}",true,""]"#.to_string()]).await;
        let mut client = BuzzTestClient::connect_unauthenticated(&url)
            .await
            .expect("connect");
        let (answer, others) = send_tracked(&mut client, &event(), Duration::from_secs(5))
            .await
            .expect("an answer");
        assert!(
            matches!(answer, Publish::Ok(ref ok) if ok.accepted),
            "{answer:?}"
        );
        assert!(others.is_empty(), "{others:?}");
    }

    #[tokio::test]
    async fn no_answer_is_a_timeout() {
        let url = fake_relay(vec![r#"["NOTICE","nothing to see"]"#.to_string()]).await;
        let mut client = BuzzTestClient::connect_unauthenticated(&url)
            .await
            .expect("connect");
        let err = send_tracked(&mut client, &event(), Duration::from_millis(500))
            .await
            .map(|_| ())
            .expect_err("no answer");
        assert!(matches!(err, TestClientError::Timeout), "{err:?}");
    }

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
