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
    /// This key's own quota: counted apart.
    RateLimited {
        retry_in: Duration,
    },
    /// The relay shed the event, full or cut off from its admission store:
    /// the relay failing (see [`Limit::Shed`]).
    Shed {
        text: String,
    },
    /// A `rate-limited:` text the pinned relay doesn't send.
    UnknownLimit {
        text: String,
    },
}

/// What a relay's `rate-limited:` message says, by its exact text. The
/// relay this harness pins (`sha-6e5c462`, `crates/buzz-relay/src`) sends
/// three:
///
/// - `rate-limited: quota exceeded; retry in {n}s`, this key's own quota
///   (`connection.rs:691`; HTTP 429, `api/bridge.rs:45`);
/// - `rate-limited: too many concurrent requests`, its one relay-wide
///   handler semaphore full, not per key or per connection
///   (`connection.rs:542` EVENT, `:571` REQ, `:592` COUNT);
/// - `rate-limited: shared admission unavailable`, the relay unable to
///   reach its own admission store (`connection.rs:699`; HTTP 503,
///   `api/bridge.rs:52`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Limit {
    /// The quota: counted apart, neither a break nor the generator's error.
    Quota { retry_in: Duration },
    /// The relay full, or failing to admit: a relay break.
    Shed { text: String },
    /// Any other `rate-limited:` text. The relay is pinned, so this means
    /// the pin moved: the run voids.
    Unknown { text: String },
}

const QUOTA_TEXT: &str = "rate-limited: quota exceeded";
const SHED_TEXTS: [&str; 2] = [
    "rate-limited: too many concurrent requests",
    "rate-limited: shared admission unavailable",
];

/// The [`Limit`] a relay message's text is, or None when it isn't a
/// `rate-limited:` message at all.
pub fn classify_limit(text: &str) -> Option<Limit> {
    if !text.starts_with("rate-limited:") {
        return None;
    }
    Some(if text.starts_with(QUOTA_TEXT) {
        Limit::Quota {
            retry_in: rate_limit_retry(text).unwrap_or(DEFAULT_RETRY),
        }
    } else if SHED_TEXTS.iter().any(|t| text.starts_with(t)) {
        Limit::Shed {
            text: text.to_string(),
        }
    } else {
        Limit::Unknown {
            text: text.to_string(),
        }
    })
}

/// Why a send got no answer, by whose it is.
#[derive(Debug)]
pub enum SendError {
    /// Nothing was written: the socket was already closed, or the write
    /// failed. The generator's own failure.
    NotSent(TestClientError),
    /// Written, then no OK within the window, or the socket failed before
    /// it: the relay not answering.
    Unanswered(TestClientError),
}

impl SendError {
    pub fn into_inner(self) -> TestClientError {
        match self {
            Self::NotSent(e) | Self::Unanswered(e) => e,
        }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSent(e) => write!(f, "not sent: {e}"),
            Self::Unanswered(e) => write!(f, "no answer: {e}"),
        }
    }
}

/// Sends `event` and waits up to `ok_timeout` for its answer: its OK, or a
/// `rate-limited:` NOTICE, which the relay sends instead of an OK (so
/// waiting for the OK alone times out), told apart by [`classify_limit`]. Every other message
/// that arrives meanwhile (a subscription's events, other notices) is
/// returned, in order, for the caller to handle; none is dropped. A failure
/// says whether the event was written ([`SendError`]).
pub async fn send_tracked(
    client: &mut BuzzTestClient,
    event: &Event,
    ok_timeout: Duration,
) -> Result<(Publish, Vec<RelayMessage>), SendError> {
    let id = event.id.to_hex();
    client
        .send_raw(&json!(["EVENT", event]))
        .await
        .map_err(SendError::NotSent)?;
    let deadline = tokio::time::Instant::now() + ok_timeout;
    let mut others = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(SendError::Unanswered(TestClientError::Timeout));
        }
        match client
            .recv_event(remaining)
            .await
            .map_err(SendError::Unanswered)?
        {
            RelayMessage::Ok(ok) if ok.event_id == id => return Ok((Publish::Ok(ok), others)),
            RelayMessage::Notice { message } => {
                let answer = match classify_limit(&message) {
                    Some(Limit::Quota { retry_in }) => Publish::RateLimited { retry_in },
                    Some(Limit::Shed { text }) => Publish::Shed { text },
                    Some(Limit::Unknown { text }) => Publish::UnknownLimit { text },
                    None => {
                        others.push(RelayMessage::Notice { message });
                        continue;
                    }
                };
                return Ok((answer, others));
            }
            other => others.push(other),
        }
    }
}

/// The wait a `rate-limited:` text asks for (`retry in {n}s`), or
/// DEFAULT_RETRY when it names none; None when it isn't a rate limit.
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
    send_tracked(client, event, ok_timeout)
        .await
        .map(|(answer, _)| answer)
        .map_err(SendError::into_inner)
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
        /// A NOTICE with this text, no OK.
        Notice(&'static str),
        /// Nothing at all: the event is never answered.
        Silent,
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
                                Answer::Silent => continue,
                                Answer::RateLimit => serde_json::json!([
                                    "NOTICE",
                                    "rate-limited: quota exceeded; retry in 60s"
                                ]),
                                Answer::Notice(text) => serde_json::json!(["NOTICE", text]),
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

    /// A relay that takes every connection as [`relay_with`] does, accepts
    /// every EVENT, and logs each REQ as (subscription id, its filters). A
    /// `#p` subscription (an id ending `-p`) gets `p_events` before its
    /// EOSE; every other one only its EOSE.
    pub(crate) async fn req_logging_relay(p_events: Vec<nostr::Event>) -> (String, ReqLog) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let log: ReqLog = Default::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = log.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (seen, p_events) = (seen.clone(), p_events.clone());
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    let challenge = serde_json::json!(["AUTH", "test-challenge"]).to_string();
                    if ws.send(Message::Text(challenge.into())).await.is_err() {
                        return;
                    }
                    while let Some(Ok(msg)) = ws.next().await {
                        let Ok(text) = msg.into_text() else { continue };
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let mut replies = Vec::new();
                        match v[0].as_str() {
                            Some("AUTH") | Some("EVENT") => {
                                replies.push(serde_json::json!(["OK", v[1]["id"], true, ""]))
                            }
                            Some("REQ") => {
                                let sid = v[1].as_str().unwrap_or_default().to_string();
                                let filters: Vec<serde_json::Value> =
                                    v.as_array().map(|a| a[2..].to_vec()).unwrap_or_default();
                                seen.lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .push((sid.clone(), serde_json::Value::Array(filters)));
                                if sid.ends_with("-p") {
                                    for ev in &p_events {
                                        replies.push(serde_json::json!(["EVENT", sid, ev]));
                                    }
                                }
                                replies.push(serde_json::json!(["EOSE", sid]));
                            }
                            _ => {}
                        }
                        for r in replies {
                            if ws.send(Message::Text(r.to_string().into())).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        (format!("ws://{addr}"), log)
    }

    /// Each REQ a [`req_logging_relay`] got: its subscription id and filters.
    pub(crate) type ReqLog = std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>;

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
        assert!(
            matches!(err, SendError::Unanswered(TestClientError::Timeout)),
            "{err:?}"
        );
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

    /// Each text the pinned relay sends, and one it doesn't: the quota is
    /// apart, the two the relay sends when it is full or can't admit are
    /// shed, and any other `rate-limited:` text is unknown.
    #[test]
    fn each_rate_limit_text_is_told_apart() {
        let rows = [
            (
                "rate-limited: quota exceeded; retry in 7s",
                Some(Limit::Quota {
                    retry_in: Duration::from_secs(7),
                }),
            ),
            (
                "rate-limited: too many concurrent requests",
                Some(Limit::Shed {
                    text: "rate-limited: too many concurrent requests".into(),
                }),
            ),
            (
                "rate-limited: shared admission unavailable",
                Some(Limit::Shed {
                    text: "rate-limited: shared admission unavailable".into(),
                }),
            ),
            (
                "rate-limited: slow down",
                Some(Limit::Unknown {
                    text: "rate-limited: slow down".into(),
                }),
            ),
            ("auth-required: please authenticate", None),
            ("quota exceeded", None),
        ];
        for (text, want) in rows {
            assert_eq!(classify_limit(text), want, "{text}");
        }
    }

    #[test]
    fn other_notices_are_not_rate_limits() {
        assert_eq!(rate_limit_retry("auth-required: please authenticate"), None);
        assert_eq!(rate_limit_retry(""), None);
    }
}
