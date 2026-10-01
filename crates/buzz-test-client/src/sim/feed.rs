//! The home-feed poll: what Buzz Desktop sends for a human's home feed,
//! over the relay's HTTP bridge (`POST /query`) with NIP-98, as each
//! human's background load. One poll is the desktop's `get_feed`
//! (`desktop/src-tauri/src/commands/messages.rs`, `get_feed`), up to four
//! queries, one after another:
//!
//! 1. mentions: built at `messages.rs:72-89`, sent at `:104`;
//! 2. approvals: built at `messages.rs:94-98`, sent at `:111`;
//! 3. the edits of the mentions it got, only if it got some:
//!    `messages.rs:124-131`;
//! 4. the profiles of those mentions' authors, only if it got some:
//!    `messages.rs:132`, `messages/forum.rs:12-29`
//!    (`fetch_agent_owner_pubkeys`).
//!
//! The desktop sends a poll when it connects, every 30 s while connected
//! (`desktop/src/features/home/hooks.ts:22`, `refetchInterval`), never a
//! second while one is in flight, and again on a reconnect, at most once
//! every 15 s (`desktop/src/shared/api/useRelayAutoHeal.ts:16`,
//! `AUTO_HEAL_MIN_INTERVAL_MS`). Its HTTP client has no timeout; this one
//! times a query out at 30 s, and a query with no answer by then is the
//! relay's break, through the read counters, as is a refused one. The
//! relay's per-key quota is counted apart. The desktop turns a failed query
//! into an empty answer and goes on (`unwrap_or_default`), so a poll here
//! goes on too.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr::Keys;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};

use super::guard::{HttpClient, Target};
use super::reads::{self, Read, ReadError};
use super::roles::Band;
use super::stats::Stats;

/// The desktop polls every 30 s while connected.
pub const POLL_EVERY: Duration = Duration::from_secs(30);
/// A reconnect polls at once, at most once every 15 s.
pub const HEAL_MIN: Duration = Duration::from_secs(15);

/// The mentions query's kinds: `messages.rs:73-86`. 9, 40002, 1, 45001 and
/// 45003, then buzz-core's git kinds: `KIND_GIT_PULL_REQUEST` (1618),
/// `KIND_GIT_PR_UPDATE` (1619), `KIND_GIT_ISSUE` (1621) and the four
/// `KIND_GIT_STATUS_*` (1630 to 1633, `crates/buzz-core/src/kind.rs:611-623`).
pub const MENTION_KINDS: [u32; 12] = [
    9, 40002, 1, 45001, 45003, 1618, 1619, 1621, 1630, 1631, 1632, 1633,
];

/// The mentions query, `messages.rs:72-89`: `limit` is the caller's 50
/// (`desktop/src/features/home/hooks.ts:13-16`); no `since`.
pub fn mentions(me: &str) -> Read {
    Read {
        what: "feed-mentions",
        path: "/query",
        filters: json!([{"kinds": MENTION_KINDS, "#p": [me], "limit": 50}]),
    }
}

/// The approvals query, `messages.rs:94-98`.
pub fn approvals(me: &str) -> Read {
    Read {
        what: "feed-approvals",
        path: "/query",
        filters: json!([{"kinds": [46010, 46011, 46012], "#p": [me], "limit": 20}]),
    }
}

/// The mentions' edits, `messages.rs:124-131`: kind 40003 by `#e`.
pub fn edits(mention_ids: &[String]) -> Read {
    Read {
        what: "feed-edits",
        path: "/query",
        filters: json!([{"kinds": [40003], "#e": mention_ids}]),
    }
}

/// The mentions' authors' profiles, `messages/forum.rs:16-29`: kind 0 by
/// `authors`, each author once (the desktop dedupes in a set; this sorts).
pub fn profiles(authors: &[String]) -> Read {
    Read {
        what: "feed-profiles",
        path: "/query",
        filters: json!([{"kinds": [0], "authors": authors}]),
    }
}

/// Where a poll sends its queries, and as whom.
#[derive(Clone)]
pub struct PollTarget {
    pub http: HttpClient,
    pub url: Target,
    pub keys: Keys,
}

/// One poll: the four queries, in the desktop's order, each counted as it
/// ends. Returns the queries sent, by `what`.
pub async fn poll(to: &PollTarget, stats: &Stats) -> Vec<&'static str> {
    let me = to.keys.public_key().to_hex();
    let mut sent = Vec::new();
    let mentioned = match one(to, stats, &mentions(&me), &mut sent).await {
        Some(Value::Array(evs)) => evs,
        _ => Vec::new(),
    };
    one(to, stats, &approvals(&me), &mut sent).await;
    if !mentioned.is_empty() {
        let ids: Vec<String> = mentioned
            .iter()
            .filter_map(|e| e["id"].as_str().map(str::to_string))
            .collect();
        one(to, stats, &edits(&ids), &mut sent).await;
        let mut authors: Vec<String> = mentioned
            .iter()
            .filter_map(|e| e["pubkey"].as_str().map(str::to_string))
            .collect();
        authors.sort();
        authors.dedup();
        one(to, stats, &profiles(&authors), &mut sent).await;
    }
    sent
}

/// One query of a poll: its answer, or None when it failed, counted where
/// it failed.
async fn one(
    to: &PollTarget,
    stats: &Stats,
    r: &Read,
    sent: &mut Vec<&'static str>,
) -> Option<Value> {
    sent.push(r.what);
    match reads::query(&to.http, &to.url, &to.keys, None, r).await {
        Ok((_, v)) => Some(v),
        Err(ReadError::RateLimited) => {
            stats.record_read_rate_limited();
            None
        }
        Err(ReadError::UnknownLimit(text)) => {
            tracing::warn!("{} got an unknown limit: {text}", r.what);
            stats.record_read_limit_unknown(&text);
            None
        }
        Err(ReadError::Failed { at, err }) => {
            tracing::warn!("{} ({at:?}): {err:#}", r.what);
            stats.record_read_failed(at);
            None
        }
    }
}

/// What the poller is told by its identity: whether it is connected, and
/// each reconnect.
pub struct Link {
    pub connected: watch::Sender<bool>,
    pub healed: Notify,
}

impl Link {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connected: watch::channel(false).0,
            healed: Notify::new(),
        })
    }

    /// Connected for the first time (the warm-up's subscribe): no
    /// reconnect.
    pub fn up(&self) {
        self.connected.send_replace(true);
    }

    /// The connection is gone.
    pub fn down(&self) {
        self.connected.send_replace(false);
    }

    /// The connection is back after a drop (a reconnect).
    pub fn healed(&self) {
        self.connected.send_replace(true);
        self.healed.notify_one();
    }
}

/// The poll schedule, as the desktop runs it: a poll as soon as the identity
/// is connected, then one at each 30 s tick while it stays connected; a tick
/// that comes while a poll is in flight is skipped, never queued. A reconnect
/// polls at once, unless the last reconnect's poll was under 15 s ago, and
/// restarts the 30 s ticks from there (the desktop's interval starts again
/// when the connection does). Ends when the run stops. `run` makes one poll
/// and says which band it began in; each poll's time is recorded against
/// it.
pub async fn schedule<F, Fut>(
    link: Arc<Link>,
    mut band_rx: watch::Receiver<Band>,
    stats: Arc<Stats>,
    every: Duration,
    heal_min: Duration,
    mut run: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut connected = link.connected.subscribe();
    let mut last_heal: Option<tokio::time::Instant> = None;
    // The first poll goes out as soon as the identity is connected.
    let mut next: Option<tokio::time::Instant> = Some(tokio::time::Instant::now());
    loop {
        if *band_rx.borrow() == Band::Stop {
            return;
        }
        // Down, even if it went down while a poll was in flight: no ticks
        // until it's back, and they start again from the reconnect, whose
        // own notice decides its poll.
        if !*connected.borrow_and_update() {
            next = None;
        }
        let tick = async {
            match next {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        let healed = tokio::select! {
            _ = tick => false,
            _ = link.healed.notified() => true,
            _ = connected.changed() => continue,
            _ = band_rx.changed() => continue,
        };
        let now = tokio::time::Instant::now();
        if healed {
            if last_heal.is_some_and(|t| now.duration_since(t) < heal_min) {
                next = Some(now + every);
                continue;
            }
            last_heal = Some(now);
        }
        let band = *band_rx.borrow();
        if band == Band::Stop {
            return;
        }
        let started = Instant::now();
        run().await;
        stats.record_poll(
            band.sampled().then(|| band.as_str()),
            started.elapsed().as_secs_f64() * 1e3,
        );
        // The next tick on the 30 s grid from the last start; ticks that
        // passed while this poll was in flight are skipped.
        let mut at = now + every;
        let after = tokio::time::Instant::now();
        while at <= after {
            at += every;
        }
        next = Some(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::guard::testsrv::{self, Server};
    use crate::sim::guard::{http_client, Cidr, TargetGuard};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn target(base: &str) -> Target {
        TargetGuard::new(vec![Cidr::parse("127.0.0.0/8").expect("allow")], vec![])
            .expect("guard")
            .check_url(base, &["http"])
            .expect("target")
    }

    fn to(base: &str, timeout: Duration) -> PollTarget {
        PollTarget {
            http: http_client(timeout).expect("client"),
            url: target(base),
            keys: Keys::generate(),
        }
    }

    /// An HTTP server that logs each request's JSON body and answers it
    /// with `answer(body)`: a status and a JSON body.
    async fn logging_server(
        answer: fn(&Value) -> (u16, String),
    ) -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let log: Arc<Mutex<Vec<Value>>> = Default::default();
        let seen = log.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        // One request: headers, then Content-Length bytes.
                        let head_end = loop {
                            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break i + 4;
                            }
                            let mut chunk = [0u8; 4096];
                            match tcp.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        while buf.len() < head_end + len {
                            let mut chunk = [0u8; 4096];
                            match tcp.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let body: Value = serde_json::from_slice(&buf[head_end..head_end + len])
                            .unwrap_or(Value::Null);
                        buf.drain(..head_end + len);
                        let (code, reply) = answer(&body);
                        seen.lock().expect("log").push(body);
                        let resp = format!(
                            "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
                            reply.len()
                        );
                        if tcp.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (format!("http://{addr}"), log)
    }

    /// Each query's filter is the desktop's own, exactly.
    #[test]
    fn the_queries_are_the_desktops() {
        let me = "aa".repeat(32);
        assert_eq!(
            mentions(&me).filters,
            json!([{"kinds": [9, 40002, 1, 45001, 45003, 1618, 1619, 1621, 1630, 1631, 1632, 1633],
                    "#p": [me], "limit": 50}])
        );
        assert!(mentions(&me).filters[0].get("since").is_none());
        assert_eq!(
            approvals(&me).filters,
            json!([{"kinds": [46010, 46011, 46012], "#p": [me], "limit": 20}])
        );
        let ids = vec!["e1".to_string(), "e2".to_string()];
        assert_eq!(
            edits(&ids).filters,
            json!([{"kinds": [40003], "#e": ["e1", "e2"]}])
        );
        let authors = vec!["p1".to_string()];
        assert_eq!(
            profiles(&authors).filters,
            json!([{"kinds": [0], "authors": ["p1"]}])
        );
        for r in [
            mentions(&me),
            approvals(&me),
            edits(&ids),
            profiles(&authors),
        ] {
            assert_eq!(r.path, "/query", "{}", r.what);
        }
    }

    fn two_mentions(body: &Value) -> (u16, String) {
        if body[0]["#p"].is_array() && body[0]["limit"] == 50 {
            let evs = json!([{"id": "e2", "pubkey": "pb"}, {"id": "e1", "pubkey": "pa"},
                             {"id": "e0", "pubkey": "pb"}]);
            (200, evs.to_string())
        } else {
            (200, "[]".into())
        }
    }

    fn none(_: &Value) -> (u16, String) {
        (200, "[]".into())
    }

    /// The desktop's order: mentions, approvals, then the mentions' edits
    /// and their authors' profiles (each author once), only when mentions
    /// came back.
    #[tokio::test]
    async fn a_poll_sends_the_desktops_queries_in_its_order() {
        let (url, log) = logging_server(two_mentions).await;
        let t = to(&url, Duration::from_secs(5));
        let me = t.keys.public_key().to_hex();
        let stats = Stats::new();
        let sent = poll(&t, &stats).await;
        assert_eq!(
            sent,
            [
                "feed-mentions",
                "feed-approvals",
                "feed-edits",
                "feed-profiles"
            ]
        );
        let ids = vec!["e2".to_string(), "e1".to_string(), "e0".to_string()];
        let authors = vec!["pa".to_string(), "pb".to_string()];
        assert_eq!(
            *log.lock().expect("log"),
            vec![
                mentions(&me).filters,
                approvals(&me).filters,
                edits(&ids).filters,
                profiles(&authors).filters
            ]
        );
        let (url, log) = logging_server(none).await;
        let t = to(&url, Duration::from_secs(5));
        let me = t.keys.public_key().to_hex();
        assert_eq!(poll(&t, &stats).await, ["feed-mentions", "feed-approvals"]);
        assert_eq!(
            *log.lock().expect("log"),
            vec![mentions(&me).filters, approvals(&me).filters]
        );
        let live = stats.live(1);
        assert_eq!(
            (
                live.read_refused,
                live.read_unanswered,
                live.read_rate_limited
            ),
            (0, 0, 0)
        );
    }

    /// A refused query and one with no answer are the relay's, through the
    /// read counters; the quota is apart. The poll goes on past each, as
    /// the desktop's does.
    #[tokio::test]
    async fn a_polls_failures_are_counted_where_they_failed() {
        let refused = Server::start("127.0.0.1:0", testsrv::status(503, r#"{"error":"down"}"#));
        let quota = Server::start(
            "127.0.0.1:0",
            testsrv::status(
                429,
                r#"{"error":"rate-limited: quota exceeded; retry in 5s"}"#,
            ),
        );
        let silent = Server::start_after(
            "127.0.0.1:0",
            testsrv::status(200, "[]"),
            Duration::from_secs(5),
        );
        // (name, server, (refused, unanswered, rate_limited))
        let rows: [(&str, &Server, (u64, u64, u64)); 3] = [
            ("refused", &refused, (2, 0, 0)),
            ("no answer", &silent, (0, 2, 0)),
            ("quota", &quota, (0, 0, 2)),
        ];
        for (name, srv, want) in rows {
            let stats = Stats::new();
            let t = to(&srv.http(), Duration::from_millis(500));
            assert_eq!(
                poll(&t, &stats).await,
                ["feed-mentions", "feed-approvals"],
                "{name}"
            );
            let live = stats.live(1);
            assert_eq!(
                (
                    live.read_refused,
                    live.read_unanswered,
                    live.read_rate_limited
                ),
                want,
                "{name}"
            );
            assert_eq!(live.read_client_failed, 0, "{name}");
        }
    }

    /// A schedule whose polls take `took(n)` each, n from 0; its start
    /// times, in seconds from the start, and the most in flight at once.
    struct Recorder {
        starts: Arc<Mutex<Vec<u64>>>,
        in_flight: Arc<std::sync::atomic::AtomicU32>,
        most: Arc<std::sync::atomic::AtomicU32>,
    }

    fn recorder(
        took: fn(usize) -> u64,
    ) -> (
        Recorder,
        impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    ) {
        use std::sync::atomic::Ordering::SeqCst;
        let t0 = tokio::time::Instant::now();
        let r = Recorder {
            starts: Default::default(),
            in_flight: Default::default(),
            most: Default::default(),
        };
        let (starts, in_flight, most) = (r.starts.clone(), r.in_flight.clone(), r.most.clone());
        let run = move || {
            let (starts, in_flight, most) = (starts.clone(), in_flight.clone(), most.clone());
            Box::pin(async move {
                let n = {
                    let mut s = starts.lock().expect("starts");
                    s.push(t0.elapsed().as_secs());
                    s.len() - 1
                };
                let now = in_flight.fetch_add(1, SeqCst) + 1;
                most.fetch_max(now, SeqCst);
                tokio::time::sleep(Duration::from_secs(took(n))).await;
                in_flight.fetch_sub(1, SeqCst);
            }) as std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
        };
        (r, run)
    }

    /// At connect, then on the 30 s ticks; a tick that comes while a poll is
    /// in flight is skipped, never queued, so two polls never overlap. The
    /// stop ends it.
    #[tokio::test(start_paused = true)]
    async fn the_poll_runs_every_30_s_and_never_twice_at_once() {
        use std::sync::atomic::Ordering::SeqCst;
        // The first poll takes 45 s: the 30 s tick is skipped.
        fn took(n: usize) -> u64 {
            if n == 0 {
                45
            } else {
                1
            }
        }
        let (rec, run) = recorder(took);
        let link = Link::new();
        let (band_tx, band_rx) = watch::channel(Band::Warmup);
        let stats = Arc::new(Stats::new());
        link.up();
        let task = tokio::spawn(schedule(
            link.clone(),
            band_rx,
            stats.clone(),
            POLL_EVERY,
            HEAL_MIN,
            run,
        ));
        tokio::time::sleep(Duration::from_secs(125)).await;
        band_tx.send_replace(Band::Stop);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the stop ended it")
            .expect("join");
        assert_eq!(*rec.starts.lock().expect("starts"), [0, 60, 90, 120]);
        assert_eq!(rec.most.load(SeqCst), 1, "two polls at once");
        assert_eq!(stats.live(1).polls, 4);
    }

    /// No poll while disconnected. A reconnect polls at once, unless the
    /// last reconnect's poll was under 15 s ago, and the 30 s ticks start
    /// again from the reconnect.
    #[tokio::test(start_paused = true)]
    async fn a_reconnect_polls_at_most_once_every_15_s() {
        // The first poll is still in flight when the connection drops.
        fn took(n: usize) -> u64 {
            if n == 0 {
                20
            } else {
                1
            }
        }
        let (rec, run) = recorder(took);
        let link = Link::new();
        let (band_tx, band_rx) = watch::channel(Band::Steady);
        link.up();
        let task = tokio::spawn(schedule(
            link.clone(),
            band_rx,
            Arc::new(Stats::new()),
            POLL_EVERY,
            HEAL_MIN,
            run,
        ));
        let at =
            |s: u64| tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_secs(s));
        at(10).await; // t = 10: dropped, the first poll in flight to 20
        link.down();
        at(90).await; // t = 100: back, polls at once
        link.healed();
        at(5).await; // t = 105: dropped and back again, under 15 s
        link.down();
        link.healed();
        at(45).await; // t = 150
        band_tx.send_replace(Band::Stop);
        task.await.expect("join");
        // 0 at connect; nothing while down, not even the tick due when the
        // first poll ended (30, 60, 90); 100 on the reconnect; none at 105;
        // the ticks from 105: 135.
        assert_eq!(*rec.starts.lock().expect("starts"), [0, 100, 135]);
    }
}
