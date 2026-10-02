//! Client-side counters, percentiles, and the summary JSON schema.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Percentiles {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

pub fn percentiles(mut xs: Vec<f64>) -> Percentiles {
    if xs.is_empty() {
        return Percentiles::default();
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = |p: f64| {
        let idx = ((xs.len() as f64 - 1.0) * p).round() as usize;
        xs[idx.min(xs.len() - 1)]
    };
    Percentiles {
        p50: pct(0.50),
        p95: pct(0.95),
        p99: pct(0.99),
        max: *xs.last().unwrap(),
    }
}

/// The ack-time histogram's upper bounds, in ms. The service level is "95%
/// of events acknowledged within 500 ms", so 500 is a bound: the share
/// within it is exact, not interpolated.
pub const ACK_MS_BOUNDS: [u64; 10] = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
/// The home-feed poll's time bounds, in ms, for live.json's `poll_ms_le`:
/// a poll is up to four queries, each up to 30 s.
pub const POLL_MS_BOUNDS: [u64; 10] = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 120000];

#[derive(Clone, Debug, Default, Serialize)]
pub struct BandClient {
    pub start_unix: u64,
    pub end_unix: u64,
    pub sent: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Sends the relay's per-key rate limiter turned away (a NOTICE, no OK):
    /// counted apart from `rejected`, neither a break nor the generator's
    /// error.
    pub rate_limited: u64,
    /// Sends written that got no OK in time, or whose socket failed before
    /// it: the relay not answering.
    pub unanswered: u64,
    /// Sends that failed before anything was written: the generator's own.
    pub failed: u64,
    /// Sends the relay shed, full or unable to admit (see
    /// `admission::Limit::Shed`): a relay break.
    pub shed: u64,
    /// Sends answered with a `rate-limited:` text the pinned relay doesn't
    /// send: the run voids.
    pub limit_unknown: u64,
    pub received: u64,
    /// Sends in this band by event kind; acceptance checks the floor with it.
    pub sent_by_kind: BTreeMap<String, u64>,
    pub ok_ms: Percentiles,
    pub fanout_ms: Percentiles,
    /// Agent per-turn reads that the relay answered, and how long each took.
    pub reads: u64,
    pub read_ms: Percentiles,
    /// Humans' home-feed polls begun in this band, and how long each took,
    /// whole (its two to four queries).
    pub polls: u64,
    pub poll_ms: Percentiles,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storm_backfill_ms: Option<Percentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storm_events_returned: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MediaStats {
    pub uploads: u64,
    pub bytes: u64,
    pub put_ms: Percentiles,
    pub rejected: u64,
}

/// Agent per-turn reads over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReadStats {
    pub reads: u64,
    pub ms: Percentiles,
    /// Reads by what they read (thread, profiles, memory, ...).
    pub by_what: BTreeMap<String, u64>,
    /// Turned away by the relay's per-key HTTP rate limit: apart.
    pub rate_limited: u64,
    /// Every failure, wherever it failed (see `live.json` for where).
    pub failed: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GitStats {
    pub pushes: u64,
    pub bytes: u64,
    pub push_ms: Percentiles,
    pub failed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub profile: String,
    pub seed: u64,
    pub relay_url: String,
    pub identities: BTreeMap<String, u64>,
    pub bands: BTreeMap<String, BandClient>,
    pub sent_by_kind: BTreeMap<String, u64>,
    pub media: MediaStats,
    pub git: GitStats,
    pub reads: ReadStats,
    /// Humans' home-feed polls in any band, never-mentioned humans apart
    /// from the rest: a never-mentioned human's poll walks every event.
    pub polls: PollStats,
    pub join_backfill_ms: Percentiles,
    pub gaps_detected: u64,
    pub lost_after_backfill: u64,
    pub rejects_by_message: BTreeMap<String, u64>,
    pub blink: Option<serde_json::Value>,
}

/// Home-feed polls and their whole times, by whether the human polling is
/// ever mentioned (`mentions.rs`'s tail).
#[derive(Clone, Debug, Default, Serialize)]
pub struct PollStats {
    pub never_mentioned: u64,
    pub never_mentioned_ms: Percentiles,
    pub mentioned: u64,
    pub mentioned_ms: Percentiles,
}

#[derive(Default)]
struct BandAcc {
    start_unix: u64,
    sent: u64,
    accepted: u64,
    rejected: u64,
    rate_limited: u64,
    unanswered: u64,
    failed: u64,
    shed: u64,
    limit_unknown: u64,
    received: u64,
    sent_by_kind: BTreeMap<String, u64>,
    ok_ms: Vec<f64>,
    fanout_ms: Vec<f64>,
    reads: u64,
    read_ms: Vec<f64>,
    polls: u64,
    poll_ms: Vec<f64>,
    storm_backfill_ms: Vec<f64>,
    storm_events_returned: u64,
}

#[derive(Default)]
struct Inner {
    sent_by_kind: BTreeMap<String, u64>,
    rejects_by_message: BTreeMap<String, u64>,
    bands: HashMap<String, BandAcc>,
    join_backfill_ms: Vec<f64>,
    media_uploads: u64,
    media_bytes: u64,
    media_rejected: u64,
    media_failed_by: BTreeMap<MediaFailure, u64>,
    media_put_ms: Vec<f64>,
    git_pushes: u64,
    git_bytes: u64,
    git_failed: u64,
    git_failed_by: BTreeMap<GitFailure, u64>,
    git_push_ms: Vec<f64>,
    /// Sends the relay never answered, in any band.
    send_unanswered: u64,
    /// Sends the relay shed, in any band.
    relay_shed: u64,
    /// Unknown `rate-limited:` texts, sends and reads, by text.
    limit_unknown: BTreeMap<String, u64>,
    /// Identities whose task ended on its own, by name: why.
    identities_ended: BTreeMap<String, String>,
    /// Home-feed polls, in any band, by time: one count per bound in
    /// POLL_MS_BOUNDS and one past the last.
    polls: u64,
    poll_ms_buckets: [u64; POLL_MS_BOUNDS.len() + 1],
    /// Every poll's time, by whether its human is never mentioned.
    poll_ms_tail: Vec<f64>,
    poll_ms_mentioned: Vec<f64>,
    /// Accepted sends by ack time, one count per bound in ACK_MS_BOUNDS
    /// and one past the last; cumulative in live.json.
    ack_ms_buckets: [u64; ACK_MS_BOUNDS.len() + 1],
    /// Identities connected and subscribed: the population, then each ramp
    /// joiner.
    joined: u64,
    reads: u64,
    read_ms: Vec<f64>,
    reads_by_what: BTreeMap<String, u64>,
    reads_rate_limited: u64,
    read_failed_by: BTreeMap<ReadFailure, u64>,
    gaps_detected: u64,
    lost_after_backfill: u64,
    blink_closes: Vec<u64>,
    blink: Option<serde_json::Value>,
    /// The generator's own failures, by kind, as opposed to the relay's
    /// rejections (which `record_send` counts as `rejected`).
    client_errors: BTreeMap<String, u64>,
}

/// Where a media upload failed. Only `Client` is the generator's own
/// failure; the other two are the relay's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaFailure {
    /// Before the request went out: encoding the image or signing the auth.
    Client,
    /// The relay answered, but not with a 2xx.
    Refused,
    /// No answer: a transport error or a timeout.
    Unanswered,
}

/// Where an agent's read failed. Only `Client` is the generator's own
/// failure; the other two are the relay's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadFailure {
    /// Before the request went out: building or signing it.
    Client,
    /// The relay answered, but not with a 2xx and JSON.
    Refused,
    /// No answer: a transport error or a timeout.
    Unanswered,
}

/// Where a git push failed. Only `Local` is the generator's own failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GitFailure {
    /// Writing the blob, `git add`, `commit` or `branch`.
    Local,
    /// The push to the relay: refused, failed, or past git's timeout.
    Push,
}

/// The live counters `tenant_sim` rewrites into `<out-dir>/live.json` while
/// it runs, so a sampler can watch the generator's own health during a band
/// instead of only after the run. Counts are totals since the start.
#[derive(Clone, Debug, Serialize)]
pub struct Live {
    pub t_unix: u64,
    /// Sends, accepted and rejected by the relay, and events received,
    /// summed over the sampled bands.
    pub sent: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Sends the relay's per-key rate limiter turned away, apart from
    /// `rejected`.
    pub rate_limited: u64,
    pub received: u64,
    /// The generator's own failures, by kind: `send_failed` (no answer to a
    /// send), `recv_error`, `reconnect_failed`, `backfill_failed`, and
    /// `connection_dropped` (the connection closed under it).
    pub client_errors: BTreeMap<String, u64>,
    /// Media uploads and git pushes that failed, by where they failed (see
    /// [`MediaFailure`] and [`GitFailure`]): only `media_client_failed` and
    /// `git_local_failed` are the generator's own.
    pub media_client_failed: u64,
    pub media_refused: u64,
    pub media_unanswered: u64,
    pub git_local_failed: u64,
    pub git_push_failed: u64,
    /// Agent per-turn reads that failed, by where (see [`ReadFailure`]):
    /// only `read_client_failed` is the generator's own. Reads the relay's
    /// per-key rate limit turned away are apart, in `read_rate_limited`.
    pub read_client_failed: u64,
    pub read_refused: u64,
    pub read_unanswered: u64,
    pub read_rate_limited: u64,
    /// Sends written that got no OK in time, or whose socket failed before
    /// it, in any band: the relay not answering (a relay break). A send
    /// that failed before anything was written is `send_failed` in
    /// `client_errors`, the generator's own.
    pub send_unanswered: u64,
    /// Sends the relay shed in any band, full (its relay-wide handler limit)
    /// or unable to reach its admission store: a relay break. The relay's
    /// per-key quota is apart, in `rate_limited`.
    pub relay_shed: u64,
    /// `rate-limited:` texts the pinned relay doesn't send, sends and
    /// reads, by text: any voids the run (the relay's pin moved).
    pub limit_unknown: BTreeMap<String, u64>,
    /// Identities whose task ended on its own, not on a stop or a lease,
    /// by name: why. Any voids the run: a lost identity under-loads it.
    pub identities_ended: BTreeMap<String, String>,
    /// Humans' home-feed polls, in any band, and their times, cumulative
    /// like `ack_ms_le`: `"1000": n` is every poll done within 1 s. A
    /// poll's failed queries are in the read failures.
    pub polls: u64,
    pub poll_ms_le: BTreeMap<String, u64>,
    /// Accepted sends (in sampled bands) acknowledged within each bound,
    /// in ms, cumulative like a Prometheus histogram: `"500": n` is every
    /// ack within 500 ms; `"+Inf"` is every ack.
    pub ack_ms_le: BTreeMap<String, u64>,
    /// Events found lost after a recheck, at a band's end or a ramp step.
    pub lost: u64,
    /// Identities connected and subscribed so far.
    pub joined: u64,
    /// On the last write only: why the run ended (`stop`, `lease` or
    /// `eof`). A file that has it is final, never stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
}

/// Writes `live` to `path` whole: a temp file beside it, then a rename, so a
/// reader never sees half a file.
pub fn write_live(path: &Path, live: &Live) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(live).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, path)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Rewrites `path` from `stats` every `every`, as a task on the runtime. A
/// runtime too busy to run it leaves the file stale, and the sampler voids
/// the run on that, so nothing slow may block a runtime worker (see
/// `git::push_blob_async`). A failed write is logged and the next one tried.
pub fn spawn_live_writer(
    stats: Arc<Stats>,
    path: PathBuf,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            if let Err(e) = write_live(&path, &stats.live(unix_now())) {
                tracing::warn!("live counters {}: {e}", path.display());
            }
        }
    })
}

/// A histogram's buckets as cumulative counts by bound, `"+Inf"` last.
fn cumulative(buckets: &[u64], bounds: &[u64]) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut total = 0;
    for (i, n) in buckets.iter().enumerate() {
        total += n;
        let key = bounds
            .get(i)
            .map_or_else(|| "+Inf".to_string(), |b| b.to_string());
        out.insert(key, total);
    }
    out
}

fn count<K: Ord>(m: &BTreeMap<K, u64>, k: K) -> u64 {
    m.get(&k).copied().unwrap_or(0)
}

pub struct Stats {
    inner: Mutex<Inner>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.inner.lock().expect("stats lock"))
    }

    pub fn band_start(&self, band: &str, unix: u64) {
        self.with(|s| {
            s.bands.entry(band.to_string()).or_default().start_unix = unix;
        });
    }

    pub fn record_send(&self, band: &str, kind: u16, accepted: bool, message: &str, ok_ms: f64) {
        self.with(|s| {
            *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            let b = s.bands.entry(band.to_string()).or_default();
            b.sent += 1;
            *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            if accepted {
                b.accepted += 1;
                b.ok_ms.push(ok_ms);
                let i = ACK_MS_BOUNDS
                    .iter()
                    .position(|&le| ok_ms <= le as f64)
                    .unwrap_or(ACK_MS_BOUNDS.len());
                s.ack_ms_buckets[i] += 1;
            } else {
                b.rejected += 1;
                *s.rejects_by_message.entry(message.to_string()).or_default() += 1;
            }
        });
    }

    /// A send written that got no answer (`band`: a sampled band's name).
    pub fn record_send_unanswered(&self, band: Option<&str>, kind: u16) {
        self.with(|s| {
            s.send_unanswered += 1;
            if let Some(band) = band {
                *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
                let b = s.bands.entry(band.to_string()).or_default();
                b.sent += 1;
                b.unanswered += 1;
                *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            }
        });
    }

    /// A send that failed before anything was written: the generator's own
    /// error (`send_failed` in client_errors).
    pub fn record_send_failed(&self, band: Option<&str>, kind: u16) {
        self.with(|s| {
            *s.client_errors
                .entry("send_failed".to_string())
                .or_default() += 1;
            if let Some(band) = band {
                *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
                let b = s.bands.entry(band.to_string()).or_default();
                b.sent += 1;
                b.failed += 1;
                *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            }
        });
    }

    /// A send the relay shed (`band`: a sampled band's name).
    pub fn record_send_shed(&self, band: Option<&str>, kind: u16) {
        self.with(|s| {
            s.relay_shed += 1;
            if let Some(band) = band {
                *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
                let b = s.bands.entry(band.to_string()).or_default();
                b.sent += 1;
                b.shed += 1;
                *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            }
        });
    }

    /// A send answered with an unknown `rate-limited:` text.
    pub fn record_limit_unknown(&self, band: Option<&str>, kind: u16, text: &str) {
        self.with(|s| {
            *s.limit_unknown.entry(text.to_string()).or_default() += 1;
            if let Some(band) = band {
                *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
                let b = s.bands.entry(band.to_string()).or_default();
                b.sent += 1;
                b.limit_unknown += 1;
                *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            }
        });
    }

    /// A read answered with an unknown `rate-limited:` text.
    pub fn record_read_limit_unknown(&self, text: &str) {
        self.with(|s| *s.limit_unknown.entry(text.to_string()).or_default() += 1);
    }

    /// An identity's task ended on its own (not on a stop or a lease): the
    /// first reason kept per identity.
    pub fn record_identity_ended(&self, name: &str, why: &str) {
        self.with(|s| {
            s.identities_ended
                .entry(name.to_string())
                .or_insert_with(|| why.to_string());
        });
    }

    /// An identity connected and subscribed.
    pub fn record_joined(&self) {
        self.with(|s| s.joined += 1);
    }

    /// A send the relay's per-key rate limiter turned away.
    pub fn record_rate_limited(&self, band: &str, kind: u16) {
        self.with(|s| {
            *s.sent_by_kind.entry(kind.to_string()).or_default() += 1;
            let b = s.bands.entry(band.to_string()).or_default();
            b.sent += 1;
            b.rate_limited += 1;
            *b.sent_by_kind.entry(kind.to_string()).or_default() += 1;
        });
    }

    pub fn record_recv(&self, band: &str, fanout_ms: Option<f64>) {
        self.with(|s| {
            let b = s.bands.entry(band.to_string()).or_default();
            b.received += 1;
            if let Some(ms) = fanout_ms {
                b.fanout_ms.push(ms);
            }
        });
    }

    pub fn record_join_backfill(&self, ms: f64) {
        self.with(|s| s.join_backfill_ms.push(ms));
    }

    pub fn record_storm_backfill(&self, band: &str, ms: f64, events: u64) {
        self.with(|s| {
            let b = s.bands.entry(band.to_string()).or_default();
            b.storm_backfill_ms.push(ms);
            b.storm_events_returned += events;
        });
    }

    pub fn record_gap(&self, n: u64) {
        self.with(|s| s.gaps_detected += n);
    }

    pub fn record_lost(&self, n: u64) {
        self.with(|s| s.lost_after_backfill += n);
    }

    pub fn record_media(&self, bytes: u64, put_ms: f64) {
        self.with(|s| {
            s.media_uploads += 1;
            s.media_bytes += bytes;
            s.media_put_ms.push(put_ms);
        });
    }

    /// A failed upload. summary.json's media `rejected` still counts every
    /// failure, wherever it failed; live.json splits them.
    pub fn record_media_failed(&self, why: MediaFailure) {
        self.with(|s| {
            s.media_rejected += 1;
            *s.media_failed_by.entry(why).or_default() += 1;
        });
    }

    /// An agent's read the relay answered, in `band` (unsampled bands count
    /// in the run's totals only).
    pub fn record_read(&self, band: Option<&str>, what: &str, ms: f64) {
        self.with(|s| {
            s.reads += 1;
            s.read_ms.push(ms);
            *s.reads_by_what.entry(what.to_string()).or_default() += 1;
            if let Some(band) = band {
                let b = s.bands.entry(band.to_string()).or_default();
                b.reads += 1;
                b.read_ms.push(ms);
            }
        });
    }

    pub fn record_read_failed(&self, why: ReadFailure) {
        self.with(|s| *s.read_failed_by.entry(why).or_default() += 1);
    }

    pub fn record_read_rate_limited(&self) {
        self.with(|s| s.reads_rate_limited += 1);
    }

    /// A home-feed poll that took `ms`, whole, begun in `band` (a sampled
    /// band's name; others count in the totals only), by a human who is
    /// never mentioned (`tail`) or not.
    pub fn record_poll(&self, band: Option<&str>, ms: f64, tail: bool) {
        self.with(|s| {
            s.polls += 1;
            if tail {
                s.poll_ms_tail.push(ms);
            } else {
                s.poll_ms_mentioned.push(ms);
            }
            let i = POLL_MS_BOUNDS
                .iter()
                .position(|&le| ms <= le as f64)
                .unwrap_or(POLL_MS_BOUNDS.len());
            s.poll_ms_buckets[i] += 1;
            if let Some(band) = band {
                let b = s.bands.entry(band.to_string()).or_default();
                b.polls += 1;
                b.poll_ms.push(ms);
            }
        });
    }

    pub fn record_git(&self, bytes: u64, push_ms: f64) {
        self.with(|s| {
            s.git_pushes += 1;
            s.git_bytes += bytes;
            s.git_push_ms.push(push_ms);
        });
    }

    /// A failed push. summary.json's git `failed` still counts every
    /// failure, wherever it failed; live.json splits them.
    pub fn record_git_failed(&self, why: GitFailure) {
        self.with(|s| {
            s.git_failed += 1;
            *s.git_failed_by.entry(why).or_default() += 1;
        });
    }

    pub fn set_blink(&self, value: serde_json::Value) {
        self.with(|s| s.blink = Some(value));
    }

    pub fn record_blink_closes(&self, closes: &[u64]) {
        self.with(|s| s.blink_closes.extend_from_slice(closes));
    }

    pub fn lost_after_backfill(&self) -> u64 {
        self.with(|s| s.lost_after_backfill)
    }

    /// Counts one of the generator's own failures (see `Live`).
    pub fn record_client_error(&self, what: &str) {
        self.with(|s| *s.client_errors.entry(what.to_string()).or_default() += 1);
    }

    /// The live counters, stamped `t_unix`.
    pub fn live(&self, t_unix: u64) -> Live {
        self.with(|s| {
            let (mut sent, mut accepted, mut rejected, mut rate_limited, mut received) =
                (0, 0, 0, 0, 0);
            for b in s.bands.values() {
                sent += b.sent;
                accepted += b.accepted;
                rejected += b.rejected;
                rate_limited += b.rate_limited;
                received += b.received;
            }
            Live {
                t_unix,
                sent,
                accepted,
                rejected,
                rate_limited,
                received,
                client_errors: s.client_errors.clone(),
                media_client_failed: count(&s.media_failed_by, MediaFailure::Client),
                media_refused: count(&s.media_failed_by, MediaFailure::Refused),
                media_unanswered: count(&s.media_failed_by, MediaFailure::Unanswered),
                git_local_failed: count(&s.git_failed_by, GitFailure::Local),
                git_push_failed: count(&s.git_failed_by, GitFailure::Push),
                read_client_failed: count(&s.read_failed_by, ReadFailure::Client),
                read_refused: count(&s.read_failed_by, ReadFailure::Refused),
                read_unanswered: count(&s.read_failed_by, ReadFailure::Unanswered),
                read_rate_limited: s.reads_rate_limited,
                send_unanswered: s.send_unanswered,
                relay_shed: s.relay_shed,
                limit_unknown: s.limit_unknown.clone(),
                identities_ended: s.identities_ended.clone(),
                polls: s.polls,
                poll_ms_le: cumulative(&s.poll_ms_buckets, &POLL_MS_BOUNDS),
                ack_ms_le: {
                    let mut out = BTreeMap::new();
                    let mut total = 0;
                    for (i, n) in s.ack_ms_buckets.iter().enumerate() {
                        total += n;
                        let key = ACK_MS_BOUNDS
                            .get(i)
                            .map_or_else(|| "+Inf".to_string(), |b| b.to_string());
                        out.insert(key, total);
                    }
                    out
                },
                lost: s.lost_after_backfill,
                joined: s.joined,
                ended: None,
            }
        })
    }

    pub fn summarize(
        &self,
        profile: &str,
        seed: u64,
        relay_url: &str,
        humans: u64,
        agents: u64,
        band_ends: &HashMap<String, u64>,
    ) -> Summary {
        self.with(|s| {
            let mut bands = BTreeMap::new();
            for (name, acc) in &s.bands {
                let mut client = BandClient {
                    start_unix: acc.start_unix,
                    end_unix: band_ends.get(name).copied().unwrap_or(0),
                    sent: acc.sent,
                    accepted: acc.accepted,
                    rejected: acc.rejected,
                    rate_limited: acc.rate_limited,
                    unanswered: acc.unanswered,
                    failed: acc.failed,
                    shed: acc.shed,
                    limit_unknown: acc.limit_unknown,
                    received: acc.received,
                    sent_by_kind: acc.sent_by_kind.clone(),
                    ok_ms: percentiles(acc.ok_ms.clone()),
                    fanout_ms: percentiles(acc.fanout_ms.clone()),
                    reads: acc.reads,
                    read_ms: percentiles(acc.read_ms.clone()),
                    polls: acc.polls,
                    poll_ms: percentiles(acc.poll_ms.clone()),
                    storm_backfill_ms: None,
                    storm_events_returned: None,
                };
                if name == "peak" && !acc.storm_backfill_ms.is_empty() {
                    client.storm_backfill_ms = Some(percentiles(acc.storm_backfill_ms.clone()));
                    client.storm_events_returned = Some(acc.storm_events_returned);
                }
                bands.insert(name.clone(), client);
            }
            Summary {
                profile: profile.to_string(),
                seed,
                relay_url: relay_url.to_string(),
                identities: BTreeMap::from([
                    ("humans".into(), humans),
                    ("agents".into(), agents),
                ]),
                bands,
                sent_by_kind: s.sent_by_kind.clone(),
                media: MediaStats {
                    uploads: s.media_uploads,
                    bytes: s.media_bytes,
                    put_ms: percentiles(s.media_put_ms.clone()),
                    rejected: s.media_rejected,
                },
                git: GitStats {
                    pushes: s.git_pushes,
                    bytes: s.git_bytes,
                    push_ms: percentiles(s.git_push_ms.clone()),
                    failed: s.git_failed,
                },
                polls: PollStats {
                    never_mentioned: s.poll_ms_tail.len() as u64,
                    never_mentioned_ms: percentiles(s.poll_ms_tail.clone()),
                    mentioned: s.poll_ms_mentioned.len() as u64,
                    mentioned_ms: percentiles(s.poll_ms_mentioned.clone()),
                },
                reads: ReadStats {
                    reads: s.reads,
                    ms: percentiles(s.read_ms.clone()),
                    by_what: s.reads_by_what.clone(),
                    rate_limited: s.reads_rate_limited,
                    failed: s.read_failed_by.values().sum(),
                },
                join_backfill_ms: percentiles(s.join_backfill_ms.clone()),
                gaps_detected: s.gaps_detected,
                lost_after_backfill: s.lost_after_backfill,
                rejects_by_message: s.rejects_by_message.clone(),
                blink: s.blink.clone().or_else(|| {
                    if s.blink_closes.is_empty() {
                        None
                    } else {
                        Some(serde_json::json!({
                            "closes": s.blink_closes.len(),
                            "first_unix": s.blink_closes.iter().min(),
                            "last_unix": s.blink_closes.iter().max(),
                            "note": "client-side reconnect timestamps only; rollout is not implemented in this PR",
                        }))
                    }
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    /// The fields live.json holds, typed out here and in the sampler's row
    /// test_the_loop_reads_what_tenant_sim_writes: the loop requires every
    /// total, so a field renamed on one side fails both.
    #[test]
    fn live_json_holds_the_fields_the_sampler_reads() {
        let v = serde_json::to_value(super::Stats::new().live(1)).expect("json");
        let mut keys: Vec<&str> = v
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut want = vec![
            "t_unix",
            "sent",
            "accepted",
            "rejected",
            "rate_limited",
            "received",
            "client_errors",
            "media_client_failed",
            "media_refused",
            "media_unanswered",
            "git_local_failed",
            "git_push_failed",
            "read_client_failed",
            "read_refused",
            "read_unanswered",
            "read_rate_limited",
            "send_unanswered",
            "relay_shed",
            "limit_unknown",
            "identities_ended",
            "polls",
            "poll_ms_le",
            "ack_ms_le",
            "lost",
            "joined",
        ];
        want.sort_unstable();
        assert_eq!(keys, want, "\"ended\" is only on the last write");
    }

    /// The ack histogram is cumulative, and 500 ms is one of its bounds.
    #[test]
    fn the_ack_histogram() {
        let s = super::Stats::new();
        for ms in [3.0, 500.0, 500.5, 20_000.0] {
            s.record_send("steady", 9, true, "", ms);
        }
        s.record_send("steady", 9, false, "blocked", 1.0);
        let le = s.live(1).ack_ms_le;
        let at = |k: &str| le[k];
        assert_eq!(
            (
                at("10"),
                at("250"),
                at("500"),
                at("1000"),
                at("10000"),
                at("+Inf")
            ),
            (1, 1, 2, 3, 3, 4)
        );
        assert_eq!(le.len(), super::ACK_MS_BOUNDS.len() + 1);
    }

    use super::*;

    #[test]
    fn live_counts_the_generators_own_errors_apart_from_rejects() {
        let st = Stats::new();
        st.record_send("steady", 9, true, "", 1.0);
        st.record_send("steady", 9, false, "blocked: rate", 0.0);
        st.record_client_error("send_failed");
        st.record_client_error("send_failed");
        st.record_client_error("reconnect_failed");
        let live = st.live(42);
        assert_eq!(
            (live.t_unix, live.sent, live.accepted, live.rejected),
            (42, 2, 1, 1)
        );
        assert_eq!(live.client_errors.get("send_failed"), Some(&2));
        assert_eq!(live.client_errors.get("reconnect_failed"), Some(&1));
        assert_eq!(live.client_errors.len(), 2);
    }

    #[test]
    fn live_splits_media_and_git_failures_by_where_they_failed() {
        let st = Stats::new();
        st.record_media(10, 1.0);
        for why in [
            MediaFailure::Client,
            MediaFailure::Refused,
            MediaFailure::Refused,
            MediaFailure::Unanswered,
            MediaFailure::Unanswered,
            MediaFailure::Unanswered,
        ] {
            st.record_media_failed(why);
        }
        st.record_git(5, 1.0);
        for why in [GitFailure::Local, GitFailure::Push, GitFailure::Push] {
            st.record_git_failed(why);
        }
        let live = st.live(7);
        assert_eq!(
            (
                live.media_client_failed,
                live.media_refused,
                live.media_unanswered,
                live.git_local_failed,
                live.git_push_failed
            ),
            (1, 2, 3, 1, 2)
        );
        let v = serde_json::to_value(&live).expect("json");
        for k in [
            "media_client_failed",
            "media_refused",
            "media_unanswered",
            "git_local_failed",
            "git_push_failed",
        ] {
            assert!(v.get(k).is_some(), "live.json has no {k}");
        }
        // summary.json keeps its meaning: every failure, wherever it failed.
        let summary = st.summarize("p", 1, "ws://x", 1, 1, &HashMap::new());
        assert_eq!((summary.media.uploads, summary.media.rejected), (1, 6));
        assert_eq!((summary.git.pushes, summary.git.failed), (1, 3));
    }

    /// Poll times: never-mentioned humans' apart from the rest, over every
    /// band; each band's own, and live.json's histogram, over both.
    #[test]
    fn poll_times_are_split_by_whether_the_human_is_mentioned() {
        let st = Stats::new();
        st.record_poll(Some("steady"), 1400.0, true);
        st.record_poll(Some("steady"), 1500.0, true);
        st.record_poll(Some("steady"), 90.0, false);
        st.record_poll(None, 80.0, false);
        let summary = st.summarize("p", 1, "ws://x", 1, 1, &HashMap::new());
        assert_eq!(
            (summary.polls.never_mentioned, summary.polls.mentioned),
            (2, 2)
        );
        assert_eq!(summary.polls.never_mentioned_ms.max, 1500.0);
        assert_eq!(summary.polls.mentioned_ms.max, 90.0);
        assert_eq!(summary.bands["steady"].polls, 3);
        let live = st.live(1);
        assert_eq!(
            (live.polls, live.poll_ms_le["100"], live.poll_ms_le["2500"]),
            (4, 2, 4)
        );
    }

    #[test]
    fn write_live_replaces_the_file_whole() {
        let dir = std::env::temp_dir().join(format!("live-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("live.json");
        let st = Stats::new();
        write_live(&path, &st.live(1)).unwrap();
        st.record_client_error("recv_error");
        write_live(&path, &st.live(2)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["t_unix"], 2);
        assert_eq!(v["client_errors"]["recv_error"], 1);
        assert!(
            !dir.join("live.json.tmp").exists(),
            "the temp file was left"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sends_are_counted_by_kind_per_band() {
        let stats = Stats::new();
        stats.record_send("floor", 20001, true, "", 1.0);
        stats.record_send("floor", 20001, true, "", 1.0);
        stats.record_send("steady", 9, true, "", 1.0);
        stats.record_send("steady", 20001, false, "blocked", 1.0);
        let summary = stats.summarize("p", 1, "ws://x", 1, 1, &HashMap::new());
        assert_eq!(
            summary.bands["floor"].sent_by_kind,
            BTreeMap::from([("20001".to_string(), 2)])
        );
        assert_eq!(
            summary.bands["steady"].sent_by_kind,
            BTreeMap::from([("9".to_string(), 1), ("20001".to_string(), 1)])
        );
        assert_eq!(summary.sent_by_kind["20001"], 3);
    }
}
