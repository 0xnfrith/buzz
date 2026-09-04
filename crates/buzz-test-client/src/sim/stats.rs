//! Client-side counters, percentiles, and the summary JSON schema.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

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

#[derive(Clone, Debug, Default, Serialize)]
pub struct BandClient {
    pub start_unix: u64,
    pub end_unix: u64,
    pub sent: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub received: u64,
    pub ok_ms: Percentiles,
    pub fanout_ms: Percentiles,
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
    pub join_backfill_ms: Percentiles,
    pub gaps_detected: u64,
    pub lost_after_backfill: u64,
    pub rejects_by_message: BTreeMap<String, u64>,
    pub blink: Option<serde_json::Value>,
}

#[derive(Default)]
struct BandAcc {
    start_unix: u64,
    sent: u64,
    accepted: u64,
    rejected: u64,
    received: u64,
    ok_ms: Vec<f64>,
    fanout_ms: Vec<f64>,
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
    media_put_ms: Vec<f64>,
    git_pushes: u64,
    git_bytes: u64,
    git_failed: u64,
    git_push_ms: Vec<f64>,
    gaps_detected: u64,
    lost_after_backfill: u64,
    blink: Option<serde_json::Value>,
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
            if accepted {
                b.accepted += 1;
                b.ok_ms.push(ok_ms);
            } else {
                b.rejected += 1;
                *s.rejects_by_message.entry(message.to_string()).or_default() += 1;
            }
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

    pub fn record_media(&self, ok: bool, bytes: u64, put_ms: f64) {
        self.with(|s| {
            if ok {
                s.media_uploads += 1;
                s.media_bytes += bytes;
                s.media_put_ms.push(put_ms);
            } else {
                s.media_rejected += 1;
            }
        });
    }

    pub fn record_git(&self, ok: bool, bytes: u64, push_ms: f64) {
        self.with(|s| {
            if ok {
                s.git_pushes += 1;
                s.git_bytes += bytes;
                s.git_push_ms.push(push_ms);
            } else {
                s.git_failed += 1;
            }
        });
    }

    pub fn set_blink(&self, value: serde_json::Value) {
        self.with(|s| s.blink = Some(value));
    }

    pub fn lost_after_backfill(&self) -> u64 {
        self.with(|s| s.lost_after_backfill)
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
                    received: acc.received,
                    ok_ms: percentiles(acc.ok_ms.clone()),
                    fanout_ms: percentiles(acc.fanout_ms.clone()),
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
                join_backfill_ms: percentiles(s.join_backfill_ms.clone()),
                gaps_detected: s.gaps_detected,
                lost_after_backfill: s.lost_after_backfill,
                rejects_by_message: s.rejects_by_message.clone(),
                blink: s.blink.clone(),
            }
        })
    }
}
