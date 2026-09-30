//! Volume seed: stored history written at current timestamps.
//!
//! The relay rejects events far from its own clock, so history cannot be
//! backdated. The seed writes the same volume now, before any identity
//! subscribes, from the population's own keys (one socket and one event in
//! flight per identity). It reports what the client saw; the orchestrator
//! measures what the relay stored.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use nostr::{EventBuilder, Keys};
use serde::Serialize;
use tracing::warn;

use super::admission::{publish, Publish};
use super::identity::{connect_identity, IdentityRecord, Population};
use super::kinds;
use super::profile::KindTable;

const OK_TIMEOUT: Duration = Duration::from_secs(30);
const CONTENT_BYTES: usize = 200;

#[derive(Debug, Default, Serialize)]
pub struct SeedReport {
    pub requested: u64,
    pub acked: u64,
    pub rejected: u64,
    pub rate_limited: u64,
    pub errors: u64,
    pub writers: u64,
    pub seconds: f64,
    pub acked_per_s: f64,
    pub first_reject: Option<String>,
}

#[derive(Default)]
struct Counters {
    acked: AtomicU64,
    rejected: AtomicU64,
    rate_limited: AtomicU64,
    errors: AtomicU64,
    first_reject: Mutex<Option<String>>,
}

/// Build the `i`-th seed message: a plain channel message with no sequence
/// tag, so it never opens a gap in the live run that follows.
pub fn seed_event(keys: &Keys, kinds: &KindTable, channel: &str, i: u64) -> Result<nostr::Event> {
    Ok(
        EventBuilder::new(kinds::kind(kinds.msg), kinds::lorem(i, CONTENT_BYTES))
            .tags([kinds::tag(&["h", channel])?])
            .sign_with_keys(keys)?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn writer(
    relay_url: String,
    rec: IdentityRecord,
    keys: Keys,
    oa_owner: Option<Keys>,
    kinds: KindTable,
    channels: Arc<Vec<String>>,
    next: Arc<AtomicU64>,
    target: u64,
    deadline: Instant,
    c: Arc<Counters>,
) {
    let mut client = None;
    let mut pending: Option<(u64, nostr::Event)> = None;
    while Instant::now() < deadline {
        let (i, event) = match pending.take() {
            Some(p) => p,
            None => {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= target {
                    break;
                }
                let ch = &channels[(i as usize) % channels.len()];
                match seed_event(&keys, &kinds, ch, i) {
                    Ok(ev) => (i, ev),
                    Err(e) => {
                        warn!("seed {} build: {e:#}", rec.name);
                        c.errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }
        };
        if client.is_none() {
            match connect_identity(&relay_url, &rec, &keys, oa_owner.as_ref()).await {
                Ok(cl) => client = Some(cl),
                Err(e) => {
                    warn!("seed {} connect: {e:#}", rec.name);
                    c.errors.fetch_add(1, Ordering::Relaxed);
                    pending = Some((i, event));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        let Some(cl) = client.as_mut() else { continue };
        match publish(cl, &event, OK_TIMEOUT).await {
            Ok(Publish::Ok(ok)) if ok.accepted => {
                c.acked.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Publish::Ok(ok)) => {
                c.rejected.fetch_add(1, Ordering::Relaxed);
                let mut first = c.first_reject.lock().unwrap_or_else(|p| p.into_inner());
                first.get_or_insert(ok.message);
            }
            Ok(Publish::RateLimited { retry_in }) => {
                c.rate_limited.fetch_add(1, Ordering::Relaxed);
                pending = Some((i, event));
                let left = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(retry_in.min(left)).await;
            }
            Err(e) => {
                warn!("seed {} publish: {e}", rec.name);
                c.errors.fetch_add(1, Ordering::Relaxed);
                pending = Some((i, event));
                client = None;
            }
        }
    }
    if let Some(cl) = client {
        let _ = cl.disconnect().await;
    }
}

/// Write `target` stored messages across the population, stopping early at
/// `max`. Agents authenticate with their owner's NIP-OA tag, as in the run.
pub async fn seed(
    relay_url: &str,
    pop: &Population,
    kinds: &KindTable,
    channels: &[String],
    target: u64,
    max: Duration,
) -> Result<SeedReport> {
    let c = Arc::new(Counters::default());
    let next = Arc::new(AtomicU64::new(0));
    let channels = Arc::new(channels.to_vec());
    let start = Instant::now();
    let deadline = start + max;
    let mut tasks = Vec::new();
    for rec in pop.humans.iter().chain(pop.agents.iter()) {
        let keys = pop.keys_of(rec)?;
        let oa_owner = rec
            .owner_name
            .as_ref()
            .and_then(|n| pop.humans.iter().find(|h| h.name == *n))
            .and_then(|h| pop.keys_of(h).ok());
        tasks.push(tokio::spawn(writer(
            relay_url.to_string(),
            rec.clone(),
            keys,
            oa_owner,
            *kinds,
            channels.clone(),
            next.clone(),
            target,
            deadline,
            c.clone(),
        )));
    }
    let writers = tasks.len() as u64;
    for t in tasks {
        let _ = t.await;
    }
    let seconds = start.elapsed().as_secs_f64();
    let acked = c.acked.load(Ordering::Relaxed);
    let first_reject = c
        .first_reject
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    Ok(SeedReport {
        requested: target,
        acked,
        rejected: c.rejected.load(Ordering::Relaxed),
        rate_limited: c.rate_limited.load(Ordering::Relaxed),
        errors: c.errors.load(Ordering::Relaxed),
        writers,
        seconds,
        acked_per_s: if seconds > 0.0 {
            acked as f64 / seconds
        } else {
            0.0
        },
        first_reject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_event_is_an_unsequenced_channel_message() {
        let keys = Keys::generate();
        let k = kinds::sample_kinds();
        let ev = seed_event(&keys, &k, "chan-a", 7).expect("build");
        assert_eq!(ev.kind.as_u16(), k.msg);
        let names: Vec<&str> = ev
            .tags
            .iter()
            .filter_map(|t| t.as_slice().first().map(String::as_str))
            .collect();
        assert_eq!(names, vec!["h"]);
        assert_eq!(ev.content.len(), CONTENT_BYTES);
    }
}
