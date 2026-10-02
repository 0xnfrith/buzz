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
use super::guard::Target;
use super::identity::{connect_identity, IdentityRecord, Population};
use super::kinds;
use super::mentions::{self, Mentions};
use super::profile::KindTable;
use super::roles::{Band, Role};
use tokio::sync::watch;

const OK_TIMEOUT: Duration = Duration::from_secs(30);
const CONTENT_BYTES: usize = 200;

#[derive(Debug, Default, Serialize)]
pub struct SeedReport {
    pub requested: u64,
    pub acked: u64,
    pub rejected: u64,
    pub rate_limited: u64,
    /// Events the relay shed, full or unable to admit, each resent.
    pub shed: u64,
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
    shed: AtomicU64,
    errors: AtomicU64,
    first_reject: Mutex<Option<String>>,
}

/// Build the `i`-th seed message: a plain channel message with no sequence
/// tag, so it never opens a gap in the live run that follows. `mention`
/// tags one identity, as the run's messages do (`mentions.rs`), so the
/// history carries mentions at the same shares and with the same skew.
pub fn seed_event(
    keys: &Keys,
    kinds: &KindTable,
    channel: &str,
    i: u64,
    mention: Option<&str>,
) -> Result<nostr::Event> {
    let mut tags = vec![kinds::tag(&["h", channel])?];
    if let Some(pk) = mention {
        tags.push(kinds::tag(&["p", pk])?);
    }
    Ok(
        EventBuilder::new(kinds::kind(kinds.msg), kinds::lorem(i, CONTENT_BYTES))
            .tags(tags)
            .sign_with_keys(keys)?,
    )
}

/// The `i`-th seed message, as a writer builds it: its channel by `i`, and
/// its mention ([`seed_mention`]).
pub fn seed_message(
    keys: &Keys,
    kinds: &KindTable,
    channels: &[String],
    i: u64,
    role: Role,
    author: &str,
    m: &Mentions,
) -> Result<nostr::Event> {
    let ch = &channels[(i as usize) % channels.len()];
    let mention = seed_mention(m, role, author, i);
    seed_event(keys, kinds, ch, i, mention.as_deref())
}

/// Whom the `i`-th seed message, by `author` in `role`, mentions: drawn
/// from `i`, so the same event always draws the same.
pub fn seed_mention(m: &Mentions, role: Role, author: &str, i: u64) -> Option<String> {
    let (u, v) = mentions::unit_pair(i);
    m.draw(role, author, u, v).map(str::to_string)
}

#[allow(clippy::too_many_arguments)]
async fn writer(
    relay_url: Target,
    rec: IdentityRecord,
    role: Role,
    mentions: Arc<Mentions>,
    keys: Keys,
    oa_owner: Option<Keys>,
    kinds: KindTable,
    channels: Arc<Vec<String>>,
    next: Arc<AtomicU64>,
    target: u64,
    deadline: Instant,
    c: Arc<Counters>,
    stop: watch::Receiver<Band>,
) {
    let mut client = None;
    let mut pending: Option<(u64, nostr::Event)> = None;
    // Each step is bounded (an OK window, a 1 s retry, a rate-limit window
    // cut to the deadline); between them, a stopped run seeds no more.
    while Instant::now() < deadline && *stop.borrow() != Band::Stop {
        let (i, event) = match pending.take() {
            Some(p) => p,
            None => {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= target {
                    break;
                }
                match seed_message(&keys, &kinds, &channels, i, role, &rec.pubkey, &mentions) {
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
            // The relay shed it: resent after a pause, counted apart.
            Ok(Publish::Shed { text }) => {
                warn!("seed {} shed: {text}", rec.name);
                c.shed.fetch_add(1, Ordering::Relaxed);
                pending = Some((i, event));
                let left = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(Duration::from_secs(1).min(left)).await;
            }
            // A text the pinned relay doesn't send: an error, not resent.
            Ok(Publish::UnknownLimit { text }) => {
                warn!("seed {} unknown limit: {text}", rec.name);
                c.errors.fetch_add(1, Ordering::Relaxed);
                let mut first = c.first_reject.lock().unwrap_or_else(|p| p.into_inner());
                first.get_or_insert(text);
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
/// `max`, or when the run stops. Agents authenticate with their owner's
/// NIP-OA tag, as in the run.
#[allow(clippy::too_many_arguments)]
pub async fn seed(
    relay_url: &Target,
    pop: &Population,
    mentions: &Arc<Mentions>,
    kinds: &KindTable,
    channels: &[String],
    target: u64,
    max: Duration,
    stop: watch::Receiver<Band>,
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
        let role = if pop.humans.iter().any(|h| h.pubkey == rec.pubkey) {
            Role::Human
        } else {
            Role::Agent
        };
        tasks.push(tokio::spawn(writer(
            relay_url.clone(),
            rec.clone(),
            role,
            mentions.clone(),
            keys,
            oa_owner,
            *kinds,
            channels.clone(),
            next.clone(),
            target,
            deadline,
            c.clone(),
            stop.clone(),
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
        shed: c.shed.load(Ordering::Relaxed),
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
        let ev = seed_event(&keys, &k, "chan-a", 7, None).expect("build");
        assert_eq!(ev.kind.as_u16(), k.msg);
        let names: Vec<&str> = ev
            .tags
            .iter()
            .filter_map(|t| t.as_slice().first().map(String::as_str))
            .collect();
        assert_eq!(names, vec!["h"]);
        assert_eq!(ev.content.len(), CONTENT_BYTES);
        let who = "cd".repeat(32);
        let ev = seed_event(&keys, &k, "chan-a", 7, Some(&who)).expect("build");
        let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert_eq!(
            tags,
            vec![
                vec!["h".to_string(), "chan-a".to_string()],
                vec!["p".to_string(), who]
            ]
        );
    }

    /// The seed's mentions: the run's shares and skew, the tail never
    /// tagged, no one tagging themselves, the same event always drawing the
    /// same.
    #[test]
    fn the_seed_carries_mentions_with_the_runs_shares_and_tail() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../perf/clock-proof/profiles/proof-heavy.toml");
        let profile = crate::sim::profile::load_profile(&path).expect("profile");
        let pop = crate::sim::identity::generate_population(&profile);
        let m = Mentions::new(&pop);
        let k = kinds::sample_kinds();
        let channels = vec!["chan-a".to_string(), "chan-b".to_string()];
        for (rec, role, share) in [
            (&pop.humans[0], Role::Human, mentions::HUMAN_SHARE),
            (&pop.agents[0], Role::Agent, mentions::AGENT_SHARE),
        ] {
            let keys = pop.keys_of(rec).expect("keys");
            let n = 4_000u64;
            let mut tagged = 0;
            for i in 0..n {
                let ev =
                    seed_message(&keys, &k, &channels, i, role, &rec.pubkey, &m).expect("build");
                let ps: Vec<String> = ev
                    .tags
                    .iter()
                    .filter(|t| t.as_slice().first().map(String::as_str) == Some("p"))
                    .filter_map(|t| t.as_slice().get(1).cloned())
                    .collect();
                assert!(ps.len() <= 1, "more than one mention");
                if let Some(who) = ps.first() {
                    tagged += 1;
                    assert!(!m.is_tail(who), "a tail identity was tagged in the seed");
                    assert_ne!(who, &rec.pubkey, "a self-mention");
                }
            }
            let got = tagged as f64 / n as f64;
            assert!((got - share).abs() < 0.02, "{:?}: {got}", role);
        }
        assert_eq!(
            seed_mention(&m, Role::Agent, &pop.agents[3].pubkey, 77),
            seed_mention(&m, Role::Agent, &pop.agents[3].pubkey, 77)
        );
    }
}
