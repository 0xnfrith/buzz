//! Seeded identities and the per-identity duty-cycle session.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use buzz_sdk::nip_oa;
use buzz_test_client::{BuzzTestClient, RelayMessage, TestClientError};
use nostr::{Alphabet, Filter, Keys, Kind, SingleLetterTag, Tag, Timestamp, ToBech32};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use super::admission::{self, Publish};
use super::feed;
use super::git::{self, GitRepo};
use super::guard::{self, Target};
use super::kinds;
use super::media;
use super::mentions;
use super::profile::{Profile, Rates};
use super::reads;
use super::roles::{
    in_active_window, next_any_wait, pick_action, rng_f64, rng_usize, scaled_rates, Band, Role,
};
use super::stats::Stats;

/// How long a send waits for its OK: buzz-ws-client's own publish window.
const OK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub name: String,
    pub role: String,
    pub pubkey: String,
    pub secret_hex: String,
    pub nsec: String,
    pub owner_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Population {
    pub owner: IdentityRecord,
    pub humans: Vec<IdentityRecord>,
    pub agents: Vec<IdentityRecord>,
}

impl Population {
    pub fn owner_keys(&self) -> Result<Keys> {
        Keys::parse(&self.owner.secret_hex).context("parse owner key")
    }

    pub fn keys_of(&self, rec: &IdentityRecord) -> Result<Keys> {
        Keys::parse(&rec.secret_hex).with_context(|| format!("parse key {}", rec.name))
    }
}

pub struct World {
    /// The relay's websocket URL, checked by the target guard.
    pub relay_url: Target,
    /// The relay's HTTP base (media and git), checked by the target guard.
    pub http_url: Target,
    pub channels: Vec<String>,
    pub human_pubkeys: Vec<String>,
    pub repos: Vec<RepoRef>,
    pub git_helper: PathBuf,
    pub out_dir: PathBuf,
    pub blink: bool,
    /// Who mentions whom, and how often ([`mentions::Mentions`]).
    pub mentions: Arc<mentions::Mentions>,
    /// Each identity's last accepted `seq`, as it sends: a joiner's
    /// baseline for each author ([`SeqBoard`]).
    pub seqs: Arc<SeqBoard>,
}

/// Every identity's last accepted channel-message `seq`, in this generator
/// process. All of a relay's identities are in one process, so a joiner
/// knows exactly what each author had sent before it subscribed: anything
/// after that it doesn't see is a gap, and anything before is not.
#[derive(Debug, Default)]
pub struct SeqBoard {
    last: std::sync::Mutex<HashMap<String, u64>>,
}

impl SeqBoard {
    /// `identity` had its `seq` accepted.
    pub fn set(&self, identity: &str, seq: u64) {
        let mut m = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let e = m.entry(identity.to_string()).or_insert(0);
        *e = (*e).max(seq);
    }

    /// Each identity's last accepted `seq` now.
    pub fn snapshot(&self) -> HashMap<String, u64> {
        self.last.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[derive(Clone)]
pub struct RepoRef {
    pub name: String,
    pub owner_hex: String,
    pub owner_nsec: String,
    pub a_tag: String,
    /// The checked git URL: pushes go here, never to a URL read from disk.
    pub clone_url: Target,
    pub worktree: PathBuf,
}

fn std_rng(seed: u64, salt: u32) -> StdRng {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..12].copy_from_slice(&salt.to_le_bytes());
    StdRng::from_seed(bytes)
}

fn rng_keys(rng: &mut StdRng) -> Keys {
    loop {
        let mut sk = [0u8; 32];
        rng.fill(&mut sk);
        if sk.iter().all(|b| *b == 0) {
            continue;
        }
        if let Ok(keys) = Keys::parse(&hex::encode(sk)) {
            return keys;
        }
    }
}

fn record(name: &str, role: &str, keys: &Keys, owner_name: Option<String>) -> IdentityRecord {
    let secret_hex = keys.secret_key().display_secret().to_string();
    let nsec = keys
        .secret_key()
        .to_bech32()
        .unwrap_or_else(|_| secret_hex.clone());
    IdentityRecord {
        name: name.to_string(),
        role: role.to_string(),
        pubkey: keys.public_key().to_hex(),
        secret_hex,
        nsec,
        owner_name,
    }
}

pub fn generate_population(profile: &Profile) -> Population {
    let mut rng = std_rng(profile.seed, 0);
    let owner = rng_keys(&mut rng);
    let mut humans = Vec::new();
    for i in 0..profile.humans {
        let keys = rng_keys(&mut rng);
        humans.push(record(&format!("h{i}"), "human", &keys, None));
    }
    let mut agents = Vec::new();
    for i in 0..profile.agent_count() {
        let keys = rng_keys(&mut rng);
        let owner_name = format!("h{}", i / profile.agents_per_human.max(1));
        agents.push(record(&format!("a{i}"), "agent", &keys, Some(owner_name)));
    }
    Population {
        owner: record("owner", "owner", &owner, None),
        humans,
        agents,
    }
}

pub fn save_population(path: &Path, pop: &Population) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(pop)?)?;
    Ok(())
}

pub fn load_population(path: &Path) -> Result<Population> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// An agent's NIP-OA credential JSON (`["auth", owner, conditions, sig]`),
/// signed by its owner with no conditions. HTTP paths carry it as-is:
/// `x-auth-tag` for media, `BUZZ_AUTH_TAG` for the git credential helper.
pub fn nip_oa_json(owner: &Keys, agent: &Keys) -> Result<String> {
    Ok(nip_oa::compute_auth_tag(owner, &agent.public_key(), "")?)
}

pub fn nip_oa_tag(owner: &Keys, agent: &Keys) -> Result<Tag> {
    Ok(nip_oa::parse_auth_tag(&nip_oa_json(owner, agent)?)?)
}

/// Multiplier on an agent's `git_push` rate. Only a repo's owner can push to
/// it, and there are usually far fewer repos than agents. The profile's rate
/// is per agent, so the owners carry the whole population's pushes and every
/// other agent pushes none; total push volume stays what the profile says.
pub fn git_push_scale(agents: u32, owners: usize, owns_repo: bool) -> f64 {
    if !owns_repo || owners == 0 {
        return 0.0;
    }
    f64::from(agents) / owners as f64
}

/// Newest received event that lives in a channel. Events from the `#p`
/// stream (DMs, turn metrics) have no channel; a reaction to one carries an
/// empty `h` tag, which no client sends and the relay stores without an OK.
fn reaction_target(seen: &VecDeque<(String, String)>) -> Option<(String, String)> {
    seen.iter().rev().find(|(_, ch)| !ch.is_empty()).cloned()
}

/// The band to move to, if the signal changed. Once the signal reader exits
/// the channel is closed and tokio's `has_changed` returns an error even when
/// an unseen value is waiting; the last value sent (normally `Stop`) still
/// stands and must be acted on, or the identity never stops.
/// A ramp identity's place: it connects once the ramp has switched on more
/// identities than its index; every identity in a ramp rechecks for lost
/// events at each step, without restarting its band.
pub struct RampSlot {
    pub on: watch::Receiver<usize>,
    pub index: usize,
}

/// Waits until the ramp has switched this identity on: true, or false if
/// the run stopped first.
async fn wait_switched_on(slot: &mut RampSlot, band: &mut watch::Receiver<Band>) -> bool {
    loop {
        if *slot.on.borrow_and_update() > slot.index {
            return true;
        }
        if *band.borrow() == Band::Stop {
            return false;
        }
        tokio::select! {
            r = slot.on.changed() => {
                if r.is_err() {
                    return *slot.on.borrow() > slot.index;
                }
            }
            r = band.changed() => {
                if r.is_err() {
                    return false;
                }
            }
        }
    }
}

/// Resolves once the run is stopping: a `stop`, or a lease that ran out.
/// Never resolves if the signal's sender is gone without a stop (it lives
/// as long as the process).
pub async fn until_stop(rx: &mut watch::Receiver<Band>) {
    loop {
        if *rx.borrow_and_update() == Band::Stop {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub fn next_band(rx: &mut watch::Receiver<Band>, current: Band) -> Option<Band> {
    match rx.has_changed() {
        Ok(true) => Some(*rx.borrow_and_update()),
        Ok(false) => None,
        Err(_) => {
            let last = *rx.borrow_and_update();
            (last != current).then_some(last)
        }
    }
}

/// Aborts its task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn filter_channel(kinds: &[u16], channel: &str, limit: u32) -> Filter {
    let ks: Vec<Kind> = kinds.iter().copied().map(Kind::Custom).collect();
    Filter::new()
        .kinds(ks)
        .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel])
        .limit(limit as usize)
}

/// The identity's `#p` subscription, from `since` on: the desktop's live
/// `#p` subscriptions carry a `since` (the time they start), never a
/// kind-less history query. On a heavy relay that history query walks every
/// event newest-first; this one is answered at once. Its events are never
/// counted as backfill.
fn filter_p(pubkey: &str, since: u64) -> Filter {
    Filter::new()
        .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [pubkey])
        .since(Timestamp::from(since))
}

/// The desktop's replay window for a live subscription on reconnect
/// (`desktop/src/shared/api/relayReconnectReplay.ts`): its filter's own
/// `since`, or the newest event it saw less 5 s, whichever is later.
const P_REPLAY_SKEW_S: u64 = 5;

/// Warm-up must prove EOSE; reconnects may keep going if a later EOSE is late.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EosePolicy {
    Required,
    Tolerant,
}

fn apply_eose(
    identity: &str,
    label: &str,
    policy: EosePolicy,
    result: Result<Vec<nostr::Event>, TestClientError>,
) -> Result<u64> {
    match result {
        Ok(events) => Ok(events.len() as u64),
        Err(e) if policy == EosePolicy::Required => {
            Err(anyhow!("{identity} warm-up EOSE failed on {label}: {e}"))
        }
        Err(e) => {
            warn!("{identity} backfill {label}: {e}");
            Ok(0)
        }
    }
}

fn tag_value(event: &nostr::Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(String::as_str) == Some(name) {
            s.get(1).cloned()
        } else {
            None
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn subscribe_all(
    client: &mut BuzzTestClient,
    identity: &str,
    pubkey: &str,
    channels: &[String],
    kinds: &[u16],
    limit: u32,
    stats: &Stats,
    record_join: bool,
    since: Option<u64>,
    p_since: u64,
    eose: EosePolicy,
) -> Result<u64> {
    let mut returned = 0u64;
    for (i, ch) in channels.iter().enumerate() {
        let sid = format!("{identity}-ch{i}");
        let mut filter = filter_channel(kinds, ch, limit);
        if let Some(ts) = since {
            filter = filter.since(Timestamp::from(ts));
        }
        client.subscribe(&sid, vec![filter]).await?;
        let start = Instant::now();
        let eose_result = client
            .collect_until_eose(&sid, Duration::from_secs(12))
            .await;
        let eose_ok = eose_result.is_ok();
        if !eose_ok {
            stats.record_client_error("backfill_failed");
        }
        let n = apply_eose(identity, ch, eose, eose_result)?;
        returned += n;
        if record_join && eose_ok {
            stats.record_join_backfill(start.elapsed().as_secs_f64() * 1e3);
        }
    }
    let sid = format!("{identity}-p");
    client
        .subscribe(&sid, vec![filter_p(pubkey, p_since)])
        .await?;
    let p_result = client
        .collect_until_eose(&sid, Duration::from_secs(8))
        .await;
    if p_result.is_err() {
        stats.record_client_error("backfill_failed");
    }
    apply_eose(identity, "#p", eose, p_result)?;
    Ok(returned)
}

pub async fn connect_identity(
    relay_url: &Target,
    rec: &IdentityRecord,
    keys: &Keys,
    oa_owner: Option<&Keys>,
) -> Result<BuzzTestClient> {
    if rec.role == "agent" {
        if let Some(owner) = oa_owner {
            let tag = nip_oa_tag(owner, keys)?;
            let mut client = BuzzTestClient::connect_unauthenticated(relay_url.as_str()).await?;
            client.authenticate_with_nip_oa(keys, &tag).await?;
            return Ok(client);
        }
    }
    Ok(BuzzTestClient::connect(relay_url.as_str(), keys).await?)
}

struct Session {
    rec: IdentityRecord,
    keys: Keys,
    role: Role,
    oa_owner: Option<Keys>,
    /// This agent's NIP-OA credential JSON for HTTP (media); `None` for humans.
    auth_tag: Option<String>,
    /// See [`git_push_scale`].
    git_push_scale: f64,
    profile: Arc<Profile>,
    world: Arc<World>,
    stats: Arc<Stats>,
    band_rx: watch::Receiver<Band>,
    rng: StdRng,
    seq: u64,
    own: VecDeque<(String, String)>,
    seen: VecDeque<(String, String)>,
    /// Recent distinct authors seen, newest last: a turn reads their
    /// profiles.
    authors: VecDeque<String>,
    /// This agent's turns so far: one in four also counts a thread.
    turns: u64,
    /// How long a send waits for its OK.
    ok_timeout: Duration,
    expected: HashMap<String, u64>,
    missing: HashSet<String>,
    last_seen_created_at: u64,
    /// When the `#p` subscription first started, and the newest event seen
    /// on it: a reconnect resubscribes from these, as the desktop does.
    p_since: u64,
    p_last_seen: Option<u64>,
    git_repo: Option<GitRepo>,
    http: guard::HttpClient,
    /// A human's home-feed poller's view of the connection
    /// ([`feed::Link`]); None for an agent, which doesn't poll.
    feed_link: Option<Arc<feed::Link>>,
}

impl Session {
    fn rates(&self, band: Band) -> Rates {
        let mut rates = scaled_rates(&self.profile, self.role, band);
        rates.git_push *= self.git_push_scale;
        rates
    }

    fn sub_kinds(&self) -> Vec<u16> {
        let k = &self.profile.kinds;
        vec![
            k.msg,
            k.reaction,
            k.edit,
            k.canvas,
            k.issue,
            k.pr,
            k.turn_metric,
        ]
    }

    async fn handle_msg(&mut self, band: Band, msg: RelayMessage) {
        if let RelayMessage::Event {
            event,
            subscription_id,
        } = msg
        {
            self.last_seen_created_at = self.last_seen_created_at.max(event.created_at.as_secs());
            if subscription_id == format!("{}-p", self.rec.name) {
                let t = event.created_at.as_secs();
                self.p_last_seen = Some(self.p_last_seen.map_or(t, |l| l.max(t)));
                // A live mention: a human's desktop polls its home feed at
                // once (C, `feed::poll_on_mention`).
                if self.feed_link.is_some()
                    && feed::LIVE_MENTION_KINDS.contains(&event.kind.as_u16())
                    && event.pubkey.to_hex() != self.rec.pubkey
                {
                    feed::poll_on_mention(self.poll_target(), self.stats.clone(), band);
                }
            }
            let channel = tag_value(&event, "h").unwrap_or_default();
            self.seen.push_back((event.id.to_hex(), channel.clone()));
            if self.seen.len() > 64 {
                self.seen.pop_front();
            }
            let author = event.pubkey.to_hex();
            self.authors.retain(|a| *a != author);
            self.authors.push_back(author);
            if self.authors.len() > 5 {
                self.authors.pop_front();
            }
            let fanout = tag_value(&event, "ts_ms").and_then(|t| t.parse::<u64>().ok());
            let fanout_ms = fanout.map(|ts| {
                let now = kinds::now_ms();
                now.saturating_sub(ts) as f64
            });
            if band.sampled() {
                self.stats.record_recv(band.as_str(), fanout_ms);
            }
            if let Some(seq_tag) = tag_value(&event, "seq") {
                if let Some((who, n_s)) = seq_tag.rsplit_once('-') {
                    if let Ok(n) = n_s.parse::<u64>() {
                        let exp = self.expected.entry(who.to_string()).or_insert(1);
                        if n > *exp {
                            let gap = n - *exp;
                            self.stats.record_gap(gap);
                            for missing_n in *exp..n {
                                self.missing.insert(format!("{who}-{missing_n}"));
                            }
                        }
                        if n >= *exp {
                            *exp = n + 1;
                        }
                        self.missing.remove(&seq_tag);
                    }
                }
            }
        }
    }

    async fn send(&mut self, client: &mut BuzzTestClient, band: Band, event: nostr::Event) -> bool {
        let kind = event.kind.as_u16();
        let start = Instant::now();
        let answer = match admission::send_tracked(client, &event, self.ok_timeout).await {
            Ok((answer, others)) => {
                // A subscription's events that came in while this send
                // waited, handled as they would have been.
                for msg in others {
                    self.handle_msg(band, msg).await;
                }
                Ok(answer)
            }
            Err(e) => Err(e),
        };
        match answer {
            Ok(Publish::RateLimited { retry_in }) => {
                if band.sampled() {
                    self.stats.record_rate_limited(band.as_str(), kind);
                }
                warn!(
                    "{} kind {kind} rate-limited (retry in {retry_in:?})",
                    self.rec.name
                );
                false
            }
            // The relay full, or unable to admit: its break, not a quota.
            Ok(Publish::Shed { text }) => {
                self.stats
                    .record_send_shed(band.sampled().then(|| band.as_str()), kind);
                warn!("{} kind {kind} shed by the relay: {text}", self.rec.name);
                false
            }
            // A text the pinned relay doesn't send: the run voids on it.
            Ok(Publish::UnknownLimit { text }) => {
                self.stats
                    .record_limit_unknown(band.sampled().then(|| band.as_str()), kind, &text);
                warn!("{} kind {kind} got an unknown limit: {text}", self.rec.name);
                false
            }
            Ok(Publish::Ok(ok)) => {
                let ms = start.elapsed().as_secs_f64() * 1e3;
                if band.sampled() {
                    self.stats
                        .record_send(band.as_str(), kind, ok.accepted, &ok.message, ms);
                }
                if !ok.accepted {
                    warn!("{} kind {kind} rejected: {}", self.rec.name, ok.message);
                }
                if ok.accepted && kind == self.profile.kinds.msg {
                    let ch = tag_value(&event, "h").unwrap_or_default();
                    self.own.push_back((ok.event_id.clone(), ch));
                    if self.own.len() > 32 {
                        self.own.pop_front();
                    }
                }
                ok.accepted
            }
            // One counter per send: written and never answered is the
            // relay's; not written at all is the generator's.
            Err(admission::SendError::Unanswered(e)) => {
                self.stats
                    .record_send_unanswered(band.sampled().then(|| band.as_str()), kind);
                warn!("{} kind {kind} got no answer: {e}", self.rec.name);
                false
            }
            Err(admission::SendError::NotSent(e)) => {
                self.stats
                    .record_send_failed(band.sampled().then(|| band.as_str()), kind);
                warn!("{} kind {kind} send failed: {e}", self.rec.name);
                false
            }
        }
    }

    /// Publish a channel-visible event and consume a sequence number only if
    /// the relay accepted it. Presence, DMs, NIP-34 git, typing, and 44200 are
    /// not subscriber-visible on the `#h` stream and must not open sequence gaps.
    async fn send_channel(
        &mut self,
        client: &mut BuzzTestClient,
        band: Band,
        build: impl FnOnce(u64) -> Result<nostr::Event>,
    ) -> Result<bool> {
        let seq = self.seq + 1;
        let event = build(seq)?;
        if kinds::is_global_git_kind(event.kind.as_u16(), &self.profile.kinds) {
            return Err(anyhow!(
                "refusing to sequence global git kind {}",
                event.kind.as_u16()
            ));
        }
        let accepted = self.send(client, band, event).await;
        if accepted {
            self.seq = seq;
            self.world.seqs.set(&self.rec.name, seq);
        }
        Ok(accepted)
    }

    async fn act(&mut self, client: &mut BuzzTestClient, band: Band) -> Result<()> {
        let rates = self.rates(band);
        let Some(action) = pick_action(&rates, &mut self.rng) else {
            return Ok(());
        };
        let name = self.rec.name.clone();
        let k = self.profile.kinds;
        let keys = self.keys.clone();
        let ch = self.world.channels[rng_usize(&mut self.rng, self.world.channels.len())].clone();
        match action {
            "presence" => {
                let ev = kinds::presence(&keys, &k)?;
                self.send(client, band, ev).await;
            }
            "msg" => {
                if self.role == Role::Human
                    && rng_f64(&mut self.rng) < self.profile.human.typing_before_msg_prob
                {
                    let ev = kinds::typing(&keys, &k, &ch)?;
                    self.send(client, band, ev).await;
                }
                let name = name.clone();
                let ch = ch.clone();
                let mention = self.draw_mention();
                self.send_channel(client, band, |seq| {
                    let content = kinds::lorem(seq, 200);
                    kinds::stream_message(&keys, &k, &ch, &name, seq, &content, mention.as_deref())
                })
                .await?;
            }
            "reaction" => {
                if let Some((id, target_ch)) = reaction_target(&self.seen) {
                    self.send_channel(client, band, |seq| {
                        kinds::reaction(&keys, &k, &target_ch, &id, &name, seq)
                    })
                    .await?;
                }
            }
            "edit" => {
                if let Some((id, target_ch)) = self.own.back().cloned() {
                    self.send_channel(client, band, |seq| {
                        let content = kinds::lorem(seq, 180);
                        kinds::edit(&keys, &k, &target_ch, &id, &name, seq, &content)
                    })
                    .await?;
                }
            }
            "canvas" => {
                self.send_channel(client, band, |seq| {
                    kinds::canvas(&keys, &k, &ch, &name, seq)
                })
                .await?;
            }
            "turn_metric" => {
                let Some(owner) = self.oa_owner.as_ref() else {
                    return Ok(());
                };
                let owner_hex = owner.public_key().to_hex();
                let turn_seq = self.seq + 1;
                let ev = kinds::turn_metric(&keys, &k, &owner_hex, &ch, turn_seq)?;
                self.send(client, band, ev).await;
                self.turn_reads(band, &ch, &owner_hex).await;
            }
            "dm" => {
                if let Some(pk) = self
                    .world
                    .human_pubkeys
                    .iter()
                    .find(|p| *p != &self.rec.pubkey)
                    .cloned()
                {
                    let ev = kinds::gift_wrap(&keys, &k, &pk, &kinds::lorem(self.seq + 1, 80))?;
                    self.send(client, band, ev).await;
                }
            }
            "issue" => {
                if let Some(repo) = self.world.repos.first().cloned() {
                    let n = self.seq.saturating_add(1);
                    let ev = kinds::issue(&keys, &k, &repo.a_tag, &repo.owner_hex, &name, n)?;
                    self.send(client, band, ev).await;
                }
            }
            "pr" => {
                if let Some(repo) = self.world.repos.first().cloned() {
                    let mut commit = [0u8; 20];
                    self.rng.fill(&mut commit);
                    let commit = hex::encode(commit);
                    let n = self.seq.saturating_add(1);
                    let ev = kinds::pull_request(
                        &keys,
                        &k,
                        &repo.a_tag,
                        &repo.owner_hex,
                        repo.clone_url.as_str(),
                        &commit,
                        &name,
                        n,
                    )?;
                    self.send(client, band, ev).await;
                }
            }
            "media" => {
                let sizes = self.profile.media.sizes_kb.clone();
                let weights = self.profile.media.weights.clone();
                let kb = *super::roles::pick_weighted(&sizes, &weights, &mut self.rng);
                let mut body = vec![0u8; (kb * 1024) as usize];
                self.rng.fill(body.as_mut_slice());
                match media::upload(
                    &self.http,
                    &self.world.http_url,
                    &keys,
                    body,
                    self.auth_tag.as_deref(),
                )
                .await
                {
                    Ok(up) => {
                        self.stats.record_media(up.bytes, up.put_ms);
                        let content = format!("media {}", up.url);
                        let mention = self.draw_mention();
                        self.send_channel(client, band, |seq| {
                            kinds::stream_message(
                                &keys,
                                &k,
                                &ch,
                                &name,
                                seq,
                                &content,
                                mention.as_deref(),
                            )
                        })
                        .await?;
                    }
                    Err(e) => {
                        warn!("{} media ({:?}): {e}", self.rec.name, e.at);
                        self.stats.record_media_failed(e.at);
                    }
                }
            }
            "git_push" => {
                if let Some(repo) = self.git_repo.clone() {
                    let lo = self.profile.git.push_kb[0];
                    let hi = *self.profile.git.push_kb.last().unwrap_or(&lo);
                    let kb = lo + (rng_f64(&mut self.rng) * (hi.saturating_sub(lo) as f64)) as u64;
                    let mut blob = vec![0u8; (kb * 1024).max(1) as usize];
                    self.rng.fill(blob.as_mut_slice());
                    let git_seq = self.seq + 1;
                    let helper = self.world.git_helper.clone();
                    match git::push_blob_async(repo, helper, blob, git_seq).await {
                        Ok((bytes, ms)) => self.stats.record_git(bytes, ms),
                        Err(e) => {
                            warn!("{} git push ({:?}): {e}", self.rec.name, e.at);
                            self.stats.record_git_failed(e.at);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A turn's reads (see [`reads`]), one after another, as a harness
    /// makes them, each counted by where it ended.
    async fn turn_reads(&mut self, band: Band, channel: &str, owner_hex: &str) {
        self.turns += 1;
        let root = self
            .seen
            .iter()
            .rev()
            .find(|(_, ch)| ch == channel)
            .map(|(id, _)| id.clone());
        let authors: Vec<String> = self.authors.iter().cloned().collect();
        let agent = self.rec.pubkey.clone();
        let turn = reads::Turn {
            channel,
            root: root.as_deref(),
            authors: &authors,
            agent: &agent,
            owner: Some(owner_hex),
            n: self.turns,
        };
        for r in reads::turn_reads(&self.profile.kinds, &turn) {
            // Each read is bounded by the client's timeout; between them, a
            // stopped run reads no more.
            if *self.band_rx.borrow() == Band::Stop {
                break;
            }
            let res = reads::read(
                &self.http,
                &self.world.http_url,
                &self.keys,
                self.auth_tag.as_deref(),
                &r,
            )
            .await;
            match res {
                Ok(ms) => self
                    .stats
                    .record_read(band.sampled().then(|| band.as_str()), r.what, ms),
                Err(reads::ReadError::RateLimited) => self.stats.record_read_rate_limited(),
                Err(reads::ReadError::UnknownLimit(text)) => {
                    warn!(
                        "{} read {} got an unknown limit: {text}",
                        self.rec.name, r.what
                    );
                    self.stats.record_read_limit_unknown(&text);
                }
                Err(reads::ReadError::Failed { at, err }) => {
                    warn!("{} read {} ({at:?}): {err:#}", self.rec.name, r.what);
                    self.stats.record_read_failed(at);
                }
            }
        }
    }

    async fn gap_recheck(&mut self, client: &mut BuzzTestClient, since: u64) {
        if self.missing.is_empty() {
            return;
        }
        let k = self.sub_kinds();
        for (i, ch) in self.world.channels.iter().enumerate() {
            let sid = format!("{}-recheck-{i}", self.rec.name);
            let filter = filter_channel(&k, ch, 500).since(Timestamp::from(since));
            if client.subscribe(&sid, vec![filter]).await.is_err() {
                continue;
            }
            if let Ok(events) = client
                .collect_until_eose(&sid, Duration::from_secs(8))
                .await
            {
                for ev in events {
                    if let Some(seq_tag) = tag_value(&ev, "seq") {
                        self.missing.remove(&seq_tag);
                    }
                }
            }
        }
        let lost = self.missing.len() as u64;
        if lost > 0 {
            self.stats.record_lost(lost);
            self.missing.clear();
        }
    }

    /// Where this identity's home-feed polls go, and as whom.
    fn poll_target(&self) -> feed::PollTarget {
        feed::PollTarget {
            http: self.http.clone(),
            url: self.world.http_url.clone(),
            keys: self.keys.clone(),
            tail: self.world.mentions.is_tail(&self.rec.pubkey),
        }
    }

    /// Before subscribing: each author's next expected `seq` is the one
    /// after its last accepted one now ([`SeqBoard`]). A ramp joiner
    /// switched on mid-stream counts no gap for what was sent before it
    /// subscribed, and every one after. An identity on from the start sees
    /// an empty board: it expects every author from 1.
    fn take_baseline(&mut self) {
        for (author, last) in self.world.seqs.snapshot() {
            self.expected.insert(author, last + 1);
        }
    }

    /// Whom this message mentions, if anyone (see [`mentions`]).
    fn draw_mention(&mut self) -> Option<String> {
        self.world
            .mentions
            .draw_rng(self.role, &self.rec.pubkey, &mut self.rng)
    }

    /// The `#p` subscription's `since` on a reconnect: the desktop's replay
    /// (`relayReconnectReplay.ts`, `replayLiveSubscriptions` and
    /// `buildReconnectReplayFilter`) resends a live subscription from the
    /// later of its filter's own `since` and the newest event it saw less
    /// 5 s; with no event seen, from its own `since`.
    fn p_replay_since(&self) -> u64 {
        match self.p_last_seen {
            Some(t) => self.p_since.max(t.saturating_sub(P_REPLAY_SKEW_S)),
            None => self.p_since,
        }
    }

    async fn reconnect(
        &mut self,
        reason: &str,
        limit: u32,
        record_join: bool,
        storm_ms: bool,
        since: Option<u64>,
    ) -> Result<Option<BuzzTestClient>> {
        info!("{} reconnect ({reason})", self.rec.name);
        if let Some(link) = &self.feed_link {
            link.down();
        }
        let mut delay = Duration::from_millis(250);
        let cap = Duration::from_secs(5);
        // Every attempt, its backoff and the subscribe after it end when the
        // run stops (a `stop`, or a lease that ran out): None. A relay that
        // is gone must not keep a stopped run alive.
        let mut stop = self.band_rx.clone();
        loop {
            let attempt = tokio::select! {
                r = connect_identity(
                    &self.world.relay_url,
                    &self.rec,
                    &self.keys,
                    self.oa_owner.as_ref(),
                ) => r,
                _ = until_stop(&mut stop) => return Ok(None),
            };
            match attempt {
                Ok(mut client) => {
                    let start = Instant::now();
                    let kinds = self.sub_kinds();
                    let subscribed = tokio::select! {
                        n = subscribe_all(
                            &mut client,
                            &self.rec.name,
                            &self.rec.pubkey,
                            &self.world.channels,
                            &kinds,
                            limit,
                            &self.stats,
                            record_join,
                            since,
                            self.p_replay_since(),
                            EosePolicy::Tolerant,
                        ) => n,
                        _ = until_stop(&mut stop) => return Ok(None),
                    };
                    let n = subscribed.unwrap_or(0);
                    if storm_ms {
                        self.stats.record_storm_backfill(
                            "peak",
                            start.elapsed().as_secs_f64() * 1e3,
                            n,
                        );
                    }
                    if let Some(link) = &self.feed_link {
                        link.healed();
                    }
                    return Ok(Some(client));
                }
                Err(e) => {
                    self.stats.record_client_error("reconnect_failed");
                    warn!("{} reconnect failed: {e}", self.rec.name);
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = until_stop(&mut stop) => return Ok(None),
                    }
                    delay = (delay * 2).min(cap);
                }
            }
        }
    }
}

/// One identity's task: [`identity_task`], with one rule on top. A task
/// that joined, then ended for any reason but a stop or a lease (an error,
/// a panic), is recorded in live.json's `identities_ended` at once, and the
/// sampler voids the run on it: a lost identity under-loads the run and
/// over-states the relay's ceiling. An identity that never joined is
/// reported through `ready` instead (a failed warm-up, or a ramp joiner the
/// relay didn't take).
#[allow(clippy::too_many_arguments)]
pub async fn run_identity(
    rec: IdentityRecord,
    keys: Keys,
    oa_owner: Option<Keys>,
    role: Role,
    profile: Arc<Profile>,
    world: Arc<World>,
    stats: Arc<Stats>,
    band_rx: watch::Receiver<Band>,
    git_repo: Option<GitRepo>,
    rng_salt: u32,
    ready: mpsc::Sender<Result<(), String>>,
    ramp: Option<RampSlot>,
) -> Result<()> {
    let name = rec.name.clone();
    let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (stop, record) = (band_rx.clone(), stats.clone());
    let task = identity_task(
        rec,
        keys,
        oa_owner,
        role,
        profile,
        world,
        stats,
        band_rx,
        git_repo,
        rng_salt,
        ready,
        ramp,
        joined.clone(),
    );
    guard_identity(&name, &joined, &stop, &record, task).await
}

/// Runs one identity's task and records it in `identities_ended` if it
/// joined, then failed or panicked while the run wasn't stopping.
async fn guard_identity(
    name: &str,
    joined: &std::sync::atomic::AtomicBool,
    stop: &watch::Receiver<Band>,
    stats: &Stats,
    task: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    use futures_util::FutureExt;
    let res = match std::panic::AssertUnwindSafe(task).catch_unwind().await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("{name}'s task panicked")),
    };
    if let Err(e) = &res {
        let stopping = *stop.borrow() == Band::Stop;
        if joined.load(std::sync::atomic::Ordering::SeqCst) && !stopping {
            warn!("{name} ended on its own: {e:#}");
            stats.record_identity_ended(name, &format!("{e:#}"));
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
async fn identity_task(
    rec: IdentityRecord,
    keys: Keys,
    oa_owner: Option<Keys>,
    role: Role,
    profile: Arc<Profile>,
    world: Arc<World>,
    stats: Arc<Stats>,
    mut band_rx: watch::Receiver<Band>,
    git_repo: Option<GitRepo>,
    rng_salt: u32,
    ready: mpsc::Sender<Result<(), String>>,
    mut ramp: Option<RampSlot>,
    joined: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    if let Some(slot) = ramp.as_mut() {
        if !wait_switched_on(slot, &mut band_rx).await {
            return Ok(());
        }
    }
    let auth_tag = match (role, oa_owner.as_ref()) {
        (Role::Agent, Some(owner)) => Some(nip_oa_json(owner, &keys)?),
        _ => None,
    };
    let git_push_scale = match role {
        Role::Agent => git_push_scale(profile.agent_count(), world.repos.len(), git_repo.is_some()),
        Role::Human => 0.0,
    };
    let mut sess = Session {
        rng: std_rng(profile.seed, rng_salt),
        rec,
        keys,
        role,
        oa_owner,
        auth_tag,
        git_push_scale,
        profile,
        world,
        stats,
        band_rx: band_rx.clone(),
        seq: 0,
        own: VecDeque::new(),
        seen: VecDeque::new(),
        authors: VecDeque::new(),
        turns: 0,
        ok_timeout: OK_TIMEOUT,
        expected: HashMap::new(),
        missing: HashSet::new(),
        last_seen_created_at: unix_now(),
        p_since: unix_now(),
        p_last_seen: None,
        // Humans run Buzz Desktop, whose home feed polls; agents don't.
        feed_link: (role == Role::Human).then(feed::Link::new),
        git_repo,
        http: guard::http_client(Duration::from_secs(30))?,
    };

    // The first connect and subscribe end when the run stops, too: a
    // joiner switched on just before a stop mustn't hold the run open.
    let mut stop = band_rx.clone();
    let connected = tokio::select! {
        r = connect_identity(
            &sess.world.relay_url,
            &sess.rec,
            &sess.keys,
            sess.oa_owner.as_ref(),
        ) => r,
        _ = until_stop(&mut stop) => return Ok(()),
    };
    let mut client = match connected {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{} connect: {e:#}", sess.rec.name);
            let _ = ready.send(Err(msg.clone())).await;
            return Err(anyhow!(msg));
        }
    };
    let kinds = sess.sub_kinds();
    sess.take_baseline();
    // The `#p` subscription starts now, as the desktop's does.
    sess.p_since = unix_now();
    let subscribed = tokio::select! {
        r = subscribe_all(
            &mut client,
            &sess.rec.name,
            &sess.rec.pubkey,
            &sess.world.channels,
            &kinds,
            sess.profile.human.backfill_limit,
            &sess.stats,
            true,
            None,
            sess.p_since,
            EosePolicy::Required,
        ) => r,
        _ = until_stop(&mut stop) => return Ok(()),
    };
    if let Err(e) = subscribed {
        let msg = format!("{} subscribe: {e:#}", sess.rec.name);
        let _ = ready.send(Err(msg.clone())).await;
        return Err(anyhow!(msg));
    }
    if ready.send(Ok(())).await.is_err() {
        return Ok(());
    }
    joined.store(true, std::sync::atomic::Ordering::SeqCst);
    // A human's home feed polls from here on, beside this task, until the
    // run stops; it ends with this task.
    let _poller = sess.feed_link.clone().map(|link| {
        link.up();
        let to = sess.poll_target();
        let stats = sess.stats.clone();
        AbortOnDrop(tokio::spawn(feed::schedule(
            link,
            band_rx.clone(),
            sess.stats.clone(),
            to.tail,
            feed::POLL_EVERY,
            feed::HEAL_MIN,
            move || {
                let (to, stats) = (to.clone(), stats.clone());
                async move {
                    feed::poll(&to, &stats).await;
                }
            },
        )))
    });

    let mut band = *band_rx.borrow();
    let mut band_started = Instant::now();
    let mut band_unix = unix_now();
    let mut step_unix = band_unix;
    let mut next_action = Instant::now();
    let mut stormed = false;
    let mut blink_closes: Vec<u64> = Vec::new();

    loop {
        // A ramp step: look for lost events since the step before (a
        // little earlier, for a gap seen late), without restarting the
        // band, whose duty cycles count from its start.
        if let Some(slot) = ramp.as_mut() {
            if slot.on.has_changed().unwrap_or(false) {
                slot.on.borrow_and_update();
                if band.sampled() {
                    sess.gap_recheck(&mut client, step_unix.saturating_sub(30))
                        .await;
                }
                step_unix = unix_now();
            }
        }
        if let Some(new_band) = next_band(&mut band_rx, band) {
            if band.sampled() {
                sess.gap_recheck(&mut client, band_unix).await;
            }
            band = new_band;
            band_started = Instant::now();
            band_unix = unix_now();
            step_unix = band_unix;
            if band.sampled() {
                sess.stats.band_start(band.as_str(), band_unix);
            }
            stormed = false;
            if band == Band::Stop {
                break;
            }
        }

        if band == Band::Peak
            && sess.profile.storm.enabled
            && sess.role == Role::Human
            && sess.profile.storm.joiners == "humans"
            && !stormed
        {
            stormed = true;
            let stagger = Duration::from_secs_f64(
                rng_f64(&mut sess.rng) * sess.profile.storm.stagger_s as f64,
            );
            let mut stop = band_rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(stagger) => {}
                _ = until_stop(&mut stop) => break,
            }
            let _ = client.disconnect().await;
            match sess
                .reconnect(
                    "storm",
                    sess.profile.storm.backfill_limit,
                    false,
                    true,
                    None,
                )
                .await?
            {
                Some(c) => client = c,
                // The old socket is already closed: nothing to disconnect.
                None => {
                    if sess.world.blink && !blink_closes.is_empty() {
                        sess.stats.record_blink_closes(&blink_closes);
                    }
                    return Ok(());
                }
            }
        }

        let active = in_active_window(sess.role, band, band_started.elapsed(), &sess.profile);
        if Instant::now() >= next_action {
            let rates = sess.rates(band);
            if band == Band::Floor || active || rates.presence > 0.0 {
                if band == Band::Floor {
                    let ev = kinds::presence(&sess.keys, &sess.profile.kinds)?;
                    sess.send(&mut client, band, ev).await;
                    next_action = Instant::now()
                        + Duration::from_secs(sess.profile.human.presence_interval_s.max(1));
                } else if active {
                    sess.act(&mut client, band).await?;
                    next_action = Instant::now() + next_any_wait(&rates, &mut sess.rng);
                } else if rates.presence > 0.0 {
                    let ev = kinds::presence(&sess.keys, &sess.profile.kinds)?;
                    sess.send(&mut client, band, ev).await;
                    next_action =
                        Instant::now() + super::roles::poisson_wait(rates.presence, &mut sess.rng);
                } else {
                    next_action = Instant::now() + Duration::from_millis(200);
                }
            } else {
                next_action = Instant::now() + Duration::from_millis(200);
            }
        }

        match client.recv_event(Duration::from_millis(50)).await {
            Ok(msg) => sess.handle_msg(band, msg).await,
            Err(TestClientError::Timeout) => {}
            Err(e) => {
                let s = e.to_string();
                let is_closed = matches!(
                    e,
                    TestClientError::ConnectionClosed | TestClientError::WebSocket(_)
                ) || s.contains("closed")
                    || s.contains("1012");
                if is_closed && sess.world.blink {
                    blink_closes.push(unix_now());
                    let since = sess.last_seen_created_at.saturating_sub(5);
                    match sess
                        .reconnect(
                            "blink",
                            sess.profile.human.backfill_limit,
                            false,
                            false,
                            Some(since),
                        )
                        .await?
                    {
                        Some(c) => client = c,
                        None => break,
                    }
                } else if is_closed {
                    sess.stats.record_client_error("connection_dropped");
                    warn!("{} connection dropped: {s}", sess.rec.name);
                    match sess
                        .reconnect(
                            "drop",
                            sess.profile.human.backfill_limit,
                            false,
                            false,
                            None,
                        )
                        .await?
                    {
                        Some(c) => client = c,
                        None => break,
                    }
                } else {
                    sess.stats.record_client_error("recv_error");
                    warn!("{} recv: {s}", sess.rec.name);
                }
            }
        }
    }

    if sess.world.blink && !blink_closes.is_empty() {
        sess.stats.record_blink_closes(&blink_closes);
    }
    let _ = client.disconnect().await;
    Ok(())
}

pub fn uuid_v4(rng: &mut StdRng) -> uuid::Uuid {
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::admission::testrelay::fake_relay;
    use crate::sim::guard::{Cidr, TargetGuard};

    /// A human's session in the team profile, its world on loopback.
    fn test_session(stats: Arc<Stats>) -> Session {
        test_session_at(stats, "http://127.0.0.1:1")
    }

    /// [`test_session`] with its HTTP base at `http`.
    fn test_session_at(stats: Arc<Stats>, http: &str) -> Session {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../perf/profiles/10h-20a.toml");
        let profile = Arc::new(crate::sim::profile::load_profile(&path).expect("profile"));
        let pop = generate_population(&profile);
        let rec = pop.humans[0].clone();
        let keys = pop.keys_of(&rec).expect("keys");
        let guard = TargetGuard::new(vec![Cidr::parse("127.0.0.0/8").expect("allow")], vec![])
            .expect("guard");
        let world = Arc::new(World {
            relay_url: guard.check_url("ws://127.0.0.1:1", &["ws"]).expect("relay"),
            http_url: guard.check_url(http, &["http"]).expect("http"),
            channels: vec!["chan-a".into()],
            human_pubkeys: pop.humans.iter().map(|h| h.pubkey.clone()).collect(),
            repos: vec![],
            git_helper: PathBuf::from("/usr/bin/true"),
            out_dir: std::env::temp_dir(),
            blink: false,
            mentions: Arc::new(mentions::Mentions::new(&pop)),
            seqs: Default::default(),
        });
        let (_tx, band_rx) = watch::channel(Band::Steady);
        Session {
            rng: std_rng(profile.seed, 1),
            rec,
            keys,
            role: Role::Human,
            oa_owner: None,
            auth_tag: None,
            git_push_scale: 0.0,
            profile,
            world,
            stats,
            band_rx,
            seq: 0,
            own: VecDeque::new(),
            seen: VecDeque::new(),
            authors: VecDeque::new(),
            turns: 0,
            ok_timeout: OK_TIMEOUT,
            expected: HashMap::new(),
            missing: HashSet::new(),
            last_seen_created_at: unix_now(),
            p_since: unix_now(),
            p_last_seen: None,
            feed_link: None,
            git_repo: None,
            http: guard::http_client(Duration::from_secs(5)).expect("http client"),
        }
    }

    /// A turn against a relay that refuses every read: each of the turn's
    /// reads counts as the relay's refusal in the live counters, none as
    /// the generator's error.
    #[tokio::test]
    async fn a_turn_against_a_refusing_relay_counts_each_read_as_refused() {
        use crate::sim::guard::testsrv::{self, Server};
        let refusing = Server::start("127.0.0.1:0", testsrv::status(503, r#"{"error":"down"}"#));
        let stats = Arc::new(Stats::new());
        let mut sess = test_session_at(stats.clone(), &refusing.http());
        sess.seen.push_back(("ee".repeat(32), "chan-a".into()));
        sess.authors.push_back("ab".repeat(32));
        sess.turn_reads(Band::Steady, "chan-a", &"cd".repeat(32))
            .await;
        let live = stats.live(1);
        assert_eq!(
            (
                live.read_refused,
                live.read_unanswered,
                live.read_client_failed,
                live.read_rate_limited
            ),
            (5, 0, 0, 0)
        );
        assert_eq!(refusing.accepts(), 5);
    }

    /// An agent's turn, as `act` takes it: the turn metric is sent, then the
    /// turn's reads are made (here with no root and no author seen yet:
    /// memory, history and canvas), each counted where it ended.
    #[tokio::test]
    async fn an_agents_turn_sends_its_metric_then_reads() {
        use crate::sim::guard::testsrv::{self, Server};
        let refusing = Server::start("127.0.0.1:0", testsrv::status(503, r#"{"error":"down"}"#));
        let ws = fake_relay(vec![r#"["OK","{id}",true,""]"#.to_string()]).await;
        let stats = Arc::new(Stats::new());
        let mut sess = test_session_at(stats.clone(), &refusing.http());
        let pop = generate_population(&sess.profile);
        let agent = pop.agents[0].clone();
        let owner = pop
            .humans
            .iter()
            .find(|h| Some(&h.name) == agent.owner_name.as_ref())
            .expect("owner");
        sess.oa_owner = Some(pop.keys_of(owner).expect("owner keys"));
        sess.keys = pop.keys_of(&agent).expect("agent keys");
        sess.rec = agent;
        sess.role = Role::Agent;
        // Only turns, so the one action is a turn.
        let mut profile = (*sess.profile).clone();
        profile.agent.rates = Rates {
            turn_metric: 1.0,
            ..Rates::default()
        };
        sess.profile = Arc::new(profile);
        let mut client = BuzzTestClient::connect_unauthenticated(&ws)
            .await
            .expect("connect");
        sess.act(&mut client, Band::Steady).await.expect("act");
        let live = stats.live(1);
        assert_eq!((live.sent, live.accepted), (1, 1), "the turn metric");
        assert_eq!((live.read_refused, live.read_client_failed), (3, 0));
        assert_eq!(refusing.accepts(), 3);
    }

    /// A session whose relay is `url`.
    fn session_on(stats: Arc<Stats>, url: &str) -> Session {
        let mut sess = test_session(stats);
        let guard = TargetGuard::new(vec![Cidr::parse("127.0.0.0/8").expect("allow")], vec![])
            .expect("guard");
        let w = &sess.world;
        sess.world = Arc::new(World {
            relay_url: guard.check_url(url, &["ws"]).expect("relay"),
            http_url: w.http_url.clone(),
            channels: w.channels.clone(),
            human_pubkeys: w.human_pubkeys.clone(),
            repos: vec![],
            git_helper: w.git_helper.clone(),
            out_dir: w.out_dir.clone(),
            blink: false,
            mentions: w.mentions.clone(),
            seqs: Default::default(),
        });
        sess
    }

    /// An event that tags `pubkey`, made `created_at`.
    fn p_event(pubkey: &str, created_at: u64) -> nostr::Event {
        nostr::EventBuilder::new(nostr::Kind::Custom(9), "hi")
            .tags([Tag::parse(["p", pubkey]).expect("tag")])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&Keys::generate())
            .expect("sign")
    }

    /// The `#p` filters a relay was sent, by subscription id.
    fn p_reqs(log: &admission::testrelay::ReqLog, name: &str) -> Vec<serde_json::Value> {
        log.lock()
            .expect("log")
            .iter()
            .filter(|(sid, _)| *sid == format!("{name}-p"))
            .map(|(_, f)| f.clone())
            .collect()
    }

    /// The warm-up's `#p` subscription is exactly `#p` and `since` (its
    /// start): no kinds, no limit, no history query. What it returns is
    /// never counted as backfill. The channel subscriptions are unchanged.
    #[tokio::test]
    async fn the_warmup_p_subscription_starts_at_its_since() {
        let stats = Arc::new(Stats::new());
        let sess = test_session(stats.clone());
        let pk = sess.rec.pubkey.clone();
        let (url, log) = admission::testrelay::req_logging_relay(vec![
            p_event(&pk, 1_700_000_000),
            p_event(&pk, 1_700_000_100),
        ])
        .await;
        let mut client = BuzzTestClient::connect(&url, &sess.keys)
            .await
            .expect("connect");
        let returned = subscribe_all(
            &mut client,
            &sess.rec.name,
            &pk,
            &sess.world.channels,
            &sess.sub_kinds(),
            50,
            &stats,
            true,
            None,
            1_790_000_000,
            EosePolicy::Required,
        )
        .await
        .expect("subscribed");
        assert_eq!(
            returned, 0,
            "the #p subscription's events counted as backfill"
        );
        assert_eq!(
            p_reqs(&log, &sess.rec.name),
            vec![serde_json::json!([{"#p": [pk], "since": 1_790_000_000u64}])]
        );
        let ch = log
            .lock()
            .expect("log")
            .iter()
            .find(|(sid, _)| *sid == format!("{}-ch0", sess.rec.name))
            .map(|(_, f)| f.clone())
            .expect("channel REQ");
        assert!(ch[0].get("since").is_none(), "{ch}");
        assert_eq!(
            (ch[0]["#h"][0].as_str(), ch[0]["limit"].as_u64()),
            (Some("chan-a"), Some(50))
        );
    }

    /// A reconnect resubscribes `#p` as the desktop's replay does: from the
    /// subscription's own start, or the newest event seen on it less 5 s,
    /// whichever is later. An event on a channel subscription doesn't move
    /// it, nor does one older than the start. Each reconnect tells a human's
    /// home-feed poller, which polls on it.
    #[tokio::test]
    async fn a_reconnect_resubscribes_p_as_the_desktop_replays() {
        let (url, log) = admission::testrelay::req_logging_relay(vec![]).await;
        let stats = Arc::new(Stats::new());
        let mut sess = session_on(stats, &url);
        let name = sess.rec.name.clone();
        let pk = sess.rec.pubkey.clone();
        sess.p_since = 1_790_000_000;
        // A human: its home-feed poller hears each reconnect.
        let link = feed::Link::new();
        link.up();
        sess.feed_link = Some(link.clone());
        let on = |sid: &str, t: u64| RelayMessage::Event {
            subscription_id: sid.to_string(),
            event: Box::new(p_event(&pk, t)),
        };
        // (what came in on which subscription, the since a reconnect sends)
        let rows: [(Option<(String, u64)>, u64); 4] = [
            (None, 1_790_000_000),
            (Some((format!("{name}-ch0"), 1_790_000_900)), 1_790_000_000),
            (Some((format!("{name}-p"), 1_789_999_000)), 1_790_000_000),
            (Some((format!("{name}-p"), 1_790_000_500)), 1_790_000_495),
        ];
        for (i, (msg, want)) in rows.into_iter().enumerate() {
            if let Some((sid, t)) = msg {
                sess.handle_msg(Band::Warmup, on(&sid, t)).await;
            }
            let client = sess
                .reconnect("test", 50, false, false, None)
                .await
                .expect("reconnect")
                .expect("a client");
            let _ = client.disconnect().await;
            assert!(
                *link.connected.borrow(),
                "row {i}: the poller wasn't told it's back"
            );
            tokio::time::timeout(Duration::from_millis(100), link.healed.notified())
                .await
                .unwrap_or_else(|_| panic!("row {i}: the poller wasn't told of the reconnect"));
            let reqs = p_reqs(&log, &name);
            assert_eq!(reqs.len(), i + 1, "row {i}");
            assert_eq!(
                reqs[i],
                serde_json::json!([{"#p": [pk.clone()], "since": want}]),
                "row {i}"
            );
        }
    }

    /// A joiner takes each author's last accepted `seq` at its subscribe as
    /// its baseline: the author then sends 38 and 39, both lost, and the
    /// joiner first sees 40: it counts both. An identity on from the start
    /// (an empty board) counts from 1.
    #[tokio::test]
    async fn a_joiner_counts_what_was_lost_after_it_subscribed() {
        let author = "someone";
        let msg = |n: u64| {
            let ev = nostr::EventBuilder::new(nostr::Kind::Custom(9), "hi")
                .tags([
                    Tag::parse(["h", "chan-a"]).expect("tag"),
                    Tag::parse(["seq", &format!("{author}-{n}")]).expect("tag"),
                ])
                .sign_with_keys(&Keys::generate())
                .expect("sign");
            RelayMessage::Event {
                subscription_id: "x-ch0".into(),
                event: Box::new(ev),
            }
        };
        let stats = Arc::new(Stats::new());
        let mut joiner = test_session(stats.clone());
        joiner.world.seqs.set(author, 37);
        joiner.take_baseline();
        // The author's 38 and 39 are accepted, and never reach the joiner.
        joiner.world.seqs.set(author, 39);
        joiner.handle_msg(Band::Steady, msg(40)).await;
        let mut missing: Vec<String> = joiner.missing.iter().cloned().collect();
        missing.sort();
        assert_eq!(missing, [format!("{author}-38"), format!("{author}-39")]);
        // From the start: an empty board, every author from 1.
        let mut first = test_session(stats);
        first.take_baseline();
        first.handle_msg(Band::Steady, msg(3)).await;
        assert_eq!(first.missing.len(), 2, "1 and 2 are gaps");
    }

    /// A channel message the relay accepted sets its author's last `seq`
    /// on the board; one it rejected doesn't.
    #[tokio::test]
    async fn an_accepted_message_moves_the_seq_board() {
        use crate::sim::admission::testrelay::{relay_with, Answer};
        fn accept(_: u64) -> Answer {
            Answer::Accept
        }
        fn reject(_: u64) -> Answer {
            Answer::Reject("blocked: test")
        }
        for (answer, want) in [(accept as fn(u64) -> Answer, Some(1u64)), (reject, None)] {
            let relay = relay_with(answer).await;
            let mut sess = test_session(Arc::new(Stats::new()));
            let mut client = BuzzTestClient::connect_unauthenticated(&relay.url)
                .await
                .expect("connect");
            let (keys, k, name) = (sess.keys.clone(), sess.profile.kinds, sess.rec.name.clone());
            sess.send_channel(&mut client, Band::Steady, |seq| {
                kinds::stream_message(&keys, &k, "chan-a", &name, seq, "hi", None)
            })
            .await
            .expect("send");
            assert_eq!(sess.world.seqs.snapshot().get(&name).copied(), want);
        }
    }

    /// C: each live mention a human gets starts a whole home-feed poll at
    /// once, beside any in flight (no coalescing). An event on `#p` that
    /// isn't a message kind, one on a channel subscription, and an agent's
    /// mention start none.
    #[tokio::test]
    async fn a_live_mention_starts_a_poll_at_once() {
        fn none(_: &serde_json::Value) -> (u16, String) {
            (200, "[]".into())
        }
        // Each answer comes 3 s late, so two polls overlap if both start.
        let (http, log) = feed::testhttp::logging_server(none, Duration::from_secs(3)).await;
        let stats = Arc::new(Stats::new());
        let mut sess = test_session_at(stats.clone(), &http);
        sess.feed_link = Some(feed::Link::new());
        let name = sess.rec.name.clone();
        let me = sess.rec.pubkey.clone();
        let other = Keys::generate();
        let ev = |kind: u16| {
            Box::new(
                nostr::EventBuilder::new(nostr::Kind::Custom(kind), "hi")
                    .tags([Tag::parse(["p", &me]).expect("tag")])
                    .sign_with_keys(&other)
                    .expect("sign"),
            )
        };
        for (sid, kind) in [
            (format!("{name}-p"), 9u16),
            (format!("{name}-p"), 40002),
            (format!("{name}-p"), 1059),
            (format!("{name}-ch0"), 9),
        ] {
            let event = ev(kind);
            sess.handle_msg(
                Band::Steady,
                RelayMessage::Event {
                    subscription_id: sid,
                    event,
                },
            )
            .await;
        }
        let mentions_queries = || {
            log.lock()
                .expect("log")
                .iter()
                .filter(|b| b[0]["limit"] == 50 && b[0]["#p"].is_array())
                .count()
        };
        let started = Instant::now();
        while mentions_queries() < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "two polls didn't start at once"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            mentions_queries(),
            2,
            "a poll per message-kind mention, no more"
        );
        // An agent's desktop doesn't poll: no link, no poll.
        let mut agent = test_session_at(stats.clone(), &http);
        agent.feed_link = None;
        let aname = agent.rec.name.clone();
        let event = ev(9);
        agent
            .handle_msg(
                Band::Steady,
                RelayMessage::Event {
                    subscription_id: format!("{aname}-p"),
                    event,
                },
            )
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(mentions_queries(), 2);
    }

    /// An identity that joined, then failed or panicked while the run
    /// wasn't stopping, is in live.json's `identities_ended` at once, with
    /// why. One that never joined (reported through `ready`), one that
    /// ended on a stop, or one that ended cleanly, is not.
    #[tokio::test]
    async fn an_identity_that_ends_on_its_own_is_recorded_at_once() {
        use std::sync::atomic::{AtomicBool, Ordering};
        type Task = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;
        fn fails(joined: &Arc<AtomicBool>) -> Task {
            let j = joined.clone();
            Box::pin(async move {
                j.store(true, Ordering::SeqCst);
                Err(anyhow!("kind 9 sign: no key"))
            })
        }
        fn panics(joined: &Arc<AtomicBool>) -> Task {
            let j = joined.clone();
            Box::pin(async move {
                j.store(true, Ordering::SeqCst);
                panic!("a bug")
            })
        }
        fn never_joins(_: &Arc<AtomicBool>) -> Task {
            Box::pin(async move { Err(anyhow!("h1 subscribe: no EOSE")) })
        }
        fn clean(joined: &Arc<AtomicBool>) -> Task {
            let j = joined.clone();
            Box::pin(async move {
                j.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
        type Row = (
            &'static str,
            fn(&Arc<AtomicBool>) -> Task,
            Band,
            Option<&'static str>,
        );
        let rows: [Row; 5] = [
            ("failed", fails, Band::Steady, Some("kind 9 sign: no key")),
            ("panicked", panics, Band::Steady, Some("h7's task panicked")),
            ("failed on a stop", fails, Band::Stop, None),
            ("never joined", never_joins, Band::Steady, None),
            ("ended cleanly", clean, Band::Steady, None),
        ];
        for (name, task, band, want) in rows {
            let stats = Stats::new();
            let joined = Arc::new(AtomicBool::new(false));
            let (_tx, stop) = watch::channel(band);
            let res = guard_identity("h7", &joined, &stop, &stats, task(&joined)).await;
            assert_eq!(res.is_err(), name != "ended cleanly", "{name}");
            let ended = stats.live(1).identities_ended;
            match want {
                Some(why) => assert_eq!(
                    ended,
                    std::collections::BTreeMap::from([("h7".to_string(), why.to_string())]),
                    "{name}"
                ),
                None => assert!(ended.is_empty(), "{name}: {ended:?}"),
            }
        }
    }

    /// One counter per send, never two and never none: accepted, rejected,
    /// written and never answered (no OK in time, or the socket failing
    /// after the write), not written at all (the socket already closed),
    /// and each `rate-limited:` text: the quota apart, the relay full or
    /// unable to admit shed, any other text unknown.
    #[tokio::test]
    async fn each_send_ends_in_exactly_one_counter() {
        use crate::sim::admission::testrelay::{relay_with, Answer};
        fn accept(_: u64) -> Answer {
            Answer::Accept
        }
        fn reject(_: u64) -> Answer {
            Answer::Reject("blocked: test")
        }
        fn silent(_: u64) -> Answer {
            Answer::Silent
        }
        fn close(_: u64) -> Answer {
            Answer::Close
        }
        fn quota(_: u64) -> Answer {
            Answer::Notice("rate-limited: quota exceeded; retry in 7s")
        }
        fn full(_: u64) -> Answer {
            Answer::Notice("rate-limited: too many concurrent requests")
        }
        fn no_admission(_: u64) -> Answer {
            Answer::Notice("rate-limited: shared admission unavailable")
        }
        fn unknown(_: u64) -> Answer {
            Answer::Notice("rate-limited: slow down")
        }
        // (accepted, rejected, rate_limited, send_unanswered, send_failed,
        // relay_shed, limit_unknown)
        type Row = (
            &'static str,
            fn(u64) -> Answer,
            bool,
            (u64, u64, u64, u64, u64, u64, u64),
        );
        let rows: [Row; 9] = [
            ("accepted", accept, false, (1, 0, 0, 0, 0, 0, 0)),
            ("rejected", reject, false, (0, 1, 0, 0, 0, 0, 0)),
            ("no OK in time", silent, false, (0, 0, 0, 1, 0, 0, 0)),
            (
                "the socket fails after the write",
                close,
                false,
                (0, 0, 0, 1, 0, 0, 0),
            ),
            (
                "the socket already closed",
                accept,
                true,
                (0, 0, 0, 0, 1, 0, 0),
            ),
            ("the quota", quota, false, (0, 0, 1, 0, 0, 0, 0)),
            ("the relay full", full, false, (0, 0, 0, 0, 0, 1, 0)),
            (
                "the relay's admission store unreachable",
                no_admission,
                false,
                (0, 0, 0, 0, 0, 1, 0),
            ),
            ("an unknown limit", unknown, false, (0, 0, 0, 0, 0, 0, 1)),
        ];
        for (name, answer, closed_first, want) in rows {
            let relay = relay_with(answer).await;
            let stats = Arc::new(Stats::new());
            let mut sess = test_session(stats.clone());
            sess.ok_timeout = Duration::from_millis(500);
            let mut client = BuzzTestClient::connect_unauthenticated(&relay.url)
                .await
                .expect("connect");
            if closed_first {
                relay.kill();
                // Read until the close is seen: the socket is then closed on
                // this side too, and nothing more can be written.
                let started = Instant::now();
                loop {
                    match client.recv_event(Duration::from_millis(200)).await {
                        Ok(_) => continue,
                        Err(TestClientError::Timeout) => {
                            assert!(
                                started.elapsed() < Duration::from_secs(5),
                                "{name}: never closed"
                            );
                        }
                        Err(_) => break,
                    }
                }
            }
            let ev = kinds::presence(&sess.keys, &sess.profile.kinds).expect("event");
            sess.send(&mut client, Band::Steady, ev).await;
            let live = stats.live(1);
            let failed = live.client_errors.get("send_failed").copied().unwrap_or(0);
            assert_eq!(
                (
                    live.accepted,
                    live.rejected,
                    live.rate_limited,
                    live.send_unanswered,
                    failed,
                    live.relay_shed,
                    live.limit_unknown.values().sum::<u64>()
                ),
                want,
                "{name}"
            );
            if want.6 > 0 {
                assert_eq!(
                    live.limit_unknown,
                    std::collections::BTreeMap::from([("rate-limited: slow down".to_string(), 1)]),
                    "{name}: the text is kept"
                );
            }
            assert_eq!(live.sent, 1, "{name}: the send counted once");
            // The band's line in summary.json, by the names a local run's
            // acceptance reads (tenant_cogs.py client_from_summary).
            let summary = stats.summarize("p", 1, "ws://x", 1, 1, &HashMap::new());
            let band = serde_json::to_value(&summary.bands["steady"]).expect("band json");
            assert_eq!(
                (
                    band["sent"].as_u64(),
                    band["unanswered"].as_u64(),
                    band["failed"].as_u64(),
                    band["shed"].as_u64(),
                    band["limit_unknown"].as_u64()
                ),
                (
                    Some(1),
                    Some(want.3),
                    Some(want.4),
                    Some(want.5),
                    Some(want.6)
                ),
                "{name}"
            );
        }
    }

    /// A send the relay's per-key rate limiter turns away during a band
    /// (a NOTICE, no OK) is counted as rate-limited: not rejected, and not a
    /// send that failed, which the sampler would read as the generator's
    /// own error and void on.
    #[tokio::test]
    async fn a_rate_limited_send_in_a_band_is_counted_apart() {
        let url = fake_relay(vec![
            r#"["NOTICE","rate-limited: quota exceeded; retry in 7s"]"#.to_string(),
        ])
        .await;
        let stats = Arc::new(Stats::new());
        let mut sess = test_session(stats.clone());
        let mut client = BuzzTestClient::connect_unauthenticated(&url)
            .await
            .expect("connect");
        let ev = kinds::presence(&sess.keys, &sess.profile.kinds).expect("event");
        let started = Instant::now();
        assert!(!sess.send(&mut client, Band::Steady, ev).await);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the send waited out the OK window"
        );
        let live = stats.live(1);
        assert_eq!(
            (live.sent, live.accepted, live.rejected, live.rate_limited),
            (1, 0, 0, 1)
        );
        assert!(live.client_errors.is_empty(), "{:?}", live.client_errors);
    }

    #[test]
    fn repo_owners_carry_the_populations_pushes() {
        // 20 agents, 2 repos: each owner pushes at 10x the per-agent rate.
        assert_eq!(git_push_scale(20, 2, true), 10.0);
        assert_eq!(git_push_scale(20, 2, false), 0.0);
        assert_eq!(git_push_scale(20, 0, true), 0.0);
        let total = 2.0 * git_push_scale(20, 2, true) + 18.0 * git_push_scale(20, 2, false);
        assert_eq!(total, 20.0);
    }

    #[test]
    fn reactions_target_channel_events_only() {
        let mut seen = VecDeque::new();
        seen.push_back(("chan-msg".to_string(), "chan-a".to_string()));
        // Newest is a #p event (DM or turn metric): no channel.
        seen.push_back(("p-event".to_string(), String::new()));
        assert_eq!(
            reaction_target(&seen),
            Some(("chan-msg".to_string(), "chan-a".to_string()))
        );
        let only_p: VecDeque<_> = [("p-event".to_string(), String::new())].into();
        assert_eq!(reaction_target(&only_p), None);
    }

    #[test]
    fn stop_is_seen_after_the_band_reader_exits() {
        let (tx, mut rx) = watch::channel(Band::Cooldown);
        tx.send(Band::Stop).expect("send stop");
        drop(tx);
        // What the loop used to check: a closed channel reads as "no change",
        // so no identity ever saw Stop and tenant_sim never exited.
        assert!(!rx.has_changed().unwrap_or(false));
        assert_eq!(next_band(&mut rx, Band::Cooldown), Some(Band::Stop));
        assert_eq!(next_band(&mut rx, Band::Stop), None);
    }

    #[test]
    fn open_channel_reports_each_change_once() {
        let (tx, mut rx) = watch::channel(Band::Warmup);
        assert_eq!(next_band(&mut rx, Band::Warmup), None);
        tx.send(Band::Floor).expect("send floor");
        assert_eq!(next_band(&mut rx, Band::Warmup), Some(Band::Floor));
        assert_eq!(next_band(&mut rx, Band::Floor), None);
    }

    #[test]
    fn warmup_eose_timeout_propagates() {
        let err = apply_eose(
            "h0",
            "ch0",
            EosePolicy::Required,
            Err(TestClientError::Timeout),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("warm-up EOSE failed"), "{msg}");
        assert!(msg.contains("h0"), "{msg}");
        assert!(msg.contains("ch0"), "{msg}");
    }

    #[test]
    fn warmup_eose_error_on_p_filter_propagates() {
        let err = apply_eose(
            "a3",
            "#p",
            EosePolicy::Required,
            Err(TestClientError::Timeout),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("#p"), "{msg}");
    }

    #[test]
    fn reconnect_eose_timeout_is_tolerant() {
        let n = apply_eose(
            "h0",
            "ch0",
            EosePolicy::Tolerant,
            Err(TestClientError::Timeout),
        )
        .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn successful_eose_counts_events() {
        let n = apply_eose("h0", "ch0", EosePolicy::Required, Ok(vec![])).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn global_git_kinds_must_not_consume_channel_seq() {
        let k = kinds::sample_kinds();
        assert!(kinds::is_global_git_kind(k.issue, &k));
        assert!(kinds::is_global_git_kind(k.pr, &k));
        assert!(!kinds::is_global_git_kind(k.msg, &k));
    }
}
