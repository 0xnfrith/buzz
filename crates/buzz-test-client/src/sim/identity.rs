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

use super::git::{self, GitRepo};
use super::guard::{self, Target};
use super::kinds;
use super::media;
use super::profile::{Profile, Rates};
use super::roles::{
    in_active_window, next_any_wait, pick_action, rng_f64, rng_usize, scaled_rates, Band, Role,
};
use super::stats::Stats;

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

fn filter_p(pubkey: &str) -> Filter {
    Filter::new().custom_tags(SingleLetterTag::lowercase(Alphabet::P), [pubkey])
}

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
    client.subscribe(&sid, vec![filter_p(pubkey)]).await?;
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
    expected: HashMap<String, u64>,
    missing: HashSet<String>,
    last_seen_created_at: u64,
    git_repo: Option<GitRepo>,
    http: guard::HttpClient,
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
        if let RelayMessage::Event { event, .. } = msg {
            self.last_seen_created_at = self.last_seen_created_at.max(event.created_at.as_secs());
            let channel = tag_value(&event, "h").unwrap_or_default();
            self.seen.push_back((event.id.to_hex(), channel.clone()));
            if self.seen.len() > 64 {
                self.seen.pop_front();
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
        match client.send_event(event.clone()).await {
            Ok(ok) => {
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
            Err(e) => {
                if band.sampled() {
                    self.stats
                        .record_send(band.as_str(), kind, false, &e.to_string(), 0.0);
                }
                self.stats.record_client_error("send_failed");
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
                self.send_channel(client, band, |seq| {
                    let content = kinds::lorem(seq, 200);
                    kinds::stream_message(&keys, &k, &ch, &name, seq, &content)
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
                        self.stats.record_media(true, up.bytes, up.put_ms);
                        let content = format!("media {}", up.url);
                        self.send_channel(client, band, |seq| {
                            kinds::stream_message(&keys, &k, &ch, &name, seq, &content)
                        })
                        .await?;
                    }
                    Err(e) => {
                        warn!("{} media: {e}", self.rec.name);
                        self.stats.record_media(false, 0, 0.0);
                    }
                }
            }
            "git_push" => {
                if let Some(repo) = self.git_repo.as_ref() {
                    let lo = self.profile.git.push_kb[0];
                    let hi = *self.profile.git.push_kb.last().unwrap_or(&lo);
                    let kb = lo + (rng_f64(&mut self.rng) * (hi.saturating_sub(lo) as f64)) as u64;
                    let mut blob = vec![0u8; (kb * 1024).max(1) as usize];
                    self.rng.fill(blob.as_mut_slice());
                    let git_seq = self.seq + 1;
                    match git::push_blob(repo, &self.world.git_helper, &blob, git_seq) {
                        Ok((bytes, ms)) => self.stats.record_git(true, bytes, ms),
                        Err(e) => {
                            warn!("{} git push: {e}", self.rec.name);
                            self.stats.record_git(false, 0, 0.0);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
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

    async fn reconnect(
        &mut self,
        reason: &str,
        limit: u32,
        record_join: bool,
        storm_ms: bool,
        since: Option<u64>,
    ) -> Result<BuzzTestClient> {
        info!("{} reconnect ({reason})", self.rec.name);
        let mut delay = Duration::from_millis(250);
        let cap = Duration::from_secs(5);
        loop {
            match connect_identity(
                &self.world.relay_url,
                &self.rec,
                &self.keys,
                self.oa_owner.as_ref(),
            )
            .await
            {
                Ok(mut client) => {
                    let start = Instant::now();
                    let n = subscribe_all(
                        &mut client,
                        &self.rec.name,
                        &self.rec.pubkey,
                        &self.world.channels,
                        &self.sub_kinds(),
                        limit,
                        &self.stats,
                        record_join,
                        since,
                        EosePolicy::Tolerant,
                    )
                    .await
                    .unwrap_or(0);
                    if storm_ms {
                        self.stats.record_storm_backfill(
                            "peak",
                            start.elapsed().as_secs_f64() * 1e3,
                            n,
                        );
                    }
                    return Ok(client);
                }
                Err(e) => {
                    self.stats.record_client_error("reconnect_failed");
                    warn!("{} reconnect failed: {e}", self.rec.name);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(cap);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_identity(
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
) -> Result<()> {
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
        expected: HashMap::new(),
        missing: HashSet::new(),
        last_seen_created_at: unix_now(),
        git_repo,
        http: guard::http_client(Duration::from_secs(30))?,
    };

    let mut client = match connect_identity(
        &sess.world.relay_url,
        &sess.rec,
        &sess.keys,
        sess.oa_owner.as_ref(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{} connect: {e:#}", sess.rec.name);
            let _ = ready.send(Err(msg.clone())).await;
            return Err(anyhow!(msg));
        }
    };
    if let Err(e) = subscribe_all(
        &mut client,
        &sess.rec.name,
        &sess.rec.pubkey,
        &sess.world.channels,
        &sess.sub_kinds(),
        sess.profile.human.backfill_limit,
        &sess.stats,
        true,
        None,
        EosePolicy::Required,
    )
    .await
    {
        let msg = format!("{} subscribe: {e:#}", sess.rec.name);
        let _ = ready.send(Err(msg.clone())).await;
        return Err(anyhow!(msg));
    }
    if ready.send(Ok(())).await.is_err() {
        return Ok(());
    }

    let mut band = *band_rx.borrow();
    let mut band_started = Instant::now();
    let mut band_unix = unix_now();
    let mut next_action = Instant::now();
    let mut stormed = false;
    let mut blink_closes: Vec<u64> = Vec::new();

    loop {
        if let Some(new_band) = next_band(&mut band_rx, band) {
            if band.sampled() {
                sess.gap_recheck(&mut client, band_unix).await;
            }
            band = new_band;
            band_started = Instant::now();
            band_unix = unix_now();
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
            tokio::time::sleep(stagger).await;
            let _ = client.disconnect().await;
            client = sess
                .reconnect(
                    "storm",
                    sess.profile.storm.backfill_limit,
                    false,
                    true,
                    None,
                )
                .await?;
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
                    client = sess
                        .reconnect(
                            "blink",
                            sess.profile.human.backfill_limit,
                            false,
                            false,
                            Some(since),
                        )
                        .await?;
                } else if is_closed {
                    sess.stats.record_client_error("connection_dropped");
                    warn!("{} connection dropped: {s}", sess.rec.name);
                    client = sess
                        .reconnect(
                            "drop",
                            sess.profile.human.backfill_limit,
                            false,
                            false,
                            None,
                        )
                        .await?;
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
