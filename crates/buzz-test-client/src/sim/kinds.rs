//! Event builders for the kinds the population emits.

use anyhow::{anyhow, Context, Result};
use buzz_core::agent_turn_metric::{
    encrypt_agent_turn_metric, AgentTurnMetricPayload, StopReason, TokenCounts,
};
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};

use super::profile::KindTable;

const LOREM: &str = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat";

pub fn kind(k: u16) -> Kind {
    Kind::Custom(k)
}

pub fn tag(values: &[&str]) -> Result<Tag> {
    Tag::parse(values.iter().copied()).context("tag parse")
}

pub fn lorem(seq: u64, target_bytes: usize) -> String {
    let mut out = format!("seq-{seq} ");
    while out.len() < target_bytes {
        out.push_str(LOREM);
        out.push(' ');
    }
    out.truncate(target_bytes);
    out
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn seq_tags(identity: &str, seq: u64, extra: Vec<Tag>) -> Result<Vec<Tag>> {
    let mut tags = extra;
    tags.push(tag(&["seq", &format!("{identity}-{seq}")])?);
    tags.push(tag(&["ts_ms", &now_ms().to_string()])?);
    Ok(tags)
}

pub fn stream_message(
    keys: &Keys,
    kinds: &KindTable,
    channel: &str,
    identity: &str,
    seq: u64,
    content: &str,
) -> Result<Event> {
    let tags = seq_tags(identity, seq, vec![tag(&["h", channel])?])?;
    Ok(EventBuilder::new(kind(kinds.msg), content)
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn typing(keys: &Keys, kinds: &KindTable, channel: &str) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.typing), "")
        .tags([tag(&["h", channel])?])
        .sign_with_keys(keys)?)
}

pub fn presence(keys: &Keys, kinds: &KindTable) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.presence), "{\"status\":\"online\"}").sign_with_keys(keys)?)
}

pub fn reaction(
    keys: &Keys,
    kinds: &KindTable,
    channel: &str,
    target: &str,
    identity: &str,
    seq: u64,
) -> Result<Event> {
    let tags = seq_tags(
        identity,
        seq,
        vec![tag(&["h", channel])?, tag(&["e", target])?],
    )?;
    Ok(EventBuilder::new(kind(kinds.reaction), "+")
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn edit(
    keys: &Keys,
    kinds: &KindTable,
    channel: &str,
    target: &str,
    identity: &str,
    seq: u64,
    content: &str,
) -> Result<Event> {
    let tags = seq_tags(
        identity,
        seq,
        vec![tag(&["h", channel])?, tag(&["e", target])?],
    )?;
    Ok(EventBuilder::new(kind(kinds.edit), content)
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn canvas(
    keys: &Keys,
    kinds: &KindTable,
    channel: &str,
    identity: &str,
    seq: u64,
) -> Result<Event> {
    let content = lorem(seq, 2048);
    let tags = seq_tags(identity, seq, vec![tag(&["h", channel])?])?;
    Ok(EventBuilder::new(kind(kinds.canvas), &content)
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn turn_metric(
    keys: &Keys,
    kinds: &KindTable,
    owner_hex: &str,
    channel: &str,
    turn_seq: u64,
) -> Result<Event> {
    let owner = PublicKey::from_hex(owner_hex).context("owner pubkey")?;
    let payload = AgentTurnMetricPayload {
        harness: "tenant-sim".to_string(),
        model: Some("sim".to_string()),
        channel_id: Some(channel.to_string()),
        session_id: None,
        turn_id: Some(format!("t-{turn_seq}")),
        turn_seq: Some(turn_seq),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        turn: Some(TokenCounts {
            input_tokens: Some(32),
            output_tokens: Some(8),
            total_tokens: Some(40),
            cost_usd: Some(0.0),
            cache_read_tokens: None,
            cache_write_tokens: None,
        }),
        cumulative: None,
        delta_reliable: true,
        stop_reason: Some(StopReason::EndTurn),
        pricing_identity: None,
    };
    let ciphertext = encrypt_agent_turn_metric(keys, &owner, &payload)
        .map_err(|e| anyhow!("encrypt kind 44200: {e}"))?;
    let agent_hex = keys.public_key().to_hex();
    Ok(EventBuilder::new(kind(kinds.turn_metric), ciphertext)
        .tags([tag(&["p", owner_hex])?, tag(&["agent", &agent_hex])?])
        .sign_with_keys(keys)?)
}

pub fn gift_wrap(keys: &Keys, kinds: &KindTable, recipient: &str, content: &str) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.dm), content)
        .tags([tag(&["p", recipient])?])
        .sign_with_keys(keys)?)
}

pub fn issue(
    keys: &Keys,
    kinds: &KindTable,
    repo_a: &str,
    repo_owner: &str,
    identity: &str,
    seq: u64,
) -> Result<Event> {
    let subject = format!("{identity} issue {seq}");
    let content = lorem(seq, 180);
    let tags = seq_tags(
        identity,
        seq,
        vec![
            tag(&["a", repo_a])?,
            tag(&["p", repo_owner])?,
            tag(&["subject", &subject])?,
        ],
    )?;
    Ok(EventBuilder::new(kind(kinds.issue), &content)
        .tags(tags)
        .sign_with_keys(keys)?)
}

#[allow(clippy::too_many_arguments)]
pub fn pull_request(
    keys: &Keys,
    kinds: &KindTable,
    repo_a: &str,
    repo_owner: &str,
    channel: &str,
    clone_url: &str,
    commit: &str,
    identity: &str,
    seq: u64,
) -> Result<Event> {
    let subject = format!("{identity} pr {seq}");
    let content = lorem(seq, 180);
    let tags = seq_tags(
        identity,
        seq,
        vec![
            tag(&["a", repo_a])?,
            tag(&["p", repo_owner])?,
            tag(&["subject", &subject])?,
            tag(&["c", commit])?,
            tag(&["clone", clone_url])?,
            tag(&["h", channel])?,
        ],
    )?;
    Ok(EventBuilder::new(kind(kinds.pr), &content)
        .tags(tags)
        .sign_with_keys(keys)?)
}

pub fn channel_create(
    keys: &Keys,
    kinds: &KindTable,
    channel_id: &str,
    name: &str,
) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.channel_create), "")
        .tags([
            tag(&["h", channel_id])?,
            tag(&["name", name])?,
            tag(&["channel_type", "stream"])?,
            tag(&["visibility", "open"])?,
        ])
        .sign_with_keys(keys)?)
}

pub fn member_add(keys: &Keys, kinds: &KindTable, channel_id: &str, pubkey: &str) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.member_add), "")
        .tags([tag(&["h", channel_id])?, tag(&["p", pubkey])?])
        .sign_with_keys(keys)?)
}

pub fn relay_member_add(keys: &Keys, kinds: &KindTable, pubkey: &str) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.relay_member_add), "")
        .tags([tag(&["p", pubkey])?, tag(&["role", "member"])?])
        .sign_with_keys(keys)?)
}

pub fn repo_announce(
    keys: &Keys,
    kinds: &KindTable,
    repo: &str,
    name: &str,
    channel: &str,
) -> Result<Event> {
    Ok(EventBuilder::new(kind(kinds.repo_announce), "")
        .tags([
            tag(&["d", repo])?,
            tag(&["name", name])?,
            tag(&["buzz-channel", channel])?,
        ])
        .sign_with_keys(keys)?)
}

pub fn timestamp_now() -> Timestamp {
    Timestamp::now()
}
