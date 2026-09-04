//! Profile TOML loader and validation.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

/// Loaded, validated simulation profile.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub seed: u64,
    pub humans: u32,
    pub agents_per_human: u32,
    pub channels: u32,
    pub repos: u32,
    pub bands: Bands,
    pub human: HumanRole,
    pub agent: AgentRole,
    pub storm: Storm,
    pub media: MediaMix,
    pub git: GitMix,
    pub kinds: KindTable,
    pub source_path: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Bands {
    pub warmup: u64,
    pub floor: u64,
    pub steady: u64,
    pub peak: u64,
    pub cooldown: u64,
}

#[derive(Debug, Clone)]
pub struct HumanRole {
    pub backfill_limit: u32,
    pub presence_interval_s: u64,
    pub typing_before_msg_prob: f64,
    pub burst_len_s: u64,
    pub burst_gap_s: u64,
    pub rates: Rates,
    pub peak_multiplier: f64,
}

#[derive(Debug, Clone)]
pub struct AgentRole {
    pub nip_oa: bool,
    pub active_s: u64,
    pub idle_s: u64,
    pub rates: Rates,
    pub peak_multiplier: f64,
    pub peak_all_active: bool,
}

#[derive(Debug, Clone)]
pub struct Storm {
    pub enabled: bool,
    pub at_band: String,
    pub joiners: String,
    pub stagger_s: u64,
    pub backfill_limit: u32,
}

#[derive(Debug, Clone)]
pub struct MediaMix {
    pub sizes_kb: Vec<u64>,
    pub weights: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct GitMix {
    pub push_kb: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct KindTable {
    pub msg: u16,
    pub reaction: u16,
    pub edit: u16,
    pub canvas: u16,
    pub issue: u16,
    pub pr: u16,
    pub repo_announce: u16,
    pub turn_metric: u16,
    pub presence: u16,
    pub typing: u16,
    pub dm: u16,
    pub member_add: u16,
    pub channel_create: u16,
    pub relay_member_add: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Rates {
    pub msg: f64,
    pub reaction: f64,
    pub edit: f64,
    pub media: f64,
    pub dm: f64,
    pub canvas: f64,
    pub issue: f64,
    pub pr: f64,
    pub git_push: f64,
    pub turn_metric: f64,
    pub presence: f64,
}

impl Rates {
    pub fn get(&self, name: &str) -> f64 {
        match name {
            "msg" => self.msg,
            "reaction" => self.reaction,
            "edit" => self.edit,
            "media" => self.media,
            "dm" => self.dm,
            "canvas" => self.canvas,
            "issue" => self.issue,
            "pr" => self.pr,
            "git_push" => self.git_push,
            "turn_metric" => self.turn_metric,
            "presence" => self.presence,
            _ => 0.0,
        }
    }

    pub fn entries(&self) -> Vec<(&'static str, f64)> {
        vec![
            ("msg", self.msg),
            ("reaction", self.reaction),
            ("edit", self.edit),
            ("media", self.media),
            ("dm", self.dm),
            ("canvas", self.canvas),
            ("issue", self.issue),
            ("pr", self.pr),
            ("git_push", self.git_push),
            ("turn_metric", self.turn_metric),
            ("presence", self.presence),
        ]
        .into_iter()
        .filter(|(_, v)| *v > 0.0)
        .collect()
    }
}

impl Profile {
    pub fn agent_count(&self) -> u32 {
        self.humans * self.agents_per_human
    }

    pub fn identity_count(&self) -> u32 {
        self.humans + self.agent_count()
    }

    /// Expected events per identity per band, used by `--check`.
    pub fn event_budget(&self) -> BTreeMap<String, BTreeMap<String, BTreeMap<String, f64>>> {
        let mut out = BTreeMap::new();
        for band in ["floor", "steady", "peak"] {
            let mut roles = BTreeMap::new();
            roles.insert("human".into(), self.budget_for("human", band));
            roles.insert("agent".into(), self.budget_for("agent", band));
            out.insert(band.to_string(), roles);
        }
        out
    }

    fn budget_for(&self, role: &str, band: &str) -> BTreeMap<String, f64> {
        let (rates, multiplier, duty, seconds) = match (role, band) {
            ("human", "floor") => (
                Rates {
                    presence: 3600.0 / self.human.presence_interval_s.max(1) as f64,
                    ..Rates::default()
                },
                1.0,
                1.0,
                self.bands.floor as f64,
            ),
            ("human", "steady") => {
                let duty = self.human.burst_len_s as f64
                    / (self.human.burst_len_s + self.human.burst_gap_s).max(1) as f64;
                (
                    self.human.rates.clone(),
                    1.0,
                    duty,
                    self.bands.steady as f64,
                )
            }
            ("human", "peak") => (
                self.human.rates.clone(),
                self.human.peak_multiplier,
                1.0,
                self.bands.peak as f64,
            ),
            ("agent", "floor") => (
                Rates {
                    presence: self.agent.rates.presence,
                    ..Rates::default()
                },
                1.0,
                1.0,
                self.bands.floor as f64,
            ),
            ("agent", "steady") => {
                let duty = self.agent.active_s as f64
                    / (self.agent.active_s + self.agent.idle_s).max(1) as f64;
                (
                    self.agent.rates.clone(),
                    1.0,
                    duty,
                    self.bands.steady as f64,
                )
            }
            ("agent", "peak") => (
                self.agent.rates.clone(),
                self.agent.peak_multiplier,
                1.0,
                self.bands.peak as f64,
            ),
            _ => (Rates::default(), 1.0, 0.0, 0.0),
        };
        let mut map = BTreeMap::new();
        for (name, rate) in rates.entries() {
            let expected = rate * multiplier * duty * seconds / 3600.0;
            map.insert(name.to_string(), expected);
        }
        map
    }
}

#[derive(Deserialize)]
struct Raw {
    profile: RawProfile,
    population: RawPopulation,
    bands: RawBands,
    roles: RawRoles,
    storm: RawStorm,
    media: RawMedia,
    git: RawGit,
    kinds: RawKinds,
}

#[derive(Deserialize)]
struct RawProfile {
    name: String,
    description: String,
    seed: u64,
}

#[derive(Deserialize)]
struct RawPopulation {
    humans: u32,
    agents_per_human: u32,
    channels: u32,
    repos: u32,
}

#[derive(Deserialize)]
struct RawBands {
    warmup: u64,
    floor: u64,
    steady: u64,
    peak: u64,
    cooldown: u64,
}

#[derive(Deserialize)]
struct RawRoles {
    human: RawHuman,
    agent: RawAgent,
}

#[derive(Deserialize)]
struct RawHuman {
    backfill_limit: u32,
    presence_interval_s: u64,
    typing_before_msg_prob: f64,
    burst_len_s: u64,
    burst_gap_s: u64,
    steady_per_hour: BTreeMap<String, f64>,
    peak_multiplier: f64,
}

#[derive(Deserialize)]
struct RawAgent {
    nip_oa: bool,
    active_s: u64,
    idle_s: u64,
    steady_per_hour: BTreeMap<String, f64>,
    peak_multiplier: f64,
    peak_all_active: bool,
}

#[derive(Deserialize)]
struct RawStorm {
    enabled: bool,
    at_band: String,
    joiners: String,
    stagger_s: u64,
    backfill_limit: u32,
}

#[derive(Deserialize)]
struct RawMedia {
    sizes_kb: Vec<u64>,
    weights: Vec<f64>,
}

#[derive(Deserialize)]
struct RawGit {
    push_kb: Vec<u64>,
}

#[derive(Deserialize)]
struct RawKinds {
    msg: u16,
    reaction: u16,
    edit: u16,
    canvas: u16,
    issue: u16,
    pr: u16,
    repo_announce: u16,
    turn_metric: u16,
    presence: u16,
    typing: u16,
    dm: u16,
    member_add: u16,
    channel_create: u16,
    relay_member_add: u16,
}

/// Load and validate a profile TOML file.
pub fn load_profile(path: &Path) -> Result<Profile> {
    let source =
        fs::read_to_string(path).with_context(|| format!("reading profile {}", path.display()))?;
    parse_profile(path, &source)
}

fn parse_profile(path: &Path, source: &str) -> Result<Profile> {
    let raw: Raw = toml::from_str(source).map_err(|err| annotate_toml(source, err))?;
    validate_raw(&raw, source)?;
    Ok(Profile {
        name: raw.profile.name,
        description: raw.profile.description,
        seed: raw.profile.seed,
        humans: raw.population.humans,
        agents_per_human: raw.population.agents_per_human,
        channels: raw.population.channels,
        repos: raw.population.repos,
        bands: Bands {
            warmup: raw.bands.warmup,
            floor: raw.bands.floor,
            steady: raw.bands.steady,
            peak: raw.bands.peak,
            cooldown: raw.bands.cooldown,
        },
        human: HumanRole {
            backfill_limit: raw.roles.human.backfill_limit,
            presence_interval_s: raw.roles.human.presence_interval_s,
            typing_before_msg_prob: raw.roles.human.typing_before_msg_prob,
            burst_len_s: raw.roles.human.burst_len_s,
            burst_gap_s: raw.roles.human.burst_gap_s,
            rates: rates_from_map(&raw.roles.human.steady_per_hour)?,
            peak_multiplier: raw.roles.human.peak_multiplier,
        },
        agent: AgentRole {
            nip_oa: raw.roles.agent.nip_oa,
            active_s: raw.roles.agent.active_s,
            idle_s: raw.roles.agent.idle_s,
            rates: rates_from_map(&raw.roles.agent.steady_per_hour)?,
            peak_multiplier: raw.roles.agent.peak_multiplier,
            peak_all_active: raw.roles.agent.peak_all_active,
        },
        storm: Storm {
            enabled: raw.storm.enabled,
            at_band: raw.storm.at_band,
            joiners: raw.storm.joiners,
            stagger_s: raw.storm.stagger_s,
            backfill_limit: raw.storm.backfill_limit,
        },
        media: MediaMix {
            sizes_kb: raw.media.sizes_kb,
            weights: raw.media.weights,
        },
        git: GitMix {
            push_kb: raw.git.push_kb,
        },
        kinds: KindTable {
            msg: raw.kinds.msg,
            reaction: raw.kinds.reaction,
            edit: raw.kinds.edit,
            canvas: raw.kinds.canvas,
            issue: raw.kinds.issue,
            pr: raw.kinds.pr,
            repo_announce: raw.kinds.repo_announce,
            turn_metric: raw.kinds.turn_metric,
            presence: raw.kinds.presence,
            typing: raw.kinds.typing,
            dm: raw.kinds.dm,
            member_add: raw.kinds.member_add,
            channel_create: raw.kinds.channel_create,
            relay_member_add: raw.kinds.relay_member_add,
        },
        source_path: path.display().to_string(),
        source: source.to_string(),
    })
}

fn annotate_toml(source: &str, err: toml::de::Error) -> anyhow::Error {
    if let Some(span) = err.span() {
        let line = line_of(source, span.start);
        anyhow!("profile parse error at line {line}: {err}")
    } else {
        anyhow!("profile parse error: {err}")
    }
}

fn line_of(source: &str, byte: usize) -> usize {
    source
        .get(..byte)
        .map(|s| s.bytes().filter(|b| *b == b'\n').count() + 1)
        .unwrap_or(1)
}

fn field_line(source: &str, needle: &str) -> usize {
    source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(needle))
        .map(|(i, _)| i + 1)
        .unwrap_or(1)
}

fn validate_raw(raw: &Raw, source: &str) -> Result<()> {
    let bands = [
        ("warmup", raw.bands.warmup),
        ("floor", raw.bands.floor),
        ("steady", raw.bands.steady),
        ("peak", raw.bands.peak),
        ("cooldown", raw.bands.cooldown),
    ];
    for (name, value) in bands {
        if value == 0 {
            bail!(
                "profile validation error at line {}: bands.{name} must be > 0",
                field_line(source, name)
            );
        }
    }
    if raw.population.humans == 0 {
        bail!(
            "profile validation error at line {}: population.humans must be > 0",
            field_line(source, "humans")
        );
    }
    if raw.population.channels == 0 {
        bail!(
            "profile validation error at line {}: population.channels must be > 0",
            field_line(source, "channels")
        );
    }
    for (k, v) in raw
        .roles
        .human
        .steady_per_hour
        .iter()
        .chain(raw.roles.agent.steady_per_hour.iter())
    {
        if *v < 0.0 {
            bail!(
                "profile validation error at line {}: rate {k} must be >= 0",
                field_line(source, k)
            );
        }
    }
    if raw.roles.human.typing_before_msg_prob < 0.0 || raw.roles.human.typing_before_msg_prob > 1.0
    {
        bail!(
            "profile validation error at line {}: typing_before_msg_prob must be in [0, 1]",
            field_line(source, "typing_before_msg_prob")
        );
    }
    if raw.media.sizes_kb.len() != raw.media.weights.len() || raw.media.sizes_kb.is_empty() {
        bail!(
            "profile validation error at line {}: media.sizes_kb and media.weights must be non-empty and the same length",
            field_line(source, "sizes_kb")
        );
    }
    let weight_sum: f64 = raw.media.weights.iter().sum();
    if (weight_sum - 1.0).abs() > 1e-6 {
        bail!(
            "profile validation error at line {}: media.weights must sum to 1 (got {weight_sum})",
            field_line(source, "weights")
        );
    }
    if raw.git.push_kb.is_empty() {
        bail!(
            "profile validation error at line {}: git.push_kb must be non-empty",
            field_line(source, "push_kb")
        );
    }
    Ok(())
}

fn rates_from_map(map: &BTreeMap<String, f64>) -> Result<Rates> {
    let mut rates = Rates::default();
    for (k, v) in map {
        match k.as_str() {
            "msg" => rates.msg = *v,
            "reaction" => rates.reaction = *v,
            "edit" => rates.edit = *v,
            "media" => rates.media = *v,
            "dm" => rates.dm = *v,
            "canvas" => rates.canvas = *v,
            "issue" => rates.issue = *v,
            "pr" => rates.pr = *v,
            "git_push" => rates.git_push = *v,
            "turn_metric" => rates.turn_metric = *v,
            "presence" => rates.presence = *v,
            other => bail!("unknown rate key {other}"),
        }
    }
    Ok(rates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample() -> String {
        include_str!("../../../../perf/profiles/10h-20a.toml").to_string()
    }

    #[test]
    fn valid_profile_loads() {
        let p = parse_profile(&PathBuf::from("perf/profiles/10h-20a.toml"), &sample()).unwrap();
        assert_eq!(p.name, "10h-20a");
        assert_eq!(p.identity_count(), 30);
        assert!((p.media.weights.iter().sum::<f64>() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn malformed_reports_line_number() {
        let mut bad = sample();
        bad = bad.replace("humans           = 10", "humans           = -1");
        let err = parse_profile(&PathBuf::from("p.toml"), &bad).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("line"), "{msg}");
    }

    #[test]
    fn weights_must_sum_to_one() {
        let mut bad = sample();
        bad = bad.replace("weights  = [0.6, 0.3, 0.1]", "weights  = [0.6, 0.3, 0.2]");
        let err = parse_profile(&PathBuf::from("p.toml"), &bad).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("weights must sum to 1"), "{msg}");
        assert!(msg.contains("line"), "{msg}");
    }
}
