//! Population generator: 10 humans × 20 agents against a Buzz relay.

#[path = "../sim/mod.rs"]
mod sim;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use buzz_test_client::BuzzTestClient;
use clap::Parser;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sim::admission::{publish, Publish};
use sim::git;
use sim::guard::{Target, TargetGuard};
use sim::identity::{
    connect_identity, generate_population, load_population, nip_oa_json, save_population, uuid_v4,
    IdentityRecord, Population, RepoRef, World,
};
use sim::kinds;
use sim::phase::emit;
use sim::profile::{load_profile, Profile};
use sim::roles::Role;
use sim::seed;
use sim::signal::{self, Ended};
use sim::stats::{spawn_live_writer, write_live, Stats};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::warn;

/// Same OK window as `buzz-ws-client`'s publish.
const OK_TIMEOUT: Duration = Duration::from_secs(30);
/// How often `<out-dir>/live.json` is rewritten.
const LIVE_EVERY: Duration = Duration::from_secs(2);
/// Transport failures tolerated per owner event before provisioning fails.
const SEND_ATTEMPTS: u32 = 4;
/// Rate-limit waits tolerated per owner event (each waits out one window).
const RATE_LIMIT_WAITS: u32 = 20;

#[derive(Parser, Debug)]
#[command(name = "tenant_sim", about = "Buzz relay population generator")]
struct Args {
    /// Path to the profile TOML.
    #[arg(long)]
    profile: PathBuf,

    /// Relay WebSocket URL: a literal IP address, never a name.
    #[arg(long, default_value = "ws://127.0.0.1:3030")]
    relay_url: String,

    /// Relay HTTP URL (media + git): a literal IP address, never a name.
    #[arg(long, default_value = "http://127.0.0.1:3030")]
    http_url: String,

    /// Address block every target must sit inside (repeatable, required for
    /// a run; no default). IPv4 no wider than /8, IPv6 no wider than /32.
    #[arg(long = "allow-cidr")]
    allow_cidr: Vec<String>,

    /// File of addresses and blocks no target may use, one per line; `#`
    /// comments. Required for a run; the file may be empty. Wins over
    /// --allow-cidr.
    #[arg(long)]
    deny_list: Option<PathBuf>,

    /// Run output directory (identities, summary, git worktrees).
    #[arg(long)]
    out_dir: Option<PathBuf>,

    /// Band signal source: stdin (default) or fifo (`<out-dir>/band.fifo`).
    /// See `sim::signal` for the lines and their leases.
    #[arg(long, default_value = "stdin")]
    band_signal: String,

    /// With --pause-after-setup, how long to wait for `continue` before
    /// giving up (exit 3): a driver that died during setup.
    #[arg(long, default_value_t = 3600)]
    continue_within_s: u64,

    /// Send kind 9030 for every identity (closed-relay posture).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_membership: bool,

    /// Path to git-credential-nostr.
    #[arg(long, default_value = "./target/release/git-credential-nostr")]
    git_credential_helper: PathBuf,

    /// Reconnect-tracking mode for rolling-update tests.
    #[arg(long)]
    blink: bool,

    /// Reuse a previously written identities.json.
    #[arg(long)]
    identities: Option<PathBuf>,

    /// tracing level (error, warn, info, debug).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Print the deterministic owner pubkey and exit.
    #[arg(long)]
    print_owner: bool,

    /// Parse and validate the profile, print the event budget, exit.
    #[arg(long)]
    check: bool,

    /// After provisioning, write this many stored channel messages at
    /// current timestamps before any identity subscribes (volume seed).
    #[arg(long, default_value_t = 0, conflicts_with = "seed_days")]
    seed_events: u64,

    /// The volume seed as days of history: the profile's stored events for
    /// that many days (see `--check`'s `seed_90d` for the formula).
    #[arg(long, default_value_t = 0)]
    seed_days: u64,

    /// Stop the seed after this many seconds even if it is short of
    /// --seed-events.
    #[arg(long, default_value_t = 1800)]
    seed_max_seconds: u64,

    /// After setup (provisioning and seed), print `{"phase":"setup-done"}`
    /// and wait for a `continue` line on the band signal before the
    /// population connects. Lets the orchestrator restart the relay between
    /// setup and the measured run.
    #[arg(long)]
    pause_after_setup: bool,

    /// A ramp: provision this many identities in setup (a whole number of
    /// the profile's teams: a human and their agents), and switch them on in
    /// steps with `ramp <k>` band signals. The world (channels, repos) stays
    /// the profile's, and every identity joins every channel.
    #[arg(long, default_value_t = 0)]
    ramp_max: u32,

    /// With --ramp-max: how many identities are on before the first `ramp`
    /// signal (default: the profile's population).
    #[arg(long)]
    ramp_start: Option<u32>,

    /// Exit after setup (provisioning and seed); no population run.
    #[arg(long)]
    setup_only: bool,
}

/// What provisioning cost, for the `setup-done` line, and the band signal,
/// so a stop ends setup's waits.
#[derive(Debug, Default)]
struct SetupStats {
    events: u64,
    rate_limited: u64,
    /// Setup events the relay shed, full or unable to admit, each waited
    /// out and resent like a rate limit.
    relay_shed: u64,
    stop: Option<tokio::sync::watch::Receiver<sim::roles::Band>>,
}

impl SetupStats {
    /// Sleeps `d`, or until the run stops: Err then.
    async fn sleep(&mut self, d: Duration, what: &str) -> Result<()> {
        match self.stop.as_mut() {
            Some(stop) => tokio::select! {
                _ = tokio::time::sleep(d) => Ok(()),
                _ = sim::identity::until_stop(stop) => bail!("{what}: the run was stopped during setup"),
            },
            None => {
                tokio::time::sleep(d).await;
                Ok(())
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The human who attests for an agent (NIP-OA), if any.
fn owner_of(pop: &Population, rec: &IdentityRecord) -> Option<nostr::Keys> {
    rec.owner_name
        .as_ref()
        .and_then(|n| pop.humans.iter().find(|h| h.name == *n))
        .and_then(|h| pop.keys_of(h).ok())
}

/// Identities added to the relay directly (kind 9030). With NIP-OA agents,
/// only humans: a direct member is admitted as itself, so the relay never
/// records its owner and treats it as a human (human limits, and every
/// agent-only kind such as the 44200 turn metric is refused). Agents get in
/// through their owner's attestation, as real agents on a closed relay do.
fn direct_members<'a>(profile: &Profile, pop: &'a Population) -> Vec<&'a IdentityRecord> {
    if profile.agent.nip_oa {
        pop.humans.iter().collect()
    } else {
        pop.humans.iter().chain(pop.agents.iter()).collect()
    }
}

/// Owner-socket publish. A relay rate-limit NOTICE, the quota or the relay
/// shedding, waits out the window and resends the same event (the relay did
/// not process it); a transport error reconnects. Both are bounded. A
/// `rate-limited:` text the pinned relay doesn't send fails at once.
async fn send_with_retry(
    client: &mut BuzzTestClient,
    keys: &nostr::Keys,
    relay_url: &Target,
    event: nostr::Event,
    what: &str,
    setup: &mut SetupStats,
) -> Result<buzz_test_client::OkResponse> {
    let mut last = anyhow::anyhow!("send failed");
    let mut attempt = 0u32;
    let mut waits = 0u32;
    setup.events += 1;
    while attempt < SEND_ATTEMPTS && waits <= RATE_LIMIT_WAITS {
        match publish(client, &event, OK_TIMEOUT).await {
            Ok(Publish::Ok(ok)) => return Ok(ok),
            Ok(Publish::RateLimited { retry_in }) => {
                waits += 1;
                setup.rate_limited += 1;
                last = anyhow::anyhow!("{what}: still rate-limited after {waits} waits");
                setup.sleep(retry_in, what).await?;
            }
            Ok(Publish::Shed { text }) => {
                waits += 1;
                setup.relay_shed += 1;
                last = anyhow::anyhow!("{what}: still shed after {waits} waits: {text}");
                setup.sleep(Duration::from_secs(1), what).await?;
            }
            Ok(Publish::UnknownLimit { text }) => {
                bail!("{what}: the relay sent a limit it doesn't send: {text}");
            }
            Err(e) => {
                last = anyhow::anyhow!("{what}: {e}");
                warn!("{what} attempt {attempt}: {e}");
                attempt += 1;
                setup
                    .sleep(Duration::from_millis(200 * attempt as u64), what)
                    .await?;
                match BuzzTestClient::connect(relay_url.as_str(), keys).await {
                    Ok(c) => *client = c,
                    Err(ce) => warn!("reconnect after {what}: {ce}"),
                }
            }
        }
    }
    Err(last)
}

/// The run's two checked targets.
struct Targets {
    relay: Target,
    http: Target,
}

/// Check both targets before anything else happens. A refusal leaves no
/// output directory and makes no connection.
fn check_targets(args: &Args) -> Result<Targets> {
    let guard = TargetGuard::from_args(&args.allow_cidr, args.deny_list.as_deref())?;
    Ok(Targets {
        relay: guard.check_url(&args.relay_url, &["ws", "wss"])?,
        http: guard.check_url(&args.http_url, &["http", "https"])?,
    })
}

/// Clones one setup repo for its agent. A missing credential helper or a
/// clone that fails fails setup, like a refused channel create: a run with
/// fewer repos than its profile isn't that profile's run.
async fn clone_setup_repo(
    helper: &std::path::Path,
    http: &Target,
    out_dir: Option<&std::path::Path>,
    agent: &IdentityRecord,
    name: &str,
    auth_tag: Option<String>,
) -> Result<RepoRef> {
    if !helper.exists() {
        bail!(
            "git-credential helper {} missing; setup can't clone {name}",
            helper.display()
        );
    }
    let dest = out_dir
        .map(|p| p.join("git").join(name))
        .unwrap_or_else(|| PathBuf::from("git").join(name));
    let repo = git::clone_repo_async(
        http.clone(),
        agent.pubkey.clone(),
        name.to_string(),
        dest,
        helper.to_path_buf(),
        agent.nsec.clone(),
        auth_tag,
    )
    .await
    .with_context(|| format!("git clone {name} failed"))?;
    Ok(RepoRef {
        name: repo.name.clone(),
        owner_hex: repo.owner_hex.clone(),
        owner_nsec: repo.owner_nsec.clone(),
        a_tag: format!("30617:{}:{}", repo.owner_hex, repo.name),
        clone_url: repo.url.clone(),
        worktree: repo.worktree.clone(),
    })
}

/// A ramp's shape: how many identities it provisions, how many are on at
/// the start, and the population it draws them from.
struct Ramp {
    max: usize,
    start: usize,
}

/// Checks --ramp-max and --ramp-start against the profile: the max a whole
/// number of the profile's teams, at least the profile's population, and
/// the start within it.
fn check_ramp(profile: &Profile, args: &Args) -> Result<Option<Ramp>> {
    if args.ramp_max == 0 {
        if args.ramp_start.is_some() {
            bail!("--ramp-start needs --ramp-max");
        }
        return Ok(None);
    }
    let team = 1 + profile.agents_per_human;
    if !args.ramp_max.is_multiple_of(team) {
        bail!(
            "--ramp-max {} is not a whole number of teams of {team} (a human and {} agents)",
            args.ramp_max,
            profile.agents_per_human
        );
    }
    if args.ramp_max < profile.identity_count() {
        bail!(
            "--ramp-max {} is under the profile's population, {}",
            args.ramp_max,
            profile.identity_count()
        );
    }
    let start = args.ramp_start.unwrap_or(profile.identity_count());
    if start == 0 || start > args.ramp_max {
        bail!(
            "--ramp-start {start} is not 1 to --ramp-max {}",
            args.ramp_max
        );
    }
    Ok(Some(Ramp {
        max: args.ramp_max as usize,
        start: start as usize,
    }))
}

/// The ramp's population: the profile's, with as many teams as --ramp-max
/// holds. Humans' keys come before agents' from one stream, so a ramp's
/// population is generated whole, at its maximum, never grown.
fn ramp_profile(profile: &Profile, ramp: &Ramp) -> Profile {
    let mut p = profile.clone();
    p.humans = (ramp.max as u32) / (1 + profile.agents_per_human);
    p
}

/// Where each identity sits in the ramp's order: team by team, a human
/// then their agents, so every step of whole teams keeps the profile's mix
/// and every agent's owner is on before it.
fn ramp_index(role: Role, i: usize, agents_per_human: usize) -> usize {
    let team = 1 + agents_per_human;
    match role {
        Role::Human => i * team,
        Role::Agent => (i / agents_per_human.max(1)) * team + 1 + i % agents_per_human.max(1),
    }
}

/// Linux: the open-file limit must hold a ramp's sockets (a websocket, the
/// HTTP pool, git) or joiners fail on the generator's side and look like
/// the relay refusing them. Elsewhere there is no /proc to read; the local
/// proofs ramp small.
fn check_open_files(ramp: &Ramp) -> Result<()> {
    check_open_files_in(
        std::fs::read_to_string("/proc/self/limits").ok().as_deref(),
        ramp,
    )
}

/// [`check_open_files`] on the text of /proc/self/limits, if there is one.
fn check_open_files_in(limits: Option<&str>, ramp: &Ramp) -> Result<()> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let need = ramp.max as u64 * 4 + 256;
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix("Max open files") {
            let soft = rest.split_whitespace().next().unwrap_or("");
            if soft == "unlimited" {
                return Ok(());
            }
            let soft: u64 = soft
                .parse()
                .map_err(|_| anyhow::anyhow!("/proc/self/limits: open files {soft:?}"))?;
            if soft < need {
                bail!(
                    "the open-file limit is {soft}; a ramp to {} identities needs at least {need} (raise LimitNOFILE)",
                    ramp.max
                );
            }
            return Ok(());
        }
    }
    bail!("/proc/self/limits has no open-file limit")
}

/// A run stopped (a `stop`, or a lease that ran out) before its population
/// was measured: the last live.json says why, and the exit is 0, or 5 for
/// a lease.
fn stopped_early(
    control: &signal::Control,
    stats: &Stats,
    live_task: &tokio::task::JoinHandle<()>,
    live_path: &std::path::Path,
) -> Result<i32> {
    live_task.abort();
    let ended = control.ended().unwrap_or(Ended::Stop);
    let mut last = stats.live(unix_now());
    last.ended = Some(ended.as_str().to_string());
    write_live(live_path, &last)?;
    Ok(if ended == Ended::Lease { 5 } else { 0 })
}

/// How many events the volume seed writes: `--seed-days` of the profile's
/// history, or `--seed-events` exactly.
fn seed_count(profile: &Profile, args: &Args) -> u64 {
    if args.seed_days > 0 {
        profile.seed_plan(args.seed_days).events
    } else {
        args.seed_events
    }
}

async fn provision(
    profile: &Profile,
    pop: &Population,
    args: &Args,
    targets: &Targets,
    stats: &Stats,
    setup: &mut SetupStats,
) -> Result<(Vec<String>, Vec<RepoRef>)> {
    let owner_keys = pop.owner_keys()?;
    let mut owner = BuzzTestClient::connect(targets.relay.as_str(), &owner_keys)
        .await
        .context("owner connect")?;
    if args.require_membership {
        for rec in direct_members(profile, pop) {
            let ev = kinds::relay_member_add(&owner_keys, &profile.kinds, &rec.pubkey)?;
            let ok = send_with_retry(
                &mut owner,
                &owner_keys,
                &targets.relay,
                ev,
                &format!("9030 {}", rec.name),
                setup,
            )
            .await?;
            // An identity the relay didn't admit isn't in the population a
            // run measures: setup fails, as for a refused channel create.
            if !ok.accepted {
                bail!("9030 {} rejected: {}", rec.name, ok.message);
            }
        }
    }

    let mut rng = {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&profile.seed.to_le_bytes());
        bytes[12] = 0xC4;
        StdRng::from_seed(bytes)
    };
    let mut channels = Vec::new();
    for i in 0..profile.channels {
        let id = uuid_v4(&mut rng).to_string();
        let ev = kinds::channel_create(
            &owner_keys,
            &profile.kinds,
            &id,
            &format!("sim-channel-{i}"),
        )?;
        let ok = send_with_retry(
            &mut owner,
            &owner_keys,
            &targets.relay,
            ev,
            &format!("9007 {i}"),
            setup,
        )
        .await?;
        if !ok.accepted {
            bail!("channel create rejected: {}", ok.message);
        }
        channels.push(id);
    }
    for rec in pop.humans.iter().chain(pop.agents.iter()) {
        for ch in &channels {
            let ev = kinds::member_add(&owner_keys, &profile.kinds, ch, &rec.pubkey)?;
            // Every identity joins every channel: a join the relay refused,
            // or one that failed after its retries, fails setup.
            let ok = send_with_retry(
                &mut owner,
                &owner_keys,
                &targets.relay,
                ev,
                &format!("9000 {} {ch}", rec.name),
                setup,
            )
            .await?;
            if !ok.accepted {
                bail!("9000 {} {ch} rejected: {}", rec.name, ok.message);
            }
        }
    }
    let _ = stats;
    let mut repos = Vec::new();
    if profile.repos > 0 && !pop.agents.is_empty() && !channels.is_empty() {
        let helper = &args.git_credential_helper;
        for i in 0..profile.repos as usize {
            let agent = &pop.agents[i % pop.agents.len()];
            let agent_keys = pop.keys_of(agent)?;
            let agent_owner = owner_of(pop, agent);
            let auth_tag = agent_owner
                .as_ref()
                .map(|o| nip_oa_json(o, &agent_keys))
                .transpose()?;
            let name = format!("sim-repo-{i}");
            let ev = kinds::repo_announce(&agent_keys, &profile.kinds, &name, &name, &channels[0])?;
            let mut agent_client =
                connect_identity(&targets.relay, agent, &agent_keys, agent_owner.as_ref()).await?;
            let ok = agent_client.send_event(ev).await?;
            if !ok.accepted {
                warn!("30617 {name} rejected: {}", ok.message);
            }
            let _ = agent_client.disconnect().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            repos.push(
                clone_setup_repo(
                    helper,
                    &targets.http,
                    args.out_dir.as_deref(),
                    agent,
                    &name,
                    auth_tag,
                )
                .await?,
            );
        }
    }
    let _ = owner.disconnect().await;
    Ok((channels, repos))
}

async fn run(args: Args) -> Result<i32> {
    let profile = load_profile(&args.profile)?;
    if args.print_owner {
        let pop = generate_population(&profile);
        println!("{}", pop.owner.pubkey);
        return Ok(0);
    }
    if args.check {
        let budget = profile.event_budget();
        println!(
            "{}",
            serde_json::json!({
                "profile": profile.name,
                "description": profile.description,
                "seed": profile.seed,
                "identities": {
                    "humans": profile.humans,
                    "agents": profile.agent_count(),
                    "total": profile.identity_count(),
                },
                "bands_s": {
                    "warmup": profile.bands.warmup,
                    "floor": profile.bands.floor,
                    "steady": profile.bands.steady,
                    "peak": profile.bands.peak,
                    "cooldown": profile.bands.cooldown,
                },
                "event_budget_per_identity": budget,
                "seed_90d": profile.seed_plan(90),
            })
        );
        return Ok(0);
    }

    // --print-owner and --check (above) make no connection. Everything
    // below may, so the targets are checked first.
    let targets = check_targets(&args)?;
    let out_dir = args
        .out_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--out-dir is required for a run"))?;
    std::fs::create_dir_all(&out_dir)?;

    let ramp = check_ramp(&profile, &args)?;
    if let Some(r) = &ramp {
        check_open_files(r)?;
    }
    let pop = if let Some(path) = &args.identities {
        load_population(path)?
    } else if let Some(r) = &ramp {
        generate_population(&ramp_profile(&profile, r))
    } else {
        generate_population(&profile)
    };
    save_population(&out_dir.join("identities.json"), &pop)?;
    // Who mentions whom, in the run and in the seed (sim/mentions.rs).
    let mentions = Arc::new(sim::mentions::Mentions::new(&pop));
    std::fs::write(
        out_dir.join("mentions.json"),
        serde_json::to_vec_pretty(&mentions.to_json())?,
    )?;

    sim::phase::set_file(out_dir.join("phases.jsonl"))?;
    let mut control = signal::spawn(
        &args.band_signal,
        &out_dir,
        ramp.as_ref().map_or(usize::MAX, |r| r.start),
    )?;
    let band_rx = control.band.clone();

    let stats = Arc::new(Stats::new());
    // The live counters (<out-dir>/live.json), rewritten every LIVE_EVERY,
    // so a sampler can see the generator's own errors during a band. It
    // exists from the start; a missing file is the sampler's error, not
    // "no errors".
    let live_path = out_dir.join("live.json");
    write_live(&live_path, &stats.live(unix_now()))?;
    let live_task = spawn_live_writer(stats.clone(), live_path.clone(), LIVE_EVERY);
    let setup_started = Instant::now();
    let mut setup = SetupStats {
        stop: Some(control.band.clone()),
        ..SetupStats::default()
    };
    let (channels, repos) =
        match provision(&profile, &pop, &args, &targets, &stats, &mut setup).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("warm-up failed: {e:#}");
                warn!("warm-up failed: {e:#}");
                emit(&serde_json::json!({"phase": "setup-failed", "why": format!("{e:#}")}));
                return Ok(3);
            }
        };
    let provision_s = setup_started.elapsed().as_secs_f64();

    let mut seed_failed = false;
    let seed_events = seed_count(&profile, &args);
    if seed_events > 0 {
        emit(&serde_json::json!({
            "phase": "seed-start",
            "t_unix_ms": kinds::now_ms(),
            "events": seed_events,
            "days": args.seed_days,
        }));
        let report = seed::seed(
            &targets.relay,
            &pop,
            &mentions,
            &profile.kinds,
            &channels,
            seed_events,
            Duration::from_secs(args.seed_max_seconds),
            control.band.clone(),
        )
        .await?;
        seed_failed = report.rejected > 0 || report.errors > 0;
        emit(&serde_json::json!({
            "phase": "seed-done",
            "t_unix_ms": kinds::now_ms(),
            "seed": report,
        }));
    }
    emit(&serde_json::json!({
        "phase": "setup-done",
        "provision": {
            "events": setup.events,
            "rate_limited": setup.rate_limited,
            "relay_shed": setup.relay_shed,
            "seconds": provision_s,
        },
    }));
    if args.setup_only {
        return Ok(if seed_failed { 1 } else { 0 });
    }
    if args.pause_after_setup {
        let within = Duration::from_secs(args.continue_within_s);
        let go = control
            .go
            .take()
            .ok_or_else(|| anyhow::anyhow!("continue taken twice"))?;
        // A stop (or a lease that runs out) while setup waits for continue
        // ends the run there: nobody connected, nothing to measure.
        let mut stop = control.band.clone();
        let waited = tokio::select! {
            r = timeout(within, go) => r,
            _ = sim::identity::until_stop(&mut stop) => {
                return stopped_early(&control, &stats, &live_task, &live_path);
            }
        };
        match waited {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                eprintln!("band signal closed before continue");
                return Ok(3);
            }
            Err(_) => {
                eprintln!(
                    "no continue within {} s after setup; the driver is gone",
                    within.as_secs()
                );
                return Ok(3);
            }
        }
    }

    let world = Arc::new(World {
        relay_url: targets.relay.clone(),
        http_url: targets.http.clone(),
        channels,
        human_pubkeys: pop.humans.iter().map(|h| h.pubkey.clone()).collect(),
        repos,
        git_helper: args.git_credential_helper.clone(),
        out_dir: out_dir.clone(),
        blink: args.blink,
        mentions: mentions.clone(),
        seqs: Default::default(),
    });

    let profile = Arc::new(profile);
    let expected = ramp
        .as_ref()
        .map_or(profile.identity_count() as usize, |r| r.start);
    let everyone = pop.humans.len() + pop.agents.len();
    let (ready_tx, mut ready_rx) = mpsc::channel::<Result<(), String>>(everyone.max(1));
    let aph = profile.agents_per_human as usize;
    let slot = |role: Role, i: usize| {
        ramp.as_ref().map(|_| sim::identity::RampSlot {
            on: control.ramp.clone(),
            index: ramp_index(role, i, aph),
        })
    };
    let mut tasks = Vec::new();
    let mut salt = 10u32;
    for (i, rec) in pop.humans.iter().cloned().enumerate() {
        salt += 1;
        let slot = slot(Role::Human, i);
        let keys = pop.keys_of(&rec)?;
        let profile = profile.clone();
        let world = world.clone();
        let stats = stats.clone();
        let band_rx = band_rx.clone();
        let ready_tx = ready_tx.clone();
        tasks.push(tokio::spawn(async move {
            sim::identity::run_identity(
                rec,
                keys,
                None,
                Role::Human,
                profile,
                world,
                stats,
                band_rx,
                None,
                salt,
                ready_tx,
                slot,
            )
            .await
        }));
    }
    for (i, rec) in pop.agents.iter().cloned().enumerate() {
        salt += 1;
        let slot = slot(Role::Agent, i);
        let keys = pop.keys_of(&rec)?;
        let owner_keys = owner_of(&pop, &rec);
        let auth_tag = owner_keys
            .as_ref()
            .map(|o| nip_oa_json(o, &keys))
            .transpose()?;
        let git_repo = world
            .repos
            .iter()
            .find(|r| r.owner_hex == rec.pubkey)
            .map(|r| git::GitRepo {
                name: r.name.clone(),
                owner_hex: r.owner_hex.clone(),
                owner_nsec: r.owner_nsec.clone(),
                owner_auth_tag: auth_tag.clone(),
                worktree: r.worktree.clone(),
                url: r.clone_url.clone(),
            });
        let profile = profile.clone();
        let world = world.clone();
        let stats = stats.clone();
        let band_rx = band_rx.clone();
        let ready_tx = ready_tx.clone();
        tasks.push(tokio::spawn(async move {
            sim::identity::run_identity(
                rec,
                keys,
                owner_keys,
                Role::Agent,
                profile,
                world,
                stats,
                band_rx,
                git_repo,
                salt,
                ready_tx,
                slot,
            )
            .await
        }));
    }
    drop(ready_tx);

    let mut ready = 0usize;
    let mut stop = control.band.clone();
    let wait = timeout(Duration::from_secs(180), async {
        while ready < expected {
            match ready_rx.recv().await {
                Some(Ok(())) => {
                    ready += 1;
                    stats.record_joined();
                }
                Some(Err(e)) => return Err(e),
                None => {
                    return Err(format!(
                        "identity tasks ended after {ready}/{expected} ready"
                    ))
                }
            }
        }
        Ok(())
    });
    // A stop while the population connects ends the run there too.
    let wait = tokio::select! {
        w = wait => w,
        _ = sim::identity::until_stop(&mut stop) => {
            for t in &tasks {
                t.abort();
            }
            return stopped_early(&control, &stats, &live_task, &live_path);
        }
    };
    match wait {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("warm-up identities: {e}");
            warn!("warm-up identities: {e}");
            return Ok(3);
        }
        Err(_) => {
            eprintln!("warm-up timed out with {ready}/{expected} identities ready");
            warn!("warm-up timed out with {ready}/{expected} identities ready");
            return Ok(3);
        }
    }

    emit(&serde_json::json!({
        "phase": "ready",
        "identities": expected,
        "ramp_max": ramp.as_ref().map(|r| r.max),
    }));
    // Ramp joiners, later: each one that connects counts as joined; one that
    // can't is a join the relay failed (the generator's own limits are
    // checked above).
    {
        let stats = stats.clone();
        tokio::spawn(async move {
            while let Some(r) = ready_rx.recv().await {
                match r {
                    Ok(()) => stats.record_joined(),
                    Err(e) => {
                        warn!("ramp join: {e}");
                        stats.record_client_error("join_failed");
                    }
                }
            }
        });
    }

    let mut join_err = false;
    for t in tasks {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!("identity task: {e:#}");
                join_err = true;
            }
            Err(e) => {
                warn!("identity join: {e}");
                join_err = true;
            }
        }
    }

    live_task.abort();
    // The last write says why the run ended, so a sampler never reads it
    // as stale.
    let ended = control.ended().unwrap_or(Ended::Eof);
    let mut last = stats.live(unix_now());
    last.ended = Some(ended.as_str().to_string());
    write_live(&live_path, &last)?;
    let mut ends = HashMap::new();
    ends.insert("floor".into(), unix_now());
    ends.insert("steady".into(), unix_now());
    ends.insert("peak".into(), unix_now());
    let summary = stats.summarize(
        &profile.name,
        profile.seed,
        targets.relay.as_str(),
        profile.humans as u64,
        profile.agent_count() as u64,
        &ends,
    );
    let json = serde_json::to_string_pretty(&summary)?;
    std::fs::write(out_dir.join("summary.json"), &json)?;
    println!("{json}");

    let rejected: u64 = summary.bands.values().map(|b| b.rejected).sum();
    if ended == Ended::Lease {
        Ok(5)
    } else if summary.lost_after_backfill > 0 {
        Ok(2)
    } else if join_err || rejected > 0 || summary.media.rejected > 0 || summary.git.failed > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Honour --log-level even when the host shell exports a narrow RUST_LOG
    // (e.g. buzz_acp=info) that would otherwise silence this binary.
    let filter = tracing_subscriber::EnvFilter::new(&args.log_level);
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("tenant_sim: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn shipped_profile() -> Profile {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../perf/profiles/10h-20a.toml");
        load_profile(&path).expect("load 10h-20a")
    }

    fn shipped_profile_path() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../perf/profiles/10h-20a.toml")
            .to_string_lossy()
            .into_owned()
    }

    /// A refused target (a name, an address outside the allow list, a
    /// deny-listed address) stops the run before any connection and before
    /// the output directory exists, whichever of the two targets it is.
    #[tokio::test]
    async fn a_refused_target_makes_no_connection_and_no_output() {
        use sim::guard::testsrv::{self, Server};
        let relay = Server::start("127.0.0.1:0", testsrv::status(400, ""));
        let http = Server::start("[::1]:0", testsrv::status(400, ""));
        let (rp, hp) = (relay.addr.port(), http.addr.port());
        let dir = testsrv::tempdir();
        let deny_none = dir.join("deny-none");
        std::fs::write(&deny_none, "").expect("write");
        let deny_relay = dir.join("deny-relay");
        std::fs::write(&deny_relay, "127.0.0.1\n").expect("write");
        let deny_http = dir.join("deny-http");
        std::fs::write(&deny_http, "::1\n").expect("write");
        let ok_http = format!("http://127.0.0.1:{hp}");
        let cases = [
            (
                "name",
                format!("ws://localhost:{rp}"),
                ok_http.clone(),
                "127.0.0.0/8",
                &deny_none,
                "not a literal IP",
            ),
            (
                "outside",
                format!("ws://127.0.0.1:{rp}"),
                ok_http.clone(),
                "10.0.0.0/8",
                &deny_none,
                "outside the allow list",
            ),
            (
                "denied",
                format!("ws://127.0.0.1:{rp}"),
                ok_http,
                "127.0.0.0/8",
                &deny_relay,
                "deny list",
            ),
            (
                "http-denied",
                format!("ws://127.0.0.1:{rp}"),
                format!("http://[::1]:{hp}"),
                "127.0.0.0/8",
                &deny_http,
                "deny list",
            ),
        ];
        for (name, relay_url, http_url, allow, deny, why) in cases {
            let out = dir.join(name);
            let args = Args::try_parse_from([
                "tenant_sim".to_string(),
                "--profile".into(),
                shipped_profile_path(),
                "--relay-url".into(),
                relay_url,
                "--http-url".into(),
                http_url,
                "--allow-cidr".into(),
                allow.into(),
                "--deny-list".into(),
                deny.to_string_lossy().into_owned(),
                "--out-dir".into(),
                out.to_string_lossy().into_owned(),
            ])
            .expect("args");
            let err = run(args).await.expect_err(name);
            assert!(format!("{err:#}").contains(why), "{name}: {err:#}");
            assert!(!out.exists(), "{name}: output directory created");
        }
        assert_eq!(relay.accepts(), 0, "relay target contacted");
        assert_eq!(http.accepts(), 0, "http target contacted");
    }

    /// A run needs both guard flags; `--check` and `--print-owner` make no
    /// connection and need neither.
    #[tokio::test]
    async fn a_run_needs_both_guard_flags() {
        let dir = sim::guard::testsrv::tempdir();
        let base = [
            "tenant_sim".to_string(),
            "--profile".into(),
            shipped_profile_path(),
        ];
        let out = dir.join("out").to_string_lossy().into_owned();
        let no_allow = Args::try_parse_from(
            base.iter()
                .cloned()
                .chain(["--out-dir".into(), out.clone()]),
        )
        .expect("args");
        assert!(
            format!("{:#}", run(no_allow).await.expect_err("no allow")).contains("--allow-cidr")
        );
        let no_deny = Args::try_parse_from(base.iter().cloned().chain([
            "--allow-cidr".into(),
            "127.0.0.0/8".into(),
            "--out-dir".into(),
            out.clone(),
        ]))
        .expect("args");
        assert!(format!("{:#}", run(no_deny).await.expect_err("no deny")).contains("--deny-list"));
        assert!(!dir.join("out").exists());
        for flag in ["--check", "--print-owner"] {
            let args =
                Args::try_parse_from(base.iter().cloned().chain([flag.to_string()])).expect("args");
            assert_eq!(run(args).await.expect(flag), 0);
        }
    }

    /// The three example profiles differ only in population and world shape;
    /// every per-identity rate is the team profile's.
    #[test]
    fn example_profiles_share_the_team_rates() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../perf/profiles");
        let team = shipped_profile();
        for (file, humans, agents, channels, repos) in [
            ("1h-5a.toml", 1, 5, 2, 1),
            ("10h-20a.toml", 10, 20, 6, 2),
            ("25h-75a.toml", 25, 75, 20, 8),
        ] {
            let p = load_profile(&dir.join(file)).expect(file);
            assert_eq!(
                (p.humans, p.agent_count(), p.channels, p.repos),
                (humans, agents, channels, repos),
                "{file}"
            );
            assert_eq!(
                p.human.rates.entries(),
                team.human.rates.entries(),
                "{file}"
            );
            assert_eq!(
                p.agent.rates.entries(),
                team.agent.rates.entries(),
                "{file}"
            );
            assert!(
                p.description.contains("provisional until calibration"),
                "{file}"
            );
        }
    }

    /// A setup clone that can't happen fails setup with its own line,
    /// never a warning and a smaller world: a missing credential helper
    /// before any git runs, and a clone the remote refuses.
    #[tokio::test]
    async fn a_failed_setup_clone_fails_setup() {
        use sim::guard::testsrv::{self, Server};
        use sim::guard::{Cidr, TargetGuard};
        let refusing = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let guard = TargetGuard::new(vec![Cidr::parse("127.0.0.0/8").expect("allow")], vec![])
            .expect("guard");
        let http = guard
            .check_url(&refusing.http(), &["http"])
            .expect("allowed");
        let pop = generate_population(&shipped_profile());
        let agent = &pop.agents[0];
        let dir = testsrv::tempdir();

        let missing = dir.join("no-such-helper");
        let err = clone_setup_repo(&missing, &http, Some(&dir), agent, "sim-repo-0", None)
            .await
            .map(|_| ())
            .expect_err("no helper");
        assert_eq!(
            format!("{err:#}"),
            format!(
                "git-credential helper {} missing; setup can't clone sim-repo-0",
                missing.display()
            )
        );
        assert_eq!(refusing.accepts(), 0, "git ran without a helper");

        let err = clone_setup_repo(
            std::path::Path::new("/usr/bin/true"),
            &http,
            Some(&dir),
            agent,
            "sim-repo-0",
            None,
        )
        .await
        .map(|_| ())
        .expect_err("a refused clone");
        let msg = format!("{err:#}");
        assert!(msg.starts_with("git clone sim-repo-0 failed: "), "{msg}");
        assert!(
            refusing.accepts() >= 1,
            "git never reached the remote: {msg}"
        );
    }

    /// The 90-day seed of each shipped profile, from the formula --check
    /// prints: the steady band's stored rates times its duty cycle, over 8
    /// hours a day, 5 days a week. --seed-days gives the same count, and it
    /// can't be given with --seed-events.
    #[test]
    fn the_90_day_seed_of_each_profile() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../perf/profiles");
        for (file, events) in [
            ("1h-5a.toml", 49_469),
            ("10h-20a.toml", 207_335),
            ("25h-75a.toml", 757_803),
        ] {
            let path = dir.join(file);
            let p = load_profile(&path).expect(file);
            let plan = p.seed_plan(90);
            assert_eq!(plan.events, events, "{file}: {plan:?}");
            assert!(
                (plan.hours - 514.2857).abs() < 1e-3,
                "{file}: {}",
                plan.hours
            );
            assert!(
                (plan.per_human_hour - 23.5 * 90.0 / 690.0).abs() < 1e-9,
                "{file}"
            );
            assert!((plan.per_agent_hour - 74.5 * 0.25).abs() < 1e-9, "{file}");
            let args = Args::try_parse_from([
                "tenant_sim",
                "--profile",
                &path.to_string_lossy(),
                "--seed-days",
                "90",
            ])
            .expect("args");
            assert_eq!(seed_count(&p, &args), events, "{file}");
        }
        let both = Args::try_parse_from([
            "tenant_sim",
            "--profile",
            "x.toml",
            "--seed-days",
            "90",
            "--seed-events",
            "5",
        ]);
        assert!(both.is_err(), "--seed-days with --seed-events");
    }

    /// A whole run on a fifo, against a relay that accepts everything. Its
    /// phases go to phases.jsonl. A band whose lease runs out with no newer
    /// signal ends the run on its own, exit 5, and the last live.json says
    /// "lease"; a `stop` ends it with "stop". One test, so two runs never
    /// share the phases file at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_run_on_a_fifo_ends_on_stop_or_when_its_lease_runs_out() {
        use sim::admission::testrelay::accepting_relay;
        let relay = accepting_relay().await;
        let dir = sim::guard::testsrv::tempdir();
        let solo =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../perf/profiles/1h-5a.toml");
        let text = std::fs::read_to_string(&solo)
            .expect("solo")
            .replace("repos            = 1", "repos            = 0");
        assert!(text.contains("repos            = 0"), "no repos: no clone");
        let profile = dir.join("solo-no-repos.toml");
        std::fs::write(&profile, text).expect("profile");
        let deny = dir.join("deny");
        std::fs::write(&deny, "").expect("deny");
        let read = |p: &std::path::Path| std::fs::read_to_string(p).unwrap_or_default();
        for (name, lines, want_code, want_ended) in [
            ("lease", vec!["band floor 2"], 5, "lease"),
            ("stop", vec!["band floor 60", "stop"], 0, "stop"),
        ] {
            let out = dir.join(name);
            let args = Args::try_parse_from([
                "tenant_sim".to_string(),
                "--profile".into(),
                profile.to_string_lossy().into_owned(),
                "--relay-url".into(),
                relay.clone(),
                "--http-url".into(),
                "http://127.0.0.1:1".into(),
                "--allow-cidr".into(),
                "127.0.0.0/8".into(),
                "--deny-list".into(),
                deny.to_string_lossy().into_owned(),
                "--out-dir".into(),
                out.to_string_lossy().into_owned(),
                "--band-signal".into(),
                "fifo".into(),
                "--git-credential-helper".into(),
                "/usr/bin/true".into(),
            ])
            .expect("args");
            let task = tokio::spawn(run(args));
            let phases = out.join("phases.jsonl");
            let started = Instant::now();
            while !read(&phases).contains("\"phase\":\"ready\"") {
                assert!(
                    started.elapsed() < Duration::from_secs(60),
                    "{name}: never ready: {}",
                    read(&phases)
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let fifo = out.join("band.fifo");
            for l in lines {
                let (fifo, l) = (fifo.clone(), l.to_string());
                tokio::task::spawn_blocking(move || {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fifo)
                        .expect("open fifo");
                    writeln!(f, "{l}").expect("write");
                })
                .await
                .expect("writer");
            }
            let code = timeout(Duration::from_secs(60), task)
                .await
                .expect("the run ended")
                .expect("join")
                .expect("run");
            assert_eq!(code, want_code, "{name}");
            let live: serde_json::Value =
                serde_json::from_str(&read(&out.join("live.json"))).expect("live.json");
            assert_eq!(live["ended"], want_ended, "{name}");
            let names: Vec<String> = read(&phases)
                .lines()
                .map(|l| {
                    serde_json::from_str::<serde_json::Value>(l).expect("phase line")["phase"]
                        .as_str()
                        .expect("phase")
                        .to_string()
                })
                .collect();
            let want: &[&str] = if name == "lease" {
                &["setup-done", "ready", "lease-ran-out"]
            } else {
                &["setup-done", "ready"]
            };
            assert_eq!(names, want, "{name}");
        }

        // A ramp: 3 teams provisioned, 1 on at the start, switched on by
        // `ramp` signals, each joiner counted as it connects.
        let out = dir.join("ramp");
        let args = Args::try_parse_from([
            "tenant_sim".to_string(),
            "--profile".into(),
            profile.to_string_lossy().into_owned(),
            "--relay-url".into(),
            relay.clone(),
            "--http-url".into(),
            "http://127.0.0.1:1".into(),
            "--allow-cidr".into(),
            "127.0.0.0/8".into(),
            "--deny-list".into(),
            deny.to_string_lossy().into_owned(),
            "--out-dir".into(),
            out.to_string_lossy().into_owned(),
            "--band-signal".into(),
            "fifo".into(),
            "--git-credential-helper".into(),
            "/usr/bin/true".into(),
            "--ramp-max".into(),
            "18".into(),
            "--ramp-start".into(),
            "6".into(),
        ])
        .expect("args");
        let task = tokio::spawn(run(args));
        let phases = out.join("phases.jsonl");
        let started = Instant::now();
        while !read(&phases).contains("\"phase\":\"ready\"") {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "ramp: never ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pop: serde_json::Value =
            serde_json::from_str(&read(&out.join("identities.json"))).expect("identities");
        assert_eq!(
            (
                pop["humans"].as_array().map(Vec::len),
                pop["agents"].as_array().map(Vec::len)
            ),
            (Some(3), Some(15)),
            "the whole ramp is provisioned"
        );
        let fifo = out.join("band.fifo");
        let send = |l: &'static str| {
            let fifo = fifo.clone();
            tokio::task::spawn_blocking(move || {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo)
                    .expect("open fifo");
                writeln!(f, "{l}").expect("write");
            })
        };
        let joined = |out: &std::path::Path| {
            serde_json::from_str::<serde_json::Value>(&read(&out.join("live.json")))
                .ok()
                .and_then(|v| v["joined"].as_u64())
        };
        // Only the start is on at first; live.json is rewritten every 2 s.
        for (line, want) in [
            (None, 6),
            (Some("band steady 60"), 6),
            (Some("ramp 12 60"), 12),
            (Some("ramp 18 60"), 18),
        ] {
            if let Some(line) = line {
                send(line).await.expect("writer");
            }
            let started = Instant::now();
            while joined(&out) != Some(want) {
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "{line:?}: joined {:?}, not {want}",
                    joined(&out)
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        send("stop").await.expect("writer");
        let code = timeout(Duration::from_secs(60), task)
            .await
            .expect("the ramp ended")
            .expect("join")
            .expect("run");
        let live: serde_json::Value =
            serde_json::from_str(&read(&out.join("live.json"))).expect("live.json");
        assert_eq!(
            (code, live["ended"].as_str(), live["joined"].as_u64()),
            (0, Some("stop"), Some(18))
        );

        // A setup clone that can't happen fails setup: exit 3, before
        // setup-done, with the clone's own line. The solo profile has one
        // repo; the git server refuses it, or the credential helper is
        // missing (then no git runs).
        let refusing =
            sim::guard::testsrv::Server::start("127.0.0.1:0", sim::guard::testsrv::status(404, ""));
        for (name, helper, reached) in [
            ("clone-refused", "/usr/bin/true".to_string(), true),
            (
                "clone-no-helper",
                dir.join("no-such-helper").to_string_lossy().into_owned(),
                false,
            ),
        ] {
            let before = refusing.accepts();
            let out = dir.join(name);
            let args = Args::try_parse_from([
                "tenant_sim".to_string(),
                "--profile".into(),
                solo.to_string_lossy().into_owned(),
                "--relay-url".into(),
                relay.clone(),
                "--http-url".into(),
                refusing.http(),
                "--allow-cidr".into(),
                "127.0.0.0/8".into(),
                "--deny-list".into(),
                deny.to_string_lossy().into_owned(),
                "--out-dir".into(),
                out.to_string_lossy().into_owned(),
                "--band-signal".into(),
                "fifo".into(),
                "--git-credential-helper".into(),
                helper,
            ])
            .expect("args");
            let task = tokio::spawn(run(args));
            let code = match timeout(Duration::from_secs(60), task).await {
                Ok(joined) => joined.expect("join").expect("run"),
                Err(_) => panic!("{name}: the run went on past a failed setup clone"),
            };
            assert_eq!(code, 3, "{name}");
            assert!(
                !read(&out.join("phases.jsonl")).contains("setup-done"),
                "{name}: setup-done after a failed clone"
            );
            assert_eq!(
                refusing.accepts() > before,
                reached,
                "{name}: git reached the server"
            );
        }

        setup_membership_and_stops(&profile, &deny, &dir).await;
    }

    /// The rest of the run-level rows, run in the same test as the ones
    /// above so no two runs share the phases file at once.
    async fn setup_membership_and_stops(
        profile: &std::path::Path,
        deny: &std::path::Path,
        dir: &std::path::Path,
    ) {
        use sim::admission::testrelay::{relay_with, Answer};
        let read = |p: &std::path::Path| std::fs::read_to_string(p).unwrap_or_default();
        let phases_of = |out: &std::path::Path| -> Vec<serde_json::Value> {
            read(&out.join("phases.jsonl"))
                .lines()
                .map(|l| serde_json::from_str(l).expect("phase line"))
                .collect()
        };
        let live_of = |out: &std::path::Path| -> serde_json::Value {
            serde_json::from_str(&read(&out.join("live.json"))).unwrap_or_default()
        };
        let start = |name: &str, relay: &str, extra: &[&str]| {
            let out = dir.join(name);
            let mut argv: Vec<String> = [
                "tenant_sim",
                "--profile",
                &profile.to_string_lossy(),
                "--relay-url",
                relay,
                "--http-url",
                "http://127.0.0.1:1",
                "--allow-cidr",
                "127.0.0.0/8",
                "--deny-list",
                &deny.to_string_lossy(),
                "--out-dir",
                &out.to_string_lossy(),
                "--band-signal",
                "fifo",
                "--git-credential-helper",
                "/usr/bin/true",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            argv.extend(extra.iter().map(|s| s.to_string()));
            let args = Args::try_parse_from(argv).expect("args");
            (tokio::spawn(run(args)), out)
        };
        let send = |out: &std::path::Path, line: &'static str| {
            let fifo = out.join("band.fifo");
            tokio::task::spawn_blocking(move || {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo)
                    .expect("open fifo");
                writeln!(f, "{line}").expect("write");
            })
        };
        async fn until(what: &str, within: Duration, mut ok: impl FnMut() -> bool) {
            let started = Instant::now();
            while !ok() {
                assert!(started.elapsed() < within, "{what}: not within {within:?}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        async fn ends(
            name: &str,
            task: tokio::task::JoinHandle<Result<i32>>,
            within: Duration,
        ) -> i32 {
            match timeout(within, task).await {
                Ok(joined) => joined.expect("join").expect("run"),
                Err(_) => panic!("{name}: the run didn't end within {within:?}"),
            }
        }

        // HIGH 1: every relay-member (9030) and channel-member (9000) event
        // must land, or setup fails: exit 3, its own line, no setup-done,
        // nothing measured.
        fn reject_9030(k: u64) -> Answer {
            if k == 9030 {
                Answer::Reject("blocked: test 9030")
            } else {
                Answer::Accept
            }
        }
        fn reject_9000(k: u64) -> Answer {
            if k == 9000 {
                Answer::Reject("restricted: test 9000")
            } else {
                Answer::Accept
            }
        }
        fn close_on_9000(k: u64) -> Answer {
            if k == 9000 {
                Answer::Close
            } else {
                Answer::Accept
            }
        }
        // A row: its name, the relay's answers, and the line it fails setup
        // with (whole, or as a start and an end around the channel id).
        type Row = (&'static str, fn(u64) -> Answer, &'static str, &'static str);
        let rows: [Row; 3] = [
            ("member-9030-rejected", reject_9030, "9030 h0 rejected: blocked: test 9030", ""),
            ("member-9000-rejected", reject_9000, "9000 h0 ", " rejected: restricted: test 9000"),
            ("member-9000-closed", close_on_9000, "9000 h0 ", ": WebSocket error: WebSocket protocol error: Connection reset without closing handshake"),
        ];
        for (name, answer, starts, ends_with) in rows {
            let relay = relay_with(answer).await;
            let (task, out) = start(name, &relay.url, &[]);
            let code = ends(name, task, Duration::from_secs(60)).await;
            assert_eq!(code, 3, "{name}");
            let phases = phases_of(&out);
            let names: Vec<&str> = phases.iter().filter_map(|p| p["phase"].as_str()).collect();
            assert_eq!(names, ["setup-failed"], "{name}: no setup-done, no ready");
            let why = phases[0]["why"].as_str().expect("why");
            if ends_with.is_empty() {
                assert_eq!(why, starts, "{name}");
            } else {
                assert!(
                    why.starts_with(starts) && why.ends_with(ends_with),
                    "{name}: {why}"
                );
            }
            assert_eq!(live_of(&out)["sent"], 0, "{name}: a band was measured");
        }

        // The relay's limit texts in setup. A shed is waited out and the
        // event resent, like the quota, and counted apart in setup-done's
        // provision; setup fails only when the waits give up. A text the
        // pinned relay doesn't send fails setup at once.
        fn shed_9030_once(k: u64) -> Answer {
            static SHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if k == 9030 && !SHED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                Answer::Notice("rate-limited: too many concurrent requests")
            } else {
                Answer::Accept
            }
        }
        let relay = relay_with(shed_9030_once).await;
        let (task, out) = start("setup-shed-once", &relay.url, &[]);
        until(
            "setup-shed-once: setup-done",
            Duration::from_secs(60),
            || read(&out.join("phases.jsonl")).contains("\"setup-done\""),
        )
        .await;
        let done = phases_of(&out)
            .into_iter()
            .find(|p| p["phase"] == "setup-done")
            .expect("setup-done");
        assert_eq!(
            (
                done["provision"]["relay_shed"].as_u64(),
                done["provision"]["rate_limited"].as_u64()
            ),
            (Some(1), Some(0)),
            "{done}"
        );
        until("setup-shed-once: the fifo", Duration::from_secs(20), || {
            out.join("band.fifo").exists()
        })
        .await;
        send(&out, "stop").await.expect("writer");
        assert_eq!(
            ends("setup-shed-once", task, Duration::from_secs(30)).await,
            0
        );
        fn always_shed_9030(k: u64) -> Answer {
            if k == 9030 {
                Answer::Notice("rate-limited: shared admission unavailable")
            } else {
                Answer::Accept
            }
        }
        fn unknown_9030(k: u64) -> Answer {
            if k == 9030 {
                Answer::Notice("rate-limited: slow down")
            } else {
                Answer::Accept
            }
        }
        for (name, answer, why, within) in [
            (
                "setup-always-shed",
                always_shed_9030 as fn(u64) -> Answer,
                "9030 h0: still shed after 21 waits: rate-limited: shared admission unavailable",
                Duration::from_secs(60),
            ),
            (
                "setup-unknown-limit",
                unknown_9030,
                "9030 h0: the relay sent a limit it doesn't send: rate-limited: slow down",
                Duration::from_secs(15),
            ),
        ] {
            let relay = relay_with(answer).await;
            let (task, out) = start(name, &relay.url, &[]);
            assert_eq!(ends(name, task, within).await, 3, "{name}");
            assert_eq!(
                phases_of(&out),
                vec![serde_json::json!({"phase": "setup-failed", "why": why})],
                "{name}"
            );
        }

        // A stop while setup waits out a rate limit (the relay names 60 s)
        // ends setup within seconds, with its own line.
        fn rate_limit_9030(k: u64) -> Answer {
            if k == 9030 {
                Answer::RateLimit
            } else {
                Answer::Accept
            }
        }
        let relay = relay_with(rate_limit_9030).await;
        let (task, out) = start("setup-stopped", &relay.url, &[]);
        until("setup-stopped: the fifo", Duration::from_secs(20), || {
            out.join("band.fifo").exists()
        })
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        send(&out, "stop").await.expect("writer");
        assert_eq!(
            ends("setup-stopped", task, Duration::from_secs(15)).await,
            3
        );
        let phases = phases_of(&out);
        assert_eq!(
            phases,
            vec![
                serde_json::json!({"phase": "setup-failed", "why": "9030 h0: the run was stopped during setup"})
            ]
        );

        // HIGH 2: a relay that drops, then a lease that runs out with no
        // newer signal: every identity stuck reconnecting stops, exit 5,
        // and the last live.json says lease.
        let relay = relay_with(|_| Answer::Accept).await;
        let (task, out) = start("dropped-lease", &relay.url, &[]);
        until("dropped-lease: ready", Duration::from_secs(60), || {
            read(&out.join("phases.jsonl")).contains("\"ready\"")
        })
        .await;
        send(&out, "band floor 4").await.expect("writer");
        relay.kill();
        assert_eq!(
            ends("dropped-lease", task, Duration::from_secs(30)).await,
            5
        );
        let live = live_of(&out);
        assert_eq!(live["ended"], "lease");
        assert!(
            live["client_errors"]["reconnect_failed"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "the identities were reconnecting: {live}"
        );

        // The same, ended by a stop: exit 0, the last live.json says stop.
        let relay = relay_with(|_| Answer::Accept).await;
        let (task, out) = start("dropped-stop", &relay.url, &[]);
        until("dropped-stop: ready", Duration::from_secs(60), || {
            read(&out.join("phases.jsonl")).contains("\"ready\"")
        })
        .await;
        send(&out, "band floor 600").await.expect("writer");
        relay.kill();
        until(
            "dropped-stop: reconnecting",
            Duration::from_secs(20),
            || {
                live_of(&out)["client_errors"]["reconnect_failed"]
                    .as_u64()
                    .unwrap_or(0)
                    > 0
            },
        )
        .await;
        send(&out, "stop").await.expect("writer");
        assert_eq!(ends("dropped-stop", task, Duration::from_secs(30)).await, 0);
        assert_eq!(live_of(&out)["ended"], "stop");

        // A stop while setup waits for continue ends the run there.
        let relay = relay_with(|_| Answer::Accept).await;
        let (task, out) = start("stop-before-continue", &relay.url, &["--pause-after-setup"]);
        until(
            "stop-before-continue: setup-done",
            Duration::from_secs(60),
            || read(&out.join("phases.jsonl")).contains("\"setup-done\""),
        )
        .await;
        send(&out, "stop").await.expect("writer");
        assert_eq!(
            ends("stop-before-continue", task, Duration::from_secs(30)).await,
            0
        );
        assert_eq!(live_of(&out)["ended"], "stop");
        assert!(
            !read(&out.join("phases.jsonl")).contains("\"ready\""),
            "the population connected"
        );
    }

    #[test]
    fn a_ramps_shape_is_checked() {
        let solo = load_profile(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../perf/profiles/1h-5a.toml"),
        )
        .expect("solo");
        let args = |extra: &[&str]| {
            let mut v = vec!["tenant_sim", "--profile", "x.toml"];
            v.extend_from_slice(extra);
            Args::try_parse_from(v).expect("args")
        };
        let err = |extra: &[&str]| {
            check_ramp(&solo, &args(extra))
                .map(|_| ())
                .expect_err("refused")
                .to_string()
        };
        assert!(check_ramp(&solo, &args(&[])).expect("none").is_none());
        assert_eq!(
            err(&["--ramp-max", "20"]),
            "--ramp-max 20 is not a whole number of teams of 6 (a human and 5 agents)"
        );
        assert_eq!(
            err(&["--ramp-max", "0", "--ramp-start", "6"]),
            "--ramp-start needs --ramp-max"
        );
        let team = load_profile(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../perf/profiles/10h-20a.toml"),
        )
        .expect("team");
        assert_eq!(
            check_ramp(&team, &args(&["--ramp-max", "15"]))
                .map(|_| ())
                .expect_err("under")
                .to_string(),
            "--ramp-max 15 is under the profile's population, 30"
        );
        assert_eq!(
            err(&["--ramp-max", "18", "--ramp-start", "0"]),
            "--ramp-start 0 is not 1 to --ramp-max 18"
        );
        assert_eq!(
            err(&["--ramp-max", "18", "--ramp-start", "19"]),
            "--ramp-start 19 is not 1 to --ramp-max 18"
        );
        let r = check_ramp(&team, &args(&["--ramp-max", "660"]))
            .expect("ok")
            .expect("a ramp");
        assert_eq!(
            (r.max, r.start),
            (660, 30),
            "starts at the profile's population"
        );
        let p = ramp_profile(&team, &r);
        assert_eq!(
            (p.humans, p.agent_count(), p.identity_count()),
            (220, 440, 660)
        );
        assert_eq!(
            (p.channels, p.repos),
            (team.channels, team.repos),
            "the world stays the profile's"
        );
    }

    /// Team by team: a human, then their agents; the first 15 are 5 teams.
    #[test]
    fn the_ramp_order() {
        let order: Vec<(Role, usize, usize)> = (0..5)
            .map(|i| (Role::Human, i, ramp_index(Role::Human, i, 2)))
            .chain((0..10).map(|i| (Role::Agent, i, ramp_index(Role::Agent, i, 2))))
            .collect();
        let mut by_index: Vec<_> = order.iter().map(|(r, i, at)| (*at, *r, *i)).collect();
        by_index.sort_by_key(|x| x.0);
        let want: Vec<(usize, Role, usize)> = (0..5)
            .flat_map(|t| {
                [
                    (3 * t, Role::Human, t),
                    (3 * t + 1, Role::Agent, 2 * t),
                    (3 * t + 2, Role::Agent, 2 * t + 1),
                ]
            })
            .collect();
        assert_eq!(by_index, want);
    }

    /// The open-file limit, from /proc/self/limits' text.
    #[test]
    fn the_open_file_limit_must_hold_the_ramp() {
        let ramp = Ramp {
            max: 660,
            start: 30,
        };
        let limits = |soft: &str| {
            format!("Limit                     Soft Limit           Hard Limit           Units\nMax cpu time              unlimited            unlimited            seconds\nMax open files            {soft:<21}524288               files\n")
        };
        assert_eq!(
            check_open_files_in(Some(&limits("1024")), &ramp).map(|_| ()).expect_err("low").to_string(),
            "the open-file limit is 1024; a ramp to 660 identities needs at least 2896 (raise LimitNOFILE)"
        );
        assert!(check_open_files_in(Some(&limits("65536")), &ramp).is_ok());
        assert!(check_open_files_in(Some(&limits("unlimited")), &ramp).is_ok());
        assert!(
            check_open_files_in(None, &ramp).is_ok(),
            "no /proc: not Linux"
        );
        assert_eq!(
            check_open_files_in(Some("Max cpu time unlimited\n"), &ramp)
                .map(|_| ())
                .expect_err("none")
                .to_string(),
            "/proc/self/limits has no open-file limit"
        );
    }

    #[test]
    fn nip_oa_agents_are_not_direct_relay_members() {
        let mut profile = shipped_profile();
        assert!(profile.agent.nip_oa);
        let pop = generate_population(&profile);
        let direct: Vec<&str> = direct_members(&profile, &pop)
            .iter()
            .map(|r| r.role.as_str())
            .collect();
        assert_eq!(direct.len(), pop.humans.len());
        assert!(direct.iter().all(|role| *role == "human"));

        profile.agent.nip_oa = false;
        assert_eq!(
            direct_members(&profile, &pop).len(),
            pop.humans.len() + pop.agents.len()
        );
    }

    #[test]
    fn every_agent_has_an_attesting_owner() {
        let profile = shipped_profile();
        let pop = generate_population(&profile);
        for agent in &pop.agents {
            let owner = owner_of(&pop, agent).expect("owner");
            let keys = pop.keys_of(agent).expect("keys");
            let tag = nip_oa_json(&owner, &keys).expect("tag");
            buzz_sdk::nip_oa::verify_auth_tag(&tag, &keys.public_key()).expect("verifies");
        }
    }
}
