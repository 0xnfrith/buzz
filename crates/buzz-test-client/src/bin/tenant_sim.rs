//! Population generator: 10 humans × 20 agents against a Buzz relay.

#[path = "../sim/mod.rs"]
mod sim;

use std::collections::HashMap;
use std::io::{BufRead, Write};
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
use sim::profile::{load_profile, Profile};
use sim::roles::{Band, Role};
use sim::seed;
use sim::stats::{write_live, Stats};
use tokio::sync::{mpsc, oneshot, watch};
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

    /// Band signal source: stdin (default) or fifo.
    #[arg(long, default_value = "stdin")]
    band_signal: String,

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
    #[arg(long, default_value_t = 0)]
    seed_events: u64,

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

    /// Exit after setup (provisioning and seed); no population run.
    #[arg(long)]
    setup_only: bool,
}

/// What provisioning cost, for the `setup-done` line.
#[derive(Debug, Default)]
struct SetupStats {
    events: u64,
    rate_limited: u64,
}

/// One JSON phase line on stdout, flushed so the orchestrator sees it now.
fn emit(line: &serde_json::Value) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read band signals (and the one-shot `continue` after setup) from stdin or
/// a fifo. Started before provisioning so `continue` is never missed.
fn spawn_band_reader(
    kind: &str,
    out_dir: &std::path::Path,
    tx: watch::Sender<Band>,
    go: oneshot::Sender<()>,
) -> Result<()> {
    let fifo = if kind == "fifo" {
        let path = out_dir.join("band.fifo");
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        let status = std::process::Command::new("mkfifo").arg(&path).status()?;
        if !status.success() {
            bail!("mkfifo {} failed", path.display());
        }
        Some(path)
    } else {
        None
    };
    std::thread::spawn(move || {
        // Opening a fifo blocks until a writer appears; do it off the main task.
        let source: Box<dyn BufRead + Send> = match fifo {
            Some(path) => match std::fs::File::open(&path) {
                Ok(file) => Box::new(std::io::BufReader::new(file)),
                Err(e) => {
                    eprintln!("tenant_sim: open {}: {e}", path.display());
                    return;
                }
            },
            None => Box::new(std::io::BufReader::new(std::io::stdin())),
        };
        let mut go = Some(go);
        for line in source.lines() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == "continue" {
                if let Some(go) = go.take() {
                    let _ = go.send(());
                }
                continue;
            }
            let token = line.strip_prefix("band ").unwrap_or(line);
            if let Some(band) = Band::parse(token) {
                let _ = tx.send(band);
                if band == Band::Stop {
                    break;
                }
            } else {
                eprintln!("tenant_sim: unknown band signal {line:?}");
            }
        }
        // End of input with no `stop` (the orchestrator went away) stops the
        // run too. Identities read the last value of the closed channel.
        let _ = tx.send(Band::Stop);
    });
    Ok(())
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

/// Owner-socket publish. A relay rate-limit NOTICE waits out the window and
/// resends the same event (the relay did not process it); a transport error
/// reconnects. Both are bounded.
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
                tokio::time::sleep(retry_in).await;
            }
            Err(e) => {
                last = anyhow::anyhow!("{what}: {e}");
                warn!("{what} attempt {attempt}: {e}");
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
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
            if !ok.accepted {
                warn!("9030 {} rejected: {}", rec.name, ok.message);
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
            match send_with_retry(
                &mut owner,
                &owner_keys,
                &targets.relay,
                ev,
                &format!("9000 {} {ch}", rec.name),
                setup,
            )
            .await
            {
                Ok(ok) if !ok.accepted => {
                    warn!("9000 {} {} rejected: {}", rec.name, ch, ok.message);
                }
                Ok(_) => {}
                Err(e) => warn!("9000 {} {ch}: {e:#}", rec.name),
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
            if helper.exists() {
                let dest = args
                    .out_dir
                    .as_ref()
                    .map(|p| p.join("git").join(&name))
                    .unwrap_or_else(|| PathBuf::from("git").join(&name));
                match git::clone_repo(
                    &targets.http,
                    &agent.pubkey,
                    &name,
                    &dest,
                    helper,
                    &agent.nsec,
                    auth_tag.as_deref(),
                ) {
                    Ok(repo) => {
                        repos.push(RepoRef {
                            name: repo.name.clone(),
                            owner_hex: repo.owner_hex.clone(),
                            owner_nsec: repo.owner_nsec.clone(),
                            a_tag: format!("30617:{}:{}", repo.owner_hex, repo.name),
                            clone_url: repo.url.clone(),
                            worktree: repo.worktree.clone(),
                        });
                    }
                    Err(e) => warn!("git clone {name}: {e}"),
                }
            } else {
                warn!(
                    "git-credential helper {} missing; skipping clone",
                    helper.display()
                );
            }
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

    let pop = if let Some(path) = &args.identities {
        load_population(path)?
    } else {
        generate_population(&profile)
    };
    save_population(&out_dir.join("identities.json"), &pop)?;

    let (band_tx, band_rx) = watch::channel(Band::Warmup);
    let (go_tx, go_rx) = oneshot::channel();
    spawn_band_reader(&args.band_signal, &out_dir, band_tx, go_tx)?;

    let stats = Arc::new(Stats::new());
    // The live counters (<out-dir>/live.json), rewritten every LIVE_EVERY,
    // so a sampler can see the generator's own errors during a band. It
    // exists from the start; a missing file is the sampler's error, not
    // "no errors".
    let live_path = out_dir.join("live.json");
    write_live(&live_path, &stats.live(unix_now()))?;
    let live_task = {
        let (stats, path) = (stats.clone(), live_path.clone());
        tokio::spawn(async move {
            let mut every = tokio::time::interval(LIVE_EVERY);
            loop {
                every.tick().await;
                if let Err(e) = write_live(&path, &stats.live(unix_now())) {
                    warn!("live counters {}: {e}", path.display());
                }
            }
        })
    };
    let setup_started = Instant::now();
    let mut setup = SetupStats::default();
    let (channels, repos) =
        match provision(&profile, &pop, &args, &targets, &stats, &mut setup).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("warm-up failed: {e:#}");
                warn!("warm-up failed: {e:#}");
                return Ok(3);
            }
        };
    let provision_s = setup_started.elapsed().as_secs_f64();

    let mut seed_failed = false;
    if args.seed_events > 0 {
        emit(&serde_json::json!({"phase": "seed-start", "t_unix_ms": kinds::now_ms()}));
        let report = seed::seed(
            &targets.relay,
            &pop,
            &profile.kinds,
            &channels,
            args.seed_events,
            Duration::from_secs(args.seed_max_seconds),
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
            "seconds": provision_s,
        },
    }));
    if args.setup_only {
        return Ok(if seed_failed { 1 } else { 0 });
    }
    if args.pause_after_setup && go_rx.await.is_err() {
        eprintln!("band signal closed before continue");
        return Ok(3);
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
    });

    let profile = Arc::new(profile);
    let expected = profile.identity_count() as usize;
    let (ready_tx, mut ready_rx) = mpsc::channel::<Result<(), String>>(expected);
    let mut tasks = Vec::new();
    let mut salt = 10u32;
    for rec in pop.humans.iter().cloned() {
        salt += 1;
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
            )
            .await
        }));
    }
    for rec in pop.agents.iter().cloned() {
        salt += 1;
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
            )
            .await
        }));
    }
    drop(ready_tx);

    let mut ready = 0usize;
    let wait = timeout(Duration::from_secs(180), async {
        while ready < expected {
            match ready_rx.recv().await {
                Some(Ok(())) => ready += 1,
                Some(Err(e)) => return Err(e),
                None => {
                    return Err(format!(
                        "identity tasks ended after {ready}/{expected} ready"
                    ))
                }
            }
        }
        Ok(())
    })
    .await;
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

    emit(&serde_json::json!({"phase": "ready", "identities": expected}));

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
    write_live(&live_path, &stats.live(unix_now()))?;
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
    if summary.lost_after_backfill > 0 {
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
