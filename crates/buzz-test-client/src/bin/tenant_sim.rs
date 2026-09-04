//! Population generator: 10 humans × 20 agents against a Buzz relay.

#[path = "../sim/mod.rs"]
mod sim;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use buzz_test_client::BuzzTestClient;
use clap::Parser;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sim::git;
use sim::identity::{
    connect_identity, generate_population, load_population, save_population, uuid_v4, Population,
    RepoRef, World,
};
use sim::kinds;
use sim::profile::{load_profile, Profile};
use sim::roles::{Band, Role};
use sim::stats::Stats;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tracing::warn;

#[derive(Parser, Debug)]
#[command(name = "tenant_sim", about = "Buzz relay population generator")]
struct Args {
    /// Path to the profile TOML.
    #[arg(long)]
    profile: PathBuf,

    /// Relay WebSocket URL.
    #[arg(long, default_value = "ws://localhost:3030")]
    relay_url: String,

    /// Relay HTTP URL (media + git).
    #[arg(long, default_value = "http://localhost:3030")]
    http_url: String,

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
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn spawn_band_reader(kind: &str, out_dir: &std::path::Path, tx: watch::Sender<Band>) -> Result<()> {
    let source: Box<dyn BufRead + Send> = if kind == "fifo" {
        let path = out_dir.join("band.fifo");
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        let status = std::process::Command::new("mkfifo").arg(&path).status()?;
        if !status.success() {
            bail!("mkfifo {} failed", path.display());
        }
        let file = std::fs::File::open(&path)?;
        Box::new(std::io::BufReader::new(file))
    } else {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    };
    std::thread::spawn(move || {
        for line in source.lines() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() {
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
    });
    Ok(())
}

async fn send_with_retry(
    client: &mut BuzzTestClient,
    keys: &nostr::Keys,
    relay_url: &str,
    event: nostr::Event,
    what: &str,
) -> Result<buzz_test_client::OkResponse> {
    let mut last = anyhow::anyhow!("send failed");
    for attempt in 0..4 {
        match client.send_event(event.clone()).await {
            Ok(ok) => return Ok(ok),
            Err(e) => {
                last = anyhow::anyhow!("{what}: {e}");
                warn!("{what} attempt {attempt}: {e}");
                tokio::time::sleep(Duration::from_millis(200 * (attempt + 1) as u64)).await;
                match BuzzTestClient::connect(relay_url, keys).await {
                    Ok(c) => *client = c,
                    Err(ce) => warn!("reconnect after {what}: {ce}"),
                }
            }
        }
    }
    Err(last)
}

async fn provision(
    profile: &Profile,
    pop: &Population,
    args: &Args,
    stats: &Stats,
) -> Result<(Vec<String>, Vec<RepoRef>)> {
    let owner_keys = pop.owner_keys()?;
    let mut owner = BuzzTestClient::connect(&args.relay_url, &owner_keys)
        .await
        .context("owner connect")?;
    if args.require_membership {
        for rec in pop.humans.iter().chain(pop.agents.iter()) {
            let ev = kinds::relay_member_add(&owner_keys, &profile.kinds, &rec.pubkey)?;
            let ok = send_with_retry(
                &mut owner,
                &owner_keys,
                &args.relay_url,
                ev,
                &format!("9030 {}", rec.name),
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
            &args.relay_url,
            ev,
            &format!("9007 {i}"),
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
                &args.relay_url,
                ev,
                &format!("9000 {} {ch}", rec.name),
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
            let name = format!("sim-repo-{i}");
            let ev = kinds::repo_announce(&agent_keys, &profile.kinds, &name, &name, &channels[0])?;
            let mut agent_client =
                connect_identity(&args.relay_url, agent, &agent_keys, None).await?;
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
                    &args.http_url,
                    &agent.pubkey,
                    &name,
                    &dest,
                    helper,
                    &agent.nsec,
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

    let stats = Arc::new(Stats::new());
    let (channels, repos) = match provision(&profile, &pop, &args, &stats).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warm-up failed: {e:#}");
            warn!("warm-up failed: {e:#}");
            return Ok(3);
        }
    };

    let world = Arc::new(World {
        relay_url: args.relay_url.clone(),
        http_url: args.http_url.clone(),
        channels,
        human_pubkeys: pop.humans.iter().map(|h| h.pubkey.clone()).collect(),
        repos,
        git_helper: args.git_credential_helper.clone(),
        out_dir: out_dir.clone(),
        blink: args.blink,
    });

    let (band_tx, band_rx) = watch::channel(Band::Warmup);
    spawn_band_reader(&args.band_signal, &out_dir, band_tx)?;

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
        let owner_keys = rec
            .owner_name
            .as_ref()
            .and_then(|n| pop.humans.iter().find(|h| h.name == *n))
            .and_then(|h| pop.keys_of(h).ok());
        let git_repo = world
            .repos
            .iter()
            .find(|r| r.owner_hex == rec.pubkey)
            .map(|r| git::GitRepo {
                name: r.name.clone(),
                owner_hex: r.owner_hex.clone(),
                owner_nsec: r.owner_nsec.clone(),
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

    println!(
        "{}",
        serde_json::json!({"phase": "ready", "identities": expected})
    );
    let _ = std::io::stdout().flush();

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

    let mut ends = HashMap::new();
    ends.insert("floor".into(), unix_now());
    ends.insert("steady".into(), unix_now());
    ends.insert("peak".into(), unix_now());
    let summary = stats.summarize(
        &profile.name,
        profile.seed,
        &args.relay_url,
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
