//! Real git clone/push through the relay using git-credential-nostr.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

use super::guard::Target;
use super::stats::GitFailure;

const GIT_TIMEOUT: Duration = Duration::from_secs(90);

/// A failed push, and where it failed: the live counters keep the
/// generator's own failures apart from the relay's.
#[derive(Debug)]
pub struct PushError {
    pub at: GitFailure,
    pub err: anyhow::Error,
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.err)
    }
}

fn failed(at: GitFailure) -> impl Fn(anyhow::Error) -> PushError {
    move |err| PushError { at, err }
}

#[derive(Clone)]
pub struct GitRepo {
    pub name: String,
    pub owner_hex: String,
    pub owner_nsec: String,
    /// The owner's NIP-OA credential JSON when the owner is an agent.
    pub owner_auth_tag: Option<String>,
    pub worktree: PathBuf,
    /// The checked remote. Pushes name it explicitly instead of `origin`.
    pub url: Target,
}

fn abs_helper(helper: &Path) -> PathBuf {
    std::fs::canonicalize(helper).unwrap_or_else(|_| {
        if helper.is_absolute() {
            helper.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|d| d.join(helper))
                .unwrap_or_else(|_| helper.to_path_buf())
        }
    })
}

fn wait_child_deadline(child: std::process::Child, timeout: Duration) -> Result<Output> {
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(out) => out.context("wait child"),
        Err(_) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            let _ = rx.recv_timeout(Duration::from_secs(2));
            Err(anyhow!("command pid {pid} timed out after {timeout:?}"))
        }
    }
}

/// Proxy variables git or libcurl would read, in both spellings. Cleared
/// from git's environment; `http.proxy=` also switches proxying off.
pub const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Settings that keep git on the one checked address: no redirects, no
/// proxy, and only the http(s) transports.
pub const GIT_GUARD_CONFIG: [&str; 5] = [
    "http.followRedirects=false",
    "http.proxy=",
    "protocol.allow=never",
    "protocol.http.allow=always",
    "protocol.https.allow=always",
];

/// Credential variables the credential helper (or anything it runs) could
/// pick up from the caller: every `BUZZ_*` and `NOSTR_*` name.
fn inherited_credentials(vars: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    vars.into_iter()
        .filter(|name| {
            name.to_str()
                .is_some_and(|n| n.starts_with("BUZZ_") || n.starts_with("NOSTR_"))
        })
        .collect()
}

/// `git` that authenticates only as this simulated identity. The caller's
/// own Buzz/Nostr credentials (for example an agent's `BUZZ_AUTH_TAG`) are
/// removed, then this identity's key and, for an agent, its own NIP-OA tag
/// are set. Git follows no redirect and uses no proxy (see
/// [`GIT_GUARD_CONFIG`]); injected config (`GIT_CONFIG_PARAMETERS`,
/// `GIT_CONFIG_COUNT`) and proxy variables are removed.
fn git_command(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
    inherited: impl IntoIterator<Item = OsString>,
) -> Command {
    let helper = abs_helper(helper);
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "credential.useHttpPath=true",
        "-c",
        &format!("credential.helper={}", helper.display()),
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
        "-c",
        "user.name=tenant-sim",
        "-c",
        "user.email=tenant-sim@example.com",
    ]);
    for setting in GIT_GUARD_CONFIG {
        cmd.args(["-c", setting]);
    }
    cmd.args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_CONFIG_PARAMETERS");
    for name in PROXY_VARS {
        cmd.env_remove(name);
    }
    for name in inherited_credentials(inherited) {
        cmd.env_remove(name);
    }
    cmd.env("NOSTR_PRIVATE_KEY", nsec);
    if let Some(tag) = auth_tag {
        cmd.env("BUZZ_AUTH_TAG", tag);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

fn git_cmd(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
) -> Result<Output> {
    let inherited = std::env::vars_os().map(|(name, _)| name);
    let child = git_command(args, cwd, helper, nsec, auth_tag, inherited)
        .spawn()
        .with_context(|| format!("spawn git {args:?}"))?;
    wait_child_deadline(child, GIT_TIMEOUT).with_context(|| format!("git {args:?}"))
}

fn git_ok(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
) -> Result<String> {
    let out = git_cmd(args, cwd, helper, nsec, auth_tag)?;
    if !out.status.success() {
        return Err(anyhow!(
            "git {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Clone `<http_url>/git/<owner>/<name>`. `http_url` is a checked target,
/// so git only ever talks to that address.
pub fn clone_repo(
    http_url: &Target,
    owner_hex: &str,
    name: &str,
    dest: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
) -> Result<GitRepo> {
    let url = http_url.join(&format!("/git/{owner_hex}/{name}"))?;
    if dest.exists() {
        std::fs::remove_dir_all(dest).ok();
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    git_ok(
        &["clone", "--quiet", url.as_str(), &dest.to_string_lossy()],
        dest.parent().unwrap_or(Path::new(".")),
        helper,
        nsec,
        auth_tag,
    )?;
    Ok(GitRepo {
        name: name.to_string(),
        owner_hex: owner_hex.to_string(),
        owner_nsec: nsec.to_string(),
        owner_auth_tag: auth_tag.map(str::to_string),
        worktree: dest.to_path_buf(),
        url,
    })
}

/// [`clone_repo`] on tokio's blocking pool: git runs as a child process for
/// up to [`GIT_TIMEOUT`], and must not hold a runtime worker meanwhile.
pub async fn clone_repo_async(
    http_url: Target,
    owner_hex: String,
    name: String,
    dest: PathBuf,
    helper: PathBuf,
    nsec: String,
    auth_tag: Option<String>,
) -> Result<GitRepo> {
    tokio::task::spawn_blocking(move || {
        clone_repo(
            &http_url,
            &owner_hex,
            &name,
            &dest,
            &helper,
            &nsec,
            auth_tag.as_deref(),
        )
    })
    .await
    .map_err(|e| anyhow!("clone task: {e}"))?
}

/// Commits `bytes` as a new file and pushes it. Writing the file, `add`,
/// `commit` and `branch` are the generator's own work (`Local`); the push
/// is the relay's (`Push`). Each blob is a new file, so `commit` always has
/// a change to commit.
pub fn push_blob(
    repo: &GitRepo,
    helper: &Path,
    bytes: &[u8],
    seq: u64,
) -> std::result::Result<(u64, f64), PushError> {
    let local = failed(GitFailure::Local);
    let file = repo.worktree.join(format!("blob-{seq}.bin"));
    std::fs::write(&file, bytes)
        .with_context(|| format!("write {}", file.display()))
        .map_err(&local)?;
    let tag = repo.owner_auth_tag.as_deref();
    git_ok(&["add", "."], &repo.worktree, helper, &repo.owner_nsec, tag).map_err(&local)?;
    git_ok(
        &["commit", "--quiet", "-m", &format!("sim {seq}")],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    )
    .map_err(&local)?;
    git_ok(
        &["branch", "-M", "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    )
    .map_err(&local)?;
    let start = Instant::now();
    git_ok(
        &["push", "--quiet", repo.url.as_str(), "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    )
    .map_err(failed(GitFailure::Push))?;
    Ok((bytes.len() as u64, start.elapsed().as_secs_f64() * 1e3))
}

/// [`push_blob`] on tokio's blocking pool: git runs as child processes for
/// up to [`GIT_TIMEOUT`] each, and must not hold a runtime worker meanwhile.
/// The generator box has 2 vCPUs, so 2 workers: two slow pushes run on
/// them would stall every task, the live counters' writer too.
pub async fn push_blob_async(
    repo: GitRepo,
    helper: PathBuf,
    bytes: Vec<u8>,
    seq: u64,
) -> std::result::Result<(u64, f64), PushError> {
    tokio::task::spawn_blocking(move || push_blob(&repo, &helper, &bytes, seq))
        .await
        .unwrap_or_else(|e| {
            Err(PushError {
                at: GitFailure::Local,
                err: anyhow!("push task: {e}"),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(cmd: &Command, name: &str) -> Option<Option<String>> {
        cmd.get_envs()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
    }

    #[test]
    fn git_uses_only_the_simulated_identitys_credentials() {
        let inherited = [
            "BUZZ_AUTH_TAG",
            "BUZZ_PRIVATE_KEY",
            "NOSTR_PRIVATE_KEY",
            "PATH",
        ]
        .map(OsString::from);
        let agent = git_command(
            &["push"],
            Path::new("."),
            Path::new("/bin/true"),
            "nsec-agent",
            Some("[\"auth\",\"owner\",\"\",\"sig\"]"),
            inherited.clone(),
        );
        assert_eq!(
            env_of(&agent, "BUZZ_AUTH_TAG"),
            Some(Some("[\"auth\",\"owner\",\"\",\"sig\"]".into()))
        );
        assert_eq!(
            env_of(&agent, "NOSTR_PRIVATE_KEY"),
            Some(Some("nsec-agent".into()))
        );
        // The caller's own key is removed, not passed through.
        assert_eq!(env_of(&agent, "BUZZ_PRIVATE_KEY"), Some(None));
        assert_eq!(env_of(&agent, "PATH"), None);

        let human = git_command(
            &["push"],
            Path::new("."),
            Path::new("/bin/true"),
            "nsec-human",
            None,
            inherited,
        );
        // A human carries no NIP-OA tag, and never the caller's.
        assert_eq!(env_of(&human, "BUZZ_AUTH_TAG"), Some(None));
    }

    use crate::sim::guard::testsrv::{self, Server};
    use crate::sim::guard::{Cidr, TargetGuard};

    /// Loopback allowed, `::1` denied: a 302 to `[::1]` is a redirect to a
    /// denied address we can still watch.
    fn guard() -> TargetGuard {
        TargetGuard::new(
            vec![Cidr::parse("127.0.0.0/8").expect("allow")],
            vec![Cidr::parse("::1").expect("deny")],
        )
        .expect("guard")
    }

    const OWNER: &str = "ab";
    const NSEC: &str = "nsec-test";

    #[test]
    fn git_carries_the_guard_settings_and_drops_proxy_and_config_vars() {
        let cmd = git_command(
            &["push"],
            Path::new("."),
            Path::new("/usr/bin/true"),
            NSEC,
            None,
            [],
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for setting in GIT_GUARD_CONFIG {
            assert!(
                args.windows(2).any(|w| w[0] == "-c" && w[1] == setting),
                "missing -c {setting}: {args:?}"
            );
        }
        let push = args.iter().position(|a| a == "push").expect("subcommand");
        assert!(args[..push]
            .iter()
            .any(|a| a == "http.followRedirects=false"));
        for name in PROXY_VARS
            .iter()
            .chain(["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"].iter())
        {
            assert_eq!(env_of(&cmd, name), Some(None), "{name} not removed");
        }
    }

    /// A 302 from the allowed remote to a denied address is not followed.
    #[test]
    fn git_does_not_follow_a_redirect() {
        let denied = Server::start("[::1]:0", testsrv::status(200, ""));
        let first = Server::start(
            "127.0.0.1:0",
            testsrv::redirect_to(&format!(
                "{}/git/{OWNER}/r/info/refs?service=git-upload-pack",
                denied.http()
            )),
        );
        let base = guard()
            .check_url(&first.http(), &["http"])
            .expect("allowed");
        let dir = testsrv::tempdir();
        let err = clone_repo(
            &base,
            OWNER,
            "r",
            &dir.join("r"),
            Path::new("/usr/bin/true"),
            NSEC,
            None,
        )
        .map(|_| ())
        .expect_err("a redirect is not a clone");
        assert!(
            first.accepts() >= 1,
            "git never reached the remote: {err:#}"
        );
        assert_eq!(denied.accepts(), 0, "git followed the redirect: {err:#}");
    }

    const GIT_PROXY_CHILD: &str = "sim::git::tests::git_ignores_proxy_variables";

    /// Proxy variables in git's inherited environment are ignored.
    #[test]
    fn git_ignores_proxy_variables() {
        if testsrv::is_child(GIT_PROXY_CHILD) {
            let target = Server::start("127.0.0.1:0", testsrv::status(404, ""));
            let base = guard()
                .check_url(&target.http(), &["http"])
                .expect("allowed");
            let dir = testsrv::tempdir();
            let _ = clone_repo(
                &base,
                OWNER,
                "r",
                &dir.join("r"),
                Path::new("/usr/bin/true"),
                NSEC,
                None,
            );
            assert!(
                target.accepts() >= 1,
                "git did not go to the remote directly"
            );
            println!("CHILD_OK {GIT_PROXY_CHILD}");
            return;
        }
        let proxy = Server::start("127.0.0.1:0", testsrv::status(502, ""));
        testsrv::run_child(GIT_PROXY_CHILD, &testsrv::proxy_env(&proxy.http()));
        assert_eq!(proxy.accepts(), 0, "git used the proxy");
    }

    /// A push goes to the checked URL, whatever `origin` on disk says.
    #[test]
    fn push_goes_to_the_checked_url_not_origin() {
        let checked = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let elsewhere = Server::start("[::1]:0", testsrv::status(404, ""));
        let dir = testsrv::tempdir();
        let wt = dir.join("wt");
        std::fs::create_dir_all(&wt).expect("mkdir");
        let helper = Path::new("/usr/bin/true");
        git_ok(&["init", "--quiet"], &wt, helper, NSEC, None).expect("init");
        git_ok(
            &[
                "remote",
                "add",
                "origin",
                &format!("{}/git/{OWNER}/r", elsewhere.http()),
            ],
            &wt,
            helper,
            NSEC,
            None,
        )
        .expect("remote");
        let url = guard()
            .check_url(&checked.http(), &["http"])
            .and_then(|t| t.join(&format!("/git/{OWNER}/r")))
            .expect("allowed");
        let repo = GitRepo {
            name: "r".into(),
            owner_hex: OWNER.into(),
            owner_nsec: NSEC.into(),
            owner_auth_tag: None,
            worktree: wt,
            url,
        };
        let _ = push_blob(&repo, helper, b"blob", 1);
        assert!(checked.accepts() >= 1, "push did not reach the checked URL");
        assert_eq!(elsewhere.accepts(), 0, "push went to origin");
    }

    /// A fresh worktree whose pushes go to `url`.
    fn local_repo(wt: PathBuf, url: Target) -> GitRepo {
        std::fs::create_dir_all(&wt).expect("mkdir");
        git_ok(
            &["init", "--quiet"],
            &wt,
            Path::new("/usr/bin/true"),
            NSEC,
            None,
        )
        .expect("init");
        GitRepo {
            name: "r".into(),
            owner_hex: OWNER.into(),
            owner_nsec: NSEC.into(),
            owner_auth_tag: None,
            worktree: wt,
            url,
        }
    }

    fn remote(server: &Server) -> Target {
        guard()
            .check_url(&server.http(), &["http"])
            .and_then(|t| t.join(&format!("/git/{OWNER}/r")))
            .expect("allowed")
    }

    /// Each blob is a new file, so `add`, `commit` and `branch` succeed on
    /// every push of a healthy run: a push the relay refuses fails as the
    /// relay's (`Push`), never as the generator's (`Local`).
    #[test]
    fn a_healthy_run_never_fails_commit() {
        let refusing = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let dir = testsrv::tempdir();
        let repo = local_repo(dir.join("wt"), remote(&refusing));
        let helper = Path::new("/usr/bin/true");
        for seq in 1..=3u64 {
            let e = push_blob(&repo, helper, &[seq as u8; 32], seq).expect_err("a push to a 404");
            assert_eq!(e.at, GitFailure::Push, "push {seq}: {e}");
        }
        let n = git_ok(
            &["rev-list", "--count", "main"],
            &repo.worktree,
            helper,
            NSEC,
            None,
        )
        .expect("rev-list");
        assert_eq!(n.trim(), "3", "every push committed its blob");
        assert!(refusing.accepts() >= 3);
    }

    /// `commit` failing is the generator's own failure. A healthy run can't
    /// reach it (each blob is a new file); the same blob twice does.
    #[test]
    fn a_commit_with_nothing_new_is_local() {
        let refusing = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let dir = testsrv::tempdir();
        let repo = local_repo(dir.join("wt"), remote(&refusing));
        let helper = Path::new("/usr/bin/true");
        let first = push_blob(&repo, helper, b"same", 7).expect_err("a push to a 404");
        assert_eq!(first.at, GitFailure::Push, "{first}");
        let again = push_blob(&repo, helper, b"same", 7).expect_err("nothing to commit");
        assert_eq!(again.at, GitFailure::Local, "{again}");
        assert!(again.to_string().contains("commit"), "{again}");
    }

    /// `git add` failing is the generator's own failure, and nothing is
    /// pushed. The repo's own index is locked, so `add` fails inside the
    /// test's repo whatever surrounds the temp dir.
    #[test]
    fn an_add_that_fails_is_local() {
        let refusing = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let dir = testsrv::tempdir();
        let repo = local_repo(dir.join("wt"), remote(&refusing));
        std::fs::write(repo.worktree.join(".git").join("index.lock"), b"").expect("lock");
        let e = push_blob(&repo, Path::new("/usr/bin/true"), b"x", 1).expect_err("index locked");
        assert_eq!(e.at, GitFailure::Local, "{e}");
        assert!(e.to_string().contains("\"add\""), "{e}");
        assert_eq!(refusing.accepts(), 0, "a failed add still pushed");
    }

    /// Runs `work` on a 2-worker runtime, the generator box's 2 vCPUs, with
    /// the live counters' writer beside it, as tenant_sim runs them, while a
    /// plain thread off the runtime reads live.json's age every 200 ms.
    /// Returns what `work` gave, the worst age seen, how many reads, and how
    /// long `work` took. The sampler voids at 10 s.
    fn live_age_while<T, F>(dir: &Path, work: impl FnOnce() -> F) -> (T, f64, u32, Duration)
    where
        F: std::future::Future<Output = T>,
    {
        use crate::sim::stats::{spawn_live_writer, write_live, Stats};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{SystemTime, UNIX_EPOCH};

        let live = dir.join("live.json");
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_secs_f64()
        };
        // tenant_sim writes the file once before the writer starts.
        let stats = Arc::new(Stats::new());
        write_live(&live, &stats.live(now() as u64)).expect("first write");
        let done = Arc::new(AtomicBool::new(false));
        let watcher = {
            let (live, done) = (live.clone(), done.clone());
            thread::spawn(move || {
                let (mut worst, mut reads) = (0.0f64, 0u32);
                while !done.load(Ordering::SeqCst) {
                    let t = std::fs::read(&live)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .and_then(|v| v["t_unix"].as_u64());
                    if let Some(t) = t {
                        worst = worst.max(now() - t as f64);
                        reads += 1;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
                (worst, reads)
            })
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let started = Instant::now();
        let out = rt.block_on(async {
            let writer = spawn_live_writer(stats.clone(), live.clone(), Duration::from_secs(2));
            let out = work().await;
            writer.abort();
            out
        });
        let took = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let (worst, reads) = watcher.join().expect("watcher");
        (out, worst, reads, took)
    }

    /// Two pushes to a remote that answers only after 12 s, at once: the
    /// live counters' writer keeps running, so live.json is never more than
    /// a few seconds old. Run on the workers, the pushes would stall it for
    /// the whole 12 s.
    #[test]
    fn slow_pushes_do_not_stall_the_live_writer() {
        let slow = Server::start_after(
            "127.0.0.1:0",
            testsrv::status(500, ""),
            Duration::from_secs(12),
        );
        let dir = testsrv::tempdir();
        let repos: Vec<GitRepo> = (0..2)
            .map(|i| local_repo(dir.join(format!("wt{i}")), remote(&slow)))
            .collect();
        let (results, worst, reads, took) = live_age_while(&dir, || async {
            let pushes: Vec<_> = repos
                .into_iter()
                .enumerate()
                .map(|(i, repo)| {
                    tokio::spawn(push_blob_async(
                        repo,
                        PathBuf::from("/usr/bin/true"),
                        vec![i as u8; 64],
                        1,
                    ))
                })
                .collect();
            let mut out = Vec::new();
            for p in pushes {
                out.push(p.await.expect("push task"));
            }
            out
        });
        assert!(
            took >= Duration::from_secs(12),
            "the pushes didn't wait for the slow remote: {took:?}"
        );
        for r in results {
            let e = r.map(|_| ()).expect_err("a push to a 500");
            assert_eq!(e.at, GitFailure::Push, "{e}");
        }
        assert!(reads >= 20, "live.json was read only {reads} times");
        assert!(
            worst < 5.0,
            "live.json was {worst:.1} s old while two slow pushes ran; the sampler voids at 10 s"
        );
    }

    /// The setup clones, the same way: two clones from a remote that
    /// answers only after 12 s, at once, run on the blocking pool, so the
    /// live counters stay fresh; each fails with its own error.
    #[test]
    fn slow_clones_do_not_stall_the_live_writer() {
        let slow = Server::start_after(
            "127.0.0.1:0",
            testsrv::status(500, ""),
            Duration::from_secs(12),
        );
        let dir = testsrv::tempdir();
        let base = guard().check_url(&slow.http(), &["http"]).expect("allowed");
        let (results, worst, reads, took) = live_age_while(&dir, || async {
            let clones: Vec<_> = (0..2)
                .map(|i| {
                    tokio::spawn(clone_repo_async(
                        base.clone(),
                        OWNER.into(),
                        format!("r{i}"),
                        dir.join(format!("clone{i}")),
                        PathBuf::from("/usr/bin/true"),
                        NSEC.into(),
                        None,
                    ))
                })
                .collect();
            let mut out = Vec::new();
            for c in clones {
                out.push(c.await.expect("clone task"));
            }
            out
        });
        assert!(
            took >= Duration::from_secs(12),
            "the clones didn't wait for the slow remote: {took:?}"
        );
        for r in results {
            let e = r.map(|_| ()).expect_err("a clone from a 500");
            assert!(format!("{e:#}").contains("clone"), "{e:#}");
        }
        assert!(reads >= 20, "live.json was read only {reads} times");
        assert!(
            worst < 5.0,
            "live.json was {worst:.1} s old while two slow clones ran; the sampler voids at 10 s"
        );
        assert!(slow.accepts() >= 2, "the clones never reached the remote");
    }

    #[test]
    fn wait_child_deadline_kills_silent_child() {
        let child = Command::new("sleep").arg("2").spawn().expect("spawn sleep");
        let start = Instant::now();
        let err = wait_child_deadline(child, Duration::from_millis(100)).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(800),
            "timeout took {elapsed:?}, expected << 2s"
        );
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn wait_child_deadline_allows_fast_child() {
        let child = Command::new("true").spawn().expect("spawn true");
        let out = wait_child_deadline(child, Duration::from_secs(2)).expect("true");
        assert!(out.status.success());
    }
}
