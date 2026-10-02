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

/// A failure at step `at`, unless the generator ran out of its own files,
/// ports or buffers on the way ([`super::guard::is_local_exhaustion`] on
/// any of its causes): that is its own fault at any step, the push's own
/// spawn included (`LocalExhausted`), never the relay's.
fn failed(at: GitFailure) -> impl Fn(anyhow::Error) -> PushError {
    move |err| {
        let at = if err.chain().any(super::guard::is_local_exhaustion) {
            GitFailure::LocalExhausted
        } else {
            at
        };
        PushError { at, err }
    }
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
            let _ = super::childenv::path_only(&mut Command::new("kill"))
                .args(["-9", &pid.to_string()])
                .status();
            let _ = rx.recv_timeout(Duration::from_secs(2));
            Err(anyhow!("command pid {pid} timed out after {timeout:?}"))
        }
    }
}

/// Settings that keep git on the one checked address: no redirects, no
/// proxy, and only the http(s) transports.
pub const GIT_GUARD_CONFIG: [&str; 5] = [
    "http.followRedirects=false",
    "http.proxy=",
    "protocol.allow=never",
    "protocol.http.allow=always",
    "protocol.https.allow=always",
];

/// git's `HOME`: a path with nothing at it. No file under a home folder
/// (`.gitconfig`, `.netrc`, git's `.config`) can reach git or its curl, and
/// `GIT_CONFIG_GLOBAL` is `/dev/null` besides.
pub const GIT_HOME: &str = "/nonexistent";

/// `git` that authenticates only as this simulated identity, with a fixed
/// environment: `PATH` (the generator's, given as `path`), `HOME`
/// ([`GIT_HOME`]), `LC_ALL=C`, git's own config switched off
/// (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), no prompt
/// (`GIT_TERMINAL_PROMPT=0`), and this identity's key and, for an agent,
/// its own NIP-OA tag. Nothing else of the generator's comes through, so no
/// credential, proxy or injected config of the caller's reaches git or the
/// credential helper it runs. Git follows no redirect and uses no proxy
/// (see [`GIT_GUARD_CONFIG`]).
fn git_command(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
    path: Option<OsString>,
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
    cmd.args(args).current_dir(cwd).env_clear();
    if let Some(path) = path {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", GIT_HOME)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("NOSTR_PRIVATE_KEY", nsec);
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
    timeout: Duration,
) -> Result<Output> {
    let path = std::env::var_os("PATH");
    let child = git_command(args, cwd, helper, nsec, auth_tag, path)
        .spawn()
        .with_context(|| format!("spawn git {args:?}"))?;
    wait_child_deadline(child, timeout).with_context(|| format!("git {args:?}"))
}

fn git_ok(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
) -> Result<String> {
    git_ok_within(args, cwd, helper, nsec, auth_tag, GIT_TIMEOUT)
}

/// [`git_ok`] with its own deadline: only tests pass one other than
/// [`GIT_TIMEOUT`].
fn git_ok_within(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
    timeout: Duration,
) -> Result<String> {
    let out = git_cmd(args, cwd, helper, nsec, auth_tag, timeout)?;
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
/// is the relay's (`Push`). At any step, the generator out of its own
/// files, ports or buffers is its own (`LocalExhausted`). Each blob is a
/// new file, so `commit` always has a change to commit.
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
    let ms = push_main(repo, helper, GIT_TIMEOUT)?;
    Ok((bytes.len() as u64, ms))
}

/// The push alone, to the checked URL, within `timeout`: the relay's part
/// of [`push_blob`] (`Push`). Returns how long it took, in ms. Only tests
/// pass a timeout other than [`GIT_TIMEOUT`].
fn push_main(
    repo: &GitRepo,
    helper: &Path,
    timeout: Duration,
) -> std::result::Result<f64, PushError> {
    let start = Instant::now();
    git_ok_within(
        &["push", "--quiet", repo.url.as_str(), "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        repo.owner_auth_tag.as_deref(),
        timeout,
    )
    .map_err(failed(GitFailure::Push))?;
    Ok(start.elapsed().as_secs_f64() * 1e3)
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

    /// The values git's fixed set holds: the given `PATH`, the empty
    /// `HOME`, git's config off, no prompt, and the identity's own key and
    /// tag.
    #[test]
    fn git_sets_its_fixed_values() {
        let agent = git_command(
            &["push"],
            Path::new("."),
            Path::new("/bin/true"),
            "nsec-agent",
            Some("[\"auth\",\"owner\",\"\",\"sig\"]"),
            Some(OsString::from("/usr/bin:/bin")),
        );
        for (name, want) in [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", GIT_HOME),
            ("LC_ALL", "C"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("NOSTR_PRIVATE_KEY", "nsec-agent"),
            ("BUZZ_AUTH_TAG", "[\"auth\",\"owner\",\"\",\"sig\"]"),
        ] {
            assert_eq!(env_of(&agent, name), Some(Some(want.into())), "{name}");
        }
        let human = git_command(
            &["push"],
            Path::new("."),
            Path::new("/bin/true"),
            "nsec-human",
            None,
            None,
        );
        // A human carries no NIP-OA tag; without a PATH given, none is set.
        assert_eq!(env_of(&human, "BUZZ_AUTH_TAG"), None);
        assert_eq!(env_of(&human, "PATH"), None);
    }

    const GIT_ENV_CHILD: &str = "sim::git::tests::git_gets_exactly_its_fixed_set";

    /// A planted-variable row. The parent (a fresh copy of this test
    /// binary) holds `G613_PLANTED`, its own credentials, a proxy and git's
    /// injected config, all dummies made now. The real path (`git_ok`)
    /// runs to a stub `git` first on `PATH`, which records names only. An
    /// agent's git gets exactly the fixed set, with its own key and tag
    /// (`match`, never the parent's); a human's the same without a tag.
    #[test]
    fn git_gets_exactly_its_fixed_set() {
        if testsrv::is_child(GIT_ENV_CHILD) {
            let dir = PathBuf::from(std::env::var_os("G613_ROW_DIR").expect("row dir"));
            let nsec = std::fs::read_to_string(dir.join("nsec")).expect("nsec");
            let tag = std::fs::read_to_string(dir.join("tag")).expect("tag");
            let helper = Path::new("/usr/bin/true");
            git_ok(&["push"], &dir, helper, &nsec, Some(&tag)).expect("agent's git");
            git_ok(&["push"], &dir, helper, &nsec, None).expect("human's git");
            println!("CHILD_OK {GIT_ENV_CHILD}");
            return;
        }
        let dir = testsrv::tempdir();
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let (nsec, tag) = (stub::dummy(), stub::dummy());
        std::fs::write(dir.join("nsec"), &nsec).expect("nsec");
        std::fs::write(dir.join("tag"), &tag).expect("tag");
        let out = dir.join("names");
        stub::write(
            &bin,
            "git",
            &out,
            &[("NOSTR_PRIVATE_KEY", &nsec), ("BUZZ_AUTH_TAG", &tag)],
            None,
        );
        let mut env = stub::planted();
        env.push(("G613_ROW_DIR", dir.display().to_string()));
        let path = std::env::var("PATH").unwrap_or_default();
        env.push(("PATH", format!("{}:{path}", bin.display())));
        testsrv::run_child(GIT_ENV_CHILD, &env);
        let fixed = [
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "HOME",
            "LC_ALL",
            "NOSTR_PRIVATE_KEY=match",
            "PATH",
        ];
        let mut agent = stub::set(&fixed);
        agent.insert("BUZZ_AUTH_TAG=match".into());
        assert_eq!(stub::lines(&out), vec![agent, stub::set(&fixed)]);
        std::fs::remove_dir_all(&dir).ok();
    }

    const KILL_ENV_CHILD: &str = "sim::git::tests::kill_gets_only_path";

    /// A planted-variable row for the `kill` a git past its deadline gets:
    /// the stub records names, then runs the real `/bin/kill`.
    #[test]
    fn kill_gets_only_path() {
        if testsrv::is_child(KILL_ENV_CHILD) {
            let child = testsrv::test_command("sleep")
                .arg("5")
                .spawn()
                .expect("spawn sleep");
            let err = wait_child_deadline(child, Duration::from_millis(200))
                .expect_err("past its deadline");
            assert!(err.to_string().contains("timed out"), "{err:#}");
            println!("CHILD_OK {KILL_ENV_CHILD}");
            return;
        }
        let dir = testsrv::tempdir();
        let out = dir.join("names");
        stub::write(&dir, "kill", &out, &[], Some("/bin/kill"));
        let mut env = stub::planted();
        let path = std::env::var("PATH").unwrap_or_default();
        env.push(("PATH", format!("{}:{path}", dir.display())));
        testsrv::run_child(KILL_ENV_CHILD, &env);
        assert_eq!(stub::lines(&out), vec![stub::set(&["PATH"])]);
        std::fs::remove_dir_all(&dir).ok();
    }

    use crate::sim::childenv::stub;
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
    fn git_carries_the_guard_settings() {
        let cmd = git_command(
            &["push"],
            Path::new("."),
            Path::new("/usr/bin/true"),
            NSEC,
            None,
            None,
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

    /// A repo with one commit on `main`, ready to push to `url`: a push
    /// that fails then fails at the server, never on a missing branch.
    fn committed_repo(dir: &Path, url: Target) -> GitRepo {
        let repo = local_repo(dir.join("wt"), url);
        std::fs::write(repo.worktree.join("blob"), b"x").expect("write");
        for args in [
            &["add", "."][..],
            &["commit", "--quiet", "-m", "one"],
            &["branch", "-M", "main"],
        ] {
            git_ok(args, &repo.worktree, Path::new("/usr/bin/true"), NSEC, None).expect("commit");
        }
        repo
    }

    /// A server that takes each connection, waits for the request's first
    /// byte, then aborts it: linger 0, so the close is a TCP reset. Returns
    /// its URL and how many it reset.
    fn resetting_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::Read;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let resets = std::sync::Arc::new(AtomicUsize::new(0));
        let count = resets.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = (&stream).read(&mut [0u8; 1]);
                stream.set_nonblocking(true).expect("nonblocking");
                rt.block_on(async {
                    let s = tokio::net::TcpStream::from_std(stream).expect("from_std");
                    s.set_zero_linger().expect("linger 0");
                    count.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        (format!("http://{addr}"), resets)
    }

    /// The relay failing the push stays the relay's (`Push`), a break: a
    /// refusal, a reset, and no answer within the deadline. Each reached
    /// the server, so none is the generator's own.
    #[test]
    fn a_relay_failure_at_the_push_stays_the_relays() {
        let helper = Path::new("/usr/bin/true");
        let dir = testsrv::tempdir();
        let refusing = Server::start("127.0.0.1:0", testsrv::status(404, ""));
        let repo = committed_repo(&dir.join("refused"), remote(&refusing));
        let e = push_main(&repo, helper, GIT_TIMEOUT).expect_err("a push to a 404");
        assert_eq!(e.at, GitFailure::Push, "refused: {e}");
        assert!(
            refusing.accepts() >= 1,
            "the refused push never reached the server"
        );

        let (http, resets) = resetting_server();
        let url = guard()
            .check_url(&http, &["http"])
            .and_then(|t| t.join(&format!("/git/{OWNER}/r")))
            .expect("allowed");
        let repo = committed_repo(&dir.join("reset"), url);
        let e = push_main(&repo, helper, GIT_TIMEOUT).expect_err("a reset push");
        assert_eq!(e.at, GitFailure::Push, "reset: {e}");
        assert!(e.to_string().contains("reset by peer"), "not a reset: {e}");
        assert!(resets.load(std::sync::atomic::Ordering::SeqCst) >= 1);

        let silent = Server::start_after(
            "127.0.0.1:0",
            testsrv::status(200, ""),
            Duration::from_secs(10),
        );
        let repo = committed_repo(&dir.join("timeout"), remote(&silent));
        let e = push_main(&repo, helper, Duration::from_secs(1)).expect_err("no answer in 1 s");
        assert_eq!(e.at, GitFailure::Push, "timed out: {e}");
        assert!(e.to_string().contains("timed out after 1s"), "{e}");
        assert!(
            silent.accepts() >= 1,
            "the timed-out push never reached the server"
        );
    }

    const OUT_OF_FILES_CHILD: &str = "sim::git::tests::a_push_out_of_files_is_the_generators_own";

    /// The generator out of open files: the push's own spawn fails on its
    /// side and never reaches the relay, and so does a whole `push_blob`
    /// (at its first step, writing the blob). Each is the generator's own
    /// (`LocalExhausted`), never the relay's (`Push`). Run in a child test
    /// process whose file limit is low, so nothing else here runs out.
    #[test]
    fn a_push_out_of_files_is_the_generators_own() {
        if testsrv::is_child(OUT_OF_FILES_CHILD) {
            let server = Server::start("127.0.0.1:0", testsrv::status(200, ""));
            let dir = testsrv::tempdir();
            let repo = committed_repo(&dir, remote(&server));
            let helper = Path::new("/usr/bin/true");
            // Take every file this process may still open.
            let mut held = Vec::new();
            while let Ok(f) = std::fs::File::open("/dev/null") {
                held.push(f);
            }
            let push = push_main(&repo, helper, GIT_TIMEOUT).expect_err("no push");
            let whole = push_blob(&repo, helper, b"y", 2).expect_err("no push_blob");
            drop(held);
            assert_eq!(push.at, GitFailure::LocalExhausted, "{push}");
            assert!(push.to_string().contains("spawn git"), "{push}");
            assert_eq!(whole.at, GitFailure::LocalExhausted, "{whole}");
            assert_eq!(server.accepts(), 0, "a connection reached the server");
            println!("CHILD_OK {OUT_OF_FILES_CHILD}");
            return;
        }
        testsrv::run_child_with_nofile(OUT_OF_FILES_CHILD, 128);
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
        let child = testsrv::test_command("sleep")
            .arg("2")
            .spawn()
            .expect("spawn sleep");
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
        let child = testsrv::test_command("true").spawn().expect("spawn true");
        let out = wait_child_deadline(child, Duration::from_secs(2)).expect("true");
        assert!(out.status.success());
    }
}
