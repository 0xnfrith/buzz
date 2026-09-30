//! Real git clone/push through the relay using git-credential-nostr.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

const GIT_TIMEOUT: Duration = Duration::from_secs(90);

pub struct GitRepo {
    pub name: String,
    pub owner_hex: String,
    pub owner_nsec: String,
    /// The owner's NIP-OA credential JSON when the owner is an agent.
    pub owner_auth_tag: Option<String>,
    pub worktree: PathBuf,
    pub url: String,
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
/// are set.
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
    ])
    .args(args)
    .current_dir(cwd)
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env_remove("GIT_CONFIG_COUNT");
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

pub fn clone_repo(
    http_url: &str,
    owner_hex: &str,
    name: &str,
    dest: &Path,
    helper: &Path,
    nsec: &str,
    auth_tag: Option<&str>,
) -> Result<GitRepo> {
    let url = format!("{http_url}/git/{owner_hex}/{name}");
    if dest.exists() {
        std::fs::remove_dir_all(dest).ok();
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    git_ok(
        &["clone", "--quiet", &url, &dest.to_string_lossy()],
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

pub fn push_blob(repo: &GitRepo, helper: &Path, bytes: &[u8], seq: u64) -> Result<(u64, f64)> {
    let file = repo.worktree.join(format!("blob-{seq}.bin"));
    std::fs::write(&file, bytes)?;
    let tag = repo.owner_auth_tag.as_deref();
    git_ok(&["add", "."], &repo.worktree, helper, &repo.owner_nsec, tag)?;
    let _ = git_ok(
        &["commit", "--quiet", "-m", &format!("sim {seq}")],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    );
    let _ = git_ok(
        &["branch", "-M", "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    );
    let start = Instant::now();
    git_ok(
        &["push", "--quiet", "origin", "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
        tag,
    )?;
    Ok((bytes.len() as u64, start.elapsed().as_secs_f64() * 1e3))
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
