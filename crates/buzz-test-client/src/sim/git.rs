//! Real git clone/push through the relay using git-credential-nostr.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};

pub struct GitRepo {
    pub name: String,
    pub owner_hex: String,
    pub owner_nsec: String,
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

fn git_cmd(
    args: &[&str],
    cwd: &Path,
    helper: &Path,
    nsec: &str,
) -> Result<std::process::Output> {
    let helper = abs_helper(helper);
    Command::new("git")
        .args([
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
        .env_remove("GIT_CONFIG_COUNT")
        .env("NOSTR_PRIVATE_KEY", nsec)
        .output()
        .with_context(|| format!("spawn git {args:?}"))
}

fn git_ok(args: &[&str], cwd: &Path, helper: &Path, nsec: &str) -> Result<String> {
    let out = git_cmd(args, cwd, helper, nsec)?;
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
    )?;
    Ok(GitRepo {
        name: name.to_string(),
        owner_hex: owner_hex.to_string(),
        owner_nsec: nsec.to_string(),
        worktree: dest.to_path_buf(),
        url,
    })
}

pub fn push_blob(repo: &GitRepo, helper: &Path, bytes: &[u8], seq: u64) -> Result<(u64, f64)> {
    let file = repo.worktree.join(format!("blob-{seq}.bin"));
    std::fs::write(&file, bytes)?;
    git_ok(&["add", "."], &repo.worktree, helper, &repo.owner_nsec)?;
    let _ = git_ok(
        &["commit", "--quiet", "-m", &format!("sim {seq}")],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
    );
    let _ = git_ok(
        &["branch", "-M", "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
    );
    let start = Instant::now();
    git_ok(
        &["push", "--quiet", "origin", "main"],
        &repo.worktree,
        helper,
        &repo.owner_nsec,
    )?;
    Ok((bytes.len() as u64, start.elapsed().as_secs_f64() * 1e3))
}
