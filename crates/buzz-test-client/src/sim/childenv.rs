//! Every child the generator starts gets a fixed environment: the names it
//! needs, set one by one, and nothing else of the generator's own. A
//! deny-list (every `BUZZ_*` and `NOSTR_*`) let through anything it didn't
//! name, so a credential under any other name reached git, its credential
//! helper, and anything they run.

use std::process::Command;

/// `cmd` with only this process's `PATH`: for `kill` and `mkfifo`, which
/// need nothing else.
pub fn path_only(cmd: &mut Command) -> &mut Command {
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

/// The planted-variable rows' stub: a perl script that records the names of
/// the variables it was started with, one line per call, and never a value.
/// For the names in `checks` it records `NAME=match` when the value is the
/// one given, `NAME=other` when it isn't. Perl adds no variable of its own
/// (a shell adds `PWD` and `SHLVL`; Python on macOS adds `LC_CTYPE`), so the
/// line is exactly what the child was handed.
#[cfg(test)]
pub(crate) mod stub {
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    pub const PERL: &str = "/usr/bin/perl";

    /// The variable every row plants in the parent. A fixed set never
    /// names it, so it must never reach a child.
    pub const PLANTED: &str = "G613_PLANTED";

    /// A dummy value made at run time: hex only, so it quotes safely.
    pub fn dummy() -> String {
        format!(
            "{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        )
    }

    /// The parent's planted variables, each with a fresh dummy value: the
    /// planted name, the generator's own credentials, a proxy, and git's
    /// injected config.
    pub fn planted() -> Vec<(&'static str, String)> {
        [
            PLANTED,
            "BUZZ_PRIVATE_KEY",
            "BUZZ_AUTH_TAG",
            "NOSTR_PRIVATE_KEY",
            "HTTPS_PROXY",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        ]
        .into_iter()
        .map(|k| (k, dummy()))
        .collect()
    }

    /// Writes the stub as `dir/name`. Each call appends one line to `out`;
    /// `exec` (a real program) then runs with the stub's arguments, so the
    /// stub can stand in for a child whose work the caller needs done.
    pub fn write(
        dir: &Path,
        name: &str,
        out: &Path,
        checks: &[(&str, &str)],
        exec: Option<&str>,
    ) -> PathBuf {
        assert!(
            Path::new(PERL).exists(),
            "{PERL} is missing: the planted-variable rows need it and never skip"
        );
        for (k, v) in checks {
            assert!(
                k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && v.chars().all(|c| c.is_ascii_alphanumeric()),
                "stub checks are plain names and hex values"
            );
        }
        let want: Vec<String> = checks
            .iter()
            .map(|(k, v)| format!("'{k}' => '{v}'"))
            .collect();
        let tail = match exec {
            Some(prog) => format!("exec '{prog}', @ARGV; die \"exec {prog}: $!\";\n"),
            None => "exit 0;\n".to_string(),
        };
        let script = format!(
            "#!{PERL}\n\
             my %want = ({});\n\
             open(my $f, '>>', '{}') or die \"stub: $!\";\n\
             print $f join(' ', map {{ exists $want{{$_}} ? \"$_=\" . ($ENV{{$_}} eq $want{{$_}} ? 'match' : 'other') : $_ }} sort keys %ENV), \"\\n\";\n\
             close $f;\n\
             {tail}",
            want.join(", "),
            out.display(),
        );
        let path = dir.join(name);
        std::fs::write(&path, script).expect("write stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("chmod stub");
        path
    }

    /// The lines the stub wrote, each as its set of entries.
    pub fn lines(out: &Path) -> Vec<BTreeSet<String>> {
        std::fs::read_to_string(out)
            .unwrap_or_default()
            .lines()
            .map(|l| l.split_whitespace().map(str::to_string).collect())
            .collect()
    }

    /// `names` as the set a stub line is compared with.
    pub fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }
}
