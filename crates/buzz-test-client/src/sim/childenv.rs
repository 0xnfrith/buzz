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

/// Rows for the children the tests themselves start: they get
/// `testsrv::test_command`'s fixed set, and nothing else.
#[cfg(test)]
mod tests {
    use super::stub;
    use crate::sim::guard::testsrv;
    use std::path::{Path, PathBuf};

    const TEST_COMMAND_CHILD: &str = "sim::childenv::tests::test_command_gets_exactly_its_set";

    /// A planted-variable row for `test_command`. The parent (a fresh copy
    /// of this test binary) holds `G613_PLANTED`, its own credentials, a
    /// proxy and git's injected config, `HOME` and `TMPDIR` of its own, and
    /// a stub folder first on `PATH`; all dummies made now. The command it
    /// starts gets `PATH`, `HOME`, `TMPDIR` and `LC_ALL=C` and nothing
    /// else, and the values are the right ones (`match`, never printed;
    /// `PATH` is right because the stub was found through it). Then each
    /// of the three is unset in the parent in turn, and the command gets
    /// the rest.
    #[test]
    fn test_command_gets_exactly_its_set() {
        if testsrv::is_child(TEST_COMMAND_CHILD) {
            let dir = PathBuf::from(std::env::var_os("G613_ROW_DIR").expect("row dir"));
            let probe = dir.join("bin").join("probe");
            for unset in [None, Some("TMPDIR"), Some("HOME"), Some("PATH")] {
                if let Some(name) = unset {
                    std::env::remove_var(name);
                }
                let status = testsrv::test_command(&probe).status().expect("probe");
                assert!(status.success(), "probe failed with {unset:?} unset");
            }
            println!("CHILD_OK {TEST_COMMAND_CHILD}");
            return;
        }
        let dir = testsrv::tempdir();
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let out = dir.join("names");
        let (home, tmp) = (stub::dummy(), stub::dummy());
        stub::write(
            &bin,
            "probe",
            &out,
            &[("HOME", &home), ("TMPDIR", &tmp), ("LC_ALL", "C")],
            None,
        );
        let mut env = stub::planted();
        env.push(("G613_ROW_DIR", dir.display().to_string()));
        env.push(("HOME", home));
        env.push(("TMPDIR", tmp));
        let path = std::env::var("PATH").unwrap_or_default();
        env.push(("PATH", format!("{}:{path}", bin.display())));
        testsrv::run_child(TEST_COMMAND_CHILD, &env);
        assert_eq!(
            stub::lines(&out),
            vec![
                stub::set(&["HOME=match", "LC_ALL=match", "PATH", "TMPDIR=match"]),
                stub::set(&["HOME=match", "LC_ALL=match", "PATH"]),
                stub::set(&["LC_ALL=match", "PATH"]),
                stub::set(&["LC_ALL=match"]),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The scan's text patterns, built from pieces so that this file never
    /// holds one itself.
    fn spawn() -> String {
        ["Command", "::new("].concat()
    }

    /// The end of the `{ }` body that starts at or after `at`.
    fn body_end(src: &str, at: usize) -> usize {
        let open = at + src[at..].find('{').expect("a body");
        let mut depth = 0usize;
        for (i, c) in src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return open + i + 1;
                    }
                }
                _ => {}
            }
        }
        src.len()
    }

    /// (how many calls to `test_command` the test code of `src` makes, one
    /// message per spawn in it that could hand its child the parent's
    /// environment). Test code is what follows the file's first `cfg(test)`
    /// or `#[test]`. A spawn is fine inside `test_command` itself, or when
    /// `env_clear` is in the same statement (up to the next `;`). A message
    /// is `file:line` and the call's name, never a value.
    fn test_spawn_problems(name: &str, src: &str) -> (usize, Vec<String>) {
        let starts = [["cfg(", "test)"].concat(), ["#[", "test]"].concat()];
        let Some(from) = starts.iter().filter_map(|s| src.find(s.as_str())).min() else {
            return (0, Vec::new());
        };
        let spawn = spawn();
        let is_comment = |at: usize| {
            let line = src[..at].rfind('\n').map_or(0, |i| i + 1);
            src[line..at].trim_start().starts_with("//")
        };
        let helper = src
            .find("fn test_command(")
            .map(|at| (at, body_end(src, at)));
        let through = src[from..]
            .match_indices("test_command(")
            .filter(|(i, _)| !is_comment(from + i) && !src[..from + i].ends_with("fn "))
            .count();
        let (mut bad, mut at) = (Vec::new(), from);
        while let Some(pos) = src[at..].find(spawn.as_str()) {
            let here = at + pos;
            at = here + spawn.len();
            if is_comment(here) || helper.is_some_and(|(s, e)| (s..e).contains(&here)) {
                continue;
            }
            let statement = src[here..].split(';').next().unwrap_or_default();
            if !statement.contains("env_clear") {
                bad.push(format!(
                    "{name}:{}: {} is neither built by test_command nor followed by env_clear",
                    src[..here].matches('\n').count() + 1,
                    &spawn[..spawn.len() - 1]
                ));
            }
        }
        (through, bad)
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read the source folder") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// No drift, for the tests' own children: in every source file of this
    /// crate's `src/`, every spawn after the file's first `cfg(test)` goes
    /// through `testsrv::test_command` or is followed in its statement by
    /// `env_clear`. A heuristic over the text, not a proof:
    /// - it reads `src/` only: `tests/e2e_git.rs` (a test crate of its own,
    ///   which needs a relay) is not read;
    /// - code before a file's first `cfg(test)` or `#[test]` is not read.
    ///   That is production code, held by the planted-variable rows of git,
    ///   kill and mkfifo; the one test helper that spawns outside a
    ///   `cfg(test)` module, if one were added, would escape;
    /// - it sees `Command::new` only: not `Command::from`, a `use ... as`
    ///   rename, `libc` or a spawn through another crate;
    /// - an `env_clear` in a later statement (`let mut c = ...; c.env_clear();`)
    ///   is not seen, so that form fails: use `test_command`;
    /// - a comment is a line that starts with `//`; a spawn after code on a
    ///   line that does is read.
    ///
    /// Today `testsrv` is the one helper module, inside `cfg(test)`.
    #[test]
    fn every_test_spawn_has_a_fixed_environment() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        files.sort();
        let (mut through, mut bad) = (0, Vec::new());
        for path in &files {
            let text = std::fs::read_to_string(path).expect("read a source file");
            let name = path.strip_prefix(&src).unwrap().display().to_string();
            let (n, problems) = test_spawn_problems(&name, &text);
            through += n;
            bad.extend(problems);
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
        // run_child and its nofile form, and four in git.rs.
        assert!(
            through >= 6,
            "the scan found only {through} calls to test_command: too few to mean anything"
        );
    }

    /// The scan, on snippets: the right spawns pass, each way of inheriting
    /// is named, and the limits it documents are real.
    #[test]
    fn the_scan_can_fail() {
        let test_code = |body: &str| {
            format!("{}\nmod t {{\n{body}\n}}\n", ["#[cfg(", "test)]"].concat())
                .replace("NEW(", &spawn())
        };
        for (body, through, bad) in [
            ("fn f() { let c = test_command(\"x\"); }", 1, 0),
            ("fn f() { let c = NEW(\"x\").env_clear().spawn(); }", 0, 0),
            (
                "fn f() {\n    let c = NEW(\"x\")\n        .env_clear()\n        .spawn();\n}",
                0,
                0,
            ),
            ("pub fn test_command(p: &str) -> Command { NEW(p) }", 0, 0),
            ("// NEW(\"x\") in a comment", 0, 0),
            ("fn f() { let c = NEW(\"x\").spawn(); }", 0, 1),
            ("fn f() { std::process::NEW(\"x\").status(); }", 0, 1),
            ("fn f() { let c = NEW(\"x\"); c.env_clear(); }", 0, 1),
            ("fn f() { let a = NEW(\"x\"); let b = NEW(\"y\"); }", 0, 2),
        ] {
            let (n, problems) = test_spawn_problems("s.rs", &test_code(body));
            assert_eq!((n, problems.len()), (through, bad), "{body}: {problems:?}");
            for p in problems {
                assert!(p.starts_with("s.rs:"), "{p}");
            }
        }
        // Not read: code before the first cfg(test), and a file with none.
        let before = test_code("").replace("#[cfg(", "fn p() { NEW(\"kill\"); }\n#[cfg(");
        assert_eq!(test_spawn_problems("s.rs", &before), (0, Vec::new()));
        let none = "fn p() { NEW(\"kill\"); }".replace("NEW(", &spawn());
        assert_eq!(test_spawn_problems("s.rs", &none), (0, Vec::new()));
    }
}
