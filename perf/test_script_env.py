"""Each shipped script starts its children from a fixed environment.

clock-proof.sh, build-linux.sh and testdata/remote_sampler/capture.sh run
themselves again once under `env -i` with PATH, HOME, TMPDIR, LC_ALL=C, a
marker that says it has, and the optional names each keeps when the caller
set them (the Docker selectors, the Cargo ones, PYTHON and XDG_CACHE_HOME for
the proof). They unset the marker first, so no child sees it.

Planted-variable rows: the parent holds G613_PLANTED, the caller's
credentials, a proxy, a Cargo target folder and an agent socket, all dummies
made at run time, with a stub folder first on PATH. The real script runs, in
place, to perl stubs that record the names of the variables they were
started with (a `match` or `other` beside a name whose value is checked,
never a value) and fail, so the script stops early, with an exit code each
row asserts. The names must equal the script's set exactly, plus exactly
what bash adds to a child (BASH_ADDS, which a row of its own pins). Each
optional name runs set and unset; build-linux.sh and capture.sh, which take
no lock, also run with XDG_CACHE_HOME planted and must not carry it. Perl adds no variable of its own; these
rows fail, never skip, without /usr/bin/perl.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PERF = Path(__file__).resolve().parent
sys.path.insert(0, str(PERF))

from planted_env import PERL, PLANTED_ENV, test_env, write_stub  # noqa: E402

CLOCK = PERF / "clock-proof.sh"
BUILD = PERF / "build-linux.sh"
CAPTURE = PERF / "testdata" / "remote_sampler" / "capture.sh"

DOCKER = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
CARGO = ("CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN")
# What bash itself adds to a child it starts, from an empty environment:
# BASH_ADDS, plus OLDPWD once the script has changed folder (CD_ADDS); and `_`
# is missing from the last command a script execs. test_what_bash_adds pins
# these.
BASH_ADDS = {"PWD", "SHLVL", "_"}
CD_ADDS = {"OLDPWD"}
EXEC_DROPS = {"_"}
# What else the parent holds: none of it is in any set.
PLANTED_NAMES = [*PLANTED_ENV, "HTTPS_PROXY", "CARGO_TARGET_DIR", "SSH_AUTH_SOCK"]


class Rows(unittest.TestCase):
    """A temporary folder with a stub folder, a home and a tmp folder."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="script-env-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin, self.home, self.tmp = self.dir / "bin", self.dir / "home", self.dir / "tmp"
        for d in (self.bin, self.home, self.tmp):
            d.mkdir()
        self.path = f"{self.bin}:/usr/bin:/bin"
        # A dummy for each optional name, made now. PYTHON is a stub's path,
        # XDG_CACHE_HOME an absolute folder.
        self.chosen_values = {n: secrets.token_hex(8) for n in (*DOCKER, *CARGO)}
        self.chosen_values["PYTHON"] = str(self.bin / "python-stub")
        self.chosen_values["XDG_CACHE_HOME"] = str(self.dir / "cache")

    def named(self, chosen: tuple[str, ...]) -> dict[str, str]:
        """The parent's named values: a stub folder first on PATH, a home, a
        tmp folder, a LC_ALL that isn't C, the planted names, and the
        optional names in `chosen`."""
        planted = {n: secrets.token_hex(16) for n in PLANTED_NAMES}
        return {"PATH": self.path, "HOME": str(self.home), "TMPDIR": str(self.tmp), "LC_ALL": "en_US.UTF-8",
                **planted, **{n: self.chosen_values[n] for n in chosen}}

    def fixed(self, chosen: tuple[str, ...]) -> dict[str, str]:
        """What the script's set holds, with each value the parent's, or C."""
        return {"PATH": self.path, "HOME": str(self.home), "TMPDIR": str(self.tmp), "LC_ALL": "C",
                **{n: self.chosen_values[n] for n in chosen}}

    def stub(self, name: str, checks: dict[str, str], **kw) -> Path:
        return write_stub(self.bin / name, self.dir / f"{name}.names", checks, **kw)

    def lines(self, name: str) -> list[set[str]]:
        out = self.dir / f"{name}.names"
        return [set(line.split()) for line in out.read_text().splitlines()] if out.exists() else []

    def line(self, fixed: dict[str, str], *, plain: set[str], other: set[str] = frozenset()) -> set[str]:
        """A stub's line: NAME=match for each name in `fixed` (but NAME=other
        for each in `other`, whose value the script sets itself), then the
        `plain` names bash adds."""
        return {f"{k}={'other' if k in other else 'match'}" for k in fixed} | plain

    def run_script(self, script: Path, args: tuple[str, ...], chosen: tuple[str, ...], *,
                   unset_tmp: bool = False, plant: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
        """Run `script`; the parent holds the planted names, the optional
        names in `chosen` (which the script keeps) and those in `plant`
        (which it must not)."""
        env = test_env(**{**self.named(chosen), **{n: self.chosen_values[n] for n in plant}})
        if unset_tmp:
            env.pop("TMPDIR")
        return subprocess.run([str(script), *args], env=env, cwd=self.dir, capture_output=True, text=True,
                              timeout=120)

    @staticmethod
    def variants(optional: tuple[str, ...]):
        """Every optional name unset; each alone set; all set."""
        return [(), *[(n,) for n in optional], optional]


class BashAdds(Rows):
    def test_what_bash_adds(self) -> None:
        """The names the bash a script runs in adds to its children, from an
        empty environment. The other rows add exactly these to a script's
        set; if this Mac's bash (or another machine's) adds others, this row
        names them."""
        self.stub("probe", {})
        path = {"PATH"}  # the one name the row hands bash, so it can find the stub
        cases = {
            "plain": ("probe\nprobe\n", [path | BASH_ADDS] * 2),
            "after a cd": ("cd /\nprobe\n", [path | BASH_ADDS | CD_ADDS]),
            "the last command, exec'd": ("cd /\nexec probe\n", [path | (BASH_ADDS | CD_ADDS) - EXEC_DROPS]),
        }
        for what, (body, want) in cases.items():
            with self.subTest(what=what):
                (self.dir / "probe.names").unlink(missing_ok=True)
                script = self.dir / "s.sh"
                script.write_text(f"#!/bin/bash\nset -euo pipefail\n{body}")
                subprocess.run(["/usr/bin/env", "-i", f"PATH={self.path}", "/bin/bash", str(script)],
                               env=test_env(), check=True, cwd=self.dir, capture_output=True, timeout=60)
                self.assertEqual(self.lines("probe"), want)


class ClockProofRows(Rows):
    def test_cargo_and_python(self) -> None:
        """Both cargo builds and then the interpreter (python3, or PYTHON when
        set) get the script's set (XDG_CACHE_HOME among its optional names);
        the script execs the interpreter, so its exit is the stub's, 7."""
        for chosen in self.variants(("PYTHON", "XDG_CACHE_HOME", *DOCKER, *CARGO)):
            for unset_tmp in (False, True):
                if unset_tmp and chosen:
                    continue
                with self.subTest(chosen=chosen, unset_tmp=unset_tmp):
                    for name in ("cargo", "python3", "python-stub"):
                        (self.dir / f"{name}.names").unlink(missing_ok=True)
                    fixed = self.fixed(chosen)
                    if unset_tmp:
                        del fixed["TMPDIR"]
                    # After its cd, bash adds OLDPWD; the exec'd interpreter gets no `_`.
                    self.stub("cargo", fixed)
                    self.stub("python-stub" if "PYTHON" in chosen else "python3", fixed, code=7)
                    p = self.run_script(CLOCK, ("--out", str(self.dir / "o")), chosen, unset_tmp=unset_tmp)
                    self.assertEqual(p.returncode, 7, p.stderr[-300:])
                    cargo = self.line(fixed, plain=BASH_ADDS | CD_ADDS)
                    python = self.line(fixed, plain=(BASH_ADDS | CD_ADDS) - EXEC_DROPS)
                    self.assertEqual(self.lines("cargo"), [cargo, cargo])
                    self.assertEqual(self.lines("python-stub" if "PYTHON" in chosen else "python3"), [python])

    def test_arguments_survive_the_rerun(self) -> None:
        """The interpreter gets the script's arguments, a space inside one
        included: a stub that exits with how many it got."""
        self.stub("cargo", {})
        python = self.bin / "python3"
        python.write_text(f"#!{PERL}\nexit scalar(@ARGV);\n")
        python.chmod(0o700)
        p = self.run_script(CLOCK, ("--out", "a b", "--rows", "reads"), ())
        # perf/clock_proof.py and the four arguments.
        self.assertEqual(p.returncode, 5, p.stderr[-300:])


class BuildLinuxRows(Rows):
    def test_endpoint_check_stops_the_script(self) -> None:
        """The first child, the endpoint check (python3 tenant_cogs.py
        docker-endpoint), gets the set and the Docker names the caller set.
        Its stub fails, so the script exits 2 without reaching docker."""
        for chosen in self.variants(DOCKER):
            with self.subTest(chosen=chosen):
                (self.dir / "python3.names").unlink(missing_ok=True)
                fixed = self.fixed(chosen)
                self.stub("python3", fixed, code=1)
                self.stub("docker", {})
                p = self.run_script(BUILD, (), chosen, plant=("XDG_CACHE_HOME",))
                self.assertEqual(p.returncode, 2, p.stderr[-300:])
                self.assertEqual(self.lines("python3"), [self.line(fixed, plain=BASH_ADDS)])
                self.assertEqual(self.lines("docker"), [])

    def test_docker_gets_the_endpoint_the_script_names(self) -> None:
        """docker gets the set and the Docker names the caller set, except
        that DOCKER_HOST is the script's own (the checked endpoint; here the
        stub printed none, so it is empty: `other`, whether or not the caller
        set one) and DOCKER_CONTEXT is gone. Its stub fails, so the script
        exits 1 there."""
        for chosen in self.variants(DOCKER):
            with self.subTest(chosen=chosen):
                for name in ("python3", "docker"):
                    (self.dir / f"{name}.names").unlink(missing_ok=True)
                fixed = self.fixed(chosen)
                self.stub("python3", fixed, exec_="/usr/bin/true")
                docker = {**{k: v for k, v in fixed.items() if k != "DOCKER_CONTEXT"},
                          "DOCKER_HOST": self.chosen_values["DOCKER_HOST"]}
                self.stub("docker", docker, code=1)
                p = self.run_script(BUILD, (), chosen, plant=("XDG_CACHE_HOME",))
                self.assertEqual(p.returncode, 1, p.stderr[-300:])
                self.assertEqual(self.lines("python3"), [self.line(fixed, plain=BASH_ADDS)])
                want = self.line(docker, plain=BASH_ADDS, other={"DOCKER_HOST"})
                self.assertEqual(self.lines("docker"), [want])


class CaptureRows(Rows):
    def test_docker(self) -> None:
        """The first docker call and the five removals the exit trap makes
        each get the set and the Docker names the caller set. The first call's
        stub fails, so the script exits 1 before it writes a fixture."""
        for chosen in self.variants(DOCKER):
            with self.subTest(chosen=chosen):
                (self.dir / "docker.names").unlink(missing_ok=True)
                fixed = self.fixed(chosen)
                self.stub("docker", fixed, code=1)
                p = self.run_script(CAPTURE, ("image-one", "image-two"), chosen, plant=("XDG_CACHE_HOME",))
                self.assertEqual(p.returncode, 1, p.stderr[-300:])
                self.assertEqual(self.lines("docker"), [self.line(fixed, plain=BASH_ADDS)] * 6)


if __name__ == "__main__":
    unittest.main()
