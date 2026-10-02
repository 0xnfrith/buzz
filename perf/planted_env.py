"""Test support for the environment checks and the planted-variable rows.
Tests only: nothing here ships to a generator box.

- PLANTED_ENV: the parent's planted variables, dummies made at import, so a
  check's failure message can be scanned for them.
- parent_env: a fixed fake parent environment to patch os.environ to.
- test_env: the fixed environment every test's own child gets.
- assert_names: compares variable names, never values, so a failure prints
  names only.
- write_stub: the perl stub that records the names a child was started with.
"""

from __future__ import annotations

import os
import secrets
import unittest
from pathlib import Path
from typing import Iterable, Mapping

PERL = "/usr/bin/perl"
PLANTED = "G613_PLANTED"
PLANTED_ENV = {k: secrets.token_hex(16) for k in (PLANTED, "BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG", "NOSTR_PRIVATE_KEY")}


def parent_env(**named: str) -> dict[str, str]:
    """A fixed fake parent: PATH, HOME, the planted dummies, then `named`."""
    return {"PATH": "/usr/bin:/bin", "HOME": "/home/fake", **PLANTED_ENV, **named}


def test_env(**named: str) -> dict[str, str]:
    """The environment of a child a test starts: PATH, HOME and TMPDIR from
    this process (each only when set), LC_ALL=C, then `named`. Nothing else
    of this process's comes through, so no credential of whoever runs the
    tests reaches a child, whatever its name."""
    out = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if k in os.environ}
    out["LC_ALL"] = "C"
    out.update(named)
    return out


test_env.__test__ = False  # a helper, not a test, whatever runner imports it


def assert_names(case: unittest.TestCase, env: Mapping[str, str] | Iterable[str], want: Iterable[str]) -> None:
    """`env`'s names are exactly `want`. Names only, never a value, so a
    failure can't print an environment."""
    case.assertEqual(sorted(env), sorted(want))


def write_stub(path: Path, out: Path, checks: dict[str, str] | None = None, *,
               exec_: str | None = None, code: int = 0) -> Path:
    """A perl stub at `path` that appends one line to `out` per call: the
    names of the variables it was started with, sorted. For a name in
    `checks` it writes NAME=match when the value is the one given, NAME=other
    when it isn't, never the value. Then it execs `exec_` with its arguments,
    or exits `code`. Perl adds no variable of its own (a shell adds PWD and
    SHLVL; Python on macOS adds LC_CTYPE), so the line is exactly what the
    child was handed. It fails, never skips, without /usr/bin/perl."""
    if not Path(PERL).exists():
        raise AssertionError(f"{PERL} is missing: the planted-variable rows need it and never skip")
    for k, v in (checks or {}).items():
        if "'" in k + v or "\\" in k + v:
            raise AssertionError("stub checks hold no quote or backslash")
    want = ", ".join(f"'{k}' => '{v}'" for k, v in (checks or {}).items())
    tail = f"exec '{exec_}', @ARGV; die \"exec: $!\";\n" if exec_ else f"exit {code};\n"
    path.write_text(
        f"#!{PERL}\n"
        f"my %want = ({want});\n"
        f"open(my $f, '>>', '{out}') or die \"stub: $!\";\n"
        "print $f join(' ', map { exists $want{$_} ? \"$_=\" . ($ENV{$_} eq $want{$_} ? 'match' : 'other') : $_ }"
        " sort keys %ENV), \"\\n\";\n"
        "close $f;\n"
        f"{tail}"
    )
    path.chmod(0o700)
    return path
