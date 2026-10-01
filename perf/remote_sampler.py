"""The remote sampler's loop: `tenant_cogs.py remote-sample`.

It runs on the load generator's box. Every tick it reads each relay box over
a restricted SSH key, whose forced command is `box_sampler.py`, and reads its
own box in-process with the same reader. It keeps every sample in a ring of
size-capped files, writes one summary line per band per box, and watches for
the conditions that void a run:

- a relay box's nftables rule-set hash differs from the one recorded at its
  lockdown;
- a box misses too many ticks: 3 calls in a row, or over 1% of the ticks
  once there are 100;
- the generator overloads before the relay breaks: CPU averaging over 70% on
  two 60 s windows in a row, MemAvailable under 10% of MemTotal for 3 ticks,
  an out-of-memory kill on its box, or its own errors rising in tenant_sim's
  live counters, media and git failures included;
- tenant_sim's live counters are missing or unreadable;

On a void it writes `<out>/samples/void.json` and exits 3; whoever drives
the bands acts on that. It never stops anything itself.

Every SSH destination must be a literal IP inside --allow-cidr and off
--deny-list (the target guard), reached with only --ssh-key, no agent, no
user config, a strict --known-hosts file, and `--` before the address. Only
`fast` or `slow` follows the address; the box's forced command ignores
anything else anyway.
"""

from __future__ import annotations

import json
import math
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import box_sampler

SSH = "/usr/bin/ssh"
SSH_TIMEOUT_S = 20
# A box's reply and its error output are read up to these sizes; a call
# that sends more is stopped and counts as a miss.
MAX_REPLY_BYTES = 1 << 20
MAX_ERR_BYTES = 64 << 10
EXIT_OK, EXIT_REFUSED, EXIT_VOID = 0, 2, 3

# What counts as the generator's own errors in tenant_sim's live counters,
# and what counts as the relay breaking.
GEN_ERROR_KINDS = ("send_failed", "recv_error", "reconnect_failed", "backfill_failed")
# The live counters' totals the loop reads besides client_errors. tenant_sim
# writes every one, so a missing one is an error, never 0. client_errors
# holds only the kinds that happened, so a kind missing there is 0.
LIVE_TOTALS = ("rejected", "media_failed", "git_failed")
# Media uploads and git pushes that failed: the generator's own errors too.
GEN_FAILURE_TOTALS = ("media_failed", "git_failed")


class Refused(Exception):
    """A request the loop will not act on: exit 2, nothing was run."""


@dataclass
class Box:
    role: str
    ip: str


def ssh_argv(key: str, known_hosts: str, ip: str, tier: str) -> list[str]:
    """The one SSH command the loop runs: only this key, no agent, no user
    config, a strict known-hosts file, `--` before the address, then the
    tier word."""
    return [
        SSH, "-F", "/dev/null",
        "-o", "IdentityFile=none", "-i", key,
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "AddKeysToAgent=no",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
        "-o", "VerifyHostKeyDNS=no", "-o", "CanonicalizeHostname=no", "-o", "AddressFamily=inet",
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "Tunnel=no",
        "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PermitLocalCommand=no",
        "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "RequestTTY=no",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        "-o", "LogLevel=ERROR", "-l", "root", "-p", "22", "--", ip, tier,
    ]


def ssh_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/nonexistent"), "LC_ALL": "C"}


def run_ssh(argv: list[str]) -> tuple[int, str, str]:
    """Runs one call, reading at most MAX_REPLY_BYTES of reply and
    MAX_ERR_BYTES of error output, for at most SSH_TIMEOUT_S. Past either,
    the call is killed: exit 125 (too much output) or 124 (too slow)."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ssh_env())
    except OSError as e:
        return 127, "", str(e)
    assert p.stdout is not None and p.stderr is not None
    out_fd, err_fd = p.stdout.fileno(), p.stderr.fileno()
    limits = {out_fd: ("reply", MAX_REPLY_BYTES), err_fd: ("error output", MAX_ERR_BYTES)}
    bufs = {fd: bytearray() for fd in limits}
    deadline = time.monotonic() + SSH_TIMEOUT_S
    sel = selectors.DefaultSelector()
    try:
        for fd in limits:
            sel.register(fd, selectors.EVENT_READ)
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                return 124, "", f"timed out after {SSH_TIMEOUT_S}s"
            for key, _ in sel.select(left):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    sel.unregister(key.fd)
                    continue
                what, limit = limits[key.fd]
                if len(bufs[key.fd]) + len(chunk) > limit:
                    return 125, "", f"the {what} was over {limit} bytes; the call was stopped"
                bufs[key.fd] += chunk
        try:
            code = p.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {SSH_TIMEOUT_S}s"
    finally:
        sel.close()
        if p.poll() is None:
            p.kill()
            p.wait()
        p.stdout.close()
        p.stderr.close()
    return code, bufs[out_fd].decode("utf-8", "replace"), bufs[err_fd].decode("utf-8", "replace")


def check_inputs(boxes: list[str], key: str | None, known_hosts: str | None, guard: Any,
                 parse_ip: Callable[[str], Any]) -> list[Box]:
    """Each --box is ROLE=IP: a plain role name and a literal IP the target
    guard passes. A box needs --ssh-key and --known-hosts, each a regular
    file, not a symlink."""
    out: list[Box] = []
    for spec in boxes:
        role, sep, ip = spec.partition("=")
        if not sep or not role.isidentifier() or len(role) > 32:
            raise Refused(f"--box {spec!r} is not ROLE=IP. Nothing was run.")
        addr = parse_ip(ip)
        if addr is None:
            raise Refused(f"--box {spec!r}: {ip!r} is not an IP address (names are never resolved). Nothing was run.")
        try:
            guard.check_ip(addr)
        except ValueError as e:
            raise Refused(f"--box {spec!r}: {e}. Nothing was run.") from e
        out.append(Box(role, str(addr)))
    if out:
        for flag, path in (("--ssh-key", key), ("--known-hosts", known_hosts)):
            if not path:
                raise Refused(f"{flag} is required with --box. Nothing was run.")
            try:
                st = os.lstat(path)
            except OSError as e:
                raise Refused(f"{flag} {path}: {e.strerror}. Nothing was run.") from e
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"{flag} {path} is not a regular file (a symlink or other). Nothing was run.")
    if len({b.role for b in out}) != len(out):
        raise Refused("two --box values share a role. Nothing was run.")
    return out


# ---- output that can't grow without bound ----


class Ring:
    """Appends lines to files of at most max_bytes each, keeping the newest
    `files` of them: at most files x max_bytes on disk."""

    def __init__(self, folder: Path, files: int = 8, max_bytes: int = 4 << 20) -> None:
        self.folder, self.files, self.max_bytes = folder, files, max_bytes
        folder.mkdir(parents=True, exist_ok=True)
        # A restarted loop carries on from the newest file, so restarts
        # can't leave old files behind past the bound.
        have = sorted(int(m.group(1)) for f in folder.iterdir() if (m := re.fullmatch(r"ring-(\d{6})\.jsonl", f.name)))
        self.n = have[-1] if have else 0
        self.size = self.path(self.n).stat().st_size if have else 0
        for k in have:
            if k <= self.n - self.files:
                self.path(k).unlink()

    def path(self, n: int) -> Path:
        return self.folder / f"ring-{n:06d}.jsonl"

    def append(self, line: str) -> None:
        data = (line.rstrip("\n") + "\n").encode()
        if len(data) > self.max_bytes:
            data = (json.dumps({"dropped": f"a line of {len(data)} bytes, over the ring's {self.max_bytes}-byte files"}) + "\n").encode()
        if self.size and self.size + len(data) > self.max_bytes:
            self.n += 1
            self.size = 0
            old = self.path(self.n - self.files)
            if self.n - self.files >= 0 and old.exists():
                old.unlink()
        with open(self.path(self.n), "ab") as fh:
            fh.write(data)
        self.size += len(data)


# ---- watching for a void ----


@dataclass
class Void:
    reason: str
    box: str | None
    t_unix: float
    gen_event_t: float | None = None
    relay_break_t: float | None = None


@dataclass
class Monitor:
    expected: dict[str, str]  # relay IP -> recorded rule-set hash
    max_consecutive: int = 3
    max_miss_pct: float = 1.0
    min_ticks_for_pct: int = 100
    cpu_limit_pct: float = 70.0
    cpu_window_s: float = 60.0
    mem_min_pct: float = 10.0
    mem_ticks: int = 3
    live_required: bool = False
    consecutive: dict[str, int] = field(default_factory=dict)
    misses: dict[str, int] = field(default_factory=dict)
    ticks: dict[str, int] = field(default_factory=dict)
    relay_break_t: float | None = None
    notes: list[dict[str, Any]] = field(default_factory=list)
    _win: tuple[float, dict[str, int]] | None = None
    _over: list[float] = field(default_factory=list)
    _mem_low: int = 0
    _gen_oom0: int | None = None
    _relay_oom0: dict[str, int] = field(default_factory=dict)
    _live0: dict[str, Any] | None = None

    def relay_break(self, t: float, why: str) -> None:
        if self.relay_break_t is None:
            self.relay_break_t = t
            self.notes.append({"t_unix": t, "relay_break": why})

    def box_tick(self, box: Box, t: float, sample: dict[str, Any] | None, miss: str | None) -> Void | None:
        """One relay box's tick: a sample, or the reason it was missed."""
        key = f"{box.role} ({box.ip})"
        self.ticks[box.ip] = self.ticks.get(box.ip, 0) + 1
        if sample is not None and not (sample.get("nft") or {}).get("hash"):
            miss = "the sample has no rule-set hash"
            sample = None
        if sample is None:
            self.misses[box.ip] = self.misses.get(box.ip, 0) + 1
            self.consecutive[box.ip] = self.consecutive.get(box.ip, 0) + 1
            if self.consecutive[box.ip] >= self.max_consecutive:
                return Void(f"box unreachable: {key}: {self.consecutive[box.ip]} calls in a row failed; the last: {miss}", box.role, t)
        else:
            self.consecutive[box.ip] = 0
        # Checked on every tick, not only on a miss: the share can cross the
        # limit on a good tick, when the count of ticks reaches the minimum.
        n, m = self.ticks[box.ip], self.misses.get(box.ip, 0)
        if n >= self.min_ticks_for_pct and m * 100.0 > self.max_miss_pct * n:
            return Void(f"{key} missed {m} of {n} ticks, over the {self.max_miss_pct:g}% limit", box.role, t)
        if sample is None:
            return None
        got, want = sample["nft"]["hash"], self.expected.get(box.ip)
        if want is None:
            return Void(f"no rule-set hash was recorded at the lockdown for {key}", box.role, t)
        if got != want:
            return Void(f"the rule-set hash on {key} is {got}, not {want}, recorded at the lockdown", box.role, t)
        relay = (sample.get("containers") or {}).get("relay")
        # A container list from a failed `docker ps` is empty, not a sign the
        # relay is gone: only a listing that worked can show a relay break.
        listed = not any(str(e).startswith("docker ps:") for e in sample.get("errors") or [])
        if relay is None and sample.get("containers") is not None and "containers_absent" not in sample and listed:
            self.relay_break(t, f"{key}: no relay container")
        elif relay is not None and relay.get("oom_kill") is not None:
            base = self._relay_oom0.setdefault(box.ip, relay["oom_kill"])
            if relay["oom_kill"] > base:
                self.relay_break(t, f"{key}: the relay was OOM-killed")
        return None

    def gen_tick(self, t: float, sample: dict[str, Any], live: dict[str, Any] | None, live_err: str | None) -> Void | None:
        """The generator box's own tick: its sample, and tenant_sim's live
        counters (or why they can't be read)."""
        events: list[str] = []
        ticks = (sample.get("box") or {}).get("cpu", {}).get("ticks") or {}
        if ticks:
            if self._win is None:
                self._win = (t, ticks)
            elif t - self._win[0] >= self.cpu_window_s:
                t0, k0 = self._win
                total = sum(ticks.values()) - sum(k0.values())
                idle = ticks.get("idle", 0) + ticks.get("iowait", 0) - k0.get("idle", 0) - k0.get("iowait", 0)
                share = 100.0 * (total - idle) / total if total > 0 else 0.0
                self._over = (self._over + [share])[-2:] if share > self.cpu_limit_pct else []
                self._win = (t, ticks)
                if len(self._over) == 2:
                    events.append(f"the generator's CPU averaged {self._over[0]:.1f}% and {self._over[1]:.1f}% on two {self.cpu_window_s:g} s windows in a row, over {self.cpu_limit_pct:g}%")
        mem = (sample.get("box") or {}).get("mem") or {}
        if mem.get("MemTotal") and mem.get("MemAvailable") is not None:
            if mem["MemAvailable"] * 100.0 < self.mem_min_pct * mem["MemTotal"]:
                self._mem_low += 1
            else:
                self._mem_low = 0
            if self._mem_low == self.mem_ticks:
                events.append(f"the generator's MemAvailable was under {self.mem_min_pct:g}% of MemTotal for {self._mem_low} ticks")
        oom = (sample.get("box") or {}).get("oom_kill")
        if oom is not None:
            if self._gen_oom0 is None:
                self._gen_oom0 = oom
            elif oom > self._gen_oom0:
                events.append(f"an out-of-memory kill on the generator's box ({oom - self._gen_oom0})")
                self._gen_oom0 = oom
        if self.live_required:
            if live is None:
                return Void(f"the generator's live counters: {live_err}", "generator", t, gen_event_t=t, relay_break_t=self.relay_break_t)
            # Each tick is compared with the one before, so one rise is
            # reported once.
            ce = live.get("client_errors") or {}
            if self._live0 is not None:
                c0 = self._live0.get("client_errors") or {}
                rose = {k: ce.get(k, 0) - c0.get(k, 0) for k in GEN_ERROR_KINDS if ce.get(k, 0) > c0.get(k, 0)}
                rose.update({k: live[k] - self._live0[k] for k in GEN_FAILURE_TOTALS if live[k] > self._live0[k]})
                if rose:
                    events.append("the generator reported its own errors: " + ", ".join(f"{k} +{v}" for k, v in sorted(rose.items())))
                if live["rejected"] > self._live0["rejected"]:
                    self.relay_break(t, f"the relay rejected {live['rejected'] - self._live0['rejected']} events")
                if ce.get("connection_dropped", 0) > c0.get("connection_dropped", 0):
                    self.relay_break(t, "the relay dropped connections")
            self._live0 = live
        for e in events:
            if self.relay_break_t is not None and self.relay_break_t <= t:
                self.notes.append({"t_unix": t, "after_relay_break": e, "relay_break_t": self.relay_break_t})
                continue
            return Void(e + ", before the relay broke", "generator", t, gen_event_t=t, relay_break_t=self.relay_break_t)
        return None


def read_live(path: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        return None, f"{path} is missing"
    except OSError as e:
        return None, f"{path}: {e.strerror}"
    try:
        v = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"{path} is not JSON: {e}"
    if not isinstance(v, dict) or not isinstance(v.get("client_errors"), dict):
        return None, f"{path} has no client_errors"
    for k in LIVE_TOTALS:
        if k not in v:
            return None, f"{path} has no {k}"
    counts = list(v["client_errors"].values()) + [v[k] for k in LIVE_TOTALS]
    if not all(type(c) is int and c >= 0 for c in counts):
        return None, f"{path} has a counter that is not a whole number"
    return v, None


# ---- per-band results ----


def pct(xs: list[float]) -> dict[str, float] | None:
    if not xs:
        return None
    s = sorted(xs)
    at = lambda p: s[min(len(s) - 1, max(0, math.ceil(p / 100.0 * len(s)) - 1))]  # noqa: E731
    return {"min": s[0], "p50": at(50), "p95": at(95), "max": s[-1], "n": len(s)}


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


class BandStats:
    """One box's results for one band. It keeps the numbers it needs, not
    the samples, so a long band costs a few floats per tick."""

    def __init__(self, band: str, role: str) -> None:
        self.band, self.role = band, role
        self.ticks = self.missed = self.slow_calls = self.slow_missed = 0
        self.t0: float | None = None
        self.t1: float | None = None
        self.mem: list[float] = []
        self.busy: list[float] = []
        self.first_cpu: dict[str, int] | None = None
        self.last_cpu: dict[str, int] | None = None
        self.ncpu = 1
        self.steal: dict[str, Any] = {}
        self.ws: dict[str, list[float]] = {}
        self.drops0: dict[str, Any] | None = None
        self.drops1: dict[str, Any] | None = None
        self.wal_max: int | None = None
        self.lsn0: tuple[float, int] | None = None
        self.lsn1: tuple[float, int] | None = None
        self.disk_last: dict[str, Any] | None = None
        self.cpu_s = 0.0
        self.maxrss: int | None = None

    def add(self, tier: str, sample: dict[str, Any] | None) -> None:
        if tier == "slow":
            self.slow_calls += 1
        else:
            self.ticks += 1
        if sample is None:
            if tier == "slow":
                self.slow_missed += 1
            else:
                self.missed += 1
            return
        t = sample["t_unix"]
        self.t0 = t if self.t0 is None else self.t0
        self.t1 = t
        reader = sample.get("reader") or {}
        if _num(reader.get("cpu_s")):
            self.cpu_s += reader["cpu_s"]
        rss = [reader.get(k) for k in ("maxrss_kb", "children_maxrss_kb") if _num(reader.get(k))]
        if rss:
            self.maxrss = max([self.maxrss or 0, *rss])
        self.steal = sample.get("steal") or {}
        if tier == "slow":
            disk = sample.get("disk") or {}
            wal = (disk.get("wal") or {}).get("bytes")
            if _num(wal):
                self.wal_max = wal if self.wal_max is None else max(self.wal_max, wal)
            lsn = (sample.get("wal") or {}).get("wal_lsn_bytes")
            if _num(lsn):
                self.lsn0 = self.lsn0 or (t, lsn)
                self.lsn1 = (t, lsn)
            self.disk_last = disk
            return
        box = sample["box"]
        m = box.get("mem") or {}
        if _num(m.get("MemTotal")) and _num(m.get("MemAvailable")):
            self.mem.append(m["MemTotal"] - m["MemAvailable"])
        cpu = box.get("cpu") or {}
        ticks = cpu.get("ticks") or {}
        if ticks:
            if self.last_cpu is not None:
                tot = sum(ticks.values()) - sum(self.last_cpu.values())
                idle = ticks.get("idle", 0) + ticks.get("iowait", 0) - self.last_cpu.get("idle", 0) - self.last_cpu.get("iowait", 0)
                if tot > 0:
                    self.busy.append(100.0 * (tot - idle) / tot)
            self.first_cpu = self.first_cpu or ticks
            self.last_cpu = ticks
        if _num(cpu.get("ncpu")):
            self.ncpu = max(self.ncpu, cpu["ncpu"])
        for svc, c in (sample.get("containers") or {}).items():
            if _num((c or {}).get("working_set")):
                self.ws.setdefault(svc, []).append(c["working_set"])
        drops = (sample.get("nft") or {}).get("drops")
        if drops is not None:
            self.drops0 = self.drops0 or drops
            self.drops1 = drops

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {"band": self.band, "role": self.role, "ticks": self.ticks, "missed": self.missed,
                               "slow_calls": self.slow_calls, "slow_missed": self.slow_missed}
        if self.t0 is None or self.t1 is None:
            return out
        out["from"], out["to"] = self.t0, self.t1
        out["box_mem_used_bytes"] = pct(self.mem)
        out["cpu_busy_pct"] = pct(self.busy)
        a, b = self.first_cpu, self.last_cpu
        if self.steal.get("reported") is True and a and b and a is not b:
            tot = sum(b.values()) - sum(a.values())
            out["steal_pct"] = 100.0 * (b.get("steal", 0) - a.get("steal", 0)) / tot if tot > 0 else None
        else:
            out["steal_pct"] = None
            out["steal_why"] = self.steal.get("why", "unknown")
        out["working_set_bytes"] = {svc: pct(v) for svc, v in sorted(self.ws.items())}
        if self.drops0 is not None and self.drops1 is not None and self.drops0 is not self.drops1:
            out["drops_rose"] = {ch: (v or {}).get("packets", 0) - ((self.drops0.get(ch) or {}).get("packets", 0))
                                 for ch, v in self.drops1.items()}
        if self.slow_calls:
            out["wal_high_water_bytes"] = self.wal_max
            l0, l1 = self.lsn0, self.lsn1
            out["wal_write_bytes_per_s"] = (l1[1] - l0[1]) / (l1[0] - l0[0]) if l0 and l1 and l1[0] > l0[0] else None
            out["disk_last"] = self.disk_last
        span = self.t1 - self.t0
        out["sampler"] = {
            "cpu_s": round(self.cpu_s, 4),
            "share_pct_of_box": round(100.0 * self.cpu_s / (span * self.ncpu), 4) if span > 0 else None,
            "maxrss_kb": self.maxrss,
        }
        return out


# ---- the loop ----


@dataclass
class Settings:
    boxes: list[Box]
    key: str | None
    known_hosts: str | None
    out: Path
    expected: dict[str, str]
    self_role: str | None
    self_config: dict[str, Any] | None
    live_file: str | None
    band_file: str | None
    fast_every: float
    slow_every: float
    duration: float | None
    once: bool
    ring_files: int
    ring_bytes: int


class Stop(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


def parse_reply(code: int, out: str, err: str, tier: str) -> tuple[dict[str, Any] | None, str | None]:
    """A box's reply as a sample, or why it is a miss."""
    if code != 0:
        last = err.strip().splitlines()[-1] if err.strip() else ""
        return None, f"ssh exit {code}: {last}" if last else f"ssh exit {code}"
    try:
        v = json.loads(out)
    except json.JSONDecodeError:
        return None, "the reply is not JSON"
    if not (isinstance(v, dict) and v.get("tier") == tier and _num(v.get("t_unix")) and isinstance(v.get("box"), dict)):
        return None, f"the reply is not a {tier} sample"
    return v, None


def own_cpu_s() -> float:
    me, kids = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return me.ru_utime + me.ru_stime + kids.ru_utime + kids.ru_stime


def run_loop(s: Settings, runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
             clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
             local: Callable[[str, dict[str, Any]], dict[str, Any]] = box_sampler.sample) -> int:
    # Looked up at call time, so a test's patch of run_ssh binds here too.
    runner = runner or run_ssh
    folder = s.out / "samples"
    folder.mkdir(parents=True, exist_ok=True)
    roles = [b.role for b in s.boxes] + ([s.self_role] if s.self_role else [])
    rings = {r: Ring(folder / r, s.ring_files, s.ring_bytes) for r in roles}
    mon = Monitor(expected=s.expected, live_required=bool(s.live_file))
    band = "none"
    stats = {r: BandStats(band, r) for r in roles}
    start = clock()
    next_slow = start
    # In-process, the reader's getrusage counts the whole loop since it
    # started (its ssh calls too: on this box they are the sampler's cost),
    # so each local sample is given the CPU used since the one before.
    cpu_mark = own_cpu_s()

    def quiet() -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)

    def flush() -> None:
        with open(folder / "bands.jsonl", "a") as fh:
            for r in roles:
                fh.write(json.dumps(stats[r].summary(), separators=(",", ":")) + "\n")
        with open(folder / "notes.jsonl", "a") as fh:
            for n in mon.notes:
                fh.write(json.dumps(n, separators=(",", ":")) + "\n")
        mon.notes.clear()

    def void(v: Void) -> int:
        quiet()
        flush()
        (folder / "void.json").write_text(json.dumps(v.__dict__, indent=2) + "\n")
        print(f"void: {v.reason}", file=sys.stderr)
        return EXIT_VOID

    def on_signal(signum: int, frame: Any) -> None:
        quiet()  # a second signal must not cut the summaries short
        raise Stop(130 if signum == signal.SIGINT else 143)

    old = {sig: signal.signal(sig, on_signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        while True:
            t = clock()
            if s.band_file:
                try:
                    now_band = Path(s.band_file).read_text().strip() or "none"
                except OSError:
                    now_band = "none"
                if now_band != band:
                    flush()
                    band = now_band
                    stats = {r: BandStats(band, r) for r in roles}
            tiers = ["fast"] + (["slow"] if t >= next_slow else [])
            if "slow" in tiers:
                next_slow = t + s.slow_every
            for box in s.boxes:
                for tier in tiers:
                    sample, miss = parse_reply(*runner(ssh_argv(s.key or "", s.known_hosts or "", box.ip, tier)), tier)
                    rings[box.role].append(json.dumps({"t": t, "band": band, "tier": tier, **({"sample": sample} if sample else {"miss": miss})}, separators=(",", ":")))
                    stats[box.role].add(tier, sample)
                    if tier == "fast":
                        v = mon.box_tick(box, t, sample, miss)
                        if v:
                            return void(v)
            if s.self_role and s.self_config is not None:
                live, live_err = read_live(s.live_file) if s.live_file else (None, None)
                for tier in tiers:
                    sample = local(tier, s.self_config)
                    now_cpu = own_cpu_s()
                    sample["reader"] = {**(sample.get("reader") or {}), "cpu_s": round(now_cpu - cpu_mark, 4), "cpu_s_since_start": round(now_cpu, 4)}
                    cpu_mark = now_cpu
                    rings[s.self_role].append(json.dumps({"t": t, "band": band, "tier": tier, "sample": sample, **({"live": live} if live else {})}, separators=(",", ":")))
                    stats[s.self_role].add(tier, sample)
                    if tier == "fast":
                        v = mon.gen_tick(t, sample, live, live_err)
                        if v:
                            return void(v)
            if s.once or (s.duration is not None and clock() - start >= s.duration):
                flush()
                return EXIT_OK
            sleep(max(0.0, s.fast_every - (clock() - t)))
    except Stop as e:
        flush()
        return e.code
    finally:
        for sig, h in old.items():
            signal.signal(sig, h)


def cmd_remote_sample(args: Any, guard: Any, parse_ip: Callable[[str], Any]) -> int:
    """tenant_cogs.py passes in its target guard and IP parser. This module
    never imports tenant_cogs, which may be running as __main__: a second
    copy would have its own Refused, and a refusal would escape as a
    traceback."""
    boxes = check_inputs(args.box, args.ssh_key, args.known_hosts, guard, parse_ip)
    expected: dict[str, str] = {}
    if boxes and not args.expected_hashes:
        # Without the hashes recorded at the lockdown there is nothing to
        # check a box's rule set against, so the run could not void on it.
        raise Refused("--expected-hashes is required with --box. Nothing was run.")
    if args.expected_hashes:
        try:
            raw = json.loads(Path(args.expected_hashes).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise Refused(f"--expected-hashes {args.expected_hashes}: {e}. Nothing was run.") from e
        if not isinstance(raw, dict) or not all(isinstance(v, str) and len(v) == 64 for v in raw.values()):
            raise Refused(f"--expected-hashes {args.expected_hashes} is not {{ip: sha256}}. Nothing was run.")
        expected = {str(k): v for k, v in raw.items()}
        missing = [b.ip for b in boxes if b.ip not in expected]
        if missing:
            raise Refused(f"--expected-hashes has no hash for {missing}. Nothing was run.")
    if not boxes and not args.self_role:
        raise Refused("give at least one --box or --self. Nothing was run.")
    self_cfg = None
    if args.self_role:
        try:
            self_cfg = box_sampler.load_config(Path(args.self_config).read_text()) if args.self_config else {}
        except (OSError, box_sampler.ConfigError) as e:
            raise Refused(f"--self-config {args.self_config}: {e}. Nothing was run.") from e
    fast, slow = (30.0, 300.0) if args.soak else (float(args.fast_every), float(args.slow_every))
    s = Settings(boxes, args.ssh_key, args.known_hosts, Path(args.out_dir), expected, args.self_role, self_cfg,
                 args.live_file, args.band_file, fast, slow, args.duration, args.once, args.ring_files, args.ring_bytes)
    return run_loop(s)


def add_parser(sub: Any) -> None:
    p = sub.add_parser("remote-sample", help="sample relay boxes over a restricted ssh key, and this box; void on a changed rule set or an overloaded generator")
    p.add_argument("--box", action="append", default=[], help="ROLE=IP of a box to read over ssh (repeatable)")
    p.add_argument("--ssh-key", default=None)
    p.add_argument("--known-hosts", default=None)
    p.add_argument("--allow-cidr", action="append", default=[])
    p.add_argument("--deny-list", default=None)
    p.add_argument("--expected-hashes", default=None, help="JSON {ip: sha256} of each box's rule set, recorded at its lockdown")
    p.add_argument("--self", dest="self_role", default=None, help="the role this box is sampled as (in-process)")
    p.add_argument("--self-config", default=None, help="box_sampler config for this box")
    p.add_argument("--live-file", default=None, help="tenant_sim's <out-dir>/live.json; missing or unreadable voids")
    p.add_argument("--band-file", default=None, help="a file holding the current band's name")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--fast-every", type=float, default=5.0)
    p.add_argument("--slow-every", type=float, default=60.0)
    p.add_argument("--soak", action="store_true", help="fast every 30 s, slow every 300 s")
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--once", action="store_true")
    p.add_argument("--ring-files", type=int, default=8)
    p.add_argument("--ring-bytes", type=int, default=4 << 20)
