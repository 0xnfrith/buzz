"""The remote sampler's loop: `tenant_cogs.py remote-sample`.

It runs on the load generator's box. Every tick it reads each relay box over
a restricted SSH key, whose forced command is `box_sampler.py`, and reads its
own box in-process with the same reader. It keeps every sample in a ring of
size-capped files, writes one summary line per band per box, and watches for
the conditions that void a run:

- a relay box's nftables rule-set hash differs from the one recorded at its
  lockdown;
- before that box's relay breaks, a box misses too many ticks: 3 calls in
  a row, or over 1% of the ticks once there are 100. After the break, that
  is a note;
- before that box's relay breaks, a relay box's slow calls fail as often,
  counted apart from its ticks: a slow call fails when its reply is not a
  whole slow sample (an error from `docker system df` or `psql`, or a disk
  figure missing). After the break, that is a note;
- the generator overloads before the relay breaks: CPU averaging over 70% on
  two 60 s windows in a row, MemAvailable under 10% of MemTotal for 3 ticks,
  an out-of-memory kill on its box, or its own errors rising in tenant_sim's
  live counters: a client error kind, a media upload or an agent's read that
  failed before it went out, or a git add, commit or branch that failed;
- tenant_sim's live counters are missing, unreadable, stale, ahead of the
  clock, or go backwards; or its last write says its run lost its driver
  (a lease that ran out, or stdin ended without a stop). A last write that
  ended on a stop is final and never stale.

Every limit a tick crosses is decided at the tick's end, after all of
that tick's break signals: a limit and a break on the same tick count as
after the break.

"The relay broke" is computed here, once, per relay: the service level
(acks within 500 ms at a measured band's end, the relay box's free memory,
lost events, failed joins) and the signals the loop already had. It goes
to `samples/breaks.json` as it comes, for a band driver to read. Each
generator's live file is bound to the relay it drives (`--live
RELAY=PATH`).

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
# rate_limited (sends the relay's per-key rate limits turned away) is
# counted apart: neither the relay breaking nor the generator's own error.
LIVE_TOTALS = ("sent", "accepted", "rejected", "rate_limited", "media_client_failed", "media_refused",
               "media_unanswered", "git_local_failed", "git_push_failed",
               "read_client_failed", "read_refused", "read_unanswered", "read_rate_limited", "send_unanswered",
               "lost", "joined")
# tenant_sim's ack-time histogram: accepted sends within each bound, in ms,
# cumulative. 500 ms is a bound, so the service level's share is exact.
ACK_BOUNDS = ("10", "25", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf")
# The service level: 95% of events acknowledged within
# 500 ms, judged on a measured band or ramp step with at least 20 acks.
SLO_ACK_MS, SLO_ACK_SHARE, SLO_MIN_ACKS = "500", 95.0, 20
# The bands the service level is judged on; a ramp step is ramp-<n>. A ramp
# step's window starts STEP_SETTLE_S after the step, once its joiners have
# connected and run their backfill.
MEASURED_BANDS = ("floor", "steady", "peak")
RAMP_STEP = re.compile(r"ramp-[0-9]{1,4}")
STEP_SETTLE_S = 60.0
# Media, git and read failures, split by where they failed. A media upload
# or an agent's read that failed before it went out, or a git add, commit or
# branch, is the generator's own error.
GEN_FAILURE_TOTALS = ("media_client_failed", "git_local_failed", "read_client_failed")
# An upload the relay refused (an answer that isn't 2xx) or never answered
# (a transport error or a timeout), or a push that failed, is the relay
# breaking: at its limit, a relay usually fails by timing out. A stalled
# generator still shows in its CPU, its memory and a stale live.json.
RELAY_FAILURE_TOTALS = {
    "media_refused": "the relay refused {n} media uploads",
    "media_unanswered": "the relay didn't answer {n} media uploads",
    "git_push_failed": "{n} git pushes to the relay failed",
    "read_refused": "the relay refused {n} agent reads",
    "read_unanswered": "the relay didn't answer {n} agent reads",
    # A send written that got no OK in time, or whose socket failed after
    # the write. Trusted as the relay's only because a generator too busy
    # to read its answers also shows in the generator box's own CPU and
    # memory limits, which void the run.
    "send_unanswered": "the relay didn't answer {n} sends",
}
# tenant_sim rewrites live.json every 2 s. Older than this (five writes
# missed), or this far ahead of the clock, the file is no longer live.
LIVE_MAX_AGE_S = 10.0
# tenant_sim's last write says why its run ended. A run a driver stopped is
# final, never stale; one whose band lease ran out, or whose input ended
# without a stop, lost its driver.
LIVE_ENDED = {
    "stop": None,
    "lease": "its band lease ran out with no newer signal: the driver is gone",
    "eof": "its band input ended without a stop: the driver is gone",
}

# What a relay box's slow sample must hold, as numbers: the whole box's
# filesystem, and on a box with Docker the stack's Postgres data, WAL, MinIO,
# Redis, git, container logs, image overhead and WAL position.
SLOW_NEEDS = ("box.fs.used", "box.fs.avail")
SLOW_NEEDS_DOCKER = ("disk.postgres_data.bytes", "disk.wal.bytes", "disk.minio.bytes", "disk.redis.bytes",
                     "disk.git.bytes", "disk.container_logs_bytes", "disk.images_bytes", "wal.wal_lsn_bytes")
# The reader's errors that only the slow tier makes. The others (a
# container's cgroup, a unit, nft) are the fast tier's: a relay that is
# restarting shows one, and that is the relay breaking, not the sampler
# failing.
SLOW_ERRORS = ("docker system df:", "psql:")


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


# What a limit waits on, besides one relay's role: the first break of any
# relay, or every relay's.
ANY, ALL = "*any", "*all"


@dataclass
class Limit:
    """A limit one tick crossed. The tick's end decides it, once every
    break signal read in that tick is in (Monitor.judge): a limit and a
    break on the same tick count as after the break, since one tick can't
    order them."""
    reason: str
    role: str  # whose result: a relay box's role, or "generator"
    t: float
    # The break the limit waits on: a relay's role (that relay's own), ANY
    # (the first break of any relay) or ALL (every relay's: the generator
    # box's own limits, which spoil every relay that hasn't broken).
    waits: str = ANY
    # A void before that break, a note after it. False: a void at any time.
    after_break: bool = False
    # After the break, noted once per key; None: noted each time.
    once: str | None = None


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
    live_max_age_s: float = LIVE_MAX_AGE_S
    # The relays a run measures, by role: its relay boxes, and the relays
    # its live files are bound to.
    relays: list[str] = field(default_factory=list)
    # The service level: SLO_ACK_SHARE % of acks within SLO_ACK_MS, judged
    # on a band with at least SLO_MIN_ACKS; and the relay box's
    # MemAvailable at least relay_mem_min_pct of MemTotal.
    relay_mem_min_pct: float = 10.0
    consecutive: dict[str, int] = field(default_factory=dict)
    misses: dict[str, int] = field(default_factory=dict)
    ticks: dict[str, int] = field(default_factory=dict)
    slow_consecutive: dict[str, int] = field(default_factory=dict)
    slow_misses: dict[str, int] = field(default_factory=dict)
    slow_calls: dict[str, int] = field(default_factory=dict)
    # The first break of any relay.
    relay_break_t: float | None = None
    # Each break signal's first time, by source and relay: ("box", role)
    # from a relay box's own sample; ("live", role) from the live file bound
    # to that relay; ("live", None) from a live file bound to none, which
    # counts for every relay.
    breaks: dict[tuple[str, str | None], float] = field(default_factory=dict)
    # Each break signal's first: its time, what it was, and the band it
    # came in (for the ack test, the band judged), so a driver can tell
    # which ramp step broke.
    break_info: dict[tuple[str, str | None], dict[str, Any]] = field(default_factory=dict)
    # The band the loop is in now.
    band: str = "none"
    notes: list[dict[str, Any]] = field(default_factory=list)
    _win: tuple[float, dict[str, int]] | None = None
    _over: list[float] = field(default_factory=list)
    _mem_low: int = 0
    _gen_oom0: int | None = None
    _relay_oom0: dict[str, int] = field(default_factory=dict)
    # The last good read of each live file, by the relay it is bound to.
    _lives: dict[str | None, dict[str, Any]] = field(default_factory=dict)
    _noted: set[str] = field(default_factory=set)

    def relay_break(self, t: float, why: str, role: str | None = None, source: str = "live",
                    band: str | None = None) -> None:
        """A break signal for relay `role` (None: a live file bound to no
        relay, so every relay), in `band` (the loop's band now if not
        given). Each source's first is noted."""
        key = (source, role)
        if key not in self.breaks:
            self.breaks[key] = t
            self.break_info[key] = {"t_unix": t, "why": why, "band": band or self.band}
            self.notes.append({"t_unix": t, "relay_break": why, **({"relay": role} if role else {})})
        if self.relay_break_t is None:
            self.relay_break_t = t

    def relay_broke(self, role: str) -> float | None:
        """When relay `role` broke: its first break signal, from its box, its
        live file, or a live file bound to no relay."""
        ts = [self.breaks.get(k) for k in (("box", role), ("live", role), ("live", None))]
        found = [x for x in ts if x is not None]
        return min(found) if found else None

    def break_at(self, waits: str) -> float | None:
        """When the break a limit waits on came: one relay's, the first of
        any (ANY), or the last of every relay's (ALL: None while any relay
        hasn't broken)."""
        if waits == ANY or (waits == ALL and not self.relays):
            return self.relay_break_t
        if waits == ALL:
            ts = [self.relay_broke(r) for r in self.relays]
            return None if any(x is None for x in ts) else max(ts)  # type: ignore[type-var]
        return self.relay_broke(waits)

    def broken(self) -> dict[str, dict[str, Any]]:
        """Each relay that has broken: when, what, and in which band, from
        its first break signal. What a band driver reads."""
        out: dict[str, dict[str, Any]] = {}
        for r in self.relays:
            infos = [self.break_info[k] for k in (("box", r), ("live", r), ("live", None)) if k in self.break_info]
            if infos:
                out[r] = min(infos, key=lambda i: i["t_unix"])
        return out

    def judge(self, limits: list[Limit]) -> Void | None:
        """Decides a tick's limits, in the order they were read: the first
        that is still a void, or None. A limit that waits on a break which
        came at or before it is a note instead, with its time."""
        for lim in limits:
            b = self.break_at(lim.waits)
            if lim.after_break and b is not None and b <= lim.t:
                if lim.once is None or lim.once not in self._noted:
                    if lim.once is not None:
                        self._noted.add(lim.once)
                    self.notes.append({"t_unix": lim.t, "after_relay_break": lim.reason, "relay_break_t": b})
                continue
            if lim.role == "generator":
                reason = lim.reason + (", before the relay broke" if lim.after_break else "")
                return Void(reason, "generator", lim.t, gen_event_t=lim.t, relay_break_t=self.relay_break_t)
            return Void(lim.reason, lim.role, lim.t)
        return None

    def _settle(self, limits: list[Limit], defer: list[Limit] | None) -> Void | None:
        """With defer, the limits wait for the tick's end; without, they are
        judged now."""
        if defer is not None:
            defer.extend(limits)
            return None
        return self.judge(limits)

    def box_tick(self, box: Box, t: float, sample: dict[str, Any] | None, miss: str | None,
                 defer: list[Limit] | None = None) -> Void | None:
        """One relay box's tick: a sample, or the reason it was missed.
        Missed calls are limits that wait on this box's break: a crashed or
        swapping relay box can stop answering, and that is the relay
        breaking. A changed rule set voids at any time."""
        key = f"{box.role} ({box.ip})"
        out: list[Limit] = []
        self.ticks[box.ip] = self.ticks.get(box.ip, 0) + 1
        if sample is not None and not (sample.get("nft") or {}).get("hash"):
            miss = "the sample has no rule-set hash"
            sample = None
        if sample is None:
            self.misses[box.ip] = self.misses.get(box.ip, 0) + 1
            self.consecutive[box.ip] = self.consecutive.get(box.ip, 0) + 1
            # Each run of misses reaching the limit is one limit: before the
            # break that voids, and after it, it is noted once.
            if self.consecutive[box.ip] == self.max_consecutive:
                out.append(Limit(f"box unreachable: {key}: {self.consecutive[box.ip]} calls in a row failed; the last: {miss}",
                                 box.role, t, box.role, after_break=True))
        else:
            self.consecutive[box.ip] = 0
        # Checked on every tick, not only on a miss: the share can cross the
        # limit on a good tick, when the count of ticks reaches the minimum.
        n, m = self.ticks[box.ip], self.misses.get(box.ip, 0)
        if n >= self.min_ticks_for_pct and m * 100.0 > self.max_miss_pct * n:
            out.append(Limit(f"{key} missed {m} of {n} ticks, over the {self.max_miss_pct:g}% limit",
                             box.role, t, box.role, after_break=True, once=f"{box.ip} ticks"))
        if sample is None:
            return self._settle(out, defer)
        got, want = sample["nft"]["hash"], self.expected.get(box.ip)
        if want is None:
            out.append(Limit(f"no rule-set hash was recorded at the lockdown for {key}", box.role, t))
            return self._settle(out, defer)
        if got != want:
            out.append(Limit(f"the rule-set hash on {key} is {got}, not {want}, recorded at the lockdown", box.role, t))
            return self._settle(out, defer)
        relay = (sample.get("containers") or {}).get("relay")
        # A container list from a failed `docker ps` is empty, not a sign the
        # relay is gone: only a listing that worked can show a relay break.
        listed = not any(str(e).startswith("docker ps:") for e in sample.get("errors") or [])
        if relay is None and sample.get("containers") is not None and "containers_absent" not in sample and listed:
            self.relay_break(t, f"{key}: no relay container", box.role, "box")
        elif relay is not None and relay.get("oom_kill") is not None:
            base = self._relay_oom0.setdefault(box.ip, relay["oom_kill"])
            if relay["oom_kill"] > base:
                self.relay_break(t, f"{key}: the relay was OOM-killed", box.role, "box")
        # The service level: at least 10% of the box's memory free.
        mem = (sample.get("box") or {}).get("mem") or {}
        if _num(mem.get("MemTotal")) and _num(mem.get("MemAvailable")) and mem["MemTotal"] > 0:
            if mem["MemAvailable"] * 100.0 < self.relay_mem_min_pct * mem["MemTotal"]:
                share = 100.0 * mem["MemAvailable"] / mem["MemTotal"]
                self.relay_break(t, f"{key}: MemAvailable was {share:.1f}% of MemTotal, under {self.relay_mem_min_pct:g}%",
                                 box.role, "box")
        return self._settle(out, defer)

    def slow_tick(self, box: Box, t: float, miss: str | None, defer: list[Limit] | None = None) -> Void | None:
        """One relay box's slow call: miss is None for a whole slow sample,
        else why it isn't one. The same two limits as the ticks, counted
        apart from them: a good fast call between two failed slow ones must
        not reset the count. Before this box's relay breaks, a limit voids.
        After, it is a note with its time: a crash-looping Postgres is the
        relay breaking, and the result stands. Each run of misses reaching
        the limit is noted once, and the share once."""
        key = f"{box.role} ({box.ip})"
        out: list[Limit] = []
        self.slow_calls[box.ip] = self.slow_calls.get(box.ip, 0) + 1
        if miss is not None:
            self.slow_misses[box.ip] = self.slow_misses.get(box.ip, 0) + 1
            self.slow_consecutive[box.ip] = self.slow_consecutive.get(box.ip, 0) + 1
            run = self.slow_consecutive[box.ip]
            if run == self.max_consecutive:
                out.append(Limit(f"{key}: {run} slow calls in a row failed; the last: {miss}", box.role, t, box.role, after_break=True))
        else:
            self.slow_consecutive[box.ip] = 0
        n, m = self.slow_calls[box.ip], self.slow_misses.get(box.ip, 0)
        if n >= self.min_ticks_for_pct and m * 100.0 > self.max_miss_pct * n:
            out.append(Limit(f"{key} missed {m} of {n} slow calls, over the {self.max_miss_pct:g}% limit",
                             box.role, t, box.role, after_break=True, once=f"{box.ip} slow calls"))
        return self._settle(out, defer)

    def gen_box_tick(self, t: float, sample: dict[str, Any], defer: list[Limit] | None = None) -> Void | None:
        """The generator box's own sample: its CPU, memory and OOM kills. An
        overloaded load source spoils every relay that hasn't broken yet, so
        each limit waits on every relay's break."""
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
        return self._settle([Limit(e, "generator", t, ALL, after_break=True) for e in events], defer)

    def live_tick(self, role: str | None, t: float, live: dict[str, Any] | None, live_err: str | None,
                  live_t: float | None = None, defer: list[Limit] | None = None) -> Void | None:
        """One live file's read: tenant_sim's live counters for the relay
        `role` it drives (None: a file bound to no relay), or why they can't
        be read, read at live_t (t if not given). tenant_sim and the loop
        share the generator box's clock."""
        name = "the generator's live counters" + (f" for {role}" if role else "")
        waits = role or ANY
        if live is None:
            return self._settle([Limit(f"{name}: {live_err}", "generator", t)], defer)
        ended = live.get("ended")
        if ended is not None and LIVE_ENDED[ended] is not None:
            run = "the generator's run" + (f" for {role}" if role else "")
            return self._settle([Limit(f"{run} ended: {LIVE_ENDED[ended]}", "generator", t)], defer)
        # tenant_sim logs a failed rewrite and carries on, so an old file
        # with no errors in it must not pass as a live one. A run that ended
        # on a stop wrote its last file, which ages.
        last = self._lives.get(role)
        lt, now = live["t_unix"], t if live_t is None else live_t
        stale = None
        if last is not None and lt < last["t_unix"]:
            stale = f"went backwards: t_unix {lt}, after {last['t_unix']}"
        elif now - lt > self.live_max_age_s and ended is None:
            stale = f"are stale: t_unix {lt} is {now - lt:.1f} s old, over the {self.live_max_age_s:g} s limit"
        elif lt - now > self.live_max_age_s:
            stale = f"are ahead of this box's clock: t_unix {lt} is {lt - now:.1f} s ahead, over the {self.live_max_age_s:g} s limit"
        if stale:
            return self._settle([Limit(f"{name} {stale}", "generator", t)], defer)
        out: list[Limit] = []
        # Each read is compared with the one before, so one rise is
        # reported once.
        ce = live.get("client_errors") or {}
        if last is not None:
            c0 = last.get("client_errors") or {}
            rose = {k: ce.get(k, 0) - c0.get(k, 0) for k in GEN_ERROR_KINDS if ce.get(k, 0) > c0.get(k, 0)}
            rose.update({k: live[k] - last[k] for k in GEN_FAILURE_TOTALS if live[k] > last[k]})
            if rose:
                who = "the generator" + (f" for {role}" if role else "")
                out.append(Limit(f"{who} reported its own errors: " + ", ".join(f"{k} +{v}" for k, v in sorted(rose.items())),
                                 "generator", t, waits, after_break=True))
            if live["rejected"] > last["rejected"]:
                self.relay_break(t, f"the relay rejected {live['rejected'] - last['rejected']} events", role)
            for k, why in RELAY_FAILURE_TOTALS.items():
                if live[k] > last[k]:
                    self.relay_break(t, why.format(n=live[k] - last[k]), role)
            if ce.get("connection_dropped", 0) > c0.get("connection_dropped", 0):
                self.relay_break(t, "the relay dropped connections", role)
            if ce.get("join_failed", 0) > c0.get("join_failed", 0):
                self.relay_break(t, f"{ce['join_failed'] - c0.get('join_failed', 0)} identities couldn't join the relay", role)
            if live["lost"] > last["lost"]:
                self.relay_break(t, f"the relay lost {live['lost'] - last['lost']} events", role)
        self._lives[role] = live
        return self._settle(out, defer)

    def gen_tick(self, t: float, sample: dict[str, Any], live: dict[str, Any] | None, live_err: str | None,
                 live_t: float | None = None, defer: list[Limit] | None = None) -> Void | None:
        """The generator box's sample and, with live counters required, the
        one live file bound to no relay: a run with one relay."""
        limits: list[Limit] = []
        if self.live_required:
            self.live_tick(None, t, live, live_err, live_t, limits)
        self.gen_box_tick(t, sample, limits)
        return self._settle(limits, defer)

    def band_end(self, role: str | None, band: str, live0: dict[str, Any], live1: dict[str, Any],
                 t: float) -> dict[str, Any]:
        """A measured band (or ramp step) has ended: what the relay `role`'s
        clients saw over its window (live0 to live1), and the service
        level's ack test on it. Under SLO_ACK_SHARE % of at least
        SLO_MIN_ACKS acks within SLO_ACK_MS is the relay breaking, at the
        band's end."""
        d = {k: live1[k] - live0[k] for k in ("sent", "accepted", "rejected", "rate_limited", "send_unanswered", "lost",
                                               "read_refused", "read_unanswered", "read_rate_limited")}
        le0, le1 = live0["ack_ms_le"], live1["ack_ms_le"]
        acks, within = le1["+Inf"] - le0["+Inf"], le1[SLO_ACK_MS] - le0[SLO_ACK_MS]
        out: dict[str, Any] = {**d, "acks": acks, f"acks_within_{SLO_ACK_MS}ms": within,
                               "joined": live1["joined"], "from_t_unix": live0["t_unix"], "to_t_unix": live1["t_unix"]}
        if acks:
            out[f"share_within_{SLO_ACK_MS}ms_pct"] = round(100.0 * within / acks, 3)
        if acks >= SLO_MIN_ACKS and within * 100.0 < SLO_ACK_SHARE * acks:
            self.relay_break(t, f"{band}: {within} of {acks} acks within {SLO_ACK_MS} ms "
                                f"({100.0 * within / acks:.1f}%), under {SLO_ACK_SHARE:g}%", role, band=band)
        elif acks < SLO_MIN_ACKS:
            out["ack_test"] = f"not judged: {acks} acks, fewer than {SLO_MIN_ACKS}"
        return out


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
    if not isinstance(v, dict) or "t_unix" not in v:
        return None, f"{path} has no t_unix"
    if type(v["t_unix"]) is not int or v["t_unix"] <= 0:
        return None, f"{path}: t_unix {json.dumps(v['t_unix'])} is not a whole number of seconds"
    if not isinstance(v.get("client_errors"), dict):
        return None, f"{path} has no client_errors"
    for k in LIVE_TOTALS:
        if k not in v:
            return None, f"{path} has no {k}"
    if "ended" in v and v["ended"] not in LIVE_ENDED:
        return None, f"{path}: ended {json.dumps(v['ended'])} is not one of {sorted(LIVE_ENDED)}"
    le = v.get("ack_ms_le")
    if not isinstance(le, dict) or sorted(le) != sorted(ACK_BOUNDS):
        return None, f"{path}: ack_ms_le is not the histogram with bounds {', '.join(ACK_BOUNDS)}"
    counts = list(v["client_errors"].values()) + [v[k] for k in LIVE_TOTALS] + list(le.values())
    if not all(type(c) is int and c >= 0 for c in counts):
        return None, f"{path} has a counter that is not a whole number"
    if any(le[a] > le[b] for a, b in zip(ACK_BOUNDS, ACK_BOUNDS[1:])):
        return None, f"{path}: ack_ms_le is not cumulative"
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

    def add(self, tier: str, sample: dict[str, Any] | None, partial: dict[str, Any] | None = None) -> None:
        """A call's sample, or None for a miss. A partial reply (a slow one
        that isn't whole) is a miss, but the reader still ran: its cost
        counts."""
        if tier == "slow":
            self.slow_calls += 1
        else:
            self.ticks += 1
        if sample is None:
            if tier == "slow":
                self.slow_missed += 1
            else:
                self.missed += 1
            if partial is not None:
                self.reader_cost(partial)
            return
        t = sample["t_unix"]
        self.t0 = t if self.t0 is None else self.t0
        self.t1 = t
        self.reader_cost(sample)
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

    def reader_cost(self, sample: dict[str, Any]) -> None:
        reader = sample.get("reader") or {}
        if _num(reader.get("cpu_s")):
            self.cpu_s += reader["cpu_s"]
        rss = [reader.get(k) for k in ("maxrss_kb", "children_maxrss_kb") if _num(reader.get(k))]
        if rss:
            self.maxrss = max([self.maxrss or 0, *rss])

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
    # Live files bound to the relays they drive, by role (--live).
    lives: list[tuple[str | None, str]] = field(default_factory=list)
    # How long into a ramp step its window starts (--step-settle).
    step_settle_s: float = STEP_SETTLE_S


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


def slow_gap(sample: dict[str, Any]) -> str | None:
    """Why a relay box's slow reply is not a whole slow sample, or None."""
    errors = [str(e) for e in sample.get("errors") or [] if str(e).startswith(SLOW_ERRORS)]
    if errors:
        return "the slow sample has errors: " + "; ".join(errors)
    for path in SLOW_NEEDS + (() if "containers_absent" in sample else SLOW_NEEDS_DOCKER):
        v: Any = sample
        for k in path.split("."):
            v = v.get(k) if isinstance(v, dict) else None
        if not _num(v):
            return f"the slow sample has no {path}"
    return None


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
    # tenant_sim's live files: each bound to the relay it drives, or one
    # bound to none (--live-file), which counts for every relay.
    lives: list[tuple[str | None, str]] = list(s.lives) or ([(None, s.live_file)] if s.live_file else [])
    relays = [b.role for b in s.boxes] + [r for r, _ in lives if r and r not in {b.role for b in s.boxes}]
    mon = Monitor(expected=s.expected, live_required=bool(lives), relays=relays)
    band = "none"
    stats = {r: BandStats(band, r) for r in roles}
    # A measured band's window, per live file: its live counters at the
    # window's start (a ramp step's starts after it settles), and the last
    # good read; band_end judges the service level on the two.
    band_t0 = clock()
    win0: dict[str | None, dict[str, Any]] = {}
    last_live: dict[str | None, dict[str, Any]] = {}
    clients: list[dict[str, Any]] = []
    broken_written: dict[str, Any] | None = None
    start = clock()
    next_slow = start
    # In-process, the reader's getrusage counts the whole loop since it
    # started (its ssh calls too: on this box they are the sampler's cost),
    # so each local sample is given the CPU used since the one before.
    cpu_mark = own_cpu_s()

    def quiet() -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)

    def measured(name: str) -> bool:
        return name in MEASURED_BANDS or RAMP_STEP.fullmatch(name) is not None

    def band_end(t: float) -> None:
        """The band that is ending: each live file's clients over its
        window, and the service level's ack test, before the summaries."""
        if not measured(band):
            return
        for role, _ in lives:
            if role in win0 and role in last_live:
                block = mon.band_end(role, band, win0[role], last_live[role], t)
                clients.append({"band": band, "role": role or "live", "client": block})

    def write_breaks() -> None:
        """Each relay that broke, and when, written whole as it changes:
        what a band driver reads to end that relay's ramp."""
        nonlocal broken_written
        now = {"relays": mon.broken(), "first_t_unix": mon.relay_break_t}
        if now != broken_written:
            tmp = folder / "breaks.json.tmp"
            tmp.write_text(json.dumps(now, indent=2) + "\n")
            tmp.replace(folder / "breaks.json")
            broken_written = now

    def flush() -> None:
        with open(folder / "bands.jsonl", "a") as fh:
            for r in roles:
                fh.write(json.dumps(stats[r].summary(), separators=(",", ":")) + "\n")
            for c in clients:
                fh.write(json.dumps(c, separators=(",", ":")) + "\n")
        clients.clear()
        with open(folder / "notes.jsonl", "a") as fh:
            for n in mon.notes:
                fh.write(json.dumps(n, separators=(",", ":")) + "\n")
        mon.notes.clear()

    def void(v: Void) -> int:
        quiet()
        band_end(v.t_unix)
        write_breaks()
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
                    band_end(t)
                    write_breaks()
                    flush()
                    band = mon.band = now_band
                    stats = {r: BandStats(band, r) for r in roles}
                    band_t0, win0 = t, {}
            tiers = ["fast"] + (["slow"] if t >= next_slow else [])
            if "slow" in tiers:
                next_slow = t + s.slow_every
            # Every limit this tick crosses waits for its end: a break signal
            # read later in the same tick (the live counters come after the
            # relay boxes) still counts as before the limit.
            limits: list[Limit] = []
            for box in s.boxes:
                for tier in tiers:
                    sample, miss = parse_reply(*runner(ssh_argv(s.key or "", s.known_hosts or "", box.ip, tier)), tier)
                    # A slow reply that isn't whole is a miss, kept in the
                    # ring beside its reason, never counted as a sample.
                    partial = sample if tier == "slow" and sample and (miss := slow_gap(sample)) else None
                    if partial:
                        sample = None
                    rings[box.role].append(json.dumps({"t": t, "band": band, "tier": tier, **({"sample": sample} if sample else {"miss": miss}),
                                                       **({"partial": partial} if partial else {})}, separators=(",", ":")))
                    stats[box.role].add(tier, sample, partial)
                    if tier == "fast":
                        mon.box_tick(box, t, sample, miss, limits)
                    else:
                        mon.slow_tick(box, t, miss, limits)
            read: dict[str | None, dict[str, Any]] = {}
            for role, path in lives:
                live, live_err = read_live(path)
                mon.live_tick(role, t, live, live_err, clock(), limits)
                if live is not None:
                    read[role] = last_live[role] = live
                    settle = s.step_settle_s if RAMP_STEP.fullmatch(band) else 0.0
                    if role not in win0 and measured(band) and t >= band_t0 + settle:
                        win0[role] = live
            if s.self_role and s.self_config is not None:
                for tier in tiers:
                    sample = local(tier, s.self_config)
                    now_cpu = own_cpu_s()
                    sample["reader"] = {**(sample.get("reader") or {}), "cpu_s": round(now_cpu - cpu_mark, 4), "cpu_s_since_start": round(now_cpu, 4)}
                    cpu_mark = now_cpu
                    seen = {}
                    if None in read:
                        seen["live"] = read[None]
                    if any(r is not None for r in read):
                        seen["lives"] = {r: v for r, v in read.items() if r is not None}
                    rings[s.self_role].append(json.dumps({"t": t, "band": band, "tier": tier, "sample": sample, **seen}, separators=(",", ":")))
                    stats[s.self_role].add(tier, sample)
                    if tier == "fast":
                        mon.gen_box_tick(t, sample, limits)
            v = mon.judge(limits)
            if v:
                return void(v)
            write_breaks()
            if s.once or (s.duration is not None and clock() - start >= s.duration):
                band_end(clock())
                write_breaks()
                flush()
                return EXIT_OK
            sleep(max(0.0, s.fast_every - (clock() - t)))
    except Stop as e:
        band_end(clock())
        write_breaks()
        flush()
        return e.code
    finally:
        for sig, h in old.items():
            signal.signal(sig, h)


def check_lives(specs: list[str], live_file: str | None) -> list[tuple[str | None, str]]:
    """Each --live is RELAY=PATH: a plain relay role (the box it names, or
    one with no box) and tenant_sim's live.json for the generator that
    drives it. Each relay once; not with --live-file, a file bound to none."""
    out: list[tuple[str | None, str]] = []
    for spec in specs:
        role, sep, path = spec.partition("=")
        if not sep or not role.isidentifier() or len(role) > 32 or not path:
            raise Refused(f"--live {spec!r} is not RELAY=PATH. Nothing was run.")
        out.append((role, path))
    if len({r for r, _ in out}) != len(out):
        raise Refused("two --live values name the same relay. Nothing was run.")
    if out and live_file:
        raise Refused("--live binds each live file to its relay; --live-file binds one to none: give one or the other. Nothing was run.")
    return out


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
    lives = check_lives(args.live, args.live_file)
    if not boxes and not args.self_role and not lives and not args.live_file:
        raise Refused("give at least one --box, --self or --live. Nothing was run.")
    self_cfg = None
    if args.self_role:
        try:
            self_cfg = box_sampler.load_config(Path(args.self_config).read_text()) if args.self_config else {}
        except (OSError, box_sampler.ConfigError) as e:
            raise Refused(f"--self-config {args.self_config}: {e}. Nothing was run.") from e
    fast, slow = (30.0, 300.0) if args.soak else (float(args.fast_every), float(args.slow_every))
    s = Settings(boxes, args.ssh_key, args.known_hosts, Path(args.out_dir), expected, args.self_role, self_cfg,
                 args.live_file, args.band_file, fast, slow, args.duration, args.once, args.ring_files, args.ring_bytes,
                 lives, args.step_settle)
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
    p.add_argument("--live-file", default=None, help="tenant_sim's <out-dir>/live.json, for every relay; missing or unreadable voids")
    p.add_argument("--step-settle", type=float, default=STEP_SETTLE_S,
                   help="seconds into a ramp step before its window starts (its joiners connect first)")
    p.add_argument("--live", action="append", default=[],
                   help="RELAY=PATH: the live.json of the tenant_sim that drives that relay (repeatable)")
    p.add_argument("--band-file", default=None, help="a file holding the current band's name")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--fast-every", type=float, default=5.0)
    p.add_argument("--slow-every", type=float, default=60.0)
    p.add_argument("--soak", action="store_true", help="fast every 30 s, slow every 300 s")
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--once", action="store_true")
    p.add_argument("--ring-files", type=int, default=8)
    p.add_argument("--ring-bytes", type=int, default=4 << 20)
