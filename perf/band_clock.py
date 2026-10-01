#!/usr/bin/env python3
"""The band clock: one clock driving every tenant_sim of a run, through one
hook command.

The clock owns the schedule: each profile's bands in turn, then a ramp. It
keeps the generators in lockstep (a barrier after setup), pauses them at
each measured band's end for a boundary check, reads the sampler's status
as it goes, and stops the run on a void, a failed hook, or a signal. It
never computes "the relay broke" itself: the sampler loop does, once, per
relay, and the clock reads it from `status`.

Everything it does to the world goes through the hook: the hook is a
command, run with an event and its arguments appended, and nothing else.
The clock knows nothing about where the relays or generators run.

| Event | Arguments | The hook... |
|---|---|---|
| `setup` | item | readies every relay for the item (a profile's name, or `ramp`): a fresh stack, at the raised setup limits |
| `gen-start` | gen, item | starts that generator for the item, its band signal on a fifo |
| `phases` | gen | prints that generator's phase lines (JSON, one a line) |
| `fleet` | | restarts every relay at its fleet limits and checks none is raised |
| `send` | gen, line | sends one band-signal line to that generator |
| `sampler` | `start` or `stop` | starts or stops the sampler loop |
| `band` | name | tells the sampler the band's name |
| `boundary` | band | checks the run at a band's end (for example, an egress proof) |
| `rules` | | checks the run's isolation (every minute, and at each boundary) |
| `status` | | prints JSON: `void`, `breaks`, `sampler`, `gens` |
| `end` | | the run is over: stops whatever still runs. Always called |

A hook that exits nonzero stops the run (exit 4), except `end`, which is
reported. Exits: 0 done; 2 refused; 3 void; 4 a hook failed; 5 setup failed
(a generator's setup failed, or setup or ready timed out); 6 setup was
rate-limited with --setup-must-not-rate-limit; 130 and 143 on INT and TERM.

This file is stdlib only, so a wrapper can pin it by its sha256.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

EXIT_OK, EXIT_REFUSED, EXIT_VOID, EXIT_HOOK, EXIT_SETUP, EXIT_RATE_LIMITED = 0, 2, 3, 4, 5, 6
# The bands a profile runs, in order; the measured ones end at a boundary.
BANDS = ("warmup", "floor", "steady", "peak", "cooldown")
MEASURED = ("floor", "steady", "peak")
HOOK_TIMEOUT_S = 1800
# The most of a hook's output the clock reads; past it the hook fails.
HOOK_MAX_BYTES = 16 << 20


class Stop(Exception):
    """The run stops: its exit code and the one line that says why."""

    def __init__(self, code: int, line: str) -> None:
        super().__init__(line)
        self.code, self.line = code, line


@dataclass
class Ramp:
    start: int
    step: int
    every_s: float
    max: int
    budget_s: float


@dataclass
class Item:
    name: str
    bands: list[tuple[str, float]]
    ramp: Ramp | None = None


@dataclass
class Options:
    cadence_s: float = 5.0
    rules_every_s: float = 60.0
    lease_slack_s: float = 120.0
    pause_lease_s: float = 900.0
    setup_timeout_s: float = 3600.0
    ready_timeout_s: float = 300.0
    stop_timeout_s: float = 300.0
    setup_must_not_rate_limit: bool = False


Hook = Callable[[list[str]], tuple[int, str, str]]


def run_hook(argv: list[str]) -> Hook:
    """The real hook: `argv` with the event appended, no shell, bounded."""

    def call(event: list[str]) -> tuple[int, str, str]:
        try:
            p = subprocess.run([*argv, *event], capture_output=True, timeout=HOOK_TIMEOUT_S, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {HOOK_TIMEOUT_S} s"
        except OSError as e:
            return 127, "", str(e)
        if len(p.stdout) > HOOK_MAX_BYTES:
            return 125, "", f"printed over {HOOK_MAX_BYTES} bytes"
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    return call


def last_line(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return lines[-1] if lines else ""


def load_item(path: str, ramp: Ramp | None = None) -> Item:
    """A profile's name and band lengths, from its TOML."""
    try:
        raw = tomllib.loads(Path(path).read_text())
        name = raw["profile"]["name"]
        bands = [(b, float(raw["bands"][b])) for b in BANDS]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError, ValueError) as e:
        raise Stop(EXIT_REFUSED, f"refused: profile {path}: {e!r}") from e
    if not isinstance(name, str) or not name or any(s < 0 for _, s in bands):
        raise Stop(EXIT_REFUSED, f"refused: profile {path}: no name, or a band shorter than 0 s")
    if ramp is not None:
        return Item("ramp", [b for b in bands if b[0] == "warmup"], ramp)
    return Item(name, bands)


@dataclass
class Clock:
    hook: Hook
    gens: list[str]
    items: list[Item]
    out: Path
    opts: Options = field(default_factory=Options)
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    log: Callable[[str], None] = lambda line: print(f"clock: {line}", flush=True)
    result: dict[str, Any] = field(default_factory=dict)
    _running: set[str] = field(default_factory=set)
    _sampler_on: bool = False
    _next_rules: float = 0.0

    # ---- the hook ----

    def call(self, *event: str) -> str:
        """Runs one event; a nonzero exit stops the run."""
        code, out, err = self.hook(list(event))
        if code != 0:
            why = last_line(err) or last_line(out)
            raise Stop(EXIT_HOOK, f"the hook failed at {' '.join(event)}: exit {code}" + (f": {why}" if why else ""))
        return out

    def send(self, gen: str, line: str) -> None:
        self.call("send", gen, line)

    def phases(self, gen: str) -> list[dict[str, Any]]:
        out = []
        for raw in self.call("phases", gen).splitlines():
            if raw.strip():
                try:
                    v = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise Stop(EXIT_HOOK, f"the hook's phases for {gen} are not JSON lines: {raw[:80]!r}") from e
                if isinstance(v, dict):
                    out.append(v)
        return out

    # ---- watching the run ----

    def status(self) -> dict[str, Any]:
        """The sampler's status. A void, a sampler that stopped on its own,
        or a generator that ended when it shouldn't have, stops the run."""
        try:
            st = json.loads(self.call("status"))
        except json.JSONDecodeError as e:
            raise Stop(EXIT_HOOK, f"the hook's status is not JSON: {e}") from e
        if not isinstance(st, dict):
            raise Stop(EXIT_HOOK, "the hook's status is not a JSON object")
        void = st.get("void")
        if void:
            raise Stop(EXIT_VOID, f"void: {void.get('reason') if isinstance(void, dict) else void}")
        if self._sampler_on and st.get("sampler") != "active":
            raise Stop(EXIT_VOID, f"the sampler stopped on its own: {st.get('sampler')}")
        gens = st.get("gens") or {}
        for g in sorted(self._running):
            if gens.get(g) != "active":
                raise Stop(EXIT_VOID, f"the generator for {g} stopped on its own: {gens.get(g)}")
        return st

    def breaks(self, st: dict[str, Any]) -> dict[str, dict[str, Any]]:
        b = st.get("breaks") or {}
        relays = b.get("relays") if isinstance(b, dict) else None
        return relays if isinstance(relays, dict) else {}

    def tick(self) -> dict[str, Any]:
        """One poll: the status, and the rules every rules_every_s."""
        st = self.status()
        if self.clock() >= self._next_rules:
            self.call("rules")
            self._next_rules = self.clock() + self.opts.rules_every_s
        return st

    def hold(self, seconds: float, each: Callable[[dict[str, Any]], None] | None = None) -> None:
        """Waits `seconds`, polling every cadence."""
        end = self.clock() + seconds
        while True:
            st = self.tick()
            if each:
                each(st)
            left = end - self.clock()
            if left <= 0:
                return
            self.sleep(min(self.opts.cadence_s, left))

    def wait_phase(self, want: str, timeout_s: float) -> dict[str, dict[str, Any]]:
        """Every running generator's `want` phase line (a barrier). A
        `setup-failed` line, or the timeout, stops the run."""
        got: dict[str, dict[str, Any]] = {}
        end = self.clock() + timeout_s
        while True:
            for g in sorted(self._running - set(got)):
                for p in self.phases(g):
                    if p.get("phase") == "setup-failed":
                        raise Stop(EXIT_SETUP, f"setup failed for {g}: {p.get('why')}")
                    if p.get("phase") == want:
                        got[g] = p
                        break
            if set(got) == self._running:
                return got
            if self.clock() >= end:
                missing = ", ".join(sorted(self._running - set(got)))
                raise Stop(EXIT_SETUP, f"no {want} from {missing} within {timeout_s:g} s")
            self.sleep(min(self.opts.cadence_s, max(0.0, end - self.clock())))

    # ---- the schedule ----

    def lease(self, seconds: float) -> int:
        return max(1, math.ceil(seconds + self.opts.lease_slack_s))

    def band(self, name: str, seconds: float, gens: list[str] | None = None, signal_name: str | None = None) -> None:
        """Every generator (or those given) into a band, the sampler told,
        then the band held."""
        for g in sorted(gens if gens is not None else self._running):
            self.send(g, f"band {signal_name or name} {self.lease(seconds)}")
        self.call("band", name)
        self.log(f"band {name} for {seconds:g} s")
        self.hold(seconds)

    def boundary(self, name: str) -> None:
        """A measured band has ended: the generators pause, the rules and
        the boundary check run, each stopping the run if it fails."""
        for g in sorted(self._running):
            self.send(g, f"band pause {math.ceil(self.opts.pause_lease_s)}")
        self.call("band", "pause")
        self.tick()
        self.call("rules")
        self._next_rules = self.clock() + self.opts.rules_every_s
        self.call("boundary", name)
        self.log(f"boundary {name}: passed")

    def setup(self, item: Item) -> dict[str, Any]:
        """The item's setup, in lockstep: the relays readied, every
        generator started and set up, the relays at fleet limits, then
        every generator connected."""
        self.log(f"setup {item.name}")
        self.call("setup", item.name)
        for g in self.gens:
            self.call("gen-start", g, item.name)
            self._running.add(g)
        done = self.wait_phase("setup-done", self.opts.setup_timeout_s)
        provision = {g: (p.get("provision") or {}) for g, p in done.items()}
        if self.opts.setup_must_not_rate_limit:
            for g, p in sorted(provision.items()):
                n = p.get("rate_limited")
                if n != 0:
                    raise Stop(EXIT_RATE_LIMITED,
                               f"setup for {g} was rate-limited {n} times; the setup limits are raised, so its setup is wrong")
        self.call("fleet")
        for g in sorted(self._running):
            self.send(g, f"continue {self.lease(self.opts.ready_timeout_s)}")
        self.wait_phase("ready", self.opts.ready_timeout_s)
        self.call("sampler", "start")
        self._sampler_on = True
        return provision

    def stop_gens(self, gens: list[str]) -> None:
        """Stops the generators given and waits for them to end."""
        for g in sorted(gens):
            self.send(g, "stop")
            self._running.discard(g)
        end = self.clock() + self.opts.stop_timeout_s
        while True:
            st = self.status()
            states = st.get("gens") or {}
            left = [g for g in gens if states.get(g) == "active"]
            if not left:
                return
            if self.clock() >= end:
                raise Stop(EXIT_HOOK, f"the generators {', '.join(sorted(left))} were still running {self.opts.stop_timeout_s:g} s after stop")
            self.sleep(min(self.opts.cadence_s, max(0.0, end - self.clock())))

    def run_profile(self, item: Item, rec: dict[str, Any]) -> None:
        for name, seconds in item.bands:
            self.band(name, seconds)
            if name in MEASURED:
                self.boundary(name)
        rec["bands_done"] = [b for b, _ in item.bands]

    def run_ramp(self, item: Item, rec: dict[str, Any]) -> None:
        """The ramp: after the warmup, steady-band rates with `ramp <k>`
        steps every every_s. A generator whose relay broke stops; the ramp
        ends when every relay broke, at the max, past its budget, or on a
        void. Each relay's result: the last step that held, and the first
        that broke, with its reason, from the sampler's breaks."""
        ramp = item.ramp
        assert ramp is not None
        for name, seconds in item.bands:
            self.band(name, seconds)
        steps: list[dict[str, Any]] = []
        res: dict[str, dict[str, Any]] = {g: {"held_k": None} for g in self.gens}
        started = self.clock()
        k, n = ramp.start, 1
        for g in sorted(self._running):
            self.send(g, f"band steady {self.lease(ramp.every_s)}")
        while True:
            band = f"ramp-{n:03d}"
            live = sorted(self._running)
            for g in live:
                self.send(g, f"ramp {k} {self.lease(ramp.every_s)}")
            self.call("band", band)
            steps.append({"step": n, "band": band, "k": k, "t_unix": self.clock(), "gens": live})
            self.log(f"{band}: {k} identities on {', '.join(live)}")
            self.hold(ramp.every_s)
            if k >= ramp.max or self.clock() - started >= ramp.budget_s:
                break
            # A step's ack test is judged at its end, as the next begins:
            # the breaks read now cover every step before this one.
            self.settle_breaks(steps, res)
            if not self._running:
                break
            k, n = min(k + ramp.step, ramp.max), n + 1
        # The last step is judged when the band changes: pause, read once
        # more, then the boundary.
        for g in sorted(self._running):
            self.send(g, f"band pause {math.ceil(self.opts.pause_lease_s)}")
        self.call("band", "pause")
        self.sleep(self.opts.cadence_s)
        self.settle_breaks(steps, res)
        for g, r in res.items():
            if "broke_k" not in r:
                last = steps[-1] if steps else None
                r["held_k"] = last["k"] if last else None
                r["ended"] = "held at the max" if last and last["k"] >= ramp.max else "the ramp's time ran out"
        rec["ramp"] = {"steps": steps, "relays": res}
        self.call("rules")
        self.call("boundary", "ramp")
        self.log("boundary ramp: passed")

    def settle_breaks(self, steps: list[dict[str, Any]], res: dict[str, dict[str, Any]]) -> None:
        """Records each relay that broke since the last look, on the step
        its break names (or the step it came in), and stops its generator."""
        st = self.tick()
        broke = []
        for g, info in sorted(self.breaks(st).items()):
            if g not in res or "broke_k" in res[g]:
                continue
            at = next((s for s in steps if s["band"] == info.get("band")), None)
            if at is None:
                t = info.get("t_unix") or 0
                at = next((s for s in reversed(steps) if s["t_unix"] <= t), steps[0] if steps else None)
            if at is None:
                continue
            before = [s for s in steps if s["step"] < at["step"]]
            res[g].update({"held_k": before[-1]["k"] if before else None, "broke_k": at["k"], "broke_step": at["step"],
                           "broke_t_unix": info.get("t_unix"), "why": info.get("why"), "band": info.get("band")})
            self.log(f"{g} broke at {at['band']} ({at['k']} identities): {info.get('why')}")
            if g in self._running:
                broke.append(g)
        if broke:
            self.stop_gens(broke)

    def write_result(self) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        tmp = self.out / "clock.json.tmp"
        tmp.write_text(json.dumps(self.result, indent=2) + "\n")
        tmp.replace(self.out / "clock.json")

    def run(self) -> int:
        self.result = {"gens": self.gens, "items": [], "exit": None, "stopped": None}
        code = EXIT_OK
        try:
            for item in self.items:
                rec: dict[str, Any] = {"name": item.name, "started_t_unix": self.clock()}
                self.result["items"].append(rec)
                rec["provision"] = self.setup(item)
                if item.ramp:
                    self.run_ramp(item, rec)
                else:
                    self.run_profile(item, rec)
                self.stop_gens(sorted(self._running))
                self.call("sampler", "stop")
                self._sampler_on = False
                rec["ended_t_unix"] = self.clock()
                self.write_result()
        except Stop as s:
            code = s.code
            self.result["stopped"] = s.line
            self.log(f"stopped: {s.line}")
        finally:
            self.result["exit"] = code
            # The end step always runs, whatever stopped the run.
            ecode, eout, eerr = self.hook(["end"])
            if ecode != 0:
                line = f"the hook failed at end: exit {ecode}: {last_line(eerr) or last_line(eout)}"
                self.result["end"] = line
                self.log(line)
                if code == EXIT_OK:
                    code = self.result["exit"] = EXIT_HOOK
            self.write_result()
        self.log(f"exit {code}")
        return code


def parse(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    if "--" not in argv:
        raise Stop(EXIT_REFUSED, "refused: give the hook command after --")
    i = argv.index("--")
    own, hook = argv[:i], argv[i + 1:]
    if not hook:
        raise Stop(EXIT_REFUSED, "refused: the hook command after -- is empty")
    p = argparse.ArgumentParser(prog="band_clock.py", description="drive every tenant_sim of a run through one hook")
    p.add_argument("--gen", action="append", default=[], help="a generator's name (repeatable)")
    p.add_argument("--profile", action="append", default=[], help="a profile's TOML, run in order (repeatable)")
    p.add_argument("--ramp", default=None, help="the ramp's profile TOML, run after the profiles")
    p.add_argument("--ramp-start", type=int, default=30)
    p.add_argument("--ramp-step", type=int, default=15)
    p.add_argument("--ramp-every", type=float, default=300.0)
    p.add_argument("--ramp-max", type=int, default=660)
    p.add_argument("--ramp-budget", type=float, default=4 * 3600.0, help="seconds")
    p.add_argument("--out", required=True)
    p.add_argument("--cadence", type=float, default=5.0)
    p.add_argument("--rules-every", type=float, default=60.0)
    p.add_argument("--lease-slack", type=float, default=120.0)
    p.add_argument("--pause-lease", type=float, default=900.0)
    p.add_argument("--setup-timeout", type=float, default=3600.0)
    p.add_argument("--ready-timeout", type=float, default=300.0)
    p.add_argument("--stop-timeout", type=float, default=300.0)
    p.add_argument("--setup-must-not-rate-limit", action="store_true",
                   help="refuse a setup that met any rate limit: for a relay whose setup limits are raised")
    try:
        args = p.parse_args(own)
    except SystemExit as e:
        raise Stop(EXIT_REFUSED, "refused: bad arguments") from e
    return args, hook


def build(args: argparse.Namespace) -> tuple[list[str], list[Item], Options]:
    gens = args.gen
    if not gens or len(set(gens)) != len(gens) or not all(g.isidentifier() or g.replace("-", "_").isidentifier() for g in gens):
        raise Stop(EXIT_REFUSED, "refused: give each --gen once, a plain name")
    items = [load_item(p) for p in args.profile]
    if args.ramp:
        r = Ramp(args.ramp_start, args.ramp_step, args.ramp_every, args.ramp_max, args.ramp_budget)
        if not (0 < r.start <= r.max and r.step > 0 and r.every_s > 0 and r.budget_s > 0):
            raise Stop(EXIT_REFUSED, "refused: the ramp needs 0 < start <= max, a step, a period and a budget above 0")
        items.append(load_item(args.ramp, r))
    if not items:
        raise Stop(EXIT_REFUSED, "refused: give at least one --profile or --ramp")
    names = [i.name for i in items]
    if len(set(names)) != len(names):
        raise Stop(EXIT_REFUSED, f"refused: two items share a name: {names}")
    opts = Options(args.cadence, args.rules_every, args.lease_slack, args.pause_lease, args.setup_timeout,
                   args.ready_timeout, args.stop_timeout, args.setup_must_not_rate_limit)
    if min(opts.cadence_s, opts.rules_every_s, opts.setup_timeout_s, opts.ready_timeout_s, opts.stop_timeout_s) <= 0:
        raise Stop(EXIT_REFUSED, "refused: every period and timeout must be above 0")
    return gens, items, opts


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        args, hook = parse(argv)
        gens, items, opts = build(args)
    except Stop as s:
        print(s.line, file=sys.stderr)
        return s.code
    c = Clock(run_hook(hook), gens, items, Path(args.out), opts)

    def on_signal(signum: int, frame: Any) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)  # a second signal must not cut the end step short
        raise Stop(130 if signum == signal.SIGINT else 143, f"stopped by {signal.Signals(signum).name}")

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, on_signal)
    return c.run()


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())
