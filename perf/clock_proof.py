#!/usr/bin/env python3
"""The band clock's local proof: the clock (band_clock.py) driving
tenant_sim against relay stacks on this machine, through
clock_proof_hook.py. Run it with perf/clock-proof.sh, which builds the
binaries first.

Each row runs the real clock, the real tenant_sim, the real sampler loop
and real relays, and checks what they did: each check prints PASS or FAIL,
and the proof exits 1 if any failed.

| Row | What it forces | What must happen |
|---|---|---|
| `reads` | nothing: two generators through every band of a short profile | exit 0; both driven in lockstep; agents' reads and humans' home-feed polls all answered, none refused (the hard row) |
| `ramp` | relay b at 0.03 CPU from `fleet` on | exit 0; the ramp's load reaches b's limit and breaks it after at least one step held, by a named relay-break class (the ack test, rejects or any of the loop's relay failure totals, read from `remote_sampler.py`), printed; a held to the max |
| `ramp-freeze` | relay b frozen (`docker pause`) at the ramp's second step | exit 0; b broke at step 2 because its sends went unanswered, a break and never a void; a held to the max |
| `ramp-starved` | relay b cut to 0.01 CPU at the ramp's second step | exit 0; b broke at step 2 because it shed sends (`rate-limited: too many concurrent requests` or `shared admission unavailable`), a break and never counted apart; a held to the max; the texts b got, counted |
| `boundary` | the floor's boundary check fails | exit 4 on that line; `end` still ran and removed both stacks |
| `void` | generator a stopped (SIGSTOP) in the steady band | the loop voids on its stale live file; exit 3 on that line; `end` ran |
| `crash-gen` | generator b killed (SIGKILL) in the steady band | exit 3: the generator for b stopped on its own; `end` ran |
| `crash-clock` | the clock killed (SIGKILL) in the steady band | each generator's lease runs out (exit 5, `ended: lease`), the loop voids; nothing ran `end` until the proof did |
| `heavy-seed` | one generator, the heavy profile's 90-day seed at raised limits, with mentions | the seed's time, every event acknowledged; the never-mentioned tail (4 humans, 10 agents); its humans' poll times apart from the mentioned ones' |

Every image must already be on this machine by its exact reference: the
proof checks each first and stops if one is missing; Compose runs with
`--pull never`. Docker names are `<prefix>-a` and `<prefix>-b` only, and
the proof stops if either project has anything in it before it starts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

import remote_sampler

PERF = Path(__file__).resolve().parent
REPO = PERF.parent
PROOF = PERF / "clock-proof"
IMAGES = (
    "ghcr.io/block/buzz:sha-6e5c462",
    "postgres:17-alpine",
    "redis:7-alpine",
    "minio/minio:RELEASE.2025-09-07T16-13-09Z",
    "minio/mc:RELEASE.2025-08-13T08-35-41Z",
)
BANDS = ["warmup", "floor", "steady", "peak", "cooldown"]
ROWS = ("reads", "ramp", "ramp-freeze", "ramp-starved", "boundary", "void", "crash-gen", "crash-clock", "heavy-seed")
HEAVY_SEED_EVENTS = 757_803
GENS = {"a": {"port": 13031, "health_port": 18031}, "b": {"port": 13032, "health_port": 18032}}
# The clock's own periods, short where a row would otherwise wait long.
CLOCK_FLAGS = ["--cadence", "2", "--lease-slack", "15", "--pause-lease", "120", "--setup-timeout", "900",
               "--ready-timeout", "180", "--stop-timeout", "120", "--setup-must-not-rate-limit"]


class Proof:
    def __init__(self, out: Path, prefix: str, python: str, docker: str, tenant_sim: str) -> None:
        self.out, self.prefix, self.python, self.docker, self.tenant_sim = out, prefix, python, docker, tenant_sim
        self.results: list[tuple[str, str, bool, str]] = []

    # ---- checks ----

    def check(self, row: str, what: str, ok: bool, detail: Any = "") -> bool:
        self.results.append((row, what, bool(ok), str(detail)))
        print(f"{'PASS' if ok else 'FAIL'} {row}: {what}" + (f" ({detail})" if detail != "" else ""), flush=True)
        return bool(ok)

    def eq(self, row: str, what: str, got: Any, want: Any) -> bool:
        return self.check(row, what, got == want, f"got {got!r}" + ("" if got == want else f", want {want!r}"))

    # ---- the machine ----

    def run(self, *argv: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)

    def leftovers(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for gen in GENS:
            label = f"label=com.docker.compose.project={self.prefix}-{gen}"
            for kind, args in (("containers", ("ps", "-a", "-q", "--filter", label)),
                               ("volumes", ("volume", "ls", "-q", "--filter", label)),
                               ("networks", ("network", "ls", "-q", "--filter", label))):
                ids = self.run(self.docker, *args).stdout.split()
                if ids:
                    out[f"{self.prefix}-{gen} {kind}"] = ids
        return out

    def preflight(self) -> bool:
        print(f"python: {sys.executable} {platform.python_version()}")
        print(f"docker: {self.docker}; machine: {platform.machine()} {platform.system()} {platform.release()}")
        ok = True
        for ref in IMAGES:
            p = self.run(self.docker, "image", "inspect", "--format", "{{.Id}} {{.Architecture}}", ref)
            ok &= self.check("preflight", f"image {ref} is on this machine", p.returncode == 0,
                             p.stdout.strip() or (p.stderr.strip().splitlines() or ["missing"])[-1])
        if not ok:
            print("stop: an image is missing. The proof never pulls one; get it there first.", file=sys.stderr)
            return False
        for b in (self.tenant_sim, str(REPO / "target/release/git-credential-nostr")):
            ok &= self.check("preflight", f"{b} is built", os.access(b, os.X_OK))
        sums = dict(reversed(l.split()) for l in (PROOF / "profiles" / "SHA256SUMS").read_text().splitlines())
        for name, want in sorted(sums.items()):
            got = hashlib.sha256((PROOF / "profiles" / name).read_bytes()).hexdigest()
            ok &= self.eq("preflight", f"profile {name} is the pinned one", got, want)
        left = self.leftovers()
        ok &= self.check("preflight", f"{self.prefix}-a and {self.prefix}-b are empty", not left, left or "")
        return ok

    # ---- a row ----

    def config(self, row: str, gens: list[str], **kw: Any) -> tuple[Path, Path]:
        root = self.out / row
        if root.exists():
            shutil.rmtree(root)
        (root / "state").mkdir(parents=True)
        (root / "deny").write_text("")
        profiles = {"proof-solo": PROOF / "profiles/proof-solo.toml", "proof-heavy": PROOF / "profiles/proof-heavy.toml",
                    "ramp": PROOF / "profiles/proof-ramp.toml"}
        cfg = {"root": str(root), "prefix": self.prefix, "compose": str(PROOF / "compose.yml"),
               "tenant_sim": self.tenant_sim, "helper": str(REPO / "target/release/git-credential-nostr"),
               "tenant_cogs": str(PERF / "tenant_cogs.py"), "python": self.python, "docker": self.docker,
               "deny_list": str(root / "deny"), "gens": {g: GENS[g] for g in gens},
               "profiles": {k: str(v) for k, v in profiles.items()},
               "sampler": {"step_settle": 10, "fast_every": 2}, **kw}
        path = root / "config.json"
        path.write_text(json.dumps(cfg, indent=2) + "\n")
        return root, path

    def hook(self, cfg: Path) -> list[str]:
        return [self.python, str(PERF / "clock_proof_hook.py"), "--config", str(cfg)]

    def clock_argv(self, root: Path, cfg: Path, gens: list[str], items: list[str]) -> list[str]:
        argv = [self.python, str(PERF / "tenant_cogs.py"), "clock", "--out", str(root / "clock"), *CLOCK_FLAGS]
        for g in gens:
            argv += ["--gen", g]
        return [*argv, *items, "--", *self.hook(cfg)]

    def start_clock(self, root: Path, argv: list[str]) -> subprocess.Popen[bytes]:
        so = (root / "clock.out").open("wb")
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=so, stderr=subprocess.STDOUT)

    def run_clock(self, root: Path, argv: list[str], timeout_s: float) -> int:
        t0 = time.time()
        p = self.start_clock(root, argv)
        try:
            code = p.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            p.send_signal(signal.SIGTERM)
            code = p.wait(timeout=300)
        print(f"  clock exit {code} after {time.time() - t0:.0f} s; its last lines:")
        for line in (root / "clock.out").read_text().splitlines()[-4:]:
            print(f"    {line}")
        return code

    def end(self, row: str, cfg: Path, must_have_run: bool = True) -> None:
        """The hook's `end` once more (it is safe to run twice), then nothing
        may be left."""
        log = hook_log(cfg.parent)
        if must_have_run:
            ends = [r for r in log if r.get("event") == ["end"]]
            self.check(row, "the clock ran end", bool(ends) and ends[-1]["exit"] == 0, ends[-1:] or "never")
        p = self.run(*self.hook(cfg), "end", timeout=600)
        left = self.leftovers()
        self.check(row, "nothing is left of either stack", p.returncode == 0 and not left,
                   left or (p.stderr.strip() if p.returncode else ""))

    # ---- the rows ----

    def row_reads(self) -> None:
        row = "reads"
        root, cfg = self.config(row, ["a", "b"])
        code = self.run_clock(root, self.clock_argv(root, cfg, ["a", "b"], ["--profile", str(PROOF / "profiles/proof-solo.toml")]), 900)
        clock = read_json(root / "clock" / "clock.json")
        self.eq(row, "the clock exits 0", code, 0)
        self.eq(row, "clock.json says exit 0, nothing stopped it", (clock.get("exit"), clock.get("stopped")), (0, None))
        item = (clock.get("items") or [{}])[0]
        self.eq(row, "every band ran", item.get("bands_done"), BANDS)
        log = hook_log(root)
        for g in ("a", "b"):
            sends = [r["event"][2].split()[1] for r in log if r.get("event", [None])[:2] == ["send", g] and r["event"][2].startswith("band ")]
            self.eq(row, f"{g} was sent every band in order, with a pause after each measured one", sends,
                    ["warmup", "floor", "pause", "steady", "pause", "peak", "pause", "cooldown"])
        self.check(row, "fleet recreated both relays and read back no raised limit",
                   any(r.get("event") == ["fleet"] and r["exit"] == 0 for r in log))
        self.rules_cadence(row, log)
        out = root / "items" / "proof-solo"
        for g in ("a", "b"):
            self.eq(row, f"{g}'s tenant_sim exited 0", read_text(out / g / "exit"), "0")
            live = read_json(out / g / "live.json")
            self.eq(row, f"{g}'s last live.json ended on a stop", live.get("ended"), "stop")
            prov = phase(out / g, "setup-done").get("provision") or {}
            self.eq(row, f"{g}'s setup met no rate limit", prov.get("rate_limited"), 0)
            self.check(row, f"{g} sent in the steady band", ((read_json(out / g / "summary.json").get("bands") or {}).get("steady") or {}).get("sent", 0) > 0)
            # The hard row: NIP-98 reads against a running relay.
            reads = read_json(out / g / "summary.json").get("reads") or {}
            fails = {k: live.get(k) for k in ("read_refused", "read_unanswered", "read_client_failed")}
            ok = self.check(row, f"HARD: {g}'s agents' reads were answered", reads.get("reads", 0) > 0 and reads.get("failed") == 0,
                            f"reads {reads.get('reads')}, failed {reads.get('failed')}")
            ok &= self.eq(row, f"HARD: {g}'s relay refused or dropped no read", fails,
                          {"read_refused": 0, "read_unanswered": 0, "read_client_failed": 0})
            self.eq(row, f"{g}'s tenant_sim ran under the units' open-file limit",
                    read_text(out / g / "nofile"), "16384")
            # The humans' home-feed polls go through the same read counters:
            # those were none refused, none unanswered, and they ran.
            ok &= self.check(row, f"HARD: {g}'s humans polled their home feed", (live.get("polls") or 0) > 0,
                             f"polls {live.get('polls')}")
            steady = ((read_json(out / g / "summary.json").get("bands") or {}).get("steady") or {})
            print(f"  {g}: polls {live.get('polls')}, steady polls {steady.get('polls')} "
                  f"taking {json.dumps(steady.get('poll_ms'))} ms")
            print(f"  {g}: read_rate_limited {live.get('read_rate_limited')} (counted apart), "
                  f"turns {(read_json(out / g / 'summary.json').get('sent_by_kind') or {}).get('44200')}")
            if not ok and item.get("bands_done") == BANDS:
                print("  THE HARD READS ROW FAILED: stop here and tell the lead.", flush=True)
            elif not ok:
                print("  the hard reads row was not reached: the run stopped before its bands ended.", flush=True)
        samples = out / "sampler" / "samples"
        self.check(row, "the loop did not void", not (samples / "void.json").exists(), read_text(samples / "void.json"))
        self.eq(row, "no relay broke", (read_json(samples / "breaks.json") or {}).get("relays") or {}, {})
        self.end(row, cfg)

    def ramp_result(self, row: str, root: Path, code: int) -> tuple[dict[str, Any], dict[str, Any]]:
        clock = read_json(root / "clock" / "clock.json")
        self.eq(row, "the clock exits 0: a break is a result, not a void", code, 0)
        self.eq(row, "nothing stopped the clock", clock.get("stopped"), None)
        ramp = ((clock.get("items") or [{}])[0].get("ramp") or {})
        relays = ramp.get("relays") or {}
        print(f"  steps: {[(s['band'], s['k'], s['gens']) for s in ramp.get('steps', [])]}")
        print(f"  relays: {json.dumps(relays)}")
        samples = root / "items" / "ramp" / "sampler" / "samples"
        self.check(row, "the loop did not void", not (samples / "void.json").exists(), read_text(samples / "void.json"))
        return relays.get("a") or {}, relays.get("b") or {}

    def row_ramp(self) -> None:
        """Relay b runs at 0.03 CPU from fleet on: the ramp's rising load
        reaches its limit and breaks it after at least one held step, by one
        of the loop's named relay-break classes (the ack test, rejects or a
        relay failure total: BREAK_CLASSES), whichever comes first."""
        row = "ramp"
        root, cfg = self.config(row, ["a", "b"], ramp={"max": 30, "start": 6}, fleet_cpus={"b": "0.03"})
        argv = self.clock_argv(root, cfg, ["a", "b"], ["--ramp", str(PROOF / "profiles/proof-ramp.toml"), "--ramp-start", "6",
                                                        "--ramp-step", "6", "--ramp-every", "60", "--ramp-max", "30",
                                                        "--ramp-budget", "900"])
        a, b = self.ramp_result(row, root, self.run_clock(root, argv, 1500))
        cls = break_class(b.get("why"))
        self.check(row, "b broke by a named relay-break class", cls is not None, b.get("why"))
        print(f"  b broke by: {cls} ({b.get('why')})")
        k = b.get("broke_k")
        self.check(row, "b broke after holding at least one step, before the max",
                   k in (12, 18, 24, 30) and b.get("held_k") == k - 6 and b.get("band") == f"ramp-{k // 6:03d}",
                   f"held {b.get('held_k')}, broke {k} at {b.get('band')}")
        self.eq(row, "a held to the max", (a.get("held_k"), a.get("ended"), "broke_k" in a), (30, "held at the max", False))
        self.end(row, cfg)

    def row_ramp_freeze(self) -> None:
        """Relay b frozen at the ramp's second step: its sends were written
        and never answered. That is the relay's break, never the
        generator's error, so the run goes on."""
        row = "ramp-freeze"
        root, cfg = self.config(row, ["a", "b"], ramp={"max": 18, "start": 6},
                                inject={"at_band": [{"band": "ramp-002", "do": "pause", "gen": "b"}]})
        argv = self.clock_argv(root, cfg, ["a", "b"], ["--ramp", str(PROOF / "profiles/proof-ramp.toml"), "--ramp-start", "6",
                                                        "--ramp-step", "6", "--ramp-every", "75", "--ramp-max", "18",
                                                        "--ramp-budget", "900"])
        a, b = self.ramp_result(row, root, self.run_clock(root, argv, 1500))
        self.eq(row, "b broke at the second step, 12 identities, and held 6",
                (b.get("broke_step"), b.get("broke_k"), b.get("held_k"), b.get("band")), (2, 12, 6, "ramp-002"))
        self.check(row, "b broke because its relay didn't answer its sends",
                   re.fullmatch(r"the relay didn't answer \d+ sends", str(b.get("why"))), b.get("why"))
        self.eq(row, "a held to the max", (a.get("held_k"), a.get("ended"), "broke_k" in a), (18, "held at the max", False))
        live_b = read_json(root / "items" / "ramp" / "b" / "live.json")
        self.check(row, "b's live file counted the sends as unanswered, none as failed",
                   (live_b.get("send_unanswered") or 0) > 0 and (live_b.get("client_errors") or {}).get("send_failed", 0) == 0,
                   f"send_unanswered {live_b.get('send_unanswered')}, send_failed {(live_b.get('client_errors') or {}).get('send_failed', 0)}")
        self.end(row, cfg)

    def row_ramp_starved(self) -> None:
        """Relay b cut to 0.01 CPU at the ramp's second step: it sheds the
        sends it can't take with a rate-limited text. A shed is the relay's
        break, never counted apart as a quota, so the run goes on."""
        row = "ramp-starved"
        root, cfg = self.config(row, ["a", "b"], ramp={"max": 18, "start": 6},
                                inject={"at_band": [{"band": "ramp-002", "do": "cpus", "cpus": "0.01", "gen": "b"}]})
        argv = self.clock_argv(root, cfg, ["a", "b"], ["--ramp", str(PROOF / "profiles/proof-ramp.toml"), "--ramp-start", "6",
                                                        "--ramp-step", "6", "--ramp-every", "75", "--ramp-max", "18",
                                                        "--ramp-budget", "900"])
        a, b = self.ramp_result(row, root, self.run_clock(root, argv, 1500))
        self.eq(row, "b broke at the second step, 12 identities, and held 6",
                (b.get("broke_step"), b.get("broke_k"), b.get("held_k"), b.get("band")), (2, 12, 6, "ramp-002"))
        self.check(row, "b broke because its relay shed sends",
                   re.fullmatch(r"the relay shed \d+ sends: full, or unable to reach its admission store", str(b.get("why"))),
                   b.get("why"))
        self.eq(row, "a held to the max", (a.get("held_k"), a.get("ended"), "broke_k" in a), (18, "held at the max", False))
        live_b = read_json(root / "items" / "ramp" / "b" / "live.json")
        self.check(row, "b's live file counted the sheds, none as unknown",
                   (live_b.get("relay_shed") or 0) > 0 and live_b.get("limit_unknown") == {},
                   f"relay_shed {live_b.get('relay_shed')}, rate_limited {live_b.get('rate_limited')}, "
                   f"limit_unknown {live_b.get('limit_unknown')}")
        texts: dict[str, int] = {}
        for line in read_text(root / "items" / "ramp" / "b" / "stderr.log").splitlines():
            m = re.search(r"shed by the relay: (rate-limited: [a-z ]+)", line)
            if m:
                texts[m.group(1)] = texts.get(m.group(1), 0) + 1
        print(f"  THE STARVED RELAY'S TEXTS: {json.dumps(texts)}")
        self.end(row, cfg)

    def stopped_row(self, row: str, inject: dict[str, Any], want_code: int, want: Callable[[str], bool], want_text: str) -> Path:
        root, cfg = self.config(row, ["a", "b"], inject=inject)
        code = self.run_clock(root, self.clock_argv(root, cfg, ["a", "b"], ["--profile", str(PROOF / "profiles/proof-solo.toml")]), 900)
        clock = read_json(root / "clock" / "clock.json")
        self.eq(row, f"the clock exits {want_code}", (code, clock.get("exit")), (want_code, want_code))
        stopped = str(clock.get("stopped"))
        self.check(row, f"it stopped on: {want_text}", want(stopped), stopped)
        self.end(row, cfg)
        return root

    def row_boundary(self) -> None:
        line = "the hook failed at boundary floor: exit 1: the boundary check failed at floor: forced by the proof"
        root = self.stopped_row("boundary", {"boundary_fails": "floor"}, 4, lambda s: s == line, line)
        bands = [r["event"][1] for r in hook_log(root) if r.get("event", [None])[0] == "band"]
        self.eq("boundary", "no band ran after the failed boundary", bands, ["warmup", "floor", "pause"])

    def row_void(self) -> None:
        pat = r"void: the generator's live counters for a are stale: t_unix \d+ is \d+\.\d s old, over the 10 s limit"
        self.stopped_row("void", {"at_band": [{"band": "steady", "do": "sigstop", "gen": "a"}]}, 3,
                         lambda s: re.fullmatch(pat, s) is not None, pat)

    def row_crash_gen(self) -> None:
        line = "the generator for b stopped on its own: exited -9"
        self.stopped_row("crash-gen", {"at_band": [{"band": "steady", "do": "sigkill", "gen": "b"}]}, 3,
                         lambda s: s == line, line)

    def row_crash_clock(self) -> None:
        row = "crash-clock"
        root, cfg = self.config(row, ["a", "b"])
        p = self.start_clock(root, self.clock_argv(root, cfg, ["a", "b"], ["--profile", str(PROOF / "profiles/proof-solo.toml")]))
        killed_at = None
        end = time.time() + 900
        while time.time() < end and p.poll() is None:
            if any(r.get("event") == ["band", "steady"] and r["exit"] == 0 for r in hook_log(root)):
                time.sleep(5)
                p.send_signal(signal.SIGKILL)
                p.wait()
                killed_at = time.time()
                break
            time.sleep(1)
        if not self.check(row, "the clock was killed in the steady band", killed_at is not None, f"exit {p.returncode}"):
            self.end(row, cfg, must_have_run=False)
            return
        out = root / "items" / "proof-solo"
        # The steady band's lease is 45 s plus 15 s of slack, from its start.
        deadline = killed_at + 120
        while time.time() < deadline and not all((out / g / "exit").exists() for g in ("a", "b")):
            time.sleep(2)
        for g in ("a", "b"):
            self.eq(row, f"{g}'s tenant_sim ended on its own when its lease ran out (exit 5)", read_text(out / g / "exit"), "5")
            self.eq(row, f"{g}'s last live.json says lease", read_json(out / g / "live.json").get("ended"), "lease")
        deadline = time.time() + 60
        while time.time() < deadline and not (out / "sampler" / "exit").exists():
            time.sleep(2)
        void = read_json(out / "sampler" / "samples" / "void.json")
        want = {f"the generator's run for {g} ended: its band lease ran out with no newer signal: the driver is gone" for g in ("a", "b")}
        self.check(row, "the loop voided on a lost driver", void.get("reason") in want, void.get("reason"))
        self.eq(row, "the loop exited 3 on its own", read_text(out / "sampler" / "exit"), "3")
        self.check(row, "nothing ran end before the proof did", not any(r.get("event") == ["end"] for r in hook_log(root)))
        print(f"  {self.prefix}-a and -b still up after the crash: {sorted(self.leftovers())}")
        self.end(row, cfg, must_have_run=False)

    def row_heavy_seed(self) -> None:
        row = "heavy-seed"
        root, cfg = self.config(row, ["a"], seed_days=90, seed_max_seconds=3600)
        argv = self.clock_argv(root, cfg, ["a"], ["--profile", str(PROOF / "profiles/proof-heavy.toml")])
        argv[argv.index("--setup-timeout") + 1] = "3600"
        code = self.run_clock(root, argv, 5400)
        self.eq(row, "the clock exits 0", code, 0)
        out = root / "items" / "proof-heavy" / "a"
        start, done = phase(out, "seed-start"), phase(out, "seed-done")
        seed = done.get("seed") or {}
        self.eq(row, "the seed asked for the heavy profile's 90 days", (start.get("events"), seed.get("requested")),
                (HEAVY_SEED_EVENTS, HEAVY_SEED_EVENTS))
        self.eq(row, "every seed event was acknowledged", (seed.get("acked"), seed.get("rejected"), seed.get("errors")),
                (HEAVY_SEED_EVENTS, 0, 0))
        secs = seed.get("seconds")
        print(f"  THE RIG'S HEAVY SEED: {HEAVY_SEED_EVENTS} events in {secs} s"
              + (f" ({HEAVY_SEED_EVENTS / secs:.0f} events/s)" if secs else "")
              + f". Rig: {platform.machine()} {platform.system()}, relay image {IMAGES[0]} capped at 2 CPUs and 2 GB,"
              " Docker Hub's MinIO (arm64), Postgres and Redis uncapped, the generator on the same machine.")
        # Mentions: the never-mentioned tail, and its humans' polls apart.
        m = read_json(out / "mentions.json")
        tail = [r for r in m.get("recipients") or [] if r.get("tail")]
        humans = {h.get("pubkey") for h in (read_json(out / "identities.json").get("humans") or [])}
        tail_h = sum(1 for r in tail if r.get("pubkey") in humans)
        self.eq(row, "the never-mentioned tail: humans and agents", (tail_h, len(tail) - tail_h), (4, 10))
        polls = read_json(out / "summary.json").get("polls") or {}
        self.check(row, "both the tail's humans and the mentioned ones polled",
                   (polls.get("never_mentioned") or 0) > 0 and (polls.get("mentioned") or 0) > 0, json.dumps(polls))
        print(f"  HEAVY POLLS ({m.get('source')}): never-mentioned humans {polls.get('never_mentioned')} polls, "
              f"{json.dumps(polls.get('never_mentioned_ms'))} ms; mentioned {polls.get('mentioned')} polls, "
              f"{json.dumps(polls.get('mentioned_ms'))} ms")
        self.end(row, cfg)

    def rules_cadence(self, row: str, log: list[dict[str, Any]]) -> None:
        rules = [r["t_unix"] for r in log if r.get("event") == ["rules"]]
        gaps = [round(b - a, 1) for a, b in zip(rules, rules[1:])]
        self.check(row, "the rules ran at least every 60 s (plus one cadence)", rules and max(gaps or [0]) <= 64, f"gaps {gaps}")
        boundaries = [r["t_unix"] for r in log if r.get("event", [None])[0] == "boundary"]
        before = [any(0 <= b - t <= 10 for t in rules) for b in boundaries]
        self.check(row, "the rules ran at each boundary", len(boundaries) == 3 and all(before), f"{len(boundaries)} boundaries")


def hook_log(root: Path) -> list[dict[str, Any]]:
    try:
        return [json.loads(l) for l in (root / "hook.log").read_text().splitlines() if l.strip()]
    except OSError:
        return []


# What each field of a loop's break reason may be. A reason with any other
# field stops the proof at import, until it has its pattern here.
BREAK_FIELDS = {
    "n": r"\d+",
    "within": r"\d+",
    "acks": r"\d+",
    "pct": r"\d+\.\d",
    "band": "(?:" + "|".join(remote_sampler.MEASURED_BANDS) + "|" + remote_sampler.RAMP_STEP.pattern + ")",
    "ms": re.escape(remote_sampler.SLO_ACK_MS),
    "share": re.escape(f"{remote_sampler.SLO_ACK_SHARE:g}"),
}


def reason_pattern(fmt: str) -> re.Pattern[str]:
    """A loop break reason's format string as a pattern: its text exactly,
    each field only what the loop fills it with."""
    parts = []
    for text, name, _spec, _conv in string.Formatter().parse(fmt):
        parts.append(re.escape(text))
        if name is not None:
            parts.append(BREAK_FIELDS[name])
    return re.compile("".join(parts))


# The loop's named relay-break classes a ramp row accepts, read from the loop
# itself (remote_sampler.py writes the reasons): every relay failure total,
# rejects and the ack test. Anything else, a void or an unknown reason, fails.
BREAK_CLASSES = (
    *((k, reason_pattern(why)) for k, why in remote_sampler.RELAY_FAILURE_TOTALS.items()),
    ("rejects", reason_pattern(remote_sampler.REJECTS_BREAK)),
    ("ack test", reason_pattern(remote_sampler.ACK_TEST_BREAK)),
)


def break_class(why: Any) -> str | None:
    """Which named relay-break class a break's reason is, or None."""
    return next((name for name, pat in BREAK_CLASSES if pat.fullmatch(str(why))), None)


def read_json(p: Path) -> dict[str, Any]:
    try:
        v = json.loads(p.read_text())
        return v if isinstance(v, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def read_text(p: Path) -> str | None:
    try:
        return p.read_text().strip()
    except OSError:
        return None


def phase(out: Path, name: str) -> dict[str, Any]:
    for line in (read_text(out / "phases.jsonl") or "").splitlines():
        try:
            v = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(v, dict) and v.get("phase") == name:
            return v
    return {}


class Stopped(Exception):
    """INT or TERM: the row's end still runs, then exit 130 or 143."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _stop(signum: int, _frame: Any) -> None:
    # A second signal must not cut the cleanup short.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise Stopped(130 if signum == signal.SIGINT else 143)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="clock_proof.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--rows", default=",".join(ROWS), help=f"comma-separated, from {', '.join(ROWS)}")
    p.add_argument("--out", required=True, help="where each row's files go (kept)")
    p.add_argument("--prefix", default="g613-clock", help="the Compose projects are <prefix>-a and <prefix>-b")
    p.add_argument("--tenant-sim", default=str(REPO / "target/release/tenant_sim"))
    args = p.parse_args(argv)
    rows = [r for r in args.rows.split(",") if r]
    bad = [r for r in rows if r not in ROWS]
    if bad or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.prefix):
        print(f"refused: unknown rows {bad} or a bad prefix", file=sys.stderr)
        return 2
    docker = shutil.which("docker")
    if not docker:
        print("refused: no docker on PATH", file=sys.stderr)
        return 2
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    proof = Proof(out, args.prefix, sys.executable, docker, str(Path(args.tenant_sim).resolve()))
    if not proof.preflight():
        return 1
    fns: dict[str, Callable[[], None]] = {
        "reads": proof.row_reads, "ramp": proof.row_ramp, "ramp-freeze": proof.row_ramp_freeze,
        "ramp-starved": proof.row_ramp_starved, "boundary": proof.row_boundary,
        "void": proof.row_void, "crash-gen": proof.row_crash_gen, "crash-clock": proof.row_crash_clock,
        "heavy-seed": proof.row_heavy_seed}
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        for r in rows:
            print(f"== {r}", flush=True)
            try:
                fns[r]()
            finally:
                # Whatever happened in the row, nothing of it stays up.
                cfg = out / r / "config.json"
                if cfg.exists():
                    subprocess.run([*proof.hook(cfg), "end"], capture_output=True, timeout=600)
    except Stopped as e:
        left = proof.leftovers()
        print(f"\nstopped by a signal: exit {e.code}; left: {left or 'nothing'}", flush=True)
        return e.code
    left = proof.leftovers()
    proof.check("all", "nothing is left after the proof", not left, left or "")
    failed = [x for x in proof.results if not x[2]]
    print(f"\n{len(proof.results) - len(failed)} of {len(proof.results)} checks passed")
    for row, what, _, detail in failed:
        print(f"FAILED {row}: {what} ({detail})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
