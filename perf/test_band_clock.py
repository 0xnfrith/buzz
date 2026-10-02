#!/usr/bin/env python3
"""Rows for band_clock.py: the clock against a stand-in world (a fake hook
with its own clock), and once through a real hook command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import band_clock as bc

PROFILE = """[profile]
name = "{name}"
[bands]
warmup = {w}
floor = {f}
steady = {s}
peak = {p}
cooldown = {c}
"""


def profile(d: Path, name: str, w: float = 10, f: float = 20, s: float = 30, p: float = 20, c: float = 10) -> str:
    path = d / f"{name}.toml"
    path.write_text(PROFILE.format(name=name, w=w, f=f, s=s, p=p, c=c))
    return str(path)


class World:
    """The hook's other side: generators that set up and connect, a sampler,
    and the breaks or void a row injects at a time."""

    def __init__(self, gens: list[str]) -> None:
        self.t = 1000.0
        self.events: list[list[str]] = []
        self.gens = {g: "inactive" for g in gens}
        self.phases: dict[str, list[dict[str, Any]]] = {g: [] for g in gens}
        self.continued: set[str] = set()
        self.sampler = "inactive"
        self.breaks: dict[str, dict[str, Any]] = {}
        self.void: dict[str, Any] | None = None
        self.fail: dict[str, tuple[int, str]] = {}  # "event arg" -> (exit, stderr)
        self.provision = {g: {"events": 10, "rate_limited": 0, "relay_shed": 0, "seconds": 1.0} for g in gens}
        self.setup_fails: dict[str, str] = {}
        self.never_setup: set[str] = set()
        self.at: list[tuple[float, Any]] = []  # (time, fn) run once time passes it
        self.lines: list[tuple[str, str]] = []
        self.line_t: list[tuple[str, str, float]] = []
        self.event_t: list[tuple[str, float]] = []
        # A generator that ends this many seconds after its stop (its relay
        # frozen, its sends waiting out their timeouts).
        self.slow_stop: dict[str, float] = {}

    def clock(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s
        for when, fn in list(self.at):
            if self.t >= when:
                self.at.remove((when, fn))
                fn(self)

    def hook(self, event: list[str]) -> tuple[int, str, str]:
        self.events.append(event)
        self.event_t.append((" ".join(event), self.t))
        key = " ".join(event)
        for k, (code, err) in self.fail.items():
            if key == k:
                return code, "", err
        ev, args = event[0], event[1:]
        if ev == "gen-start":
            g = args[0]
            self.gens[g] = "active"
            self.continued.discard(g)
            if g in self.setup_fails:
                self.phases[g] = [{"phase": "setup-failed", "why": self.setup_fails[g]}]
                self.gens[g] = "exited 3"
            elif g in self.never_setup:
                self.phases[g] = []
            else:
                self.phases[g] = [{"phase": "setup-done", "provision": self.provision[g]}]
        elif ev == "send":
            g, line = args
            self.lines.append((g, line))
            self.line_t.append((g, line, self.t))
            if line.startswith("continue"):
                self.phases[g].append({"phase": "ready", "identities": 6})
            if line == "stop" and g in self.slow_stop:
                self.at.append((self.t + self.slow_stop[g], lambda w, g=g: w.gens.__setitem__(g, "exited 0")))
            elif line == "stop":
                self.gens[g] = "exited 0"
        elif ev == "phases":
            return 0, "".join(json.dumps(p) + "\n" for p in self.phases[args[0]]), ""
        elif ev == "sampler":
            self.sampler = "active" if args[0] == "start" else "inactive"
        elif ev == "status":
            return 0, json.dumps({"void": self.void, "breaks": {"relays": self.breaks}, "sampler": self.sampler,
                                  "gens": self.gens}), ""
        return 0, "", ""

    def clock_for(self, items: list[bc.Item], out: Path, **opts: Any) -> bc.Clock:
        o = bc.Options(**opts) if opts else bc.Options()
        return bc.Clock(self.hook, sorted(self.gens), items, out, o, clock=self.clock, sleep=self.sleep, log=lambda l: None)

    def kinds(self) -> list[str]:
        """The events, with status, phases and rules polls left out."""
        return [" ".join(e) for e in self.events if e[0] not in ("status", "phases", "rules")]


class Profiles(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_a_profile_runs_its_bands_in_lockstep(self) -> None:
        w = World(["a", "b"])
        item = bc.load_item(profile(self.d, "solo"))
        code = w.clock_for([item], self.d / "out").run()
        self.assertEqual(code, 0)
        pause = "band pause 900"
        sends = lambda line: [f"send a {line}", f"send b {line}"]  # noqa: E731
        self.assertEqual(w.kinds(), [
            "setup solo", "gen-start a solo", "gen-start b solo", "fleet",
            *sends("continue 420"), "sampler start",
            *sends("band warmup 130"), "band warmup",
            *sends("band floor 140"), "band floor", *sends(pause), "band pause", "boundary floor",
            *sends("band steady 150"), "band steady", *sends(pause), "band pause", "boundary steady",
            *sends("band peak 140"), "band peak", *sends(pause), "band pause", "boundary peak",
            *sends("band cooldown 130"), "band cooldown",
            *sends("stop"), "sampler stop", "end",
        ])
        # Each band is held for its length: warmup 10 + floor 20 + steady 30
        # + peak 20 + cooldown 10, with the pauses taking no time here.
        self.assertGreaterEqual(w.t - 1000, 90)
        self.assertIn(["rules"], w.events, "the rules tick ran")
        res = json.loads((self.d / "out" / "clock.json").read_text())
        self.assertEqual((res["exit"], res["stopped"], res["items"][0]["name"]), (0, None, "solo"))
        self.assertEqual(res["items"][0]["provision"]["a"]["rate_limited"], 0)

    def test_rules_run_at_each_boundary_and_every_minute(self) -> None:
        w = World(["a"])
        item = bc.load_item(profile(self.d, "solo", w=0, f=150, s=0, p=0, c=0))
        self.assertEqual(w.clock_for([item], self.d / "out").run(), 0)
        times = [i for i, e in enumerate(w.events) if e == ["rules"]]
        # The first tick, about every 60 s through floor's 150 s, then at
        # floor's boundary and the other two.
        self.assertGreaterEqual(len(times), 3 + 3)
        before_boundary = [w.events[i - 1:i + 1] for i, e in enumerate(w.events) if e[:1] == ["boundary"]]
        for pair in before_boundary:
            self.assertEqual(pair[0], ["rules"], "the rules run just before each boundary")

    def test_a_boundary_that_fails_stops_the_run_and_end_still_runs(self) -> None:
        w = World(["a", "b"])
        w.fail["boundary floor"] = (1, "prove: FAIL box tcp4 1.1.1.1:443: the packet got out")
        code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "out").run()
        self.assertEqual(code, 4)
        res = json.loads((self.d / "out" / "clock.json").read_text())
        self.assertEqual(res["stopped"], "the hook failed at boundary floor: exit 1: prove: FAIL box tcp4 1.1.1.1:443: the packet got out")
        self.assertEqual(w.kinds()[-1], "end")
        self.assertNotIn("band steady", w.kinds(), "the run went on past the failed boundary")

    def test_a_void_stops_the_run(self) -> None:
        w = World(["a", "b"])
        w.at.append((1035.0, lambda w: setattr(w, "void", {"reason": "the rule-set hash on relay1 changed", "box": "relay1"})))
        code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "out").run()
        self.assertEqual(code, 3)
        res = json.loads((self.d / "out" / "clock.json").read_text())
        self.assertEqual(res["stopped"], "void: the rule-set hash on relay1 changed")
        self.assertEqual(w.kinds()[-1], "end")

    def test_a_generator_or_sampler_that_stops_on_its_own_stops_the_run(self) -> None:
        for name, fn, want in [
            ("gen", lambda w: w.gens.__setitem__("b", "exited 101"), "the generator for b stopped on its own: exited 101"),
            ("sampler", lambda w: setattr(w, "sampler", "exited 1"), "the sampler stopped on its own: exited 1"),
        ]:
            with self.subTest(name):
                w = World(["a", "b"])
                w.at.append((1015.0, fn))
                code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / name).run()
                self.assertEqual(code, 3)
                self.assertEqual(json.loads((self.d / name / "clock.json").read_text())["stopped"], want)

    def test_a_generator_that_ends_before_its_phase_stops_the_run_at_once(self) -> None:
        """A generator that exits during setup, or after `continue` before
        it is ready, stops the run at the next cadence with its own line,
        not when the wait's timeout runs out."""
        def gone_in_setup(w: World) -> None:
            w.never_setup.add("b")
            w.at.append((1012.0, lambda w: w.gens.__setitem__("b", "exited 101")))

        def gone_before_ready(w: World) -> None:
            real = w.hook

            def hook(event: list[str]) -> tuple[int, str, str]:
                if event[:2] == ["send", "b"] and event[2].startswith("continue"):
                    w.lines.append(("b", event[2]))
                    w.gens["b"] = "exited 3"
                    return 0, "", ""
                return real(event)
            w.hook = hook  # type: ignore[method-assign]
        for name, arrange, want, before in [
            ("setup-done", gone_in_setup, "the generator for b stopped before its setup-done: exited 101", 1020.0),
            ("ready", gone_before_ready, "the generator for b stopped before its ready: exited 3", 1010.0),
        ]:
            with self.subTest(name):
                w = World(["a", "b"])
                arrange(w)
                out = self.d / name
                code = w.clock_for([bc.load_item(profile(self.d, "solo"))], out,
                                   setup_timeout_s=3600, ready_timeout_s=300).run()
                self.assertEqual(code, 5)
                self.assertEqual(json.loads((out / "clock.json").read_text())["stopped"], want)
                stopped_at = max(t for e, t in w.event_t if e == "status")
                self.assertLessEqual(stopped_at, before, "the clock waited out its timeout")
                self.assertEqual(w.kinds()[-1], "end")

    def test_setup_that_fails_or_hangs_stops_the_run(self) -> None:
        w = World(["a", "b"])
        w.setup_fails["b"] = "9030 h0 rejected: blocked"
        self.assertEqual(w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "f").run(), 5)
        self.assertEqual(json.loads((self.d / "f" / "clock.json").read_text())["stopped"], "setup failed for b: 9030 h0 rejected: blocked")
        w = World(["a", "b"])
        w.never_setup.add("a")
        self.assertEqual(w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "h", setup_timeout_s=60).run(), 5)
        self.assertEqual(json.loads((self.d / "h" / "clock.json").read_text())["stopped"], "no setup-done from a within 60 s")
        self.assertNotIn("fleet", w.kinds(), "fleet ran before every generator was set up")

    def test_a_rate_limited_setup_is_refused_when_the_limits_are_raised(self) -> None:
        w = World(["a", "b"])
        w.provision["b"]["rate_limited"] = 3
        code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "out", setup_must_not_rate_limit=True).run()
        self.assertEqual(code, 6)
        self.assertEqual(json.loads((self.d / "out" / "clock.json").read_text())["stopped"],
                         "setup for b was rate-limited 3 times; the setup limits are raised, so its setup is wrong")
        self.assertNotIn("fleet", w.kinds())
        # Without the flag (a relay at its default limits), pacing is legal.
        w = World(["a", "b"])
        w.provision["b"]["rate_limited"] = 3
        self.assertEqual(w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "ok").run(), 0)

    def test_a_setup_the_relay_shed_is_refused_when_the_limits_are_raised(self) -> None:
        """Shedding (the relay full, or its admission store out of reach) is
        read apart from the quota, and refused the same; a provision with no
        count at all is refused too."""
        for name, shed, want in [
            ("shed", 2, "the relay shed 2 of b's setup events: full, or unable to reach its admission store"),
            ("missing", None, "the relay shed None of b's setup events: full, or unable to reach its admission store"),
        ]:
            with self.subTest(name):
                w = World(["a", "b"])
                if shed is None:
                    del w.provision["b"]["relay_shed"]
                else:
                    w.provision["b"]["relay_shed"] = shed
                out = self.d / name
                code = w.clock_for([bc.load_item(profile(self.d, "solo"))], out, setup_must_not_rate_limit=True).run()
                self.assertEqual(code, 6)
                self.assertEqual(json.loads((out / "clock.json").read_text())["stopped"], want)
                self.assertNotIn("fleet", w.kinds())

    def test_end_runs_once_and_its_failure_is_reported(self) -> None:
        w = World(["a"])
        w.fail["end"] = (2, "could not stop the sampler")
        code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "out").run()
        self.assertEqual(code, 4)
        res = json.loads((self.d / "out" / "clock.json").read_text())
        self.assertEqual((res["exit"], res["end"]), (4, "the hook failed at end: exit 2: could not stop the sampler"))
        self.assertEqual(w.kinds().count("end"), 1)

    def test_a_signal_mid_run_still_runs_end(self) -> None:
        w = World(["a"])

        def interrupt(w: World) -> None:
            raise bc.Stop(143, "stopped by SIGTERM")
        w.at.append((1012.0, interrupt))
        code = w.clock_for([bc.load_item(profile(self.d, "solo"))], self.d / "out").run()
        self.assertEqual(code, 143)
        self.assertEqual(w.kinds()[-1], "end")

    def test_items_run_one_after_another(self) -> None:
        w = World(["a"])
        items = [bc.load_item(profile(self.d, "solo", 1, 1, 1, 1, 1)), bc.load_item(profile(self.d, "team", 1, 1, 1, 1, 1))]
        self.assertEqual(w.clock_for(items, self.d / "out").run(), 0)
        k = w.kinds()
        self.assertLess(k.index("sampler stop"), k.index("setup team"), "the next item started before the last ended")
        self.assertEqual([e for e in k if e.startswith("setup ")], ["setup solo", "setup team"])


class Ramps(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def ramp(self, w: World, ramp: bc.Ramp) -> tuple[int, dict[str, Any]]:
        item = bc.load_item(profile(self.d, "team", w=10), ramp)
        code = w.clock_for([item], self.d / "out").run()
        return code, json.loads((self.d / "out" / "clock.json").read_text())

    def test_each_relay_records_the_last_step_held_and_the_first_broken(self) -> None:
        """a's step 3 fails its ack test, judged as step 4 begins; b's relay
        is OOM-killed during step 5. Each generator stops when its relay
        breaks; the ramp ends when both have."""
        w = World(["a", "b"])
        # Step n starts at 1010 + 300 (n - 1).
        w.at.append((1010 + 3 * 300 + 1, lambda w: w.breaks.__setitem__(
            "a", {"t_unix": 1910.0, "why": "ramp-003: 80 of 100 acks within 500 ms (80.0%), under 95%", "band": "ramp-003"})))
        w.at.append((1010 + 4 * 300 + 50, lambda w: w.breaks.__setitem__(
            "b", {"t_unix": 2260.0, "why": "relay1 (10.77.0.3): the relay was OOM-killed", "band": "ramp-005"})))
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=660, budget_s=36000))
        self.assertEqual(code, 0, res.get("stopped"))
        r = res["items"][0]["ramp"]
        self.assertEqual(r["relays"]["a"], {"held_k": 45, "broke_k": 60, "broke_step": 3, "broke_t_unix": 1910.0,
                                            "why": "ramp-003: 80 of 100 acks within 500 ms (80.0%), under 95%", "band": "ramp-003"})
        self.assertEqual((r["relays"]["b"]["held_k"], r["relays"]["b"]["broke_k"], r["relays"]["b"]["broke_step"]), (75, 90, 5))
        self.assertEqual([s["k"] for s in r["steps"]], [30, 45, 60, 75, 90])
        # a got no ramp line after its relay broke; b went on to step 5.
        ramps_a = [l for g, l in w.lines if g == "a" and l.startswith("ramp ")]
        self.assertEqual([l.split()[1] for l in ramps_a], ["30", "45", "60", "75"])
        self.assertIn(("a", "stop"), w.lines)
        self.assertEqual(w.kinds()[-3:], ["boundary ramp", "sampler stop", "end"])

    def test_the_last_steps_break_is_read_after_the_sampler_judged_it(self) -> None:
        """The last step's ack test is judged at the sampler's first tick
        after the pause: here 10 s after it, later than one cadence. The
        clock waits for it, so the relay broke at the max, not held it."""
        w = World(["a"])
        # Step 3, the last, ends at 1010 + 3 * 300.
        w.at.append((1010 + 3 * 300 + 10, lambda w: w.breaks.__setitem__(
            "a", {"t_unix": 1920.0, "why": "ramp-003: 80 of 100 acks within 500 ms (80.0%), under 95%", "band": "ramp-003"})))
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=60, budget_s=36000))
        self.assertEqual(code, 0)
        a = res["items"][0]["ramp"]["relays"]["a"]
        self.assertEqual((a["held_k"], a["broke_k"], a["broke_step"], "ended" in a), (45, 60, 3, False))

    def test_a_generator_slow_to_stop_holds_no_other_generators_step(self) -> None:
        """b's relay breaks in step 2, and b takes 800 s to end after its
        stop, past the ramp's end. a gets step 3 as soon as step 2 ends,
        inside its lease, and the item's end still waits for b before the
        sampler stops."""
        w = World(["a", "b"])
        w.slow_stop["b"] = 800
        w.at.append((1010 + 300 + 30, lambda w: w.breaks.__setitem__(
            "b", {"t_unix": 1340.0, "why": "the relay didn't answer 4 sends", "band": "ramp-002"})))
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=75, budget_s=36000))
        self.assertEqual(code, 0, res.get("stopped"))
        stop_b = next(t for g, l, t in w.line_t if (g, l) == ("b", "stop"))
        step3_a = next(t for g, l, t in w.line_t if g == "a" and l.startswith("ramp 60 "))
        self.assertLess(step3_a - stop_b, 10, "a's next step waited for b to end")
        sampler_stop = next(t for e, t in w.event_t if e == "sampler stop")
        self.assertGreaterEqual(sampler_stop, stop_b + 800, "the item ended before b did")
        self.assertEqual(w.kinds()[-4:], ["boundary ramp", "send a stop", "sampler stop", "end"])
        r = res["items"][0]["ramp"]["relays"]
        self.assertEqual((r["b"]["broke_k"], r["a"]["held_k"], r["a"]["ended"]), (45, 75, "held at the max"))

    def test_a_void_mid_ramp_keeps_the_steps_and_the_breaks_before_it(self) -> None:
        """b broke in step 2; the run voids in step 4. clock.json keeps the
        steps run and b's break; a has no result past its last held step."""
        w = World(["a", "b"])
        w.at.append((1010 + 300 + 30, lambda w: w.breaks.__setitem__(
            "b", {"t_unix": 1340.0, "why": "the relay didn't answer 4 sends", "band": "ramp-002"})))
        w.at.append((1010 + 3 * 300 + 60, lambda w: setattr(w, "void", {"reason": "the generator box's CPU averaged 85%"})))
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=660, budget_s=36000))
        self.assertEqual((code, res["stopped"]), (bc.EXIT_VOID, "void: the generator box's CPU averaged 85%"))
        r = res["items"][0]["ramp"]
        self.assertEqual([s["k"] for s in r["steps"]], [30, 45, 60, 75])
        self.assertEqual((r["relays"]["b"]["held_k"], r["relays"]["b"]["broke_k"], r["relays"]["b"]["why"]), (30, 45, "the relay didn't answer 4 sends"))
        self.assertEqual(r["relays"]["a"], {"held_k": None})

    def test_a_ramp_that_holds_to_the_max(self) -> None:
        w = World(["a"])
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=60, budget_s=36000))
        self.assertEqual(code, 0)
        r = res["items"][0]["ramp"]
        self.assertEqual([s["k"] for s in r["steps"]], [30, 45, 60])
        self.assertEqual(r["relays"]["a"], {"held_k": 60, "ended": "held at the max"})

    def test_a_step_that_would_pass_the_max_stops_at_it(self) -> None:
        """The step doesn't divide the max: the last step is the max itself,
        and no generator is ever sent more identities than that."""
        w = World(["a"])
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=70, budget_s=36000))
        self.assertEqual(code, 0)
        r = res["items"][0]["ramp"]
        self.assertEqual([s["k"] for s in r["steps"]], [30, 45, 60, 70])
        ramps_a = [l.split()[1] for g, l in w.lines if g == "a" and l.startswith("ramp ")]
        self.assertEqual(ramps_a, ["30", "45", "60", "70"])
        self.assertEqual(r["relays"]["a"], {"held_k": 70, "ended": "held at the max"})

    def test_a_ramp_that_runs_out_of_time(self) -> None:
        w = World(["a"])
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=660, budget_s=900))
        self.assertEqual(code, 0)
        r = res["items"][0]["ramp"]
        self.assertEqual([s["k"] for s in r["steps"]], [30, 45, 60])
        self.assertEqual(r["relays"]["a"], {"held_k": 60, "ended": "the ramp's time ran out"})

    def test_a_break_with_no_ramp_band_lands_on_the_step_it_came_in(self) -> None:
        w = World(["a"])
        w.at.append((1010 + 300 + 100, lambda w: w.breaks.__setitem__(
            "a", {"t_unix": 1410.0, "why": "the relay dropped connections", "band": "pause"})))
        code, res = self.ramp(w, bc.Ramp(start=30, step=15, every_s=300, max=660, budget_s=36000))
        self.assertEqual(code, 0)
        self.assertEqual(res["items"][0]["ramp"]["relays"]["a"]["broke_step"], 2)


class Cli(unittest.TestCase):
    def test_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = profile(Path(d), "solo")
            bad = Path(d) / "bad.toml"
            bad.write_text("[profile]\nname = 'x'\n")
            rows = [
                ([], "refused: give the hook command after --"),
                (["--out", d, "--"], "refused: the hook command after -- is empty"),
                (["--out", d, "--profile", p, "--", "true"], "refused: give each --gen once, a plain name"),
                (["--out", d, "--gen", "a", "--gen", "a", "--profile", p, "--", "true"], "refused: give each --gen once, a plain name"),
                (["--out", d, "--gen", "a b", "--profile", p, "--", "true"], "refused: give each --gen once, a plain name"),
                (["--out", d, "--gen", "a", "--", "true"], "refused: give at least one --profile or --ramp"),
                (["--out", d, "--gen", "a", "--profile", p, "--profile", p, "--", "true"], "refused: two items share a name: ['solo', 'solo']"),
                (["--out", d, "--gen", "a", "--ramp", p, "--ramp-start", "0", "--", "true"],
                 "refused: the ramp needs 0 < start <= max, a step, a period and a budget above 0"),
                (["--out", d, "--gen", "a", "--profile", p, "--cadence", "0", "--", "true"], "refused: every period and timeout must be above 0"),
            ]
            for argv, want in rows:
                with self.subTest(argv=argv):
                    r = subprocess.run([sys.executable, str(Path(bc.__file__)), *argv], capture_output=True, text=True)
                    self.assertEqual((r.returncode, r.stderr.strip().splitlines()[-1]), (2, want))
            r = subprocess.run([sys.executable, str(Path(bc.__file__)), "--out", d, "--gen", "a", "--profile", str(bad), "--", "true"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertTrue(r.stderr.startswith(f"refused: profile {bad}: KeyError('bands')"), r.stderr)

    def test_tenant_cogs_clock_runs_the_clock(self) -> None:
        r = subprocess.run([sys.executable, str(Path(bc.__file__).with_name("tenant_cogs.py")), "clock", "--gen", "a"],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr.strip()), (2, "refused: give the hook command after --"))

    def test_a_real_hook_command(self) -> None:
        """Through the subprocess seam: a hook script that answers every
        event, with bands of 0 s, and records what it was asked."""
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            p = profile(d, "solo", 0, 0, 0, 0, 0)
            log = d / "events"
            hook = d / "hook.py"
            hook.write_text(textwrap.dedent(f"""\
                import json, sys
                ev = sys.argv[1:]
                open({str(log)!r}, "a").write(" ".join(ev) + "\\n")
                if ev[0] == "phases":
                    print(json.dumps({{"phase": "setup-done", "provision": {{"rate_limited": 0, "relay_shed": 0}}}}))
                    print(json.dumps({{"phase": "ready"}}))
                elif ev[0] == "status":
                    print(json.dumps({{"void": None, "breaks": None, "sampler": "active",
                                      "gens": {{"a": "exited 0" if "send a stop" in open({str(log)!r}).read() else "active"}}}}))
                """))
            r = subprocess.run([sys.executable, str(Path(bc.__file__)), "--out", str(d / "out"), "--gen", "a", "--profile", p,
                                "--cadence", "0.01", "--", sys.executable, str(hook)], capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            events = log.read_text().splitlines()
            self.assertEqual([e for e in events if e.split()[0] not in ("status", "phases", "rules")][:4],
                             ["setup solo", "gen-start a solo", "fleet", "send a continue 420"])
            self.assertEqual(events[-1], "end")
            self.assertEqual(json.loads((d / "out" / "clock.json").read_text())["exit"], 0)


if __name__ == "__main__":
    unittest.main()
