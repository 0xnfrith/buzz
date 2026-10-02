#!/usr/bin/env python3
"""Rows for clock_proof.py's own checks."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_proof as cp
import remote_sampler as rs


class BreakClass(unittest.TestCase):
    def test_the_relay_refusing_reads_is_a_named_relay_break(self) -> None:
        """b's break in the round 2 proof: the loop's read_refused reason."""
        self.assertEqual(cp.break_class("the relay refused 1 agent reads"), "read_refused")

    def test_every_relay_failure_total_is_a_named_relay_break(self) -> None:
        """One row per reason in the loop's RELAY_FAILURE_TOTALS, read from the
        loop, so a reason added there is a row here too."""
        totals = rs.RELAY_FAILURE_TOTALS
        self.assertGreaterEqual(len(totals), 7)
        for k, why in totals.items():
            with self.subTest(total=k):
                self.assertEqual(cp.break_class(why.format(n=1)), k)
                self.assertEqual(cp.break_class(why.format(n=4096)), k)

    def test_rejects_and_the_ack_test_are_named_relay_breaks(self) -> None:
        """The loop's own texts: the reject reason, and the ack test on a ramp
        step and on a measured band (proof6's b broke on the first)."""
        ack = dict(ms=rs.SLO_ACK_MS, share=rs.SLO_ACK_SHARE)
        for why, want in [
            (rs.REJECTS_BREAK.format(n=3), "rejects"),
            (rs.ACK_TEST_BREAK.format(band="ramp-004", within=182, acks=230, pct=100.0 * 182 / 230, **ack), "ack test"),
            (rs.ACK_TEST_BREAK.format(band="floor", within=57, acks=76, pct=75.0, **ack), "ack test"),
        ]:
            with self.subTest(why=why):
                self.assertEqual(cp.break_class(why), want)
        self.assertEqual(rs.ACK_TEST_BREAK.format(band="ramp-004", within=182, acks=230, pct=100.0 * 182 / 230, **ack),
                         "ramp-004: 182 of 230 acks within 500 ms (79.1%), under 95%")

    def test_the_loops_box_live_and_drop_breaks_are_named_relay_breaks(self) -> None:
        """The six the loop named inline before: each renders its old text
        exactly, and each is a named break."""
        for why, want in [
            (rs.NO_RELAY_CONTAINER_BREAK.format(key="relay1 (10.77.0.3)"), ("relay1 (10.77.0.3): no relay container", "no relay container")),
            (rs.OOM_KILLED_BREAK.format(key="relay1 (10.77.0.3)"), ("relay1 (10.77.0.3): the relay was OOM-killed", "oom killed")),
            (rs.MEM_AVAILABLE_BREAK.format(key="relay1 (10.77.0.3)", pct=9.94, limit=10.0),
             ("relay1 (10.77.0.3): MemAvailable was 9.9% of MemTotal, under 10%", "mem available")),
            (rs.MEM_AVAILABLE_BREAK.format(key="b (fd00::3)", pct=4.0, limit=7.5),
             ("b (fd00::3): MemAvailable was 4.0% of MemTotal, under 7.5%", "mem available")),
            (rs.DROPPED_BREAK, ("the relay dropped connections", "dropped")),
            (rs.JOIN_FAILED_BREAK.format(n=3), ("3 identities couldn't join the relay", "join failed")),
            (rs.LOST_BREAK.format(n=216), ("the relay lost 216 events", "lost")),
        ]:
            with self.subTest(why=why):
                self.assertEqual((why, cp.break_class(why)), want)

    def test_every_named_reason_in_the_loop_is_a_named_relay_break(self) -> None:
        """One row per *_BREAK reason and relay failure total the loop has,
        read from the loop, so a reason added there is a row here too."""
        fill = dict(n=7, key="relay1 (10.77.0.3)", band="ramp-004", within=1, acks=20, pct=5.0,
                    ms=rs.SLO_ACK_MS, share=rs.SLO_ACK_SHARE, limit=10.0)
        self.assertGreaterEqual(len(cp.LOOP_BREAKS), 15)
        for k, why in cp.LOOP_BREAKS.items():
            with self.subTest(reason=k):
                self.assertEqual(cp.break_class(why.format(**fill)), k)

    def test_the_classes_are_the_loops_reasons_and_nothing_else(self) -> None:
        self.assertEqual([k for k, _ in cp.BREAK_CLASSES],
                         ["rejects", "ack test", "no relay container", "oom killed", "mem available", "dropped",
                          "join failed", "lost", *rs.RELAY_FAILURE_TOTALS])
        self.assertEqual(sorted(cp.LOOP_BREAK_NAMES), sorted(n for n in vars(rs) if n.endswith("_BREAK")))

    def test_every_relay_break_call_in_the_loop_takes_a_named_reason(self) -> None:
        """Walks remote_sampler.py: every relay_break call's reason is one of
        the proof's *_BREAK reasons (or its .format), or a relay failure
        total inside the loop over RELAY_FAILURE_TOTALS. A reason written
        inline can't skip the proof's classes."""
        tree = ast.parse(Path(rs.__file__).read_text())
        parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "relay_break"]
        self.assertGreaterEqual(len(calls), 9)
        for c in calls:
            with self.subTest(line=c.lineno, call=ast.unparse(c)):
                why = c.args[1] if len(c.args) > 1 else next(k.value for k in c.keywords if k.arg == "why")
                if isinstance(why, ast.Call) and isinstance(why.func, ast.Attribute) and why.func.attr == "format":
                    why = why.func.value
                self.assertIsInstance(why, ast.Name)
                if why.id in cp.LOOP_BREAK_NAMES:
                    continue
                loop = parent.get(c)
                while loop is not None and not isinstance(loop, ast.For):
                    loop = parent.get(loop)
                self.assertIsNotNone(loop)
                self.assertEqual(ast.unparse(loop.iter), "RELAY_FAILURE_TOTALS.items()")
                self.assertIsInstance(loop.target, ast.Tuple)
                self.assertEqual(ast.unparse(loop.target.elts[1]), why.id)

    def test_a_void_an_unknown_or_an_empty_reason_fails(self) -> None:
        """A void, a generator fault, an unknown reason, an empty one, a count
        that isn't digits or a reason with more after it is no named break."""
        for why in [
            "void: the generator's live counters for a are stale: t_unix 1790920100 is 11.1 s old, over the 10 s limit",
            "the generator for b reported its own errors: send_failed +4",
            "the relay was slow",
            "",
            None,
            "the relay refused x agent reads",
            "the relay refused -1 agent reads",
            "the relay refused 1 agent reads, and more",
            "ramp-004: 182 of 230 acks within 400 ms (79.1%), under 95%",
            "warmup: 182 of 230 acks within 500 ms (79.1%), under 95%",
            "relay1: no relay container",
            "relay1 (10.77.0.3): MemAvailable was 9.9% of MemTotal",
            "the relay lost some events",
        ]:
            with self.subTest(why=why):
                self.assertIsNone(cp.break_class(why))


if __name__ == "__main__":
    unittest.main()
