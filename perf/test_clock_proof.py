#!/usr/bin/env python3
"""Rows for clock_proof.py's own checks."""

from __future__ import annotations

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

    def test_the_classes_are_the_loops_reasons_and_nothing_else(self) -> None:
        self.assertEqual([k for k, _ in cp.BREAK_CLASSES], [*rs.RELAY_FAILURE_TOTALS, "rejects", "ack test"])

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
        ]:
            with self.subTest(why=why):
                self.assertIsNone(cp.break_class(why))


if __name__ == "__main__":
    unittest.main()
