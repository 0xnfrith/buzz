#!/usr/bin/env python3
"""Rows for clock_proof.py's own checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_proof as cp


class BreakClass(unittest.TestCase):
    def test_a_ramp_break_must_be_a_named_relay_break_class(self) -> None:
        """The ramp row accepts the loop's four named relay-break classes, and
        nothing else: a void, a generator fault or an unknown reason fails."""
        for why, want in [
            ("ramp-004: 61 of 100 acks within 500 ms (61.0%), under 95%", "ack test"),
            ("the relay rejected 3 events", "rejects"),
            ("the relay didn't answer 4 sends", "unanswered"),
            ("the relay shed 2 sends: full, or unable to reach its admission store", "shed"),
            ("void: the generator box's CPU averaged 85%", None),
            ("the generator for b reported its own errors: send_failed +4", None),
            ("the relay lost 216 events", None),
            ("", None),
            (None, None),
        ]:
            with self.subTest(why=why):
                self.assertEqual(cp.break_class(why), want)


if __name__ == "__main__":
    unittest.main()
