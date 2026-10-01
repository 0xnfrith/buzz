#!/usr/bin/env python3
"""Unit tests for remote_sampler / `tenant_cogs.py remote-sample` (stdlib unittest)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import remote_sampler as rs
import tenant_cogs

H1, H2 = "a" * 64, "b" * 64


def relay_sample(t: float, h: str = H1, ws: int = 100, busy: int = 0, oom: int = 0, tier: str = "fast") -> dict:
    return {
        "v": 1, "tier": tier, "t_unix": t,
        "box": {"mem": {"MemTotal": 1000, "MemAvailable": 600},
                "cpu": {"ticks": {"user": busy, "nice": 0, "system": 0, "idle": 1000 + int(t) * 10, "iowait": 0, "irq": 0, "softirq": 0, "steal": 0}, "ncpu": 2},
                "oom_kill": 0},
        "steal": {"reported": None, "why": "unknown: not x86 (arm64)"},
        "containers": {"relay": {"working_set": ws, "oom_kill": oom}},
        "nft": {"hash": h, "drops": {"output": {"packets": int(t), "bytes": 0}}},
        "reader": {"cpu_s": 0.02, "maxrss_kb": 9000, "children_maxrss_kb": 4000},
        "errors": [],
    }


def live_counters(t: int = 1, rejected: int = 0, media_failed: int = 0, git_failed: int = 0, **client_errors: int) -> dict:
    """tenant_sim's live.json, with every field it writes."""
    return {"t_unix": t, "sent": 0, "accepted": 0, "rejected": rejected, "received": 0,
            "client_errors": client_errors, "media_failed": media_failed, "git_failed": git_failed}


def gen_sample(t: float, busy: int, idle: int, avail: int = 900, oom: int = 0) -> dict:
    return {"tier": "fast", "t_unix": t,
            "box": {"mem": {"MemTotal": 1000, "MemAvailable": avail},
                    "cpu": {"ticks": {"user": busy, "idle": idle, "iowait": 0}, "ncpu": 2}, "oom_kill": oom},
            "reader": {"cpu_s": 0.01, "maxrss_kb": 8000, "children_maxrss_kb": 0}}


class Guard(unittest.TestCase):
    """Every refusal exits 2 with its exact line, and no ssh runs."""

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        self.deny = d / "deny.txt"
        self.deny.write_text("10.77.0.66/32\n")
        self.key, self.kh = d / "key", d / "known_hosts"
        self.key.write_text("k")
        self.kh.write_text("h")
        self.eh = d / "hashes.json"
        self.eh.write_text(json.dumps({"10.77.0.3": H1, "10.77.0.4": H1}))
        self.out = d / "out"

    def tearDown(self) -> None:
        self.td.cleanup()

    def run_cli(self, *extra: str, guard: bool = True) -> tuple[int, str]:
        argv = ["remote-sample", "--out-dir", str(self.out)]
        if guard:
            argv += ["--allow-cidr", "10.77.0.0/24", "--deny-list", str(self.deny)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(rs, "run_ssh", side_effect=AssertionError("ssh ran")):
            code = tenant_cogs.main(argv + list(extra))
        return code, err.getvalue()

    def test_refusals(self) -> None:
        k, kh = ["--ssh-key", str(self.key)], ["--known-hosts", str(self.kh), "--expected-hashes", str(self.eh)]
        rows = [
            (["--box", "relay1=10.77.0.3", *k, "--known-hosts", str(self.kh)], "refused: --expected-hashes is required with --box. Nothing was run.\n"),
            (["--box", "relay1=box.example", *k, *kh], "refused: --box 'relay1=box.example': 'box.example' is not an IP address (names are never resolved). Nothing was run.\n"),
            (["--box", "relay1=10.78.0.3", *k, *kh], "refused: --box 'relay1=10.78.0.3': 10.78.0.3 is outside the allow list. Nothing was run.\n"),
            (["--box", "relay1=10.77.0.66", *k, *kh], "refused: --box 'relay1=10.77.0.66': 10.77.0.66 is on the deny list (10.77.0.66/32). Nothing was run.\n"),
            (["--box", "10.77.0.3", *k, *kh], "refused: --box '10.77.0.3' is not ROLE=IP. Nothing was run.\n"),
            (["--box", "relay1=10.77.0.3", *kh], "refused: --ssh-key is required with --box. Nothing was run.\n"),
            (["--box", "relay1=10.77.0.3", *k, "--expected-hashes", str(self.eh)], "refused: --known-hosts is required with --box. Nothing was run.\n"),
            (["--box", "relay1=10.77.0.3", *k, "--known-hosts", str(self.kh) + ".gone", "--expected-hashes", str(self.eh)], f"refused: --known-hosts {self.kh}.gone: No such file or directory. Nothing was run.\n"),
            (["--box", "a=10.77.0.3", "--box", "a=10.77.0.4", *k, *kh], "refused: two --box values share a role. Nothing was run.\n"),
            ([], "refused: give at least one --box or --self. Nothing was run.\n"),
        ]
        for extra, want in rows:
            with self.subTest(extra=extra):
                self.assertEqual(self.run_cli(*extra), (2, want))

    def test_a_refusal_through_the_script(self) -> None:
        """Run as a script (tenant_cogs is __main__), from /, isolated."""
        for flags in ([], ["-I", "-B"]):
            with self.subTest(flags=flags):
                p = subprocess.run([sys.executable, *flags, str(Path(__file__).with_name("tenant_cogs.py")), "remote-sample",
                                    "--out-dir", str(self.out), "--allow-cidr", "10.77.0.0/24", "--deny-list", str(self.deny),
                                    "--box", "relay1=10.77.0.3", "--ssh-key", str(self.key), "--known-hosts", str(self.kh)],
                                   cwd="/", capture_output=True, text=True, timeout=60)
                self.assertEqual((p.returncode, p.stdout, p.stderr),
                                 (2, "", "refused: --expected-hashes is required with --box. Nothing was run.\n"))

    def test_a_symlinked_key(self) -> None:
        link = Path(self.td.name) / "key-link"
        link.symlink_to(self.key)
        self.assertEqual(
            self.run_cli("--box", "relay1=10.77.0.3", "--ssh-key", str(link), "--known-hosts", str(self.kh), "--expected-hashes", str(self.eh)),
            (2, f"refused: --ssh-key {link} is not a regular file (a symlink or other). Nothing was run.\n"),
        )

    def test_the_guard_flags_are_required(self) -> None:
        self.assertEqual(self.run_cli("--self", "gen", guard=False),
                         (2, "refused: --allow-cidr is required (repeatable; no default). Nothing was changed.\n"))

    def test_expected_hashes_must_cover_every_box(self) -> None:
        eh = Path(self.td.name) / "hashes.json"
        eh.write_text(json.dumps({"10.77.0.4": H1}))
        self.assertEqual(
            self.run_cli("--box", "relay1=10.77.0.3", "--ssh-key", str(self.key), "--known-hosts", str(self.kh), "--expected-hashes", str(eh)),
            (2, "refused: --expected-hashes has no hash for ['10.77.0.3']. Nothing was run.\n"),
        )

    def test_the_argv_is_fixed(self) -> None:
        self.assertEqual(rs.ssh_argv("/k", "/kh", "10.77.0.3", "fast"), [
            "/usr/bin/ssh", "-F", "/dev/null", "-o", "IdentityFile=none", "-i", "/k",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "AddKeysToAgent=no",
            "-o", "UserKnownHostsFile=/kh", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
            "-o", "VerifyHostKeyDNS=no", "-o", "CanonicalizeHostname=no", "-o", "AddressFamily=inet",
            "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "Tunnel=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "RequestTTY=no",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR", "-l", "root", "-p", "22", "--", "10.77.0.3", "fast",
        ])
        self.assertEqual(rs.ssh_env()["PATH"], "/usr/bin:/bin")
        self.assertNotIn("SSH_AUTH_SOCK", rs.ssh_env())


class Replies(unittest.TestCase):
    def test_parse_reply(self) -> None:
        ok = relay_sample(1)
        rows = [
            ((255, "", "x\nssh: connect to host 10.77.0.3 port 22: No route to host\n"), (None, "ssh exit 255: ssh: connect to host 10.77.0.3 port 22: No route to host")),
            ((124, "", ""), (None, "ssh exit 124")),
            ((0, "{", ""), (None, "the reply is not JSON")),
            ((0, "[]", ""), (None, "the reply is not a fast sample")),
            ((0, json.dumps({**ok, "tier": "slow"}), ""), (None, "the reply is not a fast sample")),
            ((0, json.dumps({**ok, "box": None}), ""), (None, "the reply is not a fast sample")),
            ((0, json.dumps({**ok, "t_unix": True}), ""), (None, "the reply is not a fast sample")),
            ((0, json.dumps(ok), ""), (ok, None)),
        ]
        for (code, out, err), want in rows:
            with self.subTest(out=out[:20], err=err):
                self.assertEqual(rs.parse_reply(code, out, err, "fast"), want)


class BoundedCalls(unittest.TestCase):
    """run_ssh reads a bounded reply, for a bounded time, and leaves no
    process behind."""

    def test_a_normal_call(self) -> None:
        self.assertEqual(rs.run_ssh(["/bin/sh", "-c", "printf out; printf err >&2; exit 7"]), (7, "out", "err"))

    def test_a_reply_over_the_cap_is_stopped(self) -> None:
        self.assertEqual(rs.run_ssh(["/bin/sh", "-c", f"head -c {rs.MAX_REPLY_BYTES + 1} /dev/zero; sleep 30"]),
                         (125, "", f"the reply was over {rs.MAX_REPLY_BYTES} bytes; the call was stopped"))

    def test_a_reply_at_the_cap_is_read(self) -> None:
        code, out, _ = rs.run_ssh(["/bin/sh", "-c", f"head -c {rs.MAX_REPLY_BYTES} /dev/zero | tr '\\0' x"])
        self.assertEqual((code, len(out)), (0, rs.MAX_REPLY_BYTES))

    def test_error_output_over_the_cap_is_stopped(self) -> None:
        self.assertEqual(rs.run_ssh(["/bin/sh", "-c", f"head -c {rs.MAX_ERR_BYTES + 1} /dev/zero >&2; sleep 30"]),
                         (125, "", f"the error output was over {rs.MAX_ERR_BYTES} bytes; the call was stopped"))

    def test_a_slow_call_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as d, mock.patch.object(rs, "SSH_TIMEOUT_S", 1):
            pidfile = Path(d) / "pid"
            self.assertEqual(rs.run_ssh(["/bin/sh", "-c", f"echo $$ > {pidfile}; exec sleep 30"]), (124, "", "timed out after 1s"))
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_a_missing_ssh(self) -> None:
        code, out, err = rs.run_ssh(["/nonexistent/ssh"])
        self.assertEqual((code, out), (127, ""))
        self.assertIn("No such file or directory", err)


class BandResults(unittest.TestCase):
    def test_the_samplers_share(self) -> None:
        b = rs.BandStats("steady", "relay1")
        for t in (0.0, 10.0):
            b.add("fast", relay_sample(t))
        b.add("fast", None)
        out = b.summary()
        self.assertEqual((out["ticks"], out["missed"]), (3, 1))
        self.assertEqual(out["sampler"], {"cpu_s": 0.04, "share_pct_of_box": 0.2, "maxrss_kb": 9000})
        self.assertEqual(out["drops_rose"], {"output": 10})

    def test_reported_steal(self) -> None:
        b = rs.BandStats("steady", "relay1")
        for t, steal in ((0.0, 0), (10.0, 20)):
            s = relay_sample(t)
            s["steal"] = {"reported": True, "why": "KVM steal time"}
            s["box"]["cpu"]["ticks"]["steal"] = steal
            b.add("fast", s)
        out = b.summary()
        self.assertEqual(out["steal_pct"], 100.0 * 20 / (100 + 20))
        self.assertNotIn("steal_why", out)


class RingBound(unittest.TestCase):
    def test_the_ring_never_holds_more_than_files_times_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ring = rs.Ring(Path(d) / "r", files=3, max_bytes=100)
            for i in range(200):
                ring.append(json.dumps({"i": i, "pad": "x" * 20}))
            files = sorted(Path(d, "r").iterdir())
            self.assertEqual(len(files), 3)
            self.assertLessEqual(sum(f.stat().st_size for f in files), 3 * 100)
            last = files[-1].read_text().splitlines()[-1]
            self.assertEqual(json.loads(last)["i"], 199, "the newest line is kept")

    def test_a_restart_carries_on_from_the_newest_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for run in range(4):
                ring = rs.Ring(Path(d) / "r", files=3, max_bytes=100)
                for i in range(50):
                    ring.append(json.dumps({"run": run, "i": i}))
            files = sorted(Path(d, "r").iterdir())
            self.assertEqual(len(files), 3)
            last = json.loads(files[-1].read_text().splitlines()[-1])
            self.assertEqual(last, {"run": 3, "i": 49})

    def test_a_line_bigger_than_a_file_is_replaced_by_a_note(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ring = rs.Ring(Path(d) / "r", files=2, max_bytes=100)
            ring.append("x" * 500)
            (f,) = Path(d, "r").iterdir()
            self.assertEqual(json.loads(f.read_text()), {"dropped": "a line of 501 bytes, over the ring's 100-byte files"})


class Voids(unittest.TestCase):
    BOX = rs.Box("relay1", "10.77.0.3")

    def mon(self, **kw: object) -> rs.Monitor:
        return rs.Monitor(expected={"10.77.0.3": H1}, **kw)  # type: ignore[arg-type]

    def test_a_changed_rule_set_voids(self) -> None:
        m = self.mon()
        self.assertIsNone(m.box_tick(self.BOX, 1, relay_sample(1), None))
        v = m.box_tick(self.BOX, 2, relay_sample(2, h=H2), None)
        self.assertEqual((v.reason, v.box), (f"the rule-set hash on relay1 (10.77.0.3) is {H2}, not {H1}, recorded at the lockdown", "relay1"))

    def test_three_misses_in_a_row_void_as_unreachable(self) -> None:
        m = self.mon()
        self.assertIsNone(m.box_tick(self.BOX, 1, None, "ssh exit 255: Connection timed out"))
        self.assertIsNone(m.box_tick(self.BOX, 2, None, "ssh exit 255: Connection timed out"))
        v = m.box_tick(self.BOX, 3, None, "ssh exit 255: Connection timed out")
        self.assertEqual(v.reason, "box unreachable: relay1 (10.77.0.3): 3 calls in a row failed; the last: ssh exit 255: Connection timed out")

    def test_a_good_tick_resets_the_run_of_misses(self) -> None:
        m = self.mon()
        for t in range(10):
            sample = relay_sample(t) if t % 3 == 2 else None
            self.assertIsNone(m.box_tick(self.BOX, t, sample, "x"))

    def test_over_one_percent_missed_voids_once_there_are_100_ticks(self) -> None:
        m = self.mon()
        out = None
        for t in range(1, 101):
            out = m.box_tick(self.BOX, t, None if t in (10, 50) else relay_sample(t), "late")
            if t < 100:
                self.assertIsNone(out, t)
        self.assertEqual(out.reason, "relay1 (10.77.0.3) missed 2 of 100 ticks, over the 1% limit")

    def test_exactly_one_percent_is_not_over(self) -> None:
        m = self.mon()
        for t in range(1, 201):
            self.assertIsNone(m.box_tick(self.BOX, t, None if t in (10, 200) else relay_sample(t), "late"), t)

    def test_the_share_is_checked_on_a_miss_after_100_ticks(self) -> None:
        m = self.mon()
        for t in range(1, 150):
            self.assertIsNone(m.box_tick(self.BOX, t, None if t == 10 else relay_sample(t), "late"), t)
        v = m.box_tick(self.BOX, 150, None, "late")
        self.assertEqual(v.reason, "relay1 (10.77.0.3) missed 2 of 150 ticks, over the 1% limit")

    def test_a_box_with_no_recorded_hash_voids(self) -> None:
        m = rs.Monitor(expected={})
        v = m.box_tick(self.BOX, 1, relay_sample(1), None)
        self.assertEqual(v.reason, "no rule-set hash was recorded at the lockdown for relay1 (10.77.0.3)")

    def test_a_sample_without_a_hash_is_a_miss(self) -> None:
        m = self.mon()
        s = relay_sample(1)
        s["nft"] = None
        for t in (1, 2):
            self.assertIsNone(m.box_tick(self.BOX, t, s, None))
        v = m.box_tick(self.BOX, 3, s, None)
        self.assertEqual(v.reason, "box unreachable: relay1 (10.77.0.3): 3 calls in a row failed; the last: the sample has no rule-set hash")

    def test_a_failed_docker_ps_is_not_a_relay_break(self) -> None:
        m = rs.Monitor(expected={"10.77.0.3": H1})
        s = relay_sample(1)
        s["containers"], s["errors"] = {}, ["docker ps: exit 124: timed out after 10s"]
        self.assertIsNone(m.box_tick(self.BOX, 1, s, None))
        self.assertIsNone(m.relay_break_t)
        self.assertIsNone(m.gen_tick(0, gen_sample(0, 0, 0), None, None))
        self.assertIsNone(m.gen_tick(60, gen_sample(60, 80, 20), None, None))
        v = m.gen_tick(120, gen_sample(120, 155, 45), None, None)
        self.assertEqual(v.reason, "the generator's CPU averaged 80.0% and 75.0% on two 60 s windows in a row, over 70%, before the relay broke")

    def test_a_listing_without_the_relay_is_a_relay_break(self) -> None:
        m = rs.Monitor(expected={"10.77.0.3": H1})
        s = relay_sample(5)
        s["containers"] = {"postgres": {"working_set": 10, "oom_kill": 0}}
        self.assertIsNone(m.box_tick(self.BOX, 5, s, None))
        self.assertEqual((m.relay_break_t, m.notes), (5, [{"t_unix": 5, "relay_break": "relay1 (10.77.0.3): no relay container"}]))

    def test_rising_drop_counters_are_reported_not_fatal(self) -> None:
        m = self.mon()
        for t in range(1, 20):
            self.assertIsNone(m.box_tick(self.BOX, t, relay_sample(t), None))

    def test_the_generators_cpu_over_70_on_two_windows_voids(self) -> None:
        m = rs.Monitor(expected={})
        self.assertIsNone(m.gen_tick(0, gen_sample(0, 0, 0), None, None))
        self.assertIsNone(m.gen_tick(60, gen_sample(60, 80, 20), None, None))  # 80%
        v = m.gen_tick(120, gen_sample(120, 155, 45), None, None)  # 75%
        self.assertEqual(v.reason, "the generator's CPU averaged 80.0% and 75.0% on two 60 s windows in a row, over 70%, before the relay broke")
        self.assertEqual((v.box, v.gen_event_t, v.relay_break_t), ("generator", 120, None))

    def test_one_window_over_70_does_not(self) -> None:
        m = rs.Monitor(expected={})
        m.gen_tick(0, gen_sample(0, 0, 0), None, None)
        self.assertIsNone(m.gen_tick(60, gen_sample(60, 80, 20), None, None))
        self.assertIsNone(m.gen_tick(120, gen_sample(120, 90, 110), None, None))  # 10%
        self.assertIsNone(m.gen_tick(180, gen_sample(180, 170, 130), None, None))  # 80%, but not two in a row

    def test_low_memory_for_three_ticks_voids(self) -> None:
        m = rs.Monitor(expected={})
        for t in (1, 2):
            self.assertIsNone(m.gen_tick(t, gen_sample(t, 0, 0, avail=50), None, None))
        v = m.gen_tick(3, gen_sample(3, 0, 0, avail=50), None, None)
        self.assertEqual(v.reason, "the generator's MemAvailable was under 10% of MemTotal for 3 ticks, before the relay broke")

    def test_an_oom_kill_on_the_generators_box_voids(self) -> None:
        m = rs.Monitor(expected={})
        self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0, oom=4), None, None))
        v = m.gen_tick(2, gen_sample(2, 0, 0, oom=5), None, None)
        self.assertEqual(v.reason, "an out-of-memory kill on the generator's box (1), before the relay broke")

    def test_live_counters(self) -> None:
        rows = [
            ("missing", None, "/x/live.json is missing", "the generator's live counters: /x/live.json is missing"),
            ("not JSON", None, "/x/live.json is not JSON: Expecting value: line 1 column 1 (char 0)", "the generator's live counters: /x/live.json is not JSON: Expecting value: line 1 column 1 (char 0)"),
        ]
        for name, value, err, want in rows:
            with self.subTest(name):
                m = rs.Monitor(expected={}, live_required=True)
                v = m.gen_tick(1, gen_sample(1, 0, 0), value, err)
                self.assertEqual(v.reason, want)
        m = rs.Monitor(expected={}, live_required=True)
        self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0), live_counters(1), None))
        self.assertIsNone(m.gen_tick(2, gen_sample(2, 0, 0), live_counters(2), None))
        v = m.gen_tick(3, gen_sample(3, 0, 0), live_counters(3, send_failed=2, reconnect_failed=1), None)
        self.assertEqual(v.reason, "the generator reported its own errors: reconnect_failed +1, send_failed +2, before the relay broke")

    def test_a_generator_event_after_the_relay_broke_is_a_note(self) -> None:
        m = rs.Monitor(expected={}, live_required=True)
        self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0), live_counters(1), None))
        self.assertIsNone(m.gen_tick(2, gen_sample(2, 0, 0), live_counters(2, rejected=5), None))
        self.assertEqual(m.relay_break_t, 2)
        self.assertIsNone(m.gen_tick(3, gen_sample(3, 0, 0), live_counters(3, rejected=5, send_failed=1), None))
        self.assertEqual(m.notes[-1], {"t_unix": 3, "after_relay_break": "the generator reported its own errors: send_failed +1", "relay_break_t": 2})
        for t in (4, 5):
            self.assertIsNone(m.gen_tick(t, gen_sample(t, 0, 0), live_counters(t, rejected=5, send_failed=1), None))
        self.assertEqual(len(m.notes), 2, "one rise is noted once")

    def test_media_and_git_failures_are_the_generators_own_errors(self) -> None:
        """Each rising before the relay breaks voids; after it, a note."""
        for k in ("media_failed", "git_failed"):
            with self.subTest(k, relay_broke=False):
                m = rs.Monitor(expected={}, live_required=True)
                self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0), live_counters(1), None))
                self.assertIsNone(m.gen_tick(2, gen_sample(2, 0, 0), live_counters(2), None))
                v = m.gen_tick(3, gen_sample(3, 0, 0), live_counters(3, **{k: 2}), None)
                self.assertEqual((v.reason, v.box, v.gen_event_t, v.relay_break_t),
                                 (f"the generator reported its own errors: {k} +2, before the relay broke", "generator", 3, None))
            with self.subTest(k, relay_broke=True):
                m = rs.Monitor(expected={}, live_required=True)
                self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0), live_counters(1), None))
                self.assertIsNone(m.gen_tick(2, gen_sample(2, 0, 0), live_counters(2, rejected=1), None))
                self.assertEqual(m.relay_break_t, 2)
                self.assertIsNone(m.gen_tick(3, gen_sample(3, 0, 0), live_counters(3, rejected=1, **{k: 2}), None))
                self.assertEqual(m.notes[-1], {"t_unix": 3, "after_relay_break": f"the generator reported its own errors: {k} +2", "relay_break_t": 2})

    def test_media_git_and_client_errors_rising_together_are_one_void(self) -> None:
        m = rs.Monitor(expected={}, live_required=True)
        self.assertIsNone(m.gen_tick(1, gen_sample(1, 0, 0), live_counters(1), None))
        v = m.gen_tick(2, gen_sample(2, 0, 0), live_counters(2, media_failed=1, git_failed=3, recv_error=1), None)
        self.assertEqual(v.reason, "the generator reported its own errors: git_failed +3, media_failed +1, recv_error +1, before the relay broke")

    def test_an_event_after_the_break_is_noted_once(self) -> None:
        m = rs.Monitor(expected={})
        m.relay_break(0, "the relay dropped connections")
        for t, oom in ((1, 0), (2, 1), (3, 1), (4, 1)):
            self.assertIsNone(m.gen_tick(t, gen_sample(t, 0, 0, avail=50, oom=oom), None, None))
        self.assertEqual([n.get("after_relay_break") for n in m.notes], [None, "an out-of-memory kill on the generator's box (1)",
                                                                         "the generator's MemAvailable was under 10% of MemTotal for 3 ticks"])

    def test_read_live(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "live.json"
            self.assertEqual(rs.read_live(str(p)), (None, f"{p} is missing"))
            p.write_text("{")
            self.assertEqual(rs.read_live(str(p))[1], f"{p} is not JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)")
            p.write_text("{}")
            self.assertEqual(rs.read_live(str(p)), (None, f"{p} has no client_errors"))
            whole = live_counters(7)
            p.write_text(json.dumps({**whole, "client_errors": {"send_failed": "2"}}))
            self.assertEqual(rs.read_live(str(p)), (None, f"{p} has a counter that is not a whole number"))
            p.write_text(json.dumps(whole))
            self.assertEqual(rs.read_live(str(p)), (whole, None))
            # tenant_sim writes every total, so a missing one is an error,
            # never 0; a kind missing from client_errors is 0.
            for k in rs.LIVE_TOTALS:
                with self.subTest(missing=k):
                    p.write_text(json.dumps({x: v for x, v in whole.items() if x != k}))
                    self.assertEqual(rs.read_live(str(p)), (None, f"{p} has no {k}"))
            for k, bad in (("rejected", 1.5), ("media_failed", -1), ("git_failed", True), ("media_failed", "2"), ("git_failed", None)):
                with self.subTest(k=k, bad=bad):
                    p.write_text(json.dumps({**whole, k: bad}))
                    self.assertEqual(rs.read_live(str(p)), (None, f"{p} has a counter that is not a whole number"))


class Loop(unittest.TestCase):
    """The loop end to end, with a fake ssh, a fake clock and a fake local
    reader."""

    def settings(self, d: Path, **kw: object) -> rs.Settings:
        base = dict(boxes=[rs.Box("relay1", "10.77.0.3")], key="/k", known_hosts="/kh", out=d, expected={"10.77.0.3": H1},
                    self_role="gen", self_config={}, live_file=None, band_file=None, fast_every=5.0, slow_every=60.0,
                    duration=None, once=False, ring_files=8, ring_bytes=1 << 20)
        base.update(kw)
        return rs.Settings(**base)  # type: ignore[arg-type]

    def drive(self, s: rs.Settings, answer):  # type: ignore[no-untyped-def]
        clock = {"t": 1000.0}
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> tuple[int, str, str]:
            calls.append(argv)
            return answer(clock["t"], argv[-1])

        def sleep(sec: float) -> None:
            clock["t"] += 5

        def local(tier: str, cfg: dict) -> dict:
            row = gen_sample(clock["t"], 0, int(clock["t"]))
            row["tier"] = tier
            row["reader"]["cpu_s"] = 999.0  # in-process, getrusage counts the loop since it started
            return row

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = rs.run_loop(s, runner=runner, clock=lambda: clock["t"], sleep=sleep, local=local)
        self.stderr = err.getvalue()
        return code, calls

    def test_a_rule_set_changed_mid_run_writes_void_and_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            def answer(t: float, tier: str) -> tuple[int, str, str]:
                return 0, json.dumps(relay_sample(t, h=H2 if t >= 1015 else H1, tier=tier)), ""
            code, calls = self.drive(self.settings(Path(d)), answer)
            self.assertEqual(code, 3)
            void = json.loads((Path(d) / "samples" / "void.json").read_text())
            self.assertEqual(void["reason"], f"the rule-set hash on relay1 (10.77.0.3) is {H2}, not {H1}, recorded at the lockdown")
            self.assertEqual(void["t_unix"], 1015.0)
            self.assertEqual(self.stderr, f"void: {void['reason']}\n")
            self.assertEqual([c[-1] for c in calls], ["fast", "slow", "fast", "fast", "fast"])
            ring = (Path(d) / "samples" / "relay1" / "ring-000000.jsonl").read_text().splitlines()
            self.assertEqual(len(ring), 5)
            bands = [json.loads(l) for l in (Path(d) / "samples" / "bands.jsonl").read_text().splitlines()]
            self.assertEqual([(b["band"], b["role"]) for b in bands], [("none", "relay1"), ("none", "gen")])
            self.assertEqual((bands[0]["ticks"], bands[0]["slow_calls"], bands[0]["missed"]), (4, 1, 0))
            self.assertEqual(bands[0]["sampler"], {"cpu_s": 0.1, "share_pct_of_box": round(100 * 0.1 / (15 * 2), 4), "maxrss_kb": 9000})
            gen = bands[1]["sampler"]
            self.assertLess(gen["cpu_s"], 5, "the in-process reader's cumulative CPU was summed, not taken as a difference")
            local_ring = [json.loads(l) for l in (Path(d) / "samples" / "gen" / "ring-000000.jsonl").read_text().splitlines()]
            self.assertIn("cpu_s_since_start", local_ring[0]["sample"]["reader"])

    def test_three_ssh_failures_in_a_row_void_as_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            def answer(t: float, tier: str) -> tuple[int, str, str]:
                if t >= 1010:
                    return 255, "", "ssh: connect to host 10.77.0.3 port 22: Connection timed out\n"
                return 0, json.dumps(relay_sample(t, tier=tier)), ""
            code, _ = self.drive(self.settings(Path(d)), answer)
            self.assertEqual(code, 3)
            void = json.loads((Path(d) / "samples" / "void.json").read_text())
            self.assertEqual(void["reason"], "box unreachable: relay1 (10.77.0.3): 3 calls in a row failed; the last: ssh exit 255: ssh: connect to host 10.77.0.3 port 22: Connection timed out")
            self.assertEqual(self.stderr, f"void: {void['reason']}\n")

    def test_replies_that_are_not_samples_are_misses(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            def answer(t: float, tier: str) -> tuple[int, str, str]:
                return (0, json.dumps(relay_sample(t, tier=tier)), "") if t < 1010 else (0, "[1, 2]", "")
            code, _ = self.drive(self.settings(Path(d)), answer)
            self.assertEqual(code, 3)
            void = json.loads((Path(d) / "samples" / "void.json").read_text())
            self.assertEqual(void["reason"], "box unreachable: relay1 (10.77.0.3): 3 calls in a row failed; the last: the reply is not a fast sample")

    def test_bands_and_the_end_of_a_run(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            band = Path(d) / "band"
            band.write_text("floor\n")
            seen = {"n": 0}

            def answer(t: float, tier: str) -> tuple[int, str, str]:
                seen["n"] += 1
                if t >= 1020:
                    band.write_text("steady\n")
                return 0, json.dumps(relay_sample(t, tier=tier)), ""
            code, _ = self.drive(self.settings(Path(d), band_file=str(band), duration=40.0), answer)
            self.assertEqual(code, 0)
            self.assertFalse((Path(d) / "samples" / "void.json").exists())
            bands = [json.loads(l) for l in (Path(d) / "samples" / "bands.jsonl").read_text().splitlines()]
            self.assertEqual([(b["band"], b["role"]) for b in bands],
                             [("none", "relay1"), ("none", "gen"), ("floor", "relay1"), ("floor", "gen"), ("steady", "relay1"), ("steady", "gen")])
            floor = bands[2]
            self.assertEqual(floor["working_set_bytes"]["relay"]["max"], 100)
            self.assertIsNone(floor["steal_pct"])
            self.assertEqual(floor["steal_why"], "unknown: not x86 (arm64)")
            self.assertGreater(floor["sampler"]["cpu_s"], 0)


class SecondSignal(unittest.TestCase):
    """A second signal while the summaries or void.json are being written
    is ignored, so they are written whole."""

    def run_with(self, answer, during_flush: int):  # type: ignore[no-untyped-def]
        clock = {"t": 1000.0}
        real = rs.BandStats.summary

        def summary(self_: rs.BandStats) -> dict:
            os.kill(os.getpid(), during_flush)
            return real(self_)

        def local(tier: str, cfg: dict) -> dict:
            if clock["t"] >= 1010:
                os.kill(os.getpid(), signal.SIGINT)
            return {**gen_sample(clock["t"], 0, int(clock["t"])), "tier": tier}

        def sleep(sec: float) -> None:
            clock["t"] += 5

        d = tempfile.mkdtemp(dir=self.td.name)
        s = Loop.settings(self, Path(d))  # type: ignore[arg-type]
        with mock.patch.object(rs.BandStats, "summary", summary), contextlib.redirect_stderr(io.StringIO()):
            code = rs.run_loop(s, runner=lambda argv: answer(clock["t"], argv[-1]), clock=lambda: clock["t"], sleep=sleep, local=local)
        return code, Path(d) / "samples"

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.td.cleanup()

    def test_during_the_summaries_after_int(self) -> None:
        code, out = self.run_with(lambda t, tier: (0, json.dumps(relay_sample(t, tier=tier)), ""), signal.SIGTERM)
        self.assertEqual(code, 130)
        self.assertEqual(len((out / "bands.jsonl").read_text().splitlines()), 2)

    def test_during_a_void(self) -> None:
        code, out = self.run_with(lambda t, tier: (0, json.dumps(relay_sample(t, h=H2 if t >= 1005 else H1, tier=tier)), ""), signal.SIGINT)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads((out / "void.json").read_text())["t_unix"], 1005.0)
        self.assertEqual(len((out / "bands.jsonl").read_text().splitlines()), 2)


class Signals(unittest.TestCase):
    """INT and TERM write the band summaries, then exit 130 and 143."""

    def test_int_and_term(self) -> None:
        for sig, want in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(sig=sig), tempfile.TemporaryDirectory() as d:
                deny = Path(d) / "deny.txt"
                deny.write_text("")
                p = subprocess.Popen([sys.executable, str(Path(__file__).with_name("tenant_cogs.py")), "remote-sample",
                                      "--allow-cidr", "10.77.0.0/24", "--deny-list", str(deny), "--self", "gen",
                                      "--out-dir", d, "--fast-every", "0.2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ring = Path(d) / "samples" / "gen" / "ring-000000.jsonl"
                deadline = time.time() + 20
                while not ring.exists() and time.time() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ring.exists(), "the loop never wrote a sample")
                p.send_signal(sig)
                out, err = p.communicate(timeout=20)
                self.assertEqual((p.returncode, out, err), (want, "", ""))
                bands = [json.loads(l) for l in (Path(d) / "samples" / "bands.jsonl").read_text().splitlines()]
                self.assertEqual([(b["band"], b["role"]) for b in bands], [("none", "gen")])
                self.assertGreaterEqual(bands[0]["ticks"], 1)


if __name__ == "__main__":
    unittest.main()
