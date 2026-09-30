#!/usr/bin/env python3
"""Unit tests for tenant_cogs / cogs_report (stdlib unittest)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cogs_report
import tenant_cogs


class PercentileTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(tenant_cogs.percentile([], 0.5), 0.0)
        self.assertEqual(tenant_cogs.pct_block([]), {"p50": 0.0, "p95": 0.0, "max": 0.0})

    def test_known_set(self) -> None:
        xs = [float(i) for i in range(1, 101)]
        # nearest-rank: idx = round((n-1)*p)
        self.assertEqual(tenant_cogs.percentile(xs, 0.50), 51.0)
        self.assertEqual(tenant_cogs.percentile(xs, 0.95), 95.0)
        self.assertEqual(tenant_cogs.pct_block(xs)["max"], 100.0)


class PrometheusTests(unittest.TestCase):
    def test_gauges_and_counters(self) -> None:
        text = """
# HELP buzz_ws_connections_active open ws
# TYPE buzz_ws_connections_active gauge
buzz_ws_connections_active 30
buzz_events_received_total{kind="9"} 10
buzz_events_received_total{kind="7"} 2
buzz_events_rejected_total 0
buzz_db_pool_acquire_duration_seconds_bucket{le="0.01"} 8
buzz_db_pool_acquire_duration_seconds_bucket{le="0.1"} 10
buzz_db_pool_acquire_duration_seconds_bucket{le="+Inf"} 10
buzz_db_pool_acquire_duration_seconds_count 10
buzz_db_pool_acquire_duration_seconds_sum 0.2
"""
        parsed = tenant_cogs.parse_prometheus(text)
        self.assertEqual(parsed["ws_connections_active"], 30.0)
        self.assertEqual(parsed["events_received_total"], 12.0)
        self.assertEqual(parsed["events_rejected_total"], 0.0)
        self.assertIsNotNone(parsed["db_pool_acquire_p95_s"])

    def test_fanout_histogram_buckets(self) -> None:
        text = """
buzz_fanout_recipients_sum 120
buzz_fanout_recipients_count 30
buzz_fanout_recipients_bucket{le="10"} 20
buzz_fanout_recipients_bucket{le="+Inf"} 30
"""
        parsed = tenant_cogs.parse_prometheus(text)
        self.assertEqual(parsed["fanout_recipients_sum"], 120.0)
        self.assertEqual(parsed["fanout_recipients_count"], 30.0)
        self.assertEqual(
            parsed["fanout_recipients_buckets"],
            [{"le": 10.0, "c": 20.0}, {"le": "+Inf", "c": 30.0}],
        )
        p50 = tenant_cogs.histogram_quantile(
            tenant_cogs.histogram_buckets_from_json(parsed["fanout_recipients_buckets"]),
            0.50,
        )
        # count=30, target=15, crosses le=10 (c=20) from prev 0 → 7.5
        self.assertAlmostEqual(p50 or 0.0, 7.5, places=6)


class CpuStatTests(unittest.TestCase):
    def test_parse_cpu_and_lsn(self) -> None:
        self.assertEqual(tenant_cogs.parse_cpu_stat("usage_usec 12345\nuser_usec 1\n"), 12345)
        self.assertEqual(tenant_cogs.parse_memory_current("4096\n"), 4096)
        self.assertEqual(tenant_cogs.lsn_to_bytes("0/1A2B3C4"), (0 << 32) + 0x1A2B3C4)


class AdapterCommandTests(unittest.TestCase):
    def test_compose_exec_command(self) -> None:
        ad = tenant_cogs.ExecAdapter(kind="compose", project="buzz-harness")
        self.assertEqual(
            ad.exec_cmd("relay", ["cat", "/sys/fs/cgroup/cpu.stat"]),
            ["docker", "exec", "buzz-harness-relay-1", "cat", "/sys/fs/cgroup/cpu.stat"],
        )
        self.assertEqual(
            ad.container("postgres"),
            "buzz-harness-postgres-1",
        )

    def test_k3s_exec_command(self) -> None:
        ad = tenant_cogs.ExecAdapter(
            kind="k3s", kubeconfig="/tmp/k.yaml", namespace="buzz-loadtest"
        )
        cmd = ad.exec_cmd("deploy/buzz", ["cat", "/sys/fs/cgroup/memory.current"])
        self.assertEqual(
            cmd,
            [
                "kubectl",
                "--kubeconfig",
                "/tmp/k.yaml",
                "-n",
                "buzz-loadtest",
                "exec",
                "deploy/buzz",
                "--",
                "cat",
                "/sys/fs/cgroup/memory.current",
            ],
        )

    def test_compose_up_command(self) -> None:
        ad = tenant_cogs.ComposeAdapter()
        self.assertEqual(
            ad.cmd("up", "-d")[:6],
            ["docker", "compose", "-p", "buzz-harness", "-f", "docker-compose.harness.yml"],
        )


class SchemaTests(unittest.TestCase):
    def fixture(self) -> dict:
        def comp() -> dict:
            return {
                "cpu_s": 1.0,
                "cpu_s_per_tenant_hour": 4.0,
                "cpu_s_per_1k_events": 0.1,
                "rss_bytes": {"p50": 10_000_000, "p95": 12_000_000, "max": 15_000_000},
            }

        band = {
            "seconds": 60,
            "samples": 12,
            "relay": comp(),
            "postgres": comp(),
            "redis": {
                "cpu_s": 0.1,
                "cpu_s_per_tenant_hour": 0.4,
                "rss_bytes": {"p50": 1, "p95": 1, "max": 1},
            },
            "minio": {
                "cpu_s": 0.1,
                "cpu_s_per_tenant_hour": 0.4,
                "rss_bytes": {"p50": 1, "p95": 1, "max": 1},
            },
            "stack": {"cpu_s": 1.2, "rss_bytes": {"p50": 20, "p95": 24, "max": 30}},
            "db": {
                "size_bytes": {"start": 1000, "end": 2000, "max": 2000},
                "wal_bytes": {"start": 100, "end": 200, "max": 200},
                "wal_gen_bytes_per_s": 1.0,
            },
            "objects": {"bytes": {"start": 0, "end": 10}, "count": {"start": 0, "end": 1}},
            "relay_metrics": {
                "events_received": 10,
                "events_stored": 10,
                "events_rejected": 0,
                "ws_connections_active": 30,
                "subscriptions_active": 210,
                "db_pool_waiters_max": 0,
                "db_pool_acquire_p95_s": 0.01,
                "backpressure_disconnects": 0,
                "fanout_recipients_p50": 5,
            },
            "client": {
                "sent": 10,
                "accepted": 10,
                "rejected": 0,
                "received": 10,
                "ok_ms": {"p50": 1, "p95": 2, "p99": 3, "max": 4},
                "fanout_ms": {"p50": 1, "p95": 2, "p99": 3, "max": 4},
            },
        }
        out = {
            "schema": 1,
            "run_id": "test-a",
            "substrate": "workstation-orbstack",
            "buzz_commit": "6e5c462",
            "buzz_image": "ghcr.io/block/buzz:sha-6e5c462",
            "harness_commit": "deadbee",
            "chart_version": None,
            "profile": "10h-20a",
            "profile_sha256": "abc",
            "machine_fingerprint": {},
            "relay_config": {},
            "bands": {
                "floor": json.loads(json.dumps(band)),
                "steady": json.loads(json.dumps(band)),
                "peak": json.loads(json.dumps(band)),
            },
            "totals": {
                "events": 30,
                "media_bytes": 0,
                "git_bytes": 0,
                "lost_after_backfill": 0,
                "db_bytes_per_1k_events": 1.0,
                "wal_high_water_bytes": 200,
                "objects_bytes_per_1k_events": 0.0,
            },
            "node": {"cpu_millicores_p95": None, "mem_bytes_p95": None, "k3s_overhead_bytes": None},
            "blink": None,
            "cost_usd": 0.0,
            "notes": "",
        }
        out["bands"]["floor"]["relay"]["rss_bytes"]["p50"] = 5_000_000
        out["bands"]["steady"]["relay"]["rss_bytes"]["p50"] = 10_000_000
        out["bands"]["peak"]["relay"]["rss_bytes"]["max"] = 20_000_000
        return out

    def test_validate_ok(self) -> None:
        line = self.fixture()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "results.jsonl"
            path.write_text(json.dumps(line) + "\n")
            self.assertEqual(cogs_report.cmd_validate(argparse_ns(results=str(path))), 0)

    def test_validate_missing_band(self) -> None:
        line = self.fixture()
        del line["bands"]["peak"]
        errs = cogs_report.validate_line(line, 1)
        self.assertTrue(any("peak" in e for e in errs))

    def test_report_emits_both_tiers(self) -> None:
        line = self.fixture()
        text = cogs_report.render_report(line)
        self.assertIn("relay.resources.requests.cpu", text)
        self.assertIn("declared_density", text)
        self.assertIn("4-vs-8", text)

    def test_density_includes_redis_minio(self) -> None:
        line = self.fixture()
        trial = cogs_report.proposed_values(line, "trial")
        self.assertIn("minio.resources.requests.memory", trial)
        self.assertIn("redis.resources.requests.cpu", trial)
        self.assertIn("minio.resources.requests.cpu", trial)
        dens = cogs_report.density(line, trial)
        self.assertIsInstance(dens["declared_density"], int)

    def test_image_commit_never_main(self) -> None:
        self.assertEqual(
            tenant_cogs.image_commit("ghcr.io/block/buzz:sha-6e5c462", inspect={}),
            "6e5c462",
        )
        commit, ref = tenant_cogs.resolve_buzz_identity(
            "ghcr.io/block/buzz:main", inspect={}
        )
        self.assertNotEqual(commit, "main")
        self.assertTrue(commit.startswith("unresolved-"))
        self.assertEqual(ref, "ghcr.io/block/buzz:main")
        digest_commit, digest_ref = tenant_cogs.resolve_buzz_identity(
            "ghcr.io/block/buzz:main",
            inspect={
                "RepoDigests": ["ghcr.io/block/buzz@sha256:abcd1234eeeeffff"],
                "Config": {"Labels": {"org.opencontainers.image.revision": "abcdef1deadbeef"}},
            },
        )
        self.assertEqual(digest_commit, "abcdef1")
        self.assertEqual(digest_ref, "ghcr.io/block/buzz@sha256:abcd1234eeeeffff")

    def test_acceptance_errors_on_rejects(self) -> None:
        line = self.fixture()
        summary = {
            "identities": {"humans": 10, "agents": 20},
            "lost_after_backfill": 0,
            "media": {"uploads": 3, "rejected": 0},
            "git": {"pushes": 1, "failed": 0},
        }
        self.assertEqual(tenant_cogs.acceptance_errors(line, summary, 0), [])
        bad = json.loads(json.dumps(line))
        bad["bands"]["steady"]["relay_metrics"]["events_rejected"] = 27
        errs = tenant_cogs.acceptance_errors(bad, summary, 0)
        self.assertTrue(any("events_rejected" in e for e in errs))


class HistogramQuantileTests(unittest.TestCase):
    def test_band_local_p50_ignores_prior_lifetime(self) -> None:
        # Warmup: 100 observations all ≤ 1. Floor adds 100 observations all > 10.
        warmup = [{"le": 1.0, "c": 100.0}, {"le": 10.0, "c": 100.0}, {"le": "+Inf", "c": 100.0}]
        floor_end = [{"le": 1.0, "c": 100.0}, {"le": 10.0, "c": 100.0}, {"le": "+Inf", "c": 200.0}]
        samples = [
            {
                "band": "warmup",
                "sampled": False,
                "t_unix": 1,
                "metrics": {"fanout_recipients_buckets": warmup},
            },
            {
                "band": "floor",
                "sampled": True,
                "t_unix": 2,
                "metrics": {"fanout_recipients_buckets": floor_end},
                "relay": {"rss": 10, "usage_usec": 10},
                "postgres": {"rss": 10, "usage_usec": 10},
                "redis": {"rss": 1, "usage_usec": 1},
                "minio": {"rss": 1, "usage_usec": 1},
            },
            {
                "band": "floor",
                "sampled": True,
                "t_unix": 12,
                "metrics": {"fanout_recipients_buckets": floor_end},
                "relay": {"rss": 10, "usage_usec": 20},
                "postgres": {"rss": 10, "usage_usec": 20},
                "redis": {"rss": 1, "usage_usec": 2},
                "minio": {"rss": 1, "usage_usec": 2},
            },
        ]
        lifetime = tenant_cogs.histogram_quantile(
            tenant_cogs.histogram_buckets_from_json(floor_end), 0.50
        )
        self.assertAlmostEqual(lifetime or -1.0, 1.0, places=6)
        delta = tenant_cogs.band_histogram_delta(samples, "floor")
        band_p50 = tenant_cogs.histogram_quantile(delta, 0.50)
        self.assertIsNotNone(band_p50)
        self.assertAlmostEqual(band_p50 or 0.0, 10.0, places=6)
        stats = tenant_cogs.band_stats(samples, "floor", None)
        self.assertAlmostEqual(stats["relay_metrics"]["fanout_recipients_p50"], 10.0, places=6)


class TimeoutTests(unittest.TestCase):
    def _silent(self, sleep_s: float) -> subprocess.Popen:
        return subprocess.Popen(
            [sys.executable, "-c", f"import time; time.sleep({sleep_s})"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    def test_wait_ready_honors_short_timeout(self) -> None:
        proc = self._silent(2.0)
        t0 = time.monotonic()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                tenant_cogs.wait_ready_line(proc, timeout_s=0.1)
            self.assertIn("timed out", str(ctx.exception))
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 0.8, f"timeout took {elapsed:.3f}s")
        finally:
            proc.kill()
            proc.wait(timeout=2)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    def test_collect_summary_honors_short_timeout(self) -> None:
        proc = self._silent(2.0)
        t0 = time.monotonic()
        try:
            out = tenant_cogs.collect_summary(proc, timeout_s=0.1)
            elapsed = time.monotonic() - t0
            self.assertEqual(out, {})
            self.assertLess(elapsed, 0.8, f"timeout took {elapsed:.3f}s")
        finally:
            proc.kill()
            proc.wait(timeout=2)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    def test_wait_ready_accepts_ready_line(self) -> None:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-c",
                "import json,sys,time; print(json.dumps({'phase':'ready'}), flush=True); time.sleep(2)",
            ],
            stdout=subprocess.PIPE,
            bufsize=0,
        )
        try:
            tenant_cogs.wait_ready_line(proc, timeout_s=1.0)
        finally:
            proc.kill()
            proc.wait(timeout=2)
            if proc.stdout:
                proc.stdout.close()


class TeardownTests(unittest.TestCase):
    def test_run_session_tears_down_on_exception(self) -> None:
        class Adapter:
            def __init__(self) -> None:
                self.torn = 0

            def teardown(self) -> None:
                self.torn += 1

        class Proc:
            def __init__(self) -> None:
                self.killed = False
                self._code = None

            def poll(self):
                return self._code

            def kill(self) -> None:
                self.killed = True
                self._code = -9

            def wait(self, timeout=None):
                return self._code

        adapter = Adapter()
        proc = Proc()
        with self.assertRaises(RuntimeError):
            with tenant_cogs.RunSession(adapter, keep=False) as session:
                session.proc = proc  # type: ignore[assignment]
                raise RuntimeError("ready failed")
        self.assertTrue(proc.killed)
        self.assertEqual(adapter.torn, 1)

    def test_run_session_keep_skips_teardown(self) -> None:
        class Adapter:
            def __init__(self) -> None:
                self.torn = 0

            def teardown(self) -> None:
                self.torn += 1

        adapter = Adapter()
        with tenant_cogs.RunSession(adapter, keep=True):
            pass
        self.assertEqual(adapter.torn, 0)


VARS = tenant_cogs.RATE_LIMIT_VARS


class SetupRateLimitTests(unittest.TestCase):
    def test_tenant_sim_env_drops_caller_credentials(self) -> None:
        env = {
            "PATH": "/usr/bin",
            "BUZZ_AUTH_TAG": '["auth","o","","s"]',
            "BUZZ_PRIVATE_KEY": "k",
            "NOSTR_PRIVATE_KEY": "n",
            "BUZZ_IMAGE": "img",
        }
        out = tenant_cogs.child_env(env)
        self.assertEqual(out, {"PATH": "/usr/bin"})
        with mock.patch.dict(os.environ, {"BUZZ_AUTH_TAG": "x"}):
            self.assertNotIn("BUZZ_AUTH_TAG", tenant_cogs.child_env())

    def test_raised_env_covers_every_var(self) -> None:
        env = tenant_cogs.raised_limit_env(500)
        self.assertEqual(sorted(env), sorted(VARS))
        self.assertTrue(all(v == "500" for v in env.values()))
        self.assertEqual(tenant_cogs.raised_limit_env(0), {})

    def test_adapter_never_inherits_shell_overrides(self) -> None:
        with mock.patch.dict(os.environ, {VARS[0]: "7"}):
            ad = tenant_cogs.ComposeAdapter(env={"BUZZ_IMAGE": "img"})
        self.assertNotIn(VARS[0], ad.env)
        self.assertEqual(ad.env["BUZZ_IMAGE"], "img")

    def test_up_raises_then_recreate_restores_defaults(self) -> None:
        calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd, **kw):
            calls.append((cmd, dict(kw.get("env") or {})))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        ad = tenant_cogs.ComposeAdapter(env={"SIM_RELAY_KEY": "k"})
        with mock.patch.object(tenant_cogs, "run", fake_run):
            ad.up(tenant_cogs.raised_limit_env(1000))
            ad.recreate_relay()
        (up_cmd, up_env), (re_cmd, re_env) = calls
        self.assertEqual(up_cmd[-2:], ["up", "-d"])
        for name in VARS:
            self.assertEqual(up_env[name], "1000")
            self.assertNotIn(name, re_env)
        self.assertEqual(re_cmd[-5:], ["up", "-d", "--no-deps", "--force-recreate", "relay"])
        # Same per-run keys across the restart.
        self.assertEqual(up_env["SIM_RELAY_KEY"], "k")
        self.assertEqual(re_env["SIM_RELAY_KEY"], "k")

    def test_overrides_read_from_container_env(self) -> None:
        env = ["PATH=/usr/bin", f"{VARS[0]}=9", "BUZZ_BIND_ADDR=0.0.0.0:3030"]
        self.assertEqual(tenant_cogs.rate_limit_overrides(env), {VARS[0]: "9"})
        self.assertEqual(tenant_cogs.rate_limit_overrides([]), {})

    def test_resolve_setup_rate_limit(self) -> None:
        def ns(**kw):
            base = {"substrate": "compose", "skip_reset": False, "setup_rate_limit": None}
            base.update(kw)
            return argparse_ns(**base)

        resolve = tenant_cogs.resolve_setup_rate_limit
        self.assertEqual(resolve(ns()), tenant_cogs.DEFAULT_SETUP_RATE_LIMIT)
        self.assertEqual(resolve(ns(skip_reset=True)), 0)
        self.assertEqual(resolve(ns(substrate="k3s")), 0)
        self.assertEqual(resolve(ns(setup_rate_limit=0)), 0)
        self.assertEqual(resolve(ns(setup_rate_limit=250)), 250)
        for bad in (
            ns(substrate="k3s", setup_rate_limit=5),
            ns(skip_reset=True, setup_rate_limit=5),
            ns(setup_rate_limit=-1),
        ):
            with self.assertRaises(SystemExit):
                resolve(bad)

    def test_results_line_records_setup_and_band_limits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            line = tenant_cogs.write_results_line(
                Path(td) / "results.jsonl",
                run_id="r",
                substrate="workstation-orbstack",
                buzz_commit="abc1234",
                buzz_image="img@sha256:00",
                harness_commit="def5678",
                profile="p",
                profile_sha="x",
                fingerprint={},
                samples=[],
                summary={},
                notes="",
                setup={
                    "rate_limit": 1000,
                    "band_rate_limits": "relay-default",
                    "provision": {"events": 216, "rate_limited": 0, "seconds": 3.0},
                },
            )
        self.assertEqual(line["relay_config"]["setup_rate_limit"], 1000)
        self.assertEqual(line["relay_config"]["band_rate_limits"], "relay-default")
        self.assertEqual(line["setup"]["events"], 216)
        self.assertEqual(cogs_report.validate_line(line, 1), [])


class ProfileMetaTests(unittest.TestCase):
    def test_bands_under_a_commented_section_header(self) -> None:
        # The shipped profiles write `[bands]   # seconds`; a line parser that
        # needs the header to end in `]` silently kept the defaults.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p.toml"
            path.write_text(
                '[profile]   # who\nname = "short"\n\n'
                "[bands]                        # seconds\n"
                "warmup  = 30   # not sampled\nfloor = 60\nsteady = 120\n"
                "peak = 45\ncooldown= 20\n"
            )
            name, sha, bands = tenant_cogs.load_profile_meta(path)
        self.assertEqual(name, "short")
        self.assertEqual(len(sha), 64)
        self.assertEqual(
            bands, {"warmup": 30, "floor": 60, "steady": 120, "peak": 45, "cooldown": 20}
        )

    def test_shipped_profile_parses(self) -> None:
        path = Path(__file__).resolve().parent / "profiles" / "10h-20a.toml"
        name, _, bands = tenant_cogs.load_profile_meta(path)
        self.assertEqual(name, "10h-20a")
        self.assertEqual(bands["floor"], 600)


class PhaseLineTests(unittest.TestCase):
    def _emit(self, objs: list[dict], then: str = "time.sleep(2)") -> subprocess.Popen:
        body = "; ".join(f"print(json.dumps({o!r}), flush=True)" for o in objs)
        return subprocess.Popen(
            [sys.executable, "-u", "-c", f"import json, sys, time; {body}; {then}"],
            stdout=subprocess.PIPE,
            bufsize=0,
        )

    def _close(self, proc: subprocess.Popen) -> None:
        proc.kill()
        proc.wait(timeout=2)
        if proc.stdout:
            proc.stdout.close()

    def test_setup_done_then_ready_in_order(self) -> None:
        proc = self._emit(
            [
                {"phase": "seed-start"},
                {"phase": "setup-done", "provision": {"events": 3}},
                {"phase": "ready"},
            ]
        )
        try:
            got = tenant_cogs.wait_phase_line(proc, "setup-done", 2.0)
            self.assertEqual(got["provision"]["events"], 3)
            tenant_cogs.wait_ready_line(proc, 2.0)
        finally:
            self._close(proc)

    def test_exit_before_phase_is_an_error(self) -> None:
        proc = self._emit([{"phase": "setup-done"}], then="sys.exit(3)")
        try:
            with self.assertRaises(RuntimeError) as ctx:
                tenant_cogs.wait_phase_line(proc, "ready", 5.0)
            self.assertIn("exited 3 before ready", str(ctx.exception))
        finally:
            self._close(proc)


class SeedBenchTests(unittest.TestCase):
    def test_rates_come_from_relay_side_deltas(self) -> None:
        before = {
            "t": 100.0,
            "stored_rows": 1000,
            "wal_lsn_bytes": 0,
            "db_size_bytes": 10_000_000,
            "relay_usage_usec": 0,
            "postgres_usage_usec": 0,
        }
        after = {
            "t": 110.0,
            "stored_rows": 6000,
            "wal_lsn_bytes": 5_000_000,
            "db_size_bytes": 13_000_000,
            "relay_usage_usec": 15_000_000,
            "postgres_usage_usec": 5_000_000,
        }
        r = tenant_cogs.seed_bench_result(
            "raised", {"acked": 5000, "acked_per_s": 480.0}, before, after
        )
        self.assertEqual(r["stored_rows"], 5000)
        self.assertAlmostEqual(r["stored_per_s"], 500.0)
        self.assertAlmostEqual(r["acked_per_s"], 480.0)
        self.assertAlmostEqual(r["wal_bytes_per_stored"], 1000.0)
        self.assertAlmostEqual(r["db_bytes_per_stored"], 600.0)
        self.assertAlmostEqual(r["relay_cores"], 1.5)
        self.assertAlmostEqual(r["postgres_cores"], 0.5)

    def test_missing_counters_stay_null(self) -> None:
        snap = {"t": 1.0, "stored_rows": None, "wal_lsn_bytes": None}
        later = {"t": 2.0, "stored_rows": None, "wal_lsn_bytes": 10}
        r = tenant_cogs.seed_bench_result("default", {}, snap, later)
        self.assertIsNone(r["stored_per_s"])
        self.assertIsNone(r["wal_bytes_per_stored"])
        self.assertIsNone(r["relay_cores"])


def argparse_ns(**kwargs):
    class N:
        pass

    n = N()
    for k, v in kwargs.items():
        setattr(n, k, v)
    return n


if __name__ == "__main__":
    unittest.main()
