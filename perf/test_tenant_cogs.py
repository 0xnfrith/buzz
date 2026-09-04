#!/usr/bin/env python3
"""Unit tests for tenant_cogs / cogs_report (stdlib unittest)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

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

    def test_fanout_histogram_sum_count(self) -> None:
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
            tenant_cogs.histogram_p50_from_sum_count(
                parsed["fanout_recipients_sum"], parsed["fanout_recipients_count"]
            ),
            4.0,
        )


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


def argparse_ns(**kwargs):
    class N:
        pass

    n = N()
    for k, v in kwargs.items():
        setattr(n, k, v)
    return n


if __name__ == "__main__":
    unittest.main()
