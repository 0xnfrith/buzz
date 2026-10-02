#!/usr/bin/env python3
"""Unit tests for tenant_cogs / cogs_report (stdlib unittest)."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cogs_report
import tenant_cogs
from planted_env import assert_names, parent_env, test_env

_LOCK_TMP: tempfile.TemporaryDirectory | None = None
_REAL_LOCK_DIR = tenant_cogs.LOCK_DIR
# Valid target-guard flags (loopback allowed, empty deny list), so a test that
# expects some other refusal is not refused by the guard first.
GUARD_ARGV: list[str] = []
# A real Unix socket the tests treat as the local Docker endpoint, and the
# environment patch that selects it, so no test depends on this machine's
# Docker setup.
_DOCKER_SOCK: socket.socket | None = None
_DOCKER_ENV: "mock._patch | None" = None
TEST_EP = tenant_cogs.DockerEndpoint("unix:///nonexistent")


def setUpModule() -> None:
    global _LOCK_TMP
    _LOCK_TMP = tempfile.TemporaryDirectory()
    tenant_cogs.LOCK_DIR = Path(_LOCK_TMP.name) / "locks"
    deny = Path(_LOCK_TMP.name) / "deny-empty.txt"
    deny.write_text("")
    GUARD_ARGV[:] = ["--allow-cidr", "127.0.0.0/8", "--deny-list", str(deny)]
    global _DOCKER_SOCK, _DOCKER_ENV, TEST_EP
    path = Path(_LOCK_TMP.name) / "d.sock"
    _DOCKER_SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _DOCKER_SOCK.bind(str(path))
    TEST_EP = tenant_cogs.DockerEndpoint(f"unix://{path}")
    _DOCKER_ENV = mock.patch.dict(os.environ, {"DOCKER_HOST": TEST_EP})
    _DOCKER_ENV.start()
    os.environ.pop("DOCKER_CONTEXT", None)


def tearDownModule() -> None:
    tenant_cogs.LOCK_DIR = _REAL_LOCK_DIR
    if _DOCKER_ENV is not None:
        _DOCKER_ENV.stop()
    if _DOCKER_SOCK is not None:
        _DOCKER_SOCK.close()
    if _LOCK_TMP is not None:
        _LOCK_TMP.cleanup()


def locked_adapter(case: unittest.TestCase, project: str, files=("a.yml",), env=None):
    """An adapter holding its project's lock, released when the test ends."""
    lock = tenant_cogs.ProjectLock(project)
    case.addCleanup(lock.release)
    return tenant_cogs.ComposeAdapter(project, files, env=env or {}, lock=lock, endpoint=TEST_EP)


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


# memory.stat as read from a relay container during a run (trimmed).
RELAY_MEMORY_STAT = """anon 23572480
file 18722816
kernel 0
shmem 0
file_mapped 4296704
inactive_anon 14790656
active_anon 9048064
inactive_file 6262784
active_file 12460032
"""


class MemoryStatTests(unittest.TestCase):
    def test_working_set_subtracts_inactive_file(self) -> None:
        stat = tenant_cogs.parse_memory_stat(RELAY_MEMORY_STAT)
        self.assertEqual(
            stat,
            {
                "anon": 23572480,
                "file": 18722816,
                "shmem": 0,
                "inactive_file": 6262784,
                "active_file": 12460032,
            },
        )
        # memory.current 43577344 - inactive_file 6262784; docker stats read 35.46 MiB.
        self.assertEqual(tenant_cogs.working_set(43577344, stat), 37314560)

    def test_working_set_needs_both_inputs(self) -> None:
        self.assertIsNone(tenant_cogs.working_set(43577344, {"anon": 1}))
        self.assertIsNone(tenant_cogs.working_set(None, {"inactive_file": 1}))
        self.assertEqual(tenant_cogs.working_set(10, {"inactive_file": 20}), 0)

    def test_cgroup_records_working_set_and_raw_figures(self) -> None:
        ad = tenant_cogs.ExecAdapter(kind="compose", project="buzz-harness", endpoint=TEST_EP)
        files = {
            "/sys/fs/cgroup/cpu.stat": "usage_usec 500\n",
            "/sys/fs/cgroup/memory.current": "43577344\n",
            "/sys/fs/cgroup/memory.stat": RELAY_MEMORY_STAT,
        }
        with mock.patch.object(ad, "exec", side_effect=lambda _svc, args: files[args[1]]):
            cg = ad.cgroup("relay")
        self.assertEqual(
            cg,
            {
                "usage_usec": 500,
                "rss": 37314560,
                "rss_anon": 23572480,
                "mem_current": 43577344,
                "mem_file": 18722816,
                "mem_active_file": 12460032,
                "mem_inactive_file": 6262784,
                "mem_shmem": 0,
            },
        )

    def test_band_reports_anon_beside_working_set(self) -> None:
        def row(t: int, rss: int, anon: int) -> dict:
            comp = {"rss": rss, "rss_anon": anon, "usage_usec": t}
            return {
                "band": "floor",
                "sampled": True,
                "t_unix": t,
                "relay": comp,
                "postgres": comp,
                "redis": comp,
                "minio": comp,
            }

        rows = [row(1, 40, 10), row(6, 50, 12), row(11, 45, 14)]
        stats = tenant_cogs.band_stats(rows, "floor", None)
        self.assertEqual(stats["relay"]["rss_bytes"], {"p50": 45.0, "p95": 50.0, "max": 50.0})
        self.assertEqual(stats["relay"]["rss_samples"], 3)
        self.assertEqual(stats["relay"]["anon_bytes"], {"p50": 12.0, "p95": 14.0, "max": 14.0})


class AdapterCommandTests(unittest.TestCase):
    def test_compose_exec_command(self) -> None:
        ad = tenant_cogs.ExecAdapter(kind="compose", project="buzz-harness", endpoint=TEST_EP)
        self.assertEqual(
            ad.exec_cmd("relay", ["cat", "/sys/fs/cgroup/cpu.stat"]),
            ["docker", "--host", TEST_EP, "exec", "buzz-harness-relay-1", "cat", "/sys/fs/cgroup/cpu.stat"],
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
        ad = tenant_cogs.ComposeAdapter("buzz-harness-t1", endpoint=TEST_EP)
        self.assertEqual(
            ad.cmd("up", "-d")[:8],
            ["docker", "--host", TEST_EP, "compose", "-p", "buzz-harness-t1", "-f", "docker-compose.harness.yml"],
        )


class SchemaTests(unittest.TestCase):
    def fixture(self) -> dict:
        def comp() -> dict:
            return {
                "cpu_s": 1.0,
                "cpu_s_per_tenant_hour": 4.0,
                "cpu_s_per_1k_events": 0.1,
                "rss_bytes": {"p50": 10_000_000, "p95": 12_000_000, "max": 15_000_000},
                "rss_samples": 12,
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
        # Floor is idle clients: heartbeats only, nothing stored.
        out["bands"]["floor"]["relay_metrics"]["events_stored"] = 0
        out["bands"]["floor"]["client"]["sent_by_kind"] = {"20001": 9, "20002": 1}
        out["bands"]["steady"]["relay"]["rss_bytes"]["p50"] = 10_000_000
        out["bands"]["peak"]["relay"]["rss_bytes"]["max"] = 20_000_000
        return out

    def test_validate_ok(self) -> None:
        line = self.fixture()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "results.jsonl"
            path.write_text(json.dumps(line) + "\n")
            self.assertEqual(cogs_report.cmd_validate(argparse_ns(results=str(path))), 0)

    def test_report_flags_emulated_services(self) -> None:
        line = self.fixture()
        self.assertNotIn("emulated", cogs_report.render_report(line))
        line["machine_fingerprint"] = {"docker_arch": "aarch64", "emulated": ["minio", "minio-init"]}
        self.assertIn(
            "**emulated:** minio, minio-init ran as linux/amd64 on aarch64",
            cogs_report.render_report(line),
        )

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

    def test_pg_pvc_scales_growth_not_wal_cap(self) -> None:
        gib = 1024 * 1024 * 1024
        line = self.fixture()
        for name in ("floor", "steady", "peak"):
            line["bands"][name]["seconds"] = 28800  # the three bands span one day
        line["bands"]["floor"]["db"]["size_bytes"]["start"] = 1 * gib
        line["bands"]["peak"]["db"]["size_bytes"]["end"] = 2 * gib
        # 1 GiB/day for a year = 365 GiB; x 1.2 = 438 GiB; plus the WAL cap once.
        trial = cogs_report.proposed_values(line, "trial")  # max_wal 256 MiB
        reference = cogs_report.proposed_values(line, "reference")  # max_wal 1 GiB
        self.assertEqual(trial["postgresql.persistence.size"], "439Gi")
        self.assertEqual(reference["postgresql.persistence.size"], "439Gi")
        self.assertEqual(trial["raw"]["retention_factor"], 182.5)

    def test_report_labels_memory_sources(self) -> None:
        line = self.fixture()
        line["bands"]["floor"]["relay"]["anon_bytes"] = {"p50": 2 * 1024 * 1024, "p95": 0, "max": 3 * 1024 * 1024}
        text = cogs_report.render_report(line)
        self.assertIn("memory.current − inactive_file", text)
        self.assertIn("| floor (idle, heartbeats only) | 5/11/14 Mi | 2/3 Mi |", text)
        self.assertIn("| steady | 10/11/14 Mi | n/a/n/a Mi |", text)
        self.assertIn("| measured from |", text)
        self.assertIn("steady relay CPU × 1.5", text)
        for key in cogs_report.proposed_values(line, "trial"):
            if key not in {"tier", "raw"}:
                self.assertIn(key, cogs_report.VALUE_SOURCES)

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
            "reads": {"reads": 0, "failed": 0},
            "git": {"pushes": 1, "failed": 0},
        }
        self.assertEqual(tenant_cogs.acceptance_errors(line, summary, 0), [])
        bad = json.loads(json.dumps(line))
        bad["bands"]["steady"]["relay_metrics"]["events_rejected"] = 27
        errs = tenant_cogs.acceptance_errors(bad, summary, 0)
        self.assertTrue(any("events_rejected" in e for e in errs))

    def test_rate_limits_are_carried_apart_and_never_an_acceptance_error(self) -> None:
        summary = {"bands": {"steady": {"sent": 9, "accepted": 4, "rejected": 0, "rate_limited": 5, "received": 3,
                                        "reads": 12, "read_ms": {"p50": 3, "p95": 9, "p99": 9, "max": 9}}}}
        client = tenant_cogs.client_from_summary(summary, "steady")
        self.assertEqual((client["rejected"], client["rate_limited"], client["reads"], client["read_ms"]["p95"]), (0, 5, 12, 9))
        line = self.fixture()
        line["bands"]["steady"]["client"]["rate_limited"] = 5
        self.assertEqual(tenant_cogs.acceptance_errors(line, self.summary_ok(), 0), [])

    def test_sends_unanswered_or_not_sent_fail_acceptance(self) -> None:
        """A send the relay never answered, one that failed before it was
        written, one the relay shed, and one answered with an unknown limit,
        each fail a local run: none is a reject, so the rejected gate alone
        would pass them."""
        rows = [
            ({"unanswered": 0, "failed": 0}, []),
            ({"unanswered": 3, "failed": 0}, ["steady client unanswered=3"]),
            ({"unanswered": 0, "failed": 2}, ["steady client failed=2"]),
            # Shed by the relay, or a limit text the pinned relay doesn't
            # send: neither is the quota, which alone is apart.
            ({"shed": 4}, ["steady client shed=4"]),
            ({"limit_unknown": 1}, ["steady client limit_unknown=1"]),
        ]
        for counts, want in rows:
            with self.subTest(counts=counts):
                summary = {"bands": {"steady": {"sent": 10, "accepted": 10 - sum(counts.values()), "rejected": 0, **counts}}}
                line = self.fixture()
                line["bands"]["steady"]["client"] = tenant_cogs.client_from_summary(summary, "steady")
                self.assertEqual(tenant_cogs.acceptance_errors(line, self.summary_ok(), 0), want)

    def test_a_run_seeds_its_days_and_reads_what_the_seed_did(self) -> None:
        """--seed-days goes to tenant_sim; the run waits for seed-start,
        seed-done, then setup-done, and keeps what the seed asked and got."""
        args = tenant_cogs.build_parser().parse_args(["run", "--substrate", "compose", "--seed-days", "90"])
        self.assertEqual(tenant_cogs.seed_flags(args), ["--seed-days", "90", "--seed-max-seconds", "1800"])
        none = tenant_cogs.build_parser().parse_args(["run", "--substrate", "compose"])
        self.assertEqual(tenant_cogs.seed_flags(none), [])
        lines = [
            {"phase": "seed-start", "t_unix_ms": 1, "events": 207335, "days": 90},
            {"other": "a log line"},
            {"phase": "seed-done", "t_unix_ms": 2, "seed": {"requested": 207335, "acked": 207335, "rejected": 0, "errors": 0, "seconds": 61.5}},
            {"phase": "setup-done", "provision": {"events": 300}},
        ]
        script = "".join(f"echo '{json.dumps(l)}'\n" for l in lines)
        proc = subprocess.Popen(["/bin/sh", "-c", script], stdout=subprocess.PIPE, env=test_env())
        try:
            setup, seed = tenant_cogs.wait_setup(proc, True, 10, 10)
        finally:
            proc.wait()
        self.assertEqual(setup["provision"], {"events": 300})
        self.assertEqual((seed["days"], seed["events"], seed["acked"], seed["seconds"]), (90, 207335, 207335, 61.5))
        self.assertEqual(tenant_cogs.seed_errors(seed), [])
        self.assertEqual(tenant_cogs.seed_errors(None), [])

    def test_a_short_seed_is_an_acceptance_error(self) -> None:
        seed = {"days": 90, "events": 207335, "acked": 150000, "rejected": 0, "errors": 3}
        self.assertEqual(tenant_cogs.seed_errors(seed),
                         ["seed: 150000 of 207335 events acknowledged (rejected 0, errors 3)"])

    def test_reads_gate_acceptance(self) -> None:
        """A local run fails acceptance on any failed read, and when agents
        took turns but no read was answered; a summary without reads is
        refused."""
        line = self.fixture()
        rows = [
            ({"reads": 40, "failed": 0}, {"44200": 12}, []),
            ({"reads": 39, "failed": 1}, {"44200": 12}, ["reads.failed=1"]),
            ({"reads": 0, "failed": 0}, {"44200": 12}, ["agents took 12 turns but no read was answered"]),
            ({"reads": 0, "failed": 0}, {}, []),
            (None, {}, ["reads missing from the summary"]),
        ]
        for reads, kinds, want in rows:
            with self.subTest(reads=reads, kinds=kinds):
                summary = {**self.summary_ok(), "sent_by_kind": kinds}
                if reads is None:
                    summary.pop("reads")
                else:
                    summary["reads"] = reads
                self.assertEqual(tenant_cogs.acceptance_errors(line, summary, 0), want)

    def summary_ok(self) -> dict:
        return {
            "identities": {"humans": 10, "agents": 20},
            "media": {"uploads": 3, "rejected": 0},
            "reads": {"reads": 0, "failed": 0},
            "git": {"pushes": 2, "failed": 0},
        }

    def test_band_order_is_a_note_not_a_gate(self) -> None:
        # A valid paid run must not fail because the relay's working set
        # didn't rise floor < steady < peak.
        line = self.fixture()
        line["bands"]["floor"]["relay"]["rss_bytes"]["p50"] = 30_000_000
        line["bands"]["steady"]["relay"]["rss_bytes"]["p50"] = 10_000_000
        self.assertEqual(tenant_cogs.acceptance_errors(line, self.summary_ok(), 0), [])
        self.assertEqual(
            tenant_cogs.band_order_note(line),
            "band order: not distinct (relay working set floor p50=30000000 steady p50=10000000 peak max=20000000)",
        )
        self.assertEqual(
            tenant_cogs.band_order_note(self.fixture()),
            "band order: distinct (relay working set rises floor < steady < peak)",
        )

    def test_each_sampled_band_needs_three_working_set_samples(self) -> None:
        for name in ("floor", "steady", "peak"):
            with self.subTest(band=name):
                line = self.fixture()
                line["bands"][name]["relay"]["rss_samples"] = 2
                self.assertEqual(
                    tenant_cogs.acceptance_errors(line, self.summary_ok(), 0),
                    [f"{name}: 2 samples with the relay's working set, fewer than 3"],
                )
                del line["bands"][name]["relay"]["rss_samples"]
                self.assertEqual(
                    tenant_cogs.acceptance_errors(line, self.summary_ok(), 0),
                    [f"{name}: 0 samples with the relay's working set, fewer than 3"],
                )

    def test_floor_must_be_idle(self) -> None:
        summary = {
            "identities": {"humans": 10, "agents": 20},
            "media": {"uploads": 3, "rejected": 0},
            "reads": {"reads": 0, "failed": 0},
            "git": {"pushes": 1, "failed": 0},
        }
        line = self.fixture()
        self.assertEqual(tenant_cogs.acceptance_errors(line, summary, 0), [])

        chatty = json.loads(json.dumps(line))
        chatty["bands"]["floor"]["client"]["sent_by_kind"]["9"] = 2
        chatty["bands"]["floor"]["client"]["sent"] += 2
        self.assertEqual(
            tenant_cogs.acceptance_errors(chatty, summary, 0),
            ["floor sent non-heartbeat kinds {'9': 2}"],
        )

        stored = json.loads(json.dumps(line))
        stored["bands"]["floor"]["relay_metrics"]["events_stored"] = 3
        self.assertEqual(
            tenant_cogs.acceptance_errors(stored, summary, 0),
            ["floor relay events_stored=3, expected 0"],
        )

        unknown = json.loads(json.dumps(line))
        del unknown["bands"]["floor"]["client"]["sent_by_kind"]
        self.assertEqual(
            tenant_cogs.acceptance_errors(unknown, summary, 0),
            ["floor client.sent_by_kind missing"],
        )

    def test_floor_kind_map_must_cover_every_send(self) -> None:
        summary = {
            "identities": {"humans": 10, "agents": 20},
            "media": {"uploads": 3, "rejected": 0},
            "reads": {"reads": 0, "failed": 0},
            "git": {"pushes": 1, "failed": 0},
        }
        line = self.fixture()
        line["bands"]["floor"]["client"]["sent"] = 330
        line["bands"]["floor"]["client"]["sent_by_kind"] = {}
        self.assertEqual(
            tenant_cogs.acceptance_errors(line, summary, 0),
            ["floor sent_by_kind covers 0 of 330 sends"],
        )
        line["bands"]["floor"]["client"]["sent_by_kind"] = {"20001": 329}
        self.assertEqual(
            tenant_cogs.acceptance_errors(line, summary, 0),
            ["floor sent_by_kind covers 329 of 330 sends"],
        )
        line["bands"]["floor"]["client"]["sent_by_kind"] = {"20001": 330}
        self.assertEqual(tenant_cogs.acceptance_errors(line, summary, 0), [])


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
            env=test_env(),
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
            env=test_env(),
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


    def test_teardown_failure_fails_a_clean_run(self) -> None:
        class Adapter:
            def teardown(self) -> None:
                raise RuntimeError("volume still in use")

        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as cm:
                with tenant_cogs.RunSession(Adapter(), keep=False):
                    pass
        self.assertEqual(cm.exception.code, 1)

    def test_teardown_failure_keeps_the_original_error(self) -> None:
        class Adapter:
            def teardown(self) -> None:
                raise RuntimeError("volume still in use")

        with mock.patch("sys.stderr"):
            with self.assertRaisesRegex(RuntimeError, "ready failed"):
                with tenant_cogs.RunSession(Adapter(), keep=False):
                    raise RuntimeError("ready failed")

    def test_teardown_is_a_no_op_unless_this_process_ran_up(self) -> None:
        def forbidden(*a, **k):
            raise AssertionError("no docker call expected")

        ad = tenant_cogs.ComposeAdapter("buzz-harness-t1", ("a.yml",), env={}, endpoint=TEST_EP)
        with mock.patch.object(tenant_cogs, "run", forbidden):
            ad.teardown()
            with tenant_cogs.RunSession(ad, keep=False):
                pass


class FloorPipelineTests(unittest.TestCase):
    """The floor gate reads what tenant_sim reported, through the results line."""

    def line_from(self, summary: dict) -> dict:
        comp = {"rss": 10, "rss_anon": 5, "usage_usec": 1}
        metrics = {"ws_connections_active": 30.0, "events_stored_total": 4.0}
        rows = [
            {"band": "floor", "sampled": True, "t_unix": t, "metrics": metrics,
             "relay": comp, "postgres": comp, "redis": comp, "minio": comp}
            for t in (1, 6)
        ]
        with tempfile.TemporaryDirectory() as td:
            return tenant_cogs.write_results_line(
                Path(td) / "results.jsonl",
                run_id="r", substrate="s", buzz_commit="c", buzz_image="i",
                harness_commit="h", profile="p", profile_sha="x", fingerprint={},
                samples=rows, summary=summary, notes="",
            )

    def test_floor_kinds_reach_the_gate(self) -> None:
        floor = {"sent": 30, "accepted": 30, "rejected": 0, "received": 0,
                 "sent_by_kind": {"20001": 30}}
        line = self.line_from({"bands": {"floor": floor}})
        self.assertEqual(line["bands"]["floor"]["client"]["sent_by_kind"], {"20001": 30})
        self.assertEqual(line["bands"]["floor"]["relay_metrics"]["events_stored"], 0)
        self.assertEqual(tenant_cogs.floor_errors(line["bands"]["floor"]), [])

    def test_unreported_kinds_fail_closed(self) -> None:
        floor = {"sent": 30, "accepted": 30, "rejected": 0, "received": 0}
        line = self.line_from({"bands": {"floor": floor}})
        self.assertEqual(
            tenant_cogs.floor_errors(line["bands"]["floor"]),
            ["floor client.sent_by_kind missing"],
        )


class FakeDocker:
    """Just enough docker for the adapter: per-project state, every call recorded."""

    LS = {"ps": "containers", "volume": "volumes", "network": "networks"}

    def __init__(self, state: dict | None = None, fail_down: bool = False) -> None:
        self.state = {k: dict(v) for k, v in (state or {}).items()}
        self.calls: list[list[str]] = []
        self.fail_down = fail_down

    def run(self, cmd, check=True, capture=True, env=None, timeout=None):
        # Every docker call names the checked endpoint; record it without.
        assert cmd[1:3] == ["--host", TEST_EP], cmd
        cmd = ["docker", *cmd[3:]]
        self.calls.append(cmd)
        out = ""
        if cmd[:2] == ["docker", "compose"]:
            project, action = cmd[3], cmd[cmd.index("-f") + 2 :]
            if action[:2] == ["up", "-d"] and len(action) == 2:
                self.state[project] = {
                    "containers": [f"{project}-relay-1"],
                    "volumes": [f"{project}_data"],
                    "networks": [f"{project}_default"],
                }
            elif action[0] == "down":
                if self.fail_down:
                    raise subprocess.CalledProcessError(1, cmd)
                self.state.pop(project, None)
        elif cmd[1] in self.LS:
            project = cmd[-1].rsplit("=", 1)[1]
            out = "\n".join(self.state.get(project, {}).get(self.LS[cmd[1]], []))
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    def projects_touched(self) -> set[str]:
        out = set()
        for cmd in self.calls:
            if cmd[:2] == ["docker", "compose"]:
                out.add(cmd[3])
            else:
                out.add(cmd[-1].rsplit("=", 1)[1])
        return out

    def deletes(self) -> list[list[str]]:
        return [c for c in self.calls if "down" in c or "rm" in c]


class ComposeProjectTests(unittest.TestCase):
    def test_each_run_gets_its_own_harness_project(self) -> None:
        name = tenant_cogs.compose_project_for("2026-09-30T15:43:32Z-c-10h-20a")
        self.assertEqual(name, "buzz-harness-2026-09-30t154332z-c-10h-20a")
        tenant_cogs.check_compose_project(name)

    def test_a_non_harness_project_is_refused_before_any_call(self) -> None:
        def forbidden(*a, **k):
            raise AssertionError("no call expected")

        with mock.patch.object(tenant_cogs, "run", forbidden):
            for bad in ("buzz-prod", "buzz-harness", "buzz-harness-", "buzz-harness-X", "prod-buzz-harness-1"):
                with self.assertRaises(tenant_cogs.Refused, msg=bad):
                    tenant_cogs.ComposeAdapter(bad, endpoint=TEST_EP)

    def test_up_on_a_fresh_project_then_teardown(self) -> None:
        docker = FakeDocker()
        ad = locked_adapter(self, "buzz-harness-t1")
        with mock.patch.object(tenant_cogs, "run", docker.run):
            with tenant_cogs.RunSession(ad, keep=False):
                ad.up()
            ad.teardown()  # safe to repeat
        self.assertEqual(docker.state, {})
        down = ["docker", "compose", "-p", "buzz-harness-t1", "-f", "a.yml", "down", "-v", "--remove-orphans"]
        self.assertEqual(docker.deletes(), [down, down])

    def test_a_non_empty_project_is_refused_and_nothing_deleted(self) -> None:
        old = {"containers": ["c1"], "volumes": ["v1"], "networks": []}
        docker = FakeDocker({"buzz-harness-old": old})
        ad = locked_adapter(self, "buzz-harness-old")
        with mock.patch.object(tenant_cogs, "run", docker.run):
            with self.assertRaisesRegex(tenant_cogs.ProjectNotEmpty, "nothing was deleted"):
                with tenant_cogs.RunSession(ad, keep=False):
                    ad.up()
        self.assertEqual(docker.deletes(), [])
        self.assertFalse(any("up" in c for c in docker.calls))
        self.assertEqual(docker.state["buzz-harness-old"], old)

    def test_a_second_run_never_touches_the_first(self) -> None:
        first = "buzz-harness-2026-09-30t150000z-c-10h-20a"
        second = tenant_cogs.compose_project_for("2026-09-30T16:00:00Z-c-10h-20a")
        still_up = {"containers": ["r1"], "volumes": ["d1"], "networks": ["n1"]}
        docker = FakeDocker({first: still_up})
        ad = locked_adapter(self, second)
        with mock.patch.object(tenant_cogs, "run", docker.run):
            with tenant_cogs.RunSession(ad, keep=False):
                ad.up()
        self.assertNotEqual(first, second)
        self.assertEqual(docker.projects_touched(), {second})
        self.assertEqual(docker.state, {first: still_up})

    def test_leftovers_fail_teardown(self) -> None:
        docker = FakeDocker()
        ad = locked_adapter(self, "buzz-harness-t1")

        def down_leaves_a_volume(cmd, **kw):
            out = docker.run(cmd, **kw)
            if "down" in cmd:
                docker.state["buzz-harness-t1"] = {"volumes": ["vol1"]}
            return out

        with mock.patch.object(tenant_cogs, "run", down_leaves_a_volume):
            ad.up()
            with self.assertRaisesRegex(RuntimeError, r"not empty after teardown: \{'volumes': \['vol1'\]\}"):
                ad.teardown()

    def test_failed_down_fails_teardown(self) -> None:
        docker = FakeDocker(fail_down=True)
        ad = locked_adapter(self, "buzz-harness-t1")
        with mock.patch.object(tenant_cogs, "run", docker.run):
            ad.up()
            with self.assertRaises(subprocess.CalledProcessError):
                ad.teardown()


class ProjectLockTests(unittest.TestCase):
    PROFILE = str(Path(__file__).resolve().parent / "profiles" / "10h-20a.toml")

    def test_same_second_runs_get_distinct_projects(self) -> None:
        import datetime as real_dt

        fixed = real_dt.datetime(2026, 9, 30, 16, 41, 5, tzinfo=real_dt.timezone.utc)

        class FrozenClock:
            timezone = real_dt.timezone

            class datetime:
                @staticmethod
                def now(tz=None):
                    return fixed

        with mock.patch.object(tenant_cogs, "dt", FrozenClock):
            a = tenant_cogs.new_run_id("c", "10h-20a")
            b = tenant_cogs.new_run_id("c", "10h-20a")
        for run_id in (a, b):
            self.assertRegex(run_id, r"^2026-09-30T16:41:05Z-c-10h-20a-[0-9a-f]{6}$")
            tenant_cogs.check_compose_project(tenant_cogs.compose_project_for(run_id))
        self.assertNotEqual(a, b)
        self.assertNotEqual(tenant_cogs.compose_project_for(a), tenant_cogs.compose_project_for(b))

    def test_a_project_has_one_lock_holder(self) -> None:
        first = tenant_cogs.ProjectLock("buzz-harness-lock1")
        self.addCleanup(first.release)
        with self.assertRaises(tenant_cogs.ProjectBusy):
            tenant_cogs.ProjectLock("buzz-harness-lock1")
        first.release()
        again = tenant_cogs.ProjectLock("buzz-harness-lock1")  # free once released
        again.release()

    def test_two_adapters_on_one_project_cannot_both_own_it(self) -> None:
        # The reviewer's interleaving: both check empty, then both run `up`.
        docker = FakeDocker()
        a = locked_adapter(self, "buzz-harness-shared1")
        b = tenant_cogs.ComposeAdapter("buzz-harness-shared1", ("a.yml",), env={}, endpoint=TEST_EP)
        with self.assertRaises(tenant_cogs.ProjectBusy):
            b.lock = tenant_cogs.ProjectLock("buzz-harness-shared1")
        with mock.patch.object(tenant_cogs, "run", docker.run):
            a.ensure_empty()
            b.ensure_empty()
            a.up()
            calls_before = len(docker.calls)
            with self.assertRaisesRegex(RuntimeError, "hold the lock"):
                b.up()
            self.assertEqual(len(docker.calls), calls_before)  # b ran nothing
            b.teardown()  # b does not own it: a no-op
        self.assertTrue(a.owned)
        self.assertFalse(b.owned)
        self.assertIn("buzz-harness-shared1", docker.state)

    def test_session_releases_the_lock_after_teardown(self) -> None:
        docker = FakeDocker()
        ad = locked_adapter(self, "buzz-harness-lock2")
        with mock.patch.object(tenant_cogs, "run", docker.run):
            with tenant_cogs.RunSession(ad, keep=False):
                ad.up()
        self.assertFalse(ad.lock.held)
        self.assertEqual(docker.state, {})
        tenant_cogs.ProjectLock("buzz-harness-lock2").release()

    def test_same_override_in_a_second_process_refuses_before_any_command(self) -> None:
        name = "buzz-harness-shared2"
        path = tenant_cogs.LOCK_DIR / f"{name}.lock"
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import fcntl, sys; f = open(sys.argv[1], 'a'); fcntl.flock(f, fcntl.LOCK_EX); "
                "print('held', flush=True); sys.stdin.read()",
                str(path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            env=test_env(),
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")

            def forbidden(*a, **k):
                raise AssertionError("no command expected while another process holds the lock")

            with tempfile.TemporaryDirectory() as td:
                for cmd in (["run"], ["seed-bench", "--limits", "raised"]):
                    out = Path(td) / cmd[0]
                    argv = [*cmd, "--substrate", "compose", "--compose-project", name,
                            "--profile", self.PROFILE, "--out-dir", str(out), *GUARD_ARGV]
                    err = io.StringIO()
                    with mock.patch.object(tenant_cogs, "run", forbidden), mock.patch.object(
                        tenant_cogs.subprocess, "Popen", forbidden
                    ), mock.patch.object(tenant_cogs.subprocess, "run", forbidden), mock.patch(
                        "sys.stderr", err
                    ):
                        self.assertEqual(tenant_cogs.main(argv), 2, cmd)
                    self.assertIn("in use by another harness process", err.getvalue(), cmd)
                    self.assertFalse(out.exists(), cmd)
        finally:
            holder.kill()  # a crash, not a clean exit
            holder.wait(timeout=5)
            holder.stdout.close()
            holder.stdin.close()
        # The kernel dropped the dead holder's lock: nothing stale is left.
        tenant_cogs.ProjectLock(name).release()


class LockDirSafetyTests(unittest.TestCase):
    """The lock directory and lock files cannot be planted or swapped."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def use_lock_dir(self, path: Path) -> None:
        patcher = mock.patch.object(tenant_cogs, "LOCK_DIR", path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_default_is_per_user_cache(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/x/cache"}):
            self.assertEqual(tenant_cogs.default_lock_dir(), Path("/x/cache/buzz-harness/locks"))
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "relative"}):
            self.assertEqual(
                tenant_cogs.default_lock_dir(),
                Path(os.path.expanduser("~")) / ".cache" / "buzz-harness" / "locks",
            )

    def test_created_0700_under_umask_022(self) -> None:
        root = self.base / "cache" / "buzz-harness" / "locks"
        self.use_lock_dir(root)
        old = os.umask(0o022)
        try:
            lock = tenant_cogs.ProjectLock("buzz-harness-umask")
        finally:
            os.umask(old)
        self.addCleanup(lock.release)
        self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(lock.path).st_mode & 0o777, 0o600)
        self.assertTrue(lock.held)

    def test_directory_symlink_is_refused(self) -> None:
        target = self.base / "elsewhere"
        target.mkdir(mode=0o700)
        root = self.base / "locks"
        root.symlink_to(target)
        self.use_lock_dir(root)
        with self.assertRaisesRegex(tenant_cogs.Refused, "real directory"):
            tenant_cogs.ProjectLock("buzz-harness-dirlink")
        self.assertEqual(list(target.iterdir()), [])

    def test_group_or_other_access_is_refused(self) -> None:
        for mode in (0o755, 0o770, 0o701):
            root = self.base / f"locks-{mode:o}"
            root.mkdir()
            os.chmod(root, mode)
            self.use_lock_dir(root)
            with self.assertRaisesRegex(tenant_cogs.Refused, "mode 0700", msg=oct(mode)):
                tenant_cogs.ProjectLock("buzz-harness-mode")

    def test_directory_owned_by_someone_else_is_refused(self) -> None:
        root = self.base / "locks"
        root.mkdir(mode=0o700)
        self.use_lock_dir(root)
        with mock.patch.object(tenant_cogs.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(tenant_cogs.Refused, "you own"):
                tenant_cogs.ProjectLock("buzz-harness-owner")

    def test_lock_file_symlink_is_refused(self) -> None:
        root = self.base / "locks"
        root.mkdir(mode=0o700)
        self.use_lock_dir(root)
        target = self.base / "planted"
        (root / "buzz-harness-filelink.lock").symlink_to(target)
        with self.assertRaisesRegex(tenant_cogs.Refused, "cannot open lock file"):
            tenant_cogs.ProjectLock("buzz-harness-filelink")
        self.assertFalse(target.exists())

    def test_hard_linked_lock_file_is_refused(self) -> None:
        root = self.base / "locks"
        root.mkdir(mode=0o700)
        self.use_lock_dir(root)
        path = root / "buzz-harness-hardlink.lock"
        path.touch()
        os.link(path, self.base / "second-name")
        with self.assertRaisesRegex(tenant_cogs.Refused, "one link"):
            tenant_cogs.ProjectLock("buzz-harness-hardlink")

    def test_path_replacement_leaves_one_holder(self) -> None:
        # The reviewer's case: lock A, move its file away, put a new file at the
        # path, lock B. B holds the file at the path; A no longer counts.
        root = self.base / "locks"
        self.use_lock_dir(root)
        first = tenant_cogs.ProjectLock("buzz-harness-swap")
        self.addCleanup(first.release)
        os.rename(first.path, root / "moved-away")
        first.path.touch()
        second = tenant_cogs.ProjectLock("buzz-harness-swap")
        self.addCleanup(second.release)
        self.assertEqual([first.held, second.held], [False, True])
        stale = tenant_cogs.ComposeAdapter("buzz-harness-swap", ("a.yml",), env={}, lock=first, endpoint=TEST_EP)

        def forbidden(*a, **k):
            raise AssertionError("no command expected")

        with mock.patch.object(tenant_cogs, "run", forbidden):
            with self.assertRaisesRegex(RuntimeError, "hold the lock"):
                stale.up()
        self.assertFalse(stale.owned)


class RefusalTests(unittest.TestCase):
    """Refusals happen before any command runs: no docker, no tenant_sim, no openssl."""

    def refused(self, argv: list[str], reason: str) -> None:
        """`argv` (with valid guard flags) exits 2 for `reason`, running nothing."""

        def forbidden(*a, **k):
            raise AssertionError(f"no command expected for {argv}")

        err = io.StringIO()
        with mock.patch.object(tenant_cogs, "run", forbidden), mock.patch.object(
            tenant_cogs.subprocess, "Popen", forbidden
        ), mock.patch.object(tenant_cogs.subprocess, "run", forbidden), mock.patch("sys.stderr", err):
            self.assertEqual(tenant_cogs.main([*argv, *GUARD_ARGV]), 2, argv)
        self.assertIn(reason, err.getvalue(), argv)

    def test_wrong_project_name(self) -> None:
        for cmd in (["run"], ["seed-bench", "--limits", "raised"], ["sample"]):
            argv = [*cmd, "--substrate", "compose", "--compose-project", "buzz-prod"]
            self.refused(argv, "compose project must be 'buzz-harness-'")

    def test_seed_bench_skip_reset(self) -> None:
        argv = ["seed-bench", "--substrate", "compose", "--limits", "raised", "--skip-reset"]
        self.refused(argv, "--skip-reset has nothing to skip")

    def test_run_skip_reset_needs_a_named_harness_project(self) -> None:
        self.refused(["run", "--substrate", "compose", "--skip-reset"], "--skip-reset samples")

    def test_sample_needs_a_named_harness_project(self) -> None:
        self.refused(["sample", "--substrate", "compose"], "needs --compose-project")


VECTORS = json.loads((Path(__file__).resolve().parent / "guard_vectors.json").read_text())
ALL_SCHEMES = ("ws", "wss", "http", "https")


def guard_of(allow: list[str], deny: list[str]) -> "tenant_cogs.TargetGuard":
    return tenant_cogs.TargetGuard(
        [tenant_cogs.parse_cidr(c) for c in allow], [tenant_cogs.parse_cidr(c) for c in deny]
    )


class Server:
    """A loopback server that counts connections and answers each request
    with `response` after reading its headers and body."""

    def __init__(self, host: str, response: bytes) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.url = f"http://[{host}]:{self.port}" if family == socket.AF_INET6 else f"http://{host}:{self.port}"
        self.accepts = 0
        self.response = response
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(self.response)

    def close(self) -> None:
        self.sock.close()


def http_response(code: int, body: str = "", location: str | None = None) -> bytes:
    head = f"HTTP/1.1 {code} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
    if location:
        head += f"Location: {location}\r\n"
    return (head + "\r\n" + body).encode()


PROXY_VARS = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")


class TargetGuardTests(unittest.TestCase):
    """Same vectors as tenant_sim's guard (perf/guard_vectors.json)."""

    def test_accepts_literal_addresses_inside_the_allow_list(self) -> None:
        g = guard_of(VECTORS["allow"], VECTORS["deny"])
        for a in VECTORS["accept"]:
            checked = g.check_url(a["url"], tuple(a["schemes"]))
            self.assertIsInstance(checked, tenant_cogs.CheckedUrl)
            self.assertEqual(checked, a["url"])

    def test_refuses_names_tricky_literals_and_listed_addresses(self) -> None:
        g = guard_of(VECTORS["allow"], VECTORS["deny"])
        for r in VECTORS["refuse"]:
            with self.assertRaises(tenant_cogs.Refused, msg=f"{r['url']!r} ({r['why']})"):
                g.check_url(r["url"], ALL_SCHEMES)

    def test_the_deny_list_wins_over_the_allow_list(self) -> None:
        g = guard_of(["198.51.100.0/24"], ["198.51.100.7"])
        with self.assertRaisesRegex(tenant_cogs.Refused, "deny list"):
            g.check_url("http://198.51.100.7:3030", ("http",))
        g.check_url("http://198.51.100.8:3030", ("http",))

    def test_allow_entries_must_be_narrow_and_well_formed(self) -> None:
        for s in VECTORS["bad_cidr"]:
            with self.assertRaises(ValueError, msg=s):
                tenant_cogs.TargetGuard([tenant_cogs.parse_cidr(s)], [])
        for given, shown in VECTORS["good_cidr"]:
            self.assertEqual(str(tenant_cogs.parse_cidr(given)), shown)

    def test_both_lists_are_required_and_a_bad_deny_line_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            empty = Path(td) / "empty"
            empty.write_text("# nothing denied\n\n")
            bad = Path(td) / "bad"
            bad.write_text("203.0.113.0/24\nrelay.example.com\n")
            with self.assertRaisesRegex(tenant_cogs.Refused, "--allow-cidr is required"):
                tenant_cogs.TargetGuard.from_args([], str(empty))
            with self.assertRaisesRegex(tenant_cogs.Refused, "--deny-list <file> is required"):
                tenant_cogs.TargetGuard.from_args(["127.0.0.0/8"], None)
            with self.assertRaises(tenant_cogs.Refused):
                tenant_cogs.TargetGuard.from_args(["127.0.0.0/8"], str(Path(td) / "missing"))
            with self.assertRaisesRegex(tenant_cogs.Refused, "line 2"):
                tenant_cogs.TargetGuard.from_args(["127.0.0.0/8"], str(bad))
            tenant_cogs.TargetGuard.from_args(["127.0.0.0/8"], str(empty))

    def test_http_get_takes_only_checked_urls(self) -> None:
        with self.assertRaises(TypeError):
            tenant_cogs.http_get("http://127.0.0.1:9/metrics", timeout=1)  # type: ignore[arg-type]


class GuardedHttpTests(unittest.TestCase):
    """The sampler's reads: no redirect followed, no proxy used."""

    def serve(self, host: str, response: bytes) -> Server:
        server = Server(host, response)
        self.addCleanup(server.close)
        return server

    def test_a_redirect_to_a_denied_address_is_not_followed(self) -> None:
        denied = self.serve("::1", http_response(200, "buzz_x 1\n"))
        first = self.serve("127.0.0.1", http_response(302, location=f"{denied.url}/metrics"))
        g = guard_of(["127.0.0.0/8"], ["::1"])
        url = g.check_url(f"{first.url}/metrics", ("http",))
        self.assertIsNone(tenant_cogs.fetch_metrics(url))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            tenant_cogs.http_get(url, timeout=2)
        self.assertEqual(cm.exception.code, 302)
        adapter = tenant_cogs.ComposeAdapter("buzz-harness-redirect", ("a.yml",), env={}, endpoint=TEST_EP)
        with self.assertRaisesRegex(RuntimeError, "refused"):
            adapter.wait_ready(url, timeout_s=1)
        self.assertGreaterEqual(first.accepts, 3)
        self.assertEqual(denied.accepts, 0, "the redirect was followed")

    def test_proxy_variables_are_ignored(self) -> None:
        """A fresh sampler process, started with every proxy variable set,
        still reads the target directly. (A process, not a patched
        environment: an opener reads proxies when it is built.) The proxy
        variables are its named values; no NO_PROXY comes through."""
        target = self.serve("127.0.0.1", http_response(200, "buzz_ws_connections_active 3\n"))
        proxy = self.serve("127.0.0.1", http_response(502))
        env = test_env(**{name: proxy.url for name in PROXY_VARS})
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); import tenant_cogs as t; "
            "g = t.TargetGuard([t.parse_cidr('127.0.0.0/8')], []); "
            "m = t.fetch_metrics(g.check_url(sys.argv[2], ('http',))); "
            "print('CHILD_OK' if m is not None else 'CHILD_NO_METRICS')"
        )
        child = subprocess.run(
            [sys.executable, "-c", code, str(Path(__file__).resolve().parent), f"{target.url}/metrics"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertIn("CHILD_OK", child.stdout, child.stderr)
        self.assertEqual(target.accepts, 1)
        self.assertEqual(proxy.accepts, 0, "the proxy was used")


class GuardRefusalTests(unittest.TestCase):
    """A bad target stops a run before the lock, docker, openssl or tenant_sim."""

    PROFILE = str(Path(__file__).resolve().parent / "profiles" / "10h-20a.toml")

    def refused(self, argv: list[str], reason: str) -> None:
        def forbidden(*a, **k):
            raise AssertionError(f"no command expected for {argv}")

        err = io.StringIO()
        with mock.patch.object(tenant_cogs, "run", forbidden), mock.patch.object(
            tenant_cogs.subprocess, "Popen", forbidden
        ), mock.patch.object(tenant_cogs.subprocess, "run", forbidden), mock.patch.object(
            tenant_cogs, "ProjectLock", forbidden
        ), mock.patch("sys.stderr", err):
            self.assertEqual(tenant_cogs.main(argv), 2, argv)
        self.assertIn(reason, err.getvalue(), argv)

    def test_run_and_seed_bench_refuse_a_bad_target_before_anything(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            deny_self = Path(td) / "deny"
            deny_self.write_text("127.0.0.1\n")
            cases = [
                (["--health-url", "http://localhost:8088/_readiness", *GUARD_ARGV], "not a literal IP"),
                (["--relay-url", "ws://10.0.0.1:3030", *GUARD_ARGV], "outside the allow list"),
                (["--allow-cidr", "127.0.0.0/8", "--deny-list", str(deny_self)], "deny list"),
                (["--metrics-url", "http://127.0.0.1@relay.example.com/metrics", *GUARD_ARGV], "userinfo"),
                (["--deny-list", str(deny_self)], "--allow-cidr is required"),
                (["--allow-cidr", "127.0.0.0/8"], "--deny-list <file> is required"),
                (["--allow-cidr", "0.0.0.0/0", "--deny-list", str(deny_self)], "wider than /8"),
            ]
            for cmd in (["run"], ["seed-bench", "--limits", "raised"]):
                for extra, reason in cases:
                    out = Path(td) / "out"
                    argv = [*cmd, "--substrate", "compose", "--profile", self.PROFILE,
                            "--out-dir", str(out), *extra]
                    self.refused(argv, reason)
                    self.assertFalse(out.exists(), argv)

    def test_sample_checks_its_metrics_url(self) -> None:
        argv = ["sample", "--substrate", "compose", "--compose-project", "buzz-harness-x",
                "--metrics-url", "http://metrics.example.com/metrics", *GUARD_ARGV]
        self.refused(argv, "not a literal IP")

    def test_k3s_sample_and_fingerprint_are_refused(self) -> None:
        for cmd in ("sample", "fingerprint"):
            argv = [cmd, "--substrate", "k3s", "--ssh", "root@192.0.2.1", *GUARD_ARGV]
            self.refused(argv, "the target guard does not cover yet")

    def test_the_defaults_are_literal_addresses(self) -> None:
        args = tenant_cogs.build_parser().parse_args(["run", "--substrate", "compose", *GUARD_ARGV])
        targets = tenant_cogs.check_targets(args)
        self.assertEqual(targets.relay, "ws://127.0.0.1:3030")

    def test_tenant_sim_gets_the_checked_targets_and_the_same_lists(self) -> None:
        args = tenant_cogs.build_parser().parse_args(["run", "--substrate", "compose", *GUARD_ARGV])
        targets = tenant_cogs.check_targets(args)
        cmd = tenant_cogs.tenant_sim_cmd(args, targets, Path("p.toml"), Path("out"), ["--x"])
        pairs = list(zip(cmd, cmd[1:]))
        self.assertIn(("--relay-url", targets.relay), pairs)
        self.assertIn(("--http-url", targets.http), pairs)
        self.assertIn(("--allow-cidr", "127.0.0.0/8"), pairs)
        self.assertIn(("--deny-list", str(Path(GUARD_ARGV[3]).resolve())), pairs)
        self.assertEqual(cmd[-1], "--x")


class EmulationTests(unittest.TestCase):
    def test_amd64_only_services_are_flagged_off_amd64(self) -> None:
        self.assertEqual(tenant_cogs.emulated_services("aarch64"), ["minio", "minio-init"])
        self.assertEqual(tenant_cogs.emulated_services("x86_64"), [])
        self.assertIsNone(tenant_cogs.emulation_note({"emulated": []}))
        note = tenant_cogs.emulation_note({"emulated": ["minio"], "docker_arch": "aarch64"})
        self.assertIn("not real-speed", note or "")

    def test_the_harness_pins_minio_to_amd64_by_digest(self) -> None:
        root = Path(__file__).resolve().parent.parent
        text = (root / "docker-compose.harness.yml").read_text()
        for service in tenant_cogs.AMD64_ONLY_SERVICES:
            block = text.split(f"  {service}:\n", 1)[1].split("\n\n", 1)[0]
            self.assertIn("image: ghcr.io/block/buzz-minio@sha256:", block, service)
            self.assertIn("platform: linux/amd64", block, service)
        self.assertNotIn("minio/minio", text)
        self.assertNotIn("minio/mc", text)


HOSTILE_HOSTS = (
    "ssh://root@203.0.113.9",
    "tcp://203.0.113.9:2375",
    "tcp://127.0.0.1:2375",
    "npipe:////./pipe/docker_engine",
    "unix://relative/docker.sock",
    "unix:///nonexistent/docker.sock",
)


def docker_config(root: Path, current: str | None, contexts: dict[str, str]) -> Path:
    """A DOCKER_CONFIG directory with `contexts` (name -> host) and an active one."""
    import hashlib

    cfg = root / "docker-config"
    for name, host in contexts.items():
        meta = cfg / "contexts" / "meta" / hashlib.sha256(name.encode()).hexdigest()
        meta.mkdir(parents=True)
        (meta / "meta.json").write_text(
            json.dumps({"Name": name, "Endpoints": {"docker": {"Host": host, "SkipTLSVerify": False}}})
        )
    cfg.mkdir(exist_ok=True)
    (cfg / "config.json").write_text(json.dumps({"currentContext": current} if current else {}))
    return cfg


class DockerEndpointTests(unittest.TestCase):
    """The Docker control connection must be a local Unix socket."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def resolve(self, env: dict[str, str]) -> str:
        return tenant_cogs.resolve_docker_endpoint(env)

    def test_a_local_socket_is_accepted(self) -> None:
        self.assertEqual(self.resolve({"DOCKER_HOST": TEST_EP}), TEST_EP)
        link = self.root / "docker.sock"  # like /var/run/docker.sock -> the engine's socket
        link.symlink_to(TEST_EP[len("unix://"):])
        self.assertEqual(self.resolve({"DOCKER_HOST": f"unix://{link}"}), f"unix://{link}")

    def test_an_active_local_context_is_accepted(self) -> None:
        cfg = docker_config(self.root, "orbstack", {"orbstack": TEST_EP})
        ep = self.resolve({"DOCKER_CONFIG": str(cfg)})
        self.assertEqual(ep, TEST_EP)
        self.assertIsInstance(ep, tenant_cogs.DockerEndpoint)

    def test_a_hostile_docker_host_is_refused(self) -> None:
        regular = self.root / "not-a-socket"
        regular.write_text("")
        for host in (*HOSTILE_HOSTS, f"unix://{regular}"):
            with self.assertRaisesRegex(tenant_cogs.Refused, "docker endpoint refused", msg=host):
                self.resolve({"DOCKER_HOST": host})

    def test_a_hostile_active_context_is_refused(self) -> None:
        for host in HOSTILE_HOSTS:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as td:
                cfg = docker_config(Path(td), "prod", {"prod": host})
                with self.assertRaisesRegex(tenant_cogs.Refused, "docker context 'prod'"):
                    self.resolve({"DOCKER_CONFIG": str(cfg)})
                with self.assertRaisesRegex(tenant_cogs.Refused, "DOCKER_CONTEXT=prod"):
                    # Refused even when DOCKER_HOST names the local socket.
                    self.resolve({"DOCKER_CONFIG": str(cfg), "DOCKER_CONTEXT": "prod", "DOCKER_HOST": TEST_EP})

    def test_an_unreadable_context_is_refused(self) -> None:
        cfg = docker_config(self.root, "gone", {})
        with self.assertRaisesRegex(tenant_cogs.Refused, "cannot read docker context 'gone'"):
            self.resolve({"DOCKER_CONFIG": str(cfg)})
        (cfg / "config.json").write_text("{not json")
        with self.assertRaisesRegex(tenant_cogs.Refused, "cannot read"):
            self.resolve({"DOCKER_CONFIG": str(cfg)})

    def test_the_default_context_is_the_default_socket(self) -> None:
        cfg = docker_config(self.root, None, {})
        self.assertEqual(
            tenant_cogs._context_host(cfg, "default", ""), tenant_cogs.DEFAULT_DOCKER_HOST
        )

    def test_a_docker_command_needs_a_checked_endpoint(self) -> None:
        def forbidden(*a, **k):
            raise AssertionError("nothing may run")

        with mock.patch.object(tenant_cogs.subprocess, "run", forbidden):
            for cmd in (["docker", "ps"], ["docker", "--host", "ssh://root@203.0.113.9", "ps"]):
                with self.assertRaisesRegex(tenant_cogs.Refused, "checked endpoint", msg=cmd):
                    tenant_cogs.run(cmd)
            with self.assertRaises(tenant_cogs.Refused):
                tenant_cogs.docker_cmd("ssh://root@203.0.113.9", "ps")  # type: ignore[arg-type]
            with self.assertRaises(tenant_cogs.Refused):
                tenant_cogs.ComposeAdapter("buzz-harness-t1", endpoint="ssh://root@203.0.113.9")  # type: ignore[arg-type]

    def test_every_call_of_a_stack_goes_to_the_checked_endpoint(self) -> None:
        """Up, sampling and teardown through the real `run`, with a hostile
        DOCKER_HOST and DOCKER_CONTEXT in this process's environment."""
        seen: list[tuple[list[str], dict]] = []

        def fake_subprocess_run(cmd, **kw):
            seen.append((list(cmd), dict(kw["env"])))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        hostile = {"DOCKER_HOST": "ssh://root@203.0.113.9", "DOCKER_CONTEXT": "prod"}
        ad = locked_adapter(self, "buzz-harness-endpoint", env={"SIM_RELAY_KEY": "k"})
        execs = tenant_cogs.ExecAdapter(kind="compose", project="buzz-harness-endpoint", endpoint=TEST_EP)
        # A fixed fake parent with the planted dummies; names compared, never
        # values (planted_env.assert_names).
        with mock.patch.dict(os.environ, parent_env(**hostile), clear=True), mock.patch.object(
            tenant_cogs.subprocess, "run", fake_subprocess_run
        ):
            with tenant_cogs.RunSession(ad, keep=False):
                ad.up()
                execs.cgroup("relay")
                ad.relay_rate_limit_overrides()
        self.assertTrue(any("down" in cmd for cmd, _ in seen), "teardown ran")
        for cmd, env in seen:
            self.assertEqual(cmd[:3], ["docker", "--host", TEST_EP], cmd)
            self.assertEqual(env["DOCKER_HOST"], TEST_EP, cmd)
            # The stack's own calls carry its named value; the rest don't.
            assert_names(self, [k for k in env if k != "SIM_RELAY_KEY"], ["DOCKER_HOST", "HOME", "PATH"])
        self.assertEqual(seen[0][1]["SIM_RELAY_KEY"], "k")


class DockerEndpointRefusalTests(unittest.TestCase):
    """Every command path refuses a hostile endpoint before anything happens."""

    PROFILE = str(Path(__file__).resolve().parent / "profiles" / "10h-20a.toml")

    def refused(self, argv: list[str], env: dict[str, str], drop: tuple[str, ...] = ()) -> None:
        def forbidden(*a, **k):
            raise AssertionError(f"nothing may run for {argv}")

        err = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(
            tenant_cogs, "run", forbidden
        ), mock.patch.object(tenant_cogs.subprocess, "run", forbidden), mock.patch.object(
            tenant_cogs.subprocess, "Popen", forbidden
        ), mock.patch.object(tenant_cogs, "ProjectLock", forbidden), mock.patch(
            "sys.stderr", err
        ):
            for name in drop:
                os.environ.pop(name, None)
            self.assertEqual(tenant_cogs.main(argv), 2, argv)
        self.assertIn("docker endpoint refused", err.getvalue(), argv)

    def commands(self, out: Path) -> list[list[str]]:
        common = ["--substrate", "compose", "--profile", self.PROFILE, "--out-dir", str(out), *GUARD_ARGV]
        return [
            ["fingerprint", *common],
            ["sample", *common, "--compose-project", "buzz-harness-x"],
            ["run", *common],
            ["seed-bench", *common, "--limits", "raised"],
            ["docker-endpoint"],
        ]

    def test_a_hostile_docker_host_refuses_every_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            for host in HOSTILE_HOSTS:
                for argv in self.commands(out):
                    self.refused(argv, {"DOCKER_HOST": host})
                    self.assertFalse(out.exists(), argv)

    def test_a_hostile_active_context_refuses_every_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            cfg = docker_config(Path(td), "prod", {"prod": "ssh://root@203.0.113.9"})
            for argv in self.commands(out):
                self.refused(argv, {"DOCKER_CONFIG": str(cfg)}, drop=("DOCKER_HOST",))
                self.refused(argv, {"DOCKER_CONFIG": str(cfg), "DOCKER_CONTEXT": "prod"})
                self.assertFalse(out.exists(), argv)


class LinuxBuildEndpointTests(unittest.TestCase):
    """perf/build-linux.sh uses the same rule, with a fake `docker` on PATH."""

    SCRIPT = Path(__file__).resolve().parent / "build-linux.sh"

    def build(self, env_changes: dict[str, str], drop: tuple[str, ...] = ()) -> tuple[int, list[str], str]:
        with tempfile.TemporaryDirectory() as td:
            fakebin = Path(td) / "bin"
            fakebin.mkdir()
            log = Path(td) / "docker.log"
            (fakebin / "docker").write_text(
                "#!/bin/sh\n"
                "args=$(printf '%s ' \"$@\" | tr '\\n' ' ')\n"
                f'printf "%s\\n" "ARGS $args" "DOCKER_HOST=${{DOCKER_HOST-<unset>}}" '
                f'"DOCKER_CONTEXT=${{DOCKER_CONTEXT-<unset>}}" >> {log}\n'
                "exit 0\n"
            )
            (fakebin / "docker").chmod(0o755)
            # Only named values: the local endpoint setUpModule selects (unless
            # the row drops it), then the row's own hostile DOCKER_* values.
            named = {} if "DOCKER_HOST" in drop else {"DOCKER_HOST": str(TEST_EP)}
            env = test_env(**{**named, **env_changes})
            env["PATH"] = f"{fakebin}:{env['PATH']}"
            proc = subprocess.run(
                ["bash", str(self.SCRIPT)], env=env, capture_output=True, text=True, timeout=60
            )
            lines = log.read_text().splitlines() if log.exists() else []
            return proc.returncode, lines, proc.stderr

    def test_a_hostile_docker_host_refuses_before_docker(self) -> None:
        for host in HOSTILE_HOSTS:
            code, calls, err = self.build({"DOCKER_HOST": host})
            self.assertNotEqual(code, 0, host)
            self.assertEqual(calls, [], host)
            self.assertIn("docker endpoint refused", err, host)

    def test_a_hostile_active_context_refuses_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = docker_config(Path(td), "prod", {"prod": "ssh://root@203.0.113.9"})
            for extra, drop in (({"DOCKER_CONFIG": str(cfg)}, ("DOCKER_HOST",)),
                                ({"DOCKER_CONFIG": str(cfg), "DOCKER_CONTEXT": "prod"}, ())):
                code, calls, err = self.build(extra, drop)
                self.assertNotEqual(code, 0, extra)
                self.assertEqual(calls, [], extra)
                self.assertIn("docker endpoint refused", err, extra)

    def test_a_local_socket_is_named_on_every_docker_call(self) -> None:
        """An active local context resolves to its socket; docker gets the
        socket by --host and DOCKER_HOST, and DOCKER_CONTEXT is gone."""
        with tempfile.TemporaryDirectory() as td:
            cfg = docker_config(Path(td), "local", {"local": TEST_EP})
            _, calls, _ = self.build(
                {"DOCKER_CONFIG": str(cfg), "DOCKER_CONTEXT": "local"}, drop=("DOCKER_HOST",)
            )
        self.assertGreaterEqual(len(calls), 3, calls)
        self.assertTrue(calls[0].startswith(f"ARGS --host {TEST_EP} run --rm --platform linux/amd64"), calls)
        self.assertEqual(calls[1], f"DOCKER_HOST={TEST_EP}")
        self.assertEqual(calls[2], "DOCKER_CONTEXT=<unset>")


class K3sRunTests(unittest.TestCase):
    def test_run_refuses_k3s_without_touching_anything(self) -> None:
        def forbidden(*a, **k):
            raise AssertionError("k3s run must not execute anything")

        with mock.patch.object(tenant_cogs, "run", forbidden), mock.patch.object(
            tenant_cogs.subprocess, "Popen", forbidden
        ), mock.patch("sys.stderr"):
            code = tenant_cogs.cmd_run(tenant_cogs.argparse.Namespace(substrate="k3s"))
        self.assertEqual(code, 2)
        self.assertFalse(hasattr(tenant_cogs, "K3sAdapter"))


VARS = tenant_cogs.RATE_LIMIT_VARS


class SetupRateLimitTests(unittest.TestCase):
    def test_tenant_sim_env_drops_caller_credentials(self) -> None:
        # A fixed fake parent with the planted dummies; names compared, never
        # values (planted_env.assert_names).
        with mock.patch.dict(os.environ, parent_env(BUZZ_IMAGE="img"), clear=True):
            assert_names(self, tenant_cogs.child_env(), ["HOME", "LC_ALL", "PATH"])

    def test_raised_env_covers_every_var(self) -> None:
        env = tenant_cogs.raised_limit_env(500)
        self.assertEqual(sorted(env), sorted(VARS))
        self.assertTrue(all(v == "500" for v in env.values()))
        self.assertEqual(tenant_cogs.raised_limit_env(0), {})

    def test_adapter_never_inherits_shell_overrides(self) -> None:
        with mock.patch.dict(os.environ, parent_env(**{VARS[0]: "7"}), clear=True):
            ad = tenant_cogs.ComposeAdapter("buzz-harness-t1", env={"BUZZ_IMAGE": "img"}, endpoint=TEST_EP)
        assert_names(self, ad.env, ["BUZZ_IMAGE"])
        self.assertEqual(ad.env["BUZZ_IMAGE"], "img")

    def test_up_raises_then_recreate_restores_defaults(self) -> None:
        calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd, **kw):
            self.assertEqual(cmd[1:3], ["--host", TEST_EP])
            cmd = ["docker", *cmd[3:]]
            if cmd[:2] == ["docker", "compose"]:  # skip the empty-project check
                calls.append((cmd, dict(kw.get("env") or {})))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.dict(os.environ, parent_env(**{name: "7" for name in VARS}), clear=True):
            ad = locked_adapter(self, "buzz-harness-t1", files=tenant_cogs.COMPOSE_FILES, env={"SIM_RELAY_KEY": "k"})
            with mock.patch.object(tenant_cogs, "run", fake_run):
                ad.up(tenant_cogs.raised_limit_env(1000))
                ad.recreate_relay()
        (up_cmd, up_env), (re_cmd, re_env) = calls
        self.assertEqual(up_cmd[-2:], ["up", "-d"])
        assert_names(self, up_env, ["SIM_RELAY_KEY", *VARS])
        assert_names(self, re_env, ["SIM_RELAY_KEY"])
        for name in VARS:
            self.assertEqual(up_env[name], "1000", name)
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
            env=test_env(),
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
