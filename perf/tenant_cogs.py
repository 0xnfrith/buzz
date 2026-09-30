#!/usr/bin/env python3
"""Orchestrator + sampler for the tenant_sim population generator.

Stdlib only. Drives a compose or k3s substrate, samples cgroup/Postgres/MinIO
and relay /metrics during floor/steady/peak bands, and appends one JSONL line
per run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import select
import shlex
import statistics
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


SCHEMA = 1
DEFAULT_CADENCE = 5
COMPOSE_PROJECT = "buzz-harness"
COMPOSE_FILES = (
    "docker-compose.harness.yml",
    "docker-compose.harness.relay.yml",
)
# Relay per-key limits raised for setup only (provisioning and seed). The
# owner authenticates as a human, so setup hits the human limits first.
# Measured bands always run with these unset: the relay's own defaults.
RATE_LIMIT_VARS = (
    "BUZZ_RATE_LIMIT_HUMAN_MESSAGES_PER_MIN",
    "BUZZ_RATE_LIMIT_HUMAN_WS_EVENTS_PER_SEC",
    "BUZZ_RATE_LIMIT_AGENT_STANDARD_MESSAGES_PER_MIN",
)
DEFAULT_SETUP_RATE_LIMIT = 1_000_000
HISTOGRAM_BASES = (
    "buzz_db_pool_acquire_duration_seconds",
    "buzz_event_processing_seconds",
    "http_request_latency_ms",
    "buzz_fanout_recipients",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def unix_now() -> int:
    return int(time.time())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        env=env,
        timeout=timeout,
    )


def child_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Env for tenant_sim: the caller's own Buzz/Nostr credentials removed.

    tenant_sim authenticates only with the keys it generates. A `BUZZ_*` or
    `NOSTR_*` value inherited from the operator's shell (for example an
    agent's `BUZZ_AUTH_TAG`) would otherwise reach the git credential helper.
    """
    src = os.environ if env is None else env
    return {
        k: v for k, v in src.items() if not (k.startswith("BUZZ_") or k.startswith("NOSTR_"))
    }


def raised_limit_env(limit: int) -> dict[str, str]:
    """Env that lifts the relay's per-key limits to `limit` for setup."""
    if limit <= 0:
        return {}
    return {name: str(limit) for name in RATE_LIMIT_VARS}


def without_limit_env(env: dict[str, str]) -> dict[str, str]:
    """Copy of `env` with every rate-limit override removed (relay defaults)."""
    return {k: v for k, v in env.items() if k not in RATE_LIMIT_VARS}


def rate_limit_overrides(container_env: list[str]) -> dict[str, str]:
    """Rate-limit overrides present in a container's `Config.Env` list."""
    out: dict[str, str] = {}
    for item in container_env:
        name, sep, value = item.partition("=")
        if sep and name in RATE_LIMIT_VARS:
            out[name] = value
    return out


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    idx = int(round((len(ys) - 1) * p))
    idx = min(max(idx, 0), len(ys) - 1)
    return float(ys[idx])


def pct_block(xs: list[float]) -> dict[str, float]:
    if not xs:
        return {"p50": 0.0, "p95": 0.0, "max": 0.0}
    return {"p50": percentile(xs, 0.50), "p95": percentile(xs, 0.95), "max": max(xs)}


def parse_cpu_stat(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("usage_usec"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    return None


def parse_memory_current(text: str) -> int | None:
    text = text.strip()
    if not text:
        return None
    return int(text.split()[0])


def parse_memory_anon(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("anon "):
            return int(line.split()[1])
    return None


def lsn_to_bytes(lsn: str) -> int | None:
    lsn = lsn.strip()
    if "/" not in lsn:
        return None
    hi, lo = lsn.split("/", 1)
    return (int(hi, 16) << 32) + int(lo, 16)


def histogram_buckets_to_json(buckets: list[tuple[float, float]]) -> list[dict[str, Any]]:
    merged: dict[float, float] = {}
    for le, c in buckets:
        merged[le] = c
    out: list[dict[str, Any]] = []
    for le, c in sorted(merged.items()):
        out.append({"le": "+Inf" if le == float("inf") else le, "c": c})
    return out


def histogram_buckets_from_json(raw: Any) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    if not raw:
        return out
    for item in raw:
        if isinstance(item, dict):
            le, c = item.get("le"), item.get("c")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            le, c = item[0], item[1]
        else:
            continue
        if le is None or c is None:
            continue
        le_v = float("inf") if le in ("+Inf", "+inf", "Inf") else float(le)
        out.append((le_v, float(c)))
    return out


def histogram_bucket_delta(
    start: list[tuple[float, float]] | None,
    end: list[tuple[float, float]] | None,
) -> list[tuple[float, float]]:
    if not end:
        return []
    start_map = {le: c for le, c in (start or [])}
    return [(le, max(float(c) - float(start_map.get(le, 0.0)), 0.0)) for le, c in end]


def histogram_quantile(buckets: list[tuple[float, float]], q: float) -> float | None:
    """Prometheus-style linear interpolation inside the bucket that crosses q."""
    if not buckets:
        return None
    merged: dict[float, float] = {}
    for le, c in buckets:
        merged[le] = c
    ordered = sorted(merged.items())
    count = ordered[-1][1]
    if count <= 0:
        return None
    target = q * count
    prev_le, prev_c = 0.0, 0.0
    for le, c in ordered:
        if c >= target:
            if le == float("inf"):
                return prev_le
            span = max(le - prev_le, 1e-12)
            frac = (target - prev_c) / max(c - prev_c, 1e-12)
            return prev_le + span * frac
        prev_le, prev_c = le, c
    return ordered[-1][0]


def band_histogram_delta(
    samples: list[dict[str, Any]],
    name: str,
    key: str = "fanout_recipients_buckets",
) -> list[tuple[float, float]]:
    start_raw = None
    end_raw = None
    seen = False
    for s in samples:
        if s.get("band") == name:
            seen = True
            metrics = s.get("metrics") or {}
            if metrics.get(key) is not None:
                end_raw = metrics.get(key)
        elif not seen:
            metrics = s.get("metrics") or {}
            if metrics.get(key) is not None:
                start_raw = metrics.get(key)
    return histogram_bucket_delta(
        histogram_buckets_from_json(start_raw),
        histogram_buckets_from_json(end_raw),
    )


def parse_prometheus(text: str) -> dict[str, Any]:
    """Parse a Prometheus text exposition into a nested dict of useful signals."""
    gauges: dict[str, float] = {}
    counters: dict[str, float] = {}
    labeled: dict[str, dict[str, float]] = {}
    hist_sum: dict[str, float] = {}
    hist_count: dict[str, float] = {}
    hist_buckets: dict[str, list[tuple[float, float]]] = {}

    line_re = re.compile(
        r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)"
    )
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        m = line_re.match(raw)
        if not m:
            continue
        name, labels, value_s = m.group(1), m.group(2) or "", float(m.group(3))
        label_map = {}
        if labels:
            for pair in labels.strip("{}").split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    label_map[k.strip()] = v.strip().strip('"')
        if name.endswith("_bucket"):
            base = name[: -len("_bucket")]
            le = label_map.get("le")
            if le is not None:
                le_v = float("inf") if le == "+Inf" else float(le)
                hist_buckets.setdefault(base, []).append((le_v, value_s))
        elif name.endswith("_sum") and name[: -len("_sum")] in HISTOGRAM_BASES:
            hist_sum[name[: -len("_sum")]] = value_s
        elif name.endswith("_count") and name[: -len("_count")] in HISTOGRAM_BASES:
            hist_count[name[: -len("_count")]] = value_s
        elif label_map:
            key = name
            labeled.setdefault(key, {})
            if "kind" in label_map:
                labeled[key][label_map["kind"]] = value_s
            elif "check" in label_map:
                labeled[key][label_map["check"]] = value_s
            else:
                labeled[key][json.dumps(label_map, sort_keys=True)] = value_s
            counters[name] = counters.get(name, 0.0) + value_s
        else:
            gauges[name] = value_s
            counters[name] = value_s

    fanout_buckets = hist_buckets.get("buzz_fanout_recipients")
    events_received = labeled.get("buzz_events_received_total", {})
    events_stored = labeled.get("buzz_events_stored_total", {})
    return {
        "ws_connections_active": gauges.get("buzz_ws_connections_active"),
        "subscriptions_active": gauges.get("buzz_subscriptions_active"),
        "events_received_total": sum(events_received.values())
        if events_received
        else counters.get("buzz_events_received_total"),
        "events_stored_total": sum(events_stored.values())
        if events_stored
        else counters.get("buzz_events_stored_total"),
        "events_rejected_total": counters.get("buzz_events_rejected_total", 0.0),
        "db_pool_waiters": gauges.get("buzz_db_pool_waiters"),
        "db_pool_acquire_p95_s": histogram_quantile(
            hist_buckets.get("buzz_db_pool_acquire_duration_seconds") or [], 0.95
        ),
        "backpressure_disconnects": counters.get(
            "buzz_ws_backpressure_disconnects_total", 0.0
        ),
        "auth_timeouts": counters.get("buzz_ws_auth_timeouts_total", 0.0),
        "media_upload_rejections": counters.get(
            "buzz_media_upload_rejections_total", 0.0
        ),
        "fanout_recipients_sum": hist_sum.get("buzz_fanout_recipients"),
        "fanout_recipients_count": hist_count.get("buzz_fanout_recipients"),
        "fanout_recipients_buckets": (
            histogram_buckets_to_json(fanout_buckets) if fanout_buckets else None
        ),
        "multinode_fanout_total": counters.get("buzz_multinode_fanout_total"),
        "raw_gauges": gauges,
        "raw_counters": counters,
    }


@dataclass
class ExecAdapter:
    """Run a command inside a named container/pod and return stdout."""

    kind: str  # compose | k3s
    project: str = COMPOSE_PROJECT
    kubeconfig: str | None = None
    namespace: str = "buzz-loadtest"
    compose_files: tuple[str, ...] = COMPOSE_FILES

    def compose_base(self) -> list[str]:
        cmd = ["docker", "compose", "-p", self.project]
        for f in self.compose_files:
            cmd.extend(["-f", f])
        return cmd

    def container(self, service: str) -> str:
        return f"{self.project}-{service}-1"

    def exec_cmd(self, service: str, args: list[str], container: str | None = None) -> list[str]:
        if self.kind == "compose":
            return ["docker", "exec", container or self.container(service), *args]
        # k3s: service is a kubectl target like "deploy/buzz" or a pod name.
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        cmd.extend(["-n", self.namespace, "exec", service, "--", *args])
        return cmd

    def exec(
        self, service: str, args: list[str], *, container: str | None = None
    ) -> str | None:
        cmd = self.exec_cmd(service, args, container=container)
        try:
            proc = run(cmd, check=False)
        except FileNotFoundError:
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout

    def cgroup(self, service: str) -> dict[str, int | None]:
        cpu = self.exec(service, ["cat", "/sys/fs/cgroup/cpu.stat"])
        mem = self.exec(service, ["cat", "/sys/fs/cgroup/memory.current"])
        stat = self.exec(service, ["cat", "/sys/fs/cgroup/memory.stat"])
        return {
            "usage_usec": parse_cpu_stat(cpu or ""),
            "rss": parse_memory_current(mem or ""),
            "rss_anon": parse_memory_anon(stat or ""),
        }


def compose_ps_cmd(project: str, files: tuple[str, ...]) -> list[str]:
    cmd = ["docker", "compose", "-p", project]
    for f in files:
        cmd.extend(["-f", f])
    cmd.append("ps")
    return cmd


class ComposeAdapter:
    def __init__(
        self,
        project: str = COMPOSE_PROJECT,
        files: tuple[str, ...] = COMPOSE_FILES,
        env: dict[str, str] | None = None,
    ) -> None:
        self.project = project
        self.files = files
        # Never inherit rate-limit overrides from the caller's shell.
        self.env = without_limit_env({**os.environ, **(env or {})})

    def cmd(self, *args: str) -> list[str]:
        out = ["docker", "compose", "-p", self.project]
        for f in self.files:
            out.extend(["-f", f])
        out.extend(args)
        return out

    def reset(self) -> None:
        run(self.cmd("down", "-v"), check=False, env=self.env, capture=True)

    def up(self, extra_env: dict[str, str] | None = None) -> None:
        env = {**self.env, **(extra_env or {})}
        run(self.cmd("up", "-d"), check=True, env=env, capture=True)

    def recreate_relay_cmd(self) -> list[str]:
        return self.cmd("up", "-d", "--no-deps", "--force-recreate", "relay")

    def recreate_relay(self) -> None:
        """Restart the relay alone with the relay's default rate limits.

        Same keys and owner as setup (self.env); backing services and their
        data are untouched.
        """
        run(self.recreate_relay_cmd(), check=True, env=self.env, capture=True)

    def relay_rate_limit_overrides(self) -> dict[str, str]:
        proc = run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .Config.Env}}",
                f"{self.project}-relay-1",
            ],
            check=True,
        )
        return rate_limit_overrides(json.loads(proc.stdout or "[]") or [])

    def wait_ready(self, health_url: str, timeout_s: int = 180) -> None:
        deadline = time.time() + timeout_s
        last = ""
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        return
                    last = f"status {resp.status}"
            except Exception as exc:  # noqa: BLE001 — readiness probe
                last = str(exc)
            time.sleep(2)
        raise RuntimeError(f"relay not ready at {health_url}: {last}")

    def teardown(self) -> None:
        run(self.cmd("down", "-v"), check=False, env=self.env, capture=True)


class K3sAdapter:
    """Generic k3s adapter. Hosts, kubeconfig and namespace come from flags."""

    def __init__(
        self,
        kubeconfig: str,
        namespace: str,
        release: str = "buzz",
        ssh: str | None = None,
        ssh_key: str | None = None,
    ) -> None:
        self.kubeconfig = kubeconfig
        self.namespace = namespace
        self.release = release
        self.ssh = ssh
        self.ssh_key = ssh_key

    def kubectl(self, *args: str) -> list[str]:
        cmd = ["kubectl", "--kubeconfig", self.kubeconfig, "-n", self.namespace]
        cmd.extend(args)
        return cmd

    def reset(self) -> None:
        run(
            [
                "helm",
                "uninstall",
                self.release,
                "-n",
                self.namespace,
                "--kubeconfig",
                self.kubeconfig,
                "--wait",
                "--timeout",
                "5m",
            ],
            check=False,
        )
        run(
            [
                "kubectl",
                "--kubeconfig",
                self.kubeconfig,
                "delete",
                "namespace",
                self.namespace,
                "--wait",
            ],
            check=False,
        )

    def up(self) -> None:
        raise RuntimeError(
            "k3s up is performed by the private wrapper (helm install); "
            "pass --skip-reset after the release is already running"
        )

    def wait_ready(self, health_url: str, timeout_s: int = 180) -> None:
        deadline = time.time() + timeout_s
        last = ""
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        return
                    last = f"status {resp.status}"
            except Exception as exc:  # noqa: BLE001
                last = str(exc)
            time.sleep(2)
        raise RuntimeError(f"relay not ready at {health_url}: {last}")

    def teardown(self) -> None:
        self.reset()


def fingerprint_compose(relay_cpu_pin: float = 2.0) -> dict[str, Any]:
    def sysctl(*args: str) -> str | None:
        try:
            return run(["sysctl", "-n", *args]).stdout.strip()
        except Exception:
            return None

    docker = run(
        [
            "docker",
            "info",
            "--format",
            "{{.NCPU}} {{.MemTotal}} {{.ServerVersion}}",
        ],
        check=False,
    )
    ncpu, mem, ver = None, None, None
    if docker.returncode == 0:
        parts = docker.stdout.split()
        if len(parts) >= 3:
            ncpu, mem, ver = parts[0], parts[1], parts[2]
    os_ver = None
    try:
        os_ver = run(["sw_vers", "-productVersion"], check=False).stdout.strip()
    except Exception:
        os_ver = None
    return {
        "chip": sysctl("machdep.cpu.brand_string"),
        "host_cores": sysctl("hw.ncpu"),
        "host_mem_bytes": sysctl("hw.memsize"),
        "docker_cpus": ncpu,
        "docker_mem_bytes": mem,
        "docker_version": ver,
        "relay_cpu_pin": relay_cpu_pin,
        "os": os_ver,
        "k3s_version": None,
        "helm_version": None,
        "chart_version": None,
        "server_type": None,
        "location": None,
    }


def fingerprint_k3s(ssh: str | None = None) -> dict[str, Any]:
    def remote(cmd: str) -> str | None:
        if not ssh:
            try:
                return run(shlex.split(cmd), check=False).stdout.strip()
            except Exception:
                return None
        full = ["ssh", ssh, cmd]
        try:
            return run(full, check=False).stdout.strip()
        except Exception:
            return None

    return {
        "chip": remote("lscpu | awk -F: '/Model name/{print $2; exit}'"),
        "host_cores": remote("nproc"),
        "host_mem_bytes": remote("free -b | awk '/Mem:/{print $2}'"),
        "docker_cpus": None,
        "docker_mem_bytes": None,
        "docker_version": None,
        "relay_cpu_pin": None,
        "os": remote("cat /etc/os-release | awk -F= '/PRETTY_NAME/{print $2}'"),
        "k3s_version": remote("k3s --version | head -1"),
        "helm_version": remote("helm version --short"),
        "chart_version": None,
        "server_type": None,
        "location": None,
    }


def fetch_metrics(url: str) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            text = resp.read().decode("utf-8", "replace")
        return parse_prometheus(text)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def docker_stats_rss(project: str) -> dict[str, int]:
    proc = run(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{.Name}} {{.MemUsage}}",
        ],
        check=False,
    )
    out: dict[str, int] = {}
    if proc.returncode != 0:
        return out
    for line in proc.stdout.splitlines():
        if not line.startswith(project):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name, mem = parts[0], parts[1]
        out[name] = parse_docker_mem(mem)
    return out


def parse_docker_mem(s: str) -> int:
    s = s.strip()
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "kB": 1000, "MB": 1000**2, "GB": 1000**3}
    m = re.match(r"([0-9.]+)([A-Za-z]+)", s)
    if not m:
        return 0
    n, unit = float(m.group(1)), m.group(2)
    return int(n * units.get(unit, 1))


class Sampler:
    def __init__(
        self,
        execs: ExecAdapter,
        metrics_url: str,
        services: dict[str, str],
    ) -> None:
        self.execs = execs
        self.metrics_url = metrics_url
        self.services = services
        self.fail_streak = 0

    def psql(self, sql: str) -> str | None:
        svc = self.services["postgres"]
        return self.execs.exec(
            svc,
            ["psql", "-U", "buzz", "-d", "buzz", "-tAc", sql],
        )

    def sample(self, band: str, sampled: bool) -> dict[str, Any]:
        row: dict[str, Any] = {
            "t_unix": unix_now(),
            "band": band,
            "sampled": sampled,
        }
        relay_cg = self.execs.cgroup(self.services["relay"])
        if relay_cg["usage_usec"] is None and relay_cg["rss"] is None:
            self.fail_streak += 1
        else:
            self.fail_streak = 0
        row["relay"] = relay_cg
        row["postgres"] = self.execs.cgroup(self.services["postgres"])
        row["redis"] = self.execs.cgroup(self.services["redis"])
        row["minio"] = self.execs.cgroup(self.services["minio"])
        db_size = self.psql("select pg_database_size('buzz');")
        wal = self.psql("select coalesce(sum(size),0) from pg_ls_waldir();")
        lsn = self.psql("select pg_current_wal_lsn();")
        row["db_size_bytes"] = int(db_size.strip()) if db_size and db_size.strip() else None
        row["wal_bytes"] = int(wal.strip()) if wal and wal.strip() else None
        row["wal_lsn_bytes"] = lsn_to_bytes(lsn) if lsn else None
        du = self.execs.exec(self.services["minio"], ["du", "-sb", "/data"])
        nfiles = self.execs.exec(
            self.services["minio"],
            ["sh", "-c", "find /data -type f | wc -l"],
        )
        row["objects_bytes"] = int(du.split()[0]) if du and du.split() else None
        row["objects_count"] = int(nfiles.strip()) if nfiles and nfiles.strip() else None
        row["metrics"] = fetch_metrics(self.metrics_url)
        return row


def load_profile_meta(path: Path) -> tuple[str, str, dict[str, int]]:
    """Profile name, file hash and band lengths, parsed as real TOML.

    tenant_sim parses the same file with a TOML parser; any other reading
    here would let the two disagree on how long each band lasts.
    """
    data = tomllib.loads(path.read_text())
    name = str((data.get("profile") or {}).get("name", "unknown"))
    bands = {"warmup": 120, "floor": 600, "steady": 900, "peak": 300, "cooldown": 60}
    for key, val in (data.get("bands") or {}).items():
        if key in bands:
            bands[key] = int(val)
    return name, sha256_file(path), bands


def _stdout_buf(proc: subprocess.Popen[Any]) -> list[bytes]:
    buf = getattr(proc, "_harness_stdout_buf", None)
    if buf is None:
        buf = [b""]
        setattr(proc, "_harness_stdout_buf", buf)
    return buf


def read_stdout_line(proc: subprocess.Popen[Any], timeout_s: float) -> str:
    """Read one stdout line without letting a silent child outlive the deadline.

    `proc.stdout` must be a binary pipe. Leftover bytes are kept on the process.
    """
    if timeout_s <= 0:
        raise TimeoutError("stdout read timed out")
    stdout = proc.stdout
    if stdout is None:
        raise RuntimeError("process has no stdout")
    leftover = _stdout_buf(proc)
    deadline = time.monotonic() + timeout_s
    while True:
        nl = leftover[0].find(b"\n")
        if nl >= 0:
            raw, leftover[0] = leftover[0][: nl + 1], leftover[0][nl + 1 :]
            return raw.decode("utf-8", errors="replace")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("stdout read timed out")
        fd = stdout.fileno()
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            raise TimeoutError("stdout read timed out")
        chunk = os.read(fd, 4096)
        if not chunk:
            if leftover[0]:
                raw, leftover[0] = leftover[0], b""
                return raw.decode("utf-8", errors="replace")
            return ""
        leftover[0] += chunk


def wait_phase_line(
    proc: subprocess.Popen[Any], phase: str, timeout_s: float
) -> dict[str, Any]:
    """Return tenant_sim's next `{"phase": <phase>, ...}` stdout line."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"timed out waiting for tenant_sim {phase}")
        try:
            line = read_stdout_line(proc, remaining)
        except TimeoutError as exc:
            raise RuntimeError(f"timed out waiting for tenant_sim {phase}") from exc
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"tenant_sim exited {proc.returncode} before {phase}")
            continue
        line = line.strip()
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("phase") == phase:
            return obj


def wait_ready_line(proc: subprocess.Popen[Any], timeout_s: float = 300) -> None:
    wait_phase_line(proc, "ready", timeout_s)


def collect_summary(proc: subprocess.Popen[Any], timeout_s: float = 120) -> dict[str, Any]:
    buf: list[str] = []
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            line = read_stdout_line(proc, remaining)
        except TimeoutError:
            break
        if not line:
            if proc.poll() is not None:
                break
            continue
        buf.append(line)
    blob = "".join(buf).strip()
    if not blob:
        return {}
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        start = blob.find("{")
        end = blob.rfind("}")
        if start >= 0 and end > start:
            return json.loads(blob[start : end + 1])
        return {}


class RunSession:
    """Kill the sim process and tear the substrate down on every exit path."""

    def __init__(self, adapter: Any, keep: bool) -> None:
        self.adapter = adapter
        self.keep = keep
        self.proc: subprocess.Popen[Any] | None = None

    def __enter__(self) -> "RunSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        proc = self.proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        if self.adapter is not None and not self.keep:
            try:
                self.adapter.teardown()
            except Exception as exc:
                print(f"teardown failed: {exc}", file=sys.stderr)


def band_stats(samples: list[dict[str, Any]], name: str, client: dict[str, Any] | None) -> dict[str, Any]:
    rows = [s for s in samples if s.get("band") == name and s.get("sampled")]
    def series(comp: str, key: str) -> list[float]:
        out = []
        for s in rows:
            val = (s.get(comp) or {}).get(key) if isinstance(s.get(comp), dict) else None
            if val is not None:
                out.append(float(val))
        return out

    def cpu_s(comp: str) -> float:
        xs = series(comp, "usage_usec")
        if len(xs) < 2:
            return 0.0
        return max(xs[-1] - xs[0], 0.0) / 1e6

    seconds = 0
    if rows:
        seconds = max(rows[-1]["t_unix"] - rows[0]["t_unix"], 1)

    def component(comp: str) -> dict[str, Any]:
        rss = series(comp, "rss")
        cpu = cpu_s(comp)
        block: dict[str, Any] = {
            "cpu_s": cpu,
            "rss_bytes": pct_block(rss),
        }
        if comp in {"relay", "postgres", "redis", "minio"}:
            block["cpu_s_per_tenant_hour"] = cpu * 3600.0 / seconds if seconds else 0.0
        if comp == "relay":
            ev = []
            for s in rows:
                m = s.get("metrics") or {}
                if m.get("events_received_total") is not None:
                    ev.append(float(m["events_received_total"]))
            delta = (ev[-1] - ev[0]) if len(ev) >= 2 else 0.0
            block["cpu_s_per_1k_events"] = (cpu / (delta / 1000.0)) if delta > 0 else None
        return block

    relay_m = [s.get("metrics") or {} for s in rows if s.get("metrics")]
    def m_last(key: str, default: float = 0.0) -> float:
        for m in reversed(relay_m):
            if m.get(key) is not None:
                return float(m[key])
        return default

    def m_max(key: str) -> float:
        xs = [float(m[key]) for m in relay_m if m.get(key) is not None]
        return max(xs) if xs else 0.0

    ev_first = next((m.get("events_received_total") for m in relay_m if m.get("events_received_total") is not None), 0) or 0
    ev_last = m_last("events_received_total")
    stored_first = next((m.get("events_stored_total") for m in relay_m if m.get("events_stored_total") is not None), 0) or 0
    stored_last = m_last("events_stored_total")
    rej_first = next((m.get("events_rejected_total") for m in relay_m if m.get("events_rejected_total") is not None), 0) or 0
    rej_last = m_last("events_rejected_total")

    db_sizes = [s["db_size_bytes"] for s in rows if s.get("db_size_bytes") is not None]
    wal_sizes = [s["wal_bytes"] for s in rows if s.get("wal_bytes") is not None]
    lsn = [s["wal_lsn_bytes"] for s in rows if s.get("wal_lsn_bytes") is not None]
    obj_b = [s["objects_bytes"] for s in rows if s.get("objects_bytes") is not None]
    obj_n = [s["objects_count"] for s in rows if s.get("objects_count") is not None]

    wal_gen = 0.0
    if len(lsn) >= 2 and seconds:
        wal_gen = max(lsn[-1] - lsn[0], 0) / seconds

    stack_cpu = cpu_s("relay") + cpu_s("postgres") + cpu_s("redis") + cpu_s("minio")
    stack_rss = []
    for s in rows:
        total = 0
        ok = False
        for comp in ("relay", "postgres", "redis", "minio"):
            rss = (s.get(comp) or {}).get("rss")
            if rss is not None:
                total += rss
                ok = True
        if ok:
            stack_rss.append(float(total))

    fanout_p50 = histogram_quantile(band_histogram_delta(samples, name), 0.50)

    out: dict[str, Any] = {
        "seconds": seconds,
        "samples": len(rows),
        "relay": component("relay"),
        "postgres": component("postgres"),
        "redis": component("redis"),
        "minio": component("minio"),
        "stack": {
            "cpu_s": stack_cpu,
            "rss_bytes": pct_block(stack_rss),
        },
        "db": {
            "size_bytes": {
                "start": int(db_sizes[0]) if db_sizes else 0,
                "end": int(db_sizes[-1]) if db_sizes else 0,
                "max": int(max(db_sizes)) if db_sizes else 0,
            },
            "wal_bytes": {
                "start": int(wal_sizes[0]) if wal_sizes else 0,
                "end": int(wal_sizes[-1]) if wal_sizes else 0,
                "max": int(max(wal_sizes)) if wal_sizes else 0,
            },
            "wal_gen_bytes_per_s": wal_gen,
        },
        "objects": {
            "bytes": {
                "start": int(obj_b[0]) if obj_b else 0,
                "end": int(obj_b[-1]) if obj_b else 0,
            },
            "count": {
                "start": int(obj_n[0]) if obj_n else 0,
                "end": int(obj_n[-1]) if obj_n else 0,
            },
        },
        "relay_metrics": {
            "events_received": int(ev_last - ev_first),
            "events_stored": int(stored_last - stored_first),
            "events_rejected": int(rej_last - rej_first),
            "ws_connections_active": int(m_last("ws_connections_active")),
            "subscriptions_active": int(m_last("subscriptions_active")),
            "db_pool_waiters_max": m_max("db_pool_waiters"),
            "db_pool_acquire_p95_s": next(
                (m.get("db_pool_acquire_p95_s") for m in reversed(relay_m) if m.get("db_pool_acquire_p95_s") is not None),
                0.0,
            )
            or 0.0,
            "backpressure_disconnects": int(m_last("backpressure_disconnects")),
            "fanout_recipients_p50": fanout_p50 or 0,
        },
        "client": client or {
            "sent": 0,
            "accepted": 0,
            "rejected": 0,
            "received": 0,
            "ok_ms": {"p50": 0, "p95": 0, "p99": 0, "max": 0},
            "fanout_ms": {"p50": 0, "p95": 0, "p99": 0, "max": 0},
        },
    }
    return out


def client_from_summary(summary: dict[str, Any], band: str) -> dict[str, Any] | None:
    bands = summary.get("bands") or {}
    b = bands.get(band)
    if not b:
        return None
    out = {
        "sent": b.get("sent", 0),
        "accepted": b.get("accepted", 0),
        "rejected": b.get("rejected", 0),
        "received": b.get("received", 0),
        "ok_ms": b.get("ok_ms") or {"p50": 0, "p95": 0, "p99": 0, "max": 0},
        "fanout_ms": b.get("fanout_ms") or {"p50": 0, "p95": 0, "p99": 0, "max": 0},
    }
    if band == "peak":
        storm = {}
        if b.get("storm_backfill_ms"):
            storm["backfill_ms"] = b["storm_backfill_ms"]
        if b.get("storm_events_returned") is not None:
            storm["events_returned"] = b["storm_events_returned"]
        if storm:
            out["storm"] = storm
    return out


def write_results_line(
    path: Path,
    *,
    run_id: str,
    substrate: str,
    buzz_commit: str,
    buzz_image: str,
    harness_commit: str,
    profile: str,
    profile_sha: str,
    fingerprint: dict[str, Any],
    samples: list[dict[str, Any]],
    summary: dict[str, Any],
    notes: str,
    setup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    setup = setup or {}
    floor = band_stats(samples, "floor", client_from_summary(summary, "floor"))
    steady = band_stats(samples, "steady", client_from_summary(summary, "steady"))
    peak = band_stats(samples, "peak", client_from_summary(summary, "peak"))
    if "storm" in (client_from_summary(summary, "peak") or {}):
        peak["storm"] = client_from_summary(summary, "peak")["storm"]  # type: ignore[index]

    totals_events = int(summary.get("sent_by_kind") and sum(summary["sent_by_kind"].values()) or 0)
    if not totals_events:
        totals_events = int(
            (floor["relay_metrics"]["events_received"]
             + steady["relay_metrics"]["events_received"]
             + peak["relay_metrics"]["events_received"])
        )
    media_bytes = int((summary.get("media") or {}).get("bytes") or 0)
    git_bytes = int((summary.get("git") or {}).get("bytes") or 0)
    lost = int(summary.get("lost_after_backfill") or 0)
    db_end = peak["db"]["size_bytes"]["end"] or steady["db"]["size_bytes"]["end"]
    wal_hw = max(
        floor["db"]["wal_bytes"]["max"],
        steady["db"]["wal_bytes"]["max"],
        peak["db"]["wal_bytes"]["max"],
    )
    obj_end = peak["objects"]["bytes"]["end"] or steady["objects"]["bytes"]["end"]
    line = {
        "schema": SCHEMA,
        "run_id": run_id,
        "substrate": substrate,
        "buzz_commit": buzz_commit,
        "buzz_image": buzz_image,
        "harness_commit": harness_commit,
        "chart_version": fingerprint.get("chart_version"),
        "profile": profile,
        "profile_sha256": profile_sha,
        "machine_fingerprint": fingerprint,
        "relay_config": {
            "require_relay_membership": True,
            "replica_count": 1,
            "drain_jitter_ms": 0,
            "max_wal_size_mb": 1024,
            # Limits raised for provisioning/seed only; 0 = never raised.
            "setup_rate_limit": setup.get("rate_limit", 0),
            # What the measured bands ran under, read back from the relay.
            "band_rate_limits": setup.get("band_rate_limits"),
        },
        "setup": setup.get("provision"),
        "bands": {"floor": floor, "steady": steady, "peak": peak},
        "totals": {
            "events": totals_events,
            "media_bytes": media_bytes,
            "git_bytes": git_bytes,
            "lost_after_backfill": lost,
            "db_bytes_per_1k_events": (db_end / (totals_events / 1000.0)) if totals_events else 0.0,
            "wal_high_water_bytes": wal_hw,
            "objects_bytes_per_1k_events": (obj_end / (totals_events / 1000.0)) if totals_events else 0.0,
        },
        "node": {
            "cpu_millicores_p95": None,
            "mem_bytes_p95": None,
            "k3s_overhead_bytes": None,
        },
        "blink": summary.get("blink"),
        "cost_usd": 0.0,
        "notes": notes,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(line, separators=(",", ":")) + "\n")
    return line


def git_head() -> str:
    proc = run(["git", "rev-parse", "--short=7", "HEAD"], check=False)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def inspect_docker_image(image: str) -> dict[str, Any]:
    proc = run(
        ["docker", "image", "inspect", image, "--format", "{{json .}}"],
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}


def resolve_buzz_identity(
    image: str, inspect: dict[str, Any] | None = None
) -> tuple[str, str]:
    """Return (buzz_commit, buzz_image) that can distinguish two Monday runs.

    Never records the moving tag `main`. Prefer the image's immutable digest
    plus `org.opencontainers.image.revision` / `sha-<hex>` source commit.
    """
    info = inspect if inspect is not None else inspect_docker_image(image)
    repo_digests = info.get("RepoDigests") or []
    digest_ref = repo_digests[0] if repo_digests else None
    labels = (info.get("Config") or {}).get("Labels") or {}
    revision = labels.get("org.opencontainers.image.revision") or labels.get(
        "org.opencontainers.image.base.digest"
    )
    tag_sha = None
    m = re.search(r"sha-([0-9a-f]{7,})", image)
    if m:
        tag_sha = m.group(1)[:7]
    commit = None
    if isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{7,40}", revision):
        commit = revision[:7]
    elif tag_sha:
        commit = tag_sha
    elif digest_ref and "@sha256:" in digest_ref:
        commit = "sha256:" + digest_ref.split("@sha256:", 1)[1][:12]
    else:
        slug = image.rsplit(":", 1)[-1] if ":" in image else image
        if slug in {"main", "latest"}:
            commit = f"unresolved-{slug}"
        else:
            commit = slug[:12]
    return commit, digest_ref or image


def image_commit(image: str, inspect: dict[str, Any] | None = None) -> str:
    return resolve_buzz_identity(image, inspect)[0]


def cmd_fingerprint(args: argparse.Namespace) -> int:
    if args.substrate == "compose":
        print(json.dumps(fingerprint_compose(), indent=2))
    else:
        print(json.dumps(fingerprint_k3s(args.ssh), indent=2))
    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    execs = ExecAdapter(
        kind=args.substrate,
        project=args.compose_project,
        kubeconfig=args.kubeconfig,
        namespace=args.namespace,
    )
    services = {
        "relay": "relay" if args.substrate == "compose" else args.relay_target,
        "postgres": "postgres" if args.substrate == "compose" else args.postgres_target,
        "redis": "redis" if args.substrate == "compose" else args.redis_target,
        "minio": "minio" if args.substrate == "compose" else args.minio_target,
    }
    sampler = Sampler(execs, args.metrics_url, services)
    row = sampler.sample("debug", True)
    print(json.dumps(row, indent=2))
    return 0


def sim_env(args: argparse.Namespace, profile_path: Path) -> tuple[dict[str, str], str]:
    """Env for the compose relay: image pin, seeded owner, fresh per-run keys."""
    env = os.environ.copy()
    image = args.buzz_image or env.get("BUZZ_IMAGE", "ghcr.io/block/buzz:sha-6e5c462")
    env["BUZZ_IMAGE"] = image
    print_owner = run(
        [args.tenant_sim, "--print-owner", "--profile", str(profile_path)], env=child_env()
    )
    env["SIM_OWNER_PUBKEY"] = print_owner.stdout.strip()
    env["SIM_RELAY_KEY"] = run(["openssl", "rand", "-hex", "32"]).stdout.strip()
    env["SIM_GIT_HMAC"] = run(["openssl", "rand", "-hex", "32"]).stdout.strip()
    return env, image


def resolve_setup_rate_limit(args: argparse.Namespace) -> int:
    """Setup-only rate limit: raised on compose runs that own the stack.

    Raising needs a relay restart before the measured bands, which only the
    compose adapter can do, and only when this run brought the stack up.
    """
    limit = args.setup_rate_limit
    owns_stack = args.substrate == "compose" and not args.skip_reset
    if limit is None:
        return DEFAULT_SETUP_RATE_LIMIT if owns_stack else 0
    if limit < 0:
        raise SystemExit("--setup-rate-limit must be >= 0")
    if limit and not owns_stack:
        raise SystemExit(
            "--setup-rate-limit needs --substrate compose without --skip-reset "
            "(the relay is restarted with default limits before the bands); "
            "pass --setup-rate-limit 0"
        )
    return limit


def cmd_run(args: argparse.Namespace) -> int:
    profile_path = Path(args.profile)
    name, profile_sha, bands = load_profile_meta(profile_path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / "samples.jsonl"

    setup_limit = resolve_setup_rate_limit(args)
    env, image = sim_env(args, profile_path)
    tenant_sim = args.tenant_sim

    notes: list[str] = []
    if args.substrate == "compose":
        adapter: Any = ComposeAdapter(args.compose_project, tuple(args.compose_files.split(",")), env)
        fp = fingerprint_compose()
        services = {
            "relay": "relay",
            "postgres": "postgres",
            "redis": "redis",
            "minio": "minio",
        }
        execs = ExecAdapter(kind="compose", project=args.compose_project)
        substrate_label = args.substrate_label or "workstation-orbstack"
    else:
        adapter = K3sAdapter(
            kubeconfig=args.kubeconfig or "",
            namespace=args.namespace,
            release=args.release,
            ssh=args.ssh,
            ssh_key=args.ssh_key,
        )
        fp = fingerprint_k3s(args.ssh)
        services = {
            "relay": args.relay_target,
            "postgres": args.postgres_target,
            "redis": args.redis_target,
            "minio": args.minio_target,
        }
        execs = ExecAdapter(
            kind="k3s",
            kubeconfig=args.kubeconfig,
            namespace=args.namespace,
        )
        substrate_label = args.substrate_label or "k3s"

    with RunSession(adapter, keep=args.keep) as session:
        if not args.skip_reset:
            adapter.reset()
            adapter.up(raised_limit_env(setup_limit))
        adapter.wait_ready(args.health_url)

        sim_cmd = [
            tenant_sim,
            "--profile",
            str(profile_path),
            "--relay-url",
            args.relay_url,
            "--http-url",
            args.http_url,
            "--out-dir",
            str(out_dir),
            "--git-credential-helper",
            str(Path(args.git_credential_helper).resolve()),
            "--band-signal",
            "stdin",
            "--log-level",
            "info",
        ]
        if args.blink:
            sim_cmd.append("--blink")
        if setup_limit:
            sim_cmd.append("--pause-after-setup")
        proc = subprocess.Popen(
            sim_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
            env=child_env(),
        )
        session.proc = proc
        setup_line = wait_phase_line(proc, "setup-done", args.setup_timeout)
        setup: dict[str, Any] = {
            "rate_limit": setup_limit,
            "provision": setup_line.get("provision"),
        }
        if setup_limit:
            # Measured bands run at the relay's default limits: restart the
            # relay alone before any identity connects.
            adapter.recreate_relay()
            adapter.wait_ready(args.health_url)
            notes.append(
                f"setup rate limits raised to {setup_limit}; relay restarted "
                "with default limits before the population connected"
            )
        if args.substrate == "compose":
            overrides = adapter.relay_rate_limit_overrides()
            if overrides:
                raise RuntimeError(
                    f"relay still has rate-limit overrides before the bands: {sorted(overrides)}"
                )
            setup["band_rate_limits"] = "relay-default"
        if setup_limit:
            assert proc.stdin is not None
            proc.stdin.write(b"continue\n")
            proc.stdin.flush()
        wait_ready_line(proc, args.ready_timeout)

        sampler = Sampler(execs, args.metrics_url, services)
        samples: list[dict[str, Any]] = []

        def run_band(band: str, seconds: int, sampled: bool) -> None:
            assert proc.stdin is not None
            proc.stdin.write(f"band {band}\n".encode())
            proc.stdin.flush()
            end = time.time() + seconds
            while time.time() < end:
                if proc.poll() is not None:
                    raise RuntimeError(f"tenant_sim exited {proc.returncode} during {band}")
                row = sampler.sample(band, sampled)
                samples.append(row)
                with samples_path.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                if sampler.fail_streak >= 3:
                    raise SystemExit(4)
                time.sleep(args.cadence)

        run_band("warmup", bands["warmup"], False)
        run_band("floor", bands["floor"], True)
        run_band("steady", bands["steady"], True)
        run_band("peak", bands["peak"], True)
        run_band("cooldown", bands["cooldown"], False)
        assert proc.stdin is not None
        proc.stdin.write(b"stop\n")
        proc.stdin.flush()
        proc.stdin.close()
        summary = collect_summary(proc, timeout_s=180)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("tenant_sim did not exit after stop") from exc
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        (out_dir / "fingerprint.json").write_text(json.dumps(fp, indent=2))

        # Community bootstrap note: if AUTH/EVENT failed with community-not-found,
        # tenant_sim rejects show up in summary.rejects_by_message.
        rejects = (summary.get("rejects_by_message") or {})
        for msg, n in rejects.items():
            if "community" in msg.lower():
                notes.append(f"community bootstrap: {msg} x{n}")

        run_id = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}-{args.substrate[0]}-{name}"
        buzz_commit, buzz_image = resolve_buzz_identity(image)
        line = write_results_line(
            Path(args.results),
            run_id=run_id,
            substrate=substrate_label,
            buzz_commit=buzz_commit,
            buzz_image=buzz_image,
            harness_commit=git_head(),
            profile=name,
            profile_sha=profile_sha,
            fingerprint=fp,
            samples=samples,
            summary=summary,
            notes="; ".join(notes),
            setup=setup,
        )
        errors = acceptance_errors(line, summary, proc.returncode)
        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "results": args.results,
                    "buzz_commit": buzz_commit,
                    "buzz_image": buzz_image,
                    "summary_rejected": (summary.get("bands") or {})
                    .get("steady", {})
                    .get("rejected"),
                    "acceptance_errors": errors,
                }
            )
        )
        if errors:
            print("acceptance failed:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        if proc.returncode not in (0, None):
            return proc.returncode
        return 0


def seed_snapshot(sampler: "Sampler") -> dict[str, Any]:
    """Relay-side counters bracketing a seed: stored rows, WAL and CPU."""
    stored = sampler.psql("select count(*) from events;")
    lsn = sampler.psql("select pg_current_wal_lsn();")
    db = sampler.psql("select pg_database_size('buzz');")
    metrics = fetch_metrics(sampler.metrics_url) or {}
    return {
        "t": time.time(),
        "stored_rows": int(stored.strip()) if stored and stored.strip() else None,
        "wal_lsn_bytes": lsn_to_bytes(lsn) if lsn else None,
        "db_size_bytes": int(db.strip()) if db and db.strip() else None,
        "events_stored_total": metrics.get("events_stored_total"),
        "relay_usage_usec": sampler.execs.cgroup(sampler.services["relay"])["usage_usec"],
        "postgres_usage_usec": sampler.execs.cgroup(sampler.services["postgres"])["usage_usec"],
    }


def seed_bench_result(
    limits: str,
    client: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Acked rate from the client; stored rate, WAL and CPU from the relay."""
    dt = max(float(after["t"]) - float(before["t"]), 1e-9)

    def delta(key: str) -> float | None:
        a, b = after.get(key), before.get(key)
        if a is None or b is None:
            return None
        return float(a) - float(b)

    stored = delta("stored_rows")
    wal = delta("wal_lsn_bytes")
    db = delta("db_size_bytes")
    relay_cpu = delta("relay_usage_usec")
    pg_cpu = delta("postgres_usage_usec")
    return {
        "limits": limits,
        "client": client,
        "acked_per_s": client.get("acked_per_s"),
        "stored_rows": int(stored) if stored is not None else None,
        "stored_per_s": (stored / dt) if stored is not None else None,
        "window_s": dt,
        "wal_bytes_per_stored": (wal / stored) if wal is not None and stored else None,
        "db_bytes_per_stored": (db / stored) if db is not None and stored else None,
        "relay_cores": (relay_cpu / 1e6 / dt) if relay_cpu is not None else None,
        "postgres_cores": (pg_cpu / 1e6 / dt) if pg_cpu is not None else None,
    }


def cmd_seed_bench(args: argparse.Namespace) -> int:
    """Measure seed throughput on a fresh compose stack: no bands, no results line."""
    if args.substrate != "compose":
        raise SystemExit("seed-bench supports --substrate compose only")
    profile_path = Path(args.profile)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    env, image = sim_env(args, profile_path)
    limit = DEFAULT_SETUP_RATE_LIMIT if args.limits == "raised" else 0
    adapter = ComposeAdapter(args.compose_project, tuple(args.compose_files.split(",")), env)
    execs = ExecAdapter(kind="compose", project=args.compose_project)
    sampler = Sampler(
        execs,
        args.metrics_url,
        {"relay": "relay", "postgres": "postgres", "redis": "redis", "minio": "minio"},
    )
    with RunSession(adapter, keep=args.keep) as session:
        adapter.reset()
        adapter.up(raised_limit_env(limit))
        adapter.wait_ready(args.health_url)
        overrides = adapter.relay_rate_limit_overrides()
        expected = raised_limit_env(limit)
        if overrides != expected:
            raise RuntimeError(f"relay rate-limit env {overrides} != expected {expected}")
        proc = subprocess.Popen(
            [
                args.tenant_sim,
                "--profile",
                str(profile_path),
                "--relay-url",
                args.relay_url,
                "--http-url",
                args.http_url,
                "--out-dir",
                str(out_dir),
                "--git-credential-helper",
                str(Path(args.git_credential_helper).resolve()),
                "--seed-events",
                str(args.seed_events),
                "--seed-max-seconds",
                str(args.seed_max_seconds),
                "--setup-only",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
            env=child_env(),
        )
        session.proc = proc
        wait_phase_line(proc, "seed-start", args.setup_timeout)
        before = seed_snapshot(sampler)
        done = wait_phase_line(proc, "seed-done", args.seed_max_seconds + 120)
        after = seed_snapshot(sampler)
        setup_line = wait_phase_line(proc, "setup-done", 60)
        try:
            code = proc.wait(timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("tenant_sim did not exit after setup") from exc
        result = seed_bench_result(args.limits, done.get("seed") or {}, before, after)
        result["buzz_image"] = resolve_buzz_identity(image)[1]
        result["relay_rate_limit_env"] = overrides
        result["provision"] = setup_line.get("provision")
        result["tenant_sim_exit"] = code
        (out_dir / "seed_bench.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
        return 0 if code == 0 else 1


def acceptance_errors(
    line: dict[str, Any], summary: dict[str, Any], proc_code: int | None
) -> list[str]:
    """Hard gates so a weekly job cannot publish a broken run as authoritative."""
    errs: list[str] = []
    expected = int(
        (summary.get("identities") or {}).get("humans", 0)
        + (summary.get("identities") or {}).get("agents", 0)
    )
    if expected <= 0:
        expected = 30
    bands = line.get("bands") or {}
    floor = bands.get("floor") or {}
    ws = (floor.get("relay_metrics") or {}).get("ws_connections_active")
    if ws is None:
        errs.append("floor ws_connections_active missing")
    elif int(ws) != expected:
        errs.append(f"floor ws_connections_active={ws} != {expected}")
    for name in ("floor", "steady", "peak"):
        band = bands.get(name) or {}
        rejected = int((band.get("relay_metrics") or {}).get("events_rejected") or 0)
        client_rej = int((band.get("client") or {}).get("rejected") or 0)
        if rejected:
            errs.append(f"{name} relay events_rejected={rejected}")
        if client_rej:
            errs.append(f"{name} client rejected={client_rej}")
    lost = int(summary.get("lost_after_backfill") or line.get("totals", {}).get("lost_after_backfill") or 0)
    if lost:
        errs.append(f"lost_after_backfill={lost}")
    media = summary.get("media") or {}
    if int(media.get("rejected") or 0):
        errs.append(f"media.rejected={media.get('rejected')}")
    if int(media.get("uploads") or 0) <= 0:
        errs.append("media.uploads == 0")
    git = summary.get("git") or {}
    if int(git.get("failed") or 0):
        errs.append(f"git.failed={git.get('failed')}")
    if int(git.get("pushes") or 0) <= 0:
        errs.append("git.pushes == 0")
    try:
        floor_rss = bands["floor"]["relay"]["rss_bytes"]["p50"]
        steady_rss = bands["steady"]["relay"]["rss_bytes"]["p50"]
        peak_rss = bands["peak"]["relay"]["rss_bytes"]["max"]
        if not (floor_rss < steady_rss < peak_rss):
            errs.append(
                f"bands not distinct: floor p50={floor_rss} steady p50={steady_rss} peak max={peak_rss}"
            )
    except (KeyError, TypeError) as exc:
        errs.append(f"band rss missing: {exc}")
    if proc_code not in (0, None):
        errs.append(f"tenant_sim exit {proc_code}")
    return errs


def cmd_blink(args: argparse.Namespace) -> int:
    print(
        "T7 blink/rollout is not implemented in this PR. --rollout is "
        "ignored; do not treat a compose run with tenant_sim --blink as a "
        "rolling-update result.",
        file=sys.stderr,
    )
    if getattr(args, "rollout", ""):
        print(f"--rollout was supplied and not executed: {args.rollout!r}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tenant_cogs.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--substrate", choices=("compose", "k3s"), required=True)
        sp.add_argument("--profile", default="perf/profiles/10h-20a.toml")
        sp.add_argument("--relay-url", default="ws://localhost:3030")
        sp.add_argument("--http-url", default="http://localhost:3030")
        sp.add_argument("--metrics-url", default="http://localhost:9202/metrics")
        sp.add_argument("--health-url", default="http://localhost:8088/_readiness")
        sp.add_argument("--out-dir", default="./runs/latest")
        sp.add_argument("--results", default="metrics/cogs/results.jsonl")
        sp.add_argument("--cadence", type=int, default=DEFAULT_CADENCE)
        sp.add_argument("--keep", action="store_true")
        sp.add_argument("--skip-reset", action="store_true")
        sp.add_argument("--tenant-sim", default="./target/release/tenant_sim")
        sp.add_argument(
            "--git-credential-helper",
            default="./target/release/git-credential-nostr",
        )
        sp.add_argument("--buzz-image", default=os.environ.get("BUZZ_IMAGE"))
        sp.add_argument("--compose-project", default=COMPOSE_PROJECT)
        sp.add_argument("--compose-files", default=",".join(COMPOSE_FILES))
        sp.add_argument("--kubeconfig", default=None)
        sp.add_argument("--namespace", default="buzz-loadtest")
        sp.add_argument("--release", default="buzz")
        sp.add_argument("--ssh", default=None)
        sp.add_argument("--ssh-key", default=None)
        sp.add_argument("--substrate-label", default=None)
        sp.add_argument("--relay-target", default="deploy/buzz")
        sp.add_argument("--postgres-target", default="sts/buzz-postgresql")
        sp.add_argument("--redis-target", default="sts/buzz-redis")
        sp.add_argument("--minio-target", default="deploy/buzz-minio")
        sp.add_argument("--blink", action="store_true")
        sp.add_argument(
            "--setup-rate-limit",
            type=int,
            default=None,
            help=(
                "per-key rate limit for provisioning/seed only (compose; default "
                f"{DEFAULT_SETUP_RATE_LIMIT}, 0 = relay defaults throughout)"
            ),
        )
        sp.add_argument("--setup-timeout", type=int, default=900)
        sp.add_argument("--ready-timeout", type=int, default=300)

    run_p = sub.add_parser("run")
    add_common(run_p)
    fp = sub.add_parser("fingerprint")
    add_common(fp)
    sample = sub.add_parser("sample")
    add_common(sample)
    sample.add_argument("--once", action="store_true")
    blink = sub.add_parser("blink")
    add_common(blink)
    blink.add_argument("--rollout", default="")
    bench = sub.add_parser("seed-bench")
    add_common(bench)
    bench.add_argument("--limits", choices=("default", "raised"), required=True)
    bench.add_argument("--seed-events", type=int, default=20000)
    bench.add_argument("--seed-max-seconds", type=int, default=300)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "fingerprint":
        return cmd_fingerprint(args)
    if args.cmd == "sample":
        return cmd_sample(args)
    if args.cmd == "blink":
        return cmd_blink(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "seed-bench":
        return cmd_seed_bench(args)
    raise SystemExit(f"unknown command {args.cmd}")


if __name__ == "__main__":
    sys.exit(main())
