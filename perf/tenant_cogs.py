#!/usr/bin/env python3
"""Orchestrator + sampler for the tenant_sim population generator.

Stdlib only. Drives a compose substrate, samples cgroup/Postgres/MinIO
and relay /metrics during floor/steady/peak bands, and appends one JSONL line
per run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import shlex
import stat
import statistics
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))
import remote_sampler  # noqa: E402


SCHEMA = 1
DEFAULT_CADENCE = 5
# Every run and seed bench brings up its own Compose project, so nothing ever
# has to be deleted before `up`. An override must still be a harness project.
COMPOSE_PROJECT_PREFIX = "buzz-harness-"


def default_lock_dir() -> Path:
    """Per-user lock directory: $XDG_CACHE_HOME (if absolute) or ~/.cache."""
    cache = os.environ.get("XDG_CACHE_HOME", "")
    if not os.path.isabs(cache):
        cache = os.path.join(os.path.expanduser("~"), ".cache")
    return Path(cache) / "buzz-harness" / "locks"


# One exclusive lock per harness project, held from before the empty check
# until after teardown. Fixed per user, so every process of this user sees the
# same lock whatever its TMPDIR, and no other user shares the directory.
LOCK_DIR = default_lock_dir()
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
    """Every command the harness runs. A `docker` command must name a checked
    endpoint (`docker_cmd`); it then runs with that endpoint as DOCKER_HOST and
    without DOCKER_CONTEXT, whatever `env` or this process's environment says."""
    if cmd and cmd[0] == "docker":
        if len(cmd) < 3 or cmd[1] != "--host" or not isinstance(cmd[2], DockerEndpoint):
            raise Refused(
                f"docker command without a checked endpoint: {cmd[:3]}. Nothing was run."
            )
        env = docker_env(cmd[2], env)
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


# --- Docker endpoint guard -----------------------------------------------------
# The Docker control connection is a target too: `run` and `seed-bench` create
# and delete containers, volumes and networks through it. Before any lock,
# output directory or docker command, the harness resolves the endpoint the
# Docker CLI would use (DOCKER_HOST, else DOCKER_CONTEXT, else the config's
# currentContext, else the default socket) and refuses unless it is a local
# Unix socket. Every docker command then names that endpoint with `--host` and
# runs with DOCKER_HOST set to it and DOCKER_CONTEXT removed. With a host
# given, the Docker CLI uses the default context and never reads the context
# store. A remote endpoint is never accepted here.

DEFAULT_DOCKER_HOST = "unix:///var/run/docker.sock"


class DockerEndpoint(str):
    """A Docker endpoint resolve_docker_endpoint checked: a local Unix socket."""


def docker_config_dir(env: Mapping[str, str]) -> Path:
    cfg = env.get("DOCKER_CONFIG")
    return Path(cfg) if cfg else Path(os.path.expanduser("~")) / ".docker"


def _docker_refusal(why: str) -> "Refused":
    return Refused(f"docker endpoint refused: {why}. Nothing was changed.")


def _context_host(config_dir: Path, name: str, docker_host: str) -> str:
    """The endpoint a named Docker context selects."""
    if name == "default":
        return docker_host or DEFAULT_DOCKER_HOST
    meta = config_dir / "contexts" / "meta" / hashlib.sha256(name.encode()).hexdigest() / "meta.json"
    try:
        host = json.loads(meta.read_text())["Endpoints"]["docker"]["Host"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise _docker_refusal(f"cannot read docker context {name!r} ({exc})") from None
    if not isinstance(host, str):
        raise _docker_refusal(f"docker context {name!r} has no endpoint")
    return host


def _current_context(config_dir: Path) -> str:
    path = config_dir / "config.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return "default"
    except (OSError, ValueError) as exc:
        raise _docker_refusal(f"cannot read {path} ({exc})") from None
    if not isinstance(data, dict):
        raise _docker_refusal(f"{path} is not a JSON object")
    name = data.get("currentContext") or "default"
    if not isinstance(name, str):
        raise _docker_refusal(f"{path} has a malformed currentContext")
    return name


def _local_socket(host: str, source: str) -> DockerEndpoint:
    if not host.startswith("unix://"):
        raise _docker_refusal(f"{source} selects {host!r}; only a local Unix socket is allowed")
    path = host[len("unix://"):]
    if not path.startswith("/"):
        raise _docker_refusal(f"{source} selects {host!r}; the socket path must be absolute")
    try:
        mode = os.stat(path).st_mode  # follows a symlinked /var/run/docker.sock
    except OSError as exc:
        raise _docker_refusal(f"{source} selects {host!r}, which does not exist ({exc.strerror})") from None
    if not stat.S_ISSOCK(mode):
        raise _docker_refusal(f"{source} selects {host!r}, which is not a Unix socket")
    return DockerEndpoint(host)


def resolve_docker_endpoint(env: Mapping[str, str] | None = None) -> DockerEndpoint:
    """The endpoint the Docker CLI would use, if it is a local Unix socket.

    A DOCKER_CONTEXT naming anything else is refused even when DOCKER_HOST is
    set, so no selector in the environment can point at a remote daemon."""
    env = os.environ if env is None else env
    config_dir = docker_config_dir(env)
    host = env.get("DOCKER_HOST", "")
    context = env.get("DOCKER_CONTEXT", "")
    from_context = None
    if context:
        from_context = _local_socket(
            _context_host(config_dir, context, host), f"DOCKER_CONTEXT={context}"
        )
    if host:
        return _local_socket(host, "DOCKER_HOST")
    if from_context is not None:
        return from_context
    name = _current_context(config_dir)
    return _local_socket(_context_host(config_dir, name, ""), f"docker context {name!r}")


def docker_cmd(endpoint: DockerEndpoint, *args: str) -> list[str]:
    """A docker command bound to a checked endpoint."""
    if not isinstance(endpoint, DockerEndpoint):
        raise Refused(f"docker needs a checked endpoint, got {endpoint!r}. Nothing was run.")
    return ["docker", "--host", endpoint, *args]


def docker_env(endpoint: DockerEndpoint, env: Mapping[str, str] | None = None) -> dict[str, str]:
    """`env` (default: this process's) with DOCKER_HOST set to `endpoint` and
    DOCKER_CONTEXT removed."""
    src = os.environ if env is None else env
    out = {k: v for k, v in src.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    out["DOCKER_HOST"] = str(endpoint)
    return out


# --- Target guard ------------------------------------------------------------
# The sampler's own wall against the wrong relay. Every URL it reads (health,
# metrics) and every URL it hands tenant_sim must be a literal IP address, never
# a name, inside the run's allow list (--allow-cidr, required) and not on its
# deny list (--deny-list, required; the deny list wins). tenant_sim checks its
# own targets again. No flag or environment variable turns this off.

# Narrowest allow entry per IP version: a wider one would switch the allow
# list off (0.0.0.0/0 allows everything).
MIN_ALLOW_PREFIX = {4: 8, 6: 32}
_IPV4_LITERAL = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
_IPV6_CHARS = re.compile(r"[0-9A-Fa-f:.]+")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_PREFIX = re.compile(r"0|[1-9][0-9]{0,2}")

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _canonical_ip(ip: IpAddress) -> IpAddress:
    """An IPv4-mapped IPv6 address is the IPv4 address it maps to."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _strict_ipv4(s: str) -> ipaddress.IPv4Address | None:
    """Four decimal parts, no leading zeros: refuses 127.1, 0x7f.0.0.1, 0177.0.0.1."""
    if not _IPV4_LITERAL.fullmatch(s):
        return None
    if any(len(p) > 1 and p.startswith("0") for p in s.split(".")):
        return None
    try:
        return ipaddress.IPv4Address(s)
    except ValueError:
        return None


def _strict_ipv6(s: str) -> ipaddress.IPv6Address | None:
    """An IPv6 literal with no zone id (ipaddress itself accepts fe80::1%eth0)."""
    if not _IPV6_CHARS.fullmatch(s):
        return None
    try:
        return ipaddress.IPv6Address(s)
    except ValueError:
        return None


def parse_ip_literal(s: str) -> IpAddress | None:
    v4 = _strict_ipv4(s)
    if v4 is not None:
        return v4
    v6 = _strict_ipv6(s)
    return _canonical_ip(v6) if v6 is not None else None


def parse_cidr(s: str) -> IpNetwork:
    """`a.b.c.d/n`, `x::y/n`, or a bare address. Host bits must be zero; an
    IPv4-mapped block becomes the IPv4 block it maps to."""
    addr, sep, prefix = s.partition("/")
    if sep and not _PREFIX.fullmatch(prefix):
        raise ValueError(f"{s!r}: bad prefix length")
    ip: IpAddress | None = _strict_ipv4(addr)
    if ip is None:
        ip = _strict_ipv6(addr)
    if ip is None:
        raise ValueError(f"{s!r}: not a literal IP address or block")
    plen = int(prefix) if sep else ip.max_prefixlen
    if plen > ip.max_prefixlen:
        raise ValueError(f"{s!r}: prefix longer than {ip.max_prefixlen}")
    if isinstance(ip, ipaddress.IPv6Address) and plen >= 96 and ip.ipv4_mapped is not None:
        ip, plen = ip.ipv4_mapped, plen - 96
    try:
        return ipaddress.ip_network(f"{ip}/{plen}", strict=True)
    except ValueError as exc:
        start = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
        raise ValueError(f"{s!r}: host bits set; the block starts at {start}") from exc


def parse_deny_list(text: str) -> list[IpNetwork]:
    """One address or block per line; `#` comments and blank lines ignored."""
    out: list[IpNetwork] = []
    for i, line in enumerate(text.splitlines(), 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            out.append(parse_cidr(entry))
        except ValueError as exc:
            raise ValueError(f"deny list line {i}: {exc}") from exc
    return out


class CheckedUrl(str):
    """A URL that passed TargetGuard.check_url. http_get takes nothing else."""


class TargetGuard:
    def __init__(self, allow: list[IpNetwork], deny: list[IpNetwork]) -> None:
        if not allow:
            raise ValueError("the allow list is empty")
        for net in allow:
            floor = MIN_ALLOW_PREFIX[net.version]
            if net.prefixlen < floor:
                raise ValueError(
                    f"--allow-cidr {net} is wider than /{floor}; that would switch the allow list off"
                )
        self.allow = allow
        self.deny = deny

    @classmethod
    def from_args(cls, allow: list[str] | None, deny_list: str | None) -> "TargetGuard":
        """Both flags are required. An empty deny-list file is fine; a missing one is not."""
        if not allow:
            raise Refused("--allow-cidr is required (repeatable; no default). Nothing was changed.")
        if not deny_list:
            raise Refused(
                "--deny-list <file> is required (the file may be empty). Nothing was changed."
            )
        try:
            text = Path(deny_list).read_text()
            nets = [parse_cidr(a) for a in allow]
            return cls(nets, parse_deny_list(text))
        except (OSError, ValueError) as exc:
            raise Refused(f"target guard: {exc}. Nothing was changed.") from exc

    def check_ip(self, ip: IpAddress) -> None:
        ip = _canonical_ip(ip)
        if ip.is_unspecified or ip.is_multicast or ip == ipaddress.IPv4Address("255.255.255.255"):
            raise ValueError(f"{ip} is not a unicast address")
        for net in self.deny:
            if ip.version == net.version and ip in net:
                raise ValueError(f"{ip} is on the deny list ({net})")
        if not any(ip.version == net.version and ip in net for net in self.allow):
            raise ValueError(f"{ip} is outside the allow list")

    def check_url(self, raw: str, schemes: tuple[str, ...]) -> CheckedUrl:
        """`scheme://IP[:port][path]`, nothing a parser would rewrite, and the
        stdlib parser must agree on the same address and port."""

        def refuse(why: str) -> Refused:
            return Refused(f"target {raw!r} refused: {why}. Nothing was changed.")

        if not raw.isascii():
            raise refuse("non-ASCII characters")
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "\\%" for c in raw):
            raise refuse("whitespace, control characters, '\\' or '%'")
        scheme, sep, rest = raw.partition("://")
        if not sep:
            raise refuse("no scheme")
        if scheme not in schemes:
            raise refuse(f"scheme must be one of {list(schemes)}")
        authority = re.match(r"[^/?#]*", rest).group(0)  # type: ignore[union-attr]
        path = rest[len(authority):]
        if any(c in path for c in "?#@"):
            raise refuse("query, fragment or '@' after the address")
        if "@" in authority:
            raise refuse("userinfo ('@')")
        ip: IpAddress | None
        if authority.startswith("["):
            host, closed, after = authority[1:].partition("]")
            if not closed:
                raise refuse("unclosed '['")
            if after and not after.startswith(":"):
                raise refuse("junk after ']'")
            port = after[1:] if after else None
            ip = _strict_ipv6(host)
            if ip is None:
                raise refuse("not an IPv6 literal")
        else:
            host, colon, port_s = authority.partition(":")
            port = port_s if colon else None
            ip = _strict_ipv4(host)
            if ip is None:
                raise refuse("not a literal IP address")
        if port is not None and (not _PORT.fullmatch(port) or int(port) > 65535):
            raise refuse("bad port")
        try:
            parsed = urllib.parse.urlsplit(raw)
            same = (
                parsed.username is None
                and parsed.password is None
                and parsed.hostname is not None
                and ipaddress.ip_address(parsed.hostname) == ip
                and parsed.port == (int(port) if port is not None else None)
            )
        except ValueError:
            same = False
        if not same:
            raise refuse("the URL parser reads a different address")
        try:
            self.check_ip(ip)
        except ValueError as exc:
            raise refuse(str(exc)) from exc
        return CheckedUrl(raw)


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect to {newurl!r} refused", headers, fp
        )


def guarded_opener() -> urllib.request.OpenerDirector:
    """Plain HTTP only, redirects refused, and no ProxyHandler, so proxy
    variables in the environment are never read. (`build_opener` would add
    the environment-reading ProxyHandler.)"""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        _RefuseRedirect(),
    ):
        opener.add_handler(handler)
    return opener


_OPENER = guarded_opener()


def http_get(url: CheckedUrl, timeout: float) -> Any:
    """The sampler's only HTTP read."""
    if not isinstance(url, CheckedUrl):
        raise TypeError(f"http_get needs a URL checked by the target guard, got {url!r}")
    return _OPENER.open(url, timeout=timeout)


@dataclass(frozen=True)
class Targets:
    relay: CheckedUrl
    http: CheckedUrl
    health: CheckedUrl
    metrics: CheckedUrl


def check_targets(args: argparse.Namespace) -> Targets:
    """Check every URL a run uses before the lock, docker or tenant_sim."""
    guard = TargetGuard.from_args(args.allow_cidr, args.deny_list)
    return Targets(
        relay=guard.check_url(args.relay_url, ("ws", "wss")),
        http=guard.check_url(args.http_url, ("http", "https")),
        health=guard.check_url(args.health_url, ("http",)),
        metrics=guard.check_url(args.metrics_url, ("http",)),
    )


def guard_args(args: argparse.Namespace) -> list[str]:
    """The same allow and deny lists, passed on to tenant_sim."""
    out: list[str] = []
    for cidr in args.allow_cidr:
        out.extend(["--allow-cidr", cidr])
    out.extend(["--deny-list", str(Path(args.deny_list).resolve())])
    return out


def tenant_sim_cmd(
    args: argparse.Namespace,
    targets: Targets,
    profile_path: Path,
    out_dir: Path,
    extra: list[str],
) -> list[str]:
    """tenant_sim with the checked targets and the same guard lists."""
    return [
        args.tenant_sim,
        "--profile",
        str(profile_path),
        "--relay-url",
        targets.relay,
        "--http-url",
        targets.http,
        *guard_args(args),
        "--out-dir",
        str(out_dir),
        "--git-credential-helper",
        str(Path(args.git_credential_helper).resolve()),
        *extra,
    ]


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


MEMORY_STAT_KEYS = ("anon", "file", "active_file", "inactive_file", "shmem")


def parse_memory_stat(text: str) -> dict[str, int]:
    """The memory.stat fields each sample records, in bytes."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in MEMORY_STAT_KEYS:
            out[parts[0]] = int(parts[1])
    return out


def working_set(current: int | None, stat: dict[str, int]) -> int | None:
    """memory.current minus inactive_file.

    This is cAdvisor's container_memory_working_set_bytes, the figure
    `docker stats` and Kubernetes read. Raw memory.current also counts page
    cache the kernel can drop at any time, which swings it far more than the
    load does.
    """
    if current is None or "inactive_file" not in stat:
        return None
    return max(current - stat["inactive_file"], 0)


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
    project: str = ""
    kubeconfig: str | None = None
    namespace: str = "buzz-loadtest"
    compose_files: tuple[str, ...] = COMPOSE_FILES
    # The checked Docker endpoint; compose commands refuse without one.
    endpoint: DockerEndpoint | None = None

    def compose_base(self) -> list[str]:
        cmd = docker_cmd(self.endpoint, "compose", "-p", self.project)  # type: ignore[arg-type]
        for f in self.compose_files:
            cmd.extend(["-f", f])
        return cmd

    def container(self, service: str) -> str:
        return f"{self.project}-{service}-1"

    def exec_cmd(self, service: str, args: list[str], container: str | None = None) -> list[str]:
        if self.kind == "compose":
            return docker_cmd(self.endpoint, "exec", container or self.container(service), *args)  # type: ignore[arg-type]
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
        stat = parse_memory_stat(
            self.exec(service, ["cat", "/sys/fs/cgroup/memory.stat"]) or ""
        )
        current = parse_memory_current(mem or "")
        return {
            "usage_usec": parse_cpu_stat(cpu or ""),
            # "rss" is the working set; the raw figures stay beside it.
            "rss": working_set(current, stat),
            "rss_anon": stat.get("anon"),
            "mem_current": current,
            "mem_file": stat.get("file"),
            "mem_active_file": stat.get("active_file"),
            "mem_inactive_file": stat.get("inactive_file"),
            "mem_shmem": stat.get("shmem"),
        }


class Refused(Exception):
    """A request the harness will not act on. main() exits 2; nothing was changed."""


class ProjectNotEmpty(Refused):
    """The Compose project already has containers, volumes or networks."""


class ProjectBusy(Refused):
    """Another harness process holds this project's lock."""


def new_run_id(tag: str, name: str) -> str:
    """UTC second plus a random suffix: runs started in the same second differ."""
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{now}-{tag}-{name}-{secrets.token_hex(3)}"


def compose_project_for(run_id: str) -> str:
    """The run's own Compose project: the prefix plus the run id, lowercased."""
    return COMPOSE_PROJECT_PREFIX + re.sub(r"[^a-z0-9_-]", "", run_id.lower())


def check_compose_project(name: str) -> None:
    """Refuse any Compose project that is not a harness project."""
    if not re.fullmatch(re.escape(COMPOSE_PROJECT_PREFIX) + r"[a-z0-9][a-z0-9_-]*", name):
        raise Refused(
            f"compose project must be {COMPOSE_PROJECT_PREFIX!r} followed by a-z, 0-9, "
            f"'-' or '_' (got {name!r}). Nothing was changed."
        )


def resolve_compose_project(args: argparse.Namespace, run_id: str) -> str:
    if args.compose_project:
        check_compose_project(args.compose_project)
        return args.compose_project
    return compose_project_for(run_id)


class ProjectLock:
    """An exclusive, non-blocking flock on one harness project's lock file.

    Taken before anything touches the project and held through teardown. The
    kernel drops it when the process exits, so a crash leaves no stale lock.
    """

    def __init__(self, project: str) -> None:
        check_compose_project(project)
        self.project = project
        self.path = secure_lock_dir(LOCK_DIR) / f"{project}.lock"
        try:
            fd = os.open(
                self.path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
            )
        except OSError as exc:  # ELOOP: the lock file is a symlink
            raise Refused(f"cannot open lock file {self.path}: {exc}. Nothing was changed.") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
                raise Refused(
                    f"lock file {self.path} must be a regular file you own with one link "
                    f"(uid {st.st_uid}, links {st.st_nlink}). Nothing was changed."
                )
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise ProjectBusy(
                f"compose project {project} is in use by another harness process "
                f"({self.path}). Refusing to start; nothing was changed."
            ) from None
        except BaseException:
            os.close(fd)
            raise
        self._fd: int | None = fd

    @property
    def held(self) -> bool:
        """True while this lock is open and its file is still the one at the path."""
        if self._fd is None:
            return False
        try:
            here, ours = os.lstat(self.path), os.fstat(self._fd)
        except OSError:
            return False
        return (here.st_dev, here.st_ino) == (ours.st_dev, ours.st_ino)

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)  # closing the file drops the lock
            self._fd = None


def secure_lock_dir(root: Path) -> Path:
    """Create the lock directory 0700 if missing, then refuse unless it is safe.

    Safe means a real directory (not a symlink), owned by this user, with no
    group or other access.
    """
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)  # exact mode whatever the umask
    except FileExistsError:
        pass
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Refused(
            f"lock directory {root} must be a real directory you own with mode 0700 "
            f"(found {stat.filemode(st.st_mode)}, uid {st.st_uid}). Nothing was changed."
        )
    return root


class ComposeAdapter:
    def __init__(
        self,
        project: str,
        files: tuple[str, ...] = COMPOSE_FILES,
        env: dict[str, str] | None = None,
        lock: ProjectLock | None = None,
        *,
        endpoint: DockerEndpoint,
    ) -> None:
        check_compose_project(project)
        if not isinstance(endpoint, DockerEndpoint):
            raise Refused(f"ComposeAdapter needs a checked docker endpoint, got {endpoint!r}")
        # Every compose and docker command of this stack goes to this endpoint,
        # including teardown.
        self.endpoint = endpoint
        self.project = project
        # This process's lock on the project; `up` refuses without it.
        self.lock = lock
        self.files = files
        # Never inherit rate-limit overrides from the caller's shell.
        self.env = without_limit_env({**os.environ, **(env or {})})
        # True once this process has run `up` on the (verified empty) project;
        # teardown removes only a stack this process brought up.
        self.owned = False

    def cmd(self, *args: str) -> list[str]:
        out = docker_cmd(self.endpoint, "compose", "-p", self.project)
        for f in self.files:
            out.extend(["-f", f])
        out.extend(args)
        return out

    def ensure_empty(self) -> None:
        """Refuse to start on a project that has anything in it. Deletes nothing."""
        left = {kind: ids for kind, ids in self.remaining().items() if ids}
        if left:
            raise ProjectNotEmpty(
                f"compose project {self.project} is not empty: {left}. "
                "Refusing to start; nothing was deleted."
            )

    def up(self, extra_env: dict[str, str] | None = None) -> None:
        if self.lock is None or not self.lock.held or self.lock.project != self.project:
            raise RuntimeError(f"up needs this process to hold the lock for {self.project}")
        self.ensure_empty()
        # From here on, anything in this project was created by this run.
        self.owned = True
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
            docker_cmd(
                self.endpoint,
                "inspect",
                "--format",
                "{{json .Config.Env}}",
                f"{self.project}-relay-1",
            ),
            check=True,
        )
        return rate_limit_overrides(json.loads(proc.stdout or "[]") or [])

    def wait_ready(self, health_url: CheckedUrl, timeout_s: int = 180) -> None:
        deadline = time.time() + timeout_s
        last = ""
        while time.time() < deadline:
            try:
                with http_get(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        return
                    last = f"status {resp.status}"
            except Exception as exc:  # noqa: BLE001 — readiness probe
                last = str(exc)
            time.sleep(2)
        raise RuntimeError(f"relay not ready at {health_url}: {last}")

    def remaining(self) -> dict[str, list[str]]:
        """This project's containers, volumes and networks, by compose label."""
        label = f"label=com.docker.compose.project={self.project}"
        out: dict[str, list[str]] = {}
        for kind, cmd in (
            ("containers", docker_cmd(self.endpoint, "ps", "-a", "-q", "--filter", label)),
            ("volumes", docker_cmd(self.endpoint, "volume", "ls", "-q", "--filter", label)),
            ("networks", docker_cmd(self.endpoint, "network", "ls", "-q", "--filter", label)),
        ):
            out[kind] = run(cmd, check=True, env=self.env).stdout.split()
        return out

    def teardown(self) -> None:
        """Remove the stack this process brought up and prove nothing is left.

        A no-op unless this process ran `up`. Safe to repeat.
        """
        if not self.owned:
            return
        run(self.cmd("down", "-v", "--remove-orphans"), check=True, env=self.env, capture=True)
        left = {kind: ids for kind, ids in self.remaining().items() if ids}
        if left:
            raise RuntimeError(f"compose project {self.project} not empty after teardown: {left}")


# Services the harness pins to linux/amd64 (Block's MinIO image is amd64 only).
AMD64_ONLY_SERVICES = ("minio", "minio-init")


def emulated_services(docker_arch: str | None) -> list[str]:
    """amd64-only services that run emulated on this Docker host."""
    if docker_arch in ("x86_64", "amd64"):
        return []
    return list(AMD64_ONLY_SERVICES)


def emulation_note(fp: dict[str, Any]) -> str | None:
    emulated = fp.get("emulated") or []
    if not emulated:
        return None
    return (
        f"{', '.join(emulated)} ran emulated (linux/amd64 on {fp.get('docker_arch')}): "
        "media upload times and MinIO CPU are not real-speed numbers"
    )


def fingerprint_compose(endpoint: DockerEndpoint, relay_cpu_pin: float = 2.0) -> dict[str, Any]:
    def sysctl(*args: str) -> str | None:
        try:
            return run(["sysctl", "-n", *args]).stdout.strip()
        except Exception:
            return None

    docker = run(
        docker_cmd(
            endpoint,
            "info",
            "--format",
            "{{.NCPU}} {{.MemTotal}} {{.ServerVersion}} {{.Architecture}}",
        ),
        check=False,
    )
    ncpu, mem, ver, arch = None, None, None, None
    if docker.returncode == 0:
        parts = docker.stdout.split()
        if len(parts) >= 4:
            ncpu, mem, ver, arch = parts[0], parts[1], parts[2], parts[3]
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
        "docker_arch": arch,
        "docker_endpoint": str(endpoint),
        "emulated": emulated_services(arch),
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


def fetch_metrics(url: CheckedUrl) -> dict[str, Any] | None:
    try:
        with http_get(url, timeout=5) as resp:
            text = resp.read().decode("utf-8", "replace")
        return parse_prometheus(text)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


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
        metrics_url: CheckedUrl,
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


def seed_flags(args: argparse.Namespace) -> list[str]:
    """tenant_sim's volume seed for a run: --seed-days of the profile's
    history (tenant_sim --check prints the count and its formula)."""
    if not getattr(args, "seed_days", 0):
        return []
    return ["--seed-days", str(args.seed_days), "--seed-max-seconds", str(args.seed_max_seconds)]


def wait_setup(
    proc: subprocess.Popen[Any], seeding: bool, setup_timeout: float, seed_max_seconds: float
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """tenant_sim's setup-done line, and with a seed, what the seed asked
    for and what the client saw: seed-start, then seed-done."""
    if not seeding:
        return wait_phase_line(proc, "setup-done", setup_timeout), None
    start = wait_phase_line(proc, "seed-start", setup_timeout)
    done = wait_phase_line(proc, "seed-done", seed_max_seconds + 120)
    seed = {"days": start.get("days"), "events": start.get("events"), **(done.get("seed") or {})}
    return wait_phase_line(proc, "setup-done", 120), seed


def seed_errors(seed: dict[str, Any] | None) -> list[str]:
    """A run's seed must have written its whole history: a short one
    flatters memory and backfill."""
    if not seed:
        return []
    asked, acked = int(seed.get("events") or 0), int(seed.get("acked") or 0)
    if acked < asked:
        return [f"seed: {acked} of {asked} events acknowledged (rejected {seed.get('rejected')}, errors {seed.get('errors')})"]
    return []


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
        failed = self.close()
        if failed and exc_type is None:
            # A stack left behind fails the run, even after a clean result.
            raise SystemExit(1)

    def close(self) -> bool:
        """Stop the sim and tear down. Returns True when teardown failed."""
        proc = self.proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        failed = False
        if self.adapter is not None and not self.keep:
            try:
                self.adapter.teardown()
            except Exception as exc:
                print(f"teardown failed: {exc}", file=sys.stderr)
                failed = True
        lock = getattr(self.adapter, "lock", None)
        if lock is not None:
            lock.release()
        return failed


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
            # How many samples carried a working set: the data-completeness
            # gate (acceptance_errors) needs it.
            "rss_samples": len(rss),
            "anon_bytes": pct_block(series(comp, "rss_anon")),
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
        # Turned away by the relay's per-key rate limits: counted apart from
        # rejected, never an acceptance error.
        "rate_limited": b.get("rate_limited", 0),
        "received": b.get("received", 0),
        "ok_ms": b.get("ok_ms") or {"p50": 0, "p95": 0, "p99": 0, "max": 0},
        "fanout_ms": b.get("fanout_ms") or {"p50": 0, "p95": 0, "p99": 0, "max": 0},
        # Agent per-turn reads the relay answered in this band, and their time.
        "reads": b.get("reads", 0),
        "read_ms": b.get("read_ms") or {"p50": 0, "p95": 0, "p99": 0, "max": 0},
    }
    # Left out when tenant_sim did not report it, so the floor gate fails closed.
    if "sent_by_kind" in b:
        out["sent_by_kind"] = b["sent_by_kind"]
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
        # The volume seed: days, events asked for, and what the client saw.
        "seed": setup.get("seed"),
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
        # Agent per-turn reads over the run: answered, by what, rate-limited
        # apart, and failed.
        "reads": summary.get("reads"),
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


def inspect_docker_image(image: str, endpoint: DockerEndpoint) -> dict[str, Any]:
    proc = run(
        docker_cmd(endpoint, "image", "inspect", image, "--format", "{{json .}}"),
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}


def resolve_buzz_identity(
    image: str,
    inspect: dict[str, Any] | None = None,
    endpoint: DockerEndpoint | None = None,
) -> tuple[str, str]:
    """Return (buzz_commit, buzz_image) that can distinguish two Monday runs.

    Never records the moving tag `main`. Prefer the image's immutable digest
    plus `org.opencontainers.image.revision` / `sha-<hex>` source commit.
    """
    info = inspect if inspect is not None else inspect_docker_image(image, endpoint)  # type: ignore[arg-type]
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


K3S_UNGUARDED = (
    "--substrate k3s is disabled for {cmd}: it would reach a host through ssh or "
    "kubectl, which the target guard does not cover yet. Nothing was changed."
)


def cmd_fingerprint(args: argparse.Namespace) -> int:
    if args.substrate != "compose":
        raise Refused(K3S_UNGUARDED.format(cmd="fingerprint"))
    endpoint = resolve_docker_endpoint()
    print(json.dumps(fingerprint_compose(endpoint), indent=2))
    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    if args.substrate != "compose":
        raise Refused(K3S_UNGUARDED.format(cmd="sample"))
    if not args.compose_project:
        raise Refused("sample --substrate compose needs --compose-project buzz-harness-<run>")
    check_compose_project(args.compose_project)
    endpoint = resolve_docker_endpoint()
    guard = TargetGuard.from_args(args.allow_cidr, args.deny_list)
    metrics = guard.check_url(args.metrics_url, ("http",))
    execs = ExecAdapter(kind="compose", project=args.compose_project, endpoint=endpoint)
    services = {"relay": "relay", "postgres": "postgres", "redis": "redis", "minio": "minio"}
    sampler = Sampler(execs, metrics, services)
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


K3S_RUN_DISABLED = (
    "run --substrate k3s is disabled: a k3s run needs a bounded, manifest-bound "
    "install and teardown, which this tree does not have yet. Nothing was changed."
)


def cmd_run(args: argparse.Namespace) -> int:
    if args.substrate != "compose":
        print(K3S_RUN_DISABLED, file=sys.stderr)
        return 2
    # Before the lock, docker or tenant_sim: a refused endpoint or target
    # changes nothing.
    endpoint = resolve_docker_endpoint()
    targets = check_targets(args)
    if args.compose_project:
        check_compose_project(args.compose_project)
    elif args.skip_reset:
        raise Refused(
            "--skip-reset samples a harness stack that is already running; name it "
            "with --compose-project buzz-harness-<run>. Nothing was changed."
        )
    profile_path = Path(args.profile)
    name, profile_sha, bands = load_profile_meta(profile_path)
    run_id = new_run_id(args.substrate[0], name)
    project = resolve_compose_project(args, run_id)
    lock = ProjectLock(project)
    print(f"compose project: {project}", file=sys.stderr)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / "samples.jsonl"

    setup_limit = resolve_setup_rate_limit(args)
    env, image = sim_env(args, profile_path)
    tenant_sim = args.tenant_sim

    notes: list[str] = []
    adapter: Any = ComposeAdapter(
        project, tuple(args.compose_files.split(",")), env, lock=lock, endpoint=endpoint
    )
    fp = fingerprint_compose(endpoint)
    note = emulation_note(fp)
    if note:
        notes.append(note)
    services = {
        "relay": "relay",
        "postgres": "postgres",
        "redis": "redis",
        "minio": "minio",
    }
    execs = ExecAdapter(kind="compose", project=project, endpoint=endpoint)
    substrate_label = args.substrate_label or "workstation-orbstack"

    with RunSession(adapter, keep=args.keep) as session:
        if not args.skip_reset:
            adapter.up(raised_limit_env(setup_limit))
        adapter.wait_ready(targets.health)

        sim_cmd = tenant_sim_cmd(
            args,
            targets,
            profile_path,
            out_dir,
            ["--band-signal", "stdin", "--log-level", "info"],
        )
        if args.blink:
            sim_cmd.append("--blink")
        sim_cmd.extend(seed_flags(args))
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
        setup_line, seed = wait_setup(proc, bool(seed_flags(args)), args.setup_timeout, args.seed_max_seconds)
        setup: dict[str, Any] = {
            "rate_limit": setup_limit,
            "provision": setup_line.get("provision"),
            "seed": seed,
            "compose_project": project,
        }
        if setup_limit:
            # Measured bands run at the relay's default limits: restart the
            # relay alone before any identity connects.
            adapter.recreate_relay()
            adapter.wait_ready(targets.health)
            notes.append(
                f"setup rate limits raised to {setup_limit}; relay restarted "
                "with default limits before the population connected"
            )
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

        sampler = Sampler(execs, targets.metrics, services)
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

        buzz_commit, buzz_image = resolve_buzz_identity(image, endpoint=endpoint)
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
        errors = acceptance_errors(line, summary, proc.returncode) + seed_errors(seed)
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
                    "band_order": band_order_note(line),
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
    if args.skip_reset:
        raise Refused(
            "seed-bench always measures a fresh stack under its own project name; "
            "--skip-reset has nothing to skip. Nothing was changed."
        )
    endpoint = resolve_docker_endpoint()
    targets = check_targets(args)
    if args.compose_project:
        check_compose_project(args.compose_project)
    project = resolve_compose_project(args, new_run_id("seed", args.limits))
    lock = ProjectLock(project)
    print(f"compose project: {project}", file=sys.stderr)
    profile_path = Path(args.profile)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    env, image = sim_env(args, profile_path)
    limit = DEFAULT_SETUP_RATE_LIMIT if args.limits == "raised" else 0
    adapter = ComposeAdapter(
        project, tuple(args.compose_files.split(",")), env, lock=lock, endpoint=endpoint
    )
    execs = ExecAdapter(kind="compose", project=project, endpoint=endpoint)
    sampler = Sampler(
        execs,
        targets.metrics,
        {"relay": "relay", "postgres": "postgres", "redis": "redis", "minio": "minio"},
    )
    with RunSession(adapter, keep=args.keep) as session:
        adapter.up(raised_limit_env(limit))
        adapter.wait_ready(targets.health)
        overrides = adapter.relay_rate_limit_overrides()
        expected = raised_limit_env(limit)
        if overrides != expected:
            raise RuntimeError(f"relay rate-limit env {overrides} != expected {expected}")
        proc = subprocess.Popen(
            tenant_sim_cmd(
                args,
                targets,
                profile_path,
                out_dir,
                [
                    "--seed-events",
                    str(args.seed_events),
                    "--seed-max-seconds",
                    str(args.seed_max_seconds),
                    "--setup-only",
                ],
            ),
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
        result["buzz_image"] = resolve_buzz_identity(image, endpoint=endpoint)[1]
        result["relay_rate_limit_env"] = overrides
        result["provision"] = setup_line.get("provision")
        result["tenant_sim_exit"] = code
        (out_dir / "seed_bench.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
        return 0 if code == 0 else 1


# The only kinds an idle client sends: presence and typing, both ephemeral.
FLOOR_KINDS = frozenset({"20001", "20002"})


def floor_errors(floor: dict[str, Any]) -> list[str]:
    """Floor is idle clients: heartbeats only, nothing stored."""
    errs: list[str] = []
    client = floor.get("client") or {}
    kinds = client.get("sent_by_kind")
    sent = int(client.get("sent") or 0)
    if kinds is None:
        errs.append("floor client.sent_by_kind missing")
    elif sum(int(v) for v in kinds.values()) != sent:
        errs.append(
            f"floor sent_by_kind covers {sum(int(v) for v in kinds.values())} of {sent} sends"
        )
    else:
        other = {k: v for k, v in sorted(kinds.items()) if k not in FLOOR_KINDS and int(v)}
        if other:
            errs.append(f"floor sent non-heartbeat kinds {other}")
    stored = (floor.get("relay_metrics") or {}).get("events_stored")
    if stored is None:
        errs.append("floor relay events_stored missing")
    elif int(stored):
        errs.append(f"floor relay events_stored={stored}, expected 0")
    return errs


# The fewest samples, with the relay's working set in them, a sampled band
# needs to count.
MIN_BAND_SAMPLES = 3


def relay_ws_samples(band: dict[str, Any]) -> int:
    """How many of a band's samples carried the relay's working set."""
    n = (band.get("relay") or {}).get("rss_samples")
    return int(n) if isinstance(n, (int, float)) else 0


def band_order_note(line: dict[str, Any]) -> str:
    """Whether the relay's working set rose band by band: a note, never a
    gate."""
    bands = line.get("bands") or {}
    try:
        floor_rss = bands["floor"]["relay"]["rss_bytes"]["p50"]
        steady_rss = bands["steady"]["relay"]["rss_bytes"]["p50"]
        peak_rss = bands["peak"]["relay"]["rss_bytes"]["max"]
    except (KeyError, TypeError) as exc:
        return f"band order: relay working set missing ({exc})"
    if floor_rss < steady_rss < peak_rss:
        return "band order: distinct (relay working set rises floor < steady < peak)"
    return (
        f"band order: not distinct (relay working set floor p50={floor_rss} "
        f"steady p50={steady_rss} peak max={peak_rss})"
    )


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
    errs.extend(floor_errors(floor))
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
    # Agent reads: none may fail, and agents that took turns must have read.
    reads = summary.get("reads")
    turns = int((summary.get("sent_by_kind") or {}).get("44200") or 0)
    if not isinstance(reads, dict):
        errs.append("reads missing from the summary")
    else:
        if int(reads.get("failed") or 0):
            errs.append(f"reads.failed={reads.get('failed')}")
        if turns and int(reads.get("reads") or 0) <= 0:
            errs.append(f"agents took {turns} turns but no read was answered")
    git = summary.get("git") or {}
    if int(git.get("failed") or 0):
        errs.append(f"git.failed={git.get('failed')}")
    if int(git.get("pushes") or 0) <= 0:
        errs.append("git.pushes == 0")
    # Data completeness, not band order: each sampled band needs enough
    # samples with the relay's working set in them. A valid paid run must
    # not fail because the relay's memory didn't rise band by band; the
    # order is reported by band_order_note instead.
    for name in ("floor", "steady", "peak"):
        n = relay_ws_samples(bands.get(name) or {})
        if n < MIN_BAND_SAMPLES:
            errs.append(f"{name}: {n} samples with the relay's working set, fewer than {MIN_BAND_SAMPLES}")
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


def cmd_docker_endpoint(args: argparse.Namespace) -> int:
    print(resolve_docker_endpoint())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tenant_cogs.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--substrate", choices=("compose", "k3s"), required=True)
        sp.add_argument("--profile", default="perf/profiles/10h-20a.toml")
        # Targets are literal IP addresses, never names (see the target guard).
        sp.add_argument("--relay-url", default="ws://127.0.0.1:3030")
        sp.add_argument("--http-url", default="http://127.0.0.1:3030")
        sp.add_argument("--metrics-url", default="http://127.0.0.1:9202/metrics")
        sp.add_argument("--health-url", default="http://127.0.0.1:8088/_readiness")
        sp.add_argument(
            "--allow-cidr",
            action="append",
            default=[],
            help="block every target must sit inside (repeatable; required to connect; no default)",
        )
        sp.add_argument(
            "--deny-list",
            default=None,
            help="file of addresses/blocks no target may use; wins over --allow-cidr (required to connect; may be empty)",
        )
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
        sp.add_argument(
            "--compose-project",
            default=None,
            help="default: buzz-harness-<run id>, new per run; an override must start with buzz-harness-",
        )
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
    run_p.add_argument(
        "--seed-days",
        type=int,
        default=0,
        help="seed this many days of the profile's history before the bands (0: none)",
    )
    run_p.add_argument("--seed-max-seconds", type=int, default=1800)
    fp = sub.add_parser("fingerprint")
    add_common(fp)
    sample = sub.add_parser("sample")
    add_common(sample)
    sample.add_argument("--once", action="store_true")
    remote_sampler.add_parser(sub)
    blink = sub.add_parser("blink")
    add_common(blink)
    blink.add_argument("--rollout", default="")
    bench = sub.add_parser("seed-bench")
    add_common(bench)
    bench.add_argument("--limits", choices=("default", "raised"), required=True)
    bench.add_argument("--seed-events", type=int, default=20000)
    bench.add_argument("--seed-max-seconds", type=int, default=300)
    sub.add_parser(
        "docker-endpoint",
        help="print the checked local Docker endpoint, or refuse (exit 2); used by build-linux.sh",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # The band clock is its own file, stdlib only, so a wrapper can pin it
    # by its sha256; `clock` runs it with the rest of the arguments.
    if argv[:1] == ["clock"]:
        import band_clock

        return band_clock.main(argv[1:])
    args = build_parser().parse_args(argv)
    commands = {
        "fingerprint": cmd_fingerprint,
        "sample": cmd_sample,
        "blink": cmd_blink,
        "run": cmd_run,
        "seed-bench": cmd_seed_bench,
        "docker-endpoint": cmd_docker_endpoint,
        "remote-sample": lambda a: remote_sampler.cmd_remote_sample(
            a, TargetGuard.from_args(a.allow_cidr, a.deny_list), parse_ip_literal
        ),
    }
    try:
        return commands[args.cmd](args)
    except (Refused, remote_sampler.Refused) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
