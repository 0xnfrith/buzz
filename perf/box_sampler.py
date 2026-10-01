#!/usr/bin/python3 -IB
"""Box-side reader for the remote sampler (`tenant_cogs.py remote-sample`).

One call prints one JSON line about the box it runs on, then exits:

    box_sampler.py --tier fast|slow --config <file>
    box_sampler.py --steal-check

`--steal-check` (run once per box by the deployment, over its own access,
never by the sampler's key) prints whether the CPU reports steal time at all.
It runs CPUID through a small executable page; the deployment writes the
answer into the config, and every sample reports it from there, so no
sample runs machine code.

It is meant to be the forced command of a restricted SSH key, behind a
wrapper the deployment owns, so it takes nothing from the client: no path, no
SQL, no option. The wrapper maps the client's word to `--tier` and passes a
fixed `--config`; this file refuses any tier but `fast` and `slow` (exit 64)
and reads nothing when it does.

It writes nothing on the box: no file, no temp file, and no bytecode (the
`-IB` above: isolated mode, which ignores PYTHON* variables and the user
site folder, and no .pyc files). It reads `/proc`, `/sys/fs/cgroup`, the Docker volumes' and
logs' folders, and runs only these commands, each with fixed arguments:

    docker ps --no-trunc --filter label=com.docker.compose.project=<config>
    docker inspect -f '{{.Id}}<tab>{{.State.Pid}}' <ids from ps>
    docker system df                                  (slow tier)
    docker exec <postgres id> psql ... -tAc <fixed SQL>  (slow tier)
    nft -s list table <config>,  nft list table <config>

`fast` is cheap, for every tick: memory, CPU (steal included), load,
out-of-memory kills, disk I/O, the filesystem, each container's cgroup, and
the nftables rule set's hash and drop counters. `slow` adds the disk walks
(Postgres data and WAL, MinIO media, Redis persistence, git storage, logs,
image overhead) and the WAL position, so the reader does not load the box it
measures every few seconds. Each sample records the reader's own CPU time and
peak memory, its children's included.

The config (JSON, written by the deployment, root-owned):

    {"compose_project": "...", "nft_table": "inet ...", "docker": "/usr/bin/docker",
     "nft": "/usr/sbin/nft", "docker_root": "/var/lib/docker",
     "volumes": {"postgres": "...", "minio": "...", "redis": "...", "git": "..."},
     "postgres": {"service": "postgres", "user": "...", "db": "..."},
     "journal": "/var/log/journal", "units": ["<name>.service", ...],
     "steal": {"reported": true|false|null, "why": "..."}}

`units` are systemd services whose cgroups are read like a container's (the
load generator's own, on its box).

`docker`, `nft` and `volumes` may be null on a box without them (the load
generator's box); what they would read is then absent, with the reason.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, NoReturn

VERSION = 1
TIERS = ("fast", "slow")
# Exit codes: 0 a sample; 64 a refused tier; 2 a bad config.
EXIT_REFUSED_TIER = 64
EXIT_BAD_CONFIG = 2
COMMAND_TIMEOUT_S = 15

Runner = Callable[[list[str]], "tuple[int, str, str]"]


def run_command(argv: list[str]) -> tuple[int, str, str]:
    """Run argv with no shell and no stdin; return (exit, stdout, stderr)."""
    try:
        p = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_S,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {COMMAND_TIMEOUT_S}s"
    return p.returncode, p.stdout, p.stderr


# ---- the config ----

PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TABLE_RE = re.compile(r"^(ip|ip6|inet|arp|bridge|netdev) [A-Za-z0-9_]{1,64}$")
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,99}\.service$")


class ConfigError(Exception):
    pass


def load_config(text: str) -> dict[str, Any]:
    """Parse and check the config strictly: every value is fixed by the
    deployment, so anything unexpected is refused rather than used."""
    try:
        c = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"not JSON: {e}") from e
    if not isinstance(c, dict):
        raise ConfigError("not a JSON object")
    known = {"compose_project", "nft_table", "docker", "nft", "docker_root", "volumes", "postgres", "journal", "units", "steal"}
    extra = sorted(set(c) - known)
    if extra:
        raise ConfigError(f"unknown keys {extra}")
    proj = c.get("compose_project")
    if proj is not None and (not isinstance(proj, str) or not PROJECT_RE.match(proj)):
        raise ConfigError(f"compose_project {proj!r} is not a Compose project name")
    table = c.get("nft_table")
    if table is not None and (not isinstance(table, str) or not TABLE_RE.match(table)):
        raise ConfigError(f"nft_table {table!r} is not '<family> <name>'")
    for k in ("docker", "nft", "docker_root", "journal"):
        v = c.get(k)
        if v is not None and (not isinstance(v, str) or not v.startswith("/") or ".." in v.split("/")):
            raise ConfigError(f"{k} {v!r} is not an absolute path")
    vols = c.get("volumes")
    if vols is not None:
        if not isinstance(vols, dict) or set(vols) - {"postgres", "minio", "redis", "git"}:
            raise ConfigError("volumes holds keys other than postgres, minio, redis and git")
        for k, v in vols.items():
            if not isinstance(v, str) or not VOLUME_RE.match(v):
                raise ConfigError(f"volume {k} {v!r} is not a volume name")
    pg = c.get("postgres")
    if pg is not None:
        if not isinstance(pg, dict) or set(pg) != {"service", "user", "db"}:
            raise ConfigError("postgres must hold exactly service, user and db")
        for k, v in pg.items():
            if not isinstance(v, str) or not (SERVICE_RE if k == "service" else NAME_RE).match(v):
                raise ConfigError(f"postgres {k} {v!r} is not a plain name")
    st = c.get("steal")
    if st is not None and (not isinstance(st, dict) or set(st) != {"reported", "why"} or not (st["reported"] is None or isinstance(st["reported"], bool)) or not isinstance(st["why"], str)):
        raise ConfigError("steal must be {\"reported\": true|false|null, \"why\": \"...\"}")
    units = c.get("units")
    if units is not None and (not isinstance(units, list) or not all(isinstance(u, str) and UNIT_RE.match(u) for u in units)):
        raise ConfigError(f"units {units!r} is not a list of systemd service names")
    if (c.get("docker") is None) != (proj is None):
        raise ConfigError("docker and compose_project are set together, or neither")
    if (c.get("nft") is None) != (table is None):
        raise ConfigError("nft and nft_table are set together, or neither")
    return c


# ---- /proc ----


def parse_meminfo(text: str) -> dict[str, int]:
    """/proc/meminfo, in bytes."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+(?:\(\w+\))?):\s+(\d+)(?:\s+kB)?$", line.strip())
        if m:
            out[m.group(1)] = int(m.group(2)) * (1024 if line.strip().endswith("kB") else 1)
    keep = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree", "Shmem")
    return {k: out[k] for k in keep if k in out}


CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def parse_stat(text: str) -> dict[str, Any]:
    """/proc/stat: the summed cpu line's ticks, and the number of CPUs."""
    ticks: dict[str, int] = {}
    ncpu = 0
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "cpu":
            ticks = {name: int(v) for name, v in zip(CPU_FIELDS, f[1:])}
        elif re.match(r"^cpu\d+$", f[0]):
            ncpu += 1
    return {"ticks": ticks, "ncpu": ncpu}


def parse_loadavg(text: str) -> list[float]:
    return [float(x) for x in text.split()[:3]]


def parse_vmstat_oom(text: str) -> int | None:
    for line in text.splitlines():
        f = line.split()
        if len(f) == 2 and f[0] == "oom_kill":
            return int(f[1])
    return None


def parse_diskstats(text: str) -> dict[str, dict[str, int]]:
    """/proc/diskstats for whole disks (not partitions, loops, ram or dm)."""
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 14:
            continue
        name = f[2]
        if re.match(r"^(loop|ram|dm-|sr|zram)", name) or re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+$", name) or re.match(r"^nvme\d+n\d+p\d+$", name):
            continue
        out[name] = {
            "reads": int(f[3]),
            "sectors_read": int(f[5]),
            "writes": int(f[7]),
            "sectors_written": int(f[9]),
            "io_ms": int(f[12]),
        }
    return out


# ---- steal: does the CPU report it at all? ----

# x86-64 System V code: store CPUID leaf edi's eax, ebx, ecx, edx at [rsi].
#   push rbx; mov eax, edi; xor ecx, ecx; cpuid; mov [rsi], eax;
#   mov [rsi+4], ebx; mov [rsi+8], ecx; mov [rsi+12], edx; pop rbx; ret
_CPUID_CODE = bytes.fromhex(
    "53"  # push rbx
    "89f8"  # mov eax, edi
    "31c9"  # xor ecx, ecx
    "0fa2"  # cpuid
    "8906"  # mov [rsi], eax
    "895e04"  # mov [rsi+4], ebx
    "894e08"  # mov [rsi+8], ecx
    "89560c"  # mov [rsi+12], edx
    "5b"  # pop rbx
    "c3"  # ret
)

KVM_SIGNATURE = b"KVMKVMKVM\x00\x00\x00"
KVM_FEATURE_STEAL_TIME_BIT = 5


def steal_decision(machine: str, leaf0: tuple[int, int, int, int] | None, leaf1: tuple[int, int, int, int] | None, why: str = "") -> dict[str, Any]:
    """Whether the guest kernel accounts steal time. Only a KVM guest whose
    CPUID leaf 0x40000001 sets KVM_FEATURE_STEAL_TIME does; anything else
    reports steal as unknown, never as 0 (on such a CPU /proc/stat's steal
    is structurally 0)."""
    if machine not in ("x86_64", "AMD64"):
        return {"reported": None, "why": f"unknown: not x86 ({machine})"}
    if leaf0 is None or leaf1 is None:
        return {"reported": None, "why": f"unknown: CPUID could not be read ({why})"}
    sig = b"".join(r.to_bytes(4, "little") for r in leaf0[1:4])
    if sig != KVM_SIGNATURE:
        return {"reported": None, "why": f"unknown: the hypervisor is not KVM ({sig!r})"}
    if leaf0[0] < 0x40000001:
        return {"reported": None, "why": f"unknown: KVM's highest leaf is {leaf0[0]:#x}"}
    on = bool(leaf1[0] >> KVM_FEATURE_STEAL_TIME_BIT & 1)
    return {"reported": on, "why": "KVM_FEATURE_STEAL_TIME is " + ("set" if on else "clear: steal is not accounted")}


def read_cpuid(leaf: int) -> tuple[int, int, int, int]:
    """CPUID through a small executable page; changes nothing on the box."""
    import ctypes
    import mmap

    page = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    page.write(_CPUID_CODE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(page))
    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_void_p)(addr)
    regs = (ctypes.c_uint32 * 4)()
    fn(leaf, ctypes.addressof(regs))
    return tuple(regs)  # type: ignore[return-value]


def steal_reported() -> dict[str, Any]:
    machine = platform.machine()
    if machine not in ("x86_64", "AMD64"):
        return steal_decision(machine, None, None)
    try:
        return steal_decision(machine, read_cpuid(0x40000000), read_cpuid(0x40000001))
    except Exception as e:  # noqa: BLE001 - any failure means "unknown"
        return steal_decision(machine, None, None, str(e))


# ---- cgroups ----


def parse_kv(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) == 2 and f[1].lstrip("-").isdigit():
            out[f[0]] = int(f[1])
    return out


def parse_single(text: str) -> int | None:
    t = text.strip()
    return int(t) if t.isdigit() else None


def cgroup_path(proc_cgroup: str) -> str | None:
    """The cgroup v2 path from /proc/<pid>/cgroup ("0::/system.slice/...")."""
    for line in proc_cgroup.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return None


def read_cgroup(root: Path, path: str) -> dict[str, Any]:
    d = root / "sys/fs/cgroup" / path.lstrip("/")
    cpu = parse_kv(_read(d / "cpu.stat") or "")
    stat = parse_kv(_read(d / "memory.stat") or "")
    events = parse_kv(_read(d / "memory.events") or "")
    current = parse_single(_read(d / "memory.current") or "")
    peak = parse_single(_read(d / "memory.peak") or "")
    ws = None
    if current is not None:
        ws = max(current - stat.get("inactive_file", 0), 0)
    return {
        "cgroup": path,
        "usage_usec": cpu.get("usage_usec"),
        "mem_current": current,
        "mem_peak": peak,
        "working_set": ws,
        "anon": stat.get("anon"),
        "file": stat.get("file"),
        "active_file": stat.get("active_file"),
        "inactive_file": stat.get("inactive_file"),
        "shmem": stat.get("shmem"),
        "oom_kill": events.get("oom_kill"),
    }


# ---- docker ----


def parse_docker_ps(text: str) -> dict[str, str]:
    """`docker ps --no-trunc --format '{{.ID}}<tab>{{.Label ...service}}'`:
    service -> full id."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) == 2 and re.match(r"^[0-9a-f]{64}$", f[0]) and f[1]:
            out[f[1]] = f[0]
    return out


def parse_docker_inspect(text: str) -> dict[str, int]:
    """`docker inspect -f '{{.Id}}<tab>{{.State.Pid}}'`: full id -> pid."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) == 2 and re.match(r"^[0-9a-f]{64}$", f[0]) and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out


SIZE_UNITS = {"B": 1, "kB": 1000, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
              "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}


def parse_size(s: str) -> int | None:
    m = re.match(r"^\s*([0-9.]+)\s*([A-Za-z]+)\s*$", s)
    if not m or m.group(2) not in SIZE_UNITS:
        return None
    return int(float(m.group(1)) * SIZE_UNITS[m.group(2)])


def parse_system_df(text: str) -> dict[str, int | None]:
    """`docker system df --format '{{.Type}}<tab>{{.Size}}'`: bytes by type."""
    out: dict[str, int | None] = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) == 2:
            out[f[0]] = parse_size(f[1])
    return out


def parse_wal(text: str) -> dict[str, int | None]:
    """psql -tA of `select pg_current_wal_lsn(), pg_database_size(...)`:
    "<hi>/<lo>|<bytes>"."""
    f = text.strip().split("|")
    if len(f) != 2:
        return {"wal_lsn_bytes": None, "db_size_bytes": None}
    m = re.match(r"^([0-9A-Fa-f]+)/([0-9A-Fa-f]+)$", f[0])
    lsn = (int(m.group(1), 16) << 32) + int(m.group(2), 16) if m else None
    return {"wal_lsn_bytes": lsn, "db_size_bytes": int(f[1]) if f[1].isdigit() else None}


# The one query the reader runs, fixed: the WAL position and the database's
# size. Nothing in it comes from the client or the config but the names the
# config already checked.
WAL_SQL = "select pg_current_wal_lsn(), pg_database_size(current_database())"


# ---- nftables ----


def drop_counters(listing: str) -> dict[str, dict[str, int]]:
    """Sum each chain's "counter packets N bytes M" from `nft list table`."""
    out: dict[str, dict[str, int]] = {}
    chain = None
    for line in listing.splitlines():
        m = re.match(r"^\s*chain\s+(\S+)\s*\{", line)
        if m:
            chain = m.group(1)
            out.setdefault(chain, {"packets": 0, "bytes": 0})
            continue
        m = re.search(r"counter packets (\d+) bytes (\d+)", line)
        if m and chain:
            out[chain]["packets"] += int(m.group(1))
            out[chain]["bytes"] += int(m.group(2))
    return out


# ---- disk walks ----


def walk_size(top: Path) -> dict[str, int] | None:
    """Apparent bytes and file count under top, never following a link."""
    if not top.is_dir() or top.is_symlink():
        return None
    total = files = 0
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        for n in filenames:
            try:
                st = os.lstat(os.path.join(dirpath, n))
            except OSError:
                continue
            total += st.st_size
            files += 1
    return {"bytes": total, "files": files}


# ---- reading ----


def _read(p: Path) -> str | None:
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def sample(tier: str, cfg: dict[str, Any], root: Path = Path("/"), runner: Runner = run_command,
           clock: Callable[[], float] = time.time) -> dict[str, Any]:
    """One sample of the box, as a dict ready for JSON."""
    errors: list[str] = []
    row: dict[str, Any] = {"v": VERSION, "tier": tier, "t_unix": clock()}

    def need(path: str) -> str:
        t = _read(root / path)
        if t is None:
            errors.append(f"{path}: cannot read")
        return t or ""

    box: dict[str, Any] = {
        "mem": parse_meminfo(need("proc/meminfo")),
        "cpu": parse_stat(need("proc/stat")),
        "load": parse_loadavg(need("proc/loadavg") or "0 0 0"),
        "oom_kill": parse_vmstat_oom(need("proc/vmstat")),
        "disk_io": parse_diskstats(need("proc/diskstats")),
    }
    try:
        st = os.statvfs(root)
        box["fs"] = {"total": st.f_blocks * st.f_frsize, "free": st.f_bfree * st.f_frsize,
                     "avail": st.f_bavail * st.f_frsize, "used": (st.f_blocks - st.f_bfree) * st.f_frsize}
    except OSError as e:
        errors.append(f"statvfs: {e}")
    row["box"] = box
    # Whether steal means anything here comes from the config (--steal-check,
    # once per box); never from a CPUID call per sample. Without it, steal is
    # unknown, never 0.
    row["steal"] = cfg.get("steal") or {"reported": None, "why": "unknown: not checked (no steal in the config)"}

    containers: dict[str, Any] = {}
    ids: dict[str, str] = {}
    docker = cfg.get("docker")
    if docker:
        code, out, err = runner([docker, "ps", "--no-trunc", "--filter",
                                 f"label=com.docker.compose.project={cfg['compose_project']}",
                                 "--format", '{{.ID}}\t{{.Label "com.docker.compose.service"}}'])
        if code != 0:
            errors.append(f"docker ps: exit {code}: {err.strip()[:200]}")
        ids = parse_docker_ps(out) if code == 0 else {}
        pids: dict[str, int] = {}
        if ids:
            code, out, err = runner([docker, "inspect", "-f", "{{.Id}}\t{{.State.Pid}}", *sorted(ids.values())])
            if code != 0:
                errors.append(f"docker inspect: exit {code}: {err.strip()[:200]}")
            pids = parse_docker_inspect(out) if code == 0 else {}
        for svc, cid in sorted(ids.items()):
            entry: dict[str, Any] = {"id": cid, "pid": pids.get(cid)}
            pid = pids.get(cid)
            path = cgroup_path(_read(root / f"proc/{pid}/cgroup") or "") if pid else None
            if path:
                entry.update(read_cgroup(root, path))
            else:
                errors.append(f"container {svc}: no cgroup (pid {pid})")
            containers[svc] = entry
    else:
        row["containers_absent"] = "no docker on this box (config)"
    row["containers"] = containers
    units: dict[str, Any] = {}
    for u in cfg.get("units") or []:
        units[u] = read_cgroup(root, f"system.slice/{u}")
        if units[u]["mem_current"] is None:
            errors.append(f"unit {u}: no cgroup (not running?)")
    row["units"] = units

    table, nft = cfg.get("nft_table"), cfg.get("nft")
    if table and nft:
        fam, name = table.split()
        code, stateless, err = runner([nft, "-s", "list", "table", fam, name])
        code2, listing, err2 = runner([nft, "list", "table", fam, name])
        if code != 0 or code2 != 0:
            errors.append(f"nft: exit {code}/{code2}: {(err or err2).strip()[:200]}")
            row["nft"] = None
        else:
            row["nft"] = {"hash": hashlib.sha256(stateless.encode()).hexdigest(), "drops": drop_counters(listing)}
    else:
        row["nft"] = None
        row["nft_absent"] = "no nft table in the config"

    if tier == "slow":
        disk: dict[str, Any] = {}
        droot = root / (cfg.get("docker_root") or "/var/lib/docker").lstrip("/")
        vols = cfg.get("volumes") or {}
        for k in ("minio", "redis", "git"):
            if k in vols:
                disk[k] = walk_size(droot / "volumes" / vols[k] / "_data")
        if "postgres" in vols:
            pg_dir = droot / "volumes" / vols["postgres"] / "_data"
            whole, wal = walk_size(pg_dir), walk_size(pg_dir / "pg_wal")
            disk["postgres_volume"] = whole
            disk["wal"] = wal
            if whole and wal:
                disk["postgres_data"] = {"bytes": whole["bytes"] - wal["bytes"], "files": whole["files"] - wal["files"]}
        logs = 0
        for cid in ids.values():
            d = droot / "containers" / cid
            for f in (d.iterdir() if d.is_dir() else []):
                if f.name.startswith(f"{cid}-json.log") and f.is_file() and not f.is_symlink():
                    logs += f.stat().st_size
        disk["container_logs_bytes"] = logs if docker else None
        journal = cfg.get("journal")
        disk["journal"] = walk_size(root / journal.lstrip("/")) if journal else None
        if docker:
            code, out, err = runner([docker, "system", "df", "--format", "{{.Type}}\t{{.Size}}"])
            if code != 0:
                errors.append(f"docker system df: exit {code}: {err.strip()[:200]}")
            disk["images_bytes"] = parse_system_df(out).get("Images") if code == 0 else None
            pg = cfg.get("postgres")
            pg_id = ids.get(pg["service"]) if pg else None
            if pg and pg_id:
                code, out, err = runner([docker, "exec", pg_id, "psql", "-U", pg["user"], "-d", pg["db"], "-tAc", WAL_SQL])
                if code != 0:
                    errors.append(f"psql: exit {code}: {err.strip()[:200]}")
                row["wal"] = parse_wal(out) if code == 0 else None
            elif pg:
                errors.append(f"psql: no {pg['service']} container")
        row["disk"] = disk

    me, kids = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    row["reader"] = {
        "cpu_s": round(me.ru_utime + me.ru_stime + kids.ru_utime + kids.ru_stime, 4),
        "maxrss_kb": me.ru_maxrss,
        "children_maxrss_kb": kids.ru_maxrss,
    }
    row["errors"] = errors
    return row


class _Usage(Exception):
    pass


class _QuietParser(argparse.ArgumentParser):
    """Raises instead of printing argparse's own usage, so a refusal is
    always the one exact line below."""

    def error(self, message: str) -> "NoReturn":  # type: ignore[override]
        raise _Usage(message)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--steal-check"]:
        print(json.dumps(steal_reported(), separators=(",", ":")))
        return 0
    p = _QuietParser(prog="box_sampler.py", add_help=False)
    p.add_argument("--tier", required=True)
    p.add_argument("--config", required=True)
    try:
        args, extra = p.parse_known_args(argv)
    except _Usage:
        print("refused: usage: box_sampler.py --tier fast|slow --config <file>; nothing was read", file=sys.stderr)
        return EXIT_REFUSED_TIER
    if extra or args.tier not in TIERS:
        print(f"refused: tier {args.tier!r} is not fast or slow; nothing was read", file=sys.stderr)
        return EXIT_REFUSED_TIER
    text = _read(Path(args.config))
    if text is None:
        print(f"refused: cannot read the config {args.config}", file=sys.stderr)
        return EXIT_BAD_CONFIG
    try:
        cfg = load_config(text)
    except ConfigError as e:
        print(f"refused: the config {args.config}: {e}", file=sys.stderr)
        return EXIT_BAD_CONFIG
    print(json.dumps(sample(args.tier, cfg), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
