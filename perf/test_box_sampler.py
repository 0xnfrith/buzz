#!/usr/bin/env python3
"""Unit tests for box_sampler (stdlib unittest). Fixtures: testdata/remote_sampler,
each pinned in its SHA256SUMS; PROVENANCE.md says where each came from."""

from __future__ import annotations

import builtins
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import box_sampler as bs

FIX = Path(__file__).resolve().parent / "testdata" / "remote_sampler"
CID_A = "f07c458cbd62027411da7ea41675a8928002f51771533b0f8d45e9fa867d67d0"
CID_B = "0d3a081d0c531a9c9d8a8b06ebb99e7ca4c895ed1342babb1f27b8b9887c2f6d"
CGROUP = "/system.slice/docker-" + "a" * 64 + ".scope"


def fixture(rel: str) -> str:
    """A fixture's text, refused unless its sha256 matches SHA256SUMS."""
    data = (FIX / rel).read_bytes()
    pins = dict(
        (line.split()[1], line.split()[0])
        for line in (FIX / "SHA256SUMS").read_text().splitlines()
        if line.strip()
    )
    if rel not in pins:
        raise AssertionError(f"fixture {rel} is not pinned in SHA256SUMS")
    if hashlib.sha256(data).hexdigest() != pins[rel]:
        raise AssertionError(f"fixture {rel} does not match its SHA256SUMS pin")
    return data.decode()


def config(**over: object) -> dict:
    c = {
        "compose_project": "g613-capture",
        "nft_table": "inet capture_egress",
        "docker": "/usr/bin/docker",
        "nft": "/usr/sbin/nft",
        "docker_root": "/var/lib/docker",
        "volumes": {"postgres": "p_pg", "minio": "p_minio", "redis": "p_redis", "git": "p_git"},
        "postgres": {"service": "svc-a", "user": "buzz", "db": "buzz"},
        "journal": "/var/log/journal",
        "steal": {"reported": False, "why": "KVM_FEATURE_STEAL_TIME is clear: steal is not accounted"},
    }
    c.update(over)
    return c


class FakeDocker:
    """Answers the reader's commands from the captured fixtures, and records
    every argv it was given."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.calls.append(argv)
        if argv[:2] == ["/usr/bin/docker", "ps"]:
            return 0, fixture("docker/ps.txt"), ""
        if argv[:2] == ["/usr/bin/docker", "inspect"]:
            return 0, fixture("docker/inspect.txt"), ""
        if argv[:3] == ["/usr/bin/docker", "system", "df"]:
            return 0, fixture("docker/system_df.txt"), ""
        if argv[:2] == ["/usr/bin/docker", "exec"]:
            return 0, fixture("psql/wal.txt"), ""
        if argv[:2] == ["/usr/sbin/nft", "-s"]:
            return 0, fixture("nft/stateless.txt"), ""
        if argv[:2] == ["/usr/sbin/nft", "list"]:
            return 0, fixture("nft/counters.txt"), ""
        return 127, "", f"unexpected command {argv}"


def fixture_root(tmp: Path) -> Path:
    """The captured /proc and cgroup tree, plus a small synthetic Docker data
    folder for the slow tier's walks."""
    for rel in [p for p in (FIX / "root").rglob("*") if p.is_file()]:
        fixture(str(rel.relative_to(FIX)))  # each copied file is pinned
    shutil.copytree(FIX / "root", tmp / "root")
    root = tmp / "root"
    vols = root / "var/lib/docker/volumes"
    for name, files in {"p_pg": {"base/1/1": 1000, "pg_wal/000000010000000000000001": 16000}, "p_minio": {"a": 7},
                        "p_redis": {"dump.rdb": 11}, "p_git": {"r.git/HEAD": 23}}.items():
        for rel, size in files.items():
            f = vols / name / "_data" / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b"x" * size)
    logs = root / "var/lib/docker/containers" / CID_A
    logs.mkdir(parents=True)
    (logs / f"{CID_A}-json.log").write_bytes(b"y" * 300)
    (logs / f"{CID_A}-json.log.1").write_bytes(b"y" * 200)
    (logs / "config.v2.json").write_bytes(b"not counted")
    (root / "var/log/journal/m").mkdir(parents=True)
    (root / "var/log/journal/m/system.journal").write_bytes(b"j" * 4096)
    return root


class Refusals(unittest.TestCase):
    """The forced command takes nothing from the client: any tier but fast
    or slow exits 64 with one exact line, having read nothing."""

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(bs, "_read", side_effect=AssertionError("read after a refusal")):
            code = bs.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_hostile_tiers(self) -> None:
        for tier in ["/etc/shadow", "select 1; drop table events", "fast; rm -rf /", "fast\nslow", "", "FAST", "slow "]:
            with self.subTest(tier=tier):
                code, out, err = self.run_main(["--tier", tier, "--config", "/etc/loadtest/sampler.conf"])
                self.assertEqual(code, 64)
                self.assertEqual(out, "")
                self.assertEqual(err, f"refused: tier {tier!r} is not fast or slow; nothing was read\n")

    def test_extra_or_missing_arguments(self) -> None:
        code, out, err = self.run_main(["--tier", "fast", "--config", "/c", "--root", "/tmp"])
        self.assertEqual((code, out), (64, ""))
        self.assertEqual(err, "refused: tier 'fast' is not fast or slow; nothing was read\n")
        code, out, err = self.run_main(["--tier", "fast"])
        self.assertEqual((code, out), (64, ""))
        self.assertEqual(err, "refused: usage: box_sampler.py --tier fast|slow --config <file>; nothing was read\n")

    def test_bad_configs(self) -> None:
        rows = {
            "not json": "refused: the config {p}: not JSON: Expecting value: line 1 column 1 (char 0)\n",
            json.dumps({**config(), "extra": 1}): "refused: the config {p}: unknown keys ['extra']\n",
            json.dumps(config(compose_project="Bad Name")): "refused: the config {p}: compose_project 'Bad Name' is not a Compose project name\n",
            json.dumps(config(nft_table="loadtest_egress")): "refused: the config {p}: nft_table 'loadtest_egress' is not '<family> <name>'\n",
            json.dumps(config(docker="docker")): "refused: the config {p}: docker 'docker' is not an absolute path\n",
            json.dumps(config(docker_root="/var/../etc")): "refused: the config {p}: docker_root '/var/../etc' is not an absolute path\n",
            json.dumps(config(volumes={"etc": "x"})): "refused: the config {p}: volumes holds keys other than postgres, minio, redis and git\n",
            json.dumps(config(volumes={"postgres": "../x"})): "refused: the config {p}: volume postgres '../x' is not a volume name\n",
            json.dumps(config(postgres={"service": "pg", "user": "buzz; drop", "db": "buzz"})): "refused: the config {p}: postgres user 'buzz; drop' is not a plain name\n",
            json.dumps(config(docker=None)): "refused: the config {p}: docker and compose_project are set together, or neither\n",
            json.dumps(config(steal={"reported": 0, "why": "x"})): 'refused: the config {p}: steal must be {"reported": true|false|null, "why": "..."}\n',
            json.dumps(config(units=["x; rm"])): "refused: the config {p}: units ['x; rm'] is not a list of systemd service names\n",
        }
        for text, want in rows.items():
            with self.subTest(config=text[:40]), tempfile.TemporaryDirectory() as d:
                p = Path(d) / "c.json"
                p.write_text(text)
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = bs.main(["--tier", "fast", "--config", str(p)])
                self.assertEqual((code, out.getvalue()), (2, ""))
                self.assertEqual(err.getvalue(), want.replace("{p}", str(p)))

    def test_a_missing_config(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bs.main(["--tier", "slow", "--config", "/nonexistent/sampler.conf"])
        self.assertEqual((code, out.getvalue(), err.getvalue()), (2, "", "refused: cannot read the config /nonexistent/sampler.conf\n"))


class Parsers(unittest.TestCase):
    def test_proc(self) -> None:
        mem = bs.parse_meminfo(fixture("root/proc/meminfo"))
        self.assertGreater(mem["MemTotal"], mem["MemAvailable"])
        self.assertEqual(mem["MemTotal"] % 1024, 0, "kB lines are turned into bytes")
        stat = bs.parse_stat(fixture("root/proc/stat"))
        self.assertEqual(list(stat["ticks"]), list(bs.CPU_FIELDS))
        self.assertGreater(stat["ncpu"], 0)
        self.assertEqual(len(bs.parse_loadavg(fixture("root/proc/loadavg"))), 3)
        self.assertIsInstance(bs.parse_vmstat_oom(fixture("root/proc/vmstat")), int)
        disks = bs.parse_diskstats(fixture("root/proc/diskstats"))
        self.assertTrue(disks)
        for name in disks:
            self.assertNotRegex(name, r"^(loop|ram|dm-|sr|zram)")
            self.assertNotRegex(name, r"^(sd|vd|xvd)[a-z]+\d+$")

    def test_cgroup(self) -> None:
        self.assertEqual(bs.cgroup_path(fixture("root/proc/2322844/cgroup")), CGROUP)
        with tempfile.TemporaryDirectory() as d:
            root = fixture_root(Path(d))
            cg = bs.read_cgroup(root, CGROUP)
        self.assertIsNotNone(cg["usage_usec"])
        self.assertIsNotNone(cg["mem_current"])
        self.assertEqual(cg["working_set"], max(cg["mem_current"] - cg["inactive_file"], 0))
        self.assertIsInstance(cg["oom_kill"], int)

    def test_docker_and_psql(self) -> None:
        self.assertEqual(bs.parse_docker_ps(fixture("docker/ps.txt")), {"svc-a": CID_A, "svc-b": CID_B})
        self.assertEqual(bs.parse_docker_inspect(fixture("docker/inspect.txt")), {CID_A: 2322844, CID_B: 2322882})
        self.assertEqual(bs.parse_system_df(fixture("docker/system_df.txt"))["Images"], 1234000000)
        self.assertEqual(bs.parse_wal(fixture("psql/wal.txt")), {"wal_lsn_bytes": 0x14ED2F0, "db_size_bytes": 7689907})
        self.assertEqual(bs.parse_wal("garbage"), {"wal_lsn_bytes": None, "db_size_bytes": None})

    def test_nft(self) -> None:
        self.assertEqual(bs.drop_counters(fixture("nft/counters.txt")), {"output": {"packets": 4, "bytes": 143}, "forward": {"packets": 0, "bytes": 0}})
        self.assertEqual(bs.drop_counters(fixture("nft/stateless.txt")), {"output": {"packets": 0, "bytes": 0}, "forward": {"packets": 0, "bytes": 0}})


class Steal(unittest.TestCase):
    """Steal is reported only when a KVM guest's CPUID sets the steal-time
    bit; otherwise it is unknown, never 0."""

    KVM = (0x40000001, int.from_bytes(b"KVMK", "little"), int.from_bytes(b"VMKV", "little"), int.from_bytes(b"M\x00\x00\x00", "little"))

    def test_rows(self) -> None:
        rows = [
            ("arm64", None, None, "", {"reported": None, "why": "unknown: not x86 (arm64)"}),
            ("x86_64", None, None, "mmap: denied", {"reported": None, "why": "unknown: CPUID could not be read (mmap: denied)"}),
            ("x86_64", (7, 0x340, 0x340, 0), (0, 0, 0, 0), "", {"reported": None, "why": "unknown: the hypervisor is not KVM (b'@\\x03\\x00\\x00@\\x03\\x00\\x00\\x00\\x00\\x00\\x00')"}),
            ("x86_64", (0x40000000,) + self.KVM[1:], (1 << 5, 0, 0, 0), "", {"reported": None, "why": "unknown: KVM's highest leaf is 0x40000000"}),
            ("x86_64", self.KVM, (1 << 5, 0, 0, 0), "", {"reported": True, "why": "KVM_FEATURE_STEAL_TIME is set"}),
            # The Hetzner CCX13 value: bit 5 clear.
            ("x86_64", self.KVM, (0x0100005B & ~(1 << 5), 0, 0, 0), "", {"reported": False, "why": "KVM_FEATURE_STEAL_TIME is clear: steal is not accounted"}),
        ]
        for machine, l0, l1, why, want in rows:
            with self.subTest(machine=machine, l1=l1):
                self.assertEqual(bs.steal_decision(machine, l0, l1, why), want)

    def test_the_hetzner_value_reads_clear(self) -> None:
        self.assertEqual(0x0100005B >> 5 & 1, 0)

    def test_a_sample_reports_steal_from_the_config_only(self) -> None:
        with tempfile.TemporaryDirectory() as d, mock.patch.object(bs, "read_cpuid", side_effect=AssertionError("CPUID in a sample")):
            root = fixture_root(Path(d))
            row = bs.sample("fast", config(), root=root, runner=FakeDocker())
            self.assertEqual(row["steal"], config()["steal"])
            row = bs.sample("fast", {k: v for k, v in config().items() if k != "steal"}, root=root, runner=FakeDocker())
            self.assertEqual(row["steal"], {"reported": None, "why": "unknown: not checked (no steal in the config)"})


class NoWrites:
    """Fails the test on any attempt to write, create, rename or remove."""

    def __enter__(self) -> "NoWrites":
        real_open, real_os_open = builtins.open, os.open

        def guarded_open(file, mode="r", *a, **k):  # type: ignore[no-untyped-def]
            if any(c in mode for c in "wax+"):
                raise AssertionError(f"the reader opened {file} for writing ({mode})")
            return real_open(file, mode, *a, **k)

        def guarded_os_open(path, flags, *a, **k):  # type: ignore[no-untyped-def]
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
                raise AssertionError(f"the reader opened {path} for writing")
            return real_os_open(path, flags, *a, **k)

        def refuse(name: str):  # type: ignore[no-untyped-def]
            def f(*a, **k):  # type: ignore[no-untyped-def]
                raise AssertionError(f"the reader called os.{name}{a}")
            return f

        self.patches = [mock.patch.object(builtins, "open", guarded_open), mock.patch.object(os, "open", guarded_os_open)]
        self.patches += [mock.patch.object(os, n, refuse(n)) for n in ("mkdir", "makedirs", "rename", "replace", "remove", "unlink", "rmdir", "chmod", "symlink", "link")]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self.patches):
            p.stop()


class TheGuardItself(unittest.TestCase):
    def test_the_no_write_guard_catches_each_kind_of_write(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "x")
            for name, act in {
                "open w": lambda: open(target, "w"),
                "open a": lambda: open(target, "a"),
                "os.open O_CREAT": lambda: os.open(target, os.O_CREAT | os.O_WRONLY),
                "mkdir": lambda: os.mkdir(target),
                "rename": lambda: os.rename(d, d + "y"),
                "remove": lambda: os.remove(target),
            }.items():
                with self.subTest(name), NoWrites(), self.assertRaises(AssertionError):
                    act()
            self.assertEqual(os.listdir(d), [])


class Sample(unittest.TestCase):
    """Both tiers end to end, on the captured /proc, cgroup and command
    output, writing nothing and running only the fixed commands."""

    def test_fast(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root, docker = fixture_root(Path(d)), FakeDocker()
            with NoWrites():
                row = bs.sample("fast", config(), root=root, runner=docker, clock=lambda: 1000.5)
        self.assertEqual((row["v"], row["tier"], row["t_unix"]), (1, "fast", 1000.5))
        self.assertGreater(row["box"]["mem"]["MemTotal"], 0)
        self.assertIn("fs", row["box"])
        a, b = row["containers"]["svc-a"], row["containers"]["svc-b"]
        self.assertEqual((a["id"], a["pid"], a["cgroup"]), (CID_A, 2322844, CGROUP))
        self.assertIsNotNone(a["working_set"])
        self.assertEqual((b["id"], b["pid"]), (CID_B, 2322882))
        self.assertEqual(row["errors"], ["container svc-b: no cgroup (pid 2322882)"])
        self.assertEqual(row["nft"]["hash"], hashlib.sha256(fixture("nft/stateless.txt").encode()).hexdigest())
        self.assertEqual(row["nft"]["drops"]["output"], {"packets": 4, "bytes": 143})
        self.assertNotIn("disk", row)
        self.assertIn("cpu_s", row["reader"])
        self.assertEqual(docker.calls, [
            ["/usr/bin/docker", "ps", "--no-trunc", "--filter", "label=com.docker.compose.project=g613-capture", "--format", '{{.ID}}\t{{.Label "com.docker.compose.service"}}'],
            ["/usr/bin/docker", "inspect", "-f", "{{.Id}}\t{{.State.Pid}}", CID_B, CID_A],
            ["/usr/sbin/nft", "-s", "list", "table", "inet", "capture_egress"],
            ["/usr/sbin/nft", "list", "table", "inet", "capture_egress"],
        ])

    def test_slow(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root, docker = fixture_root(Path(d)), FakeDocker()
            with NoWrites():
                row = bs.sample("slow", config(), root=root, runner=docker)
        disk = row["disk"]
        self.assertEqual(disk["postgres_volume"], {"bytes": 17000, "files": 2})
        self.assertEqual(disk["wal"], {"bytes": 16000, "files": 1})
        self.assertEqual(disk["postgres_data"], {"bytes": 1000, "files": 1})
        self.assertEqual((disk["minio"], disk["redis"], disk["git"]), ({"bytes": 7, "files": 1}, {"bytes": 11, "files": 1}, {"bytes": 23, "files": 1}))
        self.assertEqual(disk["container_logs_bytes"], 500)
        self.assertEqual(disk["journal"], {"bytes": 4096, "files": 1})
        self.assertEqual(disk["images_bytes"], 1234000000)
        self.assertEqual(row["wal"], {"wal_lsn_bytes": 0x14ED2F0, "db_size_bytes": 7689907})
        self.assertEqual(docker.calls[-2:], [
            ["/usr/bin/docker", "system", "df", "--format", "{{.Type}}\t{{.Size}}"],
            ["/usr/bin/docker", "exec", CID_A, "psql", "-U", "buzz", "-d", "buzz", "-tAc", bs.WAL_SQL],
        ])

    def test_a_box_with_no_docker_and_no_nft(self) -> None:
        cfg = {"steal": {"reported": None, "why": "unknown: not x86 (arm64)"}, "units": ["loadtest-gen.service"]}
        with tempfile.TemporaryDirectory() as d:
            root, docker = fixture_root(Path(d)), FakeDocker()
            with NoWrites():
                row = bs.sample("slow", bs.load_config(json.dumps(cfg)), root=root, runner=docker)
        self.assertEqual(docker.calls, [])
        self.assertEqual((row["containers"], row["nft"]), ({}, None))
        self.assertEqual(row["containers_absent"], "no docker on this box (config)")
        self.assertEqual(row["nft_absent"], "no nft table in the config")
        self.assertIn("unit loadtest-gen.service: no cgroup (not running?)", row["errors"])
        self.assertIsNone(row["disk"]["container_logs_bytes"])

    def test_a_failing_command_is_an_error_not_an_empty_reading(self) -> None:
        def broken(argv: list[str]) -> tuple[int, str, str]:
            return 1, "", "Cannot connect to the Docker daemon"
        with tempfile.TemporaryDirectory() as d:
            row = bs.sample("slow", config(), root=fixture_root(Path(d)), runner=broken)
        self.assertIn("docker ps: exit 1: Cannot connect to the Docker daemon", row["errors"])
        self.assertIn("nft: exit 1/1: Cannot connect to the Docker daemon", row["errors"])
        self.assertIsNone(row["nft"])
        self.assertIsNone(row["disk"]["images_bytes"])


if __name__ == "__main__":
    unittest.main()
