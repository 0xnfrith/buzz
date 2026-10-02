"""Every child the harness starts gets exactly its fixed environment.

Planted-variable rows: the parent's environment is patched to a fixed fake
set (PATH with a stub folder first, a temporary HOME) plus G613_PLANTED, the
caller's own credentials, a hostile DOCKER_HOST and DOCKER_CONTEXT, and the
three rate-limit variables, each a dummy made at run time. The real code
path runs to a perl stub that records the names of the variables it was
started with, one line per call, and never a value. The names must equal the
child's set exactly. Where a name is both planted and in a set (DOCKER_HOST,
the raised limits), the stub records whether the value is the right one
(`match`) or not (`other`). Perl adds no variable of its own; these rows fail,
never skip, without /usr/bin/perl.

The tests' own children get a fixed environment too (planted_env.test_env):
a planted-variable row for the helper, and a syntax-tree row that holds every
subprocess call in perf/test_*.py to it.
"""

from __future__ import annotations

import ast
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

PERF = Path(__file__).resolve().parent
sys.path.insert(0, str(PERF))

import clock_proof  # noqa: E402
import clock_proof_hook as hook  # noqa: E402
import tenant_cogs  # noqa: E402
import planted_env  # noqa: E402
from planted_env import PLANTED, parent_env, write_stub  # noqa: E402

LIMITS = tenant_cogs.RATE_LIMIT_VARS
CHECKED = "unix:///checked/docker.sock"

TENANT_SIM = {"HOME", "LC_ALL", "PATH"}
COMMAND = {"HOME", "LC_ALL", "PATH"}
PYTHON = {"HOME", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE"}
DOCKER = {"DOCKER_HOST=match", "HOME", "PATH"}


class Planted(unittest.TestCase):
    """A temporary folder with a stub folder, a home and the names file, and
    os.environ patched to the planted parent for the whole test."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="child-env-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin, self.home, self.out = self.dir / "bin", self.dir / "home", self.dir / "names"
        self.bin.mkdir()
        self.home.mkdir()
        self.planted = {k: secrets.token_hex(16) for k in
                        (PLANTED, "BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG", "NOSTR_PRIVATE_KEY",
                         "DOCKER_HOST", "DOCKER_CONTEXT", *LIMITS)}
        parent = {"PATH": f"{self.bin}:{os.environ.get('PATH', '')}", "HOME": str(self.home), **self.planted}
        patch = mock.patch.dict(os.environ, parent, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def stub(self, name: str, checks: dict[str, str] | None = None, **kw) -> Path:
        return write_stub(self.bin / name, self.out, checks, **kw)

    def lines(self) -> list[set[str]]:
        if not self.out.exists():
            return []
        return [set(line.split()) for line in self.out.read_text().splitlines()]

    def wait_lines(self, n: int, timeout_s: float = 10.0) -> list[set[str]]:
        end = time.time() + timeout_s
        while len(self.lines()) < n and time.time() < end:
            time.sleep(0.05)
        return self.lines()


class TenantCogsRows(Planted):
    def test_sim_env_print_owner_and_openssl(self) -> None:
        """`sim_env`: tenant_sim --print-owner gets tenant_sim's set, each
        `openssl rand` the set of run()'s other commands; the relay's values
        hold nothing of the parent's."""
        sim = self.stub("tenant_sim")
        self.stub("openssl")
        args = mock.Mock(tenant_sim=str(sim), buzz_image="img")
        env, image = tenant_cogs.sim_env(args, self.dir / "p.toml")
        self.assertEqual(self.lines(), [TENANT_SIM, COMMAND, COMMAND])
        self.assertEqual(sorted(env), ["BUZZ_IMAGE", "SIM_GIT_HMAC", "SIM_OWNER_PUBKEY", "SIM_RELAY_KEY"])
        self.assertEqual(image, "img")

    def test_compose_adapter(self) -> None:
        """Compose through the adapter: PATH, HOME, the checked endpoint and
        the stack's named values; the limits only in `up` for setup, at the
        raised value, never the parent's."""
        self.stub("docker", {"DOCKER_HOST": CHECKED, **{k: "1000" for k in LIMITS}})
        lock = tenant_cogs.ProjectLock("buzz-harness-childenv")
        self.addCleanup(lock.release)
        ad = tenant_cogs.ComposeAdapter("buzz-harness-childenv", ("a.yml",), env={"SIM_RELAY_KEY": "k"},
                                        lock=lock, endpoint=tenant_cogs.DockerEndpoint(CHECKED))
        ad.up(tenant_cogs.raised_limit_env(1000))
        ad.recreate_relay()
        named = DOCKER | {"SIM_RELAY_KEY"}
        raised = named | {f"{k}=match" for k in LIMITS}
        # The empty check's three reads, `up` raised, then the recreate.
        self.assertEqual(self.lines(), [named, named, named, raised, named])

    def test_run_other_commands(self) -> None:
        """run()'s commands other than docker: PATH, HOME, LC_ALL=C and the
        command's own named values."""
        self.stub("sysctl")
        tenant_cogs.run(["sysctl", "-n", "hw.ncpu"])
        tenant_cogs.run(["sysctl", "-n", "hw.ncpu"], env={"ONE_NAMED": "v"})
        self.assertEqual(self.lines(), [COMMAND, COMMAND | {"ONE_NAMED"}])


class HookRows(Planted):
    def cfg(self) -> dict:
        root = self.dir / "root"
        (root / "state").mkdir(parents=True)
        (root / "state" / "keys-solo.json").write_text(json.dumps(
            {"SIM_OWNER_PUBKEY": "o", "SIM_RELAY_KEY": "r", "SIM_GIT_HMAC": "h"}))
        return {"root": str(root), "prefix": "child-env", "compose": "c.yml", "python": sys.executable,
                "docker": str(self.bin / "docker"), "docker_host": CHECKED,
                "gens": {"a": {"port": 1, "health_port": 2}}, "profiles": {"solo": "p.toml"},
                "tenant_sim": str(self.bin / "tenant_sim")}

    def test_supervisor_and_tenant_sim(self) -> None:
        """The supervisor a Python child's set; tenant_sim under it its own."""
        cfg = self.cfg()
        cfg["python"] = str(self.stub("python", exec_=sys.executable))
        self.stub("tenant_sim")
        out = self.dir / "gen"
        hook.spawn(cfg, out, "tenant_sim", [cfg["tenant_sim"]])
        self.assertEqual(self.wait_lines(2), [PYTHON, TENANT_SIM])

    def test_supervisor_and_sampler(self) -> None:
        """The sampler loop under the supervisor: a Python child's set."""
        cfg = self.cfg()
        sampler = self.stub("sampler")
        hook.spawn(cfg, self.dir / "sampler", "python", [str(sampler)])
        self.assertEqual(self.wait_lines(1), [PYTHON])

    def test_compose(self) -> None:
        """The hook's compose: PATH, HOME, the proof's checked socket and the
        stack's values; the limits only raised, at the raised value."""
        cfg = self.cfg()
        self.stub("docker", {"DOCKER_HOST": CHECKED, **{k: hook.SETUP_RATE_LIMIT for k in LIMITS}})
        hook.compose(cfg, "a", "up", env=hook.stack_env(cfg, "a", "solo", True))
        hook.compose(cfg, "a", "down", env=hook.stack_env(cfg, "a", "solo", False))
        stack = DOCKER | {"PROOF_PORT", "PROOF_HEALTH_PORT", "SIM_OWNER_PUBKEY", "SIM_RELAY_KEY", "SIM_GIT_HMAC"}
        self.assertEqual(self.lines(), [stack | {f"{k}=match" for k in LIMITS}, stack])

    def test_print_owner(self) -> None:
        """`setup`'s tenant_sim --print-owner: tenant_sim's set. The stub
        fails it, so setup stops there."""
        cfg = self.cfg()
        self.stub("tenant_sim", code=1)
        with self.assertRaises(subprocess.CalledProcessError):
            hook.ev_setup(cfg, "solo")
        self.assertEqual(self.lines(), [TENANT_SIM])


class ProofRows(Planted):
    def proof(self) -> clock_proof.Proof:
        return clock_proof.Proof(self.dir / "out", "child-env", sys.executable, str(self.bin / "docker"),
                                 str(self.bin / "tenant_sim"), CHECKED)

    def test_docker(self) -> None:
        """The proof's own docker calls: docker's set, the checked socket."""
        self.stub("docker", {"DOCKER_HOST": CHECKED})
        self.proof().leftovers()
        self.assertEqual(self.lines(), [DOCKER] * 6)

    def test_hook_end(self) -> None:
        """The hook's `end`, from the proof: a Python child's set."""
        proof = self.proof()
        proof.python = str(self.stub("python"))
        proof.run(*proof.hook(self.dir / "config.json"), "end")
        self.assertEqual(self.lines(), [PYTHON])

    def test_clock(self) -> None:
        """The clock the proof starts: a Python child's set."""
        root = self.dir / "row"
        root.mkdir()
        p = self.proof().start_clock(root, [str(self.stub("clock"))])
        self.assertEqual(p.wait(timeout=30), 0)
        self.assertEqual(self.lines(), [PYTHON])

    def test_the_clock_hands_its_set_to_the_hook(self) -> None:
        """The chain: the real start_clock runs the real `tenant_cogs.py
        clock`, whose hook is the stub. The hook gets the clock's set, through
        band_clock.py, which is unchanged. The stub fails the first event, so
        the clock stops with exit 4 (a hook failed). macOS's Python adds
        __CF_USER_TEXT_ENCODING (CoreFoundation's text encoding, never a
        credential) to its own environment, so on Darwin that one name comes
        through too."""
        root = self.dir / "row"
        root.mkdir()
        proof = self.proof()
        argv = proof.clock_argv(root, self.dir / "config.json", ["a"],
                                ["--profile", str(clock_proof.PROOF / "profiles/proof-solo.toml")])
        argv = [*argv[:argv.index("--") + 1], str(self.stub("hook", code=1))]
        p = proof.start_clock(root, argv)
        self.assertEqual(p.wait(timeout=60), clock_proof_exit_hook(), (root / "clock.out").read_text()[-400:])
        want = PYTHON | ({"__CF_USER_TEXT_ENCODING"} if platform.system() == "Darwin" else set())
        self.assertEqual(self.lines()[0], want)

    def test_refuses_a_remote_docker(self) -> None:
        """The proof refuses any Docker endpoint but a local socket, before
        anything runs: exit 2 on its own line."""
        self.stub("docker")
        os.environ["DOCKER_HOST"] = "tcp://203.0.113.9:2375"
        del os.environ["DOCKER_CONTEXT"]
        err = self.dir / "err"
        with open(err, "w") as fh, mock.patch.object(sys, "stderr", fh):
            code = clock_proof.main(["--out", str(self.dir / "out"), "--rows", "reads"])
        self.assertEqual(code, 2)
        self.assertEqual(err.read_text(),
                         "refused: docker endpoint refused: DOCKER_HOST selects 'tcp://203.0.113.9:2375'; "
                         "only a local Unix socket is allowed. Nothing was changed.\n")
        self.assertEqual(self.lines(), [])


def clock_proof_exit_hook() -> int:
    import band_clock
    return band_clock.EXIT_HOOK


class TestEnvRows(Planted):
    def test_test_env_is_exactly_its_set(self) -> None:
        """`test_env`: PATH, HOME and TMPDIR from the parent (each only when
        set), LC_ALL=C and the named values, whatever else the parent holds.
        Each value is the right one (`match`), never printed."""
        tmp = str(self.dir / "tmp")
        for unset in ((), ("TMPDIR",), ("HOME", "TMPDIR"), ("PATH", "HOME", "TMPDIR")):
            with self.subTest(unset=unset):
                self.out.unlink(missing_ok=True)
                parent = parent_env(TMPDIR=tmp)
                with mock.patch.dict(os.environ, parent, clear=True):
                    for name in unset:
                        del os.environ[name]
                    env = planted_env.test_env(ONE_NAMED="v")
                want = {k: v for k, v in parent.items() if k in ("PATH", "HOME", "TMPDIR") and k not in unset}
                want.update({"LC_ALL": "C", "ONE_NAMED": "v"})
                stub = self.stub("probe", want)
                subprocess.run([str(stub)], env=env, check=True)
                self.assertEqual(self.lines(), [{f"{k}=match" for k in want}])


class EverySpawnHasAFixedEnv(unittest.TestCase):
    """No drift: every subprocess call in the harness files passes `env=`
    built by one of tenant_cogs's fixed-set functions (or, inside run(), the
    `env` it built from them). A call that inherits would fail this row."""

    BUILDERS = {"child_env", "command_env", "python_env", "docker_env", "fixed_env"}

    def built(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name in self.BUILDERS:
                return True
            # CHILD_ENVS[kind](): a table of the builders.
            if isinstance(f, ast.Subscript) and getattr(f.value, "id", None) == "CHILD_ENVS":
                return True
        if isinstance(node, ast.IfExp):
            return self.built(node.body) and self.built(node.orelse)
        return False

    def test_every_spawn(self) -> None:
        seen = 0
        for name in ("tenant_cogs.py", "clock_proof.py", "clock_proof_hook.py"):
            tree = ast.parse((PERF / name).read_text())
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(fn):
                    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr in ("run", "Popen", "call", "check_call", "check_output")
                            and getattr(node.func.value, "id", None) == "subprocess"):
                        continue
                    seen += 1
                    env = next((k.value for k in node.keywords if k.arg == "env"), None)
                    where = f"{name}:{node.lineno}"
                    self.assertIsNotNone(env, f"{where} passes no env")
                    ok = self.built(env) or (
                        name == "tenant_cogs.py" and fn.name == "run" and isinstance(env, ast.Name)
                        and env.id == "env")
                    self.assertTrue(ok, f"{where} passes an env no fixed-set function built")
                    if isinstance(env, ast.Name):
                        # run()'s own `env`: every path to the call sets it
                        # from docker_env or command_env.
                        src = ast.get_source_segment((PERF / name).read_text(), fn) or ""
                        self.assertIn("env = docker_env(", src, where)
                        self.assertIn("env = command_env(", src, where)
        # 3 in tenant_cogs.py, 3 in clock_proof.py, 4 in the hook.
        self.assertGreaterEqual(seen, 10, "the walk found too few calls to mean anything")


SPAWNS = ("run", "Popen", "call", "check_call", "check_output")


def environ_mentions(node: ast.AST) -> bool:
    """`node` reads the parent's environment: os.environ, os.environb, getenv."""
    return any(
        (isinstance(n, ast.Attribute) and n.attr in ("environ", "environb", "getenv"))
        or (isinstance(n, ast.Name) and n.id in ("environ", "environb", "getenv"))
        for n in ast.walk(node))


def is_test_env_call(node: ast.AST | None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    return (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)) == "test_env"


def spawn_problems(name: str, source: str) -> tuple[int, list[str]]:
    """(spawn calls in `source`, one 'name:line: call reason' per call that
    could hand its child the parent's environment). A spawn is a call of
    subprocess.run/Popen/call/check_call/check_output, through the module, an
    alias of it (`import subprocess as sp`), a `.subprocess` attribute, or a
    name imported from it. Its `env=` must be a test_env call, or a name every
    assignment to which, in the same function, is one; nothing that writes to
    that name may read os.environ. Names only: no value is ever printed."""
    tree = ast.parse(source)
    parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    modules, funcs = {"subprocess"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.asname for a in node.names if a.name == "subprocess" and a.asname}
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            funcs |= {a.asname or a.name for a in node.names if a.name in SPAWNS}
    found, bad = 0, []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr in SPAWNS and (
                (isinstance(f.value, ast.Name) and f.value.id in modules)
                or (isinstance(f.value, ast.Attribute) and f.value.attr == "subprocess")):
            what = f"subprocess.{f.attr}"
        elif isinstance(f, ast.Name) and f.id in funcs:
            what = f.id
        else:
            continue
        found += 1
        where = f"{name}:{call.lineno}: {what}"
        env = next((k.value for k in call.keywords if k.arg == "env"), None)
        if env is None:
            bad.append(f"{where} passes no env")
        elif environ_mentions(env):
            bad.append(f"{where} builds its env from the parent's")
        elif is_test_env_call(env):
            continue
        elif not isinstance(env, ast.Name):
            bad.append(f"{where} passes an env test_env did not build")
        else:
            scope = call
            while scope in parent and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = parent[scope]
            assigns = [n for n in ast.walk(scope) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == env.id for t in n.targets)]
            writes = [n for n in ast.walk(scope) if environ_mentions(n) and (
                (isinstance(n, (ast.Assign, ast.AugAssign)) and any(
                    env.id in {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
                or (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == env.id))]
            if not assigns or not all(is_test_env_call(a.value) for a in assigns):
                bad.append(f"{where} passes an env test_env did not build")
            elif writes:
                bad.append(f"{where} builds its env from the parent's")
    return found, bad


class EveryTestSpawnHasAFixedEnv(unittest.TestCase):
    """No drift, for the tests' own children: every subprocess call in
    perf/test_*.py passes `env=` built by planted_env.test_env, and nothing
    reads os.environ into it. A heuristic over the syntax tree, not a proof:
    it does not see os.system, os.popen, os.spawn*, asyncio's
    create_subprocess_*, multiprocessing, a call through a name it can't
    follow (a function that returns subprocess.run, a getattr), or a spawn
    in a file that is not perf/test_*.py (the harness's own spawns are held by
    EverySpawnHasAFixedEnv above). `**kwargs` that may carry `env` count as no
    env, so they fail."""

    def test_every_spawn(self) -> None:
        seen, bad = 0, []
        for path in sorted(PERF.glob("test_*.py")):
            n, problems = spawn_problems(path.name, path.read_text())
            seen += n
            bad += problems
        self.assertEqual(bad, [])
        # 4 in test_band_clock.py, 2 in test_remote_sampler.py, 7 in test_tenant_cogs.py.
        self.assertGreaterEqual(seen, 13, "the walk found too few calls to mean anything")

    def test_the_row_can_fail(self) -> None:
        """The scan, on snippets: the right spawns pass, each way of
        inheriting is named."""
        head = "import os, subprocess\nfrom planted_env import test_env\n"
        good = [
            "subprocess.run(['x'], env=test_env())",
            "subprocess.Popen(['x'], env=test_env(A='1'))",
            "def f():\n    env = test_env(A='1')\n    env['PATH'] = 'p'\n    subprocess.run(['x'], env=env)",
            "def f():\n    env = planted_env.test_env()\n    subprocess.check_output(['x'], env=env)",
            "with mock.patch.dict(os.environ, {'A': '1'}):\n    pass",
            "raise subprocess.CalledProcessError(1, 'x')",
            "docker.run(['x'])",
        ]
        for code in good:
            with self.subTest(code=code):
                self.assertEqual(spawn_problems("s.py", head + code)[1], [], code)
        bad = {
            "subprocess.run(['x'])": "passes no env",
            "subprocess.run(['x'], env=None)": "passes an env test_env did not build",
            "subprocess.call(['x'], env={'A': '1'})": "passes an env test_env did not build",
            "subprocess.run(['x'], env=dict(os.environ))": "builds its env from the parent's",
            "subprocess.run(['x'], env={**os.environ, 'A': '1'})": "builds its env from the parent's",
            "subprocess.run(['x'], env=test_env(**os.environ))": "builds its env from the parent's",
            "subprocess.run(['x'], env=test_env(A=os.getenv('A')))": "builds its env from the parent's",
            "def f():\n    env = dict(os.environ)\n    subprocess.run(['x'], env=env)": "passes an env test_env did not build",
            "def f():\n    env = test_env()\n    env = {}\n    subprocess.run(['x'], env=env)": "passes an env test_env did not build",
            "def f():\n    env = test_env()\n    env.update(os.environ)\n    subprocess.run(['x'], env=env)": "builds its env from the parent's",
            "def f():\n    env = test_env()\n    env['A'] = os.environ['A']\n    subprocess.run(['x'], env=env)": "builds its env from the parent's",
            "def f(env):\n    subprocess.run(['x'], env=env)": "passes an env test_env did not build",
            "subprocess.run(['x'], **{'env': test_env()})": "passes no env",
            "import subprocess as sp\nsp.Popen(['x'])": "passes no env",
            "from subprocess import run\nrun(['x'])": "passes no env",
            "from subprocess import check_output as co\nco(['x'])": "passes no env",
            "tenant_cogs.subprocess.run(['x'])": "passes no env",
        }
        for code, why in bad.items():
            with self.subTest(code=code):
                found, problems = spawn_problems("s.py", head + code)
                self.assertEqual(found, 1, code)
                self.assertEqual(len(problems), 1, code)
                self.assertTrue(problems[0].startswith("s.py:") and problems[0].endswith(why), problems)


if __name__ == "__main__":
    unittest.main()
