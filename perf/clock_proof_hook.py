#!/usr/bin/env python3
"""The band clock's hook for its local proof (clock_proof.py): each
generator drives its own relay stack on this machine, a Compose project
named `<prefix>-<gen>`.

    clock_proof_hook.py --config CONFIG.json EVENT [ARGS...]

The events are the clock's (band_clock.py). This hook:

- `setup <item>`: removes the item before's stack (`down -v`, that project
  only), checks the project is empty, and starts a fresh one with the three
  per-key limits raised for setup;
- `gen-start <gen> <item>`: starts `tenant_sim` under a supervisor that
  records its pid and exit, its band signal on `<out>/band.fifo`;
- `fleet`: recreates each relay without the raised limits, and reads back
  that none of the three is set;
- `send <gen> <line>`: writes the line to the fifo, retrying for 5 s;
- `sampler start|stop`: the sampler loop, one `--live` per relay;
- `status`: the sampler's `void.json` and `breaks.json`, and whether each
  process still runs;
- `end`: stops every process, removes each project (`down -v`, that project
  only) and checks by label that nothing is left.

What the proof forces comes from the config's `inject`: a boundary that
fails, a generator stopped (SIGSTOP) or killed at a band, and a relay frozen
(`docker pause`) at a band; and from `fleet_cpus`, a relay's CPU cap from
`fleet` on, for the whole run. Every image is used as it is on the machine: Compose runs
with `--pull never`. Every call appends a line to `<root>/hook.log`.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

RATE_LIMIT_VARS = (
    "BUZZ_RATE_LIMIT_HUMAN_MESSAGES_PER_MIN",
    "BUZZ_RATE_LIMIT_HUMAN_WS_EVENTS_PER_SEC",
    "BUZZ_RATE_LIMIT_AGENT_STANDARD_MESSAGES_PER_MIN",
)
SETUP_RATE_LIMIT = "1000000"
FIFO_WAIT_S = 5.0
READY_TIMEOUT_S = 300.0


class Fail(Exception):
    """The event failed: exit 1 with this line."""


# ---- config and state ----


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def root(cfg: dict[str, Any]) -> Path:
    return Path(cfg["root"])


def project(cfg: dict[str, Any], gen: str) -> str:
    return f"{cfg['prefix']}-{gen}"


def item_now(cfg: dict[str, Any]) -> str | None:
    p = root(cfg) / "state" / "item"
    return p.read_text().strip() if p.exists() else None


def item_dir(cfg: dict[str, Any], item: str) -> Path:
    return root(cfg) / "items" / item


def gen_dir(cfg: dict[str, Any], item: str, gen: str) -> Path:
    return item_dir(cfg, item) / gen


def log(cfg: dict[str, Any], rec: dict[str, Any]) -> None:
    with (root(cfg) / "hook.log").open("a") as fh:
        fh.write(json.dumps({"t_unix": round(time.time(), 3), **rec}) + "\n")


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


# ---- processes ----


def supervise(out: Path, argv: list[str]) -> int:
    """Runs argv, its pid in <out>/pid, its exit in <out>/exit (a signal as
    its negative number). Started detached by `spawn`."""
    with (out / "stdout.log").open("ab") as so, (out / "stderr.log").open("ab") as se:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=so, stderr=se, env=child_env())
        (out / "pid").write_text(f"{p.pid}\n")
        code = p.wait()
    tmp = out / "exit.tmp"
    tmp.write_text(f"{code}\n")
    tmp.replace(out / "exit")
    return 0


def spawn(cfg: dict[str, Any], out: Path, argv: list[str]) -> None:
    """Starts argv under a supervisor that outlives this hook (and the
    clock, if the clock dies: the proof kills the clock's pid alone). Not in
    a session of its own: some sandboxes reap a Python session leader."""
    out.mkdir(parents=True, exist_ok=True)
    for f in ("pid", "exit"):
        (out / f).unlink(missing_ok=True)
    with open(os.devnull, "rb") as null_in, (out / "supervisor.log").open("ab") as so:
        subprocess.Popen([cfg["python"], str(Path(__file__).resolve()), "_supervise", str(out), "--", *argv],
                         stdin=null_in, stdout=so, stderr=so, close_fds=True)
    end = time.time() + 10
    while not (out / "pid").exists():
        if (out / "exit").exists() or time.time() > end:
            raise Fail(f"{argv[0]} did not start: {(out / 'stderr.log').read_text()[-400:] if (out / 'stderr.log').exists() else ''}")
        time.sleep(0.05)


def state(out: Path) -> str:
    """'active', 'exited <code>', or 'not started'."""
    if (out / "exit").exists():
        return f"exited {(out / 'exit').read_text().strip()}"
    if not (out / "pid").exists():
        return "not started"
    try:
        os.kill(int((out / "pid").read_text()), 0)
    except ProcessLookupError:
        # Gone without an exit written: its supervisor was killed too.
        return "exited unknown"
    return "active"


def pid_of(out: Path) -> int | None:
    try:
        return int((out / "pid").read_text())
    except (OSError, ValueError):
        return None


def stop(out: Path, sig: int = signal.SIGTERM, wait_s: float = 30.0) -> str:
    """Stops a process if it runs, SIGKILL after wait_s; returns its state."""
    pid = pid_of(out)
    if pid is None or state(out) != "active":
        return state(out)
    try:
        os.kill(pid, signal.SIGCONT)  # a stopped process can't act on TERM
        os.kill(pid, sig)
    except ProcessLookupError:
        pass
    end = time.time() + wait_s
    while state(out) == "active" and time.time() < end:
        time.sleep(0.2)
    if state(out) == "active":
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        end = time.time() + 10
        while state(out) == "active" and time.time() < end:
            time.sleep(0.2)
    return state(out)


def child_env() -> dict[str, str]:
    """This environment without Buzz or Nostr credentials and without the
    rate-limit variables."""
    return {k: v for k, v in os.environ.items()
            if not (k.startswith("BUZZ_") or k.startswith("NOSTR_")) and k not in RATE_LIMIT_VARS}


# ---- docker ----


def docker(cfg: dict[str, Any], *args: str, env: dict[str, str] | None = None, check: bool = True,
           timeout: float = 600) -> subprocess.CompletedProcess[str]:
    p = subprocess.run([cfg["docker"], *args], capture_output=True, text=True, timeout=timeout,
                       env={**child_env(), **(env or {})})
    if check and p.returncode != 0:
        raise Fail(f"docker {' '.join(args[:4])}: exit {p.returncode}: {(p.stderr or p.stdout).strip()[-400:]}")
    return p


def compose(cfg: dict[str, Any], gen: str, *args: str, env: dict[str, str] | None = None,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    return docker(cfg, "compose", "-p", project(cfg, gen), "-f", cfg["compose"], *args, env=env, check=check)


def stack_env(cfg: dict[str, Any], gen: str, item: str, raised: bool) -> dict[str, str]:
    keys = json.loads((root(cfg) / "state" / f"keys-{item}.json").read_text())
    g = cfg["gens"][gen]
    env = {"PROOF_PORT": str(g["port"]), "PROOF_HEALTH_PORT": str(g["health_port"]), **keys}
    if raised:
        env.update({k: SETUP_RATE_LIMIT for k in RATE_LIMIT_VARS})
    return env


def leftovers(cfg: dict[str, Any], gen: str) -> dict[str, list[str]]:
    label = f"label=com.docker.compose.project={project(cfg, gen)}"
    out = {}
    for kind, args in (("containers", ("ps", "-a", "-q", "--filter", label)),
                       ("volumes", ("volume", "ls", "-q", "--filter", label)),
                       ("networks", ("network", "ls", "-q", "--filter", label))):
        out[kind] = docker(cfg, *args).stdout.split()
    return {k: v for k, v in out.items() if v}


def wait_ready(cfg: dict[str, Any], gen: str) -> None:
    url = f"http://127.0.0.1:{cfg['gens'][gen]['health_port']}/_readiness"
    opener = urllib.request.OpenerDirector()
    for h in (urllib.request.HTTPHandler(), urllib.request.HTTPDefaultErrorHandler(),
              urllib.request.HTTPErrorProcessor()):
        opener.add_handler(h)
    end, last = time.time() + READY_TIMEOUT_S, ""
    while time.time() < end:
        try:
            with opener.open(url, timeout=2) as r:
                if r.status == 200:
                    return
                last = f"status {r.status}"
        except Exception as e:  # noqa: BLE001: a readiness probe
            last = str(e)
        time.sleep(1)
    # Keep what the relay said, for whoever reads the failure.
    name = f"{project(cfg, gen)}-relay-1"
    st = docker(cfg, "inspect", "--format", "{{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}}",
                name, check=False).stdout.strip()
    logs = docker(cfg, "logs", "--tail", "200", name, check=False)
    (root(cfg) / f"relay-{gen}-not-ready.log").write_text(f"{st}\n{logs.stdout}{logs.stderr}")
    raise Fail(f"the relay for {gen} was not ready at {url}: {last} ({st})")


def relay_overrides(cfg: dict[str, Any], gen: str) -> list[str]:
    """The limit variables set on the relay: in its container's config, and
    in its running process. Compose passes an unset pass-through key as a
    bare name with no `=`, which Docker leaves out of the process: unset."""
    name = f"{project(cfg, gen)}-relay-1"
    raw = docker(cfg, "inspect", "--format", "{{json .Config.Env}}", name).stdout
    config = {e.partition("=")[0] for e in (json.loads(raw) or []) if "=" in e}
    proc = docker(cfg, "exec", name, "cat", "/proc/1/environ").stdout
    running = {e.partition("=")[0] for e in proc.split("\0") if "=" in e}
    return sorted((config | running) & set(RATE_LIMIT_VARS))


# ---- events ----


def ev_setup(cfg: dict[str, Any], item: str) -> None:
    (root(cfg) / "state").mkdir(parents=True, exist_ok=True)
    (root(cfg) / "state" / "item").write_text(item + "\n")
    owner = subprocess.run([cfg["tenant_sim"], "--print-owner", "--profile", cfg["profiles"][item]],
                           capture_output=True, text=True, env=child_env(), check=True).stdout.strip()
    write_private(root(cfg) / "state" / f"keys-{item}.json", json.dumps({
        "SIM_OWNER_PUBKEY": owner, "SIM_RELAY_KEY": secrets.token_hex(32), "SIM_GIT_HMAC": secrets.token_hex(32)}))
    for gen in cfg["gens"]:
        compose(cfg, gen, "down", "-v", "--remove-orphans", env=stack_env(cfg, gen, item, False))
        left = leftovers(cfg, gen)
        if left:
            raise Fail(f"{project(cfg, gen)} is not empty after down: {left}")
    for gen in cfg["gens"]:
        compose(cfg, gen, "up", "-d", "--pull", "never", env=stack_env(cfg, gen, item, True))
    for gen in cfg["gens"]:
        wait_ready(cfg, gen)


def ev_gen_start(cfg: dict[str, Any], gen: str, item: str) -> None:
    out = gen_dir(cfg, item, gen)
    port = cfg["gens"][gen]["port"]
    argv = [cfg["tenant_sim"], "--profile", cfg["profiles"][item],
            "--relay-url", f"ws://127.0.0.1:{port}", "--http-url", f"http://127.0.0.1:{port}",
            "--allow-cidr", "127.0.0.0/8", "--deny-list", cfg["deny_list"], "--out-dir", str(out),
            "--git-credential-helper", cfg["helper"], "--band-signal", "fifo", "--pause-after-setup",
            "--log-level", "info"]
    if item == "ramp":
        argv += ["--ramp-max", str(cfg["ramp"]["max"]), "--ramp-start", str(cfg["ramp"]["start"])]
    if cfg.get("seed_days"):
        argv += ["--seed-days", str(cfg["seed_days"]), "--seed-max-seconds", str(cfg.get("seed_max_seconds", 1800))]
    spawn(cfg, out, argv)


def ev_phases(cfg: dict[str, Any], gen: str) -> None:
    item = item_now(cfg)
    p = gen_dir(cfg, item, gen) / "phases.jsonl" if item else None
    if p and p.exists():
        sys.stdout.write(p.read_text())


def ev_fleet(cfg: dict[str, Any]) -> None:
    item = item_now(cfg) or ""
    for gen in cfg["gens"]:
        env = stack_env(cfg, gen, item, False)
        cpus = (cfg.get("fleet_cpus") or {}).get(gen)
        if cpus:
            env["PROOF_RELAY_CPUS"] = str(cpus)
        compose(cfg, gen, "up", "-d", "--no-deps", "--force-recreate", "--pull", "never", "relay", env=env)
    for gen in cfg["gens"]:
        wait_ready(cfg, gen)
        left = relay_overrides(cfg, gen)
        if left:
            raise Fail(f"the relay for {gen} still has rate-limit overrides: {left}")


def ev_send(cfg: dict[str, Any], gen: str, line: str) -> None:
    fifo = gen_dir(cfg, item_now(cfg) or "", gen) / "band.fifo"
    end = time.time() + FIFO_WAIT_S
    while True:
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError as e:
            if e.errno not in (errno.ENXIO, errno.ENOENT) or time.time() >= end:
                raise Fail(f"no reader on {fifo} within {FIFO_WAIT_S:g} s: {e.strerror}") from e
            time.sleep(0.1)
    try:
        os.write(fd, (line + "\n").encode())
    finally:
        os.close(fd)


def ev_sampler(cfg: dict[str, Any], what: str) -> None:
    item = item_now(cfg) or ""
    out = item_dir(cfg, item) / "sampler"
    if what == "start":
        s = cfg["sampler"]
        argv = [cfg["python"], cfg["tenant_cogs"], "remote-sample", "--out-dir", str(out),
                "--allow-cidr", "127.0.0.0/8", "--deny-list", cfg["deny_list"],
                "--band-file", str(root(cfg) / "band"), "--step-settle", str(s["step_settle"]),
                "--fast-every", str(s["fast_every"])]
        for gen in cfg["gens"]:
            argv += ["--live", f"{gen}={gen_dir(cfg, item, gen) / 'live.json'}"]
        spawn(cfg, out, argv)
    elif what == "stop":
        st = stop(out)
        if st not in ("exited 143", "exited 0"):
            raise Fail(f"the sampler ended {st}")
    else:
        raise Fail(f"sampler {what}: not start or stop")


def ev_band(cfg: dict[str, Any], name: str) -> None:
    tmp = root(cfg) / "band.tmp"
    tmp.write_text(name + "\n")
    tmp.replace(root(cfg) / "band")
    inj = cfg.get("inject") or {}
    item = item_now(cfg) or ""
    for act in inj.get("at_band", []):
        if act["band"] != name:
            continue
        if act["do"] == "pause":
            # The relay frozen: every send it was written goes unanswered.
            docker(cfg, "pause", f"{project(cfg, act['gen'])}-relay-1")
        elif act["do"] in ("sigstop", "sigkill"):
            pid = pid_of(gen_dir(cfg, item, act["gen"]))
            if pid is None:
                raise Fail(f"no pid for {act['gen']}")
            os.kill(pid, signal.SIGSTOP if act["do"] == "sigstop" else signal.SIGKILL)
        log(cfg, {"inject": act})


def ev_boundary(cfg: dict[str, Any], band: str) -> None:
    if (cfg.get("inject") or {}).get("boundary_fails") == band:
        raise Fail(f"the boundary check failed at {band}: forced by the proof")
    for gen in cfg["gens"]:
        running = docker(cfg, "inspect", "--format", "{{.State.Running}}", f"{project(cfg, gen)}-relay-1").stdout.strip()
        if running != "true":
            raise Fail(f"the relay for {gen} is not running at the {band} boundary")


def ev_rules(cfg: dict[str, Any]) -> None:
    # The local stacks have no firewall to check: the proof records when the
    # clock asked, and that each stack is still there.
    for gen in cfg["gens"]:
        if not docker(cfg, "ps", "-q", "--filter", f"label=com.docker.compose.project={project(cfg, gen)}").stdout.split():
            raise Fail(f"{project(cfg, gen)} has no running container")


def ev_status(cfg: dict[str, Any]) -> None:
    item = item_now(cfg) or ""
    samples = item_dir(cfg, item) / "sampler" / "samples"

    def read(p: Path) -> Any:
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return None
    print(json.dumps({
        "void": read(samples / "void.json"),
        "breaks": read(samples / "breaks.json") or {},
        "sampler": state(item_dir(cfg, item) / "sampler"),
        "gens": {g: state(gen_dir(cfg, item, g)) for g in cfg["gens"]},
    }))


def ev_end(cfg: dict[str, Any]) -> None:
    item = item_now(cfg)
    ended = {}
    if item:
        for gen in cfg["gens"]:
            ended[gen] = stop(gen_dir(cfg, item, gen))
        ended["sampler"] = stop(item_dir(cfg, item) / "sampler")
    left = {}
    for gen in cfg["gens"]:
        name = f"{project(cfg, gen)}-relay-1"
        if docker(cfg, "inspect", "--format", "{{.State.Paused}}", name, check=False).stdout.strip() == "true":
            docker(cfg, "unpause", name)
        compose(cfg, gen, "down", "-v", "--remove-orphans", env=stack_env(cfg, gen, item, False) if item else
                {"PROOF_PORT": "1", "PROOF_HEALTH_PORT": "1", "SIM_OWNER_PUBKEY": "x", "SIM_RELAY_KEY": "x", "SIM_GIT_HMAC": "x"})
        lo = leftovers(cfg, gen)
        if lo:
            left[project(cfg, gen)] = lo
    print(json.dumps({"ended": ended, "left": left}))
    if left:
        raise Fail(f"left after down: {left}")


EVENTS = {
    "setup": (ev_setup, 1), "gen-start": (ev_gen_start, 2), "phases": (ev_phases, 1), "fleet": (ev_fleet, 0),
    "send": (ev_send, 2), "sampler": (ev_sampler, 1), "band": (ev_band, 1), "boundary": (ev_boundary, 1),
    "rules": (ev_rules, 0), "status": (ev_status, 0), "end": (ev_end, 0),
}


def main(argv: list[str]) -> int:
    if argv[:1] == ["_supervise"]:
        return supervise(Path(argv[1]), argv[argv.index("--") + 1:])
    if len(argv) < 3 or argv[0] != "--config":
        print("usage: clock_proof_hook.py --config CONFIG.json EVENT [ARGS...]", file=sys.stderr)
        return 2
    cfg = load(argv[1])
    event, args = argv[2], argv[3:]
    fn, n = EVENTS.get(event, (None, -1))
    if fn is None or len(args) != n:
        print(f"unknown event or wrong arguments: {[event, *args]}", file=sys.stderr)
        return 2
    t0 = time.time()
    code = 0
    try:
        fn(cfg, *args)
    except (Fail, subprocess.SubprocessError, OSError) as e:
        print(str(e), file=sys.stderr)
        code = 1
    if event != "status":
        log(cfg, {"event": [event, *args], "exit": code, "s": round(time.time() - t0, 3)})
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
