# Tenant cost-of-goods harness

A population generator (`tenant_sim`) plus a sampler (`tenant_cogs.py`) and a
report (`cogs_report.py`). They measure what a 10-human / 20-agent team does
to a Buzz relay so chart `requests`/`limits` and PVC sizes can be set from
numbers instead of guesses.

No CI. Run it by hand against an isolated compose project. Every target is a
literal IP address inside an allow list you give at run time (see "Target
guard"); the default URLs use `127.0.0.1`. k3s runs are disabled for now (see
"Substrate: k3s").

## Pieces

| path | what |
|---|---|
| `crates/buzz-test-client` bin `tenant_sim` | the fake customer (profile-driven) |
| `perf/profiles/1h-5a.toml`, `10h-20a.toml`, `25h-75a.toml` | example profiles: solo, team, heavy (data, not code; rates provisional until calibration) |
| `perf/guard_vectors.json` | target-guard test vectors shared by the Rust and Python tests |
| `perf/build-linux.sh` | static linux/amd64 build of `tenant_sim` and `git-credential-nostr` |
| `perf/tenant_cogs.py` | orchestrator + cgroup/Postgres/MinIO/`/metrics` sampler |
| `perf/cogs_report.py` | bands → proposed Helm values, density, diff, anchor |
| `docker-compose.harness.relay.yml` | overlay that runs the relay as a 2-CPU container on top of `docker-compose.harness.yml` |

## One-time build

```bash
cargo build --release -p buzz-test-client --bin tenant_sim
cargo build --release -p git-credential-nostr
```

`rustup` honours `rust-toolchain.toml`.

### Linux build (for a linux/amd64 load box)

```bash
perf/build-linux.sh
```

Builds both binaries as static musl executables in `rust:1.95.0-alpine`
(pinned by digest), with `--locked`, a fixed source path and a fixed Cargo
home, and prints their sha256. They land in `target/linux-amd64/` and run on
any x86_64 Linux. The Cargo registry and target directory are two named Docker
volumes (`buzz-harness-linux-cargo`, `buzz-harness-linux-target`); remove them
for a clean build. On an arm64 host the build runs emulated. The script takes
the same Docker endpoint rule as the sampler (see "Target guard") and refuses
before any docker command if the endpoint is not a local Unix socket.

Check a profile on Linux without a relay:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/w:ro -w /w ubuntu:24.04 \
  target/linux-amd64/tenant_sim --check --profile perf/profiles/10h-20a.toml
```

## Target guard

`tenant_sim` and `tenant_cogs.py` each refuse any target that is not
provably inside the test range. The rules are the same in both, and
`perf/guard_vectors.json` holds the test vectors both test suites read.

- **Literal IP addresses only, never names.** Nothing is ever resolved. A
  target is `scheme://IPv4[:port][/path]` or `scheme://[IPv6][:port][/path]`.
  Refused: any name (`localhost` too), forms a URL parser would quietly
  rewrite (`127.1`, `0x7f.0.0.1`, `0177.0.0.1`, `2130706433`, a trailing dot,
  `%`-encoding, fullwidth digits), userinfo (`http://10.0.0.1@host`, with `@`
  or `\@`), IPv6 zone ids, queries and fragments. The stdlib/WHATWG parser
  must then read the same address and port. An IPv4-mapped IPv6 address
  (`::ffff:a.b.c.d`) is treated as the IPv4 address it maps to.
- **An allow list and a deny list, both required.** `--allow-cidr` is
  repeatable, has no default, and each entry must be no wider than /8 (IPv4)
  or /32 (IPv6), with no host bits set: `0.0.0.0/0` would switch the wall off.
  `--deny-list <file>` holds one address or block per line, `#` comments
  allowed; the file may be empty but must exist, and a bad line refuses the
  run. The deny list wins over the allow list. No flag or environment variable
  turns the guard off.
- **Checked before anything happens.** `run` and `seed-bench` check the relay,
  HTTP, health and metrics URLs before the lock, `docker`, `openssl` or
  `tenant_sim`; a refusal exits 2 and leaves no output directory. `sample`
  checks its metrics URL. `tenant_sim` gets the same lists and checks its two
  targets again before it creates its output directory or opens a
  connection. `tenant_sim --check` and `--print-owner` make no connection and
  need no guard flags.
- **No redirects, no proxies.** `tenant_sim`'s HTTP client ignores proxy
  variables and system proxy settings, follows no redirect and has a resolver
  that refuses every name. `git` runs with `http.followRedirects=false`,
  `http.proxy=` (empty: no proxy), only the http(s) transports allowed, and
  the proxy variables (`HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, both cases),
  `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` removed from its environment.
  Pushes name the checked URL, not `origin`. The sampler reads HTTP through an
  opener with no proxy handler and a redirect handler that refuses.
- **The Docker endpoint must be a local Unix socket.** `run`, `seed-bench`,
  `sample`, `fingerprint` and `perf/build-linux.sh` first resolve the endpoint
  the Docker CLI would use: `DOCKER_HOST`, else `DOCKER_CONTEXT`, else the
  config's `currentContext`, else `unix:///var/run/docker.sock`. They refuse
  (exit 2, before the lock, an output directory or any docker command) unless
  it is `unix://` plus an absolute path to an existing socket; a symlink to a
  socket is fine, as with `/var/run/docker.sock` on OrbStack or Docker
  Desktop. A `DOCKER_CONTEXT` naming anything else is refused even when
  `DOCKER_HOST` is local. Every docker and compose command, teardown included,
  then names the endpoint with `--host` and runs with `DOCKER_HOST` set to it
  and `DOCKER_CONTEXT` removed; with a host given, the Docker CLI ignores the
  context store. `python3 perf/tenant_cogs.py docker-endpoint` prints the
  endpoint or refuses. A remote endpoint (`ssh://`, `tcp://`, a remote
  context) is never accepted. The check proves the endpoint is a local socket,
  not where that socket leads: whoever owns the machine can still point a
  socket at another daemon.
- **What the guard does not cover.** `sample` and `fingerprint` with
  `--substrate k3s` would reach a host through ssh or kubectl, so they are
  refused.

Every connection and where it is checked:

| Connection | Made by | Guarded by |
|---|---|---|
| Websocket (owner, identities, reconnects, seed) | `tenant_sim` | `World.relay_url: Target`; `connect_identity` and `send_with_retry` take `&Target` |
| Media upload (Blossom PUT) | `tenant_sim` | `media::upload` takes `&Target` and `&HttpClient`; only `guard::http_client` builds an `HttpClient` |
| Git clone and push | `tenant_sim` (`git`, which runs `git-credential-nostr`) | `git::clone_repo` takes `&Target`; `GitRepo.url: Target` |
| Docker and compose (up, exec, inspect, ls, teardown) | `tenant_cogs.py`, `build-linux.sh` | `resolve_docker_endpoint` → `DockerEndpoint`; `run()` refuses a docker command not built by `docker_cmd` with one |
| Relay health (`/_readiness`) | `tenant_cogs.py` | `check_targets` → `CheckedUrl`; `http_get` takes nothing else |
| Relay metrics (`/metrics`) | `tenant_cogs.py` | same |

`git-credential-nostr` makes no network connection: it signs a NIP-98 event
for the URL git hands it and runs `git config` locally.

## Substrate: local compose (relative numbers)

The relay runs from a published image, CPU-pinned to 2, so the sampler reads
the same cgroup files a cluster would.

```bash
export BUZZ_IMAGE=ghcr.io/block/buzz:sha-6e5c462   # pin; change to test a newer tag
export SIM_OWNER_PUBKEY=$(./target/release/tenant_sim --print-owner --profile perf/profiles/10h-20a.toml)
export SIM_RELAY_KEY=$(openssl rand -hex 32)
export SIM_GIT_HMAC=$(openssl rand -hex 32)
printf '192.0.2.0/24\n' > ./runs/deny.txt          # addresses no target may use

python3 perf/tenant_cogs.py run \
  --substrate compose \
  --profile perf/profiles/10h-20a.toml \
  --allow-cidr 127.0.0.0/8 \
  --deny-list ./runs/deny.txt \
  --relay-url ws://127.0.0.1:3030 \
  --http-url http://127.0.0.1:3030 \
  --metrics-url http://127.0.0.1:9202/metrics \
  --out-dir ./runs/local-1 \
  --results ./runs/local-1/results.jsonl \
  --tenant-sim ./target/release/tenant_sim \
  --git-credential-helper ./target/release/git-credential-nostr
```

MinIO and its bucket setup use Block's image, pinned by digest
(`ghcr.io/block/buzz-minio@sha256:b8470bb…`); MinIO's own Docker Hub images
can no longer be pulled. It is linux/amd64 only. On an arm64 workstation both
MinIO services run emulated: the results line records `docker_arch` and
`emulated` in `machine_fingerprint`, adds a note, and the report flags it.
Treat workstation media upload times and MinIO CPU as emulated, not real-speed.

Every `run` and `seed-bench` brings up its own Compose project,
`buzz-harness-<run id>`, and prints the name. The run id ends in six random
hex characters, so two runs started in the same second still differ. Before
anything touches the project, the run takes an exclusive lock on
`<project>.lock` in a per-user directory, `$XDG_CACHE_HOME/buzz-harness/locks`
or `~/.cache/buzz-harness/locks`, and holds it through teardown. Processes
that should exclude each other must agree on `XDG_CACHE_HOME`. A second
process that asks for the same project refuses (exit 2) before it runs any
command. The kernel drops the lock when the process exits, so a crash leaves
no stale lock. The directory is created `0700` and refused unless it is a real
directory (not a symlink), owned by you, with no group or other access. A lock
file must be a regular file you own with one link; a symlinked lock file is
refused. Nothing is ever deleted before `up`: the run checks
that the project has no container, volume or network, and refuses (exit 2,
nothing deleted) if it has. `--compose-project`
overrides the name, but only with one that starts with `buzz-harness-`; any
other name is refused before any command runs. The host ports are fixed, so
one harness stack runs at a time; a second `up` fails on the port and removes
only its own project.

`--keep` leaves the stack up under its printed name. `run --skip-reset
--compose-project buzz-harness-<run>` samples a harness stack that is already
running and never tears it down. `seed-bench` refuses `--skip-reset`: it
always measures a fresh stack.

Pin the image by digest (`ghcr.io/block/buzz@sha256:…`) for a result you
will compare later; a tag can move. The results line records the digest and
the image's source revision either way.

### The band signal

`tenant_sim --band-signal stdin` (the default, as `run` uses it) or `fifo`
(`<out-dir>/band.fifo`) takes one line at a time:

| Line | Means |
|---|---|
| `continue [lease]` | after `setup-done`, with `--pause-after-setup`: connect the population |
| `band <name> [lease]` | move to that band: `warmup`, `floor`, `steady`, `peak`, `cooldown`, or `pause` (connected, nothing sent, not sampled: for a driver's checks at a band boundary). `<name>` alone is the same |
| `ramp <k> <lease>` | switch on the first k identities of a ramp |
| `stop` | end the run |

- **A lease** is whole seconds, 1 to 86400. **When the last lease runs out
  with no newer signal, the run stops on its own**: phase `lease-ran-out`,
  `"ended": "lease"` in the last `live.json`, exit 5. A driver that died
  can't leave the load running.
- **On a fifo, every `band` and `ramp` line needs a lease,** and the fifo is
  opened again after each writer closes it: a driver may send each line
  with its own short-lived writer (bound its open: opening a fifo blocks
  while nobody reads it).
- **On stdin,** its end without a `stop` ends the run (`"ended": "eof"`), as
  before.
- **A line that can't be read** (an unknown band, a bad lease, a band line
  on a fifo without one) is refused with phase `signal-refused`, the line
  and why, and changes nothing.
- **`--continue-within-s`** (default 3600) bounds the wait for `continue`:
  past it, exit 3 with its own line.
- **A stop, or a lease that runs out, ends every wait,** wherever the run
  is: an identity's reconnects, their backoff and the subscribe after them
  (a relay that is gone can't keep a stopped run alive), the storm's
  stagger, an identity's first connect, setup's retry waits (exit 3,
  "the run was stopped during setup"), the seed, the wait for `continue`
  and the wait for the population (exit 0, or 5 for a lease, with
  `ended` in the last `live.json`). Agent reads stop between reads. What
  is left can't block past its own bound: a send's OK (30 s), a media
  upload (30 s a path), a read (30 s), a git command (90 s), a gap
  recheck (8 s a channel).
- **Setup fails** (phase `setup-failed` with why, exit 3, before
  `setup-done`) when the relay refuses, or doesn't take after the
  retries, a channel create, a relay-member event (9030) or a
  channel-member event (9000), or a setup clone fails: a run with fewer
  members, channels or repos than its profile isn't that profile's run.
  A rate limit fails setup only when the retries give up; one waited out
  is how the owner is paced at relay defaults.
- **Phase lines** (`setup-done`, `setup-failed`, `seed-start`, `seed-done`,
  `ready`, `lease-ran-out`, `signal-refused`) go to stdout and to
  `<out-dir>/phases.jsonl`, so a driver can read them where stdout goes to a
  journal.

### Rate limits: raised for setup, relay defaults for every band

The relay limits events per key (for example 60 a minute for a human key).
Setup sends every membership and channel event from one owner key, which
authenticates as a human, so at default limits the owner is throttled for
minutes. On compose, `run` therefore:

1. brings the stack up with `BUZZ_RATE_LIMIT_HUMAN_MESSAGES_PER_MIN`,
   `BUZZ_RATE_LIMIT_HUMAN_WS_EVENTS_PER_SEC` and
   `BUZZ_RATE_LIMIT_AGENT_STANDARD_MESSAGES_PER_MIN` set to
   `--setup-rate-limit` (default 1000000);
2. waits for `tenant_sim`'s `{"phase":"setup-done"}` line (provisioning done,
   no identity connected yet);
3. recreates the relay container alone (`up -d --no-deps --force-recreate
   relay`) with those variables unset, waits for readiness, and checks the
   container's env has no override;
4. sends `continue`; the population connects to a relay at its default
   limits, and warm-up, floor, steady and peak all run there.

The results line records `relay_config.setup_rate_limit`,
`relay_config.band_rate_limits` (`relay-default` once verified) and a
`setup` block (owner events, rate-limit waits, seconds). The restart resets
the relay's cgroup and `/metrics` counters before warm-up; every band figure
is a within-band delta, so nothing measured spans it.

`--setup-rate-limit 0` keeps the relay's defaults throughout. `tenant_sim`
then paces the owner itself: a rate-limit `NOTICE` waits out the window the
relay names and resends the same event, instead of waiting 30 s for an `OK`
that never comes. The same applies with `--skip-reset`, where the harness did
not start the relay and cannot restart it.

### Identities

- The relay owner adds only the humans as relay members (kind 9030). Agents
  are admitted through their owner's NIP-OA attestation, as agents on a
  closed relay are. A key that is a direct member is admitted as itself; the
  relay then never records an owner for it, counts it as a human, and refuses
  agent-only kinds such as the 44200 turn metric. (`nip_oa = false` in the
  profile restores direct membership for agents.)
- Agents carry the same attestation on HTTP: `x-auth-tag` on media uploads,
  `BUZZ_AUTH_TAG` for the git credential helper.
- `tenant_sim` and its git children authenticate only with keys the run
  generates. Every `BUZZ_*` and `NOSTR_*` variable in the caller's
  environment is removed before they start.
- Only a repo's owner can push to it. The profile's `git_push` rate is per
  agent, so the repo-owning agents carry the whole population's pushes and
  total push volume matches the profile.
- Reactions target the newest received channel event, never a DM or turn
  metric from the `#p` stream.

## The ramp

The ramp finds how many people and agents a relay carries before it breaks
the service level. `tenant_sim --ramp-max 660` provisions 660 identities
in setup, at the raised limits: relay membership and every channel join.
Then `ramp <k> <lease>` band signals switch them on, k at a time; nothing is
provisioned while a band is measured.

- **The order is team by team:** a human, then their agents, so each step
  of whole teams keeps the profile's mix, and an agent's owner is on before
  it. `--ramp-max` must be a whole number of teams, at least the profile's
  population. The population is generated once, at its maximum: humans'
  keys come before agents' from one stream, so a smaller population would
  give different agent keys.
- **`--ramp-start`** identities are on before the first `ramp` signal: the
  profile's population unless given. A lower k changes nothing.
- **A step adds load the way growth does:** each new identity connects and
  runs its join backfill, then acts at the band's rates. Its duty cycle
  starts when it joins, so steps are staggered.
- **A step is not a band.** The band's clock (and its duty cycles) runs on;
  at each step every identity rechecks for lost events since the step
  before, which costs nothing when none is missing.
- **A sizing ramp, as planned:** the team profile on a fresh stack
  seeded with the team's 90 days (`--seed-days 90`), from its 30 identities,
  15 more (5 teams) every 300 s, at steady-band rates with no storm, up to
  660. A box's ramp ends at its first broken step, when it reaches 660, at
  the run's time limit, or on a void. The result records the last step that
  held (the ceiling) and the first that broke, with what broke it and when.
- **The world stays the profile's:** its channels and repos, and every
  identity joins every channel. So every message fans out to the whole
  population, and fan-out grows with the square of the population; channel
  member lists are full size from the first step. **The ceiling is
  therefore a lower bound for an organisation whose people don't all share
  every channel.** The report must say so.
- **The generator's own limits:** on Linux, `tenant_sim` refuses a ramp its
  open-file limit can't hold (4 per identity, plus 256), so a joiner never
  fails on the generator's side and looks like the relay refusing it. An
  identity that can't join counts as `join_failed` in the live counters.

`live.json` carries what the ramp needs: `joined` (identities connected so
far), `lost` (events found lost after a recheck), and `ack_ms_le`, the
accepted sends of the sampled bands by ack time, cumulative like a
Prometheus histogram, with 500 ms as one of its bounds (10, 25, 50, 100,
250, 500, 1000, 2500, 5000, 10000 ms and `+Inf`).

## The volume seed in a run

An empty database flatters memory and backfill, so a run can seed history
first. The relay rejects events far from its own clock, so the seed writes
the history's volume now, at current timestamps, from the population's own
keys, before any identity subscribes. It writes channel messages only:
no media in MinIO and no git history.

`run --seed-days 90` (or `tenant_sim --seed-days 90`) writes the profile's
stored events for 90 days. `tenant_sim --profile <p> --check` prints the
count and its formula as `seed_90d`:

- **Hours:** 90 days x 5/7 working days x 8 hours = 514.3 hours. **The 8
  hours a day and 5 days a week are an assumption** (`SEED_HOURS_PER_DAY`,
  `SEED_DAYS_PER_WEEK` in `profile.rs`): agents that work around the clock
  would multiply the count several-fold. Calibration replaces it with real
  stored events a day.
- **Per identity per working hour:** the steady band's rates of every
  stored kind (everything but presence and git pushes; a media upload posts
  one message), times the steady duty cycle. The shipped profiles' rates
  give a human 23.5 x 90/690 = 3.07 and an agent 74.5 x 300/1200 = 18.6.

| Profile | Humans | Agents | 90-day seed |
|---|---|---|---|
| `1h-5a` (solo) | 1 | 5 | 49,469 |
| `10h-20a` (team) | 10 | 20 | 207,335 |
| `25h-75a` (heavy) | 25 | 75 | 757,803 |

The run waits for `seed-start`, `seed-done` and `setup-done`, keeps what the
seed asked for and what the client saw in the results line's `seed`, and
fails acceptance if fewer events were acknowledged than asked for. Seed at
raised limits (the default `--setup-rate-limit` on a run that owns its
stack): the relay is restarted with its default limits before the bands.

## Seed throughput (`seed-bench`)

How fast a fresh relay stores history written through its front door. The
relay rejects events far from its own clock, so a history seed writes its
volume at current timestamps; this measures how long that takes.

```bash
python3 perf/tenant_cogs.py seed-bench --substrate compose --limits raised \
  --profile perf/profiles/10h-20a.toml --seed-events 50000 --seed-max-seconds 300 \
  --out-dir ./runs/seed-raised
python3 perf/tenant_cogs.py seed-bench --substrate compose --limits default \
  --profile perf/profiles/10h-20a.toml --seed-events 50000 --seed-max-seconds 300 \
  --out-dir ./runs/seed-default
```

`tenant_sim --seed-events N --setup-only` provisions, then every identity
writes 200-byte channel messages (one socket, one event in flight each) until
N are acknowledged or `--seed-max-seconds` passes. `seed_bench.json` holds the
client's acknowledged rate and, from the relay side over the same window,
rows stored per second, WAL and database bytes per stored event, and relay
and Postgres CPU in cores. If the relay is well under its CPU pin, the
number is bounded by the client, not the relay. Postgres is not CPU-pinned on
the workstation, so a raised-limit figure is an upper bound for a small box.

## Substrate: k3s (disabled)

`run --substrate k3s` refuses and exits 2 before it runs anything: no
`helm`, no `kubectl`, no `tenant_sim`. A k3s run needs an install and a
teardown bounded to the exact resources that run created, and this tree does
not have that yet. `sample --substrate k3s` and `fingerprint --substrate k3s`
also refuse (exit 2, nothing run): they would reach a host through ssh or
kubectl, which the target guard does not cover yet.

Rolling-update reconnect tracking (`tenant_sim --blink` plus
`python3 perf/tenant_cogs.py blink --substrate k3s ... --rollout '...'`)
is **not implemented** in this tree. `blink` exits 2 and does not run a
rollout. `tenant_sim --blink` only records client-side close timestamps.
Do not treat those paths as a completed two-replica rolling-update result.

## Report

```bash
python3 perf/cogs_report.py validate --results ./runs/local-1/results.jsonl
python3 perf/cogs_report.py report   --results ./runs/local-1/results.jsonl --out ./runs/local-1/report.md
python3 perf/cogs_report.py diff     --results ./runs/all.jsonl --profile 10h-20a
python3 perf/cogs_report.py anchor   --results ./runs/all.jsonl --a <run-a> --b <run-b>
```

### Memory figures

Every memory number in a results line (`rss_bytes`) is the container's
**working set**: cgroup `memory.current` minus `inactive_file` from
`memory.stat`. That is cAdvisor's `container_memory_working_set_bytes`, the
figure `docker stats` and Kubernetes read. Raw `memory.current` also counts
page cache the kernel can drop at any time (git packs, uploaded media, files
the relay has deleted), which moved the relay's number by 30–50 Mi inside a
single band at 10h-20a.

Each band also carries `anon_bytes`: the container's anonymous memory, its
own heap and stacks. It is a floor, not the full need. The report shows it
beside the working set. Each sample keeps the raw inputs as well
(`mem_current`, `mem_file`, `mem_active_file`, `mem_inactive_file`,
`mem_shmem`) so a surprising band can be explained from the run's own data.

The report's "measured from" column names the figure behind each proposed
value. The density and 4-vs-8 GiB lines sum the four containers' working sets
and add a fixed k3s and OS allowance; they are not a whole-box reading.

`diff` compares the two most recent lines of the same `(profile, substrate)`
that have **different** `buzz_commit` values and flags anything that moved
more than 15%. `buzz_commit` is the relay image's source revision (or an
immutable digest prefix). A moving tag such as `:main` is resolved at run
time; it is never recorded as the literal string `main`.

## Profile check (no relay)

```bash
./target/release/tenant_sim --profile perf/profiles/10h-20a.toml --check
./target/release/tenant_sim --profile perf/profiles/10h-20a.toml --print-owner
```

A second population is a new TOML file under `perf/profiles/`, never a code
change. The three example profiles are made up:

| Profile | Humans | Agents | Channels | Repos |
|---|---|---|---|---|
| `1h-5a` (solo) | 1 | 5 | 2 | 1 |
| `10h-20a` (team) | 10 | 20 | 6 | 2 |
| `25h-75a` (heavy) | 25 | 75 | 20 | 8 |

They share the same per-identity rates, the original guesses, which are
provisional until calibrated from real traffic. The world shape scales from
the team profile: one channel per 5 identities and one repo per 10 agents,
rounded up.

## Tests

```bash
python3 -m unittest perf/test_tenant_cogs.py
# from the perf/ directory:
cd perf && python3 -m unittest test_tenant_cogs.py test_box_sampler.py test_remote_sampler.py
```

The profile is parsed as TOML by both `tenant_sim` and `tenant_cogs.py`, so
band lengths in `[bands]` are the lengths the orchestrator runs.

A successful `run` exits 0 only when the floor shows 30 connections and is
idle (the per-kind counts cover every client send, every one is presence or
typing, kinds 20001/20002, and the relay stores nothing), sampled bands have zero unexpected rejects, media uploads succeeded with zero
rejects, git pushed with zero failures, each sampled band (floor, steady,
peak) has at least 3 samples carrying the relay's working set, and
`lost_after_backfill` is 0. Whether the bands are distinct (the relay's
working set rising floor p50 < steady p50 < peak max) is reported as
`band_order` in the final line, never as a failure: a valid run must not
fail because the relay's memory didn't rise band by band. A results line is
still appended for diagnosis; the process exit is the weekly-job gate.

`fanout_recipients_p50` is a true histogram percentile of the observations
that landed in that band (end-minus-start bucket counts), not a lifetime
`sum/count` mean. Ready/summary reads time out against a silent child.

The only delete is the final teardown, and only of a stack this same process
brought up: never with `--keep`, never with `--skip-reset`, never after a
refused start. Teardown is `docker compose down -v --remove-orphans`, then a
check that no container, volume or network with the project's compose label
is left. If either step fails, the run exits nonzero, even after a passing
result. Teardown is safe to repeat.

## Remote sampler (`remote-sample`, `box_sampler.py`)

For a run on rented boxes, the sampler runs on the load generator's box and
reads each relay box from outside, over a restricted SSH key whose forced
command is `box_sampler.py`. It never runs Docker commands of its own on a
relay box: the box's reader does, with fixed arguments.

**`box_sampler.py --tier fast|slow --config <file>`** prints one JSON sample
of the box it runs on. It takes nothing from the client (a deployment
wrapper maps the client's word to `--tier`), refuses any tier but `fast` or
`slow` with exit 64, and writes nothing (`python3 -IB`).
- `fast`, every tick: memory, CPU with steal, load, out-of-memory kills,
  disk I/O, the filesystem, each Compose container's cgroup (found from
  `/proc/<pid>/cgroup`), systemd units' cgroups, and the nftables rule
  set's stateless sha256 and drop counters.
- `slow` adds the disk walks (Postgres data and WAL, MinIO, Redis, git,
  container logs, the journal), image overhead, and the WAL position and
  database size (one fixed `psql` query).
- Steal is reported only when `box_sampler.py --steal-check` (run once per
  box by the deployment) found KVM's steal-time bit set; otherwise it is
  "unknown", never 0.
- Each sample records the reader's own CPU time and peak memory, its
  children's included (`getrusage`), so the per-band results show the
  sampler's share of the box. On a relay box that is the reader and what it
  runs; the SSH server's own cost is not in it.

**`tenant_cogs.py remote-sample`** runs the loop:

```bash
python3 perf/tenant_cogs.py remote-sample \
  --box relay1=10.77.0.3 --ssh-key <key> --known-hosts <file> \
  --allow-cidr 10.77.0.0/24 --deny-list <file> --expected-hashes <json> \
  --self gen --self-config <box_sampler config> \
  --live-file <tenant_sim out-dir>/live.json --band-file <file> --out-dir <dir>
```

- **One generator per relay:** `--live <relay>=<path>` (repeatable) binds
  each `tenant_sim`'s live file to the relay it drives, instead of one
  `--live-file` for every relay. A live file may name a relay with no
  `--box` (on a workstation, with no SSH at all). The loop reads every live
  file each tick, with or without `--self`.

- **Every SSH destination passes the target guard:** a literal IP, inside
  `--allow-cidr`, off `--deny-list`. The argv is fixed: only `--ssh-key`,
  no agent, `-F /dev/null`, a strict `--known-hosts`, `--` before the
  address, then the tier word. `--ssh-key` and `--known-hosts` must be
  regular files, and `--expected-hashes` must name every box: without the
  hashes recorded at the lockdown there is nothing to check a rule set
  against. The existing `--ssh` option and the k3s refusals are unchanged.
- **Every call is bounded:** 20 s, 1 MiB of reply and 64 KiB of error
  output. Past any of them the call is killed and counts as a miss, as
  does a reply that is not a sample of the tier asked for.
- **Cadence:** `fast` every 5 s and `slow` every 60 s; `--soak` makes it 30 s
  and 300 s.
- **Output:** `<out-dir>/samples/<role>/ring-*.jsonl`, at most
  `--ring-files` x `--ring-bytes` (8 x 4 MiB) per box, and a restarted loop
  carries on from the newest file; `bands.jsonl`, one line per band per
  box, and for each live file a `client` line per measured band (below);
  `notes.jsonl`; `breaks.json`. A slow reply that isn't whole is kept in the ring as
  `partial`, beside its `miss` reason. A band line has `ticks` and `missed`
  (fast), `slow_calls` and `slow_missed`, percentiles of memory used, CPU busy and
  each container's working set, steal (or why it is unknown), drops, WAL
  high water and write rate, and `sampler`: its CPU seconds, its share of
  the box, and its peak memory. On the generator's own box the sampler's
  CPU is the loop's, its SSH calls included.
- **A void** writes `samples/void.json` and exits 3:
  - a relay's rule-set hash differs from `--expected-hashes`;
  - before that box's relay breaks, a relay box misses 3 ticks in a row
    ("box unreachable"), or over 1% of its ticks once it has 100. After
    the break each is a note with its time instead: a relay box that is
    swapping or crashing can stop answering, and that is the relay
    breaking. Each run of misses reaching 3 is noted once, and the share
    once;
  - before that box's relay breaks, a relay box's slow calls fail 3 in a
    row, or over 1% of them once there are 100, counted apart from its
    ticks. After the break each is a note with its time instead, noted
    the same way: a crash-looping Postgres is the relay breaking. A slow
    call fails when the
    reply is not a whole slow sample: an error from `docker system df` or
    `psql`, or a figure missing (the filesystem's used and free; on a box
    with Docker, Postgres data, WAL, MinIO, Redis, git, container logs,
    image overhead and the WAL position). A missing volume is a gap even
    though the walk logs no error. The fast tier's errors (a container
    with no cgroup, a unit, nft) don't count here: a restarting relay
    shows one, and that is the relay breaking. The journal is not
    required, so a box without one doesn't void every run;
  - before the relay breaks, the generator's CPU averages over 70% on two
    60 s windows in a row, its MemAvailable stays under 10% of MemTotal for
    3 ticks, its box has an out-of-memory kill, or its own errors rise in
    `tenant_sim`'s live counters: its client errors, a media upload that
    failed before it went out (`media_client_failed`), a git add, commit
    or branch that failed (`git_local_failed`), or an agent's read that
    failed before it went out (`read_client_failed`). A missing or unreadable
    `--live-file` is a void too, never "no errors", and so is a file
    without `rejected`, `rate_limited`, `media_client_failed`, `media_refused`,
    `media_unanswered`, `git_local_failed`, `git_push_failed`,
    `read_client_failed`, `read_refused`, `read_unanswered` or
    `read_rate_limited`: a total missing is never read as 0.
  - `tenant_sim`'s live counters stop being live: `t_unix` missing or not
    a whole number of seconds, more than 10 s old or 10 s ahead of the
    clock when the loop reads it, or lower than the last one read; or its
    last write says the run lost its driver (`"ended": "lease"` or
    `"eof"`). A last write that ended on a stop is final: it is never
    stale. The writer and the loop share the generator box's clock.
  - **"The relay broke" has one definition, here, per relay:** the first
    of these, and a band driver reads it (`breaks.json`) rather than
    computing its own. It is the service level (95% of events acknowledged
    within 500 ms, at least 10% of memory free, nothing lost or rejected,
    rate limits apart), and the signals the loop already had:
    - **acks:** under 95% of a measured band's or ramp step's acks within
      500 ms, judged at its end on at least 20 acks, from `live.json`'s
      histogram;
    - **memory:** the relay box's MemAvailable under 10% of MemTotal, on
      any fast sample;
    - **lost or rejected:** events found lost after a recheck (`lost`);
      relay rejects (not rate limits); media uploads, git pushes or agent
      reads the relay refused or didn't answer (`media_refused`,
      `media_unanswered`, `git_push_failed`, `read_refused`,
      `read_unanswered`; a timeout included);
    - **connections:** dropped connections, or identities that couldn't
      join (`join_failed`);
    - **the relay itself:** an OOM kill, or no relay container in a
      `docker ps` that worked (a failed listing is not a break).

    At its limit a relay usually fails by timing out, so a timeout is the
    relay's; a stalled generator still shows in its CPU, its memory and a
    stale live file. Rate limits are counted apart: never a break. A
    generator event after the break is a note, not a void, written once.
  - **Whose break.** A relay's break is its box's own signals, those in the
    live file bound to it, or those in a live file bound to no relay
    (`--live-file`), whichever came first; another relay's doesn't count
    for it. A relay box's missed calls, and a generator's own errors in a
    relay's live file, wait on that relay's break. The generator box's own
    limits (CPU, memory, an OOM kill) wait on every relay's: an
    overloaded load source spoils every relay that hasn't broken yet.
    Each source's first break is a note, naming its relay.
  - **Measured bands** are `floor`, `steady`, `peak` and ramp steps
    (`ramp-<n>`) in the band file. A band's window, per live file, runs
    from its first read in the band to the last before the band changed;
    **a ramp step's starts 60 s in,** once its joiners have connected and
    run their backfill. Each window's client line in `bands.jsonl` holds
    its sends, accepts, rejects, rate limits, lost events, reads, acks
    and the share within 500 ms, and `joined`, the population so far.
  - **`breaks.json`** holds each relay that broke and when, and the first
    break, rewritten whole as soon as a break comes.
  - **The same tick.** Every limit a tick crosses is decided at the tick's
    end, once all of that tick's break signals are in. A limit and a break
    on the same tick count as after the break: one tick can't order them,
    and the loop reads the relay boxes before the live counters.
  - A changed rule set, a missing hash, and live counters that are
    missing or no longer live void at any time, before or after a break.
- **INT and TERM** write the band summaries, then exit 130 and 143. A
  second signal while the summaries or `void.json` are written is ignored.

`tenant_sim` rewrites `<out-dir>/live.json` every 2 s for this: totals of
sent, accepted, rejected, rate-limited and received, its own errors by kind
(`send_failed`, `recv_error`, `reconnect_failed`, `backfill_failed`,
`connection_dropped`), and media and git failures by where they failed,
stamped `t_unix`. If a rewrite fails, `tenant_sim` logs it and carries on;
the file then goes stale and the loop voids 10 s later.

**The last write says why the run ended:** `"ended": "stop"` (a `stop`
signal), `"lease"` (its band lease ran out) or `"eof"` (stdin ended without
a `stop`). A file that ended on a stop is final: it ages, and the loop
never calls it stale, so the loop may outlive `tenant_sim`. One that ended
on a lease or an eof lost its driver, and the loop voids on it. A crash
writes neither, goes stale, and voids as before.

| Failure | live.json total | Counts as |
|---|---|---|
| Media: encoding the image or signing the auth, before the request goes out | `media_client_failed` | the generator's error |
| Media: an answer that isn't 2xx | `media_refused` | a relay break |
| Media: a transport error or a timeout, no answer | `media_unanswered` | a relay break |
| Git: writing the blob, `add`, `commit` or `branch` | `git_local_failed` | the generator's error |
| Git: the push, refused, failed or past the 90 s timeout | `git_push_failed` | a relay break |
| Agent read: building or signing the request, before it goes out | `read_client_failed` | the generator's error |
| Agent read: an answer that isn't 2xx, or isn't JSON | `read_refused` | a relay break |
| Agent read: a transport error or a timeout, no answer | `read_unanswered` | a relay break |
| Agent read: a 429 from the relay's per-key rate limit | `read_rate_limited` | apart: neither |

## Agent per-turn reads

Reads are the database's main cost, so agents read as well as write. On
each agent turn (each `turn_metric` it sends: 20 an hour in steady, 4x at
peak) `tenant_sim` makes the reads an agent harness makes, one after
another, over the relay's HTTP bridge with NIP-98, as Buzz's own harness
does (`buzz-acp`: every read is `POST /query` with NIP-98, and a NIP-OA
agent sends its credential in `x-auth-tag`). The NIP-98 event carries the
`u`, `method`, `payload` and a fresh `nonce` tag, and the request goes to
the checked `--http-url` through the guarded client: no proxy, no redirect.

**The mix is a default until calibration replaces it.** Five reads a turn,
a sixth on one turn in four:

| # | Read | Filter |
|---|---|---|
| 1 | The thread's context, in one query | the root (an event the agent saw in the channel) by id; its replies, kinds 9 and 40002 with `#e` root and `#h` channel, limit 51; the agent's own last reply, limit 1 |
| 2 | Profiles | kind 0 for up to 5 authors seen |
| 3 | Memory | kind 30174, `authors` the agent, its `#d`, `#p` its owner, limit 16 |
| 4 | Channel history (the agent's own tool use) | kind 9 `#h` channel, limit 50 |
| 5 | Canvas | kind 40100 `#h` channel, limit 1 |
| 6 | On one turn in four: a count | `POST /count` of the thread's replies |

Every filter names its kinds, and none is a p-gated kind. Each read's time
counts in its band (`reads`, `read_ms`), and the run's totals in
`summary.json`'s `reads`. Where a read fails is in the table below.

**Per-key rate limits are counted apart.** relay-v0.2.1 answers an
over-quota event with a `NOTICE` ("rate-limited: ...") and no `OK`. In a
band, `tenant_sim` reads that notice as the send's answer, counts it as
`rate_limited` (in `live.json` and in each band of `summary.json`), and
doesn't resend. It is neither a reject, nor a break, nor the generator's
own error, so the loop never voids on it and acceptance never fails on
it: the service level counts rate limits apart. Messages that arrive
while a send waits for its answer are handled, never dropped.

Each blob is a new file, so `commit` always has a change in a healthy run.
`summary.json` keeps its meaning: its media `rejected` and git `failed`
count every failure, wherever it failed, not only the relay's refusals.

`tenant_sim` runs git (the setup clones and every push) on tokio's
blocking pool, never on a runtime worker: each git command can take up to
90 s, and the generator box's 2 vCPUs give the runtime 2 workers. Two slow
pushes on them would stall every task, the live counters' writer
included, and the loop would void the run as stale at the relay's limit.

## What is not in this tree

Run outputs, identities, kubeconfigs, and `.env` files. `runs/` and
`identities.json` are gitignored. Do not commit them.

k3s bring-up, chart/server fingerprint, replica config, Postgres secret
handling, box cost, and the rolling-update blink test are out of scope
here. Those live in the private wrapper, which is not part of this PR.
