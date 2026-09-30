# Tenant cost-of-goods harness

A population generator (`tenant_sim`) plus a sampler (`tenant_cogs.py`) and a
report (`cogs_report.py`). They measure what a 10-human / 20-agent team does
to a Buzz relay so chart `requests`/`limits` and PVC sizes can be set from
numbers instead of guesses.

No CI. Run it by hand against an isolated compose project or a dedicated k3s
namespace. Default hosts are `localhost`; default namespace is `buzz-loadtest`.

## Pieces

| path | what |
|---|---|
| `crates/buzz-test-client` bin `tenant_sim` | the fake customer (profile-driven) |
| `perf/profiles/10h-20a.toml` | the sizing profile (data, not code) |
| `perf/tenant_cogs.py` | orchestrator + cgroup/Postgres/MinIO/`/metrics` sampler |
| `perf/cogs_report.py` | bands → proposed Helm values, density, diff, anchor |
| `docker-compose.harness.relay.yml` | overlay that runs the relay as a 2-CPU container on top of `docker-compose.harness.yml` |

## One-time build

```bash
cargo build --release -p buzz-test-client --bin tenant_sim
cargo build --release -p git-credential-nostr
```

`rustup` honours `rust-toolchain.toml`.

## Substrate: local compose (relative numbers)

The relay runs from a published image, CPU-pinned to 2, so the sampler reads
the same cgroup files a cluster would.

```bash
export BUZZ_IMAGE=ghcr.io/block/buzz:sha-6e5c462   # pin; change to test a newer tag
export SIM_OWNER_PUBKEY=$(./target/release/tenant_sim --print-owner --profile perf/profiles/10h-20a.toml)
export SIM_RELAY_KEY=$(openssl rand -hex 32)
export SIM_GIT_HMAC=$(openssl rand -hex 32)

python3 perf/tenant_cogs.py run \
  --substrate compose \
  --profile perf/profiles/10h-20a.toml \
  --relay-url ws://localhost:3030 \
  --http-url http://localhost:3030 \
  --metrics-url http://localhost:9202/metrics \
  --out-dir ./runs/local-1 \
  --results ./runs/local-1/results.jsonl \
  --tenant-sim ./target/release/tenant_sim \
  --git-credential-helper ./target/release/git-credential-nostr
```

`tenant_cogs.py` wipes the compose project (`down -v`) before each run unless
you pass `--skip-reset`. Pass `--keep` to leave the stack up.

Pin the image by digest (`ghcr.io/block/buzz@sha256:…`) for a result you
will compare later; a tag can move. The results line records the digest and
the image's source revision either way.

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
that never comes. The same applies with `--skip-reset` and on k3s, where the
harness cannot restart the relay.

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

## Substrate: k3s (absolute numbers)

Same generator. Point `--kubeconfig`, `--namespace` (default `buzz-loadtest`),
and `--substrate k3s` at a cluster you already installed the chart on. The
harness does not mint machines and does not assume any hostnames.

```bash
python3 perf/tenant_cogs.py run \
  --substrate k3s \
  --kubeconfig ./kubeconfig \
  --namespace buzz-loadtest \
  --relay-url ws://127.0.0.1:30030 \
  --http-url http://127.0.0.1:30030 \
  --metrics-url http://127.0.0.1:9102/metrics \
  --health-url http://127.0.0.1:30030/ \
  --profile perf/profiles/10h-20a.toml \
  --out-dir ./runs/k3s-1 \
  --results ./runs/k3s-1/results.jsonl \
  --skip-reset
```

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
change.

## Tests

```bash
python3 -m unittest perf/test_tenant_cogs.py
# from the perf/ directory:
cd perf && python3 -m unittest test_tenant_cogs.py
```

The profile is parsed as TOML by both `tenant_sim` and `tenant_cogs.py`, so
band lengths in `[bands]` are the lengths the orchestrator runs.

A successful `run` exits 0 only when the floor shows 30 connections, sampled
bands have zero unexpected rejects, media uploads succeeded with zero
rejects, git pushed with zero failures, the three bands are distinct, and
`lost_after_backfill` is 0. A results line is still appended for diagnosis;
the process exit is the weekly-job gate.

`fanout_recipients_p50` is a true histogram percentile of the observations
that landed in that band (end-minus-start bucket counts), not a lifetime
`sum/count` mean. Ready/summary reads time out against a silent child, and
`cmd_run` always tears the stack down unless `--keep` is set.

## What is not in this tree

Run outputs, identities, kubeconfigs, and `.env` files. `runs/` and
`identities.json` are gitignored. Do not commit them.

k3s bring-up, chart/server fingerprint, replica config, Postgres secret
handling, box cost, and the rolling-update blink test are out of scope
here. Those live in the private wrapper, which is not part of this PR.
