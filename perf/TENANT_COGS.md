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

Rolling-update reconnect tracking: `tenant_sim --blink` plus
`python3 perf/tenant_cogs.py blink --substrate k3s ... --rollout 'kubectl -n buzz-loadtest rollout restart deploy/buzz'`.

## Report

```bash
python3 perf/cogs_report.py validate --results ./runs/local-1/results.jsonl
python3 perf/cogs_report.py report   --results ./runs/local-1/results.jsonl --out ./runs/local-1/report.md
python3 perf/cogs_report.py diff     --results ./runs/all.jsonl --profile 10h-20a
python3 perf/cogs_report.py anchor   --results ./runs/all.jsonl --a <run-a> --b <run-b>
```

`diff` compares the two most recent lines of the same `(profile, substrate)`
that have **different** `buzz_commit` values and flags anything that moved
more than 15%.

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

## What is not in this tree

Run outputs, identities, kubeconfigs, and `.env` files. `runs/` and
`identities.json` are gitignored. Do not commit them.
