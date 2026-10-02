#!/usr/bin/env bash
# The band clock's local proof: builds tenant_sim and git-credential-nostr,
# then runs perf/clock_proof.py, which says what each row forces and checks.
#
#   perf/clock-proof.sh --out DIR [--rows reads,ramp,...] [--prefix NAME]
#
# PYTHON picks the interpreter (default: python3 on PATH); the proof prints
# which one ran. Every image must already be on this machine: the proof
# never pulls one.
set -euo pipefail

# Run again, once, from a fixed environment (perf/TENANT_COGS.md, "Child
# environments"): PATH, HOME, TMPDIR and LC_ALL=C, and the names below, each
# only when set. Nothing else of the caller's reaches cargo, the proof or
# anything they start. PYTHON picks the interpreter below. The DOCKER_* names
# select the daemon the proof checks and drives; CARGO_HOME, RUSTUP_HOME and
# RUSTUP_TOOLCHAIN select the registry and the toolchain. Dropping one would
# silently switch to another.
if [[ -z "${HARNESS_ENV_FIXED:-}" ]]; then
  fixed=(LC_ALL=C HARNESS_ENV_FIXED=1)
  for name in PATH HOME TMPDIR PYTHON DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN; do
    [[ -z "${!name+x}" ]] || fixed+=("$name=${!name}")
  done
  exec /usr/bin/env -i "${fixed[@]}" /bin/bash "$0" "$@"
fi
unset HARNESS_ENV_FIXED

trap 'exit 130' INT
trap 'exit 143' TERM
cd "$(dirname "$0")/.."
cargo build --release -p buzz-test-client --bin tenant_sim
cargo build --release -p git-credential-nostr
exec "${PYTHON:-python3}" perf/clock_proof.py "$@"
