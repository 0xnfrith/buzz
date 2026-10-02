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
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$(dirname "$0")/.."
cargo build --release -p buzz-test-client --bin tenant_sim
cargo build --release -p git-credential-nostr
exec "${PYTHON:-python3}" perf/clock_proof.py "$@"
