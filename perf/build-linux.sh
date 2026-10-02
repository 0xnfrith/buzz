#!/usr/bin/env bash
# Build tenant_sim and git-credential-nostr for linux/amd64, the same way
# every time: static musl binaries from a digest-pinned Rust image, with
# --locked dependencies, a fixed source path (/src) and a fixed Cargo home
# (/cargo). Prints the sha256 of each binary.
#
#   perf/build-linux.sh            # binaries in target/linux-amd64/
#
# Needs Docker. On an arm64 host the build runs emulated (slower, same
# output). The Cargo registry and the target directory live in two named
# Docker volumes so a rebuild is incremental; `docker volume rm` them for a
# clean build.
set -euo pipefail

# Run again, once, from a fixed environment (perf/TENANT_COGS.md, "Child
# environments"): PATH, HOME, TMPDIR and LC_ALL=C, and the names below, each
# only when set. Nothing else of the caller's reaches the endpoint check or
# docker. The DOCKER_* names select the daemon the endpoint check reads and
# docker talks to; dropping one would silently switch to another. (Cargo runs
# inside the container, with the values docker run names, so no CARGO_* name
# is kept.)
if [[ -z "${HARNESS_ENV_FIXED:-}" ]]; then
  fixed=(LC_ALL=C HARNESS_ENV_FIXED=1)
  for name in PATH HOME TMPDIR DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG; do
    [[ -z "${!name+x}" ]] || fixed+=("$name=${!name}")
  done
  exec /usr/bin/env -i "${fixed[@]}" /bin/bash "$0" "$@"
fi
unset HARNESS_ENV_FIXED

# rust:1.95.0-alpine (rust-toolchain.toml pins 1.95.0), linux/amd64 manifest.
IMAGE="rust:1.95.0-alpine@sha256:e98196986adced5602f6e21c54babdbf2a8700400c7a78868324a3630e0c5d15"
TARGET="x86_64-unknown-linux-musl"
BINS=(tenant_sim git-credential-nostr)

repo="$(cd "$(dirname "$0")/.." && pwd)"

# The Docker endpoint must be a local Unix socket, by the same rule as the
# sampler (perf/tenant_cogs.py, "Docker endpoint guard"). Every docker call
# names it, with DOCKER_HOST set to it and DOCKER_CONTEXT removed.
endpoint="$(python3 "$repo/perf/tenant_cogs.py" docker-endpoint)" || exit 2
unset DOCKER_CONTEXT
export DOCKER_HOST="$endpoint"

out="$repo/target/linux-amd64"
mkdir -p "$out"

docker --host "$endpoint" run --rm --platform linux/amd64 \
  -v "$repo":/src:ro \
  -v buzz-harness-linux-cargo:/cargo \
  -v buzz-harness-linux-target:/target \
  -v "$out":/out \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -e RUSTUP_TOOLCHAIN=1.95.0 \
  -e SOURCE_DATE_EPOCH=0 \
  -w /src \
  "$IMAGE" \
  sh -euc '
    apk add --no-cache build-base cmake perl git >/dev/null
    cargo build --release --locked --target '"$TARGET"' \
      -p buzz-test-client --bin tenant_sim \
      -p git-credential-nostr --bin git-credential-nostr
    for b in '"${BINS[*]}"'; do
      install -m 0755 "/target/'"$TARGET"'/release/$b" "/out/$b"
    done
  '

cd "$out"
for b in "${BINS[@]}"; do
  file "$b"
done
shasum -a 256 "${BINS[@]}"
