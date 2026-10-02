#!/usr/bin/env bash
# Captures the fixtures test_box_sampler.py reads, from real commands on a
# workstation's Docker, so the reader's parsers are tested on real output.
# Run once; the result is pinned in SHA256SUMS.
#
#   perf/testdata/remote_sampler/capture.sh <ubuntu image with nft> <postgres image>
#
# Both images must already be local: it never pulls (--pull never). Every
# container is named g613-capture-*, has no network unless it needs one, and
# is removed by that exact name on any exit. It changes nothing else.
set -euo pipefail

# Run again, once, from a fixed environment (perf/TENANT_COGS.md, "Child
# environments"): PATH, HOME, TMPDIR and LC_ALL=C, and the names below, each
# only when set. Nothing else of the caller's reaches docker. The DOCKER_*
# names select the daemon the containers run on; dropping one would silently
# switch to another.
if [[ -z "${HARNESS_ENV_FIXED:-}" ]]; then
  fixed=(LC_ALL=C HARNESS_ENV_FIXED=1)
  for name in PATH HOME TMPDIR DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG; do
    [[ -z "${!name+x}" ]] || fixed+=("$name=${!name}")
  done
  exec /usr/bin/env -i "${fixed[@]}" /bin/bash "$0" "$@"
fi
unset HARNESS_ENV_FIXED

UBUNTU=${1:?usage: capture.sh <ubuntu image with nft> <postgres image>}
POSTGRES=${2:?usage: capture.sh <ubuntu image with nft> <postgres image>}
HERE=$(cd "$(dirname "$0")" && pwd)
NAMES=(g613-capture-proc g613-capture-nft g613-capture-a g613-capture-b g613-capture-pg)
cleanup() { for c in "${NAMES[@]}"; do docker rm -fv "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ROOT="$HERE/root"
CG="$ROOT/sys/fs/cgroup/system.slice/docker-$(printf 'a%.0s' {1..64}).scope"
mkdir -p "$ROOT/proc" "$CG" "$HERE/docker" "$HERE/nft" "$HERE/psql"

# /proc and one cgroup's files, from inside a container: /proc shows the
# Docker VM's totals; /sys/fs/cgroup is the container's own cgroup (v2).
docker run -d --name g613-capture-proc --network none --pull never "$UBUNTU" sleep 60 >/dev/null
for f in meminfo stat loadavg vmstat diskstats; do docker exec g613-capture-proc cat "/proc/$f" >"$ROOT/proc/$f"; done
for f in cpu.stat memory.current memory.stat memory.events memory.peak; do docker exec g613-capture-proc cat "/sys/fs/cgroup/$f" >"$CG/$f"; done

# nftables: a two-chain table with counters, and some drops, in a
# container's own network namespace (NET_ADMIN only, never --privileged).
docker run -d --name g613-capture-nft --network none --cap-add NET_ADMIN --pull never "$UBUNTU" sleep 60 >/dev/null
docker exec -i g613-capture-nft nft -f - <<'NFT'
table inet capture_egress {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    counter drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    counter drop
  }
}
NFT
# A dummy interface gives the sends a way out, so the output chain drops
# them (and its counter moves) rather than the kernel finding no route.
docker exec g613-capture-nft sh -c 'ip link add g613d0 type dummy && ip link set g613d0 up && ip addr add 192.0.2.1/24 dev g613d0; for i in 1 2 3; do timeout 1 bash -c "exec 3<>/dev/udp/192.0.2.9/53; printf x >&3" 2>/dev/null || true; done'
docker exec g613-capture-nft nft -s list table inet capture_egress >"$HERE/nft/stateless.txt"
docker exec g613-capture-nft nft list table inet capture_egress >"$HERE/nft/counters.txt"

# docker ps and inspect, in the exact formats the reader asks for, on two
# containers labelled like a Compose project's.
for svc in a b; do
	docker run -d --name "g613-capture-$svc" --network none --pull never \
		--label com.docker.compose.project=g613-capture --label "com.docker.compose.service=svc-$svc" "$UBUNTU" sleep 60 >/dev/null
done
docker ps --no-trunc --filter label=com.docker.compose.project=g613-capture \
	--format '{{.ID}}	{{.Label "com.docker.compose.service"}}' >"$HERE/docker/ps.txt"
# shellcheck disable=SC2046
docker inspect -f '{{.Id}}	{{.State.Pid}}' $(cut -f1 "$HERE/docker/ps.txt") >"$HERE/docker/inspect.txt"

# The reader's one SQL query, through psql -tA, on a real Postgres.
docker run -d --name g613-capture-pg --network none --pull never -e POSTGRES_PASSWORD=capture "$POSTGRES" >/dev/null
for _ in $(seq 1 60); do docker exec g613-capture-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
docker exec g613-capture-pg psql -U postgres -d postgres -tAc \
	"select pg_current_wal_lsn(), pg_database_size(current_database())" >"$HERE/psql/wal.txt"

echo "captured into $HERE"
