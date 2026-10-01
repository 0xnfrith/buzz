# Remote sampler fixtures

`test_box_sampler.py` reads these. Each file's sha256 is pinned in
`SHA256SUMS`, and the tests refuse a file that doesn't match.

| File | Where it came from |
|---|---|
| `root/proc/{meminfo,stat,loadavg,vmstat,diskstats}` | `capture.sh`: `cat` inside a container on Docker 29.4.0 (OrbStack, arm64), so they show the Docker VM's kernel's totals. Same formats as on an Ubuntu 24.04 host |
| `root/sys/fs/cgroup/system.slice/docker-a…a.scope/*` | `capture.sh`: the container's own cgroup v2 files (`cpu.stat`, `memory.current`, `memory.stat`, `memory.events`, `memory.peak`). The folder name is the Ubuntu `docker.io` (systemd cgroup driver) layout, with a placeholder id |
| `root/proc/2322844/cgroup` | **Written by hand:** the line a container's main process shows on an Ubuntu host with the systemd cgroup driver, `0::/system.slice/docker-<id>.scope`. The pid is the one `docker/inspect.txt` gives for `svc-a` |
| `docker/ps.txt`, `docker/inspect.txt` | `capture.sh`: the real `docker ps --no-trunc --filter label=… --format '{{.ID}}<tab>{{.Label …}}'` and `docker inspect -f '{{.Id}}<tab>{{.State.Pid}}'`, on two throwaway containers labelled like a Compose project's |
| `docker/system_df.txt` | **Format real, sizes made up:** `docker system df --format '{{.Type}}<tab>{{.Size}}'` gives these four types in this order on Docker 29.4.0. The sizes are replaced, so no workstation's totals are in the tree |
| `nft/stateless.txt`, `nft/counters.txt` | `capture.sh`: `nft -s list table` and `nft list table` of a two-chain table with counters, after three sends the output chain dropped, in a container's own network namespace |
| `psql/wal.txt` | `capture.sh`: the reader's query through `psql -tA` on Postgres 17 (Alpine) |

`capture.sh` was run with the local images `g613-proof:df7e0f79671983ab`
(Ubuntu 24.04 with nftables) and `postgres:17-alpine`. It never pulls, and it
removes each `g613-capture-*` container by name.
