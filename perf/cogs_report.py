#!/usr/bin/env python3
"""Turn tenant_cogs results.jsonl into proposed Helm values, diffs, and anchors."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


SCHEMA = 1
REQUIRED_TOP = (
    "schema",
    "run_id",
    "substrate",
    "buzz_commit",
    "profile",
    "bands",
    "totals",
)
REQUIRED_BAND = ("seconds", "samples", "relay", "postgres", "redis", "minio", "stack", "db")

# Idle RSS fallbacks (bytes) used when no second-substrate run exists.
IDLE_RSS = {
    "relay": 35 * 1024 * 1024,
    "postgres": 80 * 1024 * 1024,
    "minio": 105 * 1024 * 1024,
    "redis": 4 * 1024 * 1024,
}


def load_lines(path: Path) -> list[dict[str, Any]]:
    lines = []
    for i, raw in enumerate(path.read_text().splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{i}: invalid JSON: {exc}") from exc
        lines.append(obj)
    return lines


def validate_line(obj: dict[str, Any], idx: int) -> list[str]:
    errs = []
    if obj.get("schema") != SCHEMA:
        errs.append(f"line {idx}: schema {obj.get('schema')!r} != {SCHEMA}")
    for key in REQUIRED_TOP:
        if key not in obj:
            errs.append(f"line {idx}: missing {key}")
    bands = obj.get("bands") or {}
    for band in ("floor", "steady", "peak"):
        b = bands.get(band)
        if not isinstance(b, dict):
            errs.append(f"line {idx}: bands.{band} missing")
            continue
        for key in REQUIRED_BAND:
            if key not in b:
                errs.append(f"line {idx}: bands.{band}.{key} missing")
    return errs


def cmd_validate(args: argparse.Namespace) -> int:
    lines = load_lines(Path(args.results))
    errs: list[str] = []
    for i, obj in enumerate(lines, 1):
        errs.extend(validate_line(obj, i))
    if errs:
        print("\n".join(errs), file=sys.stderr)
        return 1
    print(f"ok: {len(lines)} valid line(s)")
    return 0


def ceil_to(value: float, step: float) -> float:
    if value <= 0:
        return step
    return math.ceil(value / step) * step


def millicores(cpu_s_per_tenant_hour: float) -> int:
    raw = cpu_s_per_tenant_hour / 3600.0 * 1000.0 * 1.5
    return int(ceil_to(raw, 25))


def bytes_to_mi(n: float) -> int:
    return int(round(n / (1024 * 1024)))


def ceil32mi(n: float) -> int:
    step = 32 * 1024 * 1024
    return int(ceil_to(n, step) // (1024 * 1024))


def ceil1gi(n: float) -> int:
    step = 1024 * 1024 * 1024
    return int(ceil_to(max(n, step), step) // step)


def fmt_cpu(m: int) -> str:
    if m >= 1000 and m % 1000 == 0:
        return f"{m // 1000}"
    return f"{m}m"


def fmt_mi(mi: int) -> str:
    if mi >= 1024 and mi % 1024 == 0:
        return f"{mi // 1024}Gi"
    return f"{mi}Mi"


def pick_run(lines: list[dict[str, Any]], run_id: str | None) -> dict[str, Any]:
    if run_id:
        for obj in lines:
            if obj.get("run_id") == run_id:
                return obj
        raise SystemExit(f"run_id not found: {run_id}")
    if not lines:
        raise SystemExit("no results")
    return lines[-1]


def proposed_values(line: dict[str, Any], tier: str) -> dict[str, Any]:
    steady = line["bands"]["steady"]
    peak = line["bands"]["peak"]
    relay_req_cpu = millicores(steady["relay"].get("cpu_s_per_tenant_hour") or 0)
    rss_src = (
        peak["relay"]["rss_bytes"]["p95"]
        if tier == "reference"
        else steady["relay"]["rss_bytes"]["p95"]
    )
    relay_req_mem = max(ceil32mi(rss_src * 1.2), 32)
    relay_lim_cpu = "1" if tier == "trial" else "2"
    relay_lim_mem = max(ceil32mi((peak["relay"]["rss_bytes"]["max"] or 1) * 1.5), 512)

    pg_req_cpu = millicores(steady["postgres"].get("cpu_s_per_tenant_hour") or 0)
    pg_req_mem = max(ceil32mi((steady["postgres"]["rss_bytes"]["p95"] or 1) * 1.2), 32)
    pg_lim_mem = max(ceil32mi((peak["postgres"]["rss_bytes"]["max"] or 1) * 1.5), 256)

    db_end = peak["db"]["size_bytes"]["end"] or 1
    wal_hw = line["totals"].get("wal_high_water_bytes") or peak["db"]["wal_bytes"]["max"] or 0
    run_s = (
        line["bands"]["floor"]["seconds"]
        + steady["seconds"]
        + peak["seconds"]
    ) or 1
    db_start = line["bands"]["floor"]["db"]["size_bytes"]["start"] or db_end
    growth = max(db_end - db_start, 0)
    daily_growth = growth * 86400 / run_s if run_s else 0
    retention_factor = (365 * daily_growth / db_end) if db_end else 1.0
    retention_factor = max(retention_factor, 1.0)
    max_wal = 256 * 1024 * 1024 if tier == "trial" else 1024 * 1024 * 1024
    pg_pvc = max(ceil1gi((db_end + max_wal) * 1.2 * retention_factor), 3)

    wal_gen = peak["db"].get("wal_gen_bytes_per_s") or 0
    wal_cfg = min(max(int(ceil_to(3 * wal_gen * 300, 64 * 1024 * 1024)), 128 * 1024 * 1024), 1024 * 1024 * 1024)
    if tier != "trial":
        wal_cfg = 1024 * 1024 * 1024

    obj_end = peak["objects"]["bytes"]["end"] or 1
    minio_pvc = max(ceil1gi(obj_end * retention_factor * 1.2), 3)

    redis_mem = max(ceil32mi((steady["redis"]["rss_bytes"]["p95"] or 1) * 1.2), 32)

    return {
        "tier": tier,
        "relay.resources.requests.cpu": fmt_cpu(relay_req_cpu),
        "relay.resources.requests.memory": fmt_mi(relay_req_mem),
        "relay.resources.limits.cpu": relay_lim_cpu,
        "relay.resources.limits.memory": fmt_mi(relay_lim_mem),
        "postgresql.resources.requests.cpu": fmt_cpu(pg_req_cpu),
        "postgresql.resources.requests.memory": fmt_mi(pg_req_mem),
        "postgresql.resources.limits.memory": fmt_mi(pg_lim_mem),
        "postgresql.persistence.size": f"{pg_pvc}Gi",
        "postgresql.config.extraConfig max_wal_size": f"{wal_cfg // (1024 * 1024)}MB",
        "minio.persistence.size": f"{minio_pvc}Gi",
        "redis.resources.requests.memory": fmt_mi(redis_mem),
        "redis.persistence.size": "1Gi",
        "raw": {
            "relay_req_cpu_m": relay_req_cpu,
            "relay_req_mem_mi": relay_req_mem,
            "daily_growth_bytes": daily_growth,
            "retention_factor": retention_factor,
            "wal_gen_bytes_per_s": wal_gen,
        },
    }


def density(line: dict[str, Any], trial: dict[str, Any]) -> dict[str, Any]:
    # Box allocatable defaults (documented as 1800m / 7.6Gi / 69Gi).
    alloc_cpu_m = 1800
    alloc_mem = int(7.6 * 1024 * 1024 * 1024)
    alloc_disk = 69 * 1024 * 1024 * 1024
    k3s_overhead = (line.get("node") or {}).get("k3s_overhead_bytes") or int(0.9 * 1024 * 1024 * 1024)

    def parse_cpu(s: str) -> int:
        if s.endswith("m"):
            return int(s[:-1])
        return int(float(s) * 1000)

    def parse_mem(s: str) -> int:
        if s.endswith("Gi"):
            return int(s[:-2]) * 1024 * 1024 * 1024
        if s.endswith("Mi"):
            return int(s[:-2]) * 1024 * 1024
        return int(s)

    req_cpu = parse_cpu(trial["relay.resources.requests.cpu"]) + parse_cpu(
        trial["postgresql.resources.requests.cpu"]
    )
    req_mem = parse_mem(trial["relay.resources.requests.memory"]) + parse_mem(
        trial["postgresql.resources.requests.memory"]
    ) + parse_mem(trial["redis.resources.requests.memory"])
    pvc = parse_mem(trial["postgresql.persistence.size"]) + parse_mem(
        trial["minio.persistence.size"]
    ) + parse_mem(trial["redis.persistence.size"])

    declared = min(
        alloc_cpu_m // max(req_cpu, 1),
        (alloc_mem - k3s_overhead) // max(req_mem, 1),
        alloc_disk // max(pvc, 1),
    )
    peak_rss = line["bands"]["peak"]["stack"]["rss_bytes"]["max"] or 1
    peak_cpu_s = line["bands"]["peak"]["stack"]["cpu_s"] or 0
    peak_seconds = line["bands"]["peak"]["seconds"] or 1
    peak_m = (peak_cpu_s / peak_seconds) * 1000
    measured = min(
        int((alloc_mem - k3s_overhead) / (peak_rss * 1.25)),
        int(2000 / max(peak_m * 2, 1)),
    )
    dedicated_need = peak_rss + k3s_overhead + 1024 * 1024 * 1024
    four_vs_eight = "4Gi sufficient" if dedicated_need <= 4 * 1024 * 1024 * 1024 else "8Gi required"
    return {
        "declared_density": int(declared),
        "measured_density": max(int(measured), 0),
        "peak_stack_rss_max": peak_rss,
        "k3s_overhead_bytes": k3s_overhead,
        "dedicated_need_bytes": dedicated_need,
        "dedicated_verdict": four_vs_eight,
    }


def render_report(line: dict[str, Any]) -> str:
    trial = proposed_values(line, "trial")
    reference = proposed_values(line, "reference")
    dens = density(line, trial)
    bands = line["bands"]
    out = []
    out.append(f"# COGS report — {line.get('run_id')}")
    out.append("")
    out.append(f"- substrate: `{line.get('substrate')}`")
    out.append(f"- buzz_commit: `{line.get('buzz_commit')}`")
    out.append(f"- profile: `{line.get('profile')}`")
    out.append(f"- image: `{line.get('buzz_image')}`")
    out.append("")
    out.append("## Bands")
    out.append("")
    out.append("| band | relay RSS p50/p95/max | relay CPU-s | postgres RSS p95 | db end | WAL max |")
    out.append("|---|---|---|---|---|---|")
    for name in ("floor", "steady", "peak"):
        b = bands[name]
        rss = b["relay"]["rss_bytes"]
        out.append(
            f"| {name} | {bytes_to_mi(rss['p50'])}/{bytes_to_mi(rss['p95'])}/{bytes_to_mi(rss['max'])} Mi "
            f"| {b['relay']['cpu_s']:.2f} | {bytes_to_mi(b['postgres']['rss_bytes']['p95'])} Mi "
            f"| {b['db']['size_bytes']['end']} | {b['db']['wal_bytes']['max']} |"
        )
    out.append("")
    floor_rss = bands["floor"]["relay"]["rss_bytes"]["p50"]
    steady_rss = bands["steady"]["relay"]["rss_bytes"]["p50"]
    peak_rss = bands["peak"]["relay"]["rss_bytes"]["max"]
    distinct = floor_rss < steady_rss < peak_rss
    out.append(f"Three bands distinct (floor p50 < steady p50 < peak max): **{distinct}**")
    out.append("")
    out.append("## Proposed values")
    out.append("")
    out.append("| key | trial | reference |")
    out.append("|---|---|---|")
    keys = [k for k in trial if k not in {"tier", "raw"}]
    for k in keys:
        out.append(f"| `{k}` | {trial[k]} | {reference[k]} |")
    out.append("")
    out.append("Margins: request = measured × 1.5 CPU / × 1.2 memory; limit = peak max × 1.5 (floor 512Mi relay).")
    out.append("PVC retention_factor default is 1 year of extrapolated daily growth, floor 3Gi.")
    out.append("")
    out.append("## Density (trial requests vs 2-vCPU / 8Gi box)")
    out.append("")
    out.append(f"- declared_density (scheduler): **{dens['declared_density']}** stacks")
    out.append(f"- measured_density (peak physics): **{dens['measured_density']}** stacks")
    out.append(f"- dedicated 4-vs-8 GiB: **{dens['dedicated_verdict']}** (need {dens['dedicated_need_bytes']} bytes)")
    out.append("")
    sat = False
    waiters = bands["peak"]["relay_metrics"].get("db_pool_waiters_max") or 0
    if waiters > 0:
        out.append(f"Peak db_pool_waiters_max={waiters} — check SATURATED before trusting peak limits.")
    if sat:
        out.append("Peak band marked SATURATED.")
    out.append("")
    out.append("## Totals")
    out.append("")
    for k, v in (line.get("totals") or {}).items():
        out.append(f"- {k}: {v}")
    notes = line.get("notes") or ""
    if notes:
        out.append("")
        out.append(f"Notes: {notes}")
    out.append("")
    return "\n".join(out) + "\n"


def cmd_report(args: argparse.Namespace) -> int:
    lines = load_lines(Path(args.results))
    line = pick_run(lines, args.run)
    text = render_report(line)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text)
        print(args.out)
    else:
        sys.stdout.write(text)
    return 0


def flatten(obj: dict[str, Any], prefix: str = "") -> dict[str, float]:
    out: dict[str, float] = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten(v, key))
        elif isinstance(v, bool):
            continue
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            out[key] = float(v)
    return out


def cmd_diff(args: argparse.Namespace) -> int:
    lines = load_lines(Path(args.results))
    if args.profile:
        lines = [l for l in lines if l.get("profile") == args.profile]
    if args.substrate:
        lines = [l for l in lines if l.get("substrate") == args.substrate]
    if args.against:
        baseline = pick_run(lines, args.against)
        newer = [l for l in lines if l.get("run_id") != args.against]
        if not newer:
            raise SystemExit("no comparison run")
        other = newer[-1]
    else:
        by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for l in lines:
            by_pair.setdefault((l.get("profile"), l.get("substrate")), []).append(l)
        pair = None
        for key, group in by_pair.items():
            commits = {g.get("buzz_commit") for g in group}
            if len(commits) >= 2:
                pair = group
        if not pair:
            raise SystemExit("need two runs of the same (profile, substrate) at different buzz_commit")
        # two most recent with different commits
        pair = sorted(pair, key=lambda x: x.get("run_id"))
        baseline, other = pair[-2], pair[-1]
        if baseline.get("buzz_commit") == other.get("buzz_commit"):
            # pick first different
            for cand in reversed(pair[:-1]):
                if cand.get("buzz_commit") != other.get("buzz_commit"):
                    baseline = cand
                    break
    print(f"# diff {baseline.get('run_id')} ({baseline.get('buzz_commit')}) → {other.get('run_id')} ({other.get('buzz_commit')})")
    print()
    print("| metric | before | after | abs | pct | flag |")
    print("|---|---|---|---|---|---|")
    a = flatten(baseline.get("bands", {}))
    b = flatten(other.get("bands", {}))
    keys = sorted(set(a) | set(b))
    for k in keys:
        av, bv = a.get(k), b.get(k)
        if av is None or bv is None:
            continue
        abs_d = bv - av
        pct = (abs_d / av * 100.0) if av else (0.0 if bv == 0 else float("inf"))
        flag = " **" if abs(pct) > 15 and av != 0 else ""
        pct_s = "n/a" if pct == float("inf") else f"{pct:.1f}%"
        print(f"| `{k}` | {av:.4g} | {bv:.4g} | {abs_d:.4g} | {pct_s} |{flag} |")
    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    lines = load_lines(Path(args.results))
    a = pick_run(lines, args.a)
    b = pick_run(lines, args.b)
    print("| component | signal | A | B | ratio |")
    print("|---|---|---|---|---|")
    suspect = False
    for comp in ("relay", "postgres", "redis", "minio"):
        for signal, path in (
            ("rss_p50", ("rss_bytes", "p50")),
            ("cpu_s_per_tenant_hour", ("cpu_s_per_tenant_hour",)),
        ):
            def get(line: dict[str, Any]) -> float:
                node = line["bands"]["floor"][comp]
                cur: Any = node
                for p in path:
                    if isinstance(cur, dict):
                        cur = cur.get(p, 0)
                    else:
                        return 0.0
                return float(cur or 0)

            av, bv = get(a), get(b)
            ratio = (bv / av) if av else None
            flag = ""
            if comp == "relay" and signal == "rss_p50" and ratio is not None:
                if ratio < 0.5 or ratio > 2.0:
                    flag = " ANCHOR_SUSPECT"
                    suspect = True
            ratio_s = "n/a" if ratio is None else f"{ratio:.3f}"
            print(f"| {comp} | {signal} | {av:.4g} | {bv:.4g} | {ratio_s}{flag} |")
    if suspect:
        print("\nANCHOR_SUSPECT: relay RSS floor ratio outside [0.5, 2.0]. Check the harness first.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cogs_report.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report")
    r.add_argument("--results", required=True)
    r.add_argument("--run", default=None)
    r.add_argument("--tier", choices=("trial", "reference", "both"), default="both")
    r.add_argument("--out", default=None)
    d = sub.add_parser("diff")
    d.add_argument("--results", required=True)
    d.add_argument("--against", default=None)
    d.add_argument("--profile", default=None)
    d.add_argument("--substrate", default=None)
    v = sub.add_parser("validate")
    v.add_argument("--results", required=True)
    a = sub.add_parser("anchor")
    a.add_argument("--results", required=True)
    a.add_argument("--a", required=True)
    a.add_argument("--b", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "diff":
        return cmd_diff(args)
    if args.cmd == "anchor":
        return cmd_anchor(args)
    raise SystemExit(args.cmd)


if __name__ == "__main__":
    sys.exit(main())
