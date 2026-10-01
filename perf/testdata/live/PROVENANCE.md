# Live counters fixture

`test_remote_sampler.py` reads `ramp-stop.json` with the loop's own
`read_live`, so the loop is held to what `tenant_sim` really writes. Its
sha256 is pinned in `SHA256SUMS`, and the test refuses a file that doesn't
match.

| File | Where it came from |
|---|---|
| `ramp-stop.json` | The last `live.json` of the run-level row `a_run_on_a_fifo_ends_on_stop_or_when_its_lease_runs_out` (`tenant_sim.rs`): a whole `tenant_sim` run on a fifo against the row's fake relay, a ramp of the solo profile to 18 identities, ended by `stop`. Re-indented with sorted keys; values unchanged |

When `tenant_sim` adds or renames a live field, capture this again the same
way and re-pin it; the Rust row `live_json_holds_the_fields_the_sampler_reads`
fails until both sides agree.
