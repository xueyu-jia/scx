# scx_agent_classed

`scx_agent_classed` is a two-level `sched_ext` scheduler for statically
classified LATENCY and BATCH workloads. It uses one DSQ per class per CPU and
keeps class arbitration, class-local ordering, and load balancing as separate
decisions.

[`DIAGNOSTICS.md`](DIAGNOSTICS.md) contains superseded experimental evidence.
It is not the contract for the policy described here.

## Architecture

The scheduling path is:

```text
Linux comm -> static class -> target CPU -> per-class per-CPU DSQ
           -> collect local candidates -> decide_class()
           -> class-local dispatch or continuation -> local fallback
           -> gated remote steal only when local work is absent
```

Each possible CPU owns exactly two priority DSQs:

- `LATENCY[cpu]`, ordered by weighted task vruntime.
- `BATCH[cpu]`, ordered by weighted task vruntime.

Actual execution time advances task vruntime and the corresponding per-CPU and
global class entities. Queue ordering never uses the configured time slice or
BATCH epoch as its key.

## Class arbitration

`decide_class()` is the only cross-class policy. Normal dispatch, wakeup
handoff, continuation, and slice expiry all consume the same decision:

```text
struct class_decision {
    winner
    fallback
    run_for_ns              // remaining CPU runtime before the next boundary
    reason                 // diagnostics only
}
```

The candidate mask is built from work that can actually run locally: a task in
a class DSQ, the currently runnable task, or the task whose enqueue callback is
in progress. The last case is explicit because SCX does not publish a pending
DSQ insertion until `enqueue()` returns. Queue and running counters are
accounting data, not substitutes for this candidate check.

If only one class is available, it wins immediately. If both are available,
the picker compares projected class vruntimes, including the current task's
uncommitted runtime:

```text
LATENCY wins when:
    latency_vruntime - batch_vruntime <= class_max_debt

BATCH wins otherwise.
```

Class runtime is normalized by `runtime * 100 / class_weight`. With the default
weights of 200 and 100, continuously runnable local classes converge toward an
approximate LATENCY:BATCH CPU-time ratio of 2:1. `class_max_debt` allows a
bounded LATENCY lead; it is not absolute priority.

After LATENCY service, the BATCH class may accumulate `batch_min_run` of CPU
time before the next LATENCY handoff. This is per-CPU class state: an
interruption or a switch between BATCH tasks does not renew the protection.
`decide_class()` returns the winner's service budget in `run_for_ns`.
`U64_MAX` means that only one class is runnable. When the winner differs from
the current class, the scheduler requests an immediate handoff; the budget is
then applied while moving the winner into the local DSQ. A finite budget only
shrinks a task's residual slice. Slice expiry returns to dispatch, which invokes
the same arbitration again. There is no second arbitration path or queue model.

Dispatch first tries `winner` with `min(task_slice, run_for_ns)`, then
`fallback`, recollects the real DSQ mask, and retries only classes which are
still present. If every DSQ move races or fails, a still-runnable previous task
receives a work-conserving continuation before remote work is considered.
If a remote source claim transiently blocks a local move, the CPU is kicked
after the claim is released instead of leaving a non-empty local DSQ idle.
`SCX_ENQ_LAST` remains the kernel-side safety net, not the normal fallback
mechanism.

## LATENCY policy

LATENCY tasks use a per-CPU weighted-vruntime queue and locality-oriented CPU
selection derived from `scx_forge`.

- A wakeup starts with a `latency_slice` grant.
- Voluntary sleep preserves bounded signed virtual lag relative to the task's
  per-CPU LATENCY frontier. Wakeup and migration rebase that lag onto the
  destination CPU instead of copying an absolute vruntime.
- A task may continue only when `decide_class()` still selects LATENCY, no
  earlier LATENCY task is waiting locally, and the wakeup's total
  `latency_burst` budget is not exhausted.
- A continuation grants at most one `latency_slice` at a time. The default
  configuration allows 2 ms total service for one wakeup; the configurable
  burst limit is validated independently.
- Every continuation advances the running task's preemption epoch, so a prior
  handoff request cannot suppress a later valid handoff on the new slice.

The bounded continuation improves short multi-slice bursts without giving the
LATENCY class unconditional service.

## BATCH policy

BATCH uses one weighted-vruntime DSQ per CPU. Its adaptive epoch changes how
often a task is reconsidered, not its CPU entitlement or queue position.

- Every task starts at `batch_min_epoch`.
- A task which consumes its complete epoch and remains runnable doubles its
  learned target, up to `batch_max_epoch`.
- Blocking or sleeping resets the learned target to `batch_min_epoch`.
- A class handoff or migration preserves the unused part of the current epoch.
- The effective grant is capped by
  `batch_round / local_batch_runnable`, clamped to the configured minimum and
  maximum epoch.
- In mixed-class operation, class arbitration may shorten that grant further;
  the learned epoch itself is preserved.
- Actual runtime, scaled by task weight, is the only value charged to task and
  class vruntime.

The running BATCH task may keep its remaining epoch while its projected
vruntime is within `batch_preempt_granularity` of the local DSQ head. If it
falls farther behind, the scheduler caps its residual slice at the remaining
part of `batch_min_run`. This uses the same cap mechanism as class arbitration.

This gives continuously CPU-bound work longer cache-friendly runs, while tasks
that block frequently retain short epochs and prompt weighted-vruntime service.

## Placement and stealing

Wake placement starts from a task's sticky home or previous CPU. Idle CPU
selection uses the kernel topology-aware helper. When all allowed CPUs are
busy, BATCH placement may scan a bounded set of CPUs and compares
capacity-normalized queued service plus the configured LLC or NUMA migration
cost. A migration cooldown prevents immediate bouncing.

Remote dispatch is gated and runs only after the destination has no local
candidate. A source must:

- have queued work in the selected class and at least two runnable tasks;
- have enough load surplus to cover one class service unit and the topology
  migration cost;
- provide a task whose affinity permits the destination;
- pass the task migration cooldown; and
- grant an exclusive per-source steal claim.

Sources are evaluated with same-LLC, same-NUMA, and remote-NUMA costs. The
global class vruntimes select which class an idle CPU tries first, while the
per-CPU class entities remain the dispatch hot path.

## Configuration

Policy options and defaults:

| Option | Default | Meaning |
|---|---:|---|
| `--latency-slice-us` | 1000 | Base LATENCY slice |
| `--latency-burst-us` | 2000 | Maximum service for one LATENCY wakeup |
| `--class-max-debt-us` | 1000 | Maximum normalized LATENCY class lead |
| `--batch-min-epoch-us` | 1000 | Initial and minimum BATCH epoch |
| `--batch-max-epoch-us` | 8000 | Maximum learned BATCH epoch |
| `--batch-round-us` | 16000 | Target upper bound for one local BATCH round |
| `--batch-min-run-us` | 500 | Minimum uninterrupted BATCH service |
| `--batch-preempt-granularity-us` | 500 | Vruntime gap required for a same-class BATCH handoff |
| `--latency-weight` | 200 | LATENCY class share weight |
| `--batch-weight` | 100 | BATCH class share weight |
| `--steal-scan` | 8 | Maximum remote CPU DSQs examined per pull |
| `--same-llc-migration-cost-us` | 250 | Same-LLC movement cost |
| `--same-node-migration-cost-us` | 500 | Same-NUMA movement cost |
| `--remote-node-migration-cost-us` | 1000 | Cross-NUMA movement cost |

The loader enforces these constraints:

- `latency_slice <= latency_burst <= 2 * latency_slice`;
- `batch_min_epoch <= batch_max_epoch <= 8 * batch_min_epoch`;
- `batch_round >= batch_min_epoch`;
- `batch_min_run <= batch_min_epoch`;
- both class weights and `batch_preempt_granularity` are nonzero;
- migration costs are ordered same-LLC <= same-node <= remote-node; and
- `steal_scan` is at most 32.

`--diagnostic-counters` enables detailed arbitration, epoch, placement, and
lifecycle counters. `--track-rule-misses` records unmatched
`comm` values in a bounded map and prints the 32 most frequent values at clean
shutdown. Both are disabled by default to keep the hot path smaller.

Use `--stats SECONDS` to monitor a scheduler launched by this process, or
`--monitor SECONDS` to monitor an already running instance. `--help` lists the
remaining operational and libbpf options.

## Static rules

The rule table is populated after the BPF object is loaded and before the
scheduler is attached. A rule file contains one exact `COMM=CLASS` entry per
line. Blank lines and `#` comments are ignored.

```text
pipewire=latency
wireplumber=latency
ninja=batch
rustc=batch
```

Rules may also be supplied repeatedly with `--rule COMM=CLASS`; command-line
entries override duplicate file entries. `--default-class` selects the class
for unmatched tasks and defaults to `batch`.

Linux `comm` is limited to 15 visible bytes plus a terminating NUL. Matching is
exact, case-sensitive, and uses the current thread name rather than the full
executable path.

## Build and validation

From the repository's `schedule/scx` directory:

```bash
cargo fmt --check --package scx_agent_classed
cargo test --package scx_agent_classed
cargo build --release --package scx_agent_classed
./target/release/scx_agent_classed --help
```

An actual load is required to exercise the BPF verifier and attach path. Run it
on a test machine or VM:

```bash
sudo timeout --signal=INT --kill-after=5s 10s \
  ./target/release/scx_agent_classed \
  --rules scheds/rust/scx_agent_classed/rules.bench \
  --diagnostic-counters \
  --stats 1
```

While it is attached, `/sys/kernel/sched_ext/root/ops` should report
`agent_classed`. After the run, inspect the kernel log for verifier,
`sched_ext`, or scheduler errors:

```bash
sudo journalctl -k --since '-2 min' --no-pager | \
  rg -i 'sched_ext|verifier|scx_agent|BUG|WARNING'
```

Correctness validation should keep `nr_task_state_errors` at zero and verify
that local fallback prevents idle CPU time while runnable work exists. Policy
validation should additionally record class runtime, BATCH epoch distribution,
context switches, migrations, useful throughput, and LATENCY percentiles.
