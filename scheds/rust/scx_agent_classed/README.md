# scx_agent_classed

`scx_agent_classed` is a two-level `sched_ext` scheduler built around two
workload classes and per-class, per-CPU DSQs.

See [DIAGNOSTICS.md](DIAGNOSTICS.md) for the initial Linux 6.18 mixed-workload
slice sweeps, policy A/B tests, perf counters, and ten-run confirmation.

## Scheduling policy

1. A static exact-match table maps Linux `comm` values to `LATENCY` or
   `BATCH`. Unmatched tasks use `BATCH` by default.
2. Every possible CPU owns one vtime-ordered DSQ for each class:
   `DSQ[class][cpu]`.
3. Class selection compares weighted class virtual runtime. With the default
   weights, a continuously runnable LATENCY class receives roughly twice the
   CPU time of a continuously runnable BATCH class. BATCH is therefore not
   starved by LATENCY work.
4. LATENCY uses the `scx_forge` CPU/vruntime policy. Runtime is charged once to
   a canonical weighted task vruntime. A voluntary sleep saves signed virtual
   lag relative to the LATENCY class-local vtime, bounded to one LATENCY slice
   plus 1 ms. Wakeup restores both bounded credit and bounded debt before using
   the canonical vruntime as the DSQ key.
5. LATENCY idle placement uses Forge's wakee policy: prefer an idle CPU starting
   from the task's previous CPU and dispatch directly when possible. `enqueue()`
   repeats idle placement for queued wakeups, re-enqueues, and per-CPU tasks
   whose `select_cpu()` hook was skipped.
6. After class selection, dispatch consumes the preferred class's local CPU DSQ
   first. With `--locality-debt-us 0`, a local miss is followed by remote
   preferred, local other, and remote other service in that order.
7. A non-zero `--locality-debt-us` inserts local-other service before the
   remote-preferred attempt when projected weighted class vruntime keeps the
   preferred class inside the configured debt bound. An atomic in-flight
   reservation prevents multiple CPUs from admitting against the same budget.
   This is a soft admission bound: the admitted task keeps its normal class
   slice, so one BATCH bypass can still run for about 2 ms.
8. On a remote LATENCY attempt, the CPU inspects every LATENCY per-CPU DSQ head
   and pulls the affinity-compatible task with the earliest DSQ vruntime.
   BATCH retains its weighted-vruntime ordering and bounded remote scan.
   `--steal-scan` controls BATCH stealing only; LATENCY scans all CPU DSQ heads.
9. If the preferred class has no movable work, dispatch falls back to the other
   class even when the locality debt gate denied the earlier bypass. This keeps
   the scheduler work-conserving. The default slices are 1 ms for LATENCY and
   2 ms for BATCH.

The Forge-style LATENCY path deliberately has no busy-CPU wakeup preemption,
`SCX_ENQ_HEAD` continuation, or awake-runtime penalty. This keeps all ordinary
LATENCY contenders comparable through one canonical vruntime key. Class
vruntime remains a separate layer, so adopting Forge within LATENCY does not
give that class absolute priority over BATCH.

Class sleeper credit remains bounded. BATCH keeps the original task sleeper
clamp; LATENCY uses signed bounded lag so a task that sleeps after consuming
service preserves debt rather than being reset to the current minimum.

The compatibility options `--latency-burst-us`, `--class-max-debt-us`,
`--batch-min-run-us`, and `--no-awake-vruntime` are still accepted so existing
bench configurations and scripts do not fail, but they no longer affect the
Forge-style LATENCY policy. Their legacy preemption, guard, and continuation
statistics remain zero. They can be removed after downstream configurations
stop passing them.

The remote-head scan inherits two Forge constraints. Its cost is O(number of
possible CPUs) after a local miss, and an affinity-incompatible DSQ head hides
compatible tasks behind it until the head moves. Production deployment on a
large or multi-LLC system should add topology and load-gap stealing limits.

The initial locality-debt experiment did not improve effective locality. On
the two-vCPU mixed workload, local-other bypasses were almost entirely BATCH
and retained the full BATCH slice. Total migrations sometimes fell because the
LATENCY workload completed less work, while migrations per completed request
rose. Keep `--locality-debt-us 0` as the reference behavior; see
[DIAGNOSTICS.md](DIAGNOSTICS.md#bounded-locality-debt-experiment) for the sweep,
topology confirmation, fixed-rate control, and diagnostic counters.

`--track-rule-misses` records unmatched `comm` values in a bounded map and
prints the 32 most frequent values during a clean shutdown. It is disabled by
default so unmatched system tasks do not add a map update to the hot path.
`--diagnostic-counters` similarly enables detailed placement, locality-debt,
LATENCY wakeup, requeue, and stopping counters that are otherwise left
disabled.

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

Rules can also be supplied repeatedly on the command line. Command-line rules
override duplicate entries from the file.

`rules.bench` contains the fixed hackbench, schbench, and stress-ng mappings
used by the initial VM feasibility experiments.

```bash
sudo ./scx_agent_classed \
  --rules rules.example \
  --rule my_server=latency \
  --latency-weight 200 \
  --batch-weight 100 \
  --stats 1
```

Linux `comm` is limited to 15 visible bytes plus a terminating NUL. Matching is
exact, case-sensitive, and based on the current thread name rather than the
full executable path.

The map is intentionally static for this first version. A future control plane
can update the same BPF map and add a generation counter so already-running
tasks are reclassified without paying for a hash lookup on every re-enqueue.
