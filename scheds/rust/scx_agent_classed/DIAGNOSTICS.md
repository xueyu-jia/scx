# Mixed-workload diagnostics

> **Superseded historical evidence:** this document records experiments across
> several retired implementations and preserves their original terminology and
> results. It is not the current policy contract. See [`README.md`](README.md)
> for the active scheduler architecture and configuration.

This document records the initial diagnosis of `scx_agent_classed` on Linux
6.18.0. It is evidence for policy development, not a production benchmark.

## Setup

- One VM with 2 vCPUs pinned to host CPUs 2-3.
- Two `stress-ng-cpu` workers saturating the VM.
- One schbench message thread and one worker for 10 seconds.
- Exact rules: `schbench=latency`, `stress-ng*=batch`.
- Alternating default/candidate order, with a fresh VM for every sample.
- Default class weights: LATENCY 200, BATCH 100.

## Slice sweeps

The BATCH sweep kept the LATENCY slice at 1 ms. Each row has two candidate
and two contemporaneous default samples.

| BATCH slice | Request p99 vs default | Request p999 | BATCH throughput | schbench RPS |
|---|---:|---:|---:|---:|
| 0.5 ms | -24.56% | -33.13% | -10.15% | +29.62% |
| 1 ms | +1.75% | +0.40% | -1.43% | -4.66% |
| 2 ms | +2.37% | +0.90% | +2.97% | -10.00% |

The transition is not linear: 0.5 ms crosses a latency threshold, while 1 ms
and 2 ms produce similar request p90 distributions. The 0.5 ms setting pays
for that improvement with more BATCH disruption.

The LATENCY sweep kept the BATCH slice at 2 ms.

| LATENCY slice | Request p99 vs default | Request p999 | BATCH throughput | schbench RPS |
|---|---:|---:|---:|---:|
| 1 ms | +2.37% | +0.90% | +2.97% | -10.00% |
| 2 ms | -11.11% | -13.98% | -2.62% | +15.08% |
| 4 ms | -48.25% | -48.10% | -18.29% | +60.69% |

The workload is closed-loop: faster requests cause schbench to issue more
work. The BATCH loss at 4 ms is therefore a combination of longer LATENCY
service and higher LATENCY demand, not just scheduler overhead.

## Path counters

With 1 ms LATENCY / 2 ms BATCH slices, active one-second intervals showed:

- 388-431 LATENCY wakeups per second.
- Every observed wakeup passed class eligibility and preempted successfully.
- Zero ineligible wakeups and zero preempt insertion failures.
- 309-335 non-wakeup LATENCY enqueues per second.
- Non-wakeup enqueues, runnable stops, and zero-slice stops matched almost
  exactly, identifying slice expiration as the requeue source.
- No idle direct dispatches because both vCPUs were saturated.

Thus the class eligibility condition is not limiting this workload. The main
delay is after the initial successful wakeup preemption.

## Policy A/B tests

Disabling `awake_vruntime` while leaving all other settings unchanged had no
meaningful effect over two direct paired runs: request p99 was unchanged,
p999 changed by +0.05%, BATCH by -0.41%, and schbench RPS by -0.31%.

Disabling stealing was harmful. LATENCY runtime fell from about 0.58 CPU to
0.43 CPU, request p99 increased by 24.62%, and schbench RPS fell by 26.46%.
BATCH throughput increased by 8.17%. Remote pulls are therefore necessary for
work conservation with the current enqueue placement.

## Scheduling overhead and placement

Two system-wide perf samples for the original 1 ms LATENCY setting measured:

| Metric | Default mean | SCX mean | Change |
|---|---:|---:|---:|
| Context switches | 11,946.5 | 14,240.5 | +19.20% |
| CPU migrations | 152 | 3,535 | 23.26x |

For the 2 ms LATENCY candidate, context switches were 26.06% above default
and migrations were 27.04x default. Its higher completed request count raises
the totals, but approximately two migrations per completed request remain.
The migration count is also close to the accumulated remote-dispatch count,
strongly linking the overhead to per-CPU DSQ placement and stealing.

The bounded rule-miss map found system, kernel, benchmark harness, and
scheduler processes. It did not find `schbench`, `stress-ng`, or
`stress-ng-cpu`, so missing exact `comm` rules did not break the measured
request path.

## Ten-run confirmation

The balanced candidate (2 ms LATENCY, 2 ms BATCH) was compared with default
for 10 alternating pairs. All 20 runs passed with no IRQ contamination or
scheduler errors. The confidence interval is an approximate paired 95% t
interval over per-pair percentage changes.

| Metric | Default mean | Candidate mean | Paired change |
|---|---:|---:|---:|
| Request p50 | 5,675.2 us | 5,828.8 us | +2.71% +/- 3.85% |
| Request p90 | 5,864.0 us | 6,814.4 us | +16.21% +/- 0.22% |
| Request p99 | 7,796.8 us | 6,931.2 us | -11.10% +/- 0.28% |
| Request p999 | 8,175.2 us | 7,035.2 us | -13.88% +/- 1.63% |
| Wakeup p99 | 2,396.8 us | 4.7 us | -99.80% +/- 0.01% |
| BATCH throughput | 2,828.43 | 2,763.82 | -2.28% +/- 1.42% |
| schbench RPS | 164.79 | 180.69 | +9.74% +/- 4.71% |

The 2/2 ms setting improves the request tail and wakeup latency at a modest
BATCH cost, but its stable p90 regression shows that it is not a complete
solution.

## Bounded continuation and class debt

The follow-up policy kept the 1 ms LATENCY and 2 ms BATCH base slices and
added:

- a 2 ms maximum privileged CPU budget per LATENCY wakeup;
- at most one 1 ms continuation;
- a 500 us normalized class-vruntime debt limit;
- a 500 us minimum uninterrupted BATCH service window.

Projected LATENCY runtime is atomically reserved before debt-controlled direct
dispatch. This prevents concurrent CPUs from independently passing the debt
test and collectively overshooting the limit. Actual runtime replaces the
reservation when `stopping()` charges class vruntime.

The first BATCH guard implementation only declined immediate preemption. A
wakeup inside the first 500 us then waited for the original 2 ms BATCH slice,
causing request p99 and p999 regressions of 55.85% and 57.62%. Shortening the
remote task's remaining slice reduced but did not eliminate the delay because
Linux 6.18 does not reprogram the high-resolution tick after that remote
update. A per-CPU one-shot BPF timer now kicks at the exact protection
boundary. Two-run samples then placed wakeup p90, p99, and p999 at about 504,
505, and 507 us.

Class eligibility alone was not selective enough for continuation. With the
BATCH guard reduced to 1 us, unconditional continuation still regressed
request p99 by 24.30%, while disabling continuation produced no meaningful
change: p99 +5.07%, p999 +9.91%, and BATCH throughput +0.28%. Diagnostics
showed zero wakeup debt denials and zero continuation debt denials, proving the
regression was a coarse run-then-repay cycle rather than an overly strict debt
limit.

The final continuation gate also requires the task's previous completed wake
burst to be in `(1 ms, 2 ms]`. This targets work likely to complete in the
extra slice and sends known long bursts back through normal class arbitration.
The original five-operation schbench workload was consistently history-denied;
a two-operation variant admitted roughly 200-270 continuations per active
second after its first learning sample.

The final default policy was compared with the pre-continuation scheduler for
two alternating pairs:

| Metric | Pre-continuation mean | Final policy mean | Change |
|---|---:|---:|---:|
| Request p99 | 7,952 us | 8,256 us | +3.82% |
| Request p999 | 8,072 us | 8,592 us | +6.44% |
| Request p90 | 7,832 us | 8,176 us | +4.39% |
| Wakeup p99 | 5 us | 505.5 us | configured BATCH guard cost |
| BATCH throughput | 2,881.52 | 2,979.68 | +3.41% |
| schbench RPS | 160.99 | 144.50 | -10.25% |

The benchmark classified the three primary metrics (request p99, request
p999, and BATCH throughput) as `no_change`. Two samples establish feasibility
and expose large regressions, but they are not enough for a confidence claim.

The same final policy was also compared directly with the Linux default
scheduler for two alternating pairs. Request p99 changed by +6.39%, request
p999 by -7.60%, and BATCH throughput by +5.27%; all three primary metrics were
classified as `no_change`. Wakeup p99 improved from about 2.39 ms to 506 us.
The tradeoff remains visible at request p90 (+40.01%) and closed-loop
schbench RPS (-14.63%), making the 250-500 us BATCH protection range an
important target for a larger tuning experiment.

## Single-class isolation tests

Two-run alternating feasibility tests then removed application-level
LATENCY/BATCH overlap. The VM still used two vCPUs pinned to SMT siblings.
These samples are directional diagnostics, not confidence results.

The BATCH-only test ran four `stress-ng --cpu` workers for 30 seconds. The
default/alternate-default control differed by only +0.28% using stress-ng's
reported real-time rate. One SCX sample exposed an inconsistent clock domain:
stress-ng reported 33.53 seconds while the wrapper's monotonic interval was
30.14 seconds. Using completed bogo operations divided by the common wrapper
interval avoids that false regression:

| BATCH metric | Default mean | SCX mean | Change |
|---|---:|---:|---:|
| Wrapper-wall throughput | 3,545.10 | 3,580.15 | +0.99% |
| CPU-time throughput | 1,789.42 | 1,796.28 | +0.38% |

Thus the earlier double-digit hackbench improvement does not generalize to
sustained CPU work; the BATCH-only result is currently no meaningful change.

The LATENCY-only test used `schbench -m 1 -t 4 -n 5 -r 30`. A dedicated
scheduler configuration assigned unmatched guest tasks to LATENCY too, so no
BATCH debt, guard, or class-share decision was active. The corresponding
default/alternate-default control changed request p99 by +0.11%, wakeup p99 by
+0.35%, and average RPS by +1.27%.

| LATENCY metric | Default mean | SCX mean | Change |
|---|---:|---:|---:|
| Request p50 | 12,000 us | 12,960 us | +8.00% |
| Request p90 | 13,792 us | 14,016 us | +1.62% |
| Request p99 | 14,896 us | 15,344 us | +3.01% |
| Request p999 | 18,272 us | 17,856 us | -2.28% |
| Wakeup p90 | 592 us | 1,636 us | +176.35% |
| Wakeup p99 | 2,260 us | 1,964 us | -13.10% |
| Wakeup p999 | 2,400 us | 2,728 us | +13.67% |
| Average RPS | 328.12 | 294.95 | -10.11% |

Both pairs showed the same RPS direction (-10.81% and -9.39%). This rules out
the hypothesis that cross-class capacity tradeoffs alone explain the mixed
workload result. Under same-class contention, direct wakeup preemption and
per-CPU queue ordering improve one tail point while worsening median service,
wakeup p90/p999, and completed work. Task-level eligibility and placement must
be isolated before further class-weight tuning.

## Conclusions

1. The original 1 ms LATENCY slice is too short for this request's CPU burst.
2. The wakeup eligibility gate works and is not the current bottleneck.
3. `awake_vruntime` is not material for this one-worker workload.
4. Stealing must remain until enqueue placement becomes work-conserving on its
   own, but the resulting migration rate is a primary optimization target.
5. A bounded LATENCY continuation must combine class debt eligibility with a
   task-level completion signal. Class eligibility alone grants long bursts a
   coarse 2 ms run followed by a repayment window and regresses this workload.
6. Future latency comparisons should use a fixed offered request rate as well
   as closed-loop schbench, so policy efficiency is separated from demand
   amplification.
7. Single-class tests show no sustained BATCH throughput gain and a repeatable
   LATENCY throughput regression under intra-class contention. Cross-class
   arbitration is therefore not the only current bottleneck.

## scx_forge comparison

On 2026-07-14, `scx_forge` was tested on the same 2-vCPU VM with two
alternating pairs per comparison. Fresh default/alternate-default controls and
all 44 default/Forge functional and perf runs passed without IRQ contamination,
scheduler errors, or kernel warnings. Together, the controls and comparisons
produced 56 valid runs.

The tested Forge policies were:

- `global`: 1 ms, global DSQ, weighted vruntime, wakee placement, no preemption;
- `cpu`: 1 ms, per-CPU DSQs, weighted vruntime, no preemption;
- `latency`: 1 ms, per-CPU DSQs, deadline ordering and eligible preemption;
- `batch`: 2 ms, per-CPU DSQs and weighted vruntime.

The CLI default is `global`, despite the Forge README describing CPU-local
queueing as the default policy. The kernel also has `CONFIG_IKCONFIG` disabled,
so the matching Linux 6.18 `.config` had to be supplied through Forge's
`--kconfig` option for `CONFIG_PREEMPT_RCU` relocation.

The fresh controls exposed substantial LATENCY p999 noise: default versus its
alias changed request p99 by +1.75%, p999 by +35.12%, and reported throughput
by -3.51%. BATCH throughput changed by +1.93%. MIX was more stable at p99
-0.31%, p999 -9.56%, and BATCH throughput +1.28%. The following two-run means
are therefore directional, especially at p999.

### Single-class results

schbench throughput below uses the final `average rps`, not the last one-second
`current rps` sample emitted by the older guest wrapper.

| Forge policy | Request p50 | Request p90 | Request p99 | Request p999 | Average RPS |
|---|---:|---:|---:|---:|---:|
| global | -43.06% | +6.17% | +78.45% | +86.46% | +27.55% |
| cpu | -42.73% | -20.23% | +6.03% | +12.80% | +43.31% |
| latency | -45.93% | -9.71% | +9.67% | +33.40% | +38.31% |

All Forge policies completed much more closed-loop work and greatly improved
request p50. CPU-local queueing also improved p90. None improved request p99:
the CPU policy regressed it by 6.03%, while deadline plus eligible preemption
regressed it by 9.67%. The latter did not remove the 1 ms wakeup floor: wakeup
p50 remained 1,001 us in both LATENCY-only samples. It mainly reduced wakeup
p99 relative to CPU vruntime, from 3,148 us to 2,159 us.

| Forge BATCH policy | Wall throughput | CPU-time throughput |
|---|---:|---:|
| global, 1 ms | -4.76% | -4.62% |
| cpu, 1 ms | -0.97% | -2.55% |
| cpu, 2 ms | -2.77% | -2.39% |

Per-CPU placement removed the clear global-DSQ BATCH regression, but neither a
1 ms nor 2 ms slice demonstrated a throughput gain over EEVDF.

### Mixed results

| Forge policy | Request p90 | Request p99 | Average RPS | BATCH throughput |
|---|---:|---:|---:|---:|
| global | +29.37% | -0.21% | -10.31% | +4.27% |
| cpu | +30.74% | -0.10% | -24.09% | +8.80% |
| latency | +29.88% | -0.72% | -17.13% | +5.15% |

All three policies kept request p99 approximately unchanged and increased
BATCH throughput, but they also shifted the request distribution: request p90
regressed by about 30% and completed request rate fell by 10-24%. Deadline
ordering and eligible preemption did not solve this tradeoff because Forge has
no workload classes and applies one request/slice policy to both applications.

Perf runs linked the global result to placement:

| MIX metric | Default | Forge global | Forge CPU |
|---|---:|---:|---:|
| Context switches | 11,867 | 11,990 (+1.04%) | 11,164 (-6.41%) |
| CPU migrations | 161.5 | 6,782 (42.0x) | 4,245.5 (26.7x) |

Per-CPU DSQs reduced Forge migrations by 37.4% relative to its global DSQ, but
aggressive local-empty stealing still migrated far more often than EEVDF. This
supports a topology-aware local-first design, but not the conclusion that
per-CPU sharding alone reproduces CFS locality.

The Forge experiment changes the redesign judgment in one useful way: its
canonical vruntime and bounded-lag core is a better starting point for median
service and work completion than the current LATENCY core. It should not be
adopted wholesale. The target design still needs class-aware arbitration,
bounded locality debt, less aggressive stealing, and a tail-oriented request
policy that does not turn higher completion rate into p99 regressions.

## Forge CPU/vruntime port into LATENCY

On 2026-07-14, the Forge CPU/vruntime core was moved into the LATENCY class
while the static classifier, weighted class-vruntime arbitration, and BATCH
policy were retained. The port includes canonical task vruntime, signed bounded
sleep lag, wakee idle placement, enqueue-side direct-dispatch retry, local-first
per-CPU dispatch, and earliest-head remote pulling. The old awake-vruntime
penalty, busy-CPU wakeup preemption, and continuation head insertion are no
longer on the LATENCY path.

The pre-port binary was saved before rebuilding. Six two-pair alternating
experiments produced 24 PASS runs. Every staged scheduler loaded with the Linux
6.18 Kconfig, attached successfully, and unregistered normally. Candidate
`dmesg.diff` files were empty and no libvirt domains remained afterward.

### Pre-port versus ported LATENCY

The single-class comparison assigned all guest tasks to LATENCY so class
arbitration could not hide the queue-policy effect.

| LATENCY-only metric | Pre-port | Ported | Change |
|---|---:|---:|---:|
| Request p50 | 298.5 us | 462.0 us | +54.77% |
| Request p90 | 312.0 us | 468.5 us | +50.16% |
| Request p99 | 16,872 us | 15,408 us | -8.68% |
| Request p999 | 20,192 us | 19,552 us | -3.17% |
| Average RPS | 299.48 | 462.50 | +54.43% |

The port removes the old implementation's completion-rate regression and
improves p99, but shifts p50/p90 upward. Closed-loop schbench therefore exposes
a throughput/distribution tradeoff rather than a uniform latency win.

The mixed perf run showed the clearest changes relative to the pre-port build:

| MIX perf metric | Pre-port | Ported | Change |
|---|---:|---:|---:|
| Request p90 | 8,196 us | 7,176 us | -12.45% |
| Request p99 | 8,272 us | 7,368 us | -10.93% |
| Request p999 | 8,560 us | 8,652 us | +1.07% |
| LATENCY average RPS | 145.49 | 150.87 | +3.70% |
| BATCH throughput | 2,954.48 | 2,933.10 | -0.72% |
| Wakeup p99 | 506 us | 3 us | -99.41% |
| Wakeup p999 | 1,939.5 us | 3.5 us | -99.82% |
| Context switches | 13,533.5 | 10,454.5 | -22.75% |
| CPU migrations | 6,896.5 | 5,248.5 | -23.90% |

The non-perf mixed run had the same wakeup and p90 direction, but request p99
changed by only -1.50%. With only two pairs, the exact request-tail magnitude
is directional; the roughly 99% wakeup-tail reduction and 24% migration
reduction are the more consistent mechanism signals. BATCH-only throughput was
3.28% higher in this run, with substantial candidate variance, so it establishes
no regression but should not be attributed to the LATENCY change.

### Ported LATENCY versus EEVDF

| LATENCY-only metric | Default | Ported | Change |
|---|---:|---:|---:|
| Request p50 | 328.0 us | 462.5 us | +41.01% |
| Request p90 | 337.0 us | 477.0 us | +41.54% |
| Request p99 | 14,848 us | 15,360 us | +3.45% |
| Request p999 | 17,600 us | 18,944 us | +7.64% |
| Average RPS | 333.48 | 458.94 | +37.62% |

Against EEVDF, the port completes substantially more closed-loop work, but it
does not improve the latency distribution. Request p99/p999 remain within the
current no-change threshold while p50/p90 regress materially.

| MIX perf metric | Default | Ported | Change |
|---|---:|---:|---:|
| Request p50 | 5,584 us | 6,984 us | +25.07% |
| Request p90 | 5,856 us | 7,168 us | +22.40% |
| Request p99 | 7,688 us | 7,360 us | -4.27% |
| Request p999 | 8,064 us | 7,896 us | -2.08% |
| LATENCY average RPS | 174.49 | 153.30 | -12.15% |
| BATCH throughput | 2,828.04 | 2,939.00 | +3.92% |
| Context switches | 12,042.5 | 10,414.0 | -13.52% |
| CPU migrations | 158.5 | 5,190.0 | +3,174.45% |

The ported class scheduler has about 24% fewer migrations than its predecessor,
but still migrates 32.7 times as often as EEVDF. The remaining problem is above
the LATENCY queue policy: dispatch selects a globally preferred class and may
pull that class remotely before consuming the other local class. The next
placement experiment should compare local-other-class service against remote
preferred-class service using bounded locality debt, then add same-LLC,
load-gap, and migration-budget gates. This has higher expected value than
adding another LATENCY ordering heuristic.

## Bounded locality-debt experiment

The next experiment isolated the dispatch-order part of that proposal. Task
vruntime, class weights, and slices stayed unchanged. The reference behavior
used `--locality-debt-us 0`:

```text
local preferred -> remote preferred -> local other -> remote other
```

For a non-zero limit, a CPU may consume local work from the other class before
pulling the preferred class remotely. Admission uses projected weighted class
vruntime:

```text
projected(class) = class.vruntime + class.locality_reserved_vruntime
preferred debt = max(0, projected(other) - projected(preferred))
```

An atomic reservation for one normal class slice serializes concurrent
admissions. `stopping()` replaces the reservation with actual charged runtime;
failed moves, dequeue, quiescence, class changes, and scheduler shutdown release
it. This deliberately keeps the original task slice, so the configured debt is
a soft admission threshold rather than a hard runtime cap. A permitted BATCH
task may still consume its full 2 ms slice.

### SMT threshold sweep

The first screen used one pair per threshold on two vCPUs pinned to the same
physical core's SMT siblings. Request rate below was reconstructed from
schbench's final raw output. The base image still contained an older wrapper
that stored the first `current rps` value in the generated comparison report,
even though the host-side parser now prefers final `average rps`. Refresh the
base image or stage the wrappers before a larger confirmation run.

| Debt limit | Total migrations | Migrations/request | Average RPS | Request p50 | Request p90 | BATCH throughput |
|---|---:|---:|---:|---:|---:|---:|
| 250 us | -6.94% | +2.55% | -9.25% | +2.75% | +6.69% | +3.14% |
| 500 us | -0.62% | +10.43% | -10.00% | +3.67% | +6.69% | +2.05% |
| 1000 us | -0.32% | +11.51% | -10.60% | +3.21% | +7.15% | +4.27% |

All three thresholds shifted service toward BATCH and away from LATENCY. The
250 us candidate was selected only because its unnormalized migration total
fell the most. Its completed requests fell by 9.25%, more than its migrations,
so even that screening sample had worse migrations per request.

### Topology confirmation

The 250 us candidate then ran for two alternating pairs on each topology.
`small_smt` used host CPUs 2 and 3, the two threads of one physical core.
`small_core` used CPUs 2 and 4, one thread from each of two physical cores in
the same LLC. All eight runs passed without scheduler, dmesg, IRQ, or staging
errors.

| Topology metric | Reference | 250 us | Change |
|---|---:|---:|---:|
| SMT migrations | 5,243 | 5,009 | -4.46% |
| SMT migrations/request | 3.5023 | 3.6994 | +5.63% |
| SMT average RPS | 149.70 | 135.40 | -9.55% |
| SMT request p50 | 6,984 us | 7,168 us | +2.63% |
| SMT request p90 | 7,160 us | 7,656 us | +6.93% |
| SMT request p99 | 7,328 us | 7,728 us | +5.46% |
| SMT wakeup p999 | 4 us | 1,501.5 us | discrete 1-2 ms stalls |
| SMT BATCH throughput | 2,944.06 | 3,006.77 | +2.13% |
| Separate-core migrations | 5,956 | 6,038 | +1.38% |
| Separate-core migrations/request | 2.1717 | 2.1932 | +0.99% |
| Separate-core average RPS | 274.25 | 275.30 | +0.38% |

On SMT, migration rate per perf enabled time fell by 6.42%, but completed work
fell more. Both alternating pairs independently regressed RPS and request
latency, so the result did not depend on execution order. On separate physical
cores, the latency and throughput changes were near measurement granularity and
migrations rose. The experiment therefore does not demonstrate useful
locality on either topology.

### Mechanism counters

A diagnostic run of the 250 us candidate collected 19 one-second samples. Its
reservation accounting was internally consistent:

- 592 local-other bypasses: 1 LATENCY and 591 BATCH;
- 1,281.24 ms of BATCH bypass runtime, or about 2,167.9 us per admission;
- 784 debt denials, followed by 771 successful remote-preferred dispatches;
- 13 work-conserving local-other fallbacks after a debt denial and failed
  remote-preferred attempt;
- zero reservation rollback or accounting errors;
- maximum sampled reservation of one 2 ms BATCH slice and a final reservation
  of zero for both classes;
- maximum admission overshoot of 2.00 ms and maximum observed pre-admission
  debt of 10.77 ms.

The high pre-admission debt can also include service from work-conserving
fallbacks; it is not all caused by successful bypass admissions. The important
mechanism signal is that almost every bypass served BATCH for approximately a
full BATCH quantum. A 250 us threshold did not create a 250 us service bound.

### Fixed offered work

A final single-pair control used `schbench -R 100`. An initial run that also
requested hardware PMU events was discarded: KVM returned zero for those
events and logged unchecked PMU MSR accesses. The clean rerun collected only
context switches and migrations; both `dmesg.diff` files were empty.

The same nominal rate did not produce exactly equal completed work. The
reference received an extra endpoint burst and completed 3,100 requests
(`average rps: 103.33`), while the candidate completed 3,000 (`average rps:
100.00`). Migrations are therefore shown both as totals and per completed
request.

| Fixed-rate metric | Reference | 250 us | Change |
|---|---:|---:|---:|
| Completed requests | 3,100 | 3,000 | -3.23% |
| CPU migrations | 8,876 | 10,121 | +14.03% |
| Migrations/request | 2.8632 | 3.3737 | +17.83% |
| Context switches | 15,431 | 19,848 | +28.62% |
| Request p50 | 7,000 us | 7,112 us | +1.60% |
| Request p90 | 7,192 us | 8,272 us | +15.02% |
| Request p99 | 7,656 us | 10,192 us | +33.12% |
| Request p999 | 7,912 us | 10,576 us | +33.67% |
| BATCH throughput | 3,082.01 | 3,116.65 | +1.12% |

The candidate also recorded a 168.6 ms wakeup outlier among only 30 wakeup
samples. One run is too sparse to treat that event as a stable tail estimate.

This schbench mode submits a burst once per second and its request statistic
does not include all arrival-side queueing, so it is not a general open-loop
latency result. Its endpoint accounting also prevents treating this as a
strictly equal-completed-work test. It remains useful as a fixed-target-rate
diagnostic: migration per completed request did not improve.

The bounded locality-debt experiment falsifies the simple cross-class bypass
for this workload. It does not show that migration is harmless; it shows that
changing locality and class service order together costs more than the saved
remote pulls. Further locality tests should keep the preferred class ordering
unchanged and vary only same-class placement: previous-CPU reuse,
same-LLC-first stealing, a load-gap threshold, and a migration budget. A hard
local-other slice cap may be tested separately, because shortening the bypass
quantum changes both locality and preemption frequency.

## Other scheds mechanisms worth testing

A source and history audit found useful local mechanisms, but no current-HEAD
cross-scheduler benchmark suite. The numbers below are author experiments from
historical commits or case studies and are evidence for an A/B direction, not
performance promises for this VM.

| Source | Quantified evidence | Relevant mechanism |
|---|---|---|
| LAVD `31938c0f` | On a 176-CPU AMD system near saturation, per-CPU versus per-LLC DSQs improved schbench m32 RPS 38.5%, p99 22.4%, and p999 33.1%. At m88, RPS and p999 improved while raw p99 regressed 52.8%. | Per-CPU queues can improve throughput and extreme tail while moving another percentile backward. |
| LAVD `c3ef934f` | Forced stealing raised average dispatch cost from 762 ns to 3,593 ns and BPF CPU from 40.87% to 250.99%. Remote consume mean/p99 was 2,216.6/13,023.5 ns versus 595.9/6,900 ns locally. | Gate stealing by load gap, topology distance, and a migration budget. |
| Flash `96474b5c` | Reusing the previous CPU improved the reported MySQL read/write result by 20-25%. | Keep cache-hot work local; only continue current when projected vruntime remains earlier than the queue head. |
| Layered case study | Shared work conservation plus full-idle-core selection improved a production p99-constrained service by about 3.5%; confinement and critical-thread preemption brought the total above 5%. | Per-class/per-LLC DSQs, cross-LLC queued-runtime thresholds, and a NUMA migration token budget. |
| P2DQ `5dfc5bfa` | Caching a node cpumask changed one schbench wakeup p99 from 200 to 23 us, request p99 from 8,784 to 7,352 us, and RPS from 4,245.47 to 4,384.33. | BPF hot-path map and cpumask operations can materially pollute tail latency. |

The recommended order after the current port is:

1. Add Flash-style previous-CPU reuse and projected-vruntime keep-running as an
   isolated A/B.
2. Replace unconditional remote pulls with LAVD-style same-LLC-first stealing,
   a load-difference threshold, and a per-round migration budget.
3. Compare per-logical-CPU DSQs with one DSQ shared by SMT siblings.
4. Test Layered-style per-class/per-LLC fallback on a multi-LLC host.
5. Only then test queue-pressure sleeper-credit decay. Rusty/LAVD criticality
   and P2DQ's complete pick-two policy would add a second classifier inside the
   already explicit LATENCY class and should remain lower priority.

## Adaptive BATCH epoch experiment

An optional per-task BATCH epoch was added on 2026-07-15 without changing the
per-CPU vruntime DSQs or class arbitration. The base BATCH slice remains 2 ms.
With `--batch-max-epoch-us=8000`, a task which repeatedly consumes its complete
grant grows through 2, 4, and 8 ms. Leaving the option unset, or setting it to
2 ms, disables growth.

Growth requires a zero remaining slice and at least seven eighths of the grant
to have executed. It is admitted only while BATCH remains the selected class
and the task's projected vruntime does not pass the local BATCH DSQ head.
Sleep, early stop, migration, remote dispatch, class change, or local LATENCY
activity resets the task to 2 ms. A LATENCY enqueue also invalidates the CPU's
BATCH generation and shortens a running long segment to the next base-slice
boundary. The dispatch reservation is shortened by the same amount, so class
vruntime accounts for the dynamic grant rather than assuming a 2 ms slice.

Reservation extension, LATENCY revocation, and `stopping()` release share a
four-state claim protocol with explicit locked and releasing states. A pending
revocation survives claim contention and prevents another long continuation.
The BATCH-only and MIX diagnostic smoke experiments both passed. They observed
long-epoch dispatches, and the MIX run observed LATENCY-triggered revocation.
Both finished with zero dispatch-reservation and task-state errors.

The formal control and adaptive configurations used the same frozen binary:

```text
cf91ddb8a77d9188124d7208fd7062c48e39cd87e7babf654ca52610f5ae9dce
```

Only `--batch-max-epoch-us` differed: 2 ms for the control and 8 ms for the
candidate. This isolates the epoch policy from the reservation-state refactor.

### Single-BATCH result

The single-class experiment used a two-vCPU `small_core` VM pinned to host CPUs
2 and 4, four continuously runnable `stress-ng --cpu` workers, a five-second
workload warmup, and a 30-second measurement. Eight alternating pairs completed
with all 16 runs passing.

| Metric | Fixed 2 ms mean | Adaptive 2-8 ms mean | Mean paired change | Paired 95% CI |
|---|---:|---:|---:|---:|
| BATCH throughput | 4,875.09 | 4,855.12 | -0.408% | [-0.940%, +0.125%] |
| Context switches / 30 s | 22,528.88 | 6,280.38 | -72.077% | [-81.804%, -62.349%] |
| CPU migrations / 30 s | 13.13 | 13.50 | +5.128% | [-15.661%, +25.917%] |

The adaptive policy clearly exercised its intended mechanism but did not
increase useful work. Removing about 72% of task switches was insufficient to
improve this CPU-only stress workload, so switching frequency is not its
dominant throughput bottleneck.

### Fixed-RPS MIX result

The MIX experiment used the same separate-core VM placement, two BATCH workers,
and `schbench -R 100`. A real five-second MIX warmup preceded each 30-second
measurement. Eight alternating pairs completed with all 16 runs passing.

| Metric | Fixed 2 ms mean | Adaptive 2-8 ms mean | Mean paired change | Paired 95% CI |
|---|---:|---:|---:|---:|
| BATCH throughput | 4,377.67 | 4,406.56 | +0.686% | [-1.263%, +2.635%] |
| Request p50 | 3,004 us | 3,004 us | 0.000% | [0.000%, 0.000%] |
| Request p90 | 3,004 us | 3,004 us | 0.000% | [0.000%, 0.000%] |
| Request p99 | 3,010 us | 3,131 us | +4.028% | [-5.768%, +13.824%] |
| Request p999 | 3,423.5 us | 3,533.5 us | +9.718% | [-25.452%, +44.888%] |
| Context switches / 30 s | 7,872.88 | 7,897.12 | +0.403% | [-3.127%, +3.933%] |
| CPU migrations / 30 s | 12.13 | 11.88 | +10.049% | [-29.043%, +49.141%] |

The change column averages the percentage change of each pair; it is not the
ratio of the two displayed group means. This distinction is especially visible
for migrations because each run contains only 7-19 events. The absolute paired
change was -0.25 migration per measurement and is also statistically
indistinguishable from zero.

All measurement commands requested exactly 100 RPS. Three pairs crossed a
schbench reporting boundary: adaptive runs 4 and 5 counted 3,100 requests,
while control run 7 counted 3,099; their partners counted 3,000. Restricting
the sensitivity analysis to the five equal-count pairs produced BATCH
throughput `+0.991%`, 95% CI `[-1.968%, +3.951%]`. Request p50 and p90 remained
unchanged, while the p99 and p999 intervals still crossed zero. The conclusion
therefore does not depend on treating a boundary burst as scheduler throughput.

Rare histogram-bucket jumps were not directional. Candidate p999 reached about
6 ms in pair 7, while control p999 reached about 6 ms in pair 8. One candidate
p99 reached about 4 ms. The large paired intervals reflect these sparse events;
they do not establish an adaptive-epoch tail regression. Final wakeup samples
near 700-800 ms were scheduler teardown artifacts and were excluded from the
request-latency pairing.

Unlike the single-BATCH experiment, MIX showed no context-switch reduction.
Frequent LATENCY activity intentionally invalidates long BATCH epochs, so the
candidate usually returns to the 2 ms base path when latency protection matters.
The policy therefore behaves as a guardrailed optimization, but this workload
shows neither a statistically supported throughput gain nor a latency gain.
The 8 ms maximum must remain opt-in and should not replace the 2 ms default.

The next useful epoch experiment needs cache-sensitive work with job structure,
such as builds, compression, or encoding, and should collect cycles,
instructions, LLC/TLB misses, epoch transitions, and dispatch cost. If those
workloads also show no paired throughput gain, further epoch lengthening should
stop in favor of simplifying the pure-BATCH dispatch hot path.

## Superseded burst-adaptive EEVDF experiment

The epoch experiment above is retained as historical evidence. A later
prototype replaced that mechanism with eligible and future BATCH priority DSQs
ordered by request deadline and virtual start. That prototype, its promotion
state, and its reservation state have been removed from the current scheduler.

The canonical adaptive defaults use 1, 2, 4, and 8 ms request levels, a 16 ms
queue-round cap, bounded sleep lag, and earlier-deadline same-class wakeup
preemption. Fixed-request experiment configurations override these defaults.
Request exhaustion must pass through `stopping()` and re-enqueue before a new
request is created, so the dispatch reservation never spans two requests.

It was a discrete SCX approximation rather than Linux EEVDF. The frozen binary
and results above remain only as controls for the historical experiments.

## Final unified-arbiter validation

The final failure was not a debt parameter or timer problem. A task inserted
from `enqueue()` is not visible through `scx_bpf_dsq_nr_queued()` until the
callback returns. The wakeup path collected candidates from visible DSQs only,
so a newly arriving LATENCY task was omitted and a running BATCH task could
retain its learned 8 ms epoch. Explicitly adding the incoming class to the same
`decide_class()` candidate mask fixed the issue without a second policy path.

A four-pair production run used a two-vCPU SMT VM, two saturated BATCH workers,
`schbench -R 100 -n 5`, a five-second real MIX warmup, and 30-second
measurements. All eight runs passed.

| Metric | alt_default mean | scx_agent_classed mean | Mean paired change | Paired 95% CI |
|---|---:|---:|---:|---:|
| Request p50 | 6,824 us | 5,924 us | -13.18% | [-14.94%, -11.42%] |
| Request p90 | 8,032 us | 6,072 us | -24.40% | [-24.71%, -24.09%] |
| Request p99 | 9,384 us | 6,208 us | -33.84% | [-34.51%, -33.18%] |
| Request p999 | 9,720 us | 6,344 us | -34.71% | [-36.65%, -32.77%] |
| BATCH throughput | 3,144.27 | 3,076.61 | -2.15% | [-4.95%, +0.64%] |
| Context switches | 14,845.25 | 14,183.00 | -4.45% | [-6.43%, -2.46%] |
| CPU migrations | 278.25 | 56.25 | -79.79% | [-82.50%, -77.09%] |

The runs crossed schbench's final reporting boundary at different points and
counted between 3,000 and 3,100 requests. The displayed RPS difference is
therefore not treated as scheduler throughput. Request latencies, BATCH
throughput, context switches per request, and migrations per request remain
directly interpretable.

Single-pair coverage also exercised both class-only paths. BATCH stress-ng
throughput was effectively unchanged at 4,866.83 versus 4,862.77 ops/s, while
context switches fell from 31,610 to 7,831. The LATENCY-only run improved
schbench throughput from 678.13 to 752.33 requests/s, request p90 from 7,992 to
5,912 us, and p99 from 15,984 to 6,984 us; p50 moved from 4,200 to 4,680 us and
migrations increased from 339 to 24,753 because idle-CPU placement remained
aggressive. These class-only numbers are diagnostics, not confidence intervals.
