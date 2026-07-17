use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::{stat_doc, Stats};
use serde::{Deserialize, Serialize};

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Current number of LATENCY tasks in class DSQs")]
    pub nr_latency_queued: u64,
    #[stat(desc = "Current number of BATCH tasks in class DSQs")]
    pub nr_batch_queued: u64,
    #[stat(desc = "Current number of running LATENCY tasks")]
    pub nr_latency_running: u64,
    #[stat(desc = "Current number of running BATCH tasks")]
    pub nr_batch_running: u64,
    #[stat(desc = "Current LATENCY class virtual runtime")]
    pub latency_class_vruntime: u64,
    #[stat(desc = "Current BATCH class virtual runtime")]
    pub batch_class_vruntime: u64,
    #[stat(desc = "Number of enqueues into per-class per-CPU DSQs")]
    pub nr_enqueues: u64,
    #[stat(desc = "Number of LATENCY DSQ enqueues")]
    pub nr_latency_enqueues: u64,
    #[stat(desc = "Number of BATCH DSQ enqueues")]
    pub nr_batch_enqueues: u64,
    #[stat(desc = "Number of idle-CPU direct LATENCY dispatches")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of successful LATENCY class preemption requests")]
    pub nr_latency_preempts: u64,
    #[stat(desc = "Number of LATENCY wakeups reaching enqueue")]
    pub nr_latency_wakeup_enqueues: u64,
    #[stat(desc = "Number of LATENCY class handoff decisions")]
    pub nr_latency_handoffs: u64,
    #[stat(desc = "Number of LATENCY class handoffs deferred by BATCH minimum service")]
    pub nr_latency_handoff_deferred: u64,
    #[stat(desc = "Number of current-task slices shortened at an arbitration boundary")]
    pub nr_arbitration_slice_caps: u64,
    #[stat(desc = "Number of LATENCY enqueues without SCX_ENQ_WAKEUP")]
    pub nr_latency_non_wakeup_enqueues: u64,
    #[stat(desc = "Number of bounded LATENCY slice continuations")]
    pub nr_latency_continuations: u64,
    #[stat(desc = "Number of LATENCY continuations denied by class arbitration")]
    pub nr_latency_continuation_class_denied: u64,
    #[stat(desc = "Number of LATENCY continuations denied by exhausted wakeup budget")]
    pub nr_latency_continuation_budget_exhausted: u64,
    #[stat(desc = "Number of LATENCY continuations denied by prior wake-burst history")]
    pub nr_latency_continuation_history_denied: u64,
    #[stat(desc = "Number of LATENCY stops while the task remained runnable")]
    pub nr_latency_stops_runnable: u64,
    #[stat(desc = "Number of LATENCY stops when the task became quiescent")]
    pub nr_latency_stops_quiescent: u64,
    #[stat(desc = "Number of runnable LATENCY stops with no slice remaining")]
    pub nr_latency_slice_expirations: u64,
    #[stat(desc = "Number of BATCH epochs started")]
    pub nr_batch_epochs: u64,
    #[stat(desc = "Number of fully consumed BATCH epochs")]
    pub nr_batch_epoch_exhaustions: u64,
    #[stat(desc = "Number of adaptive BATCH epoch growth steps")]
    pub nr_batch_epoch_grows: u64,
    #[stat(desc = "Number of learned BATCH epochs reset to the minimum")]
    pub nr_batch_epoch_resets: u64,
    #[stat(desc = "Number of BATCH epochs shortened by the queue-round cap")]
    pub nr_batch_round_caps: u64,
    #[stat(desc = "Number of effective BATCH grants at the 1x epoch level")]
    pub nr_batch_grants_1x: u64,
    #[stat(desc = "Number of effective BATCH grants at the 2x epoch level")]
    pub nr_batch_grants_2x: u64,
    #[stat(desc = "Number of effective BATCH grants at the 4x epoch level")]
    pub nr_batch_grants_4x: u64,
    #[stat(desc = "Number of effective BATCH grants above 4x, up to 8x")]
    pub nr_batch_grants_8x: u64,
    #[stat(desc = "Number of earlier-vruntime BATCH preemption requests")]
    pub nr_batch_vruntime_preempts: u64,
    #[stat(desc = "Number of dispatches from the selected class local CPU DSQ")]
    pub nr_local_dispatches: u64,
    #[stat(desc = "Number of dispatches stolen from a remote CPU DSQ")]
    pub nr_remote_dispatches: u64,
    #[stat(desc = "Number of local LATENCY class dispatches")]
    pub nr_latency_local_dispatches: u64,
    #[stat(desc = "Number of local BATCH class dispatches")]
    pub nr_batch_local_dispatches: u64,
    #[stat(desc = "Number of observed LATENCY task CPU migrations")]
    pub nr_latency_migrations: u64,
    #[stat(desc = "Number of observed BATCH task CPU migrations")]
    pub nr_batch_migrations: u64,
    #[stat(desc = "Number of dispatches that used the non-preferred class")]
    pub nr_fallback_dispatches: u64,
    #[stat(desc = "Number of task dequeue callbacks")]
    pub nr_dequeues: u64,
    #[stat(desc = "Number of task state accounting errors")]
    pub nr_task_state_errors: u64,
    #[stat(desc = "Number of stale queue or dispatch owners reclaimed by enqueue")]
    pub nr_enqueue_ownership_reconciles: u64,
    #[stat(desc = "Number of user-DSQ queue owners reclaimed by running")]
    pub nr_running_queue_reconciles: u64,
    #[stat(desc = "Number of successful static rule lookups")]
    pub nr_rule_matches: u64,
    #[stat(desc = "Number of static rule misses")]
    pub nr_rule_misses: u64,
    #[stat(desc = "LATENCY runtime charged during the interval in nanoseconds")]
    pub latency_runtime_ns: u64,
    #[stat(desc = "BATCH runtime charged during the interval in nanoseconds")]
    pub batch_runtime_ns: u64,
    #[stat(desc = "Number of enqueues sent to the built-in fallback DSQ")]
    pub nr_fallback_enqueues: u64,
    #[stat(
        desc = "Number of dispatches bypassing class arbitration because one local class was runnable"
    )]
    pub nr_single_class_fastpaths: u64,
    #[stat(desc = "Number of dispatches arbitrating between two runnable local class entities")]
    pub nr_mixed_class_arbitrations: u64,
    #[stat(desc = "Number of mixed-class decisions selecting LATENCY")]
    pub nr_class_decisions_latency: u64,
    #[stat(desc = "Number of mixed-class decisions selecting BATCH")]
    pub nr_class_decisions_batch: u64,
    #[stat(desc = "Number of mixed-class decisions protecting BATCH minimum service")]
    pub nr_class_decisions_batch_min_run: u64,
    #[stat(desc = "Most recently observed LATENCY minus BATCH class vruntime")]
    pub mixed_class_lag_ns: i64,
    #[stat(desc = "Number of remote DSQ moves attempted after passing gated-steal admission")]
    pub nr_gated_steal_attempts: u64,
    #[stat(desc = "Number of gated remote steals that moved a task")]
    pub nr_gated_steal_successes: u64,
    #[stat(desc = "Number of steal paths rejected because the destination still had local work")]
    pub nr_gated_steal_local_busy: u64,
    #[stat(desc = "Number of source candidates rejected because they lacked queued surplus")]
    pub nr_gated_steal_source_short: u64,
    #[stat(desc = "Number of source candidates rejected because their load gap was too small")]
    pub nr_gated_steal_load_gap: u64,
    #[stat(desc = "Number of source candidates rejected by task migration cooldown")]
    pub nr_gated_steal_cooldown: u64,
    #[stat(desc = "Number of source candidates rejected because another stealer held the claim")]
    pub nr_gated_steal_claim_busy: u64,
}

impl Metrics {
    fn format<W: Write>(&self, writer: &mut W) -> Result<()> {
        writeln!(
            writer,
            "[{}] q L/B: {}/{} run L/B: {}/{} | enq/deq: {}/{} rules hit/miss: {}/{} | dispatch direct/preempt/local/remote/fallback: {}/{}/{}/{}/{} | runtime L/B: {:.2}/{:.2} ms | errors: {}",
            crate::SCHEDULER_NAME,
            self.nr_latency_queued,
            self.nr_batch_queued,
            self.nr_latency_running,
            self.nr_batch_running,
            self.nr_enqueues,
            self.nr_dequeues,
            self.nr_rule_matches,
            self.nr_rule_misses,
            self.nr_direct_dispatches,
            self.nr_latency_preempts,
            self.nr_local_dispatches,
            self.nr_remote_dispatches,
            self.nr_fallback_dispatches,
            self.latency_runtime_ns as f64 / 1_000_000.0,
            self.batch_runtime_ns as f64 / 1_000_000.0,
            self.nr_task_state_errors,
        )?;
        writeln!(
            writer,
            "  latency handoff/preempt/deferred: {}/{}/{} | arbitration slice caps: {} | non-wakeup enq: {} | stops runnable/quiescent/slice-expired: {}/{}/{}",
            self.nr_latency_handoffs,
            self.nr_latency_preempts,
            self.nr_latency_handoff_deferred,
            self.nr_arbitration_slice_caps,
            self.nr_latency_non_wakeup_enqueues,
            self.nr_latency_stops_runnable,
            self.nr_latency_stops_quiescent,
            self.nr_latency_slice_expirations,
        )?;
        writeln!(
            writer,
            "  placement local L/B: {}/{} remote: {} migrations L/B: {}/{}",
            self.nr_latency_local_dispatches,
            self.nr_batch_local_dispatches,
            self.nr_remote_dispatches,
            self.nr_latency_migrations,
            self.nr_batch_migrations,
        )?;
        writeln!(
            writer,
            "  continuation run/class/budget/history: {}/{}/{}/{}",
            self.nr_latency_continuations,
            self.nr_latency_continuation_class_denied,
            self.nr_latency_continuation_budget_exhausted,
            self.nr_latency_continuation_history_denied,
        )?;
        writeln!(
            writer,
            "  batch epoch start/exhaust/grow/reset/round-cap: {}/{}/{}/{}/{} | grants 1x/2x/4x/8x: {}/{}/{}/{}",
            self.nr_batch_epochs,
            self.nr_batch_epoch_exhaustions,
            self.nr_batch_epoch_grows,
            self.nr_batch_epoch_resets,
            self.nr_batch_round_caps,
            self.nr_batch_grants_1x,
            self.nr_batch_grants_2x,
            self.nr_batch_grants_4x,
            self.nr_batch_grants_8x,
        )?;
        writeln!(
            writer,
            "  batch same-class preempt: {}",
            self.nr_batch_vruntime_preempts,
        )?;
        writeln!(
            writer,
            "  per-CPU arbitration single/mixed: {}/{} decisions L/B/min-run: {}/{}/{} | current lag: {:.3} ms",
            self.nr_single_class_fastpaths,
            self.nr_mixed_class_arbitrations,
            self.nr_class_decisions_latency,
            self.nr_class_decisions_batch,
            self.nr_class_decisions_batch_min_run,
            self.mixed_class_lag_ns as f64 / 1_000_000.0,
        )?;
        writeln!(
            writer,
            "  ownership reconcile enqueue/running: {}/{}",
            self.nr_enqueue_ownership_reconciles, self.nr_running_queue_reconciles,
        )?;
        writeln!(
            writer,
            "  gated steal attempt/success: {}/{} | reject local-busy/source-short/load-gap/cooldown/claim-busy: {}/{}/{}/{}/{}",
            self.nr_gated_steal_attempts,
            self.nr_gated_steal_successes,
            self.nr_gated_steal_local_busy,
            self.nr_gated_steal_source_short,
            self.nr_gated_steal_load_gap,
            self.nr_gated_steal_cooldown,
            self.nr_gated_steal_claim_busy,
        )?;
        Ok(())
    }

    fn delta(&self, previous: &Self) -> Self {
        Self {
            nr_latency_queued: self.nr_latency_queued,
            nr_batch_queued: self.nr_batch_queued,
            nr_latency_running: self.nr_latency_running,
            nr_batch_running: self.nr_batch_running,
            latency_class_vruntime: self.latency_class_vruntime,
            batch_class_vruntime: self.batch_class_vruntime,
            nr_enqueues: self.nr_enqueues.saturating_sub(previous.nr_enqueues),
            nr_latency_enqueues: self
                .nr_latency_enqueues
                .saturating_sub(previous.nr_latency_enqueues),
            nr_batch_enqueues: self
                .nr_batch_enqueues
                .saturating_sub(previous.nr_batch_enqueues),
            nr_direct_dispatches: self
                .nr_direct_dispatches
                .saturating_sub(previous.nr_direct_dispatches),
            nr_latency_preempts: self
                .nr_latency_preempts
                .saturating_sub(previous.nr_latency_preempts),
            nr_latency_wakeup_enqueues: self
                .nr_latency_wakeup_enqueues
                .saturating_sub(previous.nr_latency_wakeup_enqueues),
            nr_latency_handoffs: self
                .nr_latency_handoffs
                .saturating_sub(previous.nr_latency_handoffs),
            nr_latency_handoff_deferred: self
                .nr_latency_handoff_deferred
                .saturating_sub(previous.nr_latency_handoff_deferred),
            nr_arbitration_slice_caps: self
                .nr_arbitration_slice_caps
                .saturating_sub(previous.nr_arbitration_slice_caps),
            nr_latency_non_wakeup_enqueues: self
                .nr_latency_non_wakeup_enqueues
                .saturating_sub(previous.nr_latency_non_wakeup_enqueues),
            nr_latency_continuations: self
                .nr_latency_continuations
                .saturating_sub(previous.nr_latency_continuations),
            nr_latency_continuation_class_denied: self
                .nr_latency_continuation_class_denied
                .saturating_sub(previous.nr_latency_continuation_class_denied),
            nr_latency_continuation_budget_exhausted: self
                .nr_latency_continuation_budget_exhausted
                .saturating_sub(previous.nr_latency_continuation_budget_exhausted),
            nr_latency_continuation_history_denied: self
                .nr_latency_continuation_history_denied
                .saturating_sub(previous.nr_latency_continuation_history_denied),
            nr_latency_stops_runnable: self
                .nr_latency_stops_runnable
                .saturating_sub(previous.nr_latency_stops_runnable),
            nr_latency_stops_quiescent: self
                .nr_latency_stops_quiescent
                .saturating_sub(previous.nr_latency_stops_quiescent),
            nr_latency_slice_expirations: self
                .nr_latency_slice_expirations
                .saturating_sub(previous.nr_latency_slice_expirations),
            nr_batch_epochs: self
                .nr_batch_epochs
                .saturating_sub(previous.nr_batch_epochs),
            nr_batch_epoch_exhaustions: self
                .nr_batch_epoch_exhaustions
                .saturating_sub(previous.nr_batch_epoch_exhaustions),
            nr_batch_epoch_grows: self
                .nr_batch_epoch_grows
                .saturating_sub(previous.nr_batch_epoch_grows),
            nr_batch_epoch_resets: self
                .nr_batch_epoch_resets
                .saturating_sub(previous.nr_batch_epoch_resets),
            nr_batch_round_caps: self
                .nr_batch_round_caps
                .saturating_sub(previous.nr_batch_round_caps),
            nr_batch_grants_1x: self
                .nr_batch_grants_1x
                .saturating_sub(previous.nr_batch_grants_1x),
            nr_batch_grants_2x: self
                .nr_batch_grants_2x
                .saturating_sub(previous.nr_batch_grants_2x),
            nr_batch_grants_4x: self
                .nr_batch_grants_4x
                .saturating_sub(previous.nr_batch_grants_4x),
            nr_batch_grants_8x: self
                .nr_batch_grants_8x
                .saturating_sub(previous.nr_batch_grants_8x),
            nr_batch_vruntime_preempts: self
                .nr_batch_vruntime_preempts
                .saturating_sub(previous.nr_batch_vruntime_preempts),
            nr_local_dispatches: self
                .nr_local_dispatches
                .saturating_sub(previous.nr_local_dispatches),
            nr_remote_dispatches: self
                .nr_remote_dispatches
                .saturating_sub(previous.nr_remote_dispatches),
            nr_latency_local_dispatches: self
                .nr_latency_local_dispatches
                .saturating_sub(previous.nr_latency_local_dispatches),
            nr_batch_local_dispatches: self
                .nr_batch_local_dispatches
                .saturating_sub(previous.nr_batch_local_dispatches),
            nr_latency_migrations: self
                .nr_latency_migrations
                .saturating_sub(previous.nr_latency_migrations),
            nr_batch_migrations: self
                .nr_batch_migrations
                .saturating_sub(previous.nr_batch_migrations),
            nr_fallback_dispatches: self
                .nr_fallback_dispatches
                .saturating_sub(previous.nr_fallback_dispatches),
            nr_dequeues: self.nr_dequeues.saturating_sub(previous.nr_dequeues),
            nr_task_state_errors: self
                .nr_task_state_errors
                .saturating_sub(previous.nr_task_state_errors),
            nr_enqueue_ownership_reconciles: self
                .nr_enqueue_ownership_reconciles
                .saturating_sub(previous.nr_enqueue_ownership_reconciles),
            nr_running_queue_reconciles: self
                .nr_running_queue_reconciles
                .saturating_sub(previous.nr_running_queue_reconciles),
            nr_rule_matches: self
                .nr_rule_matches
                .saturating_sub(previous.nr_rule_matches),
            nr_rule_misses: self.nr_rule_misses.saturating_sub(previous.nr_rule_misses),
            latency_runtime_ns: self
                .latency_runtime_ns
                .saturating_sub(previous.latency_runtime_ns),
            batch_runtime_ns: self
                .batch_runtime_ns
                .saturating_sub(previous.batch_runtime_ns),
            nr_fallback_enqueues: self
                .nr_fallback_enqueues
                .saturating_sub(previous.nr_fallback_enqueues),
            nr_single_class_fastpaths: self
                .nr_single_class_fastpaths
                .saturating_sub(previous.nr_single_class_fastpaths),
            nr_mixed_class_arbitrations: self
                .nr_mixed_class_arbitrations
                .saturating_sub(previous.nr_mixed_class_arbitrations),
            nr_class_decisions_latency: self
                .nr_class_decisions_latency
                .saturating_sub(previous.nr_class_decisions_latency),
            nr_class_decisions_batch: self
                .nr_class_decisions_batch
                .saturating_sub(previous.nr_class_decisions_batch),
            nr_class_decisions_batch_min_run: self
                .nr_class_decisions_batch_min_run
                .saturating_sub(previous.nr_class_decisions_batch_min_run),
            mixed_class_lag_ns: self.mixed_class_lag_ns,
            nr_gated_steal_attempts: self
                .nr_gated_steal_attempts
                .saturating_sub(previous.nr_gated_steal_attempts),
            nr_gated_steal_successes: self
                .nr_gated_steal_successes
                .saturating_sub(previous.nr_gated_steal_successes),
            nr_gated_steal_local_busy: self
                .nr_gated_steal_local_busy
                .saturating_sub(previous.nr_gated_steal_local_busy),
            nr_gated_steal_source_short: self
                .nr_gated_steal_source_short
                .saturating_sub(previous.nr_gated_steal_source_short),
            nr_gated_steal_load_gap: self
                .nr_gated_steal_load_gap
                .saturating_sub(previous.nr_gated_steal_load_gap),
            nr_gated_steal_cooldown: self
                .nr_gated_steal_cooldown
                .saturating_sub(previous.nr_gated_steal_cooldown),
            nr_gated_steal_claim_busy: self
                .nr_gated_steal_claim_busy
                .saturating_sub(previous.nr_gated_steal_claim_busy),
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(request, response)| {
        request.send(())?;
        let mut previous = response.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> =
            Box::new(move |_args, (request, response)| {
                request.send(())?;
                let current = response.recv()?;
                let delta = current.delta(&previous);
                previous = current;
                delta.to_json()
            });
        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(interval: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        interval,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
