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
    #[stat(desc = "Number of eligible LATENCY wakeups directly preempting a CPU")]
    pub nr_latency_preempts: u64,
    #[stat(desc = "Number of LATENCY wakeups reaching enqueue")]
    pub nr_latency_wakeup_enqueues: u64,
    #[stat(desc = "Number of LATENCY wakeups passing class preemption eligibility")]
    pub nr_latency_preempt_eligible: u64,
    #[stat(desc = "Number of LATENCY wakeups failing class preemption eligibility")]
    pub nr_latency_preempt_ineligible: u64,
    #[stat(desc = "Number of eligible LATENCY preemption insert failures")]
    pub nr_latency_preempt_insert_failures: u64,
    #[stat(desc = "Number of LATENCY preemptions deferred by BATCH minimum service")]
    pub nr_latency_preempt_batch_protected: u64,
    #[stat(desc = "Number of running BATCH slices shortened to the minimum-service boundary")]
    pub nr_batch_guard_slice_shrinks: u64,
    #[stat(desc = "Number of BATCH minimum-service timers armed")]
    pub nr_batch_guard_timer_arms: u64,
    #[stat(desc = "Number of BATCH minimum-service timer preemption kicks")]
    pub nr_batch_guard_timer_kicks: u64,
    #[stat(desc = "Number of BATCH minimum-service timer arm failures")]
    pub nr_batch_guard_timer_failures: u64,
    #[stat(desc = "Number of LATENCY enqueues without SCX_ENQ_WAKEUP")]
    pub nr_latency_non_wakeup_enqueues: u64,
    #[stat(desc = "Number of bounded LATENCY slice continuations")]
    pub nr_latency_continuations: u64,
    #[stat(desc = "Number of LATENCY continuations denied by class debt")]
    pub nr_latency_continuation_debt_denied: u64,
    #[stat(desc = "Number of LATENCY continuations denied by exhausted wakeup budget")]
    pub nr_latency_continuation_budget_exhausted: u64,
    #[stat(desc = "Number of LATENCY continuations denied by prior wake-burst history")]
    pub nr_latency_continuation_history_denied: u64,
    #[stat(desc = "Number of LATENCY continuation insert failures")]
    pub nr_latency_continuation_insert_failures: u64,
    #[stat(desc = "Number of LATENCY stops while the task remained runnable")]
    pub nr_latency_stops_runnable: u64,
    #[stat(desc = "Number of LATENCY stops when the task became quiescent")]
    pub nr_latency_stops_quiescent: u64,
    #[stat(desc = "Number of runnable LATENCY stops with no slice remaining")]
    pub nr_latency_slice_expirations: u64,
    #[stat(desc = "Number of dispatches from the selected class local CPU DSQ")]
    pub nr_local_dispatches: u64,
    #[stat(desc = "Number of dispatches stolen from a remote CPU DSQ")]
    pub nr_remote_dispatches: u64,
    #[stat(desc = "Number of local LATENCY class dispatches")]
    pub nr_latency_local_dispatches: u64,
    #[stat(desc = "Number of local BATCH class dispatches")]
    pub nr_batch_local_dispatches: u64,
    #[stat(desc = "Number of remote LATENCY class dispatches")]
    pub nr_latency_remote_dispatches: u64,
    #[stat(desc = "Number of remote BATCH class dispatches")]
    pub nr_batch_remote_dispatches: u64,
    #[stat(desc = "Number of observed LATENCY task CPU migrations")]
    pub nr_latency_migrations: u64,
    #[stat(desc = "Number of observed BATCH task CPU migrations")]
    pub nr_batch_migrations: u64,
    #[stat(desc = "Legacy locality-debt LATENCY bypasses; inactive in the per-CPU hot path")]
    pub nr_locality_bypass_latency: u64,
    #[stat(desc = "Legacy locality-debt BATCH bypasses; inactive in the per-CPU hot path")]
    pub nr_locality_bypass_batch: u64,
    #[stat(desc = "Legacy locality-debt admission denials; inactive in the per-CPU hot path")]
    pub nr_locality_debt_denials: u64,
    #[stat(desc = "Legacy remote preferred-class dispatches after locality-debt denial")]
    pub nr_locality_remote_preferred: u64,
    #[stat(desc = "Legacy over-debt local fallbacks needed for work conservation")]
    pub nr_locality_overdebt_fallbacks: u64,
    #[stat(desc = "Number of locality reservations rolled back after a failed move")]
    pub nr_locality_reservation_rollbacks: u64,
    #[stat(desc = "Number of locality reservation accounting errors")]
    pub nr_locality_reservation_errors: u64,
    #[stat(desc = "LATENCY runtime dispatched through local-other bypass in nanoseconds")]
    pub latency_locality_bypass_runtime_ns: u64,
    #[stat(desc = "BATCH runtime dispatched through local-other bypass in nanoseconds")]
    pub batch_locality_bypass_runtime_ns: u64,
    #[stat(desc = "Maximum normalized class debt observed at locality admission")]
    pub max_locality_debt_ns: u64,
    #[stat(desc = "Maximum projected soft-bound overshoot")]
    pub max_locality_overshoot_ns: u64,
    #[stat(desc = "Current LATENCY projected locality service reservation")]
    pub latency_locality_reserved_vruntime: u64,
    #[stat(desc = "Current BATCH projected locality service reservation")]
    pub batch_locality_reserved_vruntime: u64,
    #[stat(desc = "Number of dispatches that used the non-preferred class")]
    pub nr_fallback_dispatches: u64,
    #[stat(desc = "Number of task dequeue callbacks")]
    pub nr_dequeues: u64,
    #[stat(desc = "Number of task state accounting errors")]
    pub nr_task_state_errors: u64,
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
    #[stat(desc = "Current class-vruntime reserved by debt-controlled LATENCY dispatches")]
    pub latency_reserved_vruntime: u64,
    #[stat(
        desc = "Number of dispatches bypassing class arbitration because one local class was runnable"
    )]
    pub nr_single_class_fastpaths: u64,
    #[stat(desc = "Number of dispatches arbitrating between two runnable local class entities")]
    pub nr_mixed_class_arbitrations: u64,
    #[stat(desc = "Number of per-CPU class service reservations claimed for dispatch")]
    pub nr_dispatch_reservations: u64,
    #[stat(desc = "Number of dispatch reservations rolled back before task execution")]
    pub nr_dispatch_reservation_rollbacks: u64,
    #[stat(desc = "Number of dispatch reservation accounting errors")]
    pub nr_dispatch_reservation_errors: u64,
    #[stat(desc = "Number of dispatch reservations claimed late in running()")]
    pub nr_dispatch_reservation_late: u64,
    #[stat(desc = "Number of tasks running on a CPU other than their reserved dispatch CPU")]
    pub nr_dispatch_cpu_mismatches: u64,
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
            "  latency wake eligible/ineligible/preempt/fail: {}/{}/{}/{} | non-wakeup enq: {} | stops runnable/quiescent/slice-expired: {}/{}/{}",
            self.nr_latency_preempt_eligible,
            self.nr_latency_preempt_ineligible,
            self.nr_latency_preempts,
            self.nr_latency_preempt_insert_failures,
            self.nr_latency_non_wakeup_enqueues,
            self.nr_latency_stops_runnable,
            self.nr_latency_stops_quiescent,
            self.nr_latency_slice_expirations,
        )?;
        writeln!(
            writer,
            "  placement local L/B: {}/{} remote L/B: {}/{} migrations L/B: {}/{} | locality bypass L/B: {}/{} debt-deny/remote-preferred/overdebt: {}/{}/{}",
            self.nr_latency_local_dispatches,
            self.nr_batch_local_dispatches,
            self.nr_latency_remote_dispatches,
            self.nr_batch_remote_dispatches,
            self.nr_latency_migrations,
            self.nr_batch_migrations,
            self.nr_locality_bypass_latency,
            self.nr_locality_bypass_batch,
            self.nr_locality_debt_denials,
            self.nr_locality_remote_preferred,
            self.nr_locality_overdebt_fallbacks,
        )?;
        writeln!(
            writer,
            "  legacy locality-debt (inactive) reservation L/B: {}/{} rollback/errors: {}/{} bypass runtime L/B: {:.2}/{:.2} ms | max debt/overshoot: {:.2}/{:.2} ms",
            self.latency_locality_reserved_vruntime,
            self.batch_locality_reserved_vruntime,
            self.nr_locality_reservation_rollbacks,
            self.nr_locality_reservation_errors,
            self.latency_locality_bypass_runtime_ns as f64 / 1_000_000.0,
            self.batch_locality_bypass_runtime_ns as f64 / 1_000_000.0,
            self.max_locality_debt_ns as f64 / 1_000_000.0,
            self.max_locality_overshoot_ns as f64 / 1_000_000.0,
        )?;
        writeln!(
            writer,
            "  batch guard protected/shrink/timer-arm/kick/fail: {}/{}/{}/{}/{}",
            self.nr_latency_preempt_batch_protected,
            self.nr_batch_guard_slice_shrinks,
            self.nr_batch_guard_timer_arms,
            self.nr_batch_guard_timer_kicks,
            self.nr_batch_guard_timer_failures,
        )?;
        writeln!(
            writer,
            "  continuation run/debt/budget/history/fail: {}/{}/{}/{}/{} | reserved class-vruntime: {}",
            self.nr_latency_continuations,
            self.nr_latency_continuation_debt_denied,
            self.nr_latency_continuation_budget_exhausted,
            self.nr_latency_continuation_history_denied,
            self.nr_latency_continuation_insert_failures,
            self.latency_reserved_vruntime,
        )?;
        writeln!(
            writer,
            "  per-CPU arbitration single/mixed: {}/{} | dispatch reservation claim/rollback/late/cpu-mismatch/error: {}/{}/{}/{}/{}",
            self.nr_single_class_fastpaths,
            self.nr_mixed_class_arbitrations,
            self.nr_dispatch_reservations,
            self.nr_dispatch_reservation_rollbacks,
            self.nr_dispatch_reservation_late,
            self.nr_dispatch_cpu_mismatches,
            self.nr_dispatch_reservation_errors,
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
            nr_latency_preempt_eligible: self
                .nr_latency_preempt_eligible
                .saturating_sub(previous.nr_latency_preempt_eligible),
            nr_latency_preempt_ineligible: self
                .nr_latency_preempt_ineligible
                .saturating_sub(previous.nr_latency_preempt_ineligible),
            nr_latency_preempt_insert_failures: self
                .nr_latency_preempt_insert_failures
                .saturating_sub(previous.nr_latency_preempt_insert_failures),
            nr_latency_preempt_batch_protected: self
                .nr_latency_preempt_batch_protected
                .saturating_sub(previous.nr_latency_preempt_batch_protected),
            nr_batch_guard_slice_shrinks: self
                .nr_batch_guard_slice_shrinks
                .saturating_sub(previous.nr_batch_guard_slice_shrinks),
            nr_batch_guard_timer_arms: self
                .nr_batch_guard_timer_arms
                .saturating_sub(previous.nr_batch_guard_timer_arms),
            nr_batch_guard_timer_kicks: self
                .nr_batch_guard_timer_kicks
                .saturating_sub(previous.nr_batch_guard_timer_kicks),
            nr_batch_guard_timer_failures: self
                .nr_batch_guard_timer_failures
                .saturating_sub(previous.nr_batch_guard_timer_failures),
            nr_latency_non_wakeup_enqueues: self
                .nr_latency_non_wakeup_enqueues
                .saturating_sub(previous.nr_latency_non_wakeup_enqueues),
            nr_latency_continuations: self
                .nr_latency_continuations
                .saturating_sub(previous.nr_latency_continuations),
            nr_latency_continuation_debt_denied: self
                .nr_latency_continuation_debt_denied
                .saturating_sub(previous.nr_latency_continuation_debt_denied),
            nr_latency_continuation_budget_exhausted: self
                .nr_latency_continuation_budget_exhausted
                .saturating_sub(previous.nr_latency_continuation_budget_exhausted),
            nr_latency_continuation_history_denied: self
                .nr_latency_continuation_history_denied
                .saturating_sub(previous.nr_latency_continuation_history_denied),
            nr_latency_continuation_insert_failures: self
                .nr_latency_continuation_insert_failures
                .saturating_sub(previous.nr_latency_continuation_insert_failures),
            nr_latency_stops_runnable: self
                .nr_latency_stops_runnable
                .saturating_sub(previous.nr_latency_stops_runnable),
            nr_latency_stops_quiescent: self
                .nr_latency_stops_quiescent
                .saturating_sub(previous.nr_latency_stops_quiescent),
            nr_latency_slice_expirations: self
                .nr_latency_slice_expirations
                .saturating_sub(previous.nr_latency_slice_expirations),
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
            nr_latency_remote_dispatches: self
                .nr_latency_remote_dispatches
                .saturating_sub(previous.nr_latency_remote_dispatches),
            nr_batch_remote_dispatches: self
                .nr_batch_remote_dispatches
                .saturating_sub(previous.nr_batch_remote_dispatches),
            nr_latency_migrations: self
                .nr_latency_migrations
                .saturating_sub(previous.nr_latency_migrations),
            nr_batch_migrations: self
                .nr_batch_migrations
                .saturating_sub(previous.nr_batch_migrations),
            nr_locality_bypass_latency: self
                .nr_locality_bypass_latency
                .saturating_sub(previous.nr_locality_bypass_latency),
            nr_locality_bypass_batch: self
                .nr_locality_bypass_batch
                .saturating_sub(previous.nr_locality_bypass_batch),
            nr_locality_debt_denials: self
                .nr_locality_debt_denials
                .saturating_sub(previous.nr_locality_debt_denials),
            nr_locality_remote_preferred: self
                .nr_locality_remote_preferred
                .saturating_sub(previous.nr_locality_remote_preferred),
            nr_locality_overdebt_fallbacks: self
                .nr_locality_overdebt_fallbacks
                .saturating_sub(previous.nr_locality_overdebt_fallbacks),
            nr_locality_reservation_rollbacks: self
                .nr_locality_reservation_rollbacks
                .saturating_sub(previous.nr_locality_reservation_rollbacks),
            nr_locality_reservation_errors: self
                .nr_locality_reservation_errors
                .saturating_sub(previous.nr_locality_reservation_errors),
            latency_locality_bypass_runtime_ns: self
                .latency_locality_bypass_runtime_ns
                .saturating_sub(previous.latency_locality_bypass_runtime_ns),
            batch_locality_bypass_runtime_ns: self
                .batch_locality_bypass_runtime_ns
                .saturating_sub(previous.batch_locality_bypass_runtime_ns),
            max_locality_debt_ns: self.max_locality_debt_ns,
            max_locality_overshoot_ns: self.max_locality_overshoot_ns,
            latency_locality_reserved_vruntime: self.latency_locality_reserved_vruntime,
            batch_locality_reserved_vruntime: self.batch_locality_reserved_vruntime,
            nr_fallback_dispatches: self
                .nr_fallback_dispatches
                .saturating_sub(previous.nr_fallback_dispatches),
            nr_dequeues: self.nr_dequeues.saturating_sub(previous.nr_dequeues),
            nr_task_state_errors: self
                .nr_task_state_errors
                .saturating_sub(previous.nr_task_state_errors),
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
            latency_reserved_vruntime: self.latency_reserved_vruntime,
            nr_single_class_fastpaths: self
                .nr_single_class_fastpaths
                .saturating_sub(previous.nr_single_class_fastpaths),
            nr_mixed_class_arbitrations: self
                .nr_mixed_class_arbitrations
                .saturating_sub(previous.nr_mixed_class_arbitrations),
            nr_dispatch_reservations: self
                .nr_dispatch_reservations
                .saturating_sub(previous.nr_dispatch_reservations),
            nr_dispatch_reservation_rollbacks: self
                .nr_dispatch_reservation_rollbacks
                .saturating_sub(previous.nr_dispatch_reservation_rollbacks),
            nr_dispatch_reservation_errors: self
                .nr_dispatch_reservation_errors
                .saturating_sub(previous.nr_dispatch_reservation_errors),
            nr_dispatch_reservation_late: self
                .nr_dispatch_reservation_late
                .saturating_sub(previous.nr_dispatch_reservation_late),
            nr_dispatch_cpu_mismatches: self
                .nr_dispatch_cpu_mismatches
                .saturating_sub(previous.nr_dispatch_cpu_mismatches),
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
