// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;

use std::collections::BTreeMap;
use std::fs;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::{MapCore, MapFlags, OpenObject, PrintLevel};
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::{
    scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity, uei_exited, uei_report,
    UserExitInfo,
};

use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_agent_classed";
const COMM_LEN: usize = 16;
const MAX_VISIBLE_COMM_LEN: usize = COMM_LEN - 1;
const MAX_STEAL_SCAN: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum WorkloadClass {
    Latency,
    Batch,
}

impl WorkloadClass {
    fn as_bpf(self) -> u32 {
        match self {
            Self::Latency => bpf_intf::workload_class_CLASS_LATENCY,
            Self::Batch => bpf_intf::workload_class_CLASS_BATCH,
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "latency" => Ok(Self::Latency),
            "batch" => Ok(Self::Batch),
            other => bail!("unknown workload class '{other}', expected latency or batch"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, disable_version_flag = true)]
struct Opts {
    /// LATENCY task time slice in microseconds.
    #[clap(long, default_value = "1000")]
    latency_slice_us: u64,

    /// BATCH task time slice in microseconds.
    #[clap(long, default_value = "2000")]
    batch_slice_us: u64,

    /// Total LATENCY runtime budget for one wakeup, including continuation.
    #[clap(long, default_value = "2000")]
    latency_burst_us: u64,

    /// Maximum per-CPU LATENCY class debt allowed for wakeup preemption.
    #[clap(long, default_value = "500")]
    class_max_debt_us: u64,

    /// Minimum uninterrupted BATCH runtime before LATENCY may preempt it.
    #[clap(long, default_value = "500")]
    batch_min_run_us: u64,

    /// LATENCY class share weight.
    #[clap(long, default_value = "200")]
    latency_weight: u64,

    /// BATCH class share weight.
    #[clap(long, default_value = "100")]
    batch_weight: u64,

    /// Legacy compatibility option; per-CPU class arbitration does not use locality bypass.
    #[clap(long, default_value = "0")]
    locality_debt_us: u64,

    /// Class assigned to a comm that does not match the rule table.
    #[clap(long, value_enum, default_value_t = WorkloadClass::Batch)]
    default_class: WorkloadClass,

    /// Static rule file containing COMM=latency or COMM=batch lines.
    #[clap(long, value_name = "PATH")]
    rules: Option<PathBuf>,

    /// Add or override one static COMM=latency|batch rule.
    #[clap(long = "rule", value_name = "COMM=CLASS", action = clap::ArgAction::Append)]
    rule: Vec<String>,

    /// Number of remote per-CPU class DSQs examined on an idle pull.
    #[clap(long, default_value = "8")]
    steal_scan: u32,

    /// Legacy compatibility option; LATENCY always uses canonical vruntime.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_awake_vruntime: bool,

    /// Track unmatched comm values and report them during a clean shutdown.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    track_rule_misses: bool,

    /// Enable detailed per-CPU arbitration, placement, stealing, and lifecycle counters.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    diagnostic_counters: bool,

    /// Exit debug dump buffer length. 0 uses the kernel default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Launch a statistics monitor at this interval in seconds.
    #[clap(long)]
    stats: Option<f64>,

    /// Monitor an already running scheduler without launching this one.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable BPF trace messages.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Enable verbose userspace and libbpf logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print version information and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Print descriptions for exported statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

fn parse_rule(spec: &str, origin: &str) -> Result<([u8; COMM_LEN], u32)> {
    let (comm, class) = spec
        .split_once('=')
        .with_context(|| format!("invalid rule '{spec}' in {origin}: expected COMM=CLASS"))?;
    let comm = comm.trim();
    let comm_bytes = comm.as_bytes();

    if comm.is_empty() {
        bail!("invalid empty comm in {origin}");
    }
    if comm_bytes.len() > MAX_VISIBLE_COMM_LEN {
        bail!(
            "comm '{comm}' in {origin} is {} bytes; Linux comm supports at most {MAX_VISIBLE_COMM_LEN}",
            comm_bytes.len()
        );
    }
    if comm_bytes.contains(&0) {
        bail!("comm in {origin} contains a NUL byte");
    }

    let mut key = [0u8; COMM_LEN];
    key[..comm_bytes.len()].copy_from_slice(comm_bytes);
    Ok((key, WorkloadClass::parse(class)?.as_bpf()))
}

fn load_rule_table(opts: &Opts) -> Result<BTreeMap<[u8; COMM_LEN], u32>> {
    let mut rules = BTreeMap::new();

    if let Some(path) = &opts.rules {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading rule file {}", path.display()))?;
        for (index, raw_line) in contents.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let origin = format!("{}:{}", path.display(), index + 1);
            let (key, class_id) = parse_rule(line, &origin)?;
            rules.insert(key, class_id);
        }
    }

    for (index, spec) in opts.rule.iter().enumerate() {
        let origin = format!("--rule #{}", index + 1);
        let (key, class_id) = parse_rule(spec, &origin)?;
        rules.insert(key, class_id);
    }

    if rules.len() > bpf_intf::agent_consts_AGENT_MAX_RULES as usize {
        bail!(
            "rule table contains {} entries, maximum is {}",
            rules.len(),
            bpf_intf::agent_consts_AGENT_MAX_RULES
        );
    }
    Ok(rules)
}

fn checked_ns(value_us: u64, name: &str) -> Result<u64> {
    if value_us == 0 {
        bail!("{name} must be greater than zero");
    }
    value_us
        .checked_mul(1000)
        .with_context(|| format!("{name} is too large"))
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let latency_slice_ns = checked_ns(opts.latency_slice_us, "latency-slice-us")?;
        let batch_slice_ns = checked_ns(opts.batch_slice_us, "batch-slice-us")?;
        let latency_burst_budget_ns = checked_ns(opts.latency_burst_us, "latency-burst-us")?;
        let class_max_debt_ns = checked_ns(opts.class_max_debt_us, "class-max-debt-us")?;
        let batch_min_run_ns = checked_ns(opts.batch_min_run_us, "batch-min-run-us")?;
        let locality_debt_ns = opts
            .locality_debt_us
            .checked_mul(1000)
            .context("locality-debt-us is too large")?;
        latency_slice_ns
            .checked_mul(4)
            .context("latency-slice-us is too large for latency accounting")?;
        batch_slice_ns
            .checked_mul(2)
            .context("batch-slice-us is too large for class accounting")?;
        if latency_burst_budget_ns < latency_slice_ns {
            bail!("latency-burst-us must be at least latency-slice-us");
        }
        if latency_burst_budget_ns > latency_slice_ns * 2 {
            bail!("latency-burst-us must not exceed twice latency-slice-us");
        }
        if class_max_debt_ns > i64::MAX as u64 {
            bail!("class-max-debt-us exceeds the signed vruntime comparison range");
        }
        if batch_min_run_ns > batch_slice_ns {
            bail!("batch-min-run-us must not exceed batch-slice-us");
        }
        if opts.latency_weight == 0 || opts.batch_weight == 0 {
            bail!("class weights must be greater than zero");
        }
        if opts.steal_scan > MAX_STEAL_SCAN {
            bail!("steal-scan must be in the range 0..={MAX_STEAL_SCAN}");
        }
        let rules = load_rule_table(opts)?;

        try_set_rlimit_infinity();
        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, agent_classed_ops, open_opts)?;

        skel.struct_ops.agent_classed_ops_mut().exit_dump_len = opts.exit_dump_len;
        skel.struct_ops.agent_classed_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("missing BPF rodata")?;
        rodata.debug = opts.debug;
        rodata.latency_slice_ns = latency_slice_ns;
        rodata.batch_slice_ns = batch_slice_ns;
        rodata.latency_burst_budget_ns = latency_burst_budget_ns;
        rodata.class_max_debt_ns = class_max_debt_ns;
        rodata.batch_min_run_ns = batch_min_run_ns;
        rodata.latency_weight = opts.latency_weight;
        rodata.batch_weight = opts.batch_weight;
        rodata.locality_debt_ns = locality_debt_ns;
        rodata.default_class = opts.default_class.as_bpf();
        rodata.steal_scan = opts.steal_scan;
        rodata.use_awake_vruntime = !opts.no_awake_vruntime;
        rodata.track_rule_misses = opts.track_rule_misses;
        rodata.diagnostic_counters = opts.diagnostic_counters;

        let mut skel = scx_ops_load!(skel, agent_classed_ops, uei)?;
        for (key, class_id) in &rules {
            skel.maps
                .rules_map
                .update(key, &class_id.to_ne_bytes(), MapFlags::ANY)?;
        }
        info!(
            "loaded {} static rules; unmatched tasks use {:?}",
            rules.len(),
            opts.default_class
        );

        let struct_ops = Some(scx_ops_attach!(skel, agent_classed_ops, false)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("missing BPF bss");
        let latency = &bss.classes[WorkloadClass::Latency.as_bpf() as usize];
        let batch = &bss.classes[WorkloadClass::Batch.as_bpf() as usize];

        Metrics {
            nr_latency_queued: latency.nr_queued,
            nr_batch_queued: batch.nr_queued,
            nr_latency_running: latency.nr_running,
            nr_batch_running: batch.nr_running,
            latency_class_vruntime: latency.vruntime,
            batch_class_vruntime: batch.vruntime,
            nr_enqueues: bss.nr_enqueues,
            nr_latency_enqueues: bss.nr_latency_enqueues,
            nr_batch_enqueues: bss.nr_batch_enqueues,
            nr_direct_dispatches: bss.nr_direct_dispatches,
            nr_latency_preempts: bss.nr_latency_preempts,
            nr_latency_wakeup_enqueues: bss.nr_latency_wakeup_enqueues,
            nr_latency_preempt_eligible: bss.nr_latency_preempt_eligible,
            nr_latency_preempt_ineligible: bss.nr_latency_preempt_ineligible,
            nr_latency_preempt_insert_failures: bss.nr_latency_preempt_insert_failures,
            nr_latency_preempt_batch_protected: bss.nr_latency_preempt_batch_protected,
            nr_batch_guard_slice_shrinks: bss.nr_batch_guard_slice_shrinks,
            nr_batch_guard_timer_arms: bss.nr_batch_guard_timer_arms,
            nr_batch_guard_timer_kicks: bss.nr_batch_guard_timer_kicks,
            nr_batch_guard_timer_failures: bss.nr_batch_guard_timer_failures,
            nr_latency_non_wakeup_enqueues: bss.nr_latency_non_wakeup_enqueues,
            nr_latency_continuations: bss.nr_latency_continuations,
            nr_latency_continuation_debt_denied: bss.nr_latency_continuation_debt_denied,
            nr_latency_continuation_budget_exhausted: bss.nr_latency_continuation_budget_exhausted,
            nr_latency_continuation_history_denied: bss.nr_latency_continuation_history_denied,
            nr_latency_continuation_insert_failures: bss.nr_latency_continuation_insert_failures,
            nr_latency_stops_runnable: bss.nr_latency_stops_runnable,
            nr_latency_stops_quiescent: bss.nr_latency_stops_quiescent,
            nr_latency_slice_expirations: bss.nr_latency_slice_expirations,
            nr_local_dispatches: bss.nr_local_dispatches,
            nr_remote_dispatches: bss.nr_remote_dispatches,
            nr_latency_local_dispatches: bss.nr_latency_local_dispatches,
            nr_batch_local_dispatches: bss.nr_batch_local_dispatches,
            nr_latency_remote_dispatches: bss.nr_latency_remote_dispatches,
            nr_batch_remote_dispatches: bss.nr_batch_remote_dispatches,
            nr_latency_migrations: bss.nr_latency_migrations,
            nr_batch_migrations: bss.nr_batch_migrations,
            nr_locality_bypass_latency: bss.nr_locality_bypass_latency,
            nr_locality_bypass_batch: bss.nr_locality_bypass_batch,
            nr_locality_debt_denials: bss.nr_locality_debt_denials,
            nr_locality_remote_preferred: bss.nr_locality_remote_preferred,
            nr_locality_overdebt_fallbacks: bss.nr_locality_overdebt_fallbacks,
            nr_locality_reservation_rollbacks: bss.nr_locality_reservation_rollbacks,
            nr_locality_reservation_errors: bss.nr_locality_reservation_errors,
            latency_locality_bypass_runtime_ns: bss.latency_locality_bypass_runtime_ns,
            batch_locality_bypass_runtime_ns: bss.batch_locality_bypass_runtime_ns,
            max_locality_debt_ns: bss.max_locality_debt_ns,
            max_locality_overshoot_ns: bss.max_locality_overshoot_ns,
            latency_locality_reserved_vruntime: latency.locality_reserved_vruntime,
            batch_locality_reserved_vruntime: batch.locality_reserved_vruntime,
            nr_fallback_dispatches: bss.nr_fallback_dispatches,
            nr_dequeues: bss.nr_dequeues,
            nr_task_state_errors: bss.nr_task_state_errors,
            nr_rule_matches: bss.nr_rule_matches,
            nr_rule_misses: bss.nr_rule_misses,
            latency_runtime_ns: bss.latency_runtime_ns,
            batch_runtime_ns: bss.batch_runtime_ns,
            nr_fallback_enqueues: bss.nr_fallback_enqueues,
            latency_reserved_vruntime: bss.latency_reserved_vruntime,
            nr_single_class_fastpaths: bss.nr_single_class_fastpaths,
            nr_mixed_class_arbitrations: bss.nr_mixed_class_arbitrations,
            nr_dispatch_reservations: bss.nr_dispatch_reservations,
            nr_dispatch_reservation_rollbacks: bss.nr_dispatch_reservation_rollbacks,
            nr_dispatch_reservation_errors: bss.nr_dispatch_reservation_errors,
            nr_dispatch_reservation_late: bss.nr_dispatch_reservation_late,
            nr_dispatch_cpu_mismatches: bss.nr_dispatch_cpu_mismatches,
            nr_gated_steal_attempts: bss.nr_gated_steal_attempts,
            nr_gated_steal_successes: bss.nr_gated_steal_successes,
            nr_gated_steal_local_busy: bss.nr_gated_steal_local_busy,
            nr_gated_steal_source_short: bss.nr_gated_steal_source_short,
            nr_gated_steal_load_gap: bss.nr_gated_steal_load_gap,
            nr_gated_steal_cooldown: bss.nr_gated_steal_cooldown,
            nr_gated_steal_claim_busy: bss.nr_gated_steal_claim_busy,
        }
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn log_rule_misses(&self) -> Result<()> {
        let map = &self.skel.maps.rule_miss_comms;
        let mut misses = Vec::new();

        for key in map.keys() {
            let Some(value) = map.lookup(&key, MapFlags::ANY)? else {
                continue;
            };
            if key.len() != COMM_LEN || value.len() != std::mem::size_of::<u64>() {
                continue;
            }
            let count = u64::from_ne_bytes(
                value
                    .as_slice()
                    .try_into()
                    .expect("rule miss count has a checked size"),
            );
            let visible_len = key.iter().position(|byte| *byte == 0).unwrap_or(COMM_LEN);
            let comm = String::from_utf8_lossy(&key[..visible_len]).into_owned();
            misses.push((count, comm));
        }

        misses.sort_unstable_by(|left, right| right.cmp(left));
        if !misses.is_empty() {
            info!(
                "tracked {} distinct rule-miss comm values; showing at most 32",
                misses.len()
            );
        }
        for (count, comm) in misses.into_iter().take(32) {
            info!("rule miss comm={comm:?} count={count}");
        }
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(error) => Err(error)?,
            }
        }

        if let Err(error) = self.log_rule_misses() {
            warn!("failed to read rule miss comm counters: {error}");
        }
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("unregistering {SCHEDULER_NAME}");
    }
}

fn init_logging(verbose: bool) -> Result<()> {
    let mut config = simplelog::ConfigBuilder::new();
    config
        .set_time_offset_to_local()
        .expect("failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        if verbose {
            simplelog::LevelFilter::Debug
        } else {
            simplelog::LevelFilter::Info
        },
        config.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    Ok(())
}

fn start_monitor(interval: f64, shutdown: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(
        move || match stats::monitor(Duration::from_secs_f64(interval), shutdown) {
            Ok(()) => debug!("statistics monitor stopped"),
            Err(error) => warn!("statistics monitor stopped: {error}"),
        },
    )
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }
    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    init_logging(opts.verbose)?;
    if opts.verbose {
        init_libbpf_logging(Some(PrintLevel::Debug));
    }
    if let Some(interval) = opts.monitor.or(opts.stats) {
        if !interval.is_finite() || interval <= 0.0 {
            bail!("statistics interval must be a positive finite number");
        }
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_shutdown = shutdown.clone();
    ctrlc::set_handler(move || signal_shutdown.store(true, Ordering::Relaxed))
        .context("installing Ctrl-C handler")?;

    let monitor = opts
        .monitor
        .or(opts.stats)
        .map(|interval| start_monitor(interval, shutdown.clone()));
    if opts.monitor.is_some() {
        if let Some(handle) = monitor {
            let _ = handle.join();
        }
        return Ok(());
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut scheduler = Scheduler::init(&opts, &mut open_object)?;
        if !scheduler.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_comm_rule() {
        let (key, class_id) = parse_rule("pipewire=latency", "test").unwrap();

        assert_eq!(&key[..8], b"pipewire");
        assert!(key[8..].iter().all(|byte| *byte == 0));
        assert_eq!(class_id, WorkloadClass::Latency.as_bpf());
    }

    #[test]
    fn rejects_comm_longer_than_linux_limit() {
        let error = parse_rule("sixteen-byte-name=batch", "test").unwrap_err();

        assert!(error.to_string().contains("at most 15"));
    }

    #[test]
    fn rejects_unknown_class() {
        let error = parse_rule("worker=interactive", "test").unwrap_err();

        assert!(error.to_string().contains("expected latency or batch"));
    }
}
