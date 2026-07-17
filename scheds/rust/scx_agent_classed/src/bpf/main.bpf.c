/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Two-level scheduler:
 *
 *   per-CPU class entity -> per-class/per-CPU vtime DSQ -> task queue key
 *
 * Class vruntime controls the LATENCY:BATCH share. Task vruntime controls
 * fairness inside each class. BATCH epoch length is learned independently of
 * task ordering. Remote consumption is restricted to idle load balancing.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

#define CLASS_DSQ_BASE		(1ULL << 32)
#define CLASS_DSQ_ID(__class, __cpu) \
	(CLASS_DSQ_BASE + (u64)(__class) * AGENT_MAX_CPUS + (u64)(__cpu))
#define CLASS_WEIGHT_BASE	100ULL
#define CLASS_WAKEUP_CREDIT	2ULL
#define MIGRATION_COOLDOWN_NS	(500ULL * NSEC_PER_USEC)

#define dbg_msg(_fmt, ...) do { \
	if (debug) \
		bpf_printk(_fmt, ##__VA_ARGS__); \
} while (0)

const volatile bool debug;
const volatile u64 latency_slice_ns = NSEC_PER_MSEC;
const volatile u64 batch_min_epoch_ns = NSEC_PER_MSEC;
const volatile u64 batch_max_epoch_ns = 8ULL * NSEC_PER_MSEC;
const volatile u64 batch_round_ns = 16ULL * NSEC_PER_MSEC;
const volatile u64 latency_burst_budget_ns = 2ULL * NSEC_PER_MSEC;
/* Normalized class-vruntime debt, deliberately independent of slice/weight. */
const volatile u64 class_max_debt_ns = NSEC_PER_MSEC;
const volatile u64 batch_min_run_ns = NSEC_PER_MSEC / 2;
const volatile u64 batch_preempt_granularity_ns = NSEC_PER_MSEC / 2;
const volatile u64 latency_weight = 200;
const volatile u64 batch_weight = 100;
const volatile u32 default_class = CLASS_BATCH;
const volatile u32 steal_scan = 8;
const volatile u64 same_llc_migration_cost_ns = 250ULL * NSEC_PER_USEC;
const volatile u64 same_node_migration_cost_ns = 500ULL * NSEC_PER_USEC;
const volatile u64 remote_node_migration_cost_ns = NSEC_PER_MSEC;
const volatile bool track_rule_misses;
const volatile bool diagnostic_counters;

volatile u64 nr_enqueues;
volatile u64 nr_latency_enqueues;
volatile u64 nr_batch_enqueues;
volatile u64 nr_direct_dispatches;
volatile u64 nr_latency_preempts;
volatile u64 nr_latency_wakeup_enqueues;
volatile u64 nr_latency_handoffs;
volatile u64 nr_latency_handoff_deferred;
volatile u64 nr_arbitration_slice_caps;
volatile u64 nr_latency_non_wakeup_enqueues;
volatile u64 nr_latency_continuations;
volatile u64 nr_latency_continuation_class_denied;
volatile u64 nr_latency_continuation_budget_exhausted;
volatile u64 nr_latency_continuation_history_denied;
volatile u64 nr_latency_stops_runnable;
volatile u64 nr_latency_stops_quiescent;
volatile u64 nr_latency_slice_expirations;
volatile u64 nr_batch_epochs;
volatile u64 nr_batch_epoch_exhaustions;
volatile u64 nr_batch_epoch_grows;
volatile u64 nr_batch_epoch_resets;
volatile u64 nr_batch_round_caps;
volatile u64 nr_batch_grants_1x;
volatile u64 nr_batch_grants_2x;
volatile u64 nr_batch_grants_4x;
volatile u64 nr_batch_grants_8x;
volatile u64 nr_batch_vruntime_preempts;
volatile u64 nr_local_dispatches;
volatile u64 nr_remote_dispatches;
volatile u64 nr_fallback_dispatches;
volatile u64 nr_latency_local_dispatches;
volatile u64 nr_batch_local_dispatches;
volatile u64 nr_latency_migrations;
volatile u64 nr_batch_migrations;
volatile u64 nr_dequeues;
volatile u64 nr_task_state_errors;
volatile u64 nr_enqueue_ownership_reconciles;
volatile u64 nr_running_queue_reconciles;
volatile u64 nr_rule_matches;
volatile u64 nr_rule_misses;
volatile u64 latency_runtime_ns;
volatile u64 batch_runtime_ns;
volatile u64 nr_fallback_enqueues;
volatile u64 nr_single_class_fastpaths;
volatile u64 nr_mixed_class_arbitrations;
volatile u64 nr_class_decisions_latency;
volatile u64 nr_class_decisions_batch;
volatile u64 nr_class_decisions_batch_min_run;
volatile s64 mixed_class_lag_ns;
volatile u64 nr_gated_steal_attempts;
volatile u64 nr_gated_steal_successes;
volatile u64 nr_gated_steal_local_busy;
volatile u64 nr_gated_steal_source_short;
volatile u64 nr_gated_steal_load_gap;
volatile u64 nr_gated_steal_cooldown;
volatile u64 nr_gated_steal_claim_busy;

UEI_DEFINE(uei);

enum task_state {
	TASK_NONE = 0,
	TASK_ENQUEUED,
	TASK_DISPATCHED,
};

struct task_ctx {
	u64 vruntime;
	u64 last_run_at;
	u64 last_migrate_at;
	u64 latency_burst_used_ns;
	u64 batch_epoch_target_ns;
	u64 batch_epoch_remaining_ns;
	s64 sleep_vlag;
	s32 last_cpu;
	s32 home_cpu;
	s32 vtime_cpu;
	s32 queued_cpu;
	s32 running_cpu;
	u32 class_id;
	bool has_sleep_vlag;
	enum task_state state;
};

struct class_ctx {
	u64 vruntime;
	u64 nr_queued;
	u64 nr_running;
};

struct cpu_class_ctx {
	u64 vruntime;
	u64 task_vtime;
	u64 nr_queued;
	u64 nr_running;
};

struct cpu_ctx {
	struct cpu_class_ctx entity[CLASS_NR];
	u64 class_vtime_now;
	u64 steal_claim;
	u64 running_since;
	u64 batch_service_since_latency;
	u32 running_class;
};

/* BSS-backed state avoids a map lookup on each class accounting operation. */
struct class_ctx classes[CLASS_NR];
volatile u64 class_vtime_now;
volatile u64 steal_cursor;
static u64 nr_cpu_ids;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, AGENT_MAX_CPUS);
	__type(key, u32);
	__type(value, struct cpu_ctx);
} cpu_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, AGENT_MAX_CPUS);
	__type(key, u32);
	__type(value, struct agent_cpu_topology);
} cpu_topology_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, AGENT_MAX_RULES);
	__type(key, struct rule_key);
	__type(value, struct rule_value);
} rules_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, AGENT_MAX_MISS_COMMS);
	__type(key, struct rule_key);
	__type(value, u64);
} rule_miss_comms SEC(".maps");

static struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static struct cpu_ctx *lookup_cpu_ctx(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return NULL;
	key = cpu;
	return bpf_map_lookup_elem(&cpu_ctxs, &key);
}

static const struct agent_cpu_topology *lookup_cpu_topology(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return NULL;
	key = cpu;
	return bpf_map_lookup_elem(&cpu_topology_map, &key);
}

static u32 topology_tier(s32 dst_cpu, s32 src_cpu)
{
	const struct agent_cpu_topology *dst = lookup_cpu_topology(dst_cpu);
	const struct agent_cpu_topology *src = lookup_cpu_topology(src_cpu);

	if (!dst || !src || !dst->capacity || !src->capacity)
		return 2;
	if (dst->llc_id == src->llc_id)
		return 0;
	if (dst->node_id == src->node_id)
		return 1;
	return 2;
}

static u64 topology_migration_cost(s32 dst_cpu, s32 src_cpu)
{
	u32 tier = topology_tier(dst_cpu, src_cpu);

	if (!tier)
		return same_llc_migration_cost_ns;
	if (tier == 1)
		return same_node_migration_cost_ns;
	return remote_node_migration_cost_ns;
}

static u64 capacity_scale_load(s32 cpu, u64 load)
{
	const struct agent_cpu_topology *topo = lookup_cpu_topology(cpu);
	u64 capacity = topo ? READ_ONCE(topo->capacity) : 0;

	if (!capacity)
		capacity = 1024;
	if (load > ~0ULL / 1024)
		return ~0ULL;
	return load * 1024 / capacity;
}

static struct cpu_class_ctx *cpu_class_entity(struct cpu_ctx *cpuc,
					      u32 class_id)
{
	if (!cpuc)
		return NULL;
	if (class_id == CLASS_LATENCY)
		return &cpuc->entity[CLASS_LATENCY];
	if (class_id == CLASS_BATCH)
		return &cpuc->entity[CLASS_BATCH];
	return NULL;
}

static struct class_ctx *lookup_class_ctx(u32 class_id)
{
	if (class_id >= CLASS_NR)
		return NULL;
	return &classes[class_id];
}

static u32 sanitize_class(u32 class_id)
{
	if (class_id < CLASS_NR)
		return class_id;
	return default_class < CLASS_NR ? default_class : CLASS_BATCH;
}

static u64 class_slice(u32 class_id)
{
	return class_id == CLASS_LATENCY ? latency_slice_ns :
		batch_min_epoch_ns;
}

static u64 class_weight(u32 class_id)
{
	u64 weight = class_id == CLASS_LATENCY ? latency_weight : batch_weight;

	return weight ? weight : 1;
}

static u64 class_vruntime_delta(u32 class_id, u64 runtime)
{
	u64 delta = runtime * CLASS_WEIGHT_BASE / class_weight(class_id);

	return delta ? delta : 1;
}

static u64 class_runtime_from_vruntime(u32 class_id, u64 delta)
{
	u64 weight = class_weight(class_id);

	if (delta <= 1)
		return delta;
	if (delta > (~0ULL - (CLASS_WEIGHT_BASE - 1)) / weight)
		return ~0ULL;
	return (delta * weight + CLASS_WEIGHT_BASE - 1) / CLASS_WEIGHT_BASE;
}

static void reset_batch_epoch(struct task_ctx *tctx)
{
	u64 old = tctx->batch_epoch_target_ns;

	tctx->batch_epoch_target_ns = batch_min_epoch_ns;
	tctx->batch_epoch_remaining_ns = 0;
	if (diagnostic_counters && old > batch_min_epoch_ns)
		__sync_fetch_and_add(&nr_batch_epoch_resets, 1);
}

static u64 next_batch_epoch(const struct task_ctx *tctx)
{
	u64 current = tctx->batch_epoch_target_ns;

	if (current < batch_min_epoch_ns || current > batch_max_epoch_ns)
		current = batch_min_epoch_ns;
	if (current >= batch_max_epoch_ns)
		return batch_max_epoch_ns;
	if (current > batch_max_epoch_ns / 2)
		return batch_max_epoch_ns;
	return current * 2;
}

static void record_batch_grant(u64 epoch)
{
	if (!diagnostic_counters)
		return;
	if (epoch <= batch_min_epoch_ns)
		__sync_fetch_and_add(&nr_batch_grants_1x, 1);
	else if (epoch <= batch_min_epoch_ns * 2)
		__sync_fetch_and_add(&nr_batch_grants_2x, 1);
	else if (epoch <= batch_min_epoch_ns * 4)
		__sync_fetch_and_add(&nr_batch_grants_4x, 1);
	else
		__sync_fetch_and_add(&nr_batch_grants_8x, 1);
}

static void vtime_set_max(volatile u64 *vtime, u64 value)
{
	u64 old;

	bpf_repeat(16) {
		old = READ_ONCE(*vtime);
		if (!time_before(old, value))
			return;
		if (__sync_val_compare_and_swap(vtime, old, value) == old)
			return;
	}
	__sync_fetch_and_add(&nr_task_state_errors, 1);
}

static void activate_cpu_class(u32 class_id, struct cpu_ctx *cpuc,
			       struct cpu_class_ctx *entity)
{
	u64 credit = class_vruntime_delta(class_id,
					  class_slice(class_id) * CLASS_WAKEUP_CREDIT);
	u64 now = READ_ONCE(cpuc->class_vtime_now);
	u64 floor = now > credit ? now - credit : 0;

	vtime_set_max(&entity->vruntime, floor);
}

static void cpu_queue_inc(s32 cpu, u32 class_id)
{
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 old;

	if (!cpuc || class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	entity = cpu_class_entity(cpuc, class_id);
	if (!entity) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	old = __sync_fetch_and_add(&entity->nr_queued, 1);
	if (!old && !READ_ONCE(entity->nr_running))
		activate_cpu_class(class_id, cpuc, entity);
}

static void cpu_queue_dec(struct task_ctx *tctx)
{
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc;
	u64 old;
	s32 cpu = tctx->queued_cpu;
	u32 class_id = tctx->class_id;

	if (cpu < 0)
		return;
	tctx->queued_cpu = -1;
	cpuc = lookup_cpu_ctx(cpu);
	if (!cpuc || class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	entity = cpu_class_entity(cpuc, class_id);
	if (!entity) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	old = __sync_fetch_and_sub(&entity->nr_queued, 1);
	if (!old) {
		__sync_fetch_and_add(&entity->nr_queued, 1);
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	}
}

static void record_rule_miss(const struct rule_key *key)
{
	u64 initial = 1;
	u64 *count;

	count = bpf_map_lookup_elem(&rule_miss_comms, key);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return;
	}
	bpf_map_update_elem(&rule_miss_comms, key, &initial, BPF_NOEXIST);
}

static u32 classify_task(struct task_struct *p)
{
	struct rule_key key = {};
	struct rule_value *rule;
	u32 class_id;

	__builtin_memcpy(key.comm, p->comm, sizeof(key.comm));
	rule = bpf_map_lookup_elem(&rules_map, &key);
	if (rule && rule->class_id < CLASS_NR) {
		__sync_fetch_and_add(&nr_rule_matches, 1);
		class_id = rule->class_id;
	} else {
		__sync_fetch_and_add(&nr_rule_misses, 1);
		if (track_rule_misses)
			record_rule_miss(&key);
		class_id = default_class;
	}

	return sanitize_class(class_id);
}

/* Bound sleeper credit when a class or a task becomes runnable again. */
static void activate_class(u32 class_id, struct class_ctx *cctx)
{
	u64 credit = class_vruntime_delta(class_id,
					  class_slice(class_id) * CLASS_WAKEUP_CREDIT);
	u64 floor = class_vtime_now > credit ? class_vtime_now - credit : 0;

	vtime_set_max(&cctx->vruntime, floor);
}

static u64 apply_vlag(u64 vtime, s64 vlag)
{
	u64 amount;

	if (vlag >= 0) {
		amount = (u64)vlag;
		return vtime > amount ? vtime - amount : 0;
	}
	amount = (u64)(-vlag);
	return ~0ULL - vtime < amount ? ~0ULL : vtime + amount;
}

static s64 clamp_task_vlag(struct task_struct *p, u32 class_id, s64 vlag)
{
	u64 credit_ns = class_id == CLASS_LATENCY ?
		latency_slice_ns + NSEC_PER_MSEC : batch_min_epoch_ns;
	u64 debt_ns = class_id == CLASS_LATENCY ?
		latency_slice_ns + NSEC_PER_MSEC : batch_max_epoch_ns;
	s64 credit = (s64)scale_by_task_weight_inverse(p, credit_ns);
	s64 debt = (s64)scale_by_task_weight_inverse(p, debt_ns);

	if (vlag > credit)
		return credit;
	if (vlag < -debt)
		return -debt;
	return vlag;
}

static u64 cpu_task_vtime(const struct cpu_ctx *cpuc, u32 class_id)
{
	return READ_ONCE(cpuc->entity[class_id].task_vtime);
}

static bool task_rebase_vruntime(struct task_struct *p,
				struct task_ctx *tctx, s32 cpu, bool wakeup)
{
	struct cpu_ctx *dst = lookup_cpu_ctx(cpu);
	struct cpu_ctx *src;
	u32 class_id = tctx->class_id;
	u64 dst_vtime, floor, credit;
	s64 vlag;

	if (!dst || class_id >= CLASS_NR)
		return false;
	dst_vtime = cpu_task_vtime(dst, class_id);
	if (tctx->vtime_cpu < 0) {
		tctx->vruntime = dst_vtime;
		tctx->vtime_cpu = cpu;
		tctx->has_sleep_vlag = false;
		return true;
	}

	if (class_id == CLASS_LATENCY && tctx->has_sleep_vlag) {
		vlag = clamp_task_vlag(p, class_id, tctx->sleep_vlag);
		tctx->vruntime = apply_vlag(dst_vtime, vlag);
		tctx->vtime_cpu = cpu;
		tctx->has_sleep_vlag = false;
		return true;
	}

	if (tctx->vtime_cpu != cpu) {
		src = lookup_cpu_ctx(tctx->vtime_cpu);
		if (!src)
			return false;
		vlag = (s64)(cpu_task_vtime(src, class_id) - tctx->vruntime);
		vlag = clamp_task_vlag(p, class_id, vlag);
		tctx->vruntime = apply_vlag(dst_vtime, vlag);
		tctx->vtime_cpu = cpu;
	}

	if (class_id == CLASS_BATCH && wakeup) {
		credit = scale_by_task_weight_inverse(p, batch_min_epoch_ns);
		floor = dst_vtime > credit ? dst_vtime - credit : 0;
		if (time_before(tctx->vruntime, floor))
			tctx->vruntime = floor;
	}
	tctx->has_sleep_vlag = false;
	return true;
}

static void latency_save_sleep_vlag(struct task_struct *p,
				    struct task_ctx *tctx)
{
	struct cpu_ctx *cpuc = lookup_cpu_ctx(tctx->vtime_cpu);
	s64 vlag;

	if (!cpuc || tctx->class_id != CLASS_LATENCY)
		return;
	vlag = (s64)(cpu_task_vtime(cpuc, CLASS_LATENCY) - tctx->vruntime);
	tctx->sleep_vlag = clamp_task_vlag(p, CLASS_LATENCY, vlag);
	tctx->has_sleep_vlag = true;
}

static u64 batch_start_epoch(struct task_ctx *tctx,
			     const struct cpu_ctx *cpuc,
			     bool current_unaccounted)
{
	const struct cpu_class_ctx *entity = &cpuc->entity[CLASS_BATCH];
	u64 target = tctx->batch_epoch_target_ns;
	u64 runnable, cap, grant;

	if (tctx->batch_epoch_remaining_ns)
		return tctx->batch_epoch_remaining_ns;
	if (target < batch_min_epoch_ns || target > batch_max_epoch_ns)
		target = batch_min_epoch_ns;
	runnable = READ_ONCE(entity->nr_queued) +
		   READ_ONCE(entity->nr_running);
	if (current_unaccounted)
		runnable++;
	if (!runnable)
		runnable = 1;
	cap = batch_round_ns / runnable;
	if (cap < batch_min_epoch_ns)
		cap = batch_min_epoch_ns;
	if (cap > batch_max_epoch_ns)
		cap = batch_max_epoch_ns;
	grant = target < cap ? target : cap;
	tctx->batch_epoch_target_ns = target;
	tctx->batch_epoch_remaining_ns = grant;
	if (diagnostic_counters) {
		__sync_fetch_and_add(&nr_batch_epochs, 1);
		if (grant < target)
			__sync_fetch_and_add(&nr_batch_round_caps, 1);
		record_batch_grant(grant);
	}
	return grant;
}

static bool prepare_task_enqueue(struct task_struct *p,
				 struct task_ctx *tctx, s32 cpu,
				 u64 enq_flags, u64 *key, u64 *slice)
{
	bool wakeup = enq_flags & SCX_ENQ_WAKEUP;

	if (!task_rebase_vruntime(p, tctx, cpu, wakeup))
		return false;
	*key = tctx->vruntime;
	if (tctx->class_id == CLASS_LATENCY)
		*slice = latency_slice_ns;
	else
		*slice = tctx->batch_epoch_remaining_ns ?
			tctx->batch_epoch_remaining_ns : batch_min_epoch_ns;
	return true;
}

static void class_queue_dec(u32 class_id)
{
	struct class_ctx *cctx = lookup_class_ctx(class_id);
	u64 old;

	if (!cctx) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	old = __sync_fetch_and_sub(&cctx->nr_queued, 1);
	if (!old) {
		__sync_fetch_and_add(&cctx->nr_queued, 1);
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	}
}

static void task_queue_dec(struct task_ctx *tctx)
{
	if (tctx->queued_cpu < 0)
		return;
	class_queue_dec(tctx->class_id);
	cpu_queue_dec(tctx);
}

/*
 * Generic rq migration removes a task from its DSQ without necessarily
 * invoking ops.dequeue(), then invokes ops.enqueue() again. Reclaim the old
 * queue or terminal-dispatch ownership before publishing a new one.
 */
static void reconcile_before_enqueue(struct task_ctx *tctx)
{
	bool queue_owned = tctx->state == TASK_ENQUEUED || tctx->queued_cpu >= 0;
	bool reconciled = queue_owned || tctx->state == TASK_DISPATCHED;

	if (queue_owned)
		task_queue_dec(tctx);
	tctx->state = TASK_NONE;
	tctx->queued_cpu = -1;
	if (reconciled && diagnostic_counters)
		__sync_fetch_and_add(&nr_enqueue_ownership_reconciles, 1);
}

static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

static bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static bool task_cpu_allowed(const struct task_struct *p, s32 cpu)
{
	return cpu >= 0 && cpu < nr_cpu_ids &&
	       bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

static s32 task_home_cpu(struct task_struct *p, struct task_ctx *tctx,
			 s32 prev_cpu)
{
	s32 cpu = tctx->home_cpu;

	if (task_cpu_allowed(p, cpu))
		return cpu;
	if (!task_cpu_allowed(p, prev_cpu))
		prev_cpu = scx_bpf_task_cpu(p);
	if (!task_cpu_allowed(p, prev_cpu))
		prev_cpu = bpf_cpumask_first(p->cpus_ptr);
	if (task_cpu_allowed(p, prev_cpu))
		tctx->home_cpu = prev_cpu;
	return prev_cpu;
}

static bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
}

static bool task_should_kick(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	       !scx_bpf_task_running(p);
}

static bool cpu_has_local_work(s32 cpu, const struct cpu_ctx *cpuc);
static u64 cpu_queued_load(const struct cpu_ctx *cpuc);

static s32 batch_pick_cpu(struct task_struct *p, struct task_ctx *tctx,
			  s32 home_cpu, u64 wake_flags, bool *is_idle)
{
	struct cpu_ctx *cpuc;
	u64 best_score, score;
	s32 best, cpu;
	int i;

	best = scx_bpf_select_cpu_dfl(p, home_cpu, wake_flags, is_idle);
	if (*is_idle || nr_cpu_ids <= 1 || !steal_scan)
		return best;
	if (tctx->last_migrate_at &&
	    bpf_ktime_get_ns() - tctx->last_migrate_at < MIGRATION_COOLDOWN_NS)
		return best;
	cpuc = lookup_cpu_ctx(best);
	best_score = capacity_scale_load(best, cpu_queued_load(cpuc));

	bpf_for(i, 0, AGENT_STEAL_SCAN_MAX) {
		if (i >= steal_scan || i >= nr_cpu_ids - 1)
			break;
		cpu = (home_cpu + 1 + i) % nr_cpu_ids;
		if (!task_cpu_allowed(p, cpu))
			continue;
		cpuc = lookup_cpu_ctx(cpu);
		if (!cpuc)
			continue;
		score = capacity_scale_load(cpu, cpu_queued_load(cpuc));
		if (~0ULL - score < topology_migration_cost(home_cpu, cpu))
			continue;
		score += topology_migration_cost(home_cpu, cpu);
		if (score < best_score) {
			best = cpu;
			best_score = score;
		}
	}
	return best;
}

#define CLASS_MASK(__class) (1U << (__class))

enum decision_reason {
	DECISION_NONE = 0,
	DECISION_SINGLE,
	DECISION_LATENCY_DEBT,
	DECISION_BATCH_DEBT,
	DECISION_BATCH_MIN_RUN,
};

struct class_decision {
	u64 run_for_ns;
	s64 lag_ns;
	u32 winner;
	u32 fallback;
	u32 reason;
};

struct class_candidates {
	u32 available_mask;
	u32 current_class;
};

static u64 projected_class_vruntime(const struct cpu_ctx *cpuc,
				    u32 class_id, u64 now)
{
	const struct cpu_class_ctx *entity = &cpuc->entity[class_id];
	u64 projected = READ_ONCE(entity->vruntime);
	u64 started, elapsed;

	if (READ_ONCE(cpuc->running_class) != class_id)
		return projected;
	started = READ_ONCE(cpuc->running_since);
	if (!started || now <= started)
		return projected;
	elapsed = now - started;
	return projected + class_vruntime_delta(class_id, elapsed);
}

static __always_inline u32 class_winner(u64 latency_vruntime,
						u64 batch_vruntime)
{
	s64 lag = (s64)(latency_vruntime - batch_vruntime);

	return lag <= (s64)class_max_debt_ns ?
		CLASS_LATENCY : CLASS_BATCH;
}

static void record_mixed_class_decision(u32 available_mask,
					const struct class_decision *decision)
{
	if (!diagnostic_counters)
		return;
	if ((available_mask & (CLASS_MASK(CLASS_LATENCY) |
			       CLASS_MASK(CLASS_BATCH))) !=
	    (CLASS_MASK(CLASS_LATENCY) | CLASS_MASK(CLASS_BATCH)))
		return;

	WRITE_ONCE(mixed_class_lag_ns, decision->lag_ns);
	if (decision->winner == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_class_decisions_latency, 1);
	else
		__sync_fetch_and_add(&nr_class_decisions_batch, 1);
	if (decision->reason == DECISION_BATCH_MIN_RUN)
		__sync_fetch_and_add(&nr_class_decisions_batch_min_run, 1);
}

static void decide_class(const struct cpu_ctx *cpuc, u64 now,
			 const struct class_candidates *candidates,
			 struct class_decision *out)
{
	u64 lat_vruntime, batch_vruntime, batch_service, delay, started;
	u32 available_mask = candidates->available_mask;
	u32 current_class = candidates->current_class;
	s64 lag;

	out->winner = CLASS_NR;
	out->fallback = CLASS_NR;
	out->run_for_ns = ~0ULL;
	out->lag_ns = 0;
	out->reason = DECISION_NONE;

	if (!(available_mask & (CLASS_MASK(CLASS_LATENCY) |
				CLASS_MASK(CLASS_BATCH))))
		return;
	if (!(available_mask & CLASS_MASK(CLASS_LATENCY))) {
		out->winner = CLASS_BATCH;
		out->reason = DECISION_SINGLE;
		return;
	}
	if (!(available_mask & CLASS_MASK(CLASS_BATCH))) {
		out->winner = CLASS_LATENCY;
		out->reason = DECISION_SINGLE;
		return;
	}

	lat_vruntime = projected_class_vruntime(cpuc, CLASS_LATENCY, now);
	batch_vruntime = projected_class_vruntime(cpuc, CLASS_BATCH, now);
	lag = (s64)(lat_vruntime - batch_vruntime);
	out->lag_ns = lag;
	if (class_winner(lat_vruntime, batch_vruntime) == CLASS_LATENCY) {
		out->winner = CLASS_LATENCY;
		out->fallback = CLASS_BATCH;
		out->reason = DECISION_LATENCY_DEBT;
	} else {
		out->winner = CLASS_BATCH;
		out->fallback = CLASS_LATENCY;
		out->reason = DECISION_BATCH_DEBT;
	}

	if (current_class == CLASS_BATCH &&
	    out->winner == CLASS_LATENCY) {
		batch_service = READ_ONCE(cpuc->batch_service_since_latency);
		started = READ_ONCE(cpuc->running_since);
		if (started && now > started) {
			delay = now - started;
			batch_service = ~0ULL - batch_service < delay ?
				~0ULL : batch_service + delay;
		}
		if (batch_service < batch_min_run_ns) {
			out->winner = CLASS_BATCH;
			out->fallback = CLASS_LATENCY;
			out->run_for_ns = batch_min_run_ns - batch_service;
			out->reason = DECISION_BATCH_MIN_RUN;
			return;
		}
	}

	if (out->winner == CLASS_BATCH) {
		delay = class_runtime_from_vruntime(
			CLASS_BATCH,
			(u64)(lag - (s64)class_max_debt_ns));
		out->run_for_ns = delay ? delay : 1;
	} else {
		delay = class_runtime_from_vruntime(
			CLASS_LATENCY,
			(u64)((s64)class_max_debt_ns - lag + 1));
		out->run_for_ns = delay ? delay : 1;
	}
}

static u32 local_available_mask(s32 cpu, const struct cpu_ctx *cpuc,
				bool include_current)
{
	u32 mask = 0;
	u32 current;

	if (scx_bpf_dsq_nr_queued(CLASS_DSQ_ID(CLASS_LATENCY, cpu)) > 0)
		mask |= CLASS_MASK(CLASS_LATENCY);
	if (scx_bpf_dsq_nr_queued(CLASS_DSQ_ID(CLASS_BATCH, cpu)) > 0)
		mask |= CLASS_MASK(CLASS_BATCH);
	if (!include_current)
		return mask;

	current = READ_ONCE(cpuc->running_class);
	if (current < CLASS_NR && READ_ONCE(cpuc->running_since))
		mask |= CLASS_MASK(current);
	return mask;
}

static bool dsq_head_vruntime(u64 dsq_id, u64 *vruntime)
{
	struct task_struct *head;
	bool found = false;

	bpf_rcu_read_lock();
	head = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	if (head) {
		*vruntime = READ_ONCE(head->scx.dsq_vtime);
		found = true;
	}
	bpf_rcu_read_unlock();
	return found;
}

static bool task_matches_run(const struct cpu_ctx *cpuc, s32 cpu,
			     const struct task_struct *p)
{
	struct task_ctx *tctx;
	u32 class_id;

	if (!p || p->flags & PF_IDLE || !READ_ONCE(cpuc->running_since))
		return false;
	class_id = READ_ONCE(cpuc->running_class);
	tctx = lookup_task_ctx(p);
	return class_id < CLASS_NR && tctx && tctx->running_cpu == cpu &&
	       tctx->class_id == class_id;
}

static bool cap_task_slice(struct cpu_ctx *cpuc, s32 cpu,
			   struct task_struct *curr, u64 max_runtime,
			   bool *shortened)
{
	u64 slice;

	if (!task_matches_run(cpuc, cpu, curr))
		return false;
	slice = READ_ONCE(curr->scx.slice);
	if (slice > max_runtime) {
		scx_bpf_task_set_slice(curr, max_runtime);
		*shortened = true;
		if (max_runtime && diagnostic_counters)
			__sync_fetch_and_add(&nr_arbitration_slice_caps, 1);
	}
	return true;
}

/* Callers own the target rq. A zero cap needs only a reschedule notification. */
static bool cap_cpu_slice(struct cpu_ctx *cpuc, s32 cpu,
			  struct task_struct *curr, u64 max_runtime)
{
	bool shortened = false;
	bool valid;

	if (max_runtime == ~0ULL)
		return true;
	if (curr) {
		valid = cap_task_slice(cpuc, cpu, curr, max_runtime, &shortened);
	} else {
		bpf_rcu_read_lock();
		curr = __COMPAT_scx_bpf_cpu_curr(cpu);
		valid = cap_task_slice(cpuc, cpu, curr, max_runtime, &shortened);
		bpf_rcu_read_unlock();
	}
	if (!max_runtime) {
		if (valid && shortened)
			scx_bpf_kick_cpu(cpu, 0);
		return valid && shortened;
	}
	return valid;
}

/*
 * Return the remaining runtime before a BATCH task handoff. Zero means now and
 * U64_MAX means that the current task remains competitive with the DSQ head.
 */
static u64 batch_handoff_budget(struct cpu_ctx *cpuc, s32 cpu, u64 now,
				u32 incoming_class, u64 incoming_vruntime)
{
	struct task_struct *curr;
	struct task_ctx *tctx;
	u64 current_vruntime, elapsed, granularity, head_vruntime, started;
	u64 budget = ~0ULL;
	bool has_head;

	if (READ_ONCE(cpuc->running_class) != CLASS_BATCH)
		return ~0ULL;
	started = READ_ONCE(cpuc->running_since);
	if (!started)
		return ~0ULL;

	has_head = dsq_head_vruntime(CLASS_DSQ_ID(CLASS_BATCH, cpu),
				      &head_vruntime);
	if (incoming_class == CLASS_BATCH &&
	    (!has_head || time_before(incoming_vruntime, head_vruntime))) {
		head_vruntime = incoming_vruntime;
		has_head = true;
	}
	if (!has_head)
		return ~0ULL;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!curr || curr->flags & PF_IDLE)
		goto out;
	tctx = lookup_task_ctx(curr);
	if (!tctx || tctx->class_id != CLASS_BATCH ||
	    tctx->running_cpu != cpu)
		goto out;
	elapsed = now > started ? now - started : 0;
	current_vruntime = tctx->vruntime +
		scale_by_task_weight_inverse(curr, elapsed);
	granularity = scale_by_task_weight_inverse(
		curr, batch_preempt_granularity_ns);
	if ((s64)(current_vruntime - head_vruntime) <= (s64)granularity)
		goto out;
	budget = elapsed < batch_min_run_ns ? batch_min_run_ns - elapsed : 0;
out:
	bpf_rcu_read_unlock();
	return budget;
}

/* The caller must own @cpu's rq; remote paths may only move queued tasks. */
static void arbitrate_locked_cpu(s32 cpu, struct task_struct *curr,
				 u32 incoming_class, u64 incoming_vruntime)
{
	struct class_candidates candidates;
	struct class_decision decision;
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 batch_budget, budget, now;
	u32 current, mask;

	if (!cpuc)
		return;
	current = READ_ONCE(cpuc->running_class);
	now = bpf_ktime_get_ns();

	mask = local_available_mask(cpu, cpuc, true);
	/* DSQ inserts are not visible to queue queries until enqueue() returns. */
	if (incoming_class < CLASS_NR)
		mask |= CLASS_MASK(incoming_class);
	candidates.available_mask = mask;
	candidates.current_class = current;
	decide_class(cpuc, now, &candidates, &decision);
	if (decision.winner >= CLASS_NR)
		return;
	record_mixed_class_decision(mask, &decision);

	if (decision.winner != current) {
		if (current == CLASS_BATCH &&
		    decision.winner == CLASS_LATENCY) {
			__sync_fetch_and_add(&nr_latency_handoffs, 1);
			if (cap_cpu_slice(cpuc, cpu, curr, 0))
				__sync_fetch_and_add(&nr_latency_preempts, 1);
		} else {
			cap_cpu_slice(cpuc, cpu, curr, 0);
		}
		return;
	}

	budget = decision.run_for_ns;
	if (decision.reason == DECISION_BATCH_MIN_RUN &&
	    diagnostic_counters)
		__sync_fetch_and_add(&nr_latency_handoff_deferred, 1);

	if (current == CLASS_BATCH && decision.winner == CLASS_BATCH) {
		batch_budget = batch_handoff_budget(cpuc, cpu, now,
					    incoming_class, incoming_vruntime);
		if (!batch_budget) {
			if (cap_cpu_slice(cpuc, cpu, curr, 0) &&
			    diagnostic_counters)
				__sync_fetch_and_add(&nr_batch_vruntime_preempts, 1);
			return;
		}
		if (batch_budget < budget)
			budget = batch_budget;
	}
	cap_cpu_slice(cpuc, cpu, curr, budget);
}

/* Forge's default wakee policy: seed idle selection from the previous CPU. */
static s32 latency_pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
				 u64 wake_flags, bool from_enqueue)
{
	bool is_idle = false;
	s32 cpu;

	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		if (from_enqueue)
			return -EBUSY;
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return is_idle ? cpu : -EBUSY;
	}

	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

static bool latency_try_direct_dispatch(struct task_struct *p,
					struct task_ctx *tctx, s32 prev_cpu,
					u64 enq_flags)
{
	bool cpu_selected = __COMPAT_is_enq_cpu_selected(enq_flags);
	bool waking_after_select = cpu_selected && !scx_bpf_task_running(p);
	bool do_migrate = task_should_kick(p, enq_flags);
	bool is_reenq = enq_flags & SCX_ENQ_REENQ;
	s32 cpu;

	if (!(do_migrate || waking_after_select || is_reenq ||
	      !is_cpu_idle(prev_cpu)))
		return false;

	if (is_pcpu_task(p)) {
		if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return false;
		cpu = prev_cpu;
	} else {
		cpu = latency_pick_idle_cpu(p, prev_cpu, 0, true);
		if (cpu < 0)
			return false;
	}
	if (cpu_has_local_work(cpu, lookup_cpu_ctx(cpu)))
		return false;
	if (!task_rebase_vruntime(p, tctx, cpu,
				 enq_flags & SCX_ENQ_WAKEUP))
		return false;
	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
				latency_slice_ns, enq_flags))
		return false;
	/* A successful idle placement becomes the new stable wakeup anchor. */
	tctx->home_cpu = cpu;
	tctx->state = TASK_DISPATCHED;
	__sync_fetch_and_add(&nr_direct_dispatches, 1);
	return true;
}

s32 BPF_STRUCT_OPS(agent_classed_select_cpu, struct task_struct *p,
				   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu, this_cpu;

	tctx = lookup_task_ctx(p);
	if (!tctx) {
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return cpu;
	}

	prev_cpu = task_home_cpu(p, tctx, prev_cpu);
	if (tctx->class_id != CLASS_LATENCY) {
		cpu = batch_pick_cpu(p, tctx, prev_cpu, wake_flags, &is_idle);
		if (task_cpu_allowed(p, cpu))
			tctx->home_cpu = cpu;
		return cpu;
	}

	this_cpu = bpf_get_smp_processor_id();
	if (!bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr))
		this_cpu = -ENOENT;
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = this_cpu >= 0 ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	cpu = latency_pick_idle_cpu(p, prev_cpu, wake_flags, false);
	if (cpu >= 0) {
		tctx->home_cpu = cpu;
		if (cpu_has_local_work(cpu, lookup_cpu_ctx(cpu)))
			return cpu;
		if (task_rebase_vruntime(p, tctx, cpu, true) &&
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, latency_slice_ns, 0)) {
			tctx->state = TASK_DISPATCHED;
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
		return cpu;
	}

	return prev_cpu;
}

void BPF_STRUCT_OPS(agent_classed_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	u32 class_id;
	u64 key, dsq_id, slice;
	s32 cpu;

	tctx = lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, batch_min_epoch_ns,
				   enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}

	reconcile_before_enqueue(tctx);
	class_id = sanitize_class(tctx->class_id);
	tctx->class_id = class_id;
	cctx = lookup_class_ctx(class_id);
	if (!cctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, batch_min_epoch_ns,
				   enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}

	/* ops.enqueue() owns this task rq; its CPU is the user-DSQ owner. */
	cpu = scx_bpf_task_cpu(p);
	if (!task_cpu_allowed(p, tctx->home_cpu) && task_cpu_allowed(p, cpu))
		tctx->home_cpu = cpu;

	if (!task_cpu_allowed(p, cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, class_slice(class_id), enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}

	if (class_id == CLASS_LATENCY) {
		if (diagnostic_counters) {
			if (enq_flags & SCX_ENQ_WAKEUP)
				__sync_fetch_and_add(&nr_latency_wakeup_enqueues, 1);
			else
				__sync_fetch_and_add(&nr_latency_non_wakeup_enqueues, 1);
		}
		/* Cover queued wakeups and per-CPU tasks which skip select_cpu(). */
		if (latency_try_direct_dispatch(p, tctx, cpu, enq_flags))
			return;
	}

	if (!READ_ONCE(cctx->nr_queued) && !READ_ONCE(cctx->nr_running))
		activate_class(class_id, cctx);
	if (!prepare_task_enqueue(p, tctx, cpu, enq_flags, &key, &slice)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, class_slice(class_id),
				   enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}
	dsq_id = CLASS_DSQ_ID(class_id, cpu);
	tctx->state = TASK_ENQUEUED;
	tctx->queued_cpu = cpu;
	__sync_fetch_and_add(&cctx->nr_queued, 1);
	cpu_queue_inc(cpu, class_id);

	if (!scx_bpf_dsq_insert_vtime(p, dsq_id, slice, key,
				       enq_flags)) {
		task_queue_dec(tctx);
		tctx->state = TASK_NONE;
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, class_slice(class_id), enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}
	__sync_fetch_and_add(&nr_enqueues, 1);
	if (class_id == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_latency_enqueues, 1);
	else
		__sync_fetch_and_add(&nr_batch_enqueues, 1);

	arbitrate_locked_cpu(cpu, NULL, class_id, key);
	if (task_should_kick(p, enq_flags))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(agent_classed_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_dequeues, 1);
	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Every departure from a user DSQ owns exactly one queued decrement. */
	if (tctx->state == TASK_ENQUEUED) {
		task_queue_dec(tctx);
		if (deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_CORE_SCHED_EXEC |
					 SCX_DEQ_SCHED_CHANGE)) {
			tctx->state = TASK_NONE;
		} else {
			tctx->state = TASK_DISPATCHED;
		}
	} else if (deq_flags & SCX_DEQ_SCHED_CHANGE) {
		tctx->state = TASK_NONE;
	} else if (tctx->state != TASK_DISPATCHED &&
		   tctx->state != TASK_NONE) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		dbg_msg("%s[%d]: unexpected dequeue state %d",
			p->comm, p->pid, tctx->state);
	}
}

static void record_local_dispatch(u32 class_id)
{
	__sync_fetch_and_add(&nr_local_dispatches, 1);
	if (!diagnostic_counters)
		return;
	if (class_id == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_latency_local_dispatches, 1);
	else
		__sync_fetch_and_add(&nr_batch_local_dispatches, 1);
}

static void record_remote_dispatch(void)
{
	__sync_fetch_and_add(&nr_remote_dispatches, 1);
}

static bool cpu_has_local_work(s32 cpu, const struct cpu_ctx *cpuc)
{
	if (!cpuc)
		return true;
	return scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) > 0 ||
	       READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_queued) ||
	       READ_ONCE(cpuc->entity[CLASS_BATCH].nr_queued) ||
	       READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_running) ||
	       READ_ONCE(cpuc->entity[CLASS_BATCH].nr_running);
}

static bool dispatch_from_cpu(s32 dst_cpu, s32 src_cpu, u32 class_id,
			      bool remote, u64 max_slice)
{
	struct cpu_ctx *dst = lookup_cpu_ctx(dst_cpu);
	struct cpu_ctx *src = lookup_cpu_ctx(src_cpu);
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();
	u64 slice;
	bool moved = false;

	if (!dst || !src || class_id >= CLASS_NR)
		return false;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, CLASS_DSQ_ID(class_id, src_cpu), 0) {
		struct task_ctx *tctx;

		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		tctx = lookup_task_ctx(p);
		if (!tctx || tctx->class_id != class_id ||
		    tctx->queued_cpu != src_cpu ||
		    tctx->state != TASK_ENQUEUED) {
			bpf_task_release(p);
			continue;
		}
		if (remote && tctx->last_migrate_at &&
		    now - tctx->last_migrate_at < MIGRATION_COOLDOWN_NS) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_cooldown, 1);
			bpf_task_release(p);
			continue;
		}

		slice = class_id == CLASS_LATENCY ? latency_slice_ns :
			batch_start_epoch(tctx, src, false);
		if (!slice)
			slice = class_slice(class_id);
		if (max_slice < slice) {
			slice = max_slice ? max_slice : 1;
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_arbitration_slice_caps, 1);
		}
		scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, slice);
		moved = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
					 SCX_DSQ_LOCAL_ON | dst_cpu, 0);
		if (moved) {
			task_queue_dec(tctx);
			if (remote &&
			    !task_rebase_vruntime(p, tctx, dst_cpu, false))
				__sync_fetch_and_add(&nr_task_state_errors, 1);
			vtime_set_max(&dst->entity[class_id].task_vtime,
				      tctx->vruntime);
			if (remote)
				tctx->home_cpu = dst_cpu;
			tctx->state = TASK_DISPATCHED;
		}
		bpf_task_release(p);
		break;
	}
	bpf_rcu_read_unlock();

	if (!moved)
		return false;
	if (remote)
		record_remote_dispatch();
	else
		record_local_dispatch(class_id);
	return true;
}

static u64 cpu_queued_load(const struct cpu_ctx *cpuc)
{
	if (!cpuc)
		return ~0ULL;
	return (READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_queued) +
		READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_running)) *
			latency_slice_ns +
	       (READ_ONCE(cpuc->entity[CLASS_BATCH].nr_queued) +
		READ_ONCE(cpuc->entity[CLASS_BATCH].nr_running)) *
			batch_min_epoch_ns;
}

static u64 cpu_runnable_count(const struct cpu_ctx *cpuc)
{
	return READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_queued) +
	       READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_running) +
	       READ_ONCE(cpuc->entity[CLASS_BATCH].nr_queued) +
	       READ_ONCE(cpuc->entity[CLASS_BATCH].nr_running);
}

static bool acquire_source_claim(struct cpu_ctx *cpuc, u64 claim)
{
	return __sync_val_compare_and_swap(&cpuc->steal_claim, 0, claim) == 0;
}

static void release_source_claim(struct cpu_ctx *cpuc, u64 claim)
{
	if (__sync_val_compare_and_swap(&cpuc->steal_claim, claim, 0) != claim)
		__sync_fetch_and_add(&nr_task_state_errors, 1);
}

static bool dispatch_local_claimed(s32 cpu, u32 class_id, u64 max_slice,
				   bool *claim_busy)
{
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 claim = ((u64)cpu + 1) << 32 | 1;
	bool moved;

	*claim_busy = false;
	if (!cpuc || !acquire_source_claim(cpuc, claim)) {
		if (cpuc)
			*claim_busy = true;
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_claim_busy, 1);
		return false;
	}
	moved = dispatch_from_cpu(cpu, cpu, class_id, false, max_slice);
	release_source_claim(cpuc, claim);
	return moved;
}

static bool gated_steal(s32 dst_cpu, u32 class_id)
{
	struct cpu_ctx *dst = lookup_cpu_ctx(dst_cpu);
	struct cpu_class_ctx *src_entity;
	struct cpu_ctx *src;
	u64 cursor, claim, src_load, dst_load, required_gap, surplus;
	u64 best_surplus = 0;
	u64 queued;
	s32 best_cpu = -1;
	s32 src_cpu;
	u32 best_tier = 3;
	u32 tier;
	bool moved;
	int i;

	if (class_id >= CLASS_NR)
		return false;
	if (!dst || nr_cpu_ids <= 1 || !steal_scan)
		return false;
	if (cpu_has_local_work(dst_cpu, dst)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_local_busy, 1);
		return false;
	}

	cursor = __sync_fetch_and_add(&steal_cursor, 1);
	dst_load = capacity_scale_load(dst_cpu, cpu_queued_load(dst));
	bpf_for(i, 0, AGENT_STEAL_SCAN_MAX) {
		if (i >= steal_scan || i >= nr_cpu_ids - 1)
			break;
		src_cpu = (dst_cpu + 1 +
			   (cursor + i) % (nr_cpu_ids - 1)) % nr_cpu_ids;
		tier = topology_tier(dst_cpu, src_cpu);
		if (tier > best_tier)
			continue;
		src = lookup_cpu_ctx(src_cpu);
		if (!src)
			continue;
		src_entity = cpu_class_entity(src, class_id);
		if (!src_entity)
			continue;
		queued = READ_ONCE(src_entity->nr_queued);
		if (!queued || cpu_runnable_count(src) < 2) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_source_short, 1);
			continue;
		}
		if (scx_bpf_dsq_nr_queued(CLASS_DSQ_ID(class_id, src_cpu)) <= 0)
			continue;
		src_load = capacity_scale_load(src_cpu, cpu_queued_load(src));
		required_gap = class_slice(class_id) +
			topology_migration_cost(dst_cpu, src_cpu);
		if (src_load <= dst_load || src_load - dst_load < required_gap) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_load_gap, 1);
			continue;
		}
		surplus = src_load - dst_load - required_gap;
		if (best_cpu < 0 || tier < best_tier ||
		    (tier == best_tier && surplus > best_surplus)) {
			best_cpu = src_cpu;
			best_tier = tier;
			best_surplus = surplus;
		}
	}

	if (best_cpu < 0)
		return false;
	src = lookup_cpu_ctx(best_cpu);
	claim = ((u64)dst_cpu + 1) << 32 | 2;
	if (!src || !acquire_source_claim(src, claim)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_claim_busy, 1);
		return false;
	}

	/* Serialize only the selected source, then revalidate the sampled surplus. */
	if (cpu_has_local_work(dst_cpu, dst)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_local_busy, 1);
		release_source_claim(src, claim);
		return false;
	}
	src_entity = cpu_class_entity(src, class_id);
	queued = src_entity ? READ_ONCE(src_entity->nr_queued) : 0;
	if (!queued || cpu_runnable_count(src) < 2) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_source_short, 1);
		release_source_claim(src, claim);
		return false;
	}
	if (scx_bpf_dsq_nr_queued(CLASS_DSQ_ID(class_id, best_cpu)) <= 0) {
		release_source_claim(src, claim);
		return false;
	}
	dst_load = capacity_scale_load(dst_cpu, cpu_queued_load(dst));
	src_load = capacity_scale_load(best_cpu, cpu_queued_load(src));
	required_gap = class_slice(class_id) +
		topology_migration_cost(dst_cpu, best_cpu);
	if (src_load <= dst_load || src_load - dst_load < required_gap) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_load_gap, 1);
		release_source_claim(src, claim);
		return false;
	}
	if (diagnostic_counters)
		__sync_fetch_and_add(&nr_gated_steal_attempts, 1);
	moved = dispatch_from_cpu(dst_cpu, best_cpu, class_id, true, ~0ULL);
	release_source_claim(src, claim);
	if (moved && diagnostic_counters)
		__sync_fetch_and_add(&nr_gated_steal_successes, 1);
	return moved;
}

static s32 pick_remote_class(struct cpu_ctx *cpuc, u32 *second)
{
	bool lat_queued = READ_ONCE(classes[CLASS_LATENCY].nr_queued) > 0;
	bool batch_queued = READ_ONCE(classes[CLASS_BATCH].nr_queued) > 0;
	s32 first;

	*second = CLASS_NR;
	if (!lat_queued && !batch_queued)
		return -ENOENT;
	if (lat_queued)
		activate_cpu_class(CLASS_LATENCY, cpuc,
				   &cpuc->entity[CLASS_LATENCY]);
	if (batch_queued)
		activate_cpu_class(CLASS_BATCH, cpuc,
				   &cpuc->entity[CLASS_BATCH]);
	if (lat_queued != batch_queued) {
		first = lat_queued ? CLASS_LATENCY : CLASS_BATCH;
		return first;
	}
	first = class_winner(READ_ONCE(classes[CLASS_LATENCY].vruntime),
			     READ_ONCE(classes[CLASS_BATCH].vruntime));
	*second = first == CLASS_LATENCY ? CLASS_BATCH : CLASS_LATENCY;
	return first;
}

static bool charge_runtime(struct task_struct *p, struct task_ctx *tctx,
			   struct cpu_ctx *cpuc, u64 runtime, bool runnable)
{
	struct class_ctx *cctx;
	struct cpu_class_ctx *entity;
	u64 batch_service, class_delta, new_vruntime, old_target, remaining;
	u32 class_id = tctx->class_id;

	if (!runtime)
		return true;
	if (!cpuc || class_id >= CLASS_NR)
		return false;
	cctx = lookup_class_ctx(class_id);
	entity = cpu_class_entity(cpuc, class_id);
	if (!cctx || !entity)
		return false;

	tctx->vruntime += scale_by_task_weight_inverse(p, runtime);
	if (class_id == CLASS_LATENCY) {
		WRITE_ONCE(cpuc->batch_service_since_latency, 0);
		if (~0ULL - tctx->latency_burst_used_ns < runtime)
			tctx->latency_burst_used_ns = ~0ULL;
		else
			tctx->latency_burst_used_ns += runtime;
		__sync_fetch_and_add(&latency_runtime_ns, runtime);
	} else {
		batch_service = READ_ONCE(cpuc->batch_service_since_latency);
		WRITE_ONCE(cpuc->batch_service_since_latency,
			   ~0ULL - batch_service < runtime ?
			   ~0ULL : batch_service + runtime);
		remaining = tctx->batch_epoch_remaining_ns;
		if (remaining && runtime >= remaining) {
			tctx->batch_epoch_remaining_ns = 0;
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_batch_epoch_exhaustions, 1);
			if (runnable) {
				old_target = tctx->batch_epoch_target_ns;
				tctx->batch_epoch_target_ns = next_batch_epoch(tctx);
				if (diagnostic_counters &&
				    tctx->batch_epoch_target_ns > old_target)
					__sync_fetch_and_add(
						&nr_batch_epoch_grows, 1);
			}
		} else if (remaining) {
			tctx->batch_epoch_remaining_ns = remaining - runtime;
		} else {
			__sync_fetch_and_add(&nr_task_state_errors, 1);
		}
		__sync_fetch_and_add(&batch_runtime_ns, runtime);
	}

	class_delta = class_vruntime_delta(class_id, runtime);
	new_vruntime = __sync_fetch_and_add(&cctx->vruntime,
					    class_delta) + class_delta;
	vtime_set_max(&class_vtime_now, new_vruntime);
	new_vruntime = __sync_fetch_and_add(&entity->vruntime,
					    class_delta) + class_delta;
	vtime_set_max(&cpuc->class_vtime_now, new_vruntime);
	return true;
}

static bool try_keep_running(s32 cpu, struct task_struct *prev,
			     bool work_conserving)
{
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	struct task_ctx *tctx;
	u64 current_vruntime, elapsed, granularity, head_vruntime, now, slice, used;
	u64 remaining;
	u32 class_id;
	bool has_head;

	if (!cpuc || !prev || !is_task_queued(prev) ||
	    READ_ONCE(prev->scx.slice))
		return false;
	tctx = lookup_task_ctx(prev);
	if (!tctx || !tctx->last_run_at || tctx->running_cpu != cpu)
		return false;
	class_id = sanitize_class(tctx->class_id);

	now = bpf_ktime_get_ns();
	elapsed = now > tctx->last_run_at ? now - tctx->last_run_at : 0;
	current_vruntime = tctx->vruntime +
		scale_by_task_weight_inverse(prev, elapsed);
	has_head = dsq_head_vruntime(CLASS_DSQ_ID(class_id, cpu),
				     &head_vruntime);
	if (has_head && !work_conserving) {
		if (class_id == CLASS_LATENCY) {
			if (time_before(head_vruntime, current_vruntime)) {
				if (diagnostic_counters)
					__sync_fetch_and_add(
						&nr_latency_continuation_history_denied,
						1);
				return false;
			}
		} else {
			granularity = scale_by_task_weight_inverse(
				prev, batch_preempt_granularity_ns);
			if ((s64)(current_vruntime - head_vruntime) >
			    (s64)granularity)
				return false;
		}
	}

	if (class_id == CLASS_LATENCY) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_latency_slice_expirations, 1);
		used = tctx->latency_burst_used_ns;
		if (~0ULL - used < elapsed)
			used = ~0ULL;
		else
			used += elapsed;
		if (used >= latency_burst_budget_ns && !work_conserving) {
			if (diagnostic_counters)
				__sync_fetch_and_add(
					&nr_latency_continuation_budget_exhausted,
					1);
			return false;
		}
		slice = used < latency_burst_budget_ns ?
			latency_burst_budget_ns - used : latency_slice_ns;
		if (!slice || slice > latency_slice_ns)
			slice = latency_slice_ns;
		scx_bpf_task_set_slice(prev, slice);
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_latency_continuations, 1);
		arbitrate_locked_cpu(cpu, prev, CLASS_NR, 0);
		return true;
	}

	remaining = tctx->batch_epoch_remaining_ns;
	if (remaining > elapsed) {
		scx_bpf_task_set_slice(prev, remaining - elapsed);
		arbitrate_locked_cpu(cpu, prev, CLASS_NR, 0);
		return true;
	}
	if (has_head && !work_conserving)
		return false;

	if (!charge_runtime(prev, tctx, cpuc, elapsed, true))
		return false;
	WRITE_ONCE(cpuc->running_since, now);
	tctx->last_run_at = now;
	vtime_set_max(&cpuc->entity[CLASS_BATCH].task_vtime,
		      tctx->vruntime);
	slice = batch_start_epoch(tctx, cpuc, false);
	if (slice)
		scx_bpf_task_set_slice(prev, slice);
	if (!slice)
		return false;
	arbitrate_locked_cpu(cpu, prev, CLASS_NR, 0);
	return true;
}

void BPF_STRUCT_OPS(agent_classed_dispatch, s32 cpu, struct task_struct *prev)
{
	struct class_candidates candidates;
	struct class_decision decision;
	struct task_ctx *prev_ctx = NULL;
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 now;
	u32 current = CLASS_NR;
	u32 mask;
	bool claim_busy = false;
	bool local_claim_busy = false;

	if (!cpuc)
		return;
	if (prev && is_task_queued(prev)) {
		prev_ctx = lookup_task_ctx(prev);
		if (prev_ctx && prev_ctx->running_cpu == cpu &&
		    prev_ctx->class_id < CLASS_NR) {
			current = prev_ctx->class_id;
		}
	}

	mask = local_available_mask(cpu, cpuc, false);
	if (current < CLASS_NR)
		mask |= CLASS_MASK(current);
	now = bpf_ktime_get_ns();
	candidates.available_mask = mask;
	candidates.current_class = current;
	decide_class(cpuc, now, &candidates, &decision);
	record_mixed_class_decision(mask, &decision);

	if (decision.winner < CLASS_NR) {
		if (diagnostic_counters) {
			if ((mask & (CLASS_MASK(CLASS_LATENCY) |
				     CLASS_MASK(CLASS_BATCH))) ==
			    (CLASS_MASK(CLASS_LATENCY) |
			     CLASS_MASK(CLASS_BATCH)))
				__sync_fetch_and_add(
					&nr_mixed_class_arbitrations, 1);
			else
				__sync_fetch_and_add(
					&nr_single_class_fastpaths, 1);
			if (current == CLASS_LATENCY &&
			    decision.winner != CLASS_LATENCY)
				__sync_fetch_and_add(
					&nr_latency_continuation_class_denied, 1);
		}
		if (current == decision.winner &&
		    try_keep_running(cpu, prev, false))
			return;
		if (dispatch_local_claimed(cpu, decision.winner,
						   decision.run_for_ns,
						   &claim_busy))
			return;
		local_claim_busy |= claim_busy;
		if (decision.fallback < CLASS_NR &&
		    dispatch_local_claimed(cpu, decision.fallback, ~0ULL,
					   &claim_busy)) {
			__sync_fetch_and_add(&nr_fallback_dispatches, 1);
			return;
		}
		local_claim_busy |= claim_busy;

		/* A queue can change after arbitration; retry only still-present classes. */
		mask = local_available_mask(cpu, cpuc, false);
		if ((mask & CLASS_MASK(decision.winner)) &&
		    dispatch_local_claimed(cpu, decision.winner,
						   decision.run_for_ns,
						   &claim_busy))
			return;
		local_claim_busy |= claim_busy;
		if (decision.fallback < CLASS_NR &&
		    (mask & CLASS_MASK(decision.fallback)) &&
		    dispatch_local_claimed(cpu, decision.fallback, ~0ULL,
					   &claim_busy)) {
			__sync_fetch_and_add(&nr_fallback_dispatches, 1);
			return;
		}
		local_claim_busy |= claim_busy;
	}

	/* A runnable local task is the final work-conserving fallback. */
	if (current < CLASS_NR && try_keep_running(cpu, prev, true)) {
		__sync_fetch_and_add(&nr_fallback_dispatches, 1);
		return;
	}

	mask = local_available_mask(cpu, cpuc, false);
	if (mask) {
		if (local_claim_busy)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}
	{
		u32 second;
		s32 first = pick_remote_class(cpuc, &second);

		if (first >= 0 && gated_steal(cpu, first))
			return;
		if (second < CLASS_NR && gated_steal(cpu, second))
			__sync_fetch_and_add(&nr_fallback_dispatches, 1);
	}
}
static void advance_task_vtime(struct cpu_ctx *cpuc, s32 cpu,
				       u32 class_id, u64 task_vruntime)
{
	u64 head_vruntime;
	u64 frontier = task_vruntime;

	if (dsq_head_vruntime(CLASS_DSQ_ID(class_id, cpu), &head_vruntime) &&
	    time_before(head_vruntime, frontier))
		frontier = head_vruntime;
	vtime_set_max(&cpuc->entity[class_id].task_vtime, frontier);
}

void BPF_STRUCT_OPS(agent_classed_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc;
	u64 now, slice;
	bool migrated;
	s32 cpu;
	u32 class_id;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	class_id = READ_ONCE(tctx->class_id);
	if (class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	cctx = lookup_class_ctx(class_id);
	if (!cctx)
		return;

	now = bpf_ktime_get_ns();
	cpu = scx_bpf_task_cpu(p);
	cpuc = lookup_cpu_ctx(cpu);
	if (!cpuc)
		return;
	entity = cpu_class_entity(cpuc, class_id);
	if (!entity)
		return;

	/* Core scheduling may consume a user DSQ without dispatch_from_cpu(). */
	if (tctx->state == TASK_ENQUEUED || tctx->queued_cpu >= 0) {
		task_queue_dec(tctx);
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_running_queue_reconciles, 1);
	}
	if (!task_rebase_vruntime(p, tctx, cpu, false))
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	if (class_id == CLASS_BATCH) {
		slice = batch_start_epoch(tctx, cpuc, true);
		if (!slice)
			slice = batch_min_epoch_ns;
		if (!READ_ONCE(p->scx.slice) ||
		    READ_ONCE(p->scx.slice) > slice)
			scx_bpf_task_set_slice(p, slice);
	} else if (!READ_ONCE(p->scx.slice)) {
		scx_bpf_task_set_slice(p, latency_slice_ns);
	}

	if (!READ_ONCE(cctx->nr_queued) && !READ_ONCE(cctx->nr_running))
		activate_class(class_id, cctx);
	migrated = tctx->last_cpu >= 0 && tctx->last_cpu != cpu;
	if (diagnostic_counters && migrated) {
		if (class_id == CLASS_LATENCY)
			__sync_fetch_and_add(&nr_latency_migrations, 1);
		else
			__sync_fetch_and_add(&nr_batch_migrations, 1);
	}
	if (migrated)
		tctx->last_migrate_at = now;
	if (!task_cpu_allowed(p, tctx->home_cpu))
		tctx->home_cpu = cpu;
	tctx->last_cpu = cpu;
	tctx->running_cpu = cpu;
	tctx->queued_cpu = -1;
	tctx->state = TASK_NONE;
	tctx->last_run_at = now;
	vtime_set_max(&entity->task_vtime, tctx->vruntime);

	WRITE_ONCE(cpuc->running_since, now);
	WRITE_ONCE(cpuc->running_class, class_id);
	__sync_fetch_and_add(&cctx->nr_running, 1);
	__sync_fetch_and_add(&entity->nr_running, 1);
	arbitrate_locked_cpu(cpu, p, CLASS_NR, 0);
}

void BPF_STRUCT_OPS(agent_classed_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc;
	u64 now, old_running, runtime;
	s32 cpu;
	u32 class_id;

	tctx = lookup_task_ctx(p);
	if (!tctx || !tctx->last_run_at)
		return;
	class_id = READ_ONCE(tctx->class_id);
	if (class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	cctx = lookup_class_ctx(class_id);
	cpu = tctx->running_cpu;
	cpuc = lookup_cpu_ctx(cpu);
	entity = cpu_class_entity(cpuc, class_id);
	if (!cctx || !cpuc || !entity) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}

	now = bpf_ktime_get_ns();
	runtime = now > tctx->last_run_at ? now - tctx->last_run_at : 1;

	WRITE_ONCE(cpuc->running_class, CLASS_NR);
	WRITE_ONCE(cpuc->running_since, 0);
	if (!charge_runtime(p, tctx, cpuc, runtime, runnable))
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	advance_task_vtime(cpuc, cpu, class_id, tctx->vruntime);

	if (class_id == CLASS_LATENCY && diagnostic_counters) {
		if (runnable)
			__sync_fetch_and_add(&nr_latency_stops_runnable, 1);
		else
			__sync_fetch_and_add(&nr_latency_stops_quiescent, 1);
	}
	if (class_id == CLASS_BATCH && !runnable)
		reset_batch_epoch(tctx);

	old_running = __sync_fetch_and_sub(&entity->nr_running, 1);
	if (!old_running) {
		__sync_fetch_and_add(&entity->nr_running, 1);
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	}
	old_running = __sync_fetch_and_sub(&cctx->nr_running, 1);
	if (!old_running) {
		__sync_fetch_and_add(&cctx->nr_running, 1);
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	}
	tctx->last_run_at = 0;
	tctx->running_cpu = -1;
}
void BPF_STRUCT_OPS(agent_classed_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	u32 class_id;

	if (!tctx)
		return;
	class_id = classify_task(p);
	if (class_id == CLASS_LATENCY && (enq_flags & SCX_ENQ_WAKEUP))
		tctx->latency_burst_used_ns = 0;
	if (class_id != tctx->class_id) {
		if (tctx->state == TASK_ENQUEUED) {
			task_queue_dec(tctx);
			tctx->state = TASK_NONE;
		}
		tctx->vruntime = 0;
		tctx->vtime_cpu = -1;
		tctx->sleep_vlag = 0;
		tctx->has_sleep_vlag = false;
		tctx->latency_burst_used_ns = 0;
		reset_batch_epoch(tctx);
	}
	tctx->class_id = class_id;
}

void BPF_STRUCT_OPS(agent_classed_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);

	if (!tctx)
		return;
	if (tctx->state == TASK_ENQUEUED)
		task_queue_dec(tctx);
	if (deq_flags & SCX_DEQ_SLEEP) {
		if (tctx->class_id == CLASS_LATENCY)
			latency_save_sleep_vlag(p, tctx);
		else if (tctx->class_id == CLASS_BATCH)
			reset_batch_epoch(tctx);
	}
	tctx->state = TASK_NONE;
	tctx->queued_cpu = -1;
}

static void reset_task_state(struct task_ctx *tctx, u32 class_id)
{
	tctx->vruntime = 0;
	tctx->last_run_at = 0;
	tctx->last_migrate_at = 0;
	tctx->latency_burst_used_ns = 0;
	tctx->batch_epoch_target_ns = batch_min_epoch_ns;
	tctx->batch_epoch_remaining_ns = 0;
	tctx->sleep_vlag = 0;
	tctx->last_cpu = -1;
	tctx->home_cpu = -1;
	tctx->vtime_cpu = -1;
	tctx->queued_cpu = -1;
	tctx->running_cpu = -1;
	tctx->class_id = class_id;
	tctx->has_sleep_vlag = false;
	tctx->state = TASK_NONE;
}

void BPF_STRUCT_OPS(agent_classed_enable, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);

	if (!tctx)
		return;
	if (tctx->state == TASK_ENQUEUED)
		task_queue_dec(tctx);
	reset_task_state(tctx, classify_task(p));
}

void BPF_STRUCT_OPS(agent_classed_disable, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);

	if (!tctx)
		return;
	if (tctx->state == TASK_ENQUEUED)
		task_queue_dec(tctx);
	reset_batch_epoch(tctx);
	tctx->vtime_cpu = -1;
	tctx->state = TASK_NONE;
	tctx->queued_cpu = -1;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(agent_classed_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	(void)args;
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	reset_task_state(tctx, classify_task(p));
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(agent_classed_init)
{
	struct cpu_ctx *cpuc;
	s32 cpu, ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (!nr_cpu_ids || nr_cpu_ids > AGENT_MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids %llu exceeds supported range 1..%u",
			      nr_cpu_ids, AGENT_MAX_CPUS);
		return -E2BIG;
	}
	if (!latency_slice_ns || latency_slice_ns > ~0ULL / 2 ||
	    latency_burst_budget_ns < latency_slice_ns ||
	    latency_burst_budget_ns > latency_slice_ns * 2 ||
	    class_max_debt_ns > 0x7fffffffffffffffULL ||
	    !batch_min_epoch_ns ||
	    batch_max_epoch_ns < batch_min_epoch_ns ||
	    batch_min_epoch_ns > ~0ULL / 8 ||
	    batch_max_epoch_ns > batch_min_epoch_ns * 8 ||
	    batch_round_ns < batch_min_epoch_ns ||
	    batch_min_run_ns > batch_min_epoch_ns ||
	    !batch_preempt_granularity_ns ||
	    same_llc_migration_cost_ns > same_node_migration_cost_ns ||
	    same_node_migration_cost_ns > remote_node_migration_cost_ns ||
	    !latency_weight || !batch_weight || default_class >= CLASS_NR ||
	    steal_scan > AGENT_STEAL_SCAN_MAX) {
		scx_bpf_error("invalid scheduler configuration");
		return -EINVAL;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		ret = scx_bpf_create_dsq(CLASS_DSQ_ID(CLASS_LATENCY, cpu), -1);
		if (ret) {
			scx_bpf_error("failed to create latency DSQ for CPU %d: %d",
				      cpu, ret);
			return ret;
		}
		ret = scx_bpf_create_dsq(CLASS_DSQ_ID(CLASS_BATCH, cpu), -1);
		if (ret) {
			scx_bpf_error("failed to create batch DSQ for CPU %d: %d",
				      cpu, ret);
			return ret;
		}
		cpuc = lookup_cpu_ctx(cpu);
		if (!cpuc)
			return -ENOENT;
		WRITE_ONCE(cpuc->running_class, CLASS_NR);
	}

	return 0;
}

void BPF_STRUCT_OPS(agent_classed_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(agent_classed_ops,
	       .select_cpu	= (void *)agent_classed_select_cpu,
	       .enqueue		= (void *)agent_classed_enqueue,
	       .dequeue		= (void *)agent_classed_dequeue,
	       .dispatch		= (void *)agent_classed_dispatch,
	       .running		= (void *)agent_classed_running,
	       .stopping		= (void *)agent_classed_stopping,
	       .runnable		= (void *)agent_classed_runnable,
	       .quiescent	= (void *)agent_classed_quiescent,
	       .enable		= (void *)agent_classed_enable,
	       .disable		= (void *)agent_classed_disable,
	       .init_task	= (void *)agent_classed_init_task,
	       .init		= (void *)agent_classed_init,
	       .exit		= (void *)agent_classed_exit,
	       .timeout_ms	= 5000ULL,
	       .name		= "agent_classed");
