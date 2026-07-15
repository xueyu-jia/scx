/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Two-level scheduler:
 *
 *   per-CPU class entity -> per-class/per-CPU vtime DSQ -> task queue key
 *
 * Each CPU arbitrates LATENCY and BATCH using committed plus reserved class
 * service. Both classes retain their global weighted task vruntime ordering.
 * Remote consumption is restricted to idle load balancing with a source
 * surplus, migration cooldown, and a per-source claim.
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
#define DISPATCH_CLAIM_LOCKED	(~0ULL)

#define dbg_msg(_fmt, ...) do { \
	if (debug) \
		bpf_printk(_fmt, ##__VA_ARGS__); \
} while (0)

const volatile bool debug;
const volatile u64 latency_slice_ns = NSEC_PER_MSEC;
const volatile u64 batch_slice_ns = 2ULL * NSEC_PER_MSEC;
const volatile u64 latency_burst_budget_ns = 2ULL * NSEC_PER_MSEC;
/* Normalized class-vruntime debt, deliberately independent of slice/weight. */
const volatile u64 class_max_debt_ns = NSEC_PER_MSEC / 2;
const volatile u64 batch_min_run_ns = NSEC_PER_MSEC / 2;
const volatile u64 latency_weight = 200;
const volatile u64 batch_weight = 100;
/* 0 preserves class-first remote dispatch; non-zero enables local-other bypass. */
const volatile u64 locality_debt_ns;
const volatile u32 default_class = CLASS_BATCH;
const volatile u32 steal_scan = 8;
const volatile bool use_awake_vruntime = true;
const volatile bool track_rule_misses;
const volatile bool diagnostic_counters;

volatile u64 nr_enqueues;
volatile u64 nr_latency_enqueues;
volatile u64 nr_batch_enqueues;
volatile u64 nr_direct_dispatches;
volatile u64 nr_latency_preempts;
volatile u64 nr_latency_wakeup_enqueues;
volatile u64 nr_latency_preempt_eligible;
volatile u64 nr_latency_preempt_ineligible;
volatile u64 nr_latency_preempt_insert_failures;
volatile u64 nr_latency_preempt_batch_protected;
volatile u64 nr_batch_guard_slice_shrinks;
volatile u64 nr_batch_guard_timer_arms;
volatile u64 nr_batch_guard_timer_kicks;
volatile u64 nr_batch_guard_timer_failures;
volatile u64 nr_latency_non_wakeup_enqueues;
volatile u64 nr_latency_continuations;
volatile u64 nr_latency_continuation_debt_denied;
volatile u64 nr_latency_continuation_budget_exhausted;
volatile u64 nr_latency_continuation_history_denied;
volatile u64 nr_latency_continuation_insert_failures;
volatile u64 nr_latency_stops_runnable;
volatile u64 nr_latency_stops_quiescent;
volatile u64 nr_latency_slice_expirations;
volatile u64 nr_local_dispatches;
volatile u64 nr_remote_dispatches;
volatile u64 nr_fallback_dispatches;
volatile u64 nr_latency_local_dispatches;
volatile u64 nr_batch_local_dispatches;
volatile u64 nr_latency_remote_dispatches;
volatile u64 nr_batch_remote_dispatches;
volatile u64 nr_latency_migrations;
volatile u64 nr_batch_migrations;
volatile u64 nr_locality_bypass_latency;
volatile u64 nr_locality_bypass_batch;
volatile u64 nr_locality_debt_denials;
volatile u64 nr_locality_remote_preferred;
volatile u64 nr_locality_overdebt_fallbacks;
volatile u64 nr_locality_reservation_rollbacks;
volatile u64 nr_locality_reservation_errors;
volatile u64 latency_locality_bypass_runtime_ns;
volatile u64 batch_locality_bypass_runtime_ns;
volatile u64 max_locality_debt_ns;
volatile u64 max_locality_overshoot_ns;
volatile u64 nr_dequeues;
volatile u64 nr_task_state_errors;
volatile u64 nr_rule_matches;
volatile u64 nr_rule_misses;
volatile u64 latency_runtime_ns;
volatile u64 batch_runtime_ns;
volatile u64 nr_fallback_enqueues;
volatile u64 nr_single_class_fastpaths;
volatile u64 nr_mixed_class_arbitrations;
volatile u64 nr_dispatch_reservations;
volatile u64 nr_dispatch_reservation_rollbacks;
volatile u64 nr_dispatch_reservation_errors;
volatile u64 nr_dispatch_reservation_late;
volatile u64 nr_dispatch_cpu_mismatches;
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
	u64 dispatch_claim;
	u64 dispatch_reservation;
	u64 locality_reservation;
	s64 sleep_vlag;
	s32 target_cpu;
	s32 last_cpu;
	s32 home_cpu;
	s32 queued_cpu;
	s32 dispatch_cpu;
	s32 running_cpu;
	u32 class_id;
	u32 dispatch_class;
	u32 locality_reserved_class;
	bool has_sleep_vlag;
	bool locality_bypass;
	enum task_state state;
};

struct class_ctx {
	u64 vruntime;
	u64 task_vtime_now;
	u64 locality_reserved_vruntime;
	u64 nr_queued;
	u64 nr_running;
};

struct cpu_class_ctx {
	u64 vruntime;
	u64 inflight_vruntime;
	u64 nr_queued;
	u64 nr_running;
};

struct cpu_ctx {
	struct cpu_class_ctx entity[CLASS_NR];
	u64 class_vtime_now;
	u64 steal_claim;
	u64 running_since;
	u64 last_preempt_at;
	u64 latency_preempt_pending;
	u32 running_class;
};

/* BSS-backed state avoids a map lookup on each class accounting operation. */
struct class_ctx classes[CLASS_NR];
volatile u64 class_vtime_now;
volatile u64 steal_cursor;
volatile u64 dispatch_claim_seq;
volatile u64 latency_reserved_vruntime;
volatile u64 batch_reserved_vruntime;
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
	return class_id == CLASS_LATENCY ? latency_slice_ns : batch_slice_ns;
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
	if (!old && !READ_ONCE(entity->nr_running) &&
	    !READ_ONCE(entity->inflight_vruntime))
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

static u64 reserve_dispatch(struct task_ctx *tctx, s32 cpu, u32 class_id)
{
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 amount, claim;

	if (!cpuc || class_id >= CLASS_NR)
		return 0;
	if (__sync_val_compare_and_swap(&tctx->dispatch_claim, 0,
					DISPATCH_CLAIM_LOCKED))
		return 0;

	entity = cpu_class_entity(cpuc, class_id);
	if (!entity) {
		__sync_val_compare_and_swap(&tctx->dispatch_claim,
					    DISPATCH_CLAIM_LOCKED, 0);
		return 0;
	}
	if (!READ_ONCE(entity->nr_queued) &&
	    !READ_ONCE(entity->nr_running) &&
	    !READ_ONCE(entity->inflight_vruntime))
		activate_cpu_class(class_id, cpuc, entity);
	amount = class_vruntime_delta(class_id, class_slice(class_id));
	claim = __sync_fetch_and_add(&dispatch_claim_seq, 1) + 1;
	if (!claim || claim == DISPATCH_CLAIM_LOCKED)
		claim = __sync_fetch_and_add(&dispatch_claim_seq, 1) + 1;
	tctx->dispatch_reservation = amount;
	tctx->dispatch_cpu = cpu;
	tctx->dispatch_class = class_id;
	__sync_fetch_and_add(&entity->inflight_vruntime, amount);
	if (diagnostic_counters) {
		__sync_fetch_and_add(&nr_dispatch_reservations, 1);
		if (class_id == CLASS_LATENCY)
			__sync_fetch_and_add(&latency_reserved_vruntime, amount);
		else
			__sync_fetch_and_add(&batch_reserved_vruntime, amount);
	}
	if (__sync_val_compare_and_swap(&tctx->dispatch_claim,
					DISPATCH_CLAIM_LOCKED, claim) !=
	    DISPATCH_CLAIM_LOCKED) {
		__sync_fetch_and_sub(&entity->inflight_vruntime, amount);
		tctx->dispatch_reservation = 0;
		tctx->dispatch_cpu = -1;
		tctx->dispatch_class = CLASS_NR;
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
		return 0;
	}
	return claim;
}

static bool extend_dispatch_reservation(struct task_ctx *tctx, s32 cpu,
					u32 class_id, u64 runtime)
{
	struct cpu_ctx *cpuc;
	u64 amount, claim;

	if (!runtime)
		return false;
	claim = READ_ONCE(tctx->dispatch_claim);
	if (!claim || claim == DISPATCH_CLAIM_LOCKED ||
	    __sync_val_compare_and_swap(&tctx->dispatch_claim, claim,
					DISPATCH_CLAIM_LOCKED) != claim)
		return false;
	if (!tctx->dispatch_reservation || tctx->dispatch_cpu != cpu ||
	    tctx->dispatch_class != class_id) {
		__sync_val_compare_and_swap(&tctx->dispatch_claim,
					    DISPATCH_CLAIM_LOCKED, claim);
		return false;
	}
	cpuc = lookup_cpu_ctx(cpu);
	if (!cpuc || class_id >= CLASS_NR) {
		__sync_val_compare_and_swap(&tctx->dispatch_claim,
					    DISPATCH_CLAIM_LOCKED, claim);
		return false;
	}
	amount = class_vruntime_delta(class_id, runtime);
	tctx->dispatch_reservation += amount;
	{
		struct cpu_class_ctx *entity = cpu_class_entity(cpuc, class_id);

		if (!entity) {
			__sync_val_compare_and_swap(&tctx->dispatch_claim,
						    DISPATCH_CLAIM_LOCKED, claim);
			return false;
		}
		__sync_fetch_and_add(&entity->inflight_vruntime, amount);
	}
	if (diagnostic_counters) {
		if (class_id == CLASS_LATENCY)
			__sync_fetch_and_add(&latency_reserved_vruntime, amount);
		else
			__sync_fetch_and_add(&batch_reserved_vruntime, amount);
	}
	if (__sync_val_compare_and_swap(&tctx->dispatch_claim,
					DISPATCH_CLAIM_LOCKED, claim) !=
	    DISPATCH_CLAIM_LOCKED)
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
	return true;
}

static void release_dispatch_reservation_claim(struct task_ctx *tctx,
					       u64 claim)
{
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc;
	u64 amount, old;
	s32 cpu;
	u32 class_id;

	if (!claim || claim == DISPATCH_CLAIM_LOCKED ||
	    __sync_val_compare_and_swap(&tctx->dispatch_claim, claim,
					DISPATCH_CLAIM_LOCKED) != claim)
		return;
	amount = tctx->dispatch_reservation;
	cpu = tctx->dispatch_cpu;
	class_id = tctx->dispatch_class;
	tctx->dispatch_reservation = 0;
	tctx->dispatch_cpu = -1;
	tctx->dispatch_class = CLASS_NR;
	cpuc = lookup_cpu_ctx(cpu);
	if (!amount || !cpuc || class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
		goto out_unlock;
	}
	entity = cpu_class_entity(cpuc, class_id);
	if (!entity) {
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
		goto out_unlock;
	}
	old = __sync_fetch_and_sub(&entity->inflight_vruntime, amount);
	if (old < amount) {
		/* Undo the wrapping subtraction without losing concurrent updates. */
		__sync_fetch_and_add(&entity->inflight_vruntime, amount);
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
	}
	if (diagnostic_counters) {
		volatile u64 *total = class_id == CLASS_LATENCY ?
				  &latency_reserved_vruntime :
				  &batch_reserved_vruntime;

		old = __sync_fetch_and_sub(total, amount);
		if (old < amount) {
			__sync_fetch_and_add(total, amount);
			__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
		}
	}

out_unlock:
	if (__sync_val_compare_and_swap(&tctx->dispatch_claim,
					DISPATCH_CLAIM_LOCKED, 0) !=
	    DISPATCH_CLAIM_LOCKED)
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
}

static void release_dispatch_reservation(struct task_ctx *tctx)
{
	u64 claim = READ_ONCE(tctx->dispatch_claim);

	release_dispatch_reservation_claim(tctx, claim);
}

static void release_locality_reservation(struct task_ctx *tctx)
{
	struct class_ctx *cctx;
	u64 amount = tctx->locality_reservation;
	u64 old;
	u32 class_id = tctx->locality_reserved_class;

	if (!amount)
		return;
	tctx->locality_reservation = 0;
	tctx->locality_bypass = false;
	if (class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_locality_reservation_errors, 1);
		return;
	}

	cctx = &classes[class_id];
	old = __sync_fetch_and_sub(&cctx->locality_reserved_vruntime, amount);
	if (old < amount) {
		WRITE_ONCE(cctx->locality_reserved_vruntime, 0);
		__sync_fetch_and_add(&nr_locality_reservation_errors, 1);
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

static void clamp_batch_vruntime(struct task_struct *p, struct task_ctx *tctx,
				struct class_ctx *cctx)
{
	u64 credit = scale_by_task_weight(p,
						  batch_slice_ns * CLASS_WAKEUP_CREDIT);
	u64 floor = cctx->task_vtime_now > credit ?
			    cctx->task_vtime_now - credit : 0;

	if (time_before(tctx->vruntime, floor))
		tctx->vruntime = floor;
}

/* Preserve Forge's bounded sleeper credit and debt within LATENCY only. */
static s64 latency_clamp_vlag(s64 vlag)
{
	s64 limit = (s64)latency_slice_ns + NSEC_PER_MSEC;

	if (vlag < -limit)
		return -limit;
	if (vlag > limit)
		return limit;
	return vlag;
}

static void latency_save_sleep_vlag(struct task_ctx *tctx,
				    struct class_ctx *cctx)
{
	s64 vlag = (s64)(READ_ONCE(cctx->task_vtime_now) - tctx->vruntime);

	tctx->sleep_vlag = latency_clamp_vlag(vlag);
	tctx->has_sleep_vlag = true;
}

static u64 latency_update_task_vruntime(struct task_ctx *tctx,
					struct class_ctx *cctx)
{
	s64 vlag;

	if (tctx->has_sleep_vlag) {
		vlag = latency_clamp_vlag(tctx->sleep_vlag);
		tctx->vruntime = READ_ONCE(cctx->task_vtime_now) - vlag;
		tctx->has_sleep_vlag = false;
	}

	return tctx->vruntime;
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
	u64 claim;
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

	claim = reserve_dispatch(tctx, cpu, CLASS_LATENCY);
	if (!claim)
		return false;
	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
				latency_slice_ns, enq_flags)) {
		release_dispatch_reservation_claim(tctx, claim);
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_dispatch_reservation_rollbacks, 1);
		return false;
	}
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
	u64 claim;
	s32 cpu, this_cpu;

	tctx = lookup_task_ctx(p);
	if (!tctx) {
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return cpu;
	}

	prev_cpu = task_home_cpu(p, tctx, prev_cpu);
	if (tctx->class_id != CLASS_LATENCY) {
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		tctx->target_cpu = cpu;
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
		tctx->target_cpu = cpu;
		tctx->home_cpu = cpu;
		claim = reserve_dispatch(tctx, cpu, CLASS_LATENCY);
		if (claim &&
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, latency_slice_ns, 0)) {
			tctx->state = TASK_DISPATCHED;
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		} else if (claim) {
			release_dispatch_reservation_claim(tctx, claim);
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_dispatch_reservation_rollbacks, 1);
		}
		return cpu;
	}

	tctx->target_cpu = prev_cpu;
	return prev_cpu;
}

static bool latency_try_preempt_batch(s32 cpu, u64 enq_flags)
{
	struct cpu_class_ctx *lat, *batch;
	struct cpu_ctx *cpuc;
	u64 now, elapsed, started, last, lat_vtime, batch_vtime;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return false;
	cpuc = lookup_cpu_ctx(cpu);
	if (!cpuc || READ_ONCE(cpuc->running_class) != CLASS_BATCH)
		return false;
	started = READ_ONCE(cpuc->running_since);
	if (!started)
		return false;
	now = bpf_ktime_get_ns();
	elapsed = now > started ? now - started : 0;
	lat = &cpuc->entity[CLASS_LATENCY];
	batch = &cpuc->entity[CLASS_BATCH];
	lat_vtime = READ_ONCE(lat->vruntime) + READ_ONCE(lat->inflight_vruntime);
	/* Compare against the BATCH value that stopping() will actually commit. */
	batch_vtime = READ_ONCE(batch->vruntime) +
		      class_vruntime_delta(CLASS_BATCH, elapsed);
	if ((s64)(lat_vtime - batch_vtime) > (s64)class_max_debt_ns) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_latency_preempt_ineligible, 1);
		return false;
	}

	if (__sync_val_compare_and_swap(&cpuc->latency_preempt_pending, 0, 1)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_latency_preempt_ineligible, 1);
		return false;
	}
	if (elapsed < batch_min_run_ns) {
		struct task_struct *curr;
		u64 remaining = batch_min_run_ns - elapsed;
		bool armed = false;

		if (!remaining)
			remaining = 1;
		bpf_rcu_read_lock();
		curr = __COMPAT_scx_bpf_cpu_curr(cpu);
		if (curr && READ_ONCE(cpuc->running_class) == CLASS_BATCH &&
		    READ_ONCE(cpuc->running_since) == started) {
			u64 slice = READ_ONCE(curr->scx.slice);

			if (slice > remaining) {
				WRITE_ONCE(curr->scx.slice, remaining);
				if (diagnostic_counters)
					__sync_fetch_and_add(
						&nr_batch_guard_slice_shrinks, 1);
			}
			armed = true;
		}
		bpf_rcu_read_unlock();
		if (!armed) {
			__sync_val_compare_and_swap(&cpuc->latency_preempt_pending, 1, 0);
			return false;
		}
		if (diagnostic_counters) {
			__sync_fetch_and_add(&nr_latency_preempt_batch_protected, 1);
			__sync_fetch_and_add(&nr_latency_preempt_eligible, 1);
		}
		return true;
	}
	last = READ_ONCE(cpuc->last_preempt_at);
	if ((last && now - last < batch_min_run_ns) ||
	    __sync_val_compare_and_swap(&cpuc->last_preempt_at, last, now) != last) {
		__sync_val_compare_and_swap(&cpuc->latency_preempt_pending, 1, 0);
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_latency_preempt_ineligible, 1);
		return false;
	}
	if (READ_ONCE(cpuc->running_class) != CLASS_BATCH ||
	    READ_ONCE(cpuc->running_since) != started) {
		__sync_val_compare_and_swap(&cpuc->last_preempt_at, now, last);
		__sync_val_compare_and_swap(&cpuc->latency_preempt_pending, 1, 0);
		return false;
	}

	if (diagnostic_counters)
		__sync_fetch_and_add(&nr_latency_preempt_eligible, 1);
	__sync_fetch_and_add(&nr_latency_preempts, 1);
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return true;
}

void BPF_STRUCT_OPS(agent_classed_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	u32 class_id;
	u64 key, dsq_id;
	s32 cpu;

	tctx = lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, batch_slice_ns, enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}

	class_id = sanitize_class(tctx->class_id);
	tctx->class_id = class_id;
	cctx = lookup_class_ctx(class_id);
	if (!cctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, batch_slice_ns, enq_flags);
		__sync_fetch_and_add(&nr_fallback_enqueues, 1);
		return;
	}

	cpu = tctx->target_cpu;
	if (cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		cpu = task_home_cpu(p, tctx, scx_bpf_task_cpu(p));
	if (cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		cpu = bpf_cpumask_first(p->cpus_ptr);
	tctx->target_cpu = -1;
	if (!task_cpu_allowed(p, tctx->home_cpu) && task_cpu_allowed(p, cpu))
		tctx->home_cpu = cpu;

	if (cpu < 0 || cpu >= nr_cpu_ids) {
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
	if (class_id == CLASS_LATENCY)
		key = latency_update_task_vruntime(tctx, cctx);
	else {
		clamp_batch_vruntime(p, tctx, cctx);
		key = tctx->vruntime;
	}
	dsq_id = CLASS_DSQ_ID(class_id, cpu);
	tctx->state = TASK_ENQUEUED;
	tctx->queued_cpu = cpu;
	__sync_fetch_and_add(&cctx->nr_queued, 1);
	cpu_queue_inc(cpu, class_id);

	if (!scx_bpf_dsq_insert_vtime(p, dsq_id, class_slice(class_id), key,
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

	if (class_id == CLASS_LATENCY &&
	    latency_try_preempt_batch(cpu, enq_flags))
		return;
	if (task_should_kick(p, enq_flags)) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
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
			release_locality_reservation(tctx);
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
	if (deq_flags & (SCX_DEQ_SLEEP | SCX_DEQ_CORE_SCHED_EXEC |
			 SCX_DEQ_SCHED_CHANGE)) {
		release_locality_reservation(tctx);
		release_dispatch_reservation(tctx);
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

static void record_remote_dispatch(u32 class_id)
{
	__sync_fetch_and_add(&nr_remote_dispatches, 1);
	if (!diagnostic_counters)
		return;
	if (class_id == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_latency_remote_dispatches, 1);
	else
		__sync_fetch_and_add(&nr_batch_remote_dispatches, 1);
}

static u64 projected_vruntime(const struct cpu_class_ctx *entity)
{
	return READ_ONCE(entity->vruntime) +
	       READ_ONCE(entity->inflight_vruntime);
}

static bool cpu_has_local_work(const struct cpu_ctx *cpuc)
{
	const struct cpu_class_ctx *lat = &cpuc->entity[CLASS_LATENCY];
	const struct cpu_class_ctx *batch = &cpuc->entity[CLASS_BATCH];

	return READ_ONCE(lat->nr_queued) || READ_ONCE(batch->nr_queued) ||
	       READ_ONCE(lat->nr_running) || READ_ONCE(batch->nr_running) ||
	       READ_ONCE(lat->inflight_vruntime) ||
	       READ_ONCE(batch->inflight_vruntime);
}

/* Return the local winner and place the work-conserving fallback in second. */
static s32 pick_local_class(struct cpu_ctx *cpuc, u32 *second)
{
	struct cpu_class_ctx *lat = &cpuc->entity[CLASS_LATENCY];
	struct cpu_class_ctx *batch = &cpuc->entity[CLASS_BATCH];
	bool lat_active = READ_ONCE(lat->nr_queued) > 0 ||
			  READ_ONCE(lat->nr_running) > 0;
	bool batch_active = READ_ONCE(batch->nr_queued) > 0 ||
			    READ_ONCE(batch->nr_running) > 0;
	bool latency_handoff;
	u32 first;

	latency_handoff =
		__sync_val_compare_and_swap(&cpuc->latency_preempt_pending, 1, 0) == 1;
	*second = CLASS_NR;
	if (!lat_active && !batch_active)
		return -ENOENT;
	if (lat_active != batch_active) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_single_class_fastpaths, 1);
		return lat_active ? CLASS_LATENCY : CLASS_BATCH;
	}

	if (diagnostic_counters)
		__sync_fetch_and_add(&nr_mixed_class_arbitrations, 1);
	if (latency_handoff) {
		*second = CLASS_BATCH;
		return CLASS_LATENCY;
	}
	/* LATENCY wins an exact tie; reservations move concurrent choices on. */
	first = time_before(projected_vruntime(batch),
			    projected_vruntime(lat)) ?
		CLASS_BATCH : CLASS_LATENCY;
	*second = first == CLASS_LATENCY ? CLASS_BATCH : CLASS_LATENCY;
	return first;
}

static bool dispatch_from_cpu(s32 dst_cpu, s32 src_cpu, u32 class_id,
			      bool remote)
{
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();
	u64 claim;
	bool moved = false;

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
		claim = reserve_dispatch(tctx, dst_cpu, class_id);
		if (!claim) {
			bpf_task_release(p);
			continue;
		}
		moved = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
					 SCX_DSQ_LOCAL_ON | dst_cpu, 0);
		if (moved) {
			task_queue_dec(tctx);
			/* A gated rebalance is sticky to avoid return-home ping-pong. */
			if (remote)
				tctx->home_cpu = dst_cpu;
			tctx->state = TASK_DISPATCHED;
		} else {
			release_dispatch_reservation_claim(tctx, claim);
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_dispatch_reservation_rollbacks, 1);
		}
		bpf_task_release(p);
		break;
	}
	bpf_rcu_read_unlock();

	if (!moved)
		return false;
	if (remote)
		record_remote_dispatch(class_id);
	else
		record_local_dispatch(class_id);
	return true;
}

static u64 cpu_queued_load(const struct cpu_ctx *cpuc)
{
	return (READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_queued) +
		READ_ONCE(cpuc->entity[CLASS_LATENCY].nr_running)) *
		latency_slice_ns +
	       (READ_ONCE(cpuc->entity[CLASS_BATCH].nr_queued) +
		READ_ONCE(cpuc->entity[CLASS_BATCH].nr_running)) *
		batch_slice_ns;
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
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
}

static bool dispatch_local_claimed(s32 cpu, u32 class_id)
{
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u64 claim = ((u64)cpu + 1) << 32 | 1;
	bool moved;

	if (!cpuc || !acquire_source_claim(cpuc, claim)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_claim_busy, 1);
		return false;
	}
	moved = dispatch_from_cpu(cpu, cpu, class_id, false);
	release_source_claim(cpuc, claim);
	return moved;
}

static bool gated_steal(s32 dst_cpu, u32 class_id)
{
	struct cpu_ctx *dst = lookup_cpu_ctx(dst_cpu);
	u64 cursor, claim, src_load, dst_load;
	s32 src_cpu;
	int i;

	if (!dst || nr_cpu_ids <= 1 || !steal_scan)
		return false;
	if (cpu_has_local_work(dst)) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_local_busy, 1);
		return false;
	}

	cursor = __sync_fetch_and_add(&steal_cursor, 1);
	bpf_for(i, 0, AGENT_STEAL_SCAN_MAX) {
		struct cpu_class_ctx *src_entity;
		struct cpu_ctx *src;
		u64 queued;

		if (i >= steal_scan || i >= nr_cpu_ids - 1)
			break;
		src_cpu = (dst_cpu + 1 +
			   (cursor + i) % (nr_cpu_ids - 1)) % nr_cpu_ids;
		src = lookup_cpu_ctx(src_cpu);
		if (!src)
			continue;
		claim = ((u64)dst_cpu + 1) << 32 | 2;
		if (!acquire_source_claim(src, claim)) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_claim_busy, 1);
			continue;
		}

		/* Revalidate both sides while source consumption is serialized. */
		if (cpu_has_local_work(dst)) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_local_busy, 1);
			release_source_claim(src, claim);
			return false;
		}
		src_entity = cpu_class_entity(src, class_id);
		if (!src_entity) {
			release_source_claim(src, claim);
			continue;
		}
		queued = READ_ONCE(src_entity->nr_queued);
		if (!queued || cpu_runnable_count(src) < 2) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_source_short, 1);
			release_source_claim(src, claim);
			continue;
		}
		dst_load = cpu_queued_load(dst);
		src_load = cpu_queued_load(src);
		if (src_load <= dst_load ||
		    src_load - dst_load < class_slice(class_id)) {
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_load_gap, 1);
			release_source_claim(src, claim);
			continue;
		}
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_gated_steal_attempts, 1);
		if (dispatch_from_cpu(dst_cpu, src_cpu, class_id, true)) {
			release_source_claim(src, claim);
			if (diagnostic_counters)
				__sync_fetch_and_add(&nr_gated_steal_successes, 1);
			return true;
		}
		release_source_claim(src, claim);
	}

	return false;
}

static s32 pick_remote_class(struct cpu_ctx *cpuc, u32 *second)
{
	bool lat_queued = READ_ONCE(classes[CLASS_LATENCY].nr_queued) > 0;
	bool batch_queued = READ_ONCE(classes[CLASS_BATCH].nr_queued) > 0;
	u32 first;

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
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_single_class_fastpaths, 1);
		return lat_queued ? CLASS_LATENCY : CLASS_BATCH;
	}
	if (diagnostic_counters)
		__sync_fetch_and_add(&nr_mixed_class_arbitrations, 1);
	first = time_before(projected_vruntime(&cpuc->entity[CLASS_BATCH]),
			    projected_vruntime(&cpuc->entity[CLASS_LATENCY])) ?
		CLASS_BATCH : CLASS_LATENCY;
	*second = first == CLASS_LATENCY ? CLASS_BATCH : CLASS_LATENCY;
	return first;
}

static bool try_keep_running(s32 cpu, struct task_struct *prev,
			     s32 selected_class)
{
	struct task_ctx *tctx;
	struct task_struct *next;
	u64 now, elapsed, slice, used, next_vruntime;
	u32 class_id;

	if (!prev || !is_task_queued(prev) || READ_ONCE(prev->scx.slice))
		return false;
	tctx = lookup_task_ctx(prev);
	if (!tctx || !tctx->last_run_at || tctx->running_cpu != cpu ||
	    !tctx->dispatch_claim ||
	    tctx->dispatch_claim == DISPATCH_CLAIM_LOCKED ||
	    !tctx->dispatch_reservation || tctx->dispatch_cpu != cpu)
		return false;
	class_id = sanitize_class(tctx->class_id);
	if (selected_class >= 0 && selected_class != class_id) {
		if (diagnostic_counters && class_id == CLASS_LATENCY)
			__sync_fetch_and_add(&nr_latency_continuation_debt_denied, 1);
		return false;
	}

	now = bpf_ktime_get_ns();
	elapsed = now > tctx->last_run_at ? now - tctx->last_run_at : 0;
	if (diagnostic_counters && class_id == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_latency_slice_expirations, 1);

	/* Do not continue past an earlier task in the same local class. */
	next = __COMPAT_scx_bpf_dsq_peek(CLASS_DSQ_ID(class_id, cpu));
	if (next) {
		next_vruntime = tctx->vruntime +
			scale_by_task_weight_inverse(prev, elapsed);
		if (time_before(next->scx.dsq_vtime, next_vruntime)) {
			if (diagnostic_counters && class_id == CLASS_LATENCY)
				__sync_fetch_and_add(
					&nr_latency_continuation_history_denied, 1);
			return false;
		}
	}

	if (class_id == CLASS_LATENCY) {
		used = tctx->latency_burst_used_ns;
		if (~0ULL - used < elapsed)
			used = ~0ULL;
		else
			used += elapsed;
		if (used >= latency_burst_budget_ns) {
			if (diagnostic_counters)
				__sync_fetch_and_add(
					&nr_latency_continuation_budget_exhausted, 1);
			return false;
		}
		slice = latency_burst_budget_ns - used;
		if (slice > latency_slice_ns)
			slice = latency_slice_ns;
	} else {
		slice = batch_slice_ns;
	}

	if (!extend_dispatch_reservation(tctx, cpu, class_id, slice)) {
		if (diagnostic_counters && class_id == CLASS_LATENCY)
			__sync_fetch_and_add(
				&nr_latency_continuation_insert_failures, 1);
		return false;
	}
	scx_bpf_task_set_slice(prev, slice);
	if (diagnostic_counters && class_id == CLASS_LATENCY)
		__sync_fetch_and_add(&nr_latency_continuations, 1);
	return true;
}

void BPF_STRUCT_OPS(agent_classed_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	u32 second;
	s32 first;

	if (!cpuc)
		return;
	first = pick_local_class(cpuc, &second);
	if (try_keep_running(cpu, prev, first))
		return;
	if (first >= 0) {
		if (dispatch_local_claimed(cpu, first))
			return;
		if (second < CLASS_NR &&
		    dispatch_local_claimed(cpu, second)) {
			__sync_fetch_and_add(&nr_fallback_dispatches, 1);
			return;
		}
	}

	/* Remote work is load balancing, never a normal class-selection path. */
	if (!cpu_has_local_work(cpuc)) {
		first = pick_remote_class(cpuc, &second);
		if (first >= 0 && gated_steal(cpu, first))
			return;
		if (second < CLASS_NR && gated_steal(cpu, second)) {
			__sync_fetch_and_add(&nr_fallback_dispatches, 1);
			return;
		}
	} else if (diagnostic_counters) {
		__sync_fetch_and_add(&nr_gated_steal_local_busy, 1);
	}

}

void BPF_STRUCT_OPS(agent_classed_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	struct cpu_class_ctx *entity;
	struct cpu_ctx *cpuc;
	u64 now;
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

	/* Direct dispatch bypasses enqueue's restore, so restore again here. */
	if (class_id == CLASS_LATENCY)
		latency_update_task_vruntime(tctx, cctx);
	if (!READ_ONCE(cctx->nr_queued) && !READ_ONCE(cctx->nr_running))
		activate_class(class_id, cctx);

	now = bpf_ktime_get_ns();
	cpu = scx_bpf_task_cpu(p);
	cpuc = lookup_cpu_ctx(cpu);
	if (!cpuc)
		return;
	if (!READ_ONCE(tctx->dispatch_claim) || !tctx->dispatch_reservation) {
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_dispatch_reservation_late, 1);
		reserve_dispatch(tctx, cpu, class_id);
	} else if (tctx->dispatch_cpu != cpu ||
		   tctx->dispatch_class != class_id) {
		release_dispatch_reservation(tctx);
		if (diagnostic_counters)
			__sync_fetch_and_add(&nr_dispatch_cpu_mismatches, 1);
		reserve_dispatch(tctx, cpu, class_id);
	}
	entity = cpu_class_entity(cpuc, class_id);
	if (!entity) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		return;
	}
	if (diagnostic_counters && tctx->last_cpu >= 0 &&
	    tctx->last_cpu != cpu) {
		if (class_id == CLASS_LATENCY)
			__sync_fetch_and_add(&nr_latency_migrations, 1);
		else
			__sync_fetch_and_add(&nr_batch_migrations, 1);
	}
	if (tctx->last_cpu >= 0 && tctx->last_cpu != cpu)
		tctx->last_migrate_at = now;
	if (!task_cpu_allowed(p, tctx->home_cpu))
		tctx->home_cpu = cpu;
	tctx->last_cpu = cpu;
	tctx->running_cpu = cpu;
	tctx->queued_cpu = -1;
	tctx->target_cpu = -1;
	tctx->state = TASK_NONE;
	tctx->last_run_at = now;
	WRITE_ONCE(cpuc->running_class, class_id);
	WRITE_ONCE(cpuc->running_since, now);
	__sync_fetch_and_add(&cctx->nr_running, 1);
	__sync_fetch_and_add(&entity->nr_running, 1);
	vtime_set_max(&cctx->task_vtime_now, tctx->vruntime);
}

void BPF_STRUCT_OPS(agent_classed_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;
	struct cpu_class_ctx *entity = NULL;
	struct cpu_ctx *cpuc;
	u64 now, runtime, delta, old_class_vtime, new_class_vtime;
	u64 old_running;
	s32 cpu;
	u32 class_id;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	if (!tctx->last_run_at) {
		release_dispatch_reservation(tctx);
		return;
	}
	class_id = READ_ONCE(tctx->class_id);
	if (class_id >= CLASS_NR) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		release_dispatch_reservation(tctx);
		return;
	}
	cctx = lookup_class_ctx(class_id);
	if (!cctx)
		return;
	cpu = tctx->running_cpu;
	cpuc = lookup_cpu_ctx(cpu);
	if (cpuc) {
		entity = cpu_class_entity(cpuc, class_id);
		WRITE_ONCE(cpuc->running_since, 0);
		WRITE_ONCE(cpuc->running_class, CLASS_NR);
	}

	now = bpf_ktime_get_ns();
	runtime = now > tctx->last_run_at ? now - tctx->last_run_at : 1;
	tctx->last_run_at = 0;

	delta = scale_by_task_weight_inverse(p, runtime);
	tctx->vruntime += delta;
	if (class_id == CLASS_LATENCY) {
		if (~0ULL - tctx->latency_burst_used_ns < runtime)
			tctx->latency_burst_used_ns = ~0ULL;
		else
			tctx->latency_burst_used_ns += runtime;
		if (diagnostic_counters) {
			if (runnable)
				__sync_fetch_and_add(&nr_latency_stops_runnable, 1);
			else
				__sync_fetch_and_add(&nr_latency_stops_quiescent, 1);
		}
		__sync_fetch_and_add(&latency_runtime_ns, runtime);
	} else {
		/* BATCH keeps the original minimum-vruntime advancement model. */
		vtime_set_max(&cctx->task_vtime_now, tctx->vruntime);
		__sync_fetch_and_add(&batch_runtime_ns, runtime);
	}

	delta = class_vruntime_delta(class_id, runtime);
	old_class_vtime = __sync_fetch_and_add(&cctx->vruntime, delta);
	new_class_vtime = old_class_vtime + delta;
	vtime_set_max(&class_vtime_now, new_class_vtime);
	if (entity) {
		old_class_vtime = __sync_fetch_and_add(&entity->vruntime, delta);
		new_class_vtime = old_class_vtime + delta;
		vtime_set_max(&cpuc->class_vtime_now, new_class_vtime);
	} else {
		__sync_fetch_and_add(&nr_dispatch_reservation_errors, 1);
	}
	if (tctx->locality_bypass && diagnostic_counters) {
		if (tctx->locality_reserved_class == CLASS_LATENCY)
			__sync_fetch_and_add(&latency_locality_bypass_runtime_ns,
					     runtime);
		else
			__sync_fetch_and_add(&batch_locality_bypass_runtime_ns,
					     runtime);
	}
	/* Commit actual service before removing the projected service claim. */
	release_dispatch_reservation(tctx);
	release_locality_reservation(tctx);
	if (entity) {
		old_running = __sync_fetch_and_sub(&entity->nr_running, 1);
		if (!old_running) {
			__sync_fetch_and_add(&entity->nr_running, 1);
			__sync_fetch_and_add(&nr_task_state_errors, 1);
		}
	}
	tctx->running_cpu = -1;
	old_running = __sync_fetch_and_sub(&cctx->nr_running, 1);
	if (!old_running) {
		__sync_fetch_and_add(&cctx->nr_running, 1);
		__sync_fetch_and_add(&nr_task_state_errors, 1);
	}
}

void BPF_STRUCT_OPS(agent_classed_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct class_ctx *cctx;
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
		release_locality_reservation(tctx);
		release_dispatch_reservation(tctx);
		cctx = lookup_class_ctx(class_id);
		tctx->vruntime = cctx ? READ_ONCE(cctx->task_vtime_now) : 0;
		tctx->sleep_vlag = 0;
		tctx->has_sleep_vlag = false;
	}
	tctx->class_id = class_id;
}

void BPF_STRUCT_OPS(agent_classed_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct class_ctx *cctx;

	if (!tctx)
		return;
	if (tctx->state == TASK_ENQUEUED)
		task_queue_dec(tctx);
	if (tctx->class_id == CLASS_LATENCY && (deq_flags & SCX_DEQ_SLEEP)) {
		cctx = lookup_class_ctx(CLASS_LATENCY);
		if (cctx)
			latency_save_sleep_vlag(tctx, cctx);
	}
	release_locality_reservation(tctx);
	release_dispatch_reservation(tctx);
	tctx->state = TASK_NONE;
	tctx->target_cpu = -1;
	tctx->queued_cpu = -1;
}

void BPF_STRUCT_OPS(agent_classed_enable, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct class_ctx *cctx;

	if (!tctx)
		return;
	release_locality_reservation(tctx);
	release_dispatch_reservation(tctx);
	tctx->class_id = classify_task(p);
	cctx = lookup_class_ctx(tctx->class_id);
	tctx->vruntime = cctx ? cctx->task_vtime_now : 0;
	tctx->last_run_at = 0;
	tctx->last_migrate_at = 0;
	tctx->latency_burst_used_ns = 0;
	tctx->dispatch_claim = 0;
	tctx->dispatch_reservation = 0;
	tctx->dispatch_class = CLASS_NR;
	tctx->dispatch_cpu = -1;
	tctx->running_cpu = -1;
	tctx->locality_reservation = 0;
	tctx->locality_reserved_class = CLASS_NR;
	tctx->locality_bypass = false;
	tctx->sleep_vlag = 0;
	tctx->has_sleep_vlag = false;
	tctx->target_cpu = -1;
	tctx->last_cpu = -1;
	tctx->home_cpu = -1;
	tctx->queued_cpu = -1;
	tctx->state = TASK_NONE;
}

void BPF_STRUCT_OPS(agent_classed_disable, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);

	if (tctx) {
		if (tctx->state == TASK_ENQUEUED)
			task_queue_dec(tctx);
		release_locality_reservation(tctx);
		release_dispatch_reservation(tctx);
		tctx->state = TASK_NONE;
		tctx->queued_cpu = -1;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(agent_classed_init_task, struct task_struct *p,
				     struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct class_ctx *cctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->class_id = classify_task(p);
	cctx = lookup_class_ctx(tctx->class_id);
	tctx->vruntime = cctx ? cctx->task_vtime_now : 0;
	tctx->last_run_at = 0;
	tctx->last_migrate_at = 0;
	tctx->latency_burst_used_ns = 0;
	tctx->dispatch_claim = 0;
	tctx->dispatch_reservation = 0;
	tctx->dispatch_class = CLASS_NR;
	tctx->dispatch_cpu = -1;
	tctx->running_cpu = -1;
	tctx->locality_reservation = 0;
	tctx->locality_reserved_class = CLASS_NR;
	tctx->locality_bypass = false;
	tctx->sleep_vlag = 0;
	tctx->has_sleep_vlag = false;
	tctx->target_cpu = -1;
	tctx->last_cpu = -1;
	tctx->home_cpu = -1;
	tctx->queued_cpu = -1;
	tctx->state = TASK_NONE;
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(agent_classed_init)
{
	s32 cpu, ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (!nr_cpu_ids || nr_cpu_ids > AGENT_MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids %llu exceeds supported range 1..%u",
			      nr_cpu_ids, AGENT_MAX_CPUS);
		return -E2BIG;
	}
	if (!latency_slice_ns || !batch_slice_ns ||
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
