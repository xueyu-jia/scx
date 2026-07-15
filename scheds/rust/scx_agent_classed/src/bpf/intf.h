/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCX_AGENT_CLASSED_INTF_H
#define __SCX_AGENT_CLASSED_INTF_H

enum agent_consts {
	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= 1000ULL * NSEC_PER_USEC,
	NSEC_PER_SEC		= 1000ULL * NSEC_PER_MSEC,
	AGENT_COMM_LEN		= 16,
	AGENT_MAX_CPUS		= 4096,
	AGENT_MAX_RULES		= 1024,
	AGENT_MAX_MISS_COMMS	= 128,
	AGENT_STEAL_SCAN_MAX	= 32,
};

enum workload_class {
	CLASS_LATENCY = 0,
	CLASS_BATCH = 1,
	CLASS_NR = 2,
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif /* __VMLINUX_H__ */

/* Exact Linux comm match. comm is NUL-padded and at most 15 visible bytes. */
struct rule_key {
	char comm[AGENT_COMM_LEN];
};

struct rule_value {
	u32 class_id;
};

#endif /* __SCX_AGENT_CLASSED_INTF_H */
