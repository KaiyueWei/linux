/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H

#include <linux/types.h>

struct folio;
struct mem_cgroup;

#define CACHE_EXT_MAX_EVICT_BATCH 32

/*
 * Per-proposal outcome recorded by the kernel as it processes each
 * candidate. Used to attribute evictions to the cache_ext policy
 * and to diagnose why proposals fail. CEO_PENDING is the zero-init
 * default; any leftover PENDING in a post-call slot is a kernel bug,
 * not a success.
 */
enum cache_ext_outcome {
	CEO_PENDING = 0,
	CEO_EVICTED,		/* survived shrink_folio_list → reclaimed */
	CEO_NULL_MAPPING,	/* BPF proposed a NULL mapping_ptr */
	CEO_NOT_FOUND,		/* filemap_get_folio returned IS_ERR */
	CEO_ISOLATE_FAIL,	/* folio_isolate_lru returned false */
	CEO_SHRINK_REJECT,	/* came back from shrink_folio_list unreclaimed */
};

/*
 * Eviction context passed to the BPF evict_folios hook.
 *
 * The BPF program fills candidate_ino[] and candidate_idx[] with
 * (inode_id, page_index) tuples identifying folios to evict.
 * The kernel resolves these to struct folio * via the page cache
 * xarray (filemap_get_folio), ensuring pointer safety without
 * a valid folios registry.
 *
 * candidate_outcome[] is written by the kernel AFTER evict_folios
 * returns. The BPF program MUST NOT read it during evict_folios —
 * the slots are not populated until the kernel consumes the
 * proposals in shrink_node().
 *
 * No raw kernel pointers pass through BPF arena memory.
 * Arena stores only integer identifiers. The kernel does all pointer
 * resolution from its own trusted data structures.
 */
struct cache_ext_eviction_ctx {
	__u64 candidate_ino[CACHE_EXT_MAX_EVICT_BATCH];   /* inode numbers */
	__u64 candidate_idx[CACHE_EXT_MAX_EVICT_BATCH];   /* page indices */
	int nr_candidates;                                  /* filled by BPF */
	int nr_requested;                                   /* set by kernel */
	__u8 candidate_outcome[CACHE_EXT_MAX_EVICT_BATCH];  /* filled by kernel */
};

struct cache_ext_ops {
	int (*init)(struct mem_cgroup *memcg);
	void (*folio_added)(struct folio *folio);
	void (*folio_accessed)(struct folio *folio);
	void (*folio_evicted)(struct folio *folio);
	void (*evict_folios)(struct cache_ext_eviction_ctx *ctx,
			     struct mem_cgroup *memcg);
};

#ifdef CONFIG_BPF_SYSCALL

extern struct cache_ext_ops *active_cache_ext_ops;

static inline bool cache_ext_enabled(void)
{
	return READ_ONCE(active_cache_ext_ops) != NULL;
}

#else /* !CONFIG_BPF_SYSCALL */

static inline bool cache_ext_enabled(void)
{
	return false;
}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* _LINUX_CACHE_EXT_H */
