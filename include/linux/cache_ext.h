/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H

#include <linux/types.h>

struct folio;
struct mem_cgroup;

#define CACHE_EXT_MAX_EVICT_BATCH 32

/*
 * Eviction context passed to the BPF evict_folios hook.
 *
 * The BPF program fills candidate_ino[] and candidate_idx[] with
 * (inode_id, page_index) tuples identifying folios to evict.
 * The kernel resolves these to struct folio * via the page cache
 * xarray (filemap_get_folio), ensuring pointer safety without
 * a valid folios registry.
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
