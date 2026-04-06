// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext — BPF struct_ops for custom page cache eviction policies.
 *
 * Allows a BPF program to implement folio tracking and eviction candidate
 * selection via struct_ops callbacks. The BPF program proposes eviction
 * candidates as (inode_id, page_index) integer tuples; the kernel resolves
 * them to struct folio * via xarray lookup (filemap_get_folio), ensuring
 * that no raw kernel pointers are exposed to BPF arena / userspace.
 */
#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/cache_ext.h>

struct cache_ext_ops *active_cache_ext_ops;

/* ── verifier ops ───────────────────────────────────────────────── */

static bool cache_ext_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int cache_ext_btf_struct_access(struct bpf_verifier_log *log,
				       const struct bpf_reg_state *reg,
				       int off, int size)
{
	const struct btf_type *evict_ctx;
	const struct btf_type *t;
	s32 type_id;

	type_id = btf_find_by_name_kind(reg->btf, "cache_ext_eviction_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	evict_ctx = btf_type_by_id(reg->btf, type_id);
	if (t != evict_ctx) {
		bpf_log(log, "only access to cache_ext_eviction_ctx is supported\n");
		return -EACCES;
	}

	if (off + size > sizeof(struct cache_ext_eviction_ctx)) {
		bpf_log(log, "write access at off %d with size %d\n", off, size);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops cache_ext_verifier_ops = {
	.is_valid_access = cache_ext_is_valid_access,
	.btf_struct_access = cache_ext_btf_struct_access,
};

/* ── check_member: allow init to be sleepable ───────────────────── */

static int cache_ext_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct cache_ext_ops, init):
		break;  /* init may be sleepable */
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int cache_ext_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	return 0;  /* no non-function fields to initialize */
}

/* ── reg / unreg ────────────────────────────────────────────────── */

static int cache_ext_reg(void *kdata, struct bpf_link *link)
{
	struct cache_ext_ops *ops = kdata;

	if (cmpxchg(&active_cache_ext_ops, NULL, ops) != NULL)
		return -EBUSY;  /* only one policy at a time */
	return 0;
}

static void cache_ext_unreg(void *kdata, struct bpf_link *link)
{
	WRITE_ONCE(active_cache_ext_ops, NULL);
}

/* ── CFI stubs ──────────────────────────────────────────────────── */

static int cache_ext_ops__init(struct mem_cgroup *memcg) { return 0; }
static void cache_ext_ops__folio_added(struct folio *folio) {}
static void cache_ext_ops__folio_accessed(struct folio *folio) {}
static void cache_ext_ops__folio_evicted(struct folio *folio) {}
static void cache_ext_ops__evict_folios(struct cache_ext_eviction_ctx *ctx,
					struct mem_cgroup *memcg) {}

static struct cache_ext_ops __bpf_cache_ext_ops = {
	.init           = cache_ext_ops__init,
	.folio_added    = cache_ext_ops__folio_added,
	.folio_accessed = cache_ext_ops__folio_accessed,
	.folio_evicted  = cache_ext_ops__folio_evicted,
	.evict_folios   = cache_ext_ops__evict_folios,
};

static int cache_ext_init(struct btf *btf)
{
	return 0;
}

static struct bpf_struct_ops bpf_cache_ext_ops = {
	.verifier_ops = &cache_ext_verifier_ops,
	.init         = cache_ext_init,
	.check_member = cache_ext_check_member,
	.init_member  = cache_ext_init_member,
	.reg          = cache_ext_reg,
	.unreg        = cache_ext_unreg,
	.name         = "cache_ext_ops",
	.cfi_stubs    = &__bpf_cache_ext_ops,
	.owner        = THIS_MODULE,
};

static int __init cache_ext_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_cache_ext_ops, cache_ext_ops);
}
late_initcall(cache_ext_struct_ops_init);
