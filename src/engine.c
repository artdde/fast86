#define _GNU_SOURCE
#include "f86.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <ucontext.h>
#include <unistd.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <cpuid.h>

#define CACHE_SZ   (512u << 20) /* memfd-backed, touched lazily */
#define MAP_BITS   22 /* 4M entries: XNU translates well over 2^18 instructions */
#define MAP_CAP    (1u << MAP_BITS)
#define MAP_MASK   (MAP_CAP - 1)
#define MAP_PROBES 64
#define BLK_INSNS  128
#define NPATCH     16384
#define PATCH_H    4096
#define SH_CAP     65536u
#define SCRATCH    0x000000007e000000ull /* must fit sign-extended abs32; keep low 512MiB free for firmware */
#define MAX_SYS    4096

typedef struct {
	uint64_t guest;
	uint8_t *host; /* RX pointer */
} MapEnt;

static uint8_t *g_rw, *g_rx, *g_emit, *g_cend;
static MapEnt   g_map[MAP_CAP];
static struct {
	uint8_t *h;
	uint64_t g;
} g_rev[1 << 21];
static uint32_t g_nrev;
static F86CPU  *g_cpu;
F86CPU *f86_alive_cpu(void) { return g_cpu; }
static uint8_t  g_host_stack[1 << 20];
static uint8_t *g_host_top = g_host_stack + sizeof(g_host_stack) - 128;
static jmp_buf  g_done;
static uint64_t *g_scr;
static uint64_t  g_host_fs, g_host_gs;
static uint8_t  *g_exit_tramp;
static int g_dbg, g_sys, g_cr, g_patch, g_flags_ready;
static uint64_t g_dt_slot, g_dt_slot2, g_dt_phys, g_kaddr;
static uint64_t g_boot_args;
uint64_t f86_kernel_boot_args(void) { return g_boot_args; }
uint64_t f86_kernel_base(void) { return g_kaddr; }
static uint64_t g_spec_g[24];
static uint8_t *g_spec_h[24];
static int g_nspec;
static int g_stride_done;
static int g_irq_ok;
static int g_vminit_ready;
int f86_kernel_pages_ready(void) { return g_irq_ok; }

#define SCR_OFF_NEXT  0
#define SCR_OFF_R11   8
#define SCR_OFF_RAX   16
#define SCR_OFF_TMP   24
#define SCR_OFF_RIP   32
#define SCR_OFF_SHN   40
#define SCR_OFF_INEXIT 48 /* byte: 1 while guest regs live in g_cpu->r[], not in the CPU */
#define SCR_OFF_T2    56 /* second temporary for the fsgsbase rewrites */
#define SCR_OFF_SHG   0x100
#define SCR_OFF_SHH   (0x100 + (size_t)SH_CAP * 8)
#define SCR_OFF_FX    0x001A0000

static void f86_soft_memop(void);
static void f86_fast_memcmp(void);
static void f86_fast_uuid_scan(void);
static void f86_fast_packed_walk(void);
static void f86_fast_cons(void);
static void f86_fast_stride(void);
static void f86_fast_rwspin(void);
static void f86_fast_rwwait(void);
static void f86_fast_rwassert(void);
static void f86_fast_timebase(void);
static void f86_fast_zcram(void);
static void f86_zalloc(void);
static void f86_map_create(void);
static void f86_map_enter(void);
static void f86_zfree_early(void);
static void f86_fast_zsteal(void);
static void f86_fast_startup_call(void);
static void f86_nop_ret(void);
static int plant_early_zone_mem(void);
static int pop_ret(F86CPU *c);
static uint64_t kload64(uint64_t unslid_lo);
static void f86_fast_memcmp(void);
static void f86_fast_uuid_scan(void);
static void f86_fast_packed_walk(void);
static void f86_fast_cons(void);
static void f86_fast_stride(void);
static void f86_fast_rwspin(void);
static void f86_fast_rwwait(void);
static void f86_fast_rwassert(void);
static void f86_fast_timebase(void);
static void f86_fast_zcram(void);
static void f86_zalloc(void);
static void f86_map_create(void);
static void f86_map_enter(void);
static void f86_zfree_early(void);
static void f86_fast_zsteal(void);
static void f86_fast_startup_call(void);
static void f86_nop_ret(void);
static int plant_early_zone_mem(void);
static int pop_ret(F86CPU *c);
static uint64_t kload64(uint64_t unslid_lo);
static int emulate_page0(ucontext_t *uc, void *addr);
static uint64_t g_strop_fault_gva;
static uint32_t g_strop_fault_err;
static int g_strop_fault_set;
static int gva_read(uint64_t gva, void *dst, size_t n);
static int gva_write(uint64_t gva, const void *src, size_t n);
static uint8_t *gva_host(uint64_t gva, size_t n);

#define g_next_host (*(uint8_t **)&g_scr[0])

static inline uint8_t *rx_of(uint8_t *rw)
{
	return rw + (g_rx - g_rw);
}

static uint64_t rd_fs(void)
{
	uint64_t v;
	__asm__ volatile("rdfsbase %0" : "=r"(v));
	return v;
}

static void wr_fs(uint64_t v)
{
	__asm__ volatile("wrfsbase %0" :: "r"(v) : "memory");
}

static uint64_t rd_gs(void)
{
	uint64_t v;
	__asm__ volatile("rdgsbase %0" : "=r"(v));
	return v;
}

static void wr_gs(uint64_t v)
{
	__asm__ volatile("wrgsbase %0" :: "r"(v) : "memory");
}

static void init_env_flags(void)
{
	if (g_flags_ready)
		return;
	g_flags_ready = 1;
	g_dbg   = getenv("F86_DEBUG") != NULL;
	g_sys   = getenv("F86_SYS") != NULL;
	g_cr    = getenv("F86_CR") != NULL;
	g_patch = getenv("F86_PATCH") != NULL;
}

void f86_halt(void)
{
	longjmp(g_done, 1);
}

static uint32_t map_hash(uint64_t guest)
{
	return (uint32_t)(guest * 11400714819323198485ull >> (64 - MAP_BITS));
}

static uint8_t *lookup(uint64_t guest)
{
	uint32_t i = map_hash(guest);
	for (int n = 0; n < MAP_PROBES; n++) {
		if (g_map[i].guest == guest && g_map[i].host)
			return g_map[i].host;
		if (!g_map[i].host)
			return NULL;
		i = (i + 1) & MAP_MASK;
	}
	return NULL;
}

static struct {
	uint64_t g;
	uint8_t *rel;   /* RW pointer to rel32 field */
	uint32_t next;  /* 1-based index, 0 = end */
} g_patches[NPATCH];
static uint32_t g_phead[PATCH_H];
static int g_npatch;

static void apply_patches(uint64_t guest, uint8_t *host_rx)
{
	uint32_t h = (uint32_t)guest & (PATCH_H - 1);
	for (uint32_t idx = g_phead[h]; idx; idx = g_patches[idx - 1].next) {
		if (g_patches[idx - 1].g != guest || !g_patches[idx - 1].rel)
			continue;
		uint8_t *rel = g_patches[idx - 1].rel;
		int32_t r = (int32_t)(host_rx - (rx_of(rel) + 4));
		memcpy(rel, &r, 4);
		if (g_patch)
			fprintf(stderr, "patch guest=%lx host=%p rel=%p d=%d\n",
			        (unsigned long)guest, (void *)host_rx,
			        (void *)rel, (int)r);
		g_patches[idx - 1].rel = NULL;
	}
}

/* F86_NOCHAIN=1: never chain blocks directly; every jump/call goes through
   the dispatcher, so F86_TRACE_* fire on every execution (diagnosis only). */
static int g_nochain = -1;
static inline int nochain(void)
{
	if (g_nochain < 0)
		g_nochain = getenv("F86_NOCHAIN") != NULL;
	return g_nochain;
}
static uint8_t *lookup(uint64_t guest);
static inline uint8_t *lookup_chain(uint64_t guest)
{
	return nochain() ? NULL : lookup(guest);
}

static void add_patch(uint64_t guest, uint8_t *rel_rw)
{
	if (nochain())
		return;
	if (g_npatch >= NPATCH)
		return;
	uint32_t h = (uint32_t)guest & (PATCH_H - 1);
	g_patches[g_npatch].g = guest;
	g_patches[g_npatch].rel = rel_rw;
	g_patches[g_npatch].next = g_phead[h];
	g_phead[h] = (uint32_t)g_npatch + 1;
	g_npatch++;
}

static void map_evict(uint64_t guest)
{
	uint32_t i = map_hash(guest);
	for (int n = 0; n < MAP_PROBES; n++) {
		if (g_map[i].guest == guest) {
			g_map[i].guest = 0;
			g_map[i].host = NULL;
			return;
		}
		if (!g_map[i].host)
			return;
		i = (i + 1) & MAP_MASK;
	}
}

static void insert(uint64_t guest, uint8_t *host_rx)
{
	uint32_t i = map_hash(guest);
	for (int n = 0; n < MAP_PROBES; n++) {
		if (!g_map[i].host || g_map[i].guest == guest) {
			g_map[i].guest = guest;
			g_map[i].host = host_rx;
			apply_patches(guest, host_rx);
			if (g_nrev < (uint32_t)(sizeof g_rev / sizeof g_rev[0])) {
				g_rev[g_nrev].h = host_rx;
				g_rev[g_nrev].g = guest;
				g_nrev++;
			}
			return;
		}
		i = (i + 1) & MAP_MASK;
	}
}

static uint64_t host_to_guest_exact(uint8_t *hip);

static uint64_t host_to_guest(uint8_t *hip)
{
	if (!g_nrev || !hip)
		return 0;
	uint32_t lo = 0, hi = g_nrev;
	while (lo + 1 < hi) {
		uint32_t m = (lo + hi) / 2;
		if (g_rev[m].h <= hip)
			lo = m;
		else
			hi = m;
	}
	if (g_rev[lo].h && g_rev[lo].h <= hip &&
	    hip < g_rev[lo].h + 2048)
		return g_rev[lo].g;
	return 0;
}

/* ---------------- segment-alias softmmu (system mode) ----------------
   Guest code runs with the host FS base = g_alias_off and every explicit
   memory operand carries a 0x64 override, so the CPU computes
   host EA = guest EA + g_alias_off (mod 2^64), which lands inside a 1 TiB
   PROT_NONE reservation: kernel-half VAs in its first half, the low 512 GiB
   in its second. Pages are mapped there from the RAM memfd on first touch
   (SIGSEGV -> alias_populate -> retry) and dropped on INVLPG / CR3 writes,
   so the host MMU is the TLB and the signal-per-access emulation is only
   left for MMIO, page 0 and the out-of-range fallback.
   Design notes: /root/f86-work/softmmu-design.md */
/* XNU's kernel half is not just the 0xffffff80 window: the double map sits
   around 0xfffff6b8_c0000000 and the physmap around 0xfffffe..., i.e. the
   top 32 PML4 slots (16 TiB) are in use. The reservation covers guest VAs
   [0xffffe000_00000000, 2^64) in its first 16 TiB and [0, 512 GiB) after. */
#define ALIAS_KPART (16ull << 40)
#define ALIAS_LOW   (1ull << 39)
#define ALIAS_SZ    (ALIAS_KPART + ALIAS_LOW)
static uint8_t *g_alias;
static uint64_t g_alias_off;
static uint8_t  g_alias_big[ALIAS_SZ >> 24]; /* one bit per 2 MiB chunk mapped whole */
static uint64_t g_alias_pop, g_alias_pop2m, g_alias_inv, g_alias_fl;

uint64_t f86_alias_off(void) { return g_alias_off; }
int f86_alias_on(void) { return g_alias != NULL; }
static uint64_t g_pt_diffs, g_pt_flushes;
static uint32_t g_npt;
void f86_alias_stats(uint64_t *pop, uint64_t *pop2m, uint64_t *inv, uint64_t *fl)
{
	*pop = g_alias_pop; *pop2m = g_alias_pop2m; *inv = g_alias_inv; *fl = g_alias_fl;
	fprintf(stderr, "fast86: alias pt-pages=%u pt-flushes=%lu pt-entry-changes=%lu\n",
	        g_npt, (unsigned long)g_pt_flushes, (unsigned long)g_pt_diffs);
}

static void alias_reserve(void)
{
	if (!f86_in_system() || g_alias)
		return;
	if (getenv("F86_NOALIAS"))
		return;
	/* Fixed placement keeps the set of guest VAs that could alias live
	   host mappings independent of ASLR; fall back to any address. */
	void *p = mmap((void *)0x100000000000ull, ALIAS_SZ, PROT_NONE,
	               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
	if (p == MAP_FAILED)
		p = mmap(NULL, ALIAS_SZ, PROT_NONE,
		         MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) {
		perror("mmap alias");
		exit(1);
	}
	g_alias = p;
	g_alias_off = (uint64_t)(uintptr_t)p + ALIAS_KPART;
	fprintf(stderr, "fast86: alias %p..+%lluTiB off=%lx\n", p,
	        (unsigned long long)(ALIAS_SZ >> 40), (unsigned long)g_alias_off);
}

static void alias_unmap(uint64_t o, uint64_t len)
{
	if (mmap(g_alias + o, (size_t)len, PROT_NONE,
	         MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0) == MAP_FAILED) {
		/* VMA exhaustion: replacing the whole region with one mapping
		   cannot fail for lack of VMAs, and over-invalidation is safe. */
		static int nfl;
		if (nfl++ < 4)
			fprintf(stderr, "fast86: alias unmap %lx+%lx failed (%s): dropping everything\n",
			        (unsigned long)o, (unsigned long)len, strerror(errno));
		if (len != ALIAS_SZ || o != 0)
			mmap(g_alias, ALIAS_SZ, PROT_NONE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
		memset(g_alias_big, 0, sizeof g_alias_big);
	}
}

/* INVLPG: drop the alias page for gva (the whole 2 MiB chunk when it was
   mapped as one large page). */
void f86_alias_inval(uint64_t gva)
{
	if (!g_alias)
		return;
	uint64_t o = (gva + g_alias_off) - (uint64_t)(uintptr_t)g_alias;
	if (o >= ALIAS_SZ)
		return;
	uint64_t ch = o >> 21;
	if (g_alias_big[ch >> 3] & (uint8_t)(1u << (ch & 7))) {
		g_alias_big[ch >> 3] &= (uint8_t)~(1u << (ch & 7));
		alias_unmap(ch << 21, 2u << 20);
	} else
		alias_unmap(o & ~0xfffull, 4096);
	g_alias_inv++;
}

/* Drop the whole reservation: CR0.PG / CR4 paging-mode changes. */
void f86_alias_drop_all(void)
{
	if (!g_alias)
		return;
	alias_unmap(0, ALIAS_SZ);
	memset(g_alias_big, 0, sizeof g_alias_big);
	g_alias_fl++;
}

/* Drop the alias pages for a guest VA range (clipped to the two windows). */
static void alias_unmap_va(uint64_t va, uint64_t len)
{
	if (!len)
		return;
	uint64_t o = (va + g_alias_off) - (uint64_t)(uintptr_t)g_alias;
	if (o >= ALIAS_SZ) {
		/* the range may start below a window and run into it */
		if (va < 0xfffff00000000000ull && va + len > 0xfffff00000000000ull) {
			len -= 0xfffff00000000000ull - va;
			va = 0xfffff00000000000ull;
			o = 0;
		} else
			return;
	}
	if (o + len > ALIAS_SZ)
		len = ALIAS_SZ - o;
	/* window edge: the kernel part ends at ALIAS_KPART, the low part at the end */
	if (o < ALIAS_KPART && o + len > ALIAS_KPART)
		len = ALIAS_KPART - o;
	uint64_t s0 = o & ~0xfffull, e0 = (o + len + 0xfffull) & ~0xfffull;
	/* 2 MiB chunks touched by the range go whole */
	uint64_t c0 = s0 >> 21, c1 = (e0 - 1) >> 21;
	if (g_alias_big[c0 >> 3] & (uint8_t)(1u << (c0 & 7)))
		s0 = c0 << 21;
	if (g_alias_big[c1 >> 3] & (uint8_t)(1u << (c1 & 7)))
		e0 = (c1 + 1) << 21;
	for (uint64_t ch = s0 >> 21; ch <= (e0 - 1) >> 21; ch++)
		g_alias_big[ch >> 3] &= (uint8_t)~(1u << (ch & 7));
	alias_unmap(s0, e0 - s0);
}

/* Page-table page records: every page-table page a populate walked
   through, with a 4 KiB snapshot. A "TLB flush" (INVPCID ALLG, same-CR3
   reload, ...) is applied by diffing each recorded page against its
   snapshot and dropping exactly the alias ranges whose entries changed,
   instead of tearing down the whole reservation (XNU flushes ~1000 times
   per second of boot, and re-populating a page costs ~20 us). */
#define PTREC_BITS 15
#define PTREC_CAP  (1u << PTREC_BITS)
struct ptrec {
	uint64_t gpa;    /* page-table page (RAM) */
	uint64_t vabase; /* guest VA covered by entry 0 */
	uint8_t  level;  /* 4 PML4, 3 PDPT, 2 PD, 1 PT */
	uint8_t  live;
	uint32_t slot;   /* snapshot slot */
};
static struct ptrec g_pt[PTREC_CAP];
static uint8_t *g_pt_snap;

static struct ptrec *ptrec_find(uint64_t gpa, int create)
{
	uint32_t h = (uint32_t)((gpa >> 12) * 0x9E3779B1u) & (PTREC_CAP - 1);
	for (uint32_t n = 0; n < PTREC_CAP; n++) {
		struct ptrec *r = &g_pt[(h + n) & (PTREC_CAP - 1)];
		if (!r->gpa) {
			if (!create || g_npt + 1 >= PTREC_CAP - 64)
				return NULL;
			r->gpa = gpa;
			r->slot = g_npt++;
			r->live = 0;
			return r;
		}
		if (r->gpa == gpa)
			return r;
	}
	return NULL;
}

static void ptrec_record(uint64_t gpa, int level, uint64_t vabase)
{
	if (!g_pt_snap) {
		g_pt_snap = mmap(NULL, (size_t)PTREC_CAP * 4096, PROT_READ | PROT_WRITE,
		                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (g_pt_snap == MAP_FAILED) {
			g_pt_snap = NULL;
			return;
		}
	}
	struct ptrec *r = ptrec_find(gpa, 1);
	if (!r)
		return;
	if (!r->live || r->level != level || r->vabase != vabase) {
		r->level = (uint8_t)level;
		r->vabase = vabase;
		if (!r->live) {
			memcpy(g_pt_snap + (size_t)r->slot * 4096, f86_ram() + gpa, 4096);
			r->live = 1;
		}
	}
}

static void ptrec_kill(uint64_t gpa)
{
	struct ptrec *r = ptrec_find(gpa, 0);
	if (r)
		r->live = 0;
}

/* Apply the changes between a recorded page and its snapshot. */
static void ptrec_apply(struct ptrec *r)
{
	const uint64_t *cur = (const uint64_t *)(f86_ram() + r->gpa);
	uint64_t *old = (uint64_t *)(g_pt_snap + (size_t)r->slot * 4096);
	if (memcmp(cur, old, 4096) == 0)
		return;
	int shift = r->level == 1 ? 12 : r->level == 2 ? 21 : r->level == 3 ? 30 : 39;
	for (int i = 0; i < 512; i++) {
		if (cur[i] == old[i])
			continue;
		uint64_t va = r->vabase + ((uint64_t)i << shift);
		if (r->level == 4 && i >= 256)
			va |= 0xffff000000000000ull;
		if ((old[i] & 1) || (cur[i] & 1))
			alias_unmap_va(va, 1ull << shift);
		/* an entry that pointed at a lower-level table: that page may be
		   reused for anything now */
		if (r->level >= 2 && (old[i] & 1) && !(old[i] & (1ull << 7)))
			ptrec_kill(old[i] & 0x000ffffffffff000ull);
		g_pt_diffs++;
	}
	memcpy(old, cur, 4096);
}

/* TLB-flush semantics for the alias: 0 drop all, 1 user half + pending
   page-table changes, 2 pending page-table changes only. */
void f86_alias_flush(int which)
{
	if (!g_alias)
		return;
	static int nuke = -1;
	if (nuke < 0)
		nuke = getenv("F86_ALIAS_NUKE") != NULL;
	if (which == 0 || nuke) {
		f86_alias_drop_all();
		return;
	}
	if (which == 1) {
		alias_unmap(ALIAS_KPART, ALIAS_LOW);
		memset(g_alias_big + (ALIAS_KPART >> 24), 0, (size_t)(ALIAS_LOW >> 24));
	}
	g_pt_flushes++;
	for (uint32_t i = 0; i < PTREC_CAP; i++) {
		struct ptrec *r = &g_pt[i];
		if (r->gpa && r->live)
			ptrec_apply(r);
	}
	g_alias_fl++;
}

/* SIGSEGV inside the alias: map the guest page there so the access can be
   retried natively. Returns 1 when mapped; *gva_out is the guest address. */
static int alias_populate(uint64_t fa, uint64_t *gva_out)
{
	uint64_t o = fa - (uint64_t)(uintptr_t)g_alias;
	uint64_t gva = fa - g_alias_off;
	*gva_out = gva;
	uint64_t gpa = 0;
	if (!f86_gva_to_gpa(gva, &gpa))
		return 0;
	if (f86_sys_is_mmio(gpa) || gpa >= f86_ram_size())
		return 0;
	int fd = f86_ram_fd();
	if (fd < 0)
		return 0;
	{
		uint64_t tb[4], bs[4];
		int lv[4];
		int n = f86_walk_tables(gva, tb, bs, lv);
		for (int i = 0; i < n; i++)
			ptrec_record(tb[i], lv[i], bs[i]);
	}
	if (f86_walk_shift() >= 21 && ((gva ^ gpa) & 0x1fffffull) == 0 &&
	    (gpa & ~0x1fffffull) + (2u << 20) <= f86_ram_size() &&
	    (o & ~0x1fffffull) + (2u << 20) <= ALIAS_SZ) {
		uint64_t co = o & ~0x1fffffull;
		if (mmap(g_alias + co, 2u << 20, PROT_READ | PROT_WRITE,
		         MAP_SHARED | MAP_FIXED, fd, (off_t)(gpa & ~0x1fffffull)) != MAP_FAILED) {
			g_alias_big[(co >> 21) >> 3] |= (uint8_t)(1u << ((co >> 21) & 7));
			g_alias_pop2m++;
			return 1;
		}
	}
	if (mmap(g_alias + (o & ~0xfffull), 4096, PROT_READ | PROT_WRITE,
	         MAP_SHARED | MAP_FIXED, fd, (off_t)(gpa & ~0xfffull)) == MAP_FAILED) {
		int e = errno;
		if (e == ENOMEM) { /* vm.max_map_count: drop everything and retry once */
			f86_alias_flush(0);
			if (mmap(g_alias + (o & ~0xfffull), 4096, PROT_READ | PROT_WRITE,
			         MAP_SHARED | MAP_FIXED, fd, (off_t)(gpa & ~0xfffull)) != MAP_FAILED) {
				g_alias_pop++;
				return 1;
			}
			e = errno;
		}
		static int nerr;
		if (nerr++ < 4)
			fprintf(stderr, "fast86: alias mmap failed gva=%lx gpa=%lx: %s\n",
			        (unsigned long)gva, (unsigned long)gpa, strerror(e));
		return 0;
	}
	g_alias_pop++;
	return 1;
}

/* Guest instruction that starts exactly at hip, or 0. Interrupt injection
   must only happen on such boundaries: inside a multi-instruction rewrite
   (riprel via r11, push/pop through the alias) the registers are not the
   guest's and RSP may be half-updated. */
static uint64_t host_to_guest_exact(uint8_t *hip)
{
	if (!g_nrev || !hip)
		return 0;
	uint32_t lo = 0, hi = g_nrev;
	while (lo + 1 < hi) {
		uint32_t m = (lo + hi) / 2;
		if (g_rev[m].h <= hip)
			lo = m;
		else
			hi = m;
	}
	return (g_rev[lo].h == hip) ? g_rev[lo].g : 0;
}

static void em1(uint8_t b) { *g_emit++ = b; }
static void em4(uint32_t v) { memcpy(g_emit, &v, 4); g_emit += 4; }
static void em8(uint64_t v) { memcpy(g_emit, &v, 8); g_emit += 8; }

static void emit_spill_all(void)
{
	/* Mark the exit window: from here until emit_fill_all finishes, the
	   live CPU registers are scratch (RAX holds the guest RIP, RSP moves
	   to the host stack) and g_cpu->r[] is authoritative. The timer
	   signal handler must not republish live registers in this window —
	   it used to, so a tick landing between the spill and the indirect
	   branch helper made f86_do_indirect compute [rax+...] with rax = RIP. */
	em1(0xC6); em1(0x04); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_INEXIT)); em1(0x01);
	em1(0x48); em1(0xA3); em8((uint64_t)&g_cpu->r[R_RAX]);
	em1(0x48); em1(0xB8); em8((uint64_t)&g_cpu->r[0]);
	for (int i = 1; i < 16; i++) {
		if (i < 8) {
			em1(0x48); em1(0x89); em1((uint8_t)(0x40 | (i << 3)));
			em1((uint8_t)(8 * i));
		} else {
			em1(0x4C); em1(0x89); em1((uint8_t)(0x40 | ((i & 7) << 3)));
			em1((uint8_t)(8 * i));
		}
	}
	em1(0x0F); em1(0x90); em1(0xC0);
	em1(0x9F);
	em1(0x48); em1(0xA3); em8((uint64_t)&g_cpu->rflags);
}

static void emit_fill_all(void)
{
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->rflags);
	em1(0x04); em1(0x7F);
	em1(0x9E);
	em1(0x48); em1(0xBB); em8((uint64_t)&g_cpu->r[0]);
	for (int i = 1; i < 16; i++) {
		if (i == R_RBX)
			continue;
		if (i < 8) {
			em1(0x48); em1(0x8B); em1((uint8_t)(0x43 | (i << 3)));
			em1((uint8_t)(8 * i));
		} else {
			em1(0x4C); em1(0x8B); em1((uint8_t)(0x43 | ((i & 7) << 3)));
			em1((uint8_t)(8 * i));
		}
	}
	em1(0x48); em1(0x8B); em1(0x03);
	em1(0x48); em1(0x8B); em1(0x5B); em1((uint8_t)(8 * R_RBX));
	em1(0xC6); em1(0x04); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_INEXIT)); em1(0x00);
}

static void emit_store_r11_scr(void)
{
	em1(0x4C); em1(0x89); em1(0x1C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_R11));
}

static void emit_load_r11_scr(void)
{
	em1(0x4C); em1(0x8B); em1(0x1C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_R11));
}

static void emit_store_r10_scr(void)
{
	em1(0x4C); em1(0x89); em1(0x14); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_TMP));
}

static void emit_load_r10_scr(void)
{
	em1(0x4C); em1(0x8B); em1(0x14); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_TMP));
}

static void emit_host_stack(void)
{
	em1(0x48); em1(0xBC); em8((uint64_t)(uintptr_t)g_host_top);
}

/* ---- guest-stack and guest-memory emitters for the alias softmmu ----
   push/pop/call/ret/leave have no segment override, so they are rewritten
   into explicit forms: a store/load through fs:[rsp+d] plus LEA on RSP
   (LEA keeps the flags, as push/pop do). The store precedes the RSP update
   so a fault reports the instruction with RSP untouched. */
static int sys_alias(void)
{
	return g_alias != NULL && f86_in_system();
}

static void emit_lea_rsp(int32_t d)
{
	if (d >= -128 && d <= 127) {
		em1(0x48); em1(0x8D); em1(0x64); em1(0x24); em1((uint8_t)(int8_t)d);
	} else {
		em1(0x48); em1(0x8D); em1(0xA4); em1(0x24); em4((uint32_t)d);
	}
}

static void emit_modrm_rsp(int r, int32_t d)
{
	if (d == 0) {
		em1((uint8_t)(0x04 | ((r & 7) << 3))); em1(0x24);
	} else if (d >= -128 && d <= 127) {
		em1((uint8_t)(0x44 | ((r & 7) << 3))); em1(0x24); em1((uint8_t)(int8_t)d);
	} else {
		em1((uint8_t)(0x84 | ((r & 7) << 3))); em1(0x24); em4((uint32_t)d);
	}
}

/* mov fs:[rsp+d], r64 */
static void emit_stk_store(int r, int32_t d)
{
	em1(0x64); em1((uint8_t)(r >= 8 ? 0x4C : 0x48)); em1(0x89); emit_modrm_rsp(r, d);
}

/* mov r64, fs:[rsp+d] */
static void emit_stk_load(int r, int32_t d)
{
	em1(0x64); em1((uint8_t)(r >= 8 ? 0x4C : 0x48)); em1(0x8B); emit_modrm_rsp(r, d);
}

/* push simm32 */
static void emit_push_imm32(int32_t imm)
{
	/* mov qword fs:[rsp-8], simm32 ; lea rsp,[rsp-8]: store first so a
	   fault leaves RSP untouched */
	em1(0x64); em1(0x48); em1(0xC7); em1(0x44); em1(0x24); em1(0xF8); em4((uint32_t)imm);
	emit_lea_rsp(-8);
}

/* push r64 / pop r64 */
static void emit_push_reg(int r)
{
	emit_stk_store(r, -8);
	emit_lea_rsp(-8);
}

static void emit_pop_reg(int r)
{
	emit_stk_load(r, 0);
	if (r != R_RSP)
		emit_lea_rsp(8);
}

/* Legacy prefixes of ip: returns the index of the first non-prefix byte;
   *seg gets 1 for null overrides (26/2E/36/3E), 2 for fs, 4 for gs. */
static int scan_prefixes(const uint8_t *ip, int len, int *seg)
{
	int i = 0;
	*seg = 0;
	while (i < len && i < 14) {
		uint8_t b = ip[i];
		if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E)
			*seg |= 1;
		else if (b == 0x64)
			*seg |= 2;
		else if (b == 0x65)
			*seg |= 4;
		else if (b != 0x66 && b != 0x67 && b != 0xF0 && b != 0xF2 && b != 0xF3)
			break;
		i++;
	}
	return i;
}

/* Can d's memory operand be addressed through r11 as a temporary? */
static int rm_avoids_r11(const uint8_t *ip, const F86Insn *d)
{
	if (d->flags & F86_RIPREL)
		return 0;
	int rm = (d->modrm & 7) | ((d->rex & 1) ? 8 : 0);
	if ((d->modrm & 7) == 4) {
		uint8_t sib = ip[d->modrm_off + 1];
		int base = (sib & 7) | ((d->rex & 1) ? 8 : 0);
		int index = ((sib >> 3) & 7) | ((d->rex & 2) ? 8 : 0);
		if (base == 11 || index == 11)
			return 0;
		return 1;
	}
	return rm != 11;
}

/* mov r11, fs:[m] (load) or mov fs:[m], r11 (store) with d's memory
   operand (no immediate: FF /6 and 8F /0 only). */
static void emit_rm_r11(const uint8_t *ip, const F86Insn *d, int load)
{
	em1(0x64);
	em1((uint8_t)(0x4C | (d->rex & 0x03)));
	em1(load ? 0x8B : 0x89);
	em1((uint8_t)((d->modrm & 0xC7) | 0x18));
	for (int i = d->modrm_off + 1; i < d->len; i++)
		em1(ip[i]);
}

static void emit_jmp_next_host(void)
{
	em1(0xFF); em1(0x24); em1(0x25); em4((uint32_t)SCRATCH);
}

/* Save/restore the full x87/SSE/AVX state around C helpers: glibc's
   memcpy/strlen and the compiler's own 16-byte moves use xmm/ymm, and the
   guest may hold live SIMD values at any exit (corecrypto's AES/SHA
   kernels run with rep movs and cld sysops in between). Needs rax/rdx
   free: callers spill the GPRs first. */
static void emit_xsave(void)
{
	em1(0x31); em1(0xD2);                         /* xor edx,edx */
	em1(0xB8); em4(7);                            /* mov eax,7 */
	em1(0x48); em1(0x0F); em1(0xAE); em1(0x24); em1(0x25); /* xsave64 [abs32] */
	em4((uint32_t)(SCRATCH + SCR_OFF_FX));
}

static void emit_xrstor(void)
{
	em1(0x31); em1(0xD2);
	em1(0xB8); em4(7);
	em1(0x48); em1(0x0F); em1(0xAE); em1(0x2C); em1(0x25); /* xrstor64 [abs32] */
	em4((uint32_t)(SCRATCH + SCR_OFF_FX));
}

/* wrfsbase from a 64-bit memory slot. Does not touch guest GPRs. */
static void emit_wrfs_slot(uint64_t *slot)
{
	emit_store_r11_scr();
	em1(0x49); em1(0xBB); em8((uint64_t)slot);
	em1(0x4D); em1(0x8B); em1(0x1B);
	em1(0xF3); em1(0x49); em1(0x0F); em1(0xAE); em1(0xD3);
	emit_load_r11_scr();
}

static void emit_wrgs_slot(uint64_t *slot)
{
	if (!f86_in_system())
		return;
	emit_store_r11_scr();
	em1(0x49); em1(0xBB); em8((uint64_t)slot);
	em1(0x4D); em1(0x8B); em1(0x1B);
	em1(0xF3); em1(0x49); em1(0x0F); em1(0xAE); em1(0xDB);
	emit_load_r11_scr();
}

static void emit_host_segs(void)
{
	emit_wrfs_slot(&g_host_fs);
	emit_wrgs_slot(&g_host_gs);
}

static void emit_guest_segs(void)
{
	if (sys_alias())
		emit_wrfs_slot(&g_alias_off); /* FS carries the alias offset */
	else
		emit_wrfs_slot(&g_cpu->fs_base);
	emit_wrgs_slot(&f86_gs_host);
}

static void emit_jmp_rel32(uint8_t *from_rw, uint8_t *to_rx)
{
	int32_t d = (int32_t)(to_rx - (rx_of(from_rw) + 5));
	from_rw[0] = 0xE9;
	memcpy(from_rw + 1, &d, 4);
}

void f86_dispatch(void);

static void emit_exit_body(void)
{
	emit_spill_all();
	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RIP));
	em1(0x48); em1(0xA3); em8((uint64_t)&g_cpu->rip);
	emit_xsave();
	emit_host_segs();
	emit_host_stack();
	em1(0x48); em1(0xB8); em8((uint64_t)f86_dispatch);
	em1(0xFF); em1(0xD0);
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->exited);
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); em1(0x0C);
	em1(0x48); em1(0xB8); em8((uint64_t)f86_halt);
	em1(0xFF); em1(0xE0);
	emit_xrstor();
	emit_guest_segs();
	emit_fill_all();
	emit_jmp_next_host();
}

/* Compact unlinked-exit stub: park guest RIP, jump to the shared trampoline. */
static void emit_exit_to(uint64_t guest_rip)
{
	emit_store_r11_scr();
	em1(0x49); em1(0xBB); em8(guest_rip);
	em1(0x4C); em1(0x89); em1(0x1C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_RIP));
	emit_load_r11_scr();
	emit_jmp_rel32(g_emit, g_exit_tramp);
	g_emit += 5;
}

static void emit_c_helper(void (*fn)(void))
{
	emit_xsave();
	emit_host_segs();
	emit_host_stack();
	em1(0x48); em1(0xB8); em8((uint64_t)fn);
	em1(0xFF); em1(0xD0);
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->exited);
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); em1(0x0C);
	em1(0x48); em1(0xB8); em8((uint64_t)f86_halt);
	em1(0xFF); em1(0xE0);
	emit_xrstor();
	emit_guest_segs();
	emit_fill_all();
	emit_jmp_next_host();
}

/* Indirect call/jmp: keep guest GS, only swap FS + stack for C. */
static void emit_fast_helper(void (*fn)(void))
{
	emit_xsave();
	emit_wrfs_slot(&g_host_fs);
	emit_host_stack();
	em1(0x48); em1(0xB8); em8((uint64_t)fn);
	em1(0xFF); em1(0xD0);
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->exited);
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); em1(0x0C);
	em1(0x48); em1(0xB8); em8((uint64_t)f86_halt);
	em1(0xFF); em1(0xE0);
	emit_xrstor();
	if (sys_alias())
		emit_wrfs_slot(&g_alias_off);
	else
		emit_wrfs_slot(&g_cpu->fs_base);
	emit_fill_all();
	emit_jmp_next_host();
}

static void emit_store_u64(uint64_t *dst, uint64_t val)
{
	em1(0x48); em1(0xB8); em8(val);
	em1(0x48); em1(0xA3); em8((uint64_t)dst);
}

void f86_dispatch(void)
{
	g_cpu->n_exits++;
	if (g_cpu->exited)
		return;
	if (f86_in_system()) {
		f86_replant_dt();
		f86_sys_deliver_irq(g_cpu);
	}
	/* Exit watchdog: F86_MAX_EXITS (default effectively unlimited). The
	   old fixed 10M cap killed any real OS boot after a few minutes. */
	static uint64_t max_exits;
	if (!max_exits) {
		const char *e = getenv("F86_MAX_EXITS");
		max_exits = e ? strtoull(e, NULL, 0) : ~0ull;
		if (!max_exits)
			max_exits = ~0ull;
	}
	if (g_cpu->n_exits > max_exits) {
		fprintf(stderr, "fast86: abort spin at rip=%lx exits=%lu\n",
		        (unsigned long)g_cpu->rip, (unsigned long)g_cpu->n_exits);
		g_cpu->exited = 1;
		g_cpu->exit_code = 124;
		return;
	}
	if (g_dbg)
		fprintf(stderr, "dispatch rip=%lx rsp=%lx rbp=%lx exits=%lu\n",
		        (unsigned long)g_cpu->rip,
		        (unsigned long)g_cpu->r[R_RSP],
		        (unsigned long)g_cpu->r[R_RBP],
		        (unsigned long)g_cpu->n_exits);
	g_next_host = f86_translate(g_cpu, g_cpu->rip);
	if (g_dbg)
		fprintf(stderr, "  next_host=%p\n", (void *)g_next_host);
	if (!g_next_host) {
		fprintf(stderr, "fast86: translate returned NULL at %lx\n",
		        (unsigned long)g_cpu->rip);
		g_cpu->exited = 1;
		g_cpu->exit_code = 127;
	}
}

static long raw_syscall6(long n, long a0, long a1, long a2,
                         long a3, long a4, long a5)
{
	register long rax __asm__("rax") = n;
	register long rdi __asm__("rdi") = a0;
	register long rsi __asm__("rsi") = a1;
	register long rdx __asm__("rdx") = a2;
	register long r10 __asm__("r10") = a3;
	register long r8  __asm__("r8")  = a4;
	register long r9  __asm__("r9")  = a5;
	__asm__ volatile("syscall"
	                 : "+r"(rax)
	                 : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return rax;
}

long f86_do_syscall(F86CPU *cpu)
{
	long nr = (long)cpu->r[R_RAX];
	long a0 = (long)cpu->r[R_RDI];
	long a1 = (long)cpu->r[R_RSI];
	long a2 = (long)cpu->r[R_RDX];
	long a3 = (long)cpu->r[R_R10];
	long a4 = (long)cpu->r[R_R8];
	long a5 = (long)cpu->r[R_R9];
	cpu->n_syscalls++;

	switch (nr) {
	case SYS_exit:
	case SYS_exit_group:
		cpu->exit_code = (int)a0;
		cpu->exited = 1;
		return 0;
	case SYS_brk: {
		if (a0 == 0)
			return (long)cpu->brk;
		if ((uint64_t)a0 < cpu->brk_base)
			return (long)cpu->brk;
		uint64_t want = (uint64_t)a0;
		uint64_t oldp = (cpu->brk + 0xfff) & ~0xfffull;
		uint64_t newp = (want + 0xfff) & ~0xfffull;
		if (newp > oldp) {
			void *p = mmap((void *)oldp, newp - oldp,
			               PROT_READ | PROT_WRITE,
			               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			if (p == MAP_FAILED)
				return -ENOMEM;
		} else if (newp < oldp) {
			munmap((void *)newp, oldp - newp);
		}
		cpu->brk = want;
		if (g_sys)
			fprintf(stderr, "brk %lx -> %lx\n",
			        (unsigned long)a0, (unsigned long)cpu->brk);
		return (long)want;
	}
	case SYS_arch_prctl:
		if (a0 == ARCH_SET_FS) {
			cpu->fs_base = (uint64_t)a1;
			return 0;
		}
		if (a0 == ARCH_GET_FS) {
			if (!a1)
				return -EFAULT;
			*(uint64_t *)(uintptr_t)a1 = cpu->fs_base;
			return 0;
		}
		if (a0 == ARCH_SET_GS) {
			cpu->gs_base = (uint64_t)a1;
			return 0;
		}
		if (a0 == ARCH_GET_GS) {
			if (!a1)
				return -EFAULT;
			*(uint64_t *)(uintptr_t)a1 = cpu->gs_base;
			return 0;
		}
		return raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
	default:
		if (g_sys)
			fprintf(stderr, "syscall %ld (%lx %lx %lx)\n", nr, a0, a1, a2);
		return raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
	}
}

void f86_on_priv(void)
{
	f86_on_sysop();
}

void f86_on_syscall(void)
{
	g_cpu->n_exits++;
	if (f86_sys_take_syscall(g_cpu)) {
		if (!g_cpu->exited)
			f86_set_next(g_cpu->rip);
		return;
	}
	long r = f86_do_syscall(g_cpu);
	if (!g_cpu->exited)
		g_cpu->r[R_RAX] = (uint64_t)r;
}

static void trace_cr(char kind, uint64_t a, uint64_t b)
{
	if (g_cr)
		fprintf(stderr, "  %c rsp=%lx a=%lx b=%lx\n", kind,
		        (unsigned long)g_cpu->r[R_RSP],
		        (unsigned long)a, (unsigned long)b);
}

static uint64_t rm_value(F86CPU *cpu, uint64_t insn_rip, const uint8_t *ip)
{
	F86Insn d;
	if (!ip)
		ip = (const uint8_t *)insn_rip;
	if (!f86_decode(ip, ip + 16, &d))
		return 0;
	uint8_t m = d.modrm;
	int mod = m >> 6, rm = m & 7;
	if (d.rex & 1)
		rm |= 8;
	if (mod == 3)
		return cpu->r[rm];
	uint64_t addr;
	if (d.flags & F86_RIPREL)
		addr = insn_rip + d.len + (int64_t)d.disp;
	else if ((m & 7) == 4) {
		uint8_t sib = ip[d.modrm_off + 1];
		int scale = sib >> 6, index = (sib >> 3) & 7, base = sib & 7;
		if (d.rex & 2)
			index |= 8;
		if (d.rex & 1)
			base |= 8;
		addr = 0;
		if (index != 4)
			addr += cpu->r[index] << scale;
		if (mod == 0 && (sib & 7) == 5)
			addr += (int32_t)d.disp;
		else {
			addr += cpu->r[base];
			if (mod)
				addr += (int64_t)d.disp;
		}
	} else {
		addr = cpu->r[rm];
		if (mod)
			addr += (int64_t)d.disp;
	}
	if (f86_in_system()) {
		uint64_t gpa = 0;
		void *h;
		if (f86_sys_is_mmio(addr))
			return f86_sys_mmio_read(addr, 8);
		if (!f86_gva_to_gpa(addr, &gpa))
			return 0;
		h = f86_gpa_hva(gpa);
		return h ? *(uint64_t *)h : 0;
	}
	return *(uint64_t *)(uintptr_t)addr;
}

static int rip_ok(uint64_t v)
{
	uint64_t top = v >> 47;
	if (v >= 0x100000 && v < 0x0000800000000000ull && top == 0)
		return 1;
	if (top == 0x1ffffull && v >= 0xffffff8000100000ull &&
	    v < 0xffffff8100000000ull)
		return 1;
	/* Kernel-half code outside the static window (XNU's double-mapped
	   __HIB interrupt stubs live at 0xfffff6b8c000xxxx): trust the page
	   tables. */
	if (top == 0x1ffffull && f86_in_system()) {
		uint64_t gpa = 0;
		if (f86_gva_to_gpa(v, &gpa) && gpa < f86_ram_size())
			return 1;
	}
	return 0;
}

static int looks_like_code(uint64_t v)
{
	if (!rip_ok(v))
		return 0;
	if (g_dt_phys && (v & 0xffffffffull) >= g_dt_phys &&
	    (v & 0xffffffffull) < g_dt_phys + 0x8000ull)
		return 0;
	const uint8_t *p = f86_gva_code(v, 16);
	if (!p)
		return 0;
	if (p[0] == 0x00 && p[1] == 0x00)
		return 0;
	if (p[0] == 0xf0 && (p[1] == 0x9f || p[1] == 0xff))
		return 0;
	F86Insn d;
	if (!f86_decode(p, p + 16, &d) || (d.flags & F86_BAD) || !d.len)
		return 0;
	return 1;
}

static uint64_t recover_from_stack(F86CPU *c)
{
	if (!c || !f86_in_system())
		return 0;
	uint64_t sp = c->r[R_RSP];
	for (int i = 0; i < 40; i++) {
		uint64_t gpa = 0, v = 0;
		if (!f86_gva_to_gpa(sp + (uint64_t)i * 8, &gpa) ||
		    gpa + 8 > f86_ram_size())
			continue;
		memcpy(&v, f86_ram() + gpa, 8);
		if (v == c->rip)
			continue;
		if (looks_like_code(v)) {
			c->r[R_RSP] = sp + (uint64_t)(i + 1) * 8;
			return v;
		}
	}
	return 0;
}

static int insn_touches_mem(const uint8_t *ip, const F86Insn *d)
{
	uint8_t op = d->opcode0;
	(void)ip;
	if (op == 0x8D)
		return 0; /* LEA */
	if (op >= 0x50 && op <= 0x5F)
		return 1;
	if (op == 0x68 || op == 0x6A || op == 0x9C || op == 0x9D ||
	    op == 0xC8 || op == 0xC9)
		return 1;
	if ((op >= 0xA0 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF))
		return 1;
	if (d->flags & F86_RIPREL)
		return 1;
	if ((d->flags & F86_MODRM) && ((d->modrm >> 6) != 3))
		return 1;
	return 0;
}

static uint64_t compute_ea(F86CPU *cpu, const uint8_t *ip, const F86Insn *d)
{
	int rm = d->modrm & 7;
	if (d->rex & 1)
		rm |= 8;
	uint64_t addr;
	if (d->flags & F86_RIPREL)
		addr = cpu->rip + d->len + (int64_t)d->disp;
	else if ((d->modrm & 7) == 4) {
		uint8_t sib = ip[d->modrm_off + 1];
		int scale = sib >> 6, index = (sib >> 3) & 7, base = sib & 7;
		if (d->rex & 2)
			index |= 8;
		if (d->rex & 1)
			base |= 8;
		addr = 0;
		if (index != 4)
			addr += cpu->r[index] << scale;
		if ((d->modrm >> 6) == 0 && (sib & 7) == 5)
			addr += (int32_t)d->disp;
		else {
			addr += cpu->r[base];
			if (d->modrm >> 6)
				addr += (int64_t)d->disp;
		}
	} else {
		addr = cpu->r[rm];
		if (d->modrm >> 6)
			addr += (int64_t)d->disp;
	}
	for (int i = 0; i < 4 && i < d->modrm_off; i++) {
		if (ip[i] == 0x65)
			addr += cpu->gs_base;
		else if (ip[i] == 0x64)
			addr += cpu->fs_base;
	}
	return addr;
}

static void emit_mem_helper(void)
{
	emit_xsave();
	emit_host_segs();
	emit_host_stack();
	em1(0x48); em1(0xB8); em8((uint64_t)f86_soft_memop);
	em1(0xFF); em1(0xD0);
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->exited);
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); em1(0x0C);
	em1(0x48); em1(0xB8); em8((uint64_t)f86_halt);
	em1(0xFF); em1(0xE0);
	emit_xrstor();
	emit_guest_segs();
	emit_fill_all();
	emit_jmp_next_host();
}

void f86_do_indirect(void)
{
	g_cpu->n_exits++;
	F86Insn d;
	const uint8_t *ip = f86_in_system() ? f86_gva_code(g_cpu->rip, 16)
	                                    : (const uint8_t *)g_cpu->rip;
	if (!ip || !f86_decode(ip, ip + 16, &d)) {
		g_cpu->exited = 1;
		g_cpu->exit_code = 127;
		return;
	}
	uint64_t tgt;
	{
		/* for CALL r/m the return address is already pushed: an
		   RSP-based operand must be read with RSP as it was */
		int rspb = 0;
		if ((d.flags & F86_FF_CALL) && (d.modrm >> 6) != 3 && !(d.flags & F86_RIPREL)) {
			int rm = d.modrm & 7;
			if (rm == 4) {
				uint8_t sib = ip[d.modrm_off + 1];
				rspb = ((sib & 7) == 4 && !(d.rex & 1));
			}
		}
		if (rspb)
			g_cpu->r[R_RSP] += 8;
		tgt = rm_value(g_cpu, g_cpu->rip, ip);
		if (rspb)
			g_cpu->r[R_RSP] -= 8;
	}
	if (g_dbg)
		fprintf(stderr, "indirect %s from %lx -> %lx rsp=%lx flags=%x\n",
		        (d.flags & F86_FF_CALL) ? "call" : "jmp",
		        (unsigned long)g_cpu->rip, (unsigned long)tgt,
		        (unsigned long)g_cpu->r[R_RSP], d.flags);
	if (f86_sys_bs_exited()) {
		static int nic;
		if (nic++ < 8)
			fprintf(stderr, "fast86: indirect %lx -> %lx\n",
			        (unsigned long)g_cpu->rip, (unsigned long)tgt);
	}
	if (tgt < 0x1000 || (f86_sys_bs_exited() && !rip_ok(tgt))) {
		static int nbi;
		if (nbi < 8) {
			uint64_t rax = g_cpu->r[R_RAX], q[4] = { 0, 0, 0, 0 }, gp = 0;
			gva_read(rax, q, 32);
			f86_gva_to_gpa(rax, &gp);
			fprintf(stderr, "fast86: bad indirect: rax=%lx -> gpa=%lx [%lx %lx %lx %lx]\n",
			        (unsigned long)rax, (unsigned long)gp, (unsigned long)q[0],
			        (unsigned long)q[1], (unsigned long)q[2], (unsigned long)q[3]);
		}
		if (nbi++ < 8)
			fprintf(stderr, "fast86: bad indirect at %lx tgt=%lx rcx=%lx rdx=%lx r8=%lx\n",
			        (unsigned long)g_cpu->rip, (unsigned long)tgt,
			        (unsigned long)g_cpu->r[R_RCX],
			        (unsigned long)g_cpu->r[R_RDX],
			        (unsigned long)g_cpu->r[R_R8]);
		if (f86_sys_bs_exited() && (d.flags & F86_FF_CALL)) {
			uint64_t ret = 0, gpa = 0;
			if (f86_gva_to_gpa(g_cpu->r[R_RSP], &gpa) &&
			    gpa + 8 <= f86_ram_size()) {
				memcpy(&ret, f86_ram() + gpa, 8);
				g_cpu->r[R_RSP] += 8;
			}
			g_cpu->r[R_RAX] = 0;
			if (looks_like_code(ret)) {
				g_cpu->rip = ret;
				g_next_host = f86_translate(g_cpu, ret);
				return;
			}
		}
		if (f86_sys_bs_exited()) {
			uint64_t rec = recover_from_stack(g_cpu);
			if (rec) {
				g_cpu->rip = rec;
				g_next_host = f86_translate(g_cpu, rec);
				return;
			}
		}
		g_cpu->exited = 1;
		g_cpu->exit_code = 127;
		return;
	}
	if (f86_in_system() && !f86_sys_bs_exited() && !f86_gva_code(tgt, 16)) {
		static int nbm;
		if (nbm++ < 8) {
			uint64_t rdi = g_cpu->r[R_RDI];
			fprintf(stderr, "fast86: indirect->unmapped %lx from %lx rdi=%lx rcx=%lx rdx=%lx\n",
			        (unsigned long)tgt, (unsigned long)g_cpu->rip,
			        (unsigned long)rdi, (unsigned long)g_cpu->r[R_RCX],
			        (unsigned long)g_cpu->r[R_RDX]);
			if (rdi && rdi + 0x80 < f86_ram_size() && f86_gpa_hva(rdi)) {
				uint64_t *p = f86_gpa_hva(rdi);
				for (int i = 0; i < 12; i++)
					fprintf(stderr, "  rdi[%02x]=%lx\n", i * 8, (unsigned long)p[i]);
			}
		}
	}
	g_cpu->rip = tgt;
	g_next_host = f86_translate(g_cpu, tgt);
}

void f86_do_ret(void)
{
	g_cpu->n_exits++;
	uint64_t ret = 0;
	if (f86_in_system()) {
		uint64_t gpa = 0;
		if ((g_cpu->r[R_RSP] >> 47) != 0x1ffffull && f86_sys_bs_exited()) {
			uint64_t rec = recover_from_stack(g_cpu);
			if (!rec && (g_cpu->r[R_RBP] >> 47) == 0x1ffffull)
				g_cpu->r[R_RSP] = g_cpu->r[R_RBP];
			else if (rec) {
				g_cpu->rip = rec;
				g_next_host = f86_translate(g_cpu, rec);
				return;
			}
		}
		if (!f86_gva_to_gpa(g_cpu->r[R_RSP], &gpa) ||
		    gpa + 8 > f86_ram_size()) {
			uint64_t rbp = g_cpu->r[R_RBP], gp2 = 0, sv = 0, rt = 0;
			if (f86_sys_bs_exited() &&
			    f86_gva_to_gpa(rbp, &gp2) && gp2 + 16 <= f86_ram_size()) {
				memcpy(&sv, f86_ram() + gp2, 8);
				memcpy(&rt, f86_ram() + gp2 + 8, 8);
				if (rip_ok(rt)) {
					fprintf(stderr, "fast86: ret via rbp %lx -> %lx\n",
					        (unsigned long)rbp, (unsigned long)rt);
					g_cpu->r[R_RBP] = sv;
					g_cpu->r[R_RSP] = rbp + 16;
					g_cpu->rip = rt;
					g_next_host = f86_translate(g_cpu, rt);
					return;
				}
			}
			fprintf(stderr, "fast86: ret walk fail rsp=%lx rbp=%lx\n",
			        (unsigned long)g_cpu->r[R_RSP],
			        (unsigned long)g_cpu->r[R_RBP]);
			g_cpu->exited = 1;
			g_cpu->exit_code = 127;
			return;
		}
		memcpy(&ret, f86_ram() + gpa, 8);
	} else
		ret = *(uint64_t *)(uintptr_t)g_cpu->r[R_RSP];
	trace_cr('R', ret, 0);
	g_cpu->r[R_RSP] += 8;
	if (ret < 0x1000 || (f86_sys_bs_exited() && !rip_ok(ret))) {
		/* A return address that is not code means an emulation defect
		   corrupted the guest stack (boot-60: POP RSP became ADD RSP,8).
		   Resynchronising to the next code-like stack word hid exactly that
		   for several runs, so it is opt-in: F86_RET_RECOVER=1. */
		static int recover = -1;
		if (recover < 0)
			recover = getenv("F86_RET_RECOVER") != NULL;
		if (f86_in_system() && f86_sys_bs_exited() && recover) {
			uint64_t rec = recover_from_stack(g_cpu);
			static int nret0;
			if (nret0++ < 8)
				fprintf(stderr, "fast86: ret-to-%lx recover=%lx\n",
				        (unsigned long)ret, (unsigned long)rec);
			if (rec) {
				g_cpu->rip = rec;
				g_next_host = f86_translate(g_cpu, rec);
				return;
			}
		}
		if (f86_in_system()) {
			/* EFI app returned to firmware. */
			g_cpu->exited = 1;
			g_cpu->exit_code = 0;
			return;
		}
		uint64_t *sp = (uint64_t *)(uintptr_t)(g_cpu->r[R_RSP] - 8);
		fprintf(stderr,
		        "fast86: ret to %lx from %lx rsp=%lx stack %lx %lx %lx %lx\n",
		        (unsigned long)ret, (unsigned long)g_cpu->rip,
		        (unsigned long)g_cpu->r[R_RSP],
		        (unsigned long)sp[0], (unsigned long)sp[1],
		        (unsigned long)sp[2], (unsigned long)sp[3]);
		g_cpu->exited = 1;
		g_cpu->exit_code = 127;
		return;
	}
	g_cpu->rip = ret;
	g_next_host = f86_translate(g_cpu, ret);
}

/* Push guest_ret; record (guest_ret, host_ret) on the shadow stack; jmp tgt.
   Only rax/r11 are used as temps, and both are saved. host_ret is patched
   once the return site's RX address is known. */
static void emit_native_call(uint64_t guest_ret, uint64_t tgt)
{
	if (sys_alias()) {
		if (guest_ret < 0x80000000ull)
			emit_push_imm32((int32_t)guest_ret);
		else {
			emit_store_r11_scr();
			em1(0x49); em1(0xBB); em8(guest_ret);
			emit_push_reg(11);
			emit_load_r11_scr();
		}
	} else if (guest_ret < 0x80000000ull) { /* push imm32 sign-extends */
		em1(0x68);
		em4((uint32_t)guest_ret);
	} else {
		em1(0x48); em1(0x8D); em1(0x64); em1(0x24); em1(0xF8);
		emit_store_r11_scr();
		em1(0x49); em1(0xBB); em8(guest_ret);
		em1(0x4C); em1(0x89); em1(0x1C); em1(0x24);
		emit_load_r11_scr();
	}

	em1(0x48); em1(0xA3); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	emit_store_r11_scr();
	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_SHN));
	em1(0x48); em1(0x3D); em4(SH_CAP);
	em1(0x73); uint8_t *jae = g_emit; em1(0);

	/* r11 = shn*8 (byte offset). rax/r11 already saved. */
	em1(0x49); em1(0x89); em1(0xC3);             /* mov r11, rax */
	em1(0x49); em1(0xC1); em1(0xE3); em1(3);     /* shl r11, 3 */
	em1(0x48); em1(0xB8); em8(guest_ret);
	em1(0x49); em1(0x89); em1(0x83);             /* mov [r11+SHG], rax */
	em4((uint32_t)(SCRATCH + SCR_OFF_SHG));
	em1(0x48); em1(0xB8);
	uint8_t *hr_imm = g_emit;
	em8(0);
	em1(0x49); em1(0x89); em1(0x83);             /* mov [r11+SHH], rax */
	em4((uint32_t)(SCRATCH + SCR_OFF_SHH));
	em1(0x48); em1(0xFF); em1(0x04); em1(0x25);
	em4((uint32_t)(SCRATCH + SCR_OFF_SHN));
	jae[0] = (uint8_t)(g_emit - (jae + 1));

	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	emit_load_r11_scr();

	uint8_t *th = lookup_chain(tgt);
	if (th && (int64_t)(th - (rx_of(g_emit) + 5)) ==
	    (int32_t)(th - (rx_of(g_emit) + 5))) {
		emit_jmp_rel32(g_emit, th);
		g_emit += 5;
	} else {
		em1(0xE9);
		uint8_t *rel = g_emit;
		em4(0);
		uint8_t *stub = g_emit;
		int32_t r = (int32_t)(rx_of(stub) - (rx_of(rel) + 4));
		memcpy(rel, &r, 4);
		add_patch(tgt, rel);
		emit_exit_to(tgt);
	}

	uint64_t hr = (uint64_t)(uintptr_t)rx_of(g_emit);
	memcpy(hr_imm, &hr, 8);
}

static void emit_ret_simple(uint16_t imm)
{
	if (sys_alias() && imm) {
		/* ret imm16: pop the return address, release imm more bytes,
		   dispatch through the shared exit trampoline. */
		emit_store_r11_scr();
		emit_stk_load(11, 0);
		emit_lea_rsp(8 + (int32_t)imm);
		em1(0x4C); em1(0x89); em1(0x1C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_RIP));
		emit_load_r11_scr();
		emit_jmp_rel32(g_emit, g_exit_tramp);
		g_emit += 5;
		return;
	}
	emit_store_r11_scr();
	em1(0x48); em1(0xA3); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	em1(0x48); em1(0x89); em1(0x0C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_TMP));
	if (sys_alias()) {
		emit_stk_load(11, 0);  /* r11 = guest ret */
		emit_lea_rsp(8);
	} else {
		em1(0x41); em1(0x5B); /* pop r11 = guest ret */
	}

	em1(0x48); em1(0x8B); em1(0x04); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_SHN));
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); uint8_t *jz_slow = g_emit; em1(0);
	em1(0x48); em1(0xFF); em1(0xC8);
	em1(0x48); em1(0x89); em1(0x04); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_SHN));
	/* rax is the index; compare and load without overwriting it */
	em1(0x4C); em1(0x3B); em1(0x1C); em1(0xC5); em4((uint32_t)(SCRATCH + SCR_OFF_SHG));
	em1(0x75); uint8_t *jne_slow = g_emit; em1(0);
	em1(0x4C); em1(0x8B); em1(0x1C); em1(0xC5); em4((uint32_t)(SCRATCH + SCR_OFF_SHH));
	/* park the host target, restore rax/rcx/r11, jump through the slot:
	   the guest's r11 must survive a fast-path RET */
	em1(0x4C); em1(0x89); em1(0x1C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_NEXT));
	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	em1(0x48); em1(0x8B); em1(0x0C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_TMP));
	emit_load_r11_scr();
	emit_jmp_next_host();

	uint8_t *slow = g_emit;
	jz_slow[0] = (uint8_t)(slow - (jz_slow + 1));
	jne_slow[0] = (uint8_t)(slow - (jne_slow + 1));
	/* r11 holds guest ret — put it back on the stack for f86_do_ret */
	if (sys_alias())
		emit_push_reg(11);
	else {
		em1(0x41); em1(0x53); /* push r11 */
	}
	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	em1(0x48); em1(0x8B); em1(0x0C); em1(0x25); em4((uint32_t)(SCRATCH + SCR_OFF_TMP));
	emit_load_r11_scr();
	emit_spill_all();
	emit_c_helper(f86_do_ret);
}

static uint8_t jcc_cc(const uint8_t *ip, const F86Insn *d)
{
	if (d->flags & F86_JCC8)
		return (uint8_t)(0x80 | (ip[d->len - 2] & 0x0F));
	const uint8_t *q = ip;
	while (*q != 0x0F)
		q++;
	return q[1];
}

static void emit_jcc_to(uint8_t cc, uint8_t *to_rx)
{
	int64_t near = to_rx - (rx_of(g_emit) + 6);
	int64_t sh = to_rx - (rx_of(g_emit) + 2);
	if (sh == (int8_t)sh) {
		em1((uint8_t)(0x70 | (cc & 0x0F)));
		em1((uint8_t)sh);
		return;
	}
	em1(0x0F); em1(cc);
	em4((uint32_t)(int32_t)near);
}

static void emit_jcc_or_stub(uint8_t cc, uint64_t tgt)
{
	uint8_t *th = lookup_chain(tgt);
	if (th) {
		emit_jcc_to(cc, th);
		return;
	}
	/* near jcc so apply_patches can retarget it to a far translation */
	em1(0x0F); em1(cc);
	uint8_t *jcc_rel = g_emit;
	em4(0);
	em1(0xEB);
	uint8_t *skip = g_emit;
	em1(0);
	uint8_t *taken = g_emit;
	int32_t r1 = (int32_t)(rx_of(taken) - (rx_of(jcc_rel) + 4));
	memcpy(jcc_rel, &r1, 4);
	add_patch(tgt, jcc_rel);
	emit_exit_to(tgt);
	skip[0] = (uint8_t)(g_emit - (skip + 1));
}

static void emit_jmp_or_stub(uint64_t tgt)
{
	uint8_t *th = lookup_chain(tgt);
	if (th && (int64_t)(th - (rx_of(g_emit) + 5)) ==
	    (int32_t)(th - (rx_of(g_emit) + 5))) {
		emit_jmp_rel32(g_emit, th);
		g_emit += 5;
		return;
	}
	em1(0xE9);
	uint8_t *rel = g_emit;
	em4(0);
	uint8_t *stub = g_emit;
	int32_t r = (int32_t)(rx_of(stub) - (rx_of(rel) + 4));
	memcpy(rel, &r, 4);
	add_patch(tgt, rel);
	emit_exit_to(tgt);
}

/* LOOP/JRCXZ only encode rel8. Keep the original opcode and bounce via a stub. */
static void emit_loop_or_stub(const uint8_t *ip, const F86Insn *d, uint64_t tgt)
{
	uint8_t *th = lookup_chain(tgt);
	if (th) {
		int64_t sh = th - (rx_of(g_emit) + d->len);
		/* only if the original encoding's last byte is the rel8 and
		   prefixes+opcode fit, and dest is in range */
		if (sh == (int8_t)sh && d->len >= 2) {
			memcpy(g_emit, ip, d->len - 1);
			g_emit += d->len - 1;
			em1((uint8_t)sh);
			return;
		}
	}
	/* loop stub (always in range); stub jumps/exits to tgt. Keep a
	   0x67 prefix: jecxz tests ECX, jrcxz tests RCX. */
	uint8_t op = ip[d->len - 2];
	if (d->len >= 3 && ip[d->len - 3] == 0x67)
		em1(0x67);
	em1(op);
	uint8_t *rel8 = g_emit;
	em1(0);
	em1(0xEB);
	uint8_t *skip = g_emit;
	em1(0);
	rel8[0] = (uint8_t)(g_emit - (rel8 + 1));
	emit_jmp_or_stub(tgt);
	skip[0] = (uint8_t)(g_emit - (skip + 1));
}

static void emit_syscall_continue(uint64_t next_rip)
{
	emit_spill_all();
	em1(0x48); em1(0xB8); em8(next_rip);
	em1(0x48); em1(0xA3); em8((uint64_t)&g_cpu->rip);
	emit_xsave();
	emit_host_segs();
	emit_host_stack();
	em1(0x48); em1(0xB8); em8((uint64_t)f86_on_syscall);
	em1(0xFF); em1(0xD0);
	em1(0x48); em1(0xA1); em8((uint64_t)&g_cpu->exited);
	em1(0x48); em1(0x85); em1(0xC0);
	em1(0x74); em1(0x0C);
	em1(0x48); em1(0xB8); em8((uint64_t)f86_halt);
	em1(0xFF); em1(0xE0);
	emit_xrstor();
	emit_guest_segs();
	emit_fill_all();
}

static void emit_capture_fs_ok(void)
{
	emit_store_r11_scr();
	em1(0xF3); em1(0x49); em1(0x0F); em1(0xAE); em1(0xC3); /* rdfsbase r11 */
	em1(0x48); em1(0xA3); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	em1(0x48); em1(0xB8); em8((uint64_t)&g_cpu->fs_base);
	em1(0x4C); em1(0x89); em1(0x18); /* mov [rax], r11 */
	em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
	emit_load_r11_scr();
}

static void emit_save_scr(int r, uint32_t off);
static void emit_load_scr(int r, uint32_t off);
static void emit_movabs(int r, uint64_t v);

/* Rewrite a RIP-relative memory operand as [scratch] with scratch = abs.
   Legacy/REX encodings get REX.B; VEX2 is widened to VEX3 and VEX3/EVEX
   get their inverted B bit cleared (a REX byte in front of a VEX prefix is
   #UD: corecrypto's `vpshufb xmm, xmm, [rip+c]` SHA kernels hit exactly
   that and were being skipped by the SIGILL handler). */
static void emit_riprel_via_abs(const uint8_t *insn, const F86Insn *d, uint64_t abs,
                                int fs_prefix)
{
	int moff = d->modrm_off;
	int vlen = d->vex_len;                       /* 0, 2, 3 (VEX), 4 (EVEX) */
	int vo = vlen ? moff - 1 - vlen : -1;        /* offset of C5/C4/62 */
	int reg = (insn[moff] >> 3) & 7;
	int vvvv = -1;
	if (vlen == 0) {
		if (d->rex & 4)
			reg |= 8;
	} else {
		if (!(insn[vo + 1] & 0x80))
			reg |= 8;
		uint8_t vb = (vlen == 2) ? insn[vo + 1] : insn[vo + 2];
		vvvv = (~vb >> 3) & 15;
	}
	int scratch = 11;
	if (reg == 11 || vvvv == 11)
		scratch = 10;
	if (scratch == 10 && (reg == 10 || vvvv == 10))
		scratch = 9;
	uint32_t soff = scratch == 11 ? SCR_OFF_R11 : scratch == 10 ? SCR_OFF_TMP : SCR_OFF_T2;
	emit_save_scr(scratch, soff);
	emit_movabs(scratch, abs);
	if (fs_prefix)
		em1(0x64);
	if (vlen == 0) {
		/* REX.B so rm encodes the scratch. Stop at the opcode — 0F xx
		   bytes in 0x40–0x4F are not REX (e.g. CMOVcc is 0F 40–4F). */
		uint8_t rex = 0x41;
		int op0 = 0;
		for (int i = 0; i < moff; i++) {
			uint8_t b = insn[i];
			if (b >= 0x40 && b <= 0x4F) {
				rex = (uint8_t)(b | 0x01);
				op0 = i + 1;
			} else if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
			           b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
			           b == 0x64 || b == 0x65) {
				/* null overrides are dropped next to our fs: prefix */
				if (!(fs_prefix && (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26)))
					em1(b);
				op0 = i + 1;
			} else {
				break;
			}
		}
		em1(rex);
		for (int i = op0; i < moff; i++)
			em1(insn[i]);
	} else {
		for (int i = 0; i < vo; i++) {
			uint8_t b = insn[i];
			if (fs_prefix && (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26))
				continue;
			em1(b);
		}
		if (vlen == 2) {
			uint8_t b1 = insn[vo + 1];
			em1(0xC4);
			em1((uint8_t)((b1 & 0x80) | 0x40 | 0x01)); /* R kept, X=1, B=0 -> r8-15, map 0F */
			em1((uint8_t)(b1 & 0x7F));                 /* W=0, vvvv L pp */
		} else if (vlen == 3) {
			em1(0xC4);
			em1((uint8_t)(insn[vo + 1] & ~0x20));
			em1(insn[vo + 2]);
		} else {
			em1(0x62);
			em1((uint8_t)(insn[vo + 1] & ~0x20));
			em1(insn[vo + 2]);
			em1(insn[vo + 3]);
		}
		em1(insn[moff - 1]); /* opcode */
	}
	/* mod=00 rm=scratch&7 → [r9]/[r10]/[r11] */
	em1((uint8_t)((((insn[moff] >> 3) & 7) << 3) | (scratch & 7)));
	for (int i = moff + 1 + 4; i < d->len; i++)
		em1(insn[i]);
	emit_load_scr(scratch, soff);
}

static void emit_push_retaddr(uint64_t next)
{
	if (sys_alias()) {
		if (next < 0x80000000ull)
			emit_push_imm32((int32_t)next);
		else {
			emit_store_r11_scr();
			em1(0x49); em1(0xBB); em8(next);
			emit_push_reg(11);
			emit_load_r11_scr();
		}
		return;
	}
	if (next < 0x80000000ull) { /* push imm32 sign-extends: only below 2 GiB */
		em1(0x68);
		em4((uint32_t)next);
	} else {
		em1(0x48); em1(0x8D); em1(0x64); em1(0x24); em1(0xF8);
		emit_store_r11_scr();
		em1(0x49); em1(0xBB); em8(next);
		em1(0x4C); em1(0x89); em1(0x1C); em1(0x24);
		emit_load_r11_scr();
	}
}

/* mov [SCRATCH+off], r64 / mov r64, [SCRATCH+off] (host absolute) */
static void emit_save_scr(int r, uint32_t off)
{
	em1((uint8_t)(r >= 8 ? 0x4C : 0x48)); em1(0x89);
	em1((uint8_t)(0x04 | ((r & 7) << 3))); em1(0x25); em4((uint32_t)(SCRATCH + off));
}

static void emit_load_scr(int r, uint32_t off)
{
	em1((uint8_t)(r >= 8 ? 0x4C : 0x48)); em1(0x8B);
	em1((uint8_t)(0x04 | ((r & 7) << 3))); em1(0x25); em4((uint32_t)(SCRATCH + off));
}

static void emit_movabs(int r, uint64_t v)
{
	em1((uint8_t)(r >= 8 ? 0x49 : 0x48)); em1((uint8_t)(0xB8 | (r & 7))); em8(v);
}

/* mov dst, [base] / mov [base], src; base must not be rsp/rbp/r12/r13. */
static void emit_mov_r_mem(int dst, int base, int w)
{
	em1((uint8_t)(0x40 | (w ? 8 : 0) | (dst >= 8 ? 4 : 0) | (base >= 8 ? 1 : 0)));
	em1(0x8B); em1((uint8_t)(((dst & 7) << 3) | (base & 7)));
}

static void emit_mov_mem_r(int base, int src, int w)
{
	em1((uint8_t)(0x40 | (w ? 8 : 0) | (src >= 8 ? 4 : 0) | (base >= 8 ? 1 : 0)));
	em1(0x89); em1((uint8_t)(((src & 7) << 3) | (base & 7)));
}

/* F3 [REX.W] 0F AE /0-/3 with mod=3: rdfsbase/rdgsbase/wrfsbase/wrgsbase */
static int is_fsgsbase(const uint8_t *ip, const F86Insn *d)
{
	if (d->opcode0 != 0x0F || d->opcode1 != 0xAE || (d->modrm >> 6) != 3 ||
	    ((d->modrm >> 3) & 7) > 3)
		return 0;
	for (int i = 0; i < d->modrm_off; i++)
		if (ip[i] == 0xF3)
			return 1;
	return 0;
}

/* System mode: the host FS base carries the alias offset and the host GS
   base is the guest's plus that offset, so the four fsgsbase instructions
   are virtualised against g_cpu->fs_base / g_cpu->gs_base. */
static void emit_sys_fsgsbase(const uint8_t *ip, const F86Insn *d)
{
	(void)ip;
	int reg = (d->modrm >> 3) & 7;
	int r = (d->modrm & 7) | ((d->rex & 1) ? 8 : 0);
	int w = (d->rex & 8) != 0;
	uint64_t *slot = (reg & 1) ? &g_cpu->gs_base : &g_cpu->fs_base;
	int a = (r == 11) ? 10 : 11;
	int b = (r == 10 || a == 10) ? 9 : 10;
	emit_save_scr(a, SCR_OFF_R11);
	emit_movabs(a, (uint64_t)(uintptr_t)slot);
	if (reg <= 1) { /* rdfsbase / rdgsbase */
		emit_mov_r_mem(r, a, w);
		emit_load_scr(a, SCR_OFF_R11);
		return;
	}
	emit_mov_mem_r(a, r, w);
	if (!w) { /* 32-bit form: zero the upper half */
		em1((uint8_t)(a >= 8 ? 0x41 : 0x40)); em1(0xC7);
		em1((uint8_t)(0x40 | (a & 7))); em1(4); em4(0);
	}
	if (reg == 3) { /* wrgsbase: host GS = guest GS + alias offset */
		emit_save_scr(b, SCR_OFF_T2);
		emit_mov_r_mem(a, a, 1);
		emit_movabs(b, g_alias_off);
		/* lea a, [a + b] */
		em1((uint8_t)(0x48 | (a >= 8 ? 4 : 0) | (b >= 8 ? 2 : 0) | (a >= 8 ? 1 : 0)));
		em1(0x8D); em1((uint8_t)(0x04 | ((a & 7) << 3)));
		em1((uint8_t)(((b & 7) << 3) | (a & 7)));
		/* wrgsbase a */
		em1(0xF3); em1((uint8_t)(a >= 8 ? 0x49 : 0x48)); em1(0x0F); em1(0xAE);
		em1((uint8_t)(0xD8 | (a & 7)));
		emit_movabs(b, (uint64_t)(uintptr_t)&f86_gs_host);
		emit_mov_mem_r(b, a, 1);
		emit_load_scr(b, SCR_OFF_T2);
	}
	emit_load_scr(a, SCR_OFF_R11);
}

/* System-mode memory routing for one instruction. Returns 0 when the
   instruction needs no change (copied by the caller), 1 when it was
   emitted here, 2 when it ended the block with a C helper. */
static int emit_sys_mem(const uint8_t *ip, const F86Insn *d, uint64_t pc)
{
	uint8_t op = d->opcode0, op2 = d->opcode1;
	int seg = 0;
	int p0 = scan_prefixes(ip, d->len, &seg);
	int o16 = 0, a32 = 0;
	for (int i = 0; i < p0; i++) {
		if (ip[i] == 0x66)
			o16 = 1;
		if (ip[i] == 0x67)
			a32 = 1;
	}
	int is0f = (op == 0x0F);
	int helper = 0;
	if (d->vex_len) {
		/* VEX/EVEX: opcode0 is the in-map opcode (vxorps is 0x57, not a
		   push), so only the generic memory-operand rule applies. */
		if (seg & 2) {
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, pc);
			emit_mem_helper();
			return 2;
		}
		if ((d->flags & F86_MODRM) && (d->modrm >> 6) != 3 && !(d->flags & F86_RIPREL)) {
			if (!(seg & 4))
				em1(0x64);
			for (int i = 0; i < p0; i++) {
				uint8_t b = ip[i];
				if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E)
					continue;
				em1(b);
			}
			for (int i = p0; i < d->len; i++)
				em1(ip[i]);
			return 1;
		}
		return 0;
	}
	/* string ops, enter, xlat, push/pop fs/gs, guest fs: overrides and
	   16/32-bit stack forms: one instruction through the C emulator */
	if (!is0f && ((op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF) ||
	              op == 0xC8 || op == 0xD7))
		helper = 1;
	if (is0f && (op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA8 || op2 == 0xA9))
		helper = 1;
	if (seg & 2)
		helper = 1;
	if (!is0f && (o16 || a32) &&
	    ((op >= 0x50 && op <= 0x5F) || op == 0x68 || op == 0x6A || op == 0x8F ||
	     op == 0xC9 || (op == 0xFF && ((d->modrm >> 3) & 7) == 6)))
		helper = 1;
	if (!helper && !is0f) {
		if (op >= 0x50 && op <= 0x57) {
			emit_push_reg((op - 0x50) | ((d->rex & 1) ? 8 : 0));
			return 1;
		}
		if (op >= 0x58 && op <= 0x5F) {
			emit_pop_reg((op - 0x58) | ((d->rex & 1) ? 8 : 0));
			return 1;
		}
		if (op == 0x68 || op == 0x6A) {
			int32_t imm;
			if (op == 0x6A)
				imm = (int8_t)ip[d->len - 1];
			else
				imm = (int32_t)((uint32_t)ip[d->len - 4] | ((uint32_t)ip[d->len - 3] << 8) |
				                ((uint32_t)ip[d->len - 2] << 16) | ((uint32_t)ip[d->len - 1] << 24));
			emit_push_imm32(imm);
			return 1;
		}
		if (op == 0xC9) { /* leave */
			em1(0x48); em1(0x89); em1(0xEC);
			emit_pop_reg(R_RBP);
			return 1;
		}
		if (op == 0xFF && ((d->modrm >> 3) & 7) == 6) { /* push r/m */
			if ((d->modrm >> 6) == 3) {
				emit_push_reg((d->modrm & 7) | ((d->rex & 1) ? 8 : 0));
				return 1;
			}
			if (rm_avoids_r11(ip, d)) {
				emit_store_r11_scr();
				emit_rm_r11(ip, d, 1);
				emit_push_reg(11);
				emit_load_r11_scr();
				return 1;
			}
			helper = 1;
		}
		if (op == 0x8F && !helper) { /* pop r/m */
			if ((d->modrm >> 6) == 3) {
				emit_pop_reg((d->modrm & 7) | ((d->rex & 1) ? 8 : 0));
				return 1;
			}
			if (rm_avoids_r11(ip, d)) {
				emit_store_r11_scr();
				emit_pop_reg(11);
				emit_rm_r11(ip, d, 0);
				emit_load_r11_scr();
				return 1;
			}
			helper = 1;
		}
	}
	if (helper) {
		emit_spill_all();
		emit_store_u64(&g_cpu->rip, pc);
		emit_mem_helper();
		return 2;
	}
	if (!is0f && op >= 0xA0 && op <= 0xA3) { /* mov al/eax/rax <-> moffs64 */
		if (!(seg & 4))
			em1(0x64);
		for (int i = 0; i < p0; i++) {
			uint8_t b = ip[i];
			if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E)
				continue;
			em1(b);
		}
		for (int i = p0; i < d->len; i++)
			em1(ip[i]);
		return 1;
	}
	if ((d->flags & F86_MODRM) && (d->modrm >> 6) != 3 && !(d->flags & F86_RIPREL)) {
		if (op == 0x8D || (is0f && op2 == 0x1F))
			return 0; /* lea / nop: no access */
		if (!(seg & 4))
			em1(0x64);
		for (int i = 0; i < p0; i++) {
			uint8_t b = ip[i];
			if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E)
				continue;
			em1(b);
		}
		for (int i = p0; i < d->len; i++)
			em1(ip[i]);
		return 1;
	}
	return 0;
}

static uint64_t snap_insn_pc(uint64_t pc)
{
	/* Heuristic "re-alignment" of block starts that begin with STOS or an
	   indirect branch. It moved XNU's bzero (cld; rep stosb; ret) entry
	   from the rep stosb to two bytes earlier, inside `xor eax,eax`, so
	   bzero cleared one byte. Off unless F86_SNAP=1. */
	static int snap = -1;
	if (snap < 0)
		snap = getenv("F86_SNAP") != NULL;
	if (!snap)
		return pc;
	if (!f86_sys_bs_exited() || pc < 0xffffff8000100000ull)
		return pc;
	const uint8_t *cur = f86_gva_code(pc, 16);
	F86Insn now;
	int suspicious = 0;
	if (!cur || !f86_decode(cur, cur + 16, &now) || (now.flags & F86_BAD))
		suspicious = 1;
	else if (now.flags & (F86_FF_CALL | F86_FF_JMP))
		suspicious = 1;
	else if (now.opcode0 == 0xAA || now.opcode0 == 0xAB || now.opcode0 == 0xCE)
		suspicious = 1;
	if (!suspicious)
		return pc;
	for (int back = 15; back >= 1; back--) {
		const uint8_t *p = f86_gva_code(pc - (uint64_t)back, 16);
		F86Insn d;
		if (!p || !f86_decode(p, p + 16, &d) || (d.flags & F86_BAD) || !d.len)
			continue;
		if (d.len > (unsigned)back && d.len <= 15)
			return pc - (uint64_t)back;
	}
	return pc;
}

static void *emit_special_hook(uint64_t guest_rip, void (*fn)(void), const char *tag)
{
	int i;
	for (i = 0; i < g_nspec; i++) {
		if (g_spec_g[i] == guest_rip && g_spec_h[i])
			return g_spec_h[i];
	}
	if (g_emit + 8192 >= g_cend)
		return NULL;
	while (((uintptr_t)g_emit & 15) && g_emit < g_cend)
		em1(0x90);
	uint8_t *brx = rx_of(g_emit);
	insert(guest_rip, brx);
	emit_spill_all();
	emit_store_u64(&g_cpu->rip, guest_rip);
	emit_c_helper(fn);
	if (g_nspec < 24) {
		g_spec_g[g_nspec] = guest_rip;
		g_spec_h[g_nspec] = brx;
		g_nspec++;
	}
	fprintf(stderr, "fast86: hooked %s at %lx\n", tag, (unsigned long)guest_rip);
	return brx;
}

static uint64_t slide_kptr(uint64_t p)
{
	uint64_t lo, slide, b;
	if (g_kaddr < 0x100000ull)
		return p;
	if ((p >> 32) != 0xffffff80ull)
		return p;
	lo = p & 0xffffffffull;
	slide = (g_kaddr - 0x100000ull) & 0xffffffffull;
	/* Already rebased by boot.efi: low 32 = unslid + slide. */
	if (slide && lo >= slide + 0x100000ull &&
	    (lo - slide) < 0x04000000ull)
		return p;
	if (lo < 0x100000ull || lo >= 0x04000000ull)
		return p;
	b = 0xffffff8000000000ull | slide;
	return b + lo;
}

static void store64_guest(uint64_t va, uint64_t val)
{
	uint64_t lo;
	gva_write(va, &val, 8);
	lo = va & 0xffffffffull;
	if ((va >> 32) == 0xffffff80ull && lo + 8 <= f86_ram_size())
		memcpy(f86_ram() + lo, &val, 8);
}

/* Identity PA of an unslid KC virtual address. */
static uint8_t *kc_phys(uint64_t unslid_lo, size_t n)
{
	uint64_t pa;
	if (g_kaddr < 0x100000ull || !f86_ram())
		return NULL;
	pa = (g_kaddr - 0x100000ull) + unslid_lo;
	if (pa + n > f86_ram_size())
		return NULL;
	return f86_ram() + pa;
}

static int startup_cmp(const void *va, const void *vb)
{
	uint32_t as, ar, bs, br;
	memcpy(&as, va, 4);
	memcpy(&ar, (const uint8_t *)va + 4, 4);
	memcpy(&bs, vb, 4);
	memcpy(&br, (const uint8_t *)vb + 4, 4);
	if (as != bs)
		return as < bs ? -1 : 1;
	if (ar != br)
		return ar < br ? -1 : 1;
	return 0;
}

/*
 * The on-disk STARTUP table is unsorted. The walker at 0xbd1477 does
 * `cmp sub, upto; ja done`, so the first later subsystem aborts the
 * rest of the table. Steal (sub 5) sits at index 359 and never runs,
 * leaving map_data=0. Slide func/arg, qsort by (sub, rank), and point
 * the cursor at the slid table — all through physical identity, which
 * is valid during HIB before kernel CR3 exists.
 */
static void reloc_startup_once(void)
{
	static int done;
	uint8_t *t, *curp, *endp;
	uint64_t n, i, nfix = 0, start, end, first_func = 0, new_func = 0;
	uint32_t first_sub = 0, first_rank = 0, new_sub = 0;

	if (done || !f86_sys_bs_exited() || g_kaddr < 0x100000ull)
		return;
	n = (0x13e73e0ull - 0x13d5800ull) / 24ull;
	t = kc_phys(0x13d5800ull, n * 24ull);
	if (!t)
		return;
	memcpy(&first_sub, t, 4);
	memcpy(&first_rank, t + 4, 4);
	memcpy(&first_func, t + 8, 8);
	if (first_sub > 64 || first_func == 0) {
		fprintf(stderr, "fast86: STARTUP table not ready sub=%u func=%lx\n",
		        first_sub, (unsigned long)first_func);
		return;
	}
	done = 1;
	{
		uint64_t slide = (g_kaddr - 0x100000ull) & 0xffffffffull;
		int already = ((first_func & 0xffffffffull) ==
		               ((0xbd26c9ull + slide) & 0xffffffffull));
		if (!already) {
			for (i = 0; i < n; i++) {
				uint64_t func = 0, arg = 0, nf, na;
				memcpy(&func, t + i * 24ull + 8, 8);
				memcpy(&arg, t + i * 24ull + 16, 8);
				nf = slide_kptr(func);
				na = slide_kptr(arg);
				if (nf != func) {
					memcpy(t + i * 24ull + 8, &nf, 8);
					nfix++;
				}
				if (na != arg)
					memcpy(t + i * 24ull + 16, &na, 8);
			}
		}
		start = 0xffffff8000000000ull | (slide + 0x13d5800ull);
		end = 0xffffff8000000000ull | (slide + 0x13e73e0ull);
	}
	qsort(t, (size_t)n, 24, startup_cmp);
	curp = kc_phys(0x13b56b0ull, 8);
	endp = kc_phys(0x210030ull, 8);
	if (curp)
		memcpy(curp, &start, 8);
	if (endp)
		memcpy(endp, &end, 8);
	/* Section start/end used by kernel_startup_bootstrap's n = end-start. */
	{
		static const uint64_t sec[] = {
			0x210030ull, 0x210038ull, 0x210040ull, 0x210048ull,
			0x210050ull, 0x210058ull, 0x210060ull, 0x210068ull
		};
		unsigned si;
		for (si = 0; si < sizeof sec / sizeof sec[0]; si++) {
			uint8_t *sp = kc_phys(sec[si], 8);
			uint64_t v = 0, nv;
			if (!sp)
				continue;
			memcpy(&v, sp, 8);
			nv = slide_kptr(v);
			if (nv != v)
				memcpy(sp, &nv, 8);
		}
	}
	/* Guest qsort of this table has scrambled it; nop the call. */
	{
		uint8_t *qp = kc_phys(0xbd13a0ull, 5);
		if (qp && qp[0] == 0xe8)
			memset(qp, 0x90, 5);
	}
	{
		static const uint64_t rets[] = { 0xbd363bull, 0xbd367cull };
		unsigned ri;
		for (ri = 0; ri < 2; ri++) {
			uint8_t *p = kc_phys(rets[ri], 1);
			if (p && p[0] == 0x55)
				p[0] = 0xc3;
		}
	}
	/* Point VM map-entry zalloc CALLs at a NOP island we hook. */
	{
		static const uint64_t calls[] = {
			0x493b97ull, 0x493d77ull, 0x4942fdull, 0x4943b4ull,
			0x497891ull, 0x498906ull, 0x49d567ull, 0x49df88ull,
			0x49e01eull, 0x49ea35ull, 0x49efd2ull, 0x4a09c4ull,
			0x4a13abull, 0x4a2ec7ull, 0x4a4329ull, 0x4a5ab7ull,
			0x4a6461ull, 0x4a64caull, 0x4a65fcull, 0x4a6997ull,
			0x4a822aull, 0x4a85f3ull, 0x4a8bc8ull, 0x4ae6f5ull,
			0x4ae737ull, 0x4b151dull, 0x4b16deull, 0x4b2dffull,
			0x4b2f30ull, 0x4b3e3dull, 0x4b621aull, 0x4b65afull,
			0x4b994aull, 0x4ba5d5ull, 0x4ba867ull, 0x4bb2a8ull,
			0x4bb46cull, 0x4bc7e6ull, 0x4be1afull
		};
		const uint64_t stub = 0x36e754ull;
		unsigned ci, nret = 0;
		for (ci = 0; ci < sizeof calls / sizeof calls[0]; ci++) {
			uint8_t *p = kc_phys(calls[ci], 5);
			int32_t rel;
			uint8_t buf[5];
			if (!p || p[0] != 0xe8)
				continue;
			rel = (int32_t)(stub - (calls[ci] + 5ull));
			p[0] = 0xe8;
			memcpy(p + 1, &rel, 4);
			buf[0] = 0xe8;
			memcpy(buf + 1, &rel, 4);
			gva_write(0xffffff8000000000ull |
			          (((g_kaddr - 0x100000ull) + calls[ci]) & 0xffffffffull),
			          buf, 5);
			nret++;
		}
		fprintf(stderr, "fast86: retargeted %u vm/kmem zalloc calls\n", nret);
	}
	memcpy(&new_sub, t, 4);
	memcpy(&new_func, t + 8, 8);
	fprintf(stderr,
	        "fast86: STARTUP sort+slide n=%lu slid=%lu first %u/%u:%lx -> %u:%lx cursor=%lx\n",
	        (unsigned long)n, (unsigned long)nfix, first_sub, first_rank,
	        (unsigned long)first_func, new_sub, (unsigned long)new_func,
	        (unsigned long)start);
}

static void f86_fast_startup_call(void)
{
	F86CPU *c = g_cpu;
	uint64_t b, func = 0, arg = 0, ret, sub = 0;
	if (!c || g_kaddr < 0x100000ull)
		return;
	b = 0xffffff8000000000ull | ((g_kaddr - 0x100000ull) & 0xffffffffull);
	gva_read(c->r[R_R12], &sub, 4);
	gva_read(c->r[R_R12] + 8, &func, 8);
	gva_read(c->r[R_R12] + 16, &arg, 8);
	func = slide_kptr(func);
	arg = slide_kptr(arg);
	{
		static int ns;
		uint32_t su = (uint32_t)sub;
		if (ns++ < 16 || su == 5 || (func & 0xffffffffull) == 0xbd62bfull)
			fprintf(stderr,
			        "fast86: startup-call #%d sub=%u func=%lx arg=%lx r12=%lx\n",
			        ns, su, (unsigned long)func, (unsigned long)arg,
			        (unsigned long)c->r[R_R12]);
	}
	c->r[R_RDI] = arg;
	ret = b + 0xbd1501ull;
	c->r[R_RSP] -= 8;
	gva_write(c->r[R_RSP], &ret, 8);
	{
		uint64_t lo = c->r[R_RSP] & 0xffffffffull;
		if ((c->r[R_RSP] >> 32) == 0xffffff80ull && lo + 8 <= f86_ram_size())
			memcpy(f86_ram() + lo, &ret, 8);
	}
	c->rip = func;
	f86_set_next(c->rip);
}

/* F86_TRACE_RIPS=unslid1,unslid2,...: print when a block starting at one of
   these (unslid) kernel addresses is translated, with a few registers. */
static uint64_t g_trace_rips[32];
static int g_ntrace = -1;

static void trace_rips_init(void)
{
	g_ntrace = 0;
	const char *e = getenv("F86_TRACE_RIPS");
	while (e && *e && g_ntrace < 32) {
		char *end = NULL;
		uint64_t v = strtoull(e, &end, 0);
		if (end == e)
			break;
		g_trace_rips[g_ntrace++] = v;
		e = (*end == ',') ? end + 1 : end;
	}
}

static void *special_hook(uint64_t guest_rip)
{
	if (!f86_sys_bs_exited() || g_kaddr < 0x100000ull)
		return NULL;
	if (g_ntrace < 0)
		trace_rips_init();
	/* The build-specific kernel routine replacements (zalloc, vm_map_enter,
	   zone cram/steal, rwlock waits, ...) are off unless F86_KHOOKS=1: they
	   were written around emulator defects that are now fixed, and the
	   replacements do not keep XNU's real data structures consistent
	   (kmem_range_init panicked inside vm_map_locate_space). */
	static int khooks = -1;
	if (khooks < 0)
		khooks = getenv("F86_KHOOKS") != NULL;
	uint64_t b = 0xffffff8000000000ull | ((g_kaddr - 0x100000ull) & 0xffffffffull);
	{
		/* F86_TRACE_RANGE=lo,hi (unslid): print every block start in the
		   range, each time it is entered (the block is never cached). */
		static uint64_t tr_lo, tr_hi;
		static int tr_init;
		if (!tr_init) {
			tr_init = 1;
			const char *e = getenv("F86_TRACE_RANGE");
			if (e) {
				char *end = NULL;
				tr_lo = strtoull(e, &end, 0);
				if (end && *end == ',')
					tr_hi = strtoull(end + 1, NULL, 0);
			}
		}
		if (tr_hi && g_cpu) {
			uint64_t un = guest_rip - (g_kaddr - 0x100000ull);
			if (un >= tr_lo && un < tr_hi) {
				static unsigned ntr;
				if (ntr++ < 4000)
					fprintf(stderr, "fast86: BLK %lx rax=%lx rcx=%lx rdx=%lx rbx=%lx rsi=%lx rdi=%lx rsp=%lx r12=%lx r13=%lx r14=%lx r15=%lx fl=%lx\n",
					        (unsigned long)un, (unsigned long)g_cpu->r[R_RAX],
					        (unsigned long)g_cpu->r[R_RCX], (unsigned long)g_cpu->r[R_RDX],
					        (unsigned long)g_cpu->r[R_RBX],
					        (unsigned long)g_cpu->r[R_RSI], (unsigned long)g_cpu->r[R_RDI],
					        (unsigned long)g_cpu->r[R_RSP],
					        (unsigned long)g_cpu->r[R_R12], (unsigned long)g_cpu->r[R_R13],
					        (unsigned long)g_cpu->r[R_R14], (unsigned long)g_cpu->r[R_R15],
					        (unsigned long)(g_cpu->rflags & 0x8d5));
				map_evict(guest_rip);
			}
		}
	}
	for (int i = 0; i < g_ntrace; i++) {
		if (guest_rip == g_trace_rips[i] + (g_kaddr - 0x100000ull) && g_cpu) {
			fprintf(stderr, "fast86: TRACE unslid=%lx rip=%lx rdi=%lx rsi=%lx rdx=%lx rcx=%lx rsp=%lx rbp=%lx rax=%lx rbx=%lx r12=%lx r13=%lx r14=%lx r15=%lx",
			        (unsigned long)g_trace_rips[i], (unsigned long)guest_rip,
			        (unsigned long)g_cpu->r[R_RDI], (unsigned long)g_cpu->r[R_RSI],
			        (unsigned long)g_cpu->r[R_RDX], (unsigned long)g_cpu->r[R_RCX],
			        (unsigned long)g_cpu->r[R_RSP], (unsigned long)g_cpu->r[R_RBP],
			        (unsigned long)g_cpu->r[R_RAX], (unsigned long)g_cpu->r[R_RBX],
			        (unsigned long)g_cpu->r[R_R12], (unsigned long)g_cpu->r[R_R13],
			        (unsigned long)g_cpu->r[R_R14], (unsigned long)g_cpu->r[R_R15]);
			for (int k = 0; k < 6; k++) {
				uint64_t v = 0;
				if (gva_read(g_cpu->r[R_RSP] + 8ull * k, &v, 8) && v)
					fprintf(stderr, " s%d=%lx", k, (unsigned long)v);
			}
			{
				uint64_t v = 0;
				if (g_cpu->r[R_RDI] >= 0x1000 && gva_read(g_cpu->r[R_RDI], &v, 8))
					fprintf(stderr, " [rdi]=%lx", (unsigned long)v);
			}
			{
				/* F86_TRACE_BT=1: walk the RBP frame chain (unslid) */
				static int bt = -1;
				if (bt < 0)
					bt = getenv("F86_TRACE_BT") != NULL;
				if (bt) {
					uint64_t slide = g_kaddr >= 0x100000ull ? g_kaddr - 0x100000ull : 0;
					uint64_t fp = g_cpu->r[R_RBP];
					fprintf(stderr, " bt:");
					for (int k = 0; k < 14 && fp >= 0x1000; k++) {
						uint64_t ra = 0, nfp = 0;
						if (!gva_read(fp + 8, &ra, 8) || !gva_read(fp, &nfp, 8))
							break;
						fprintf(stderr, " %lx", (unsigned long)(ra - slide));
						if (nfp <= fp)
							break;
						fp = nfp;
					}
				}
			}
			{
				/* F86_TRACE_RBPOFF=hex: also dump 64 bytes at rbp - off */
				static long rbpoff = -1;
				if (rbpoff < 0) {
					const char *e = getenv("F86_TRACE_RBPOFF");
					rbpoff = e ? strtol(e, NULL, 0) : 0;
				}
				if (rbpoff > 0) {
					uint8_t b[64];
					memset(b, 0, sizeof b);
					if (gva_read(g_cpu->r[R_RBP] - (uint64_t)rbpoff, b, sizeof b)) {
						fprintf(stderr, " [rbp-%lx]:", rbpoff);
						for (int k = 0; k < 64; k++)
							fprintf(stderr, "%s%02x", (k % 8) ? "" : " ", b[k]);
					}
				}
				/* F86_TRACE_MEM=unslid: print 4 qwords there (slid) and its GPA */
				{
					static uint64_t tmem; static int tmem_init;
					if (!tmem_init) { tmem_init = 1; const char *e = getenv("F86_TRACE_MEM"); tmem = e ? strtoull(e, NULL, 0) : 0; }
					if (tmem) {
						uint64_t va = tmem + (g_kaddr - 0x100000ull), q[4] = {0,0,0,0}, gp = 0;
						int ok = f86_gva_to_gpa(va, &gp);
						gva_read(va, q, 32);
						fprintf(stderr, " mem@%lx(gpa %lx ok=%d)=[%lx %lx %lx %lx]", (unsigned long)va,
						        (unsigned long)gp, ok, (unsigned long)q[0], (unsigned long)q[1],
						        (unsigned long)q[2], (unsigned long)q[3]);
					}
				}
			}
			fprintf(stderr, "\n");
			map_evict(guest_rip); /* keep tracing this block */
		}
	}
	if (!khooks)
		return NULL;
	reloc_startup_once();
	if (guest_rip == b + 0x36e754ull)
		return emit_special_hook(guest_rip, f86_zalloc, "vm-zalloc");
	if (guest_rip == b + 0x497990ull)
		return emit_special_hook(guest_rip, f86_map_enter, "map-enter");
	if (g_stride_done && guest_rip == b + 0x44f480ull)
		return emit_special_hook(guest_rip, f86_zfree_early, "zfree-early");
	if (guest_rip == b + 0x4f3410ull)
		return emit_special_hook(guest_rip, f86_fast_memcmp, "memcmp");
	if (guest_rip == b + 0x54491bull)
		return emit_special_hook(guest_rip, f86_fast_uuid_scan, "uuid scan");
	if (guest_rip == b + 0x54bd20ull)
		return emit_special_hook(guest_rip, f86_fast_packed_walk, "packed walk");
	if (guest_rip == b + 0x4fef40ull || guest_rip == b + 0x4fef89ull)
		return emit_special_hook(guest_rip, f86_fast_cons, "cons");
	if (guest_rip == b + 0x4d1430ull && !g_stride_done)
		return emit_special_hook(guest_rip, f86_fast_stride, "stride");
	if (guest_rip == b + 0x3f0ad0ull || guest_rip == b + 0x3f0ad3ull ||
	    (g_stride_done && (guest_rip == b + 0x3f2580ull ||
	                       guest_rip == b + 0x3f2582ull)))
		return emit_special_hook(guest_rip, f86_fast_rwspin, "rwspin");
	if (g_stride_done && guest_rip == b + 0x3f12a0ull)
		return emit_special_hook(guest_rip, f86_fast_rwwait, "rwwait");
	if (guest_rip == b + 0x36f110ull || guest_rip == b + 0x36f113ull)
		return emit_special_hook(guest_rip, f86_fast_timebase, "timebase");
	if (guest_rip == b + 0xbd1477ull) {
		static int nw;
		if (nw++ < 8)
			fprintf(stderr, "fast86: translate startup walker #%d\n", nw);
	}
	if (guest_rip == b + 0x44ed80ull)
		return emit_special_hook(guest_rip, f86_nop_ret, "zba-early");
	if (guest_rip == b + 0xbd62bfull) {
		static int ns;
		if (ns++ < 6)
			fprintf(stderr, "fast86: translate steal #%d map=%lx\n",
			        ns, (unsigned long)kload64(0x13cecf8ull));
		if (kload64(0x13cecf8ull))
			return emit_special_hook(guest_rip, f86_fast_zsteal, "steal-skip");
	}
	if (guest_rip == b + 0xbd264aull)
		return emit_special_hook(guest_rip, f86_fast_zcram, "cram-early");
	if (0 && guest_rip == b + 0xbd264aull && g_cpu) {
		uint64_t z = g_cpu->r[R_RDI];
		uint64_t pg = g_cpu->r[R_RSI];
		uint64_t sz = g_cpu->r[R_RDX];
		uint16_t cpg = 0;
		if (z) {
			gva_read(z + 0x38, &cpg, 2);
			if (!cpg)
				cpg = 1;
			{
				uint64_t za = b + 0x13640c0ull;
				unsigned zid = (unsigned)((z - za) / 256ull);
				uint8_t *cp = kc_phys(0x13640c0ull + (uint64_t)zid * 256ull + 0x38ull, 2);
				if (cp)
					memcpy(cp, &cpg, 2);
				gva_write(z + 0x38, &cpg, 2);
			}
			{
				uint64_t za = b + 0x13640c0ull;
				unsigned id = (unsigned)((z - za) / 256ull);
				uint64_t zb = kload64(0x218d78ull);
				uint64_t a;
				uint16_t bits = (uint16_t)((id & 0x3ffu) | (1u << 11) | (1u << 12));
				if (!zb)
					zb = b + 0x13bbb30ull;
				uint64_t left = sz;
				for (a = pg; left >= 0x1000ull && a; a += 0x1000ull, left -= 0x1000ull) {
					uint64_t packed = (a >> 8) & 0xffffffff0ull;
					uint64_t meta = zb + packed;
					uint8_t rec[16];
					memset(rec, 0, sizeof rec);
					memcpy(rec, &bits, 2);
					gva_write(meta, rec, 16);
					{
						uint64_t lo = meta & 0xffffffffull;
						if ((meta >> 32) == 0xffffff80ull &&
						    lo + 16 <= f86_ram_size())
							memcpy(f86_ram() + lo, rec, 16);
					}
				}
				{
					uint16_t esz = 0;
					uint32_t add = 0, cur = 0;
					gva_read(z + 0x34, &esz, 2);
					if (esz && g_cpu->r[R_RDX])
						add = (uint32_t)(g_cpu->r[R_RDX] / esz);
					{
						static uint8_t crammed[32];
						if (id < 32 && !crammed[id]) {
							gva_read(z + 0xa8, &cur, 4);
							cur += add;
							gva_write(z + 0xa8, &cur, 4);
							crammed[id] = 1;
						} else
							gva_read(z + 0xa8, &cur, 4);
					}
					{
						static const uint64_t nopsites[] = {
							0xbd26a5ull, 0xbd26adull
						};
						unsigned ni;
						for (ni = 0; ni < 2; ni++) {
							uint8_t *ip = kc_phys(nopsites[ni], 5);
							if (!ip)
								ip = gva_host(b + nopsites[ni], 5);
							if (ip && ip[0] == 0xe8)
								memset(ip, 0x90, 5);
							map_evict(b + nopsites[ni]);
						}
						map_evict(b + 0xbd264aull);
						map_evict(b + 0xbd2690ull);
					}
					fprintf(stderr,
					        "fast86: cram-early z=%lx id=%u pg=%lx cpg=%u esz=%u free=%u bits=%x\n",
					        (unsigned long)z, id, (unsigned long)pg, cpg, esz, cur, bits);
				}
			}
		}
	}
	if (guest_rip == b + 0x44e0e0ull && g_cpu) {
		static int nc;
		uint64_t z = g_cpu->r[R_RDI];
		uint16_t esz = 0, esz2 = 0, cpg = 0;
		if (z) {
			gva_read(z + 0x34, &esz, 2);
			gva_read(z + 0x36, &esz2, 2);
			gva_read(z + 0x38, &cpg, 2);
			if (!esz) {
				uint64_t za = b + 0x13640c0ull;
				unsigned id = (unsigned)((z - za) / 256ull);
				static const uint16_t es[] = {
					[15] = 0xb0, [16] = 0x50, [17] = 0x20, [18] = 0x48
				};
				if (id <= 18 && es[id]) {
					esz = es[id];
					gva_write(z + 0x34, &esz, 2);
				}
			}
			if (!cpg) {
				cpg = 1;
				gva_write(z + 0x38, &cpg, 2);
				g_cpu->r[R_RDX] = 1;
				if ((uint32_t)g_cpu->r[R_R8] == 0)
					g_cpu->r[R_R8] = 1;
			}
		}
		if (nc++ < 12) {
			uint64_t zb = kload64(0x218d78ull), pg = g_cpu->r[R_RSI];
			uint64_t packed = (pg >> 8) & 0xffffffff0ull;
			uint64_t meta = zb + packed;
			uint8_t mb[16];
			memset(mb, 0, sizeof mb);
			gva_read(meta, mb, 16);
			fprintf(stderr,
			        "fast86: zcram z=%lx pg=%lx n=%lx esz=%u/%u cpg=%u zbase=%lx meta=%lx m=%02x%02x%02x%02x\n",
			        (unsigned long)z, (unsigned long)pg,
			        (unsigned long)g_cpu->r[R_RDX], esz, esz2, cpg,
			        (unsigned long)zb, (unsigned long)meta,
			        mb[0], mb[1], mb[2], mb[3]);
		}
	}
	if (guest_rip == b + 0xbd5fd2ull) {
		uint64_t z15 = kload64(0x13640c0ull + 15ull * 256ull);
		uint16_t cpg = 0;
		uint8_t *p = kc_phys(0x13640c0ull + 15ull * 256ull + 0x38ull, 2);
		if (p)
			memcpy(&cpg, p, 2);
		fprintf(stderr, "fast86: vminit map=%lx z15_hdr=%lx cpg=%u\n",
		        (unsigned long)kload64(0x13cecf8ull),
		        (unsigned long)z15, cpg);
		plant_early_zone_mem();
	}
	if (guest_rip == b + 0xbd4bdbull) {
		static int nk;
		if (nk++ < 4)
			fprintf(stderr, "fast86: kmem_init start=%lx end=%lx z15_self=%lx map=%lx\n",
			        (unsigned long)g_cpu->r[R_RDI],
			        (unsigned long)g_cpu->r[R_RSI],
			        (unsigned long)kload64(0x13640c0ull + 15ull * 256ull),
			        (unsigned long)kload64(0x13cecf8ull));
	}
	if (guest_rip == b + 0x497990ull && g_cpu) {
		static int ne;
		uint64_t ap = g_cpu->r[R_RSI], addr = 0;
		gva_read(ap, &addr, 8);
		if (ne++ < 12)
			fprintf(stderr,
			        "fast86: vm_map_enter map=%lx addrp=%lx *addr=%lx size=%lx mask=%lx fl=%lx\n",
			        (unsigned long)g_cpu->r[R_RDI],
			        (unsigned long)ap, (unsigned long)addr,
			        (unsigned long)g_cpu->r[R_RDX],
			        (unsigned long)g_cpu->r[R_RCX],
			        (unsigned long)g_cpu->r[R_R8]);
	}
	if (guest_rip == b + 0x4906f0ull && g_cpu) {
		static int ns;
		if (ns++ < 8)
			fprintf(stderr, "fast86: kmem_suballoc map=%lx addrp=%lx size=%lx flags=%lx\n",
			        (unsigned long)g_cpu->r[R_RDI],
			        (unsigned long)g_cpu->r[R_RSI],
			        (unsigned long)g_cpu->r[R_RDX],
			        (unsigned long)g_cpu->r[R_RCX]);
	}
	if (guest_rip == b + 0xbd14fcull)
		return emit_special_hook(guest_rip, f86_fast_startup_call, "startup-call");
	return NULL;
}

void *f86_translate(F86CPU *cpu, uint64_t guest_rip)
{
	if (f86_sys_bs_exited() && g_kaddr >= 0x100000ull)
		if (getenv("F86_KHOOKS"))
			reloc_startup_once(); /* rewrites 39 zalloc call sites + 2 prologues for the hook layer */
	if (guest_rip < 0x1000) {
		fprintf(stderr, "fast86: translate of %lx\n", (unsigned long)guest_rip);
		g_cpu->exited = 1;
		g_cpu->exit_code = 127;
		return NULL;
	}
	{
		void *hk = special_hook(guest_rip);
		if (hk)
			return hk;
	}
	if (f86_sys_bs_exited()) {
		uint64_t snapped = snap_insn_pc(guest_rip);
		if (snapped != guest_rip) {
			static int nsnap;
			if (nsnap++ < 8)
				fprintf(stderr, "fast86: snap %lx -> %lx\n",
				        (unsigned long)guest_rip, (unsigned long)snapped);
			guest_rip = snapped;
			cpu->rip = snapped;
		}
	}
	if (f86_sys_bs_exited()) {
		uint64_t top = guest_rip >> 47;
		if (top != 0 && top != 0x1ffffull) {
			uint64_t rec = recover_from_stack(cpu);
			static int nc;
			if (nc++ < 8)
				fprintf(stderr, "fast86: noncanonical rip %lx recover=%lx\n",
				        (unsigned long)guest_rip, (unsigned long)rec);
			if (rec) {
				cpu->rip = rec;
				guest_rip = rec;
			} else
				guest_rip = cpu->rip;
			top = guest_rip >> 47;
			if ((guest_rip < 0x1000) || (top != 0 && top != 0x1ffffull)) {
				g_cpu->exited = 1;
				g_cpu->exit_code = 127;
				return NULL;
			}
		}
	}
	{
		void *hk = special_hook(guest_rip);
		if (hk)
			return hk;
	}
	uint8_t *hit = lookup(guest_rip);
	if (hit)
		return hit;
	if (g_emit + 8192 >= g_cend) {
		/* Full: start over instead of dying (B12). The caller's exit tail
		   sits at the old end of the cache and is not overwritten by the
		   block emitted at the base. */
		static int nflush;
		fprintf(stderr, "fast86: code cache full, flushing (%d)\n", ++nflush);
		f86_cache_flush();
	}

	while (((uintptr_t)g_emit & 15) && g_emit < g_cend)
		em1(0x90);

	uint8_t *block_rw = g_emit;
	uint8_t *block_rx = rx_of(block_rw);
	int mapped = 0;
	cpu->n_blocks++;
	if (f86_sys_bs_exited() &&
	    ((cpu->n_blocks < 1400) || (cpu->n_blocks % 64) == 0 || guest_rip >> 63)) {
		if (cpu->n_blocks < 1600 || (cpu->n_blocks % 64) == 0)
			fprintf(stderr, "fast86: post-ebs translate %lx blocks=%lu\n",
			        (unsigned long)guest_rip, (unsigned long)cpu->n_blocks);
	}
	if (f86_sys_bs_exited() && (guest_rip & 0xffffull) == 0xfd60ull) {
		static int ndt;
		if (ndt++ < 4)
			fprintf(stderr,
			        "fast86: DTfn rdi=%lx rsi=%lx rdx=%lx rcx=%lx r8=%lx rsp=%lx\n",
			        (unsigned long)cpu->r[R_RDI], (unsigned long)cpu->r[R_RSI],
			        (unsigned long)cpu->r[R_RDX], (unsigned long)cpu->r[R_RCX],
			        (unsigned long)cpu->r[R_R8], (unsigned long)cpu->r[R_RSP]);
	}
	if (f86_sys_bs_exited() && g_kaddr >= 0x100000ull) {
		static int khooks2 = -1;
		if (khooks2 < 0)
			khooks2 = getenv("F86_KHOOKS") != NULL;
		uint64_t memcmp_va = 0xffffff8000000000ull |
		                     ((g_kaddr - 0x100000ull + 0x4f3410ull) & 0xffffffffull);
		if (khooks2 && guest_rip == memcmp_va) {
			insert(guest_rip, block_rx);
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, guest_rip);
			emit_c_helper(f86_fast_memcmp);
			fprintf(stderr, "fast86: hooked memcmp at %lx\n",
			        (unsigned long)guest_rip);
			return block_rx;
		}
		uint64_t scan_va = 0xffffff8000000000ull |
		                   ((g_kaddr - 0x100000ull + 0x54491bull) & 0xffffffffull);
		if (khooks2 && guest_rip == scan_va) {
			insert(guest_rip, block_rx);
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, guest_rip);
			emit_c_helper(f86_fast_uuid_scan);
			fprintf(stderr, "fast86: hooked uuid scan at %lx\n",
			        (unsigned long)guest_rip);
			return block_rx;
		}
		uint64_t walk_va = 0xffffff8000000000ull |
		                   ((g_kaddr - 0x100000ull + 0x54bd20ull) & 0xffffffffull);
		if (khooks2 && guest_rip == walk_va) {
			insert(guest_rip, block_rx);
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, guest_rip);
			emit_c_helper(f86_fast_packed_walk);
			fprintf(stderr, "fast86: hooked packed walk at %lx\n",
			        (unsigned long)guest_rip);
			return block_rx;
		}
		uint64_t cons_va = 0xffffff8000000000ull |
		                   ((g_kaddr - 0x100000ull + 0x4fef89ull) & 0xffffffffull);
		if (khooks2 && guest_rip == cons_va) {
			insert(guest_rip, block_rx);
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, guest_rip);
			emit_c_helper(f86_fast_cons);
			fprintf(stderr, "fast86: hooked cons at %lx\n",
			        (unsigned long)guest_rip);
			return block_rx;
		}
	}
	if (f86_sys_bs_exited() && guest_rip >= 0x00100000ull && guest_rip < 0x40000000ull &&
	    (guest_rip & 0xfff) == 0 && !(cpu->cr0 & (1ull << 31))) {
		fprintf(stderr,
		        "fast86: HIB entry rip=%lx rax=%lx rdi=%lx rsi=%lx rbx=%lx rdx=%lx\n",
		        (unsigned long)guest_rip,
		        (unsigned long)cpu->r[R_RAX], (unsigned long)cpu->r[R_RDI],
		        (unsigned long)cpu->r[R_RSI], (unsigned long)cpu->r[R_RBX],
		        (unsigned long)cpu->r[R_RDX]);
		uint64_t ba = cpu->r[R_RAX];
		if (ba < 0x1000 || ba >= f86_ram_size())
			ba = cpu->r[R_RDI];
		g_boot_args = ba;
		if (ba >= 0x1000 && ba + 64 < f86_ram_size()) {
			uint8_t *p = f86_ram() + ba;
			uint16_t rev, ver;
			uint32_t mmap, mmsz, dsz, dtp, dtl, kaddr, ksz;
			memcpy(&rev, p, 2);
			memcpy(&ver, p + 2, 2);
			memcpy(&mmap, p + 1028, 4);
			memcpy(&mmsz, p + 1032, 4);
			memcpy(&dsz, p + 1036, 4);
			/* Video is 40 bytes? actually Boot_Video varies; deviceTree follows.
			   Sequoia boot_args: CommandLine[1024] at 4, then MemoryMap uint32s.
			   deviceTreeP is after video. Dump first 64 bytes and a few known fields. */
			fprintf(stderr, "fast86: boot_args@%lx rev=%u ver=%u cmd='%.80s'\n",
			        (unsigned long)ba, rev, ver, (char *)(p + 4));
			fprintf(stderr, "fast86: ba[0..80]: ");
			for (int i = 0; i < 80; i++)
				fprintf(stderr, "%02x", p[i]);
			fprintf(stderr, "\n");
			fprintf(stderr, "fast86: ba+0x408: ");
			for (int i = 0; i < 96; i++)
				fprintf(stderr, "%02x", p[0x408 + i]);
			fprintf(stderr, "\n");
			uint64_t physsz = 0, fsb = 0;
			memcpy(&physsz, p + 1144, 8);
			memcpy(&fsb, p + 1152, 8);
			fprintf(stderr, "fast86: PhysicalMemorySize@1144=%lx FSB=%lx dt=%x dtlen=%x kaddr=%x\n",
			        (unsigned long)physsz, (unsigned long)fsb,
			        *(uint32_t *)(p + 1072), *(uint32_t *)(p + 1076),
			        *(uint32_t *)(p + 1080));
			fprintf(stderr, "fast86: ba+0x460: ");
			for (int i = 0; i < 80; i++)
				fprintf(stderr, "%02x", p[0x460 + i]);
			fprintf(stderr, "\n");
			fprintf(stderr, "fast86: ba+0x4a8: ");
			for (int i = 0; i < 96; i++)
				fprintf(stderr, "%02x%s", p[0x4a8 + i], (i % 8 == 7) ? " " : "");
			fprintf(stderr, "\n");
			if (physsz == 0) {
				physsz = f86_ram_size();
				memcpy(p + 1144, &physsz, 8);
				fprintf(stderr, "fast86: PhysicalMemorySize was 0, set to RAM size %lx\n",
				        (unsigned long)physsz);
			}
			/* Report what boot.efi left in the in-memory kernel headers:
			   XNU's i386_slide_and_rebase_image derives the KASLR slide from
			   the kernel's first segment vmaddr, so these must be slid. */
			{
				uint32_t kaddr = 0;
				memcpy(&kaddr, p + 1080, 4);
				uint8_t *ram = f86_ram();
				uint64_t kcm = (uint64_t)kaddr + 0x100000ull; /* KC __TEXT, lowest vmaddr is __HIB */
				if (kcm + 0x2000 < f86_ram_size() &&
				    memcmp(ram + kcm, "\xcf\xfa\xed\xfe", 4) == 0) {
					uint32_t nc = 0;
					memcpy(&nc, ram + kcm + 16, 4);
					uint64_t o = kcm + 32;
					for (uint32_t i = 0; i < nc && i < 2000 && o + 8 < f86_ram_size(); i++) {
						uint32_t cmd = 0, csz = 0;
						memcpy(&cmd, ram + o, 4);
						memcpy(&csz, ram + o + 4, 4);
						if (csz < 8) break;
						if (cmd == 0x80000035u) {
							uint64_t va = 0, fo = 0;
							uint32_t sx = 0;
							memcpy(&va, ram + o + 8, 8);
							memcpy(&fo, ram + o + 16, 8);
							memcpy(&sx, ram + o + 24, 4);
							const char *nm = (const char *)(ram + o + sx);
							if (strncmp(nm, "com.apple.kernel", 17) == 0) {
								/* boot.efi lays the KC out by vmaddr, lowest (__HIB) at kaddr */
								uint64_t kh = (uint64_t)kaddr + (va - 0xffffff8000100000ull);
								(void)fo;
								fprintf(stderr, "fast86: kernel entry vmaddr=%lx fileoff=%lx hdr@%lx\n",
								        (unsigned long)va, (unsigned long)fo, (unsigned long)kh);
								if (kh + 0x1000 < f86_ram_size() &&
								    memcmp(ram + kh, "\xcf\xfa\xed\xfe", 4) == 0) {
									uint32_t nc2 = 0;
									memcpy(&nc2, ram + kh + 16, 4);
									uint64_t o2 = kh + 32;
									for (uint32_t j = 0; j < nc2 && j < 64; j++) {
										uint32_t c2 = 0, s2 = 0;
										memcpy(&c2, ram + o2, 4);
										memcpy(&s2, ram + o2 + 4, 4);
										if (s2 < 8) break;
										if (c2 == 0x19) {
											char sn[17];
											uint64_t sva = 0;
											memcpy(sn, ram + o2 + 8, 16);
											sn[16] = 0;
											memcpy(&sva, ram + o2 + 24, 8);
											if (j < 3 || !strcmp(sn, "__HIB") || !strcmp(sn, "__TEXT"))
												fprintf(stderr, "fast86:   kernel seg#%u %s vmaddr=%lx\n",
												        j, sn, (unsigned long)sva);
										}
										o2 += s2;
									}
								}
							}
						}
						o += csz;
					}
				}
			}
			if (getenv("F86_NOP_PANICS")) {
				/* NOP jae/ja to inlined PHYSMAP/DBLMAP panics. */
				uint32_t kaddr = 0, ksize = 0;
				memcpy(&kaddr, p + 1080, 4);
				memcpy(&ksize, p + 1084, 4);
				const char *needs[] = {
					"PHYSMAP_PTOV bounds exceeded",
					"DBLMAP bounds exceeded",
					"accounting mismatch",
					"zone bits allocator freelist is corrupt",
					NULL
				};
				if (kaddr >= 0x1000 && ksize > 0x1000 &&
				    (uint64_t)kaddr + ksize <= f86_ram_size()) {
					uint8_t *ram = f86_ram();
					int npat = 0;
				for (int ni = 0; needs[ni]; ni++) {
					const char *need = needs[ni];
					size_t nlen = strlen(need);
					uint8_t *hit = NULL;
					{
						uint8_t *q = ram + 0x100000;
						uint8_t *end = ram + (f86_ram_size() > 0x70000000ull ?
						                      0x70000000ull : f86_ram_size());
						for (;;) {
							uint8_t *h = memmem(q, (size_t)(end - q), need, nlen);
							if (!h)
								break;
							hit = h;
							q = h + 1;
						}
					}
					if (hit) {
						uint64_t str_gpa = (uint64_t)(hit - ram);
						uint64_t probe = str_gpa - 0x8e23bdull;
						if (probe > 0x1000 && probe + 16 < f86_ram_size()) {
							int32_t pd = 0;
							memcpy(&pd, ram + probe + 3, 4);
							fprintf(stderr,
							        "fast86: PHYSMAP str_gpa=%lx lea@%lx -> %lx bytes %02x%02x%02x\n",
							        (unsigned long)str_gpa, (unsigned long)probe,
							        (unsigned long)(probe + 7 + (int64_t)pd),
							        ram[probe], ram[probe+1], ram[probe+2]);
						}
						/* __TEXT_EXEC file 0xe4000 holds the inlined checks;
						   string is at file 0xa8191a in the same segment. */
						uint64_t c0 = str_gpa > 0x00c00000ull ?
						              str_gpa - 0x00c00000ull : 0x100000ull;
						uint64_t c1 = str_gpa + 0x1000;
						if (c1 > f86_ram_size())
							c1 = f86_ram_size();
						for (uint64_t c = c0; c + 7 < c1; c++) {
							if (ram[c] != 0x48 && ram[c] != 0x4c)
								continue;
							if (ram[c + 1] != 0x8d)
								continue;
							if ((ram[c + 2] & 0xC7) != 0x05)
								continue;
							int32_t disp;
							memcpy(&disp, ram + c + 3, 4);
							uint64_t tgt = c + 7 + (int64_t)disp;
							if (tgt != str_gpa)
								continue;
							uint64_t b0 = c > 160 ? c - 160 : c0;
							for (uint64_t b = b0; b + 1 < c + 48 && b + 1 < c1; b++) {
								if (ram[b] == 0x73 || ram[b] == 0x72 ||
								    ram[b] == 0x77 || ram[b] == 0x76 ||
								    ram[b] == 0x74 || ram[b] == 0x75) {
									ram[b] = 0x90;
									ram[b + 1] = 0x90;
									npat++;
								} else if (ram[b] == 0x0F &&
								           (ram[b + 1] == 0x83 || ram[b + 1] == 0x87 ||
								            ram[b + 1] == 0x82 || ram[b + 1] == 0x84 ||
								            ram[b + 1] == 0x85)) {
									memset(ram + b, 0x90, 6);
									npat++;
								} else if (ram[b] == 0xE8 && b > c && b < c + 40) {
									memset(ram + b, 0x90, 5);
									npat++;
								}
							}
						}
						if (probe > 0x80 && probe + 2 < f86_ram_size())
							fprintf(stderr, "fast86: post-patch @lea-0x4d %02x %02x\n",
							        ram[probe - 0x4d], ram[probe - 0x4c]);
						fprintf(stderr, "fast86: patched %d '%s' branches str_gpa=%lx\n",
						        npat, need, (unsigned long)str_gpa);
					}
				} /* needs[] */
				}
			}
			if (fsb < 100000000ull) {
				fsb = 1000000000ull;
				memcpy(p + 1152, &fsb, 8);
			}
			{
				uint32_t mmap = 0, mmsz = 0, mdsz = 40;
				memcpy(&mmap, p + 1032, 4);
				memcpy(&mmsz, p + 1036, 4);
				memcpy(&mdsz, p + 1040, 4);
				if (!mdsz)
					mdsz = 40;
				fprintf(stderr, "fast86: darwin mmap %x size=%u dsz=%u\n",
				        mmap, mmsz, mdsz);
				if (mmap && mmsz && mmap + mmsz < f86_ram_size()) {
					uint8_t *md = f86_ram() + mmap;
					int n = (int)(mmsz / mdsz);
					if (n > 16)
						n = 16;
					for (int i = 0; i < n; i++) {
						uint32_t ty = 0;
						uint64_t ph = 0, pg = 0;
						memcpy(&ty, md + (size_t)i * mdsz, 4);
						memcpy(&ph, md + (size_t)i * mdsz + 8, 8);
						memcpy(&pg, md + (size_t)i * mdsz + 24, 8);
						fprintf(stderr, "  map[%d] type=%u phys=%lx pages=%lx\n",
						        i, ty, (unsigned long)ph, (unsigned long)pg);
					}
				}
			}
			(void)dtp; (void)dtl; (void)kaddr; (void)ksz;
			{
				uint32_t dtp32 = 0, dtl32 = 0;
				memcpy(&dtp32, p + 1072, 4);
				memcpy(&dtl32, p + 1076, 4);
				uint32_t kbase = 0;
				memcpy(&kbase, p + 1080, 4);
				if (kbase >= 0x100000 && dtp32 >= 0x1000 && dtl32 > 8 &&
				    (uint64_t)kbase + 0x250000 < f86_ram_size()) {
					uint64_t dt_va = 0xffffff8000000000ull | (uint64_t)dtp32;
					uint8_t *ram = f86_ram();
					uint64_t g0 = (uint64_t)kbase + 0x1aa840ull;
					g_kaddr = kbase;
					g_dt_phys = dtp32;
					g_dt_slot = g0;
					g_dt_slot2 = (uint64_t)kbase + 0x23b218ull;
					/* Build-specific kernel image patches (DTStart/boot_args
					   plants, DT bounds jb rewrites, pe_gen stubs that turned
					   PE_set_kc_header into `xor eax,eax; ret`, rdrand -> xor+stc)
					   only with F86_KHOOKS=1. The random-seed DT property stays. */
					static int kentry_hacks = -1;
					if (kentry_hacks < 0)
						kentry_hacks = getenv("F86_KHOOKS") != NULL;
					if (kentry_hacks && g0 + 32 < f86_ram_size()) {
						memcpy(ram + g0, &dt_va, 8);
						uint64_t ln = dtl32;
						memcpy(ram + g0 + 8, &ln, 8);
						uint64_t en = dt_va + ln;
						memcpy(ram + g0 + 16, &en, 8);
						uint32_t one = 1;
						memcpy(ram + g0 + 24, &one, 4);
						fprintf(stderr,
						        "fast86: plant DTStart=%lx len=%lx @%lx\n",
						        (unsigned long)dt_va, (unsigned long)ln,
						        (unsigned long)g0);
					}
					/* DT bounds checks panic — turn them into not-found. */
					if (kentry_hacks) {
						static const struct { uint64_t off; uint32_t disp; } pw[] = {
							{ 0xa8f855ull, 0x1c1 },
							{ 0xa8f862ull, 0x1b4 },
							{ 0xa8fac7ull, 0x62 },
							{ 0xa8fad7ull, 0x52 },
						};
						for (size_t i = 0; i < sizeof pw / sizeof pw[0]; i++) {
							uint64_t a = (uint64_t)kbase + pw[i].off;
							if (a + 6 < f86_ram_size() &&
							    ram[a] == 0x0f && ram[a + 1] == 0x82) {
								memcpy(ram + a + 2, &pw[i].disp, 4);
							}
						}
					}
					/* pe_gen random-seed + kc_kind: return success. */
					if (kentry_hacks) {
						/* pe_read_random_seed: fill dest, return 64 */
						{
							uint64_t a = (uint64_t)kbase + 0xa911d0ull;
							if (a + 20 < f86_ram_size()) {
								static const uint8_t stub[] = {
									0x51, 0x50,
									0x48, 0x89, 0xf1,
									0xb0, 0xa5,
									0xf3, 0xaa,
									0x58, 0x59,
									0xb8, 0x40, 0x00, 0x00, 0x00,
									0xc3
								};
								memcpy(ram + a, stub, sizeof stub);
							}
							a = (uint64_t)kbase + 0xa91310ull;
							if (a + 3 < f86_ram_size()) {
								ram[a] = 0x31;
								ram[a + 1] = 0xc0;
								ram[a + 2] = 0xc3;
							}
						}
					}
					/* rdrand/rdseed → xor rax,rax; stc  (always succeed) */
					if (kentry_hacks) {
						uint64_t te = (uint64_t)kbase + 0x1e4000ull;
						uint64_t te_end = te + 0xa14000ull;
						if (te_end > f86_ram_size())
							te_end = f86_ram_size();
						int nrd = 0;
						for (uint64_t a = te; a + 4 < te_end; a++) {
							if (ram[a] == 0x48 && ram[a + 1] == 0x0f &&
							    ram[a + 2] == 0xc7 &&
							    (ram[a + 3] == 0xf0 || ram[a + 3] == 0xf8)) {
								ram[a] = 0x48;
								ram[a + 1] = 0x31;
								ram[a + 2] = 0xc0;
								ram[a + 3] = 0xf9;
								nrd++;
							}
						}
						fprintf(stderr, "fast86: patched %d rdrand/rdseed\n", nrd);
					}
					if (getenv("F86_HIB_HACK")) {
					/* Proper DBLMAP fix: doublemap_init computes
					   dblmap_dist = dblmap_base - hdescb, where hdescb is the
					   __HIB segment vmaddr read from the kernel's in-memory
					   Mach-O header. boot.efi slides the __HIB data and its
					   descriptor-table pointers, but leaves the header's segment
					   vmaddrs unslid, so DBLMAP(x) overflows the window by the
					   slide and the kernel panics. Slide the header's __HIB
					   vmaddr so the two agree. */
					{
						uint64_t slide = kbase > 0x100000ull ?
						                 kbase - 0x100000ull : 0;
						if (slide) {
							size_t rsz = f86_ram_size();
							int found = 0;
							for (size_t off = 0; off + 32 < rsz; off += 4) {
								if (memcmp(ram + off, "\xcf\xfa\xed\xfe", 4))
									continue;
								uint32_t ncmds = 0;
								memcpy(&ncmds, ram + off + 16, 4);
								if (ncmds == 0 || ncmds > 512)
									continue;
								size_t p = off + 32;
								int ok = 1;
								for (uint32_t c = 0; c < ncmds; c++) {
									uint32_t cmd = 0, cmdsize = 0;
									if (p + 8 > rsz) { ok = 0; break; }
									memcpy(&cmd, ram + p, 4);
									memcpy(&cmdsize, ram + p + 4, 4);
									if (cmdsize < 8 || p + cmdsize > rsz) {
										ok = 0;
										break;
									}
									if (cmd == 0x19 && cmdsize >= 72) {
										char segname[17];
										uint64_t vmaddr = 0;
										memcpy(segname, ram + p + 8, 16);
										segname[16] = 0;
										memcpy(&vmaddr, ram + p + 24, 8);
										if (!strcmp(segname, "__HIB") &&
										    (vmaddr >> 32) == 0xffffff80ull) {
											uint64_t slid = vmaddr + slide;
											memcpy(ram + p + 24, &slid, 8);
											found++;
											fprintf(stderr,
											        "fast86: slid __HIB header vmaddr %lx -> %lx\n",
											        (unsigned long)vmaddr,
											        (unsigned long)slid);
										}
									}
									p += cmdsize;
								}
								if (!ok)
									continue;
								if (found)
									break;
							}
							if (!found)
								fprintf(stderr,
								        "fast86: __HIB header not found (slide=%lx)\n",
								        (unsigned long)slide);
						}
						/* Skip DBLMAP panic in cpu_syscall_init (jae / jne). */
						{
							uint64_t a = (uint64_t)kbase + 0x421a75ull;
							if (a + 6 < f86_ram_size() &&
							    ram[a] == 0x0f && ram[a + 1] == 0x83)
								memset(ram + a, 0x90, 6);
							a = (uint64_t)kbase + 0x421a7dull;
							if (a + 6 < f86_ram_size() &&
							    ram[a] == 0x0f && ram[a + 1] == 0x85)
								memset(ram + a, 0x90, 6);
							a = (uint64_t)kbase + 0x421adaull;
							if (a + 2 < f86_ram_size() && ram[a] == 0x73)
								memset(ram + a, 0x90, 2);
							a = (uint64_t)kbase + 0x421adeull;
							if (a + 2 < f86_ram_size() && ram[a] == 0x75)
								memset(ram + a, 0x90, 2);
						}
					}
					} /* F86_HIB_HACK */
					uint64_t g1 = (uint64_t)kbase + 0x23b218ull;
					if (kentry_hacks && g1 + 24 < f86_ram_size()) {
						memcpy(ram + g1, &dt_va, 8);
						uint64_t bava = 0xffffff8000000000ull | ba;
						memcpy(ram + g1 + 8, &bava, 8);
						uint64_t ln = dtl32;
						memcpy(ram + g1 + 0x10, &ln, 8);
						fprintf(stderr, "fast86: plant boot_args va=%lx @%lx\n",
						        (unsigned long)bava, (unsigned long)(g1 + 8));
					}
				}
				if (dtp32 >= 0x1000 && dtl32 > 8 &&
				    (uint64_t)dtp32 + dtl32 + 256 <= f86_ram_size()) {
					uint8_t *dt = f86_ram() + dtp32;
					uint8_t *dend = dt + dtl32;
					fprintf(stderr, "fast86: DT@%x len=%u\n", dtp32, dtl32);
					uint8_t *q = dt;
					int nprop = 0, nch = 0;
					if (q + 8 <= dend) {
						memcpy(&nprop, q, 4);
						memcpy(&nch, q + 4, 4);
						q += 8;
					}
					fprintf(stderr, "  root props=%d children=%d\n", nprop, nch);
					int have_seed = 0;
					uint8_t *after_props = q;
					for (int i = 0; i < nprop && i < 32 && q + 36 <= dend; i++) {
						char nm[33];
						uint32_t ln = 0;
						memcpy(nm, q, 32);
						nm[32] = 0;
						memcpy(&ln, q + 32, 4);
						if (strcmp(nm, "random-seed") == 0)
							have_seed = 1;
						q += 36;
						uint32_t pad = (ln + 3u) & ~3u;
						fprintf(stderr, "  prop '%s' len=%u\n", nm, ln);
						if (q + pad > dend)
							break;
						q += pad;
						after_props = q;
					}
					/* Walk first-level children names. */
					uint8_t *ch = after_props;
					uint8_t *chosen = NULL;
					for (int c = 0; c < nch && c < 16 && ch + 8 <= dend; c++) {
						int cp = 0, cc = 0;
						memcpy(&cp, ch, 4);
						memcpy(&cc, ch + 4, 4);
						uint8_t *pp = ch + 8;
						char cnm[33] = { 0 };
						uint32_t cln = 0;
						if (cp > 0 && pp + 36 <= dend) {
							memcpy(cnm, pp, 32);
							memcpy(&cln, pp + 32, 4);
						}
						{
							char val[40] = { 0 };
							if (cln && cln < 36 && pp + 36 + cln <= dend)
								memcpy(val, pp + 36, cln);
							fprintf(stderr,
							        "  child[%d] prop0='%s' val='%s' props=%d ch=%d\n",
							        c, cnm, val, cp, cc);
							if (strcmp(val, "chosen") == 0)
								chosen = ch;
						}
						if (strcmp(cnm, "name") == 0 && cln >= 7 &&
						    memcmp(pp + 36, "chosen", 6) == 0)
							chosen = ch;
						if (strcmp(cnm, "chosen") == 0)
							chosen = ch;
						/* skip node */
						pp += 36;
						uint32_t pad = (cln + 3u) & ~3u;
						pp += pad;
						for (int i = 1; i < cp && pp + 36 <= dend + 0x8000; i++) {
							uint32_t ln = 0;
							memcpy(&ln, pp + 32, 4);
							pp += 36 + ((ln + 3u) & ~3u);
						}
						ch = pp;
					}
					{
						uint8_t *seedp = NULL;
						if (chosen) {
							int cp = 0;
							memcpy(&cp, chosen, 4);
							uint8_t *pp = chosen + 8;
							for (int i = 0; i < cp && pp + 36 <= dend + 0x8000; i++) {
								char nm[33] = { 0 };
								uint32_t ln = 0;
								memcpy(nm, pp, 32);
								memcpy(&ln, pp + 32, 4);
								if (strcmp(nm, "random-seed") == 0)
									seedp = pp;
								pp += 36 + ((ln + 3u) & ~3u);
							}
						}
						if (seedp) {
							uint32_t oldln = 0;
							memcpy(&oldln, seedp + 32, 4);
							uint32_t ln = 64;
							if (oldln < 64) {
								uint32_t dold = (oldln + 3u) & ~3u;
								uint32_t dnew = 64;
								memmove(seedp + 36 + dnew, seedp + 36 + dold,
								        (size_t)(dend - (seedp + 36 + dold)));
								dtl32 += dnew - dold;
								memcpy(p + 1076, &dtl32, 4);
							}
							memcpy(seedp + 32, &ln, 4);
							for (int i = 0; i < 64; i++)
								seedp[36 + i] = (uint8_t)(0x5a ^ i * 17);
							fprintf(stderr, "fast86: patched existing DT random-seed oldlen=%u\n",
							        oldln);
						} else {
						uint8_t *ins = chosen ? chosen + 8 : after_props;
						if (chosen) {
							int cp = 0;
							memcpy(&cp, chosen, 4);
							ins = chosen + 8;
							for (int i = 0; i < cp; i++) {
								uint32_t ln = 0;
								memcpy(&ln, ins + 32, 4);
								ins += 36 + ((ln + 3u) & ~3u);
							}
							cp++;
							memcpy(chosen, &cp, 4);
						} else {
							nprop++;
							memcpy(dt, &nprop, 4);
							ins = after_props;
						}
						uint32_t add = 36 + 64;
						memmove(ins + add, ins, (size_t)(dend - ins));
						memset(ins, 0, add);
						memcpy(ins, "random-seed", 12);
						uint32_t ln = 64;
						memcpy(ins + 32, &ln, 4);
						for (int i = 0; i < 64; i++)
							ins[36 + i] = (uint8_t)(0x5a ^ i * 17);
						dtl32 += add;
						memcpy(p + 1076, &dtl32, 4);
						if (g_dt_slot && g_dt_slot + 24 < f86_ram_size()) {
							uint64_t nln = dtl32;
							uint64_t dt_va = 0xffffff8000000000ull | (uint64_t)dtp32;
							uint64_t en = dt_va + nln;
							memcpy(f86_ram() + g_dt_slot + 8, &nln, 8);
							memcpy(f86_ram() + g_dt_slot + 16, &en, 8);
						}
						fprintf(stderr, "fast86: inserted DT random-seed newlen=%u\n",
						        dtl32);
						}
					}
				}
			}
		}
	}
	if (g_dbg)
		fprintf(stderr, "translate %lx -> %p  first %02x %02x %02x %02x\n",
		        (unsigned long)guest_rip, (void *)block_rx,
		        ((uint8_t *)guest_rip)[0], ((uint8_t *)guest_rip)[1],
		        ((uint8_t *)guest_rip)[2], ((uint8_t *)guest_rip)[3]);

	uint64_t pc = guest_rip;
	for (int n = 0; n < BLK_INSNS; n++) {
		if (g_emit + 2048 >= g_cend)
			break;
		F86Insn d;
		const uint8_t *ip = f86_in_system() ? f86_gva_code(pc, 16)
		                                    : (const uint8_t *)pc;
		if (!ip || !f86_decode(ip, ip + 16, &d) || (d.flags & F86_BAD)) {
			fprintf(stderr, "fast86: decode fail at 0x%lx%s\n",
			        (unsigned long)pc, ip ? "" : " (unmapped)");
			if (ip)
				fprintf(stderr, "  bytes %02x %02x %02x %02x\n",
				        ip[0], ip[1], ip[2], ip[3]);
			g_cpu->exited = 1;
			g_cpu->exit_code = 127;
			emit_exit_to(pc);
			return mapped ? block_rx : rx_of(block_rw);
		}

		if (!mapped) {
			insert(guest_rip, block_rx);
			mapped = 1;
		} else if (!lookup(pc)) {
			insert(pc, rx_of(g_emit));
		}

		cpu->n_insns++;
		uint64_t next = pc + d.len;

		if (f86_in_system() && (d.flags & F86_SYSOP)) {
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, pc);
			emit_c_helper(f86_on_sysop);
			return block_rx;
		}
		if (d.flags & F86_SYSCALL) {
			if (f86_in_system() && f86_sys_bs_exited()) {
				emit_spill_all();
				emit_store_u64(&g_cpu->rip, next);
				emit_c_helper(f86_on_syscall);
				return block_rx;
			}
			emit_syscall_continue(next);
			pc = next;
			continue;
		}
		if (d.flags & F86_PRIV) {
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, pc);
			emit_c_helper(f86_on_priv);
			return block_rx;
		}
		if (sys_alias() && is_fsgsbase(ip, &d)) {
			emit_sys_fsgsbase(ip, &d);
			pc = next;
			continue;
		}
		if (d.flags & F86_WRFS) {
			memcpy(g_emit, ip, d.len);
			g_emit += d.len;
			int wrreg = (d.modrm >> 3) & 7;
			if (wrreg == 3) {
				emit_store_r11_scr();
				em1(0xF3); em1(0x49); em1(0x0F); em1(0xAE); em1(0xCB); /* rdgsbase r11 */
				em1(0x48); em1(0xA3); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
				em1(0x48); em1(0xB8); em8((uint64_t)&g_cpu->gs_base);
				em1(0x4C); em1(0x89); em1(0x18);
				em1(0x48); em1(0xA1); em8((uint64_t)(SCRATCH + SCR_OFF_RAX));
				emit_load_r11_scr();
			} else
				emit_capture_fs_ok();
			pc = next;
			continue;
		}
		if (d.flags & (F86_JCC8 | F86_JCC32 | F86_JMP8 | F86_JMP32 |
		               F86_CALL32 | F86_RET | F86_FF_CALL | F86_FF_JMP | F86_LOOP)) {
			uint64_t tgt = next + (int64_t)d.rel;
			if (d.flags & (F86_JMP8 | F86_JMP32)) {
				emit_jmp_or_stub(tgt);
				return block_rx;
			}
			if (d.flags & (F86_JCC8 | F86_JCC32)) {
				emit_jcc_or_stub(jcc_cc(ip, &d), tgt);
				pc = next;
				continue;
			}
			if (d.flags & F86_LOOP) {
				emit_loop_or_stub(ip, &d, tgt);
				pc = next;
				continue;
			}
			if (d.flags & F86_CALL32) {
				emit_native_call(next, tgt);
				pc = next;
				continue;
			}
			if (d.flags & F86_RET) {
				uint16_t imm = 0;
				if ((d.opcode0 == 0xC2 || d.opcode0 == 0xCA) && d.imm_off)
					imm = (uint16_t)(ip[d.imm_off] | (ip[d.imm_off + 1] << 8));
				emit_ret_simple(imm);
				return block_rx;
			}
			if (d.flags & F86_FF_CALL)
				emit_push_retaddr(next);
			emit_spill_all();
			emit_store_u64(&g_cpu->rip, pc);
			emit_fast_helper(f86_do_indirect);
			return block_rx;
		}

		if (sys_alias()) {
			int r = emit_sys_mem(ip, &d, pc);
			if (r == 2)
				return block_rx;
			if (r == 1) {
				pc = next;
				if ((pc - guest_rip) > 768)
					break;
				continue;
			}
		}
		if (d.flags & F86_RIPREL) {
			uint64_t abs = next + (int64_t)d.disp;
			int fsp = 0;
			if (sys_alias()) {
				/* guest VA through the alias; the old GPA rewrite was a
				   static translation that ignored later remaps */
				int seg = 0;
				scan_prefixes(ip, d.len, &seg);
				fsp = (d.vex_len || !(d.opcode0 == 0x8D ||
				                      (d.opcode0 == 0x0F && d.opcode1 == 0x1F))) && !(seg & 4);
			} else if (d.opcode0 != 0x8D && f86_sys_bs_exited()) {
				uint64_t gpa = 0;
				if (f86_gva_to_gpa(abs, &gpa) && gpa &&
				    !f86_sys_is_mmio(gpa))
					abs = gpa;
			}
			emit_riprel_via_abs(ip, &d, abs, fsp);
		} else {
			memcpy(g_emit, ip, d.len);
			g_emit += d.len;
		}
		pc = next;
		if ((pc - guest_rip) > 768)
			break;
	}
	emit_jmp_or_stub(pc);
	return block_rx;
}

static const int k_greg[16] = {
	REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15
};

static int greg_of_ireg(int r)
{
	return k_greg[r & 15];
}

static uint64_t fault_load(uint64_t gva, uint64_t gpa, int mmio, int sz)
{
	uint64_t v = 0;
	if (mmio)
		return f86_sys_mmio_read(gva, sz);
	if (gpa + (unsigned)sz > f86_ram_size())
		return 0;
	memcpy(&v, f86_ram() + gpa, (size_t)sz);
	return v;
}

static void fault_store(uint64_t gva, uint64_t gpa, int mmio, uint64_t v, int sz)
{
	if (mmio) {
		f86_sys_mmio_write(gva, v, sz);
		return;
	}
	if (gpa + (unsigned)sz > f86_ram_size())
		return;
	{
		/* F86_WATCH_UNSLID=addr: report stores into [addr, addr+0x40) */
		static uint64_t watch; static int winit;
		if (!winit) { winit = 1; const char *e = getenv("F86_WATCH_UNSLID"); watch = e ? strtoull(e, NULL, 0) : 0; }
		if (watch && g_kaddr >= 0x100000ull) {
			uint64_t wg = (watch - 0xffffff8000000000ull) + (g_kaddr - 0x100000ull);
			if (gpa >= wg && gpa < wg + 0x40) {
				static int nw;
				if (nw++ < 40)
					fprintf(stderr, "fast86: WATCH store gpa=%lx gva=%lx sz=%d v=%lx grip=%lx\n",
					        (unsigned long)gpa, (unsigned long)gva, sz, (unsigned long)v,
					        (unsigned long)(g_cpu ? g_cpu->rip : 0));
			}
		}
	}
	if (sz == 8 && v && v < 0x0000000100000000ull &&
	    (gpa == g_dt_slot || gpa == g_dt_slot + 16 || gpa == g_dt_slot2))
		v |= 0xffffff8000000000ull;
	memcpy(f86_ram() + gpa, &v, (size_t)sz);
	(void)gva;
}

/* Emulate a guest load/store that faulted: page 0, MMIO, or a high GVA. */
/* Width-correct EFLAGS (CF PF AF ZF SF OF = 0x8d5) for ALU emulation.
   kind: 0 add, 1 or, 2 adc, 3 sbb, 4 and, 5 sub/cmp, 6 xor, 9 inc, 10 dec,
   11 neg. The old code ran 64-bit sub/add on zero-extended 8/32-bit
   operands, so SF/OF/CF were taken from bit 63: XNU's
   `cmp dword [mh->flags], 0 ; jns` (MH_DYLIB_IN_CACHE = bit 31) went the
   wrong way and the kernel never slid its Mach-O headers. */
static uint64_t x86_alu_flags(int kind, uint64_t a, uint64_t b, uint64_t cin,
                              int sz, uint64_t *res_out)
{
	uint64_t mask = sz == 8 ? ~0ull : (1ull << (sz * 8)) - 1;
	uint64_t sbit = 1ull << (sz * 8 - 1);
	a &= mask;
	b &= mask;
	uint64_t r = 0, cf = 0, of = 0, af = 0;
	switch (kind) {
	case 0: case 2: case 9: {
		uint64_t c = (kind == 2) ? (cin & 1) : 0;
		if (kind == 9) b = 1;
		r = (a + b + c) & mask;
		cf = (r < a) || (c && r == a) ? 1 : 0;
		if (sz == 8) cf = (a + b + c < a) || (c && a + b + c == a) ? 1 : 0;
		else cf = ((a + b + c) >> (sz * 8)) & 1;
		of = ((~(a ^ b) & (a ^ r)) & sbit) ? 1 : 0;
		af = ((a ^ b ^ r) >> 4) & 1;
		break;
	}
	case 3: case 5: case 10: case 11: {
		uint64_t c = (kind == 3) ? (cin & 1) : 0;
		if (kind == 10) b = 1;
		if (kind == 11) { b = a; a = 0; }
		r = (a - b - c) & mask;
		cf = (a < b + c) || (c && b == mask) ? 1 : 0;
		of = (((a ^ b) & (a ^ r)) & sbit) ? 1 : 0;
		af = ((a ^ b ^ r) >> 4) & 1;
		break;
	}
	case 1: r = (a | b) & mask; break;
	case 4: case 8: r = (a & b) & mask; break;
	case 6: r = (a ^ b) & mask; break;
	}
	uint64_t fl = 0;
	if (cf) fl |= 1;
	if (!(__builtin_popcount((unsigned)(r & 0xff)) & 1)) fl |= 4;
	if (af) fl |= 0x10;
	if (r == 0) fl |= 0x40;
	if (r & sbit) fl |= 0x80;
	if (of) fl |= 0x800;
	if (res_out)
		*res_out = r;
	return fl;
}

#define SET_EFL(uc_, fl_, keep_) \
	((uc_)->uc_mcontext.gregs[REG_EFL] = (greg_t)(((uint64_t)(uc_)->uc_mcontext.gregs[REG_EFL] & ~(0x8d5ull & ~(uint64_t)(keep_))) | ((fl_) & 0x8d5ull & ~(uint64_t)(keep_))))

/* Effective address of d's memory operand from the signal context's
   registers. No RIP-relative support: the context RIP is a code-cache
   address, and for those the faulting address already names the operand. */
static int uc_ea(const ucontext_t *uc, const uint8_t *ip, const F86Insn *d,
                 uint64_t *out)
{
	if (!(d->flags & F86_MODRM) || (d->modrm >> 6) == 3 ||
	    (d->flags & F86_RIPREL))
		return 0;
	F86CPU t;
	memset(&t, 0, sizeof t);
	for (int i = 0; i < 16; i++)
		t.r[i] = (uint64_t)uc->uc_mcontext.gregs[k_greg[i]];
	if (g_cpu) {
		t.gs_base = g_cpu->gs_base;
		/* a 0x64 in cache code is the alias prefix, not a guest fs: */
		t.fs_base = f86_in_system() ? 0 : g_cpu->fs_base;
	}
	*out = compute_ea(&t, ip, d);
	return 1;
}

static int emulate_page0(ucontext_t *uc, void *addr)
{
	uintptr_t fa = (uintptr_t)addr;
	if (!f86_in_system() || !f86_ram())
		return 0;
	int mmio = f86_sys_is_mmio(fa);
	uint64_t gpa = 0;
	unsigned long hip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
	unsigned char *ip = (hip < f86_ram_size())
		? (f86_ram() + hip) : (unsigned char *)(uintptr_t)hip;
	if (!ip)
		return 0;
	/* String ops first: they translate per element (rep with rcx=0 touches
	   nothing even when rsi/rdi are wild, e.g. memmove's backward path). */
	int rep = 0, o16 = 0;
	const uint8_t *q = ip;
	for (int n = 0; n < 4; n++, q++) {
		if (*q == 0xF3 || *q == 0xF2)
			rep = 1;
		else if (*q == 0x66)
			o16 = 1;
		else if (*q == 0x67 || *q == 0xF0 ||
		         (*q >= 0x40 && *q <= 0x4f) ||
		         *q == 0x26 || *q == 0x2e || *q == 0x36 || *q == 0x3e ||
		         *q == 0x64 || *q == 0x65)
			;
		else
			break;
	}

	/* String instructions (MOVS/STOS/CMPS/LODS/SCAS) with REP/REPE/REPNE.
	   Operand size comes from any REX.W among the prefixes (not just
	   ip[0]: "f3 48 a5" is rep movsq), 0x66 gives 16-bit, and DF selects
	   the direction (XNU's overlapping bcopy uses std; rep movsb). RSI/RDI/
	   RCX are left exactly where the hardware would leave them when a
	   translation fails part-way. */
	if (*q >= 0xA4 && *q <= 0xAF && *q != 0xA8 && *q != 0xA9) {
		int rexw = 0;
		for (const uint8_t *r = ip; r < q; r++)
			if (*r >= 0x48 && *r <= 0x4f)
				rexw = 1;
		int repne = 0;
		for (const uint8_t *r = ip; r < q; r++)
			if (*r == 0xF2)
				repne = 1;
		int sz = (*q & 1) ? (rexw ? 8 : (o16 ? 2 : 4)) : 1;
		int kind = (*q & 0xFE); /* A4 movs, A6 cmps, AA stos, AC lods, AE scas */
		uint64_t efl = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];
		int df = f86_in_system() ? f86_sys_df() : ((efl & 0x400ull) != 0);
		int64_t step = df ? -(int64_t)sz : (int64_t)sz;
		uint64_t rsi = (uint64_t)uc->uc_mcontext.gregs[REG_RSI];
		uint64_t rdi = (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
		uint64_t rcx = (uint64_t)uc->uc_mcontext.gregs[REG_RCX];
		uint64_t rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
		uint64_t n = rep ? rcx : 1;
		uint64_t mask = sz == 8 ? ~0ull : (1ull << (sz * 8)) - 1;
		if (n > (64ull << 20))
			n = 64ull << 20;
		uint64_t i = 0, nfl = efl;
		int aborted = 0;
		for (; i < n; i++) {
			uint64_t sg = rsi + (uint64_t)((int64_t)i * step);
			uint64_t dg = rdi + (uint64_t)((int64_t)i * step);
			uint64_t sp = sg, dp = dg;
			int sm = 0, dm = 0;
			if (kind == 0xA4 || kind == 0xA6 || kind == 0xAC) {
				sm = f86_sys_is_mmio(sg);
				if (!sm && !f86_gva_to_gpa(sg, &sp)) { aborted = 1; break; }
				if (!sm && f86_sys_is_mmio(sp)) sm = 1;
			}
			if (kind == 0xA4 || kind == 0xA6 || kind == 0xAA || kind == 0xAE) {
				dm = f86_sys_is_mmio(dg);
				if (!dm && !f86_gva_to_gpa(dg, &dp)) { aborted = 1; break; }
				if (!dm && f86_sys_is_mmio(dp)) dm = 1;
			}
			if (kind == 0xA4) {
				fault_store(dg, dp, dm, fault_load(sg, sp, sm, sz), sz);
			} else if (kind == 0xAA) {
				fault_store(dg, dp, dm, rax & mask, sz);
			} else if (kind == 0xAC) {
				uint64_t v = fault_load(sg, sp, sm, sz) & mask;
				rax = (sz == 8) ? v : (sz == 4) ? v : ((rax & ~mask) | v);
			} else if (kind == 0xA6 || kind == 0xAE) {
				uint64_t x = (kind == 0xA6) ? fault_load(sg, sp, sm, sz) : (rax & mask);
				uint64_t y = fault_load(dg, dp, dm, sz);
				nfl = (efl & ~0x8d5ull) | x86_alu_flags(5, x, y, 0, sz, NULL);
				if (rep) {
					int zf = (nfl & 0x40) != 0;
					if (repne ? zf : !zf) { i++; break; }
				}
			}
			if (!rep)
				{ i++; break; }
		}
		if (kind != 0xAA && kind != 0xAE)
			uc->uc_mcontext.gregs[REG_RSI] = (greg_t)(rsi + (uint64_t)((int64_t)i * step));
		if (kind != 0xAC)
			uc->uc_mcontext.gregs[REG_RDI] = (greg_t)(rdi + (uint64_t)((int64_t)i * step));
		if (rep)
			uc->uc_mcontext.gregs[REG_RCX] = (greg_t)(rcx - i);
		uc->uc_mcontext.gregs[REG_RAX] = (greg_t)rax;
		uc->uc_mcontext.gregs[REG_EFL] = (greg_t)nfl;
		{
			static int nst;
			if (kind == 0xAA && n >= 0x100 && nst < 30) {
				fprintf(stderr, "fast86: STOS rdi=%lx n=%lu done=%lu sz=%d rep=%d aborted=%d rip=%lx\n",
				        (unsigned long)rdi, (unsigned long)n, (unsigned long)i, sz, rep, aborted,
				        (unsigned long)(uintptr_t)hip);
				nst++;
			}
		}
		if (aborted) {
			/* The element at i could not be translated: registers are
			   left as the hardware would (i elements done) and the
			   caller injects #PF at the failing address. */
			static int nab;
			if (nab++ < 20)
				fprintf(stderr, "fast86: string op %02x aborted after %lu of %lu (rsi=%lx rdi=%lx)\n",
				        *q, (unsigned long)i, (unsigned long)n,
				        (unsigned long)rsi, (unsigned long)rdi);
			int st = (kind == 0xA4 || kind == 0xAA);
			uint64_t fe = (kind == 0xA4 || kind == 0xA6 || kind == 0xAC)
			              ? rsi + (uint64_t)((int64_t)i * step) : rdi + (uint64_t)((int64_t)i * step);
			if (kind == 0xA4) {
				uint64_t sp2 = 0;
				if (f86_gva_to_gpa(rsi + (uint64_t)((int64_t)i * step), &sp2))
					fe = rdi + (uint64_t)((int64_t)i * step);
				else
					st = 0;
			}
			g_strop_fault_gva = fe;
			g_strop_fault_err = st ? 2u : 0u;
			g_strop_fault_set = 1;
			return 0;
		}
		if (rep && (rcx - i) != 0) {
			/* iteration cap hit: re-execute for the remainder */
			return 1;
		}
		F86Insn d;
		if (f86_decode(ip, ip + 16, &d) && d.len)
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
		else
			uc->uc_mcontext.gregs[REG_RIP] += (long)(q - ip) + 1;
		return 1;
	}

	if ((fa & ~0xfffull) == 0xffffdeadbeefee00ull)
		fa = 0x104000ull + (fa & 0xfff);
	if (fa < 0x1000)
		gpa = fa;
	else if (mmio)
		gpa = fa;
	else if (!f86_gva_to_gpa((uint64_t)fa, &gpa)) {
		if (!f86_sys_bs_exited())
			return 0;
		/* Not present: emulate as page 0 (loads 0, stores ignored). This
		   hides guest #PFs; trace the first ones so VM bugs are visible. */
		{
			static int nnp;
			if (nnp < 24) {
				uint64_t grip = (g_rx && hip >= (unsigned long)g_rx &&
				                 hip < (unsigned long)g_rx + CACHE_SZ)
				                ? host_to_guest((uint8_t *)(uintptr_t)hip) : 0;
				uint64_t slide = g_kaddr >= 0x100000ull ? g_kaddr - 0x100000ull : 0;
				fprintf(stderr, "fast86: not-present gva=%lx grip=%lx (unslid %lx) cr3=%lx\n",
				        (unsigned long)fa, (unsigned long)grip,
				        (unsigned long)(grip ? grip - slide : 0),
				        (unsigned long)(g_cpu ? g_cpu->cr3 : 0));
				nnp++;
			}
		}
		return 0; /* unhandled here: xlat_fault injects #PF */
	} else if (f86_sys_is_mmio(gpa)) {
		mmio = 1;
		fa = (uintptr_t)gpa;
	} else if (gpa >= f86_ram_size())
		return 0;

	F86Insn d;
	if (!f86_decode(ip, ip + 16, &d) || !d.len)
		return 0;
	int op = d.opcode0, op2 = d.opcode1;
	int reg = (d.modrm >> 3) & 7;
	if (d.rex & 4)
		reg |= 8;
	int sz = 4;
	{
		/* F86_TRACE_FAULTS=lo,hi (unslid guest RIP): log every emulated access */
		static uint64_t flo, fhi; static int finit;
		if (!finit) {
			finit = 1;
			const char *e = getenv("F86_TRACE_FAULTS");
			if (e) { char *end = NULL; flo = strtoull(e, &end, 0); if (end && *end == ',') fhi = strtoull(end + 1, NULL, 0); }
		}
		if (fhi && g_kaddr >= 0x100000ull) {
			uint64_t grip = (g_rx && hip >= (unsigned long)g_rx && hip < (unsigned long)g_rx + CACHE_SZ)
			                ? host_to_guest((uint8_t *)(uintptr_t)hip) : 0;
			uint64_t un = grip ? grip - (g_kaddr - 0x100000ull) : 0;
			if (un >= flo && un < fhi) {
				static int nf;
				if (nf++ < 200) {
					fprintf(stderr, "fast86: FAULTOP grip=%lx op=%02x%02x modrm=%02x rex=%02x fa=%lx gpa=%lx hip=%lx rsp=%lx host:",
					        (unsigned long)un, op, op2, d.modrm, d.rex, (unsigned long)fa,
					        (unsigned long)gpa, hip, (unsigned long)uc->uc_mcontext.gregs[REG_RSP]);
					for (int k = -16; k < 16; k++)
						fprintf(stderr, "%s%02x", k == 0 ? " |" : " ", ((const uint8_t *)(uintptr_t)hip)[k]);
					const uint8_t *gb = grip ? f86_gva_code(grip, 16) : NULL;
					if (gb) {
						fprintf(stderr, "  guest:");
						for (int k = 0; k < 16; k++)
							fprintf(stderr, " %02x", gb[k]);
					}
					fprintf(stderr, "\n");
				}
			}
		}
	}
	if (op < 0x40 && (op & 7) < 4 && (d.flags & F86_MODRM)) {
		/* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m,r and r,r/m in every width.
		   (The old code covered only a few of these; "add r8,[mem]" and
		   "xor r8,[mem]" were silently skipped, which broke XNU's packed
		   pointer walks and constant-time compares.) */
		int kind = op >> 3;            /* 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp */
		int asz = (op & 1) ? ((d.rex & 8) ? 8 : (o16 ? 2 : 4)) : 1;
		int to_reg = (op & 2) != 0;
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		if (asz == 1 && !d.rex && reg >= 4 && reg < 8) {
			/* AH/CH/DH/BH without REX */
			rv = ((uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg - 4)] >> 8) & 0xff;
		}
		uint64_t a = to_reg ? rv : mem, b = to_reg ? mem : rv, res = 0;
		uint64_t cf_in = (uint64_t)uc->uc_mcontext.gregs[REG_EFL] & 1ull;
		uint64_t nfl = x86_alu_flags(kind == 7 ? 5 : kind, a, b, cf_in, asz, &res);
		uint64_t mask = asz == 8 ? ~0ull : (1ull << (asz * 8)) - 1;
		if (kind != 7) {
			if (to_reg) {
				if (asz == 1 && !d.rex && reg >= 4 && reg < 8) {
					int lr = greg_of_ireg(reg - 4);
					uc->uc_mcontext.gregs[lr] = (greg_t)(((uint64_t)uc->uc_mcontext.gregs[lr] & ~0xff00ull) | ((res & 0xff) << 8));
				} else if (asz == 8 || asz == 4)
					uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(res & mask);
				else
					uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
					    (greg_t)(((uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)] & ~mask) | (res & mask));
			} else
				fault_store(fa, gpa, mmio, res, asz);
		}
		SET_EFL(uc, nfl, 0);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x8A || op == 0x88 || op == 0xC6 ||
	    (op == 0x0F && (op2 == 0xB6 || op2 == 0xBE)) ||
	    op == 0xAA)
		sz = 1;
	else if (op == 0x0F && (op2 == 0xB7 || op2 == 0xBF))
		sz = 2;
	else if ((d.rex & 8) || op == 0xFF || op == 0x8F)
		sz = 8;
	int load = (op == 0x8A || op == 0x8B ||
	            (op == 0x0F && (op2 == 0xB6 || op2 == 0xB7 ||
	                            op2 == 0xBE || op2 == 0xBF)));
	int store = (op == 0x88 || op == 0x89);
	/* ALU r, r/m  — load mem, op into reg */
	{
		int alu = 0, do_store_reg = 1;
		uint64_t (*opfn)(uint64_t, uint64_t) = NULL;
		if (op == 0x03) alu = 1; /* add */
		else if (op == 0x0B) alu = 1;
		else if (op == 0x23) alu = 1;
		else if (op == 0x2B) alu = 1;
		else if (op == 0x33) alu = 1;
		else if (op == 0x3B || op == 0x3A || op == 0x39 || op == 0x38)
			alu = 2; /* cmp: flags only */
		else if (op == 0x85 || op == 0x84)
			alu = 3; /* test */
		else if (op == 0x0A) { /* or r8, r/m8 */
			uint64_t mem = fault_load(fa, gpa, mmio, 1);
			uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
			    (greg_t)((rv & ~0xffull) | ((rv | mem) & 0xff));
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return 1;
		}
		else if (op == 0x63) { /* movsxd */
			uint64_t v = fault_load(fa, gpa, mmio, 4);
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(int32_t)v;
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return 1;
		}
		if (alu) {
			int asz = (op == 0x3A || op == 0x38 || op == 0x84) ? 1
			          : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
			uint64_t mem = fault_load(fa, gpa, mmio, asz);
			uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
			if (asz == 1) {
				rv &= 0xff;
				mem &= 0xff;
			} else if (asz == 4) {
				rv &= 0xffffffffull;
				mem &= 0xffffffffull;
			}
			uint64_t out = rv, fl = 0;
			uint64_t nfl = 0;
			if (op == 0x03)
				nfl = x86_alu_flags(0, rv, mem, 0, asz, &out);
			else if (op == 0x2B || op == 0x3B || op == 0x3A)
				nfl = x86_alu_flags(5, rv, mem, 0, asz, &out);
			else if (op == 0x39 || op == 0x38) /* cmp r/m, r: mem - reg */
				nfl = x86_alu_flags(5, mem, rv, 0, asz, &out);
			else if (op == 0x23 || op == 0x85 || op == 0x84)
				nfl = x86_alu_flags(4, rv, mem, 0, asz, &out);
			else if (op == 0x0B)
				nfl = x86_alu_flags(1, rv, mem, 0, asz, &out);
			else if (op == 0x33)
				nfl = x86_alu_flags(6, rv, mem, 0, asz, &out);
			if (alu == 1) {
				if (asz == 1) {
					uint64_t old = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
					uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
					    (greg_t)((old & ~0xffull) | (out & 0xff));
				} else if (asz == 4)
					uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(uint32_t)out;
				else
					uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)out;
			}
			uc->uc_mcontext.gregs[REG_EFL] =
			    (greg_t)(((uint64_t)uc->uc_mcontext.gregs[REG_EFL] & ~0x8d5ull) |
			             (nfl & 0x8d5ull));
			(void)opfn;
			(void)do_store_reg;
			(void)fl;
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return 1;
		}
	}
	int hreg = (sz == 1 && !d.rex && reg >= 4 && reg < 8 &&
	            (op == 0x88 || op == 0x8A || op == 0x84 || op == 0x86)); /* AH/CH/DH/BH */
	if (load && hreg) {
		uint64_t v = fault_load(fa, gpa, mmio, 1);
		int lr = greg_of_ireg(reg - 4);
		uc->uc_mcontext.gregs[lr] = (greg_t)(((uint64_t)uc->uc_mcontext.gregs[lr] & ~0xff00ull) | ((v & 0xff) << 8));
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (store && hreg) {
		uint64_t v = ((uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg - 4)] >> 8) & 0xff;
		fault_store(fa, gpa, mmio, v, 1);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (load) {
		/* Memory width: mov r/m8 -> 1, mov r/m16/32/64 by prefix, movzx/
		   movsx fixed by opcode. Destination width: REX.W -> 64, 0x66 ->
		   16 (merge), else 32 (zero upper half); mov r8 merges the byte. */
		int msz = sz;
		if (op == 0x8B)
			msz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		uint64_t v = fault_load(fa, gpa, mmio, msz);
		int dsz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		int lr = greg_of_ireg(reg);
		uint64_t old = (uint64_t)uc->uc_mcontext.gregs[lr];
		if (op == 0x8A) {
			uc->uc_mcontext.gregs[lr] = (greg_t)((old & ~0xffull) | (v & 0xff));
		} else {
			if (op == 0x0F && (op2 == 0xBE || op2 == 0xBF))
				v = (msz == 1) ? (uint64_t)(int64_t)(int8_t)v : (uint64_t)(int64_t)(int16_t)v;
			if (dsz == 8)
				uc->uc_mcontext.gregs[lr] = (greg_t)v;
			else if (dsz == 4)
				uc->uc_mcontext.gregs[lr] = (greg_t)(uint32_t)v;
			else
				uc->uc_mcontext.gregs[lr] = (greg_t)((old & ~0xffffull) | (v & 0xffff));
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (store) {
		uint64_t v = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		int msz = (op == 0x88) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		fault_store(fa, gpa, mmio, v, msz);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0xC6 || op == 0xC7) {
		int isz = (op == 0xC6) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		if (isz == 8)
			isz = 4; /* C7 imm32 sign-extended */
		uint64_t imm = 0;
		if (d.imm_off)
			memcpy(&imm, ip + d.imm_off, (size_t)((op == 0xC6) ? 1 : 4));
		if (op == 0xC7 && (d.rex & 8))
			imm = (uint64_t)(int32_t)imm;
		fault_store(fa, gpa, mmio, imm, (op == 0xC6) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4)));
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x80 || op == 0x81 || op == 0x83) {
		int msz = (op == 0x80) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t cur = fault_load(fa, gpa, mmio, msz);
		uint64_t imm = 0;
		if (d.imm_off) {
			int il = (op == 0x80) ? 1 : (op == 0x83) ? 1 : (msz == 2 ? 2 : 4);
			memcpy(&imm, ip + d.imm_off, (size_t)il);
			if (il == 1)
				imm = (uint64_t)(int8_t)imm;
			else if (il == 4 && msz == 8)
				imm = (uint64_t)(int32_t)imm;
		}
		if (msz == 1) {
			cur &= 0xff;
			imm &= 0xff;
		} else if (msz == 4) {
			cur &= 0xffffffffull;
			imm &= 0xffffffffull;
		}
		int which = (d.modrm >> 3) & 7;
		uint64_t r = cur, nfl = 0;
		uint64_t cf_in = (uint64_t)uc->uc_mcontext.gregs[REG_EFL] & 1ull;
		static const int kinds[8] = { 0, 1, 2, 3, 4, 5, 6, 5 };
		nfl = x86_alu_flags(kinds[which], cur, imm, cf_in, msz, &r);
		if (which != 7)
			fault_store(fa, gpa, mmio, r, msz);
		uc->uc_mcontext.gregs[REG_EFL] =
		    (greg_t)(((uint64_t)uc->uc_mcontext.gregs[REG_EFL] & ~0x8d5ull) |
		             (nfl & 0x8d5ull));
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0xFF && ((d.modrm >> 3) & 7) == 6) {
		/* push r/m */
		uint64_t v = fault_load(fa, gpa, mmio, 8);
		uint64_t rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP] - 8;
		uint64_t spg = 0;
		if (f86_gva_to_gpa(rsp, &spg) && spg + 8 <= f86_ram_size())
			memcpy(f86_ram() + spg, &v, 8);
		uc->uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x8F || (op >= 0x58 && op <= 0x5F)) {
		/* POP always reads [RSP]. RSP is incremented before the destination
		   is written, so POP RSP ends with RSP = the popped value (writing
		   src+8 afterwards turned it into ADD RSP,8 and shifted every
		   callee-saved pop in XNU's running_timer_setup epilogue), and
		   POP [RSP+d] addresses the incremented stack. */
		uint64_t rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
		uint64_t gp = 0, v = 0;
		int mm = f86_sys_is_mmio(rsp);
		if (!mm && !f86_gva_to_gpa(rsp, &gp))
			return 0;
		v = fault_load(rsp, gp, mm, 8);
		uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp + 8);
		if (op >= 0x58 && op <= 0x5F) {
			int r = (op - 0x58) | ((d.rex & 1) ? 8 : 0);
			uc->uc_mcontext.gregs[greg_of_ireg(r)] = (greg_t)v;
		} else {
			uint64_t dest = fa, dg = gpa;
			int dmm = mmio;
			if (fa == rsp) {
				/* the fault was the stack read: locate the destination */
				if (!uc_ea(uc, ip, &d, &dest)) {
					uc->uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
					return 0;
				}
				dmm = f86_sys_is_mmio(dest);
				if (!dmm && !f86_gva_to_gpa(dest, &dg)) {
					uc->uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
					return 0;
				}
				if (!dmm && f86_sys_is_mmio(dg)) {
					dmm = 1;
					dest = dg;
				}
			}
			fault_store(dest, dg, dmm, v, 8);
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x9C || op == 0x9D) {
		uint64_t rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
		if (op == 0x9C) {
			uint64_t dest = rsp - 8;
			uint64_t gp = 0;
			int mm = f86_sys_is_mmio(dest);
			if (!mm && !f86_gva_to_gpa(dest, &gp))
				return 0;
			fault_store(dest, gp, mm, (uint64_t)uc->uc_mcontext.gregs[REG_EFL], 8);
			uc->uc_mcontext.gregs[REG_RSP] = (greg_t)dest;
		} else {
			uint64_t gp = 0, v = 0;
			int mm = f86_sys_is_mmio(rsp);
			if (!mm && !f86_gva_to_gpa(rsp, &gp))
				return 0;
			v = fault_load(rsp, gp, mm, 8);
			uc->uc_mcontext.gregs[REG_EFL] = (greg_t)v;
			uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp + 8);
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if ((op >= 0x50 && op <= 0x57) || op == 0x68 || op == 0x6A ||
	    (op == 0xFF && ((d.modrm >> 3) & 7) == 6)) {
		uint64_t val = 0;
		if (op >= 0x50 && op <= 0x57) {
			int r = (op - 0x50) | ((d.rex & 1) ? 8 : 0);
			val = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(r)];
		} else if (op == 0x6A)
			val = (uint64_t)(int8_t)ip[d.len - 1];
		else if (op == 0x68) {
			uint32_t imm = 0;
			int io = d.imm_off ? d.imm_off : (int)d.len - 4;
			memcpy(&imm, ip + io, 4);
			val = (uint64_t)(int32_t)imm;
		} else
			val = fault_load(fa, gpa, mmio, 8);
		uint64_t rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
		uint64_t dest = fa;
		if (rsp == fa + 8) {
			rsp -= 8;
			dest = rsp;
			uc->uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
		} else if (rsp != fa) {
			rsp -= 8;
			dest = rsp;
			uc->uc_mcontext.gregs[REG_RSP] = (greg_t)rsp;
		}
		uint64_t gp = 0;
		int mm = f86_sys_is_mmio(dest);
		if (!mm && !f86_gva_to_gpa(dest, &gp))
			return 0;
		fault_store(dest, gp, mm, val, 8);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x01 || op == 0x09 || op == 0x21 || op == 0x29 || op == 0x31) {
		int asz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		uint64_t out = mem, nfl;
		int kind = op == 0x01 ? 0 : op == 0x09 ? 1 : op == 0x21 ? 4 : op == 0x29 ? 5 : 6;
		nfl = x86_alu_flags(kind, mem, rv, 0, asz, &out);
		fault_store(fa, gpa, mmio, out, asz);
		SET_EFL(uc, nfl, 0);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && op2 >= 0x90 && op2 <= 0x9F) {
		/* SETcc r/m8 */
		uint64_t fl = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];
		int cf = !!(fl & 1), zf = !!(fl & 0x40), sf = !!(fl & 0x80);
		int of = !!(fl & 0x800), pf = !!(fl & 0x4);
		int v = 0, cc = op2 & 0x0f;
		switch (cc) {
		case 0: v = of; break;
		case 1: v = !of; break;
		case 2: v = cf; break;
		case 3: v = !cf; break;
		case 4: v = zf; break;
		case 5: v = !zf; break;
		case 6: v = cf | zf; break;
		case 7: v = !(cf | zf); break;
		case 8: v = sf; break;
		case 9: v = !sf; break;
		case 10: v = pf; break;
		case 11: v = !pf; break;
		case 12: v = sf ^ of; break;
		case 13: v = !(sf ^ of); break;
		case 14: v = (sf ^ of) | zf; break;
		case 15: v = !((sf ^ of) | zf); break;
		}
		fault_store(fa, gpa, mmio, (uint64_t)v, 1);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && (op2 == 0xB0 || op2 == 0xB1)) {
		/* cmpxchg r/m, r */
		int asz = (op2 == 0xB0) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t acc = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		uint64_t mask = asz == 8 ? ~0ull : asz == 4 ? 0xffffffffull : 0xffull;
		if ((acc & mask) == (mem & mask)) {
			fault_store(fa, gpa, mmio, rv, asz);
			uc->uc_mcontext.gregs[REG_EFL] |= 0x40; /* ZF */
		} else {
			if (asz == 8)
				uc->uc_mcontext.gregs[REG_RAX] = (greg_t)mem;
			else if (asz == 4)
				uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint32_t)mem;
			else
				uc->uc_mcontext.gregs[REG_RAX] =
				    (greg_t)((acc & ~0xffull) | (mem & 0xff));
			uc->uc_mcontext.gregs[REG_EFL] &= ~0x40ull;
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && (op2 == 0xC0 || op2 == 0xC1)) {
		/* xadd r/m, r */
		int asz = (op2 == 0xC0) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		fault_store(fa, gpa, mmio, mem + rv, asz);
		if (asz == 8)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)mem;
		else if (asz == 4)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(uint32_t)mem;
		else {
			uint64_t old = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
			    (greg_t)((old & ~0xffull) | (mem & 0xff));
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x86 || op == 0x87) {
		int asz = (op == 0x86) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		fault_store(fa, gpa, mmio, rv, asz);
		if (asz == 8)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)mem;
		else if (asz == 4)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(uint32_t)mem;
		else {
			uint64_t old = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
			    (greg_t)((old & ~0xffull) | (mem & 0xff));
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB ||
	                   op2 == 0xBA)) {
		int asz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t bit;
		if (op2 == 0xBA) {
			uint8_t imm = d.imm_off ? ip[d.imm_off] : 0;
			bit = imm & (asz * 8 - 1);
			int which = (d.modrm >> 3) & 7;
			int old = (int)((mem >> bit) & 1);
			uc->uc_mcontext.gregs[REG_EFL] =
			    (greg_t)(((uint64_t)uc->uc_mcontext.gregs[REG_EFL] & ~1ull) | (unsigned)old);
			if (which == 5)
				mem |= 1ull << bit;
			else if (which == 6)
				mem &= ~(1ull << bit);
			else if (which == 7)
				mem ^= 1ull << bit;
			if (which >= 5)
				fault_store(fa, gpa, mmio, mem, asz);
		} else {
			uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
			bit = rv & (uint64_t)(asz * 8 - 1);
			int old = (int)((mem >> bit) & 1);
			uc->uc_mcontext.gregs[REG_EFL] =
			    (greg_t)(((uint64_t)uc->uc_mcontext.gregs[REG_EFL] & ~1ull) | (unsigned)old);
			if (op2 == 0xAB)
				mem |= 1ull << bit;
			else if (op2 == 0xB3)
				mem &= ~(1ull << bit);
			else if (op2 == 0xBB)
				mem ^= 1ull << bit;
			if (op2 != 0xA3)
				fault_store(fa, gpa, mmio, mem, asz);
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && op2 >= 0x40 && op2 <= 0x4F) {
		uint64_t fl = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];
		int cf = !!(fl & 1), zf = !!(fl & 0x40), sf = !!(fl & 0x80);
		int of = !!(fl & 0x800), pf = !!(fl & 0x4);
		int v = 0, cc = op2 & 0x0f;
		switch (cc) {
		case 0: v = of; break;
		case 1: v = !of; break;
		case 2: v = cf; break;
		case 3: v = !cf; break;
		case 4: v = zf; break;
		case 5: v = !zf; break;
		case 6: v = cf | zf; break;
		case 7: v = !(cf | zf); break;
		case 8: v = sf; break;
		case 9: v = !sf; break;
		case 10: v = pf; break;
		case 11: v = !pf; break;
		case 12: v = sf ^ of; break;
		case 13: v = !(sf ^ of); break;
		case 14: v = (sf ^ of) | zf; break;
		case 15: v = !((sf ^ of) | zf); break;
		}
		if (v) {
			int asz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
			uint64_t mem = fault_load(fa, gpa, mmio, asz);
			if (asz == 4)
				uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(uint32_t)mem;
			else
				uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)mem;
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && (op2 == 0x6F || op2 == 0x7F || op2 == 0x10 || op2 == 0x11 ||
	                   op2 == 0x28 || op2 == 0x29 || op2 == 0x6E || op2 == 0x7E ||
	                   op2 == 0xD6 || op2 == 0x2B || op2 == 0xE7)) {
		int xmm = (d.modrm >> 3) & 7;
		if (d.rex & 4)
			xmm |= 8;
		int store = (op2 == 0x7F || op2 == 0x11 || op2 == 0x29 || op2 == 0x7E ||
		             op2 == 0xD6 || op2 == 0x2B || op2 == 0xE7);
		int szm = (op2 == 0x6E || op2 == 0x7E || op2 == 0xD6) ? ((d.rex & 8) ? 8 : (o16 ? 2 : 4)) : 16;
		uint8_t *xs;
		if (uc->uc_mcontext.fpregs)
			xs = (uint8_t *)&uc->uc_mcontext.fpregs->_xmm[xmm];
		else
			xs = (uint8_t *)(uintptr_t)(SCRATCH + SCR_OFF_FX + 160 + xmm * 16);
		if (store) {
			if (szm == 16) {
				for (int i = 0; i < 16; i++)
					fault_store(fa + (unsigned)i, gpa + (unsigned)i, mmio, xs[i], 1);
			} else {
				uint64_t v = 0;
				memcpy(&v, xs, (size_t)szm);
				fault_store(fa, gpa, mmio, v, szm);
			}
		} else {
			if (szm == 16) {
				for (int i = 0; i < 16; i++)
					xs[i] = (uint8_t)fault_load(fa + (unsigned)i, gpa + (unsigned)i, mmio, 1);
			} else {
				uint64_t v = fault_load(fa, gpa, mmio, szm);
				memset(xs, 0, 16);
				memcpy(xs, &v, (size_t)szm);
			}
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && op2 == 0xAE) {
		int which = (d.modrm >> 3) & 7;
		if (which == 2 || which == 3) {
			if (which == 3)
				fault_store(fa, gpa, mmio, 0x1f80, 4);
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return 1;
		}
		if (which == 0 || which == 1 || which == 4 || which == 5 || which == 6) {
			/* fxsave/fxrstor/xsave/xrstor: zero the area */
			if (which == 0 || which == 4 || which == 6) {
				for (int i = 0; i < 512; i += 8)
					fault_store(fa + (unsigned)i, gpa + (unsigned)i, mmio, 0, 8);
			}
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return 1;
		}
	}
	if (op == 0x69 || op == 0x6B) {
		int asz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t imm = 0;
		if (d.imm_off) {
			if (op == 0x6B)
				imm = (uint64_t)(int8_t)ip[d.imm_off];
			else {
				uint32_t i32 = 0;
				memcpy(&i32, ip + d.imm_off, 4);
				imm = (uint64_t)(int32_t)i32;
			}
		}
		uint64_t outv = (uint64_t)((int64_t)mem * (int64_t)imm);
		if (asz == 4)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)(uint32_t)outv;
		else
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)outv;
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && op2 == 0xAF) {
		int asz = (d.rex & 8) ? 8 : (o16 ? 2 : 4);
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)];
		if (asz == 8)
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] = (greg_t)((int64_t)rv * (int64_t)mem);
		else
			uc->uc_mcontext.gregs[greg_of_ireg(reg)] =
			    (greg_t)(uint32_t)((int32_t)rv * (int32_t)mem);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x0F && op2 == 0xC7 && ((d.modrm >> 3) & 7) == 1) {
		uint64_t lo = fault_load(fa, gpa, mmio, 8);
		uint64_t hi = fault_load(fa + 8, gpa + 8, mmio, 8);
		uint64_t rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
		uint64_t rdx = (uint64_t)uc->uc_mcontext.gregs[REG_RDX];
		if (rax == lo && rdx == hi) {
			fault_store(fa, gpa, mmio, (uint64_t)uc->uc_mcontext.gregs[REG_RBX], 8);
			fault_store(fa + 8, gpa + 8, mmio, (uint64_t)uc->uc_mcontext.gregs[REG_RCX], 8);
			uc->uc_mcontext.gregs[REG_EFL] |= 0x40;
		} else {
			uc->uc_mcontext.gregs[REG_RAX] = (greg_t)lo;
			uc->uc_mcontext.gregs[REG_RDX] = (greg_t)hi;
			uc->uc_mcontext.gregs[REG_EFL] &= ~0x40ull;
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0xF6 || op == 0xF7) {
		int which = (d.modrm >> 3) & 7;
		int asz = (op == 0xF6) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		if (which == 0) {
			uint64_t imm = 0;
			if (d.imm_off)
				memcpy(&imm, ip + d.imm_off, (size_t)asz > 4 ? 4 : (size_t)asz);
			if (asz == 8)
				imm = (uint64_t)(int32_t)imm;
			uint64_t nfl = x86_alu_flags(4, mem, imm, 0, asz, NULL);
			SET_EFL(uc, nfl, 0);
		} else if (which == 2)
			fault_store(fa, gpa, mmio, ~mem, asz);
		else if (which == 3) {
			uint64_t r = 0, nfl = x86_alu_flags(11, mem, 0, 0, asz, &r);
			fault_store(fa, gpa, mmio, r, asz);
			SET_EFL(uc, nfl, 0);
		} else if (which >= 4) {
			/* MUL/IMUL/DIV/IDIV r/m: these were silently skipped, which
			   left XNU's vm_compressor range size = size * ratio with
			   the division never applied. */
			uint64_t mask = asz == 8 ? ~0ull : (1ull << (asz * 8)) - 1;
			uint64_t rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];
			uint64_t rdx = (uint64_t)uc->uc_mcontext.gregs[REG_RDX];
			uint64_t m = mem & mask;
			if (which == 4 || which == 5) {
				unsigned __int128 prod;
				if (which == 4)
					prod = (unsigned __int128)(rax & mask) * m;
				else {
					int64_t sa = asz == 8 ? (int64_t)rax : asz == 4 ? (int64_t)(int32_t)rax :
					             asz == 2 ? (int64_t)(int16_t)rax : (int64_t)(int8_t)rax;
					int64_t sm = asz == 8 ? (int64_t)m : asz == 4 ? (int64_t)(int32_t)m :
					             asz == 2 ? (int64_t)(int16_t)m : (int64_t)(int8_t)m;
					prod = (unsigned __int128)((__int128)sa * sm);
				}
				uint64_t lo = (uint64_t)prod, hi = (uint64_t)(prod >> 64);
				if (asz == 8) {
					uc->uc_mcontext.gregs[REG_RAX] = (greg_t)lo;
					uc->uc_mcontext.gregs[REG_RDX] = (greg_t)hi;
				} else if (asz == 4) {
					uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint32_t)lo;
					uc->uc_mcontext.gregs[REG_RDX] = (greg_t)(uint32_t)(lo >> 32);
				} else if (asz == 2) {
					uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | (lo & 0xffff));
					uc->uc_mcontext.gregs[REG_RDX] = (greg_t)((rdx & ~0xffffull) | ((lo >> 16) & 0xffff));
				} else
					uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | (lo & 0xffff));
				/* CF=OF=1 when the upper half is significant */
				int ovf = (asz == 8) ? (hi != 0) : (asz == 4) ? ((lo >> 32) != 0) :
				          (asz == 2) ? ((lo >> 16) != 0) : ((lo >> 8) != 0);
				if (which == 5)
					ovf = (asz == 8) ? ((int64_t)hi != ((int64_t)lo >> 63)) :
					      (asz == 4) ? ((int64_t)(int32_t)lo != (int64_t)lo) :
					      (asz == 2) ? ((int64_t)(int16_t)lo != (int64_t)(int32_t)lo) :
					                   ((int64_t)(int8_t)lo != (int64_t)(int16_t)lo);
				uc->uc_mcontext.gregs[REG_EFL] = (greg_t)(((uint64_t)uc->uc_mcontext.gregs[REG_EFL] & ~0x801ull) | (ovf ? 0x801ull : 0));
			} else if (m == 0) {
				fprintf(stderr, "fast86: div by zero at hip=%lx (skipped)\n", hip);
			} else if (which == 6) {
				unsigned __int128 num;
				if (asz == 8) num = ((unsigned __int128)rdx << 64) | rax;
				else if (asz == 4) num = ((unsigned __int128)(rdx & 0xffffffffull) << 32) | (rax & 0xffffffffull);
				else if (asz == 2) num = ((unsigned __int128)(rdx & 0xffff) << 16) | (rax & 0xffff);
				else num = rax & 0xffff;
				uint64_t q = (uint64_t)(num / m), r = (uint64_t)(num % m);
				if (asz == 8) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)q; uc->uc_mcontext.gregs[REG_RDX] = (greg_t)r; }
				else if (asz == 4) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint32_t)q; uc->uc_mcontext.gregs[REG_RDX] = (greg_t)(uint32_t)r; }
				else if (asz == 2) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | (q & 0xffff)); uc->uc_mcontext.gregs[REG_RDX] = (greg_t)((rdx & ~0xffffull) | (r & 0xffff)); }
				else uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | (q & 0xff) | ((r & 0xff) << 8));
			} else {
				__int128 num;
				if (asz == 8) num = (__int128)(((unsigned __int128)rdx << 64) | rax);
				else if (asz == 4) num = (__int128)(int64_t)(((rdx & 0xffffffffull) << 32) | (rax & 0xffffffffull));
				else if (asz == 2) num = (__int128)(int32_t)(((rdx & 0xffff) << 16) | (rax & 0xffff));
				else num = (__int128)(int16_t)(rax & 0xffff);
				int64_t sm = asz == 8 ? (int64_t)m : asz == 4 ? (int64_t)(int32_t)m :
				             asz == 2 ? (int64_t)(int16_t)m : (int64_t)(int8_t)m;
				__int128 q = num / sm, r = num % sm;
				if (asz == 8) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint64_t)q; uc->uc_mcontext.gregs[REG_RDX] = (greg_t)(uint64_t)r; }
				else if (asz == 4) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint32_t)(uint64_t)q; uc->uc_mcontext.gregs[REG_RDX] = (greg_t)(uint32_t)(uint64_t)r; }
				else if (asz == 2) { uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | ((uint64_t)q & 0xffff)); uc->uc_mcontext.gregs[REG_RDX] = (greg_t)((rdx & ~0xffffull) | ((uint64_t)r & 0xffff)); }
				else uc->uc_mcontext.gregs[REG_RAX] = (greg_t)((rax & ~0xffffull) | ((uint64_t)q & 0xff) | (((uint64_t)r & 0xff) << 8));
			}
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 ||
	    op == 0xD2 || op == 0xD3) {
		int asz = ((op & 1) == 0) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		unsigned cnt;
		if (op == 0xD2 || op == 0xD3)
			cnt = (unsigned)uc->uc_mcontext.gregs[REG_RCX] & 63u;
		else if (op == 0xD0 || op == 0xD1)
			cnt = 1;
		else
			cnt = d.imm_off ? ip[d.imm_off] : 0;
		int which = (d.modrm >> 3) & 7;
		unsigned width = (unsigned)asz * 8u;
		cnt &= (asz == 8) ? 63u : (asz == 4) ? 31u : 7u;
		if (cnt) {
			if (which == 4 || which == 6)
				mem <<= cnt;
			else if (which == 5)
				mem >>= cnt;
			else if (which == 7)
				mem = (uint64_t)((int64_t)(mem << (64 - width)) >> (64 - width + cnt));
			else if (which == 0) { /* rol */
				mem = (mem << cnt) | (mem >> (width - cnt));
			} else if (which == 1)
				mem = (mem >> cnt) | (mem << (width - cnt));
			if (asz < 8)
				mem &= (asz == 4) ? 0xffffffffull : 0xffull;
			fault_store(fa, gpa, mmio, mem, asz);
		}
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if (op == 0x00 || op == 0x08 || op == 0x20 || op == 0x28 || op == 0x30) {
		uint64_t mem = fault_load(fa, gpa, mmio, 1);
		uint64_t rv = (uint64_t)uc->uc_mcontext.gregs[greg_of_ireg(reg)] & 0xff;
		int kind = op == 0x00 ? 0 : op == 0x08 ? 1 : op == 0x20 ? 4 : op == 0x28 ? 5 : 6;
		uint64_t nfl = x86_alu_flags(kind, mem, rv, 0, 1, &mem);
		fault_store(fa, gpa, mmio, mem, 1);
		SET_EFL(uc, nfl, 0);
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	if ((op == 0xFF || op == 0xFE) && (((d.modrm >> 3) & 7) <= 1)) {
		int asz = (op == 0xFE) ? 1 : ((d.rex & 8) ? 8 : (o16 ? 2 : 4));
		uint64_t mem = fault_load(fa, gpa, mmio, asz);
		uint64_t nfl = x86_alu_flags(((d.modrm >> 3) & 7) == 0 ? 9 : 10, mem, 0, 0, asz, &mem);
		fault_store(fa, gpa, mmio, mem, asz);
		SET_EFL(uc, nfl, 1); /* CF preserved */
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	/* cmp/test/inc/dec against MMIO or page0: skip */
	if (mmio || fa < 0x1000 || gpa < 0x1000) {
		uc->uc_mcontext.gregs[REG_RIP] += d.len;
		return 1;
	}
	/* High-half / unmapped guest RAM: skip with a trace so we can see it. */
	{
		static int skips;
		if (skips < 400) {
			uint64_t grip = (g_rx && hip >= (unsigned long)g_rx &&
			                 hip < (unsigned long)g_rx + CACHE_SZ)
			                ? host_to_guest((uint8_t *)(uintptr_t)hip) : 0;
			fprintf(stderr, "fast86: memop skip op=%02x%02x modrm=%02x rex=%02x gva=%lx gpa=%lx hip=%lx grip=%lx bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			        op, op2, d.modrm, d.rex, (unsigned long)fa, (unsigned long)gpa, hip,
			        (unsigned long)grip, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
			skips++;
		}
	}
	uc->uc_mcontext.gregs[REG_RIP] += d.len;
	return 1;
}

static void f86_fast_memcmp(void)
{
	F86CPU *c = g_cpu;
	if (!c)
		return;
	uint64_t a = c->r[R_RDI], b = c->r[R_RSI], n = c->r[R_RDX];
	if (n > (4ull << 20))
		n = 4ull << 20;
	int64_t r = 0;
	for (uint64_t i = 0; i < n; i++) {
		uint64_t pa = 0, pb = 0;
		uint8_t va = 0, vb = 0;
		if (!f86_gva_to_gpa(a + i, &pa) || pa >= f86_ram_size()) {
			r = 1;
			break;
		}
		if (!f86_gva_to_gpa(b + i, &pb) || pb >= f86_ram_size()) {
			r = -1;
			break;
		}
		va = f86_ram()[pa];
		vb = f86_ram()[pb];
		if (va != vb) {
			r = (int64_t)va - (int64_t)vb;
			break;
		}
	}
	c->r[R_RAX] = (uint64_t)r;
	if (r == 0)
		c->rflags |= 0x40ull;
	else
		c->rflags &= ~0x40ull;
	{
		static int nmc;
		if (nmc++ < 6)
			fprintf(stderr, "fast86: memcmp n=%lx r=%ld a=%lx b=%lx\n",
			        (unsigned long)n, (long)r,
			        (unsigned long)a, (unsigned long)b);
	}
	uint64_t ret = 0, gpa = 0;
	if (f86_gva_to_gpa(c->r[R_RSP], &gpa) && gpa + 8 <= f86_ram_size()) {
		memcpy(&ret, f86_ram() + gpa, 8);
		c->r[R_RSP] += 8;
	}
	if (looks_like_code(ret)) {
		c->rip = ret;
		f86_set_next(ret);
	}
}

static int gva_read(uint64_t gva, void *dst, size_t n)
{
	uint8_t *p = dst;
	for (size_t i = 0; i < n; i++) {
		uint64_t gpa = 0;
		if (!f86_gva_to_gpa(gva + i, &gpa) || gpa >= f86_ram_size())
			return 0;
		p[i] = f86_ram()[gpa];
	}
	return 1;
}

static uint8_t *gva_host(uint64_t gva, size_t n)
{
	uint64_t gpa = 0;
	if (!f86_gva_to_gpa(gva, &gpa) || gpa + n > f86_ram_size())
		return NULL;
	return f86_ram() + gpa;
}

static int gva_write(uint64_t gva, const void *src, size_t n)
{
	const uint8_t *p = src;
	for (size_t i = 0; i < n; i++) {
		uint64_t gpa = 0;
		if (!f86_gva_to_gpa(gva + i, &gpa) || gpa >= f86_ram_size())
			return 0;
		f86_ram()[gpa] = p[i];
	}
	return 1;
}

uint64_t f86_host_tsc_hz(void)
{
	static uint64_t hz;
	if (hz)
		return hz;
	FILE *f = fopen("/sys/devices/system/cpu/cpu0/tsc_freq_khz", "r");
	if (f) {
		unsigned long k = 0;
		if (fscanf(f, "%lu", &k) == 1 && k > 100000ul)
			hz = (uint64_t)k * 1000ull;
		fclose(f);
	}
	if (!hz) {
		FILE *c = fopen("/proc/cpuinfo", "r");
		if (c) {
			char line[256];
			while (fgets(line, sizeof line, c)) {
				double mhz = 0;
				if (sscanf(line, "cpu MHz : %lf", &mhz) == 1 && mhz > 100.0) {
					hz = (uint64_t)(mhz * 1000000.0);
					break;
				}
			}
			fclose(c);
		}
	}
	if (!hz)
		hz = 2000000000ull;
	return hz;
}

static void plant_preempt(void)
{
	if (!g_cpu || g_cpu->gs_base < 0xffffff8000000000ull)
		return;
	uint8_t *p = gva_host(g_cpu->gs_base + 0x58, 4);
	if (!p)
		return;
	uint32_t v = 0;
	memcpy(&v, p, 4);
	if (!v) {
		v = 1;
		memcpy(p, &v, 4);
		static int np;
		if (np++ < 4)
			fprintf(stderr, "fast86: plant preempt gs=%lx\n",
			        (unsigned long)g_cpu->gs_base);
	}
}

static uint32_t tsc_to_ns_scale(void)
{
	uint64_t hz = f86_host_tsc_hz();
	if (!hz)
		hz = 2000000000ull;
	return (uint32_t)((1000000000ull << 32) / hz);
}

static int steal_one_page(uint64_t base, uint32_t *pfn_out)
{
	uint64_t *rem;
	uint32_t *countp, *idxp, *maxp;
	uint8_t *table;
	uint64_t remv = 0;
	uint32_t count = 0, idx = 0;

	rem = (uint64_t *)gva_host(base + 0x1394e78ull, 8);
	countp = (uint32_t *)gva_host(base + 0x12dde20ull, 4);
	idxp = (uint32_t *)gva_host(base + 0x12da2b8ull, 4);
	maxp = (uint32_t *)gva_host(base + 0x12dde24ull, 4);
	if (!rem || !countp || !idxp)
		return 0;
	remv = *rem;
	count = *countp;
	idx = *idxp;
	if (!remv || idx >= count)
		return 0;
	table = gva_host(base + 0x12dca20ull, (size_t)count * 40ull + 32ull);
	if (!table)
		return 0;
	while (idx < count) {
		uint8_t *ent = table + (size_t)idx * 40u;
		uint32_t c0, h0, c1, h1;
		memcpy(&c0, ent + 4, 4);
		memcpy(&h0, ent + 8, 4);
		if (c0 <= h0) {
			uint32_t nxt = c0 + 1;
			memcpy(ent + 4, &nxt, 4);
			*pfn_out = c0;
			goto took;
		}
		memcpy(&c1, ent + 12, 4);
		memcpy(&h1, ent + 16, 4);
		if (c1 <= h1) {
			uint32_t nxt = c1 + 1;
			memcpy(ent + 12, &nxt, 4);
			*pfn_out = c1;
			goto took;
		}
		idx++;
		*idxp = idx;
	}
	return 0;
took:
	*rem = remv - 1;
	if (maxp && *pfn_out > *maxp)
		*maxp = *pfn_out;
	return 1;
}

static void f86_fast_uuid_scan(void)
{
	F86CPU *c = g_cpu;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t base = 0xffffff8000000000ull |
	                ((g_kaddr - 0x100000ull) & 0xffffffffull);
	uint64_t found = base + 0x544953ull;
	uint64_t miss = base + 0x544942ull;
	uint64_t table = c->r[R_R12];
	uint64_t key = c->r[R_R14];
	uint64_t obj = c->r[R_RBX];
	uint64_t count = c->r[R_RAX];
	uint8_t want[16], have[16];
	if (count == 0 || count > 65536ull)
		gva_read(obj + 0x68, &count, 8);
	if (count > 65536ull)
		count = 65536ull;
	if (!gva_read(key, want, 16))
		count = 0;
	uint64_t hit = 0, idx = 0;
	for (uint64_t i = 0; i < count; i++) {
		uint64_t ent = table + i * 24ull;
		if (!gva_read(ent, have, 16))
			continue;
		if (memcmp(have, want, 16) == 0) {
			hit = ent;
			idx = i;
			break;
		}
	}
	fprintf(stderr, "fast86: uuid scan count=%lx hit=%lx idx=%lx key=%lx tbl=%lx\n",
	        (unsigned long)count, (unsigned long)hit, (unsigned long)idx,
	        (unsigned long)key, (unsigned long)table);
	if (hit) {
		c->r[R_R13] = hit;
		c->r[R_R15] = idx + 1;
		c->r[R_RAX] = 0;
		c->rip = found;
	} else {
		c->r[R_RAX] = 0;
		c->rip = miss;
	}
	f86_set_next(c->rip);
}

static void f86_fast_packed_walk(void)
{
	F86CPU *c = g_cpu;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t rbx = c->r[R_RBX], lim = c->r[R_RCX];
	uint32_t acc = (uint32_t)c->r[R_RAX];
	int n = 0;
	/* Epilogue after the jae (0x54bd27 + 6 + 0x23b). */
	uint64_t done = 0xffffff8000000000ull |
	                ((g_kaddr - 0x100000ull + 0x54bf68ull) & 0xffffffffull);
	if ((rbx >> 47) != 0x1ffffull || (lim && (lim >> 47) != 0x1ffffull)) {
		c->rip = done;
		f86_set_next(c->rip);
		return;
	}
	while (rbx < lim && n++ < 8000000) {
		uint8_t b0 = 0, b1 = 0, b4 = 0;
		if (!gva_read(rbx, &b0, 1) || !gva_read(rbx + 1, &b1, 1))
			break;
		if (b0 == 0) {
			gva_read(rbx + 4, &b4, 1);
			acc += (uint32_t)(b4 & 1u);
		}
		rbx += b1 ? (uint64_t)b1 : 1ull;
	}
	c->r[R_RBX] = rbx;
	c->r[R_RAX] = acc;
	c->rip = done;
	{
		static int npw;
		if (npw++ < 6)
			fprintf(stderr, "fast86: packed walk n=%d rbx=%lx lim=%lx acc=%x\n",
			        n, (unsigned long)rbx, (unsigned long)lim, acc);
	}
	f86_set_next(c->rip);
}

static uint64_t kslide_base(void)
{
	return 0xffffff8000000000ull |
	       ((g_kaddr - 0x100000ull) & 0xffffffffull);
}

/* Replay vm_map_steal_memory. This build calls vm_map_init before
   initialize_upto(PMAP_STEAL), so the STARTUP steal entry never runs
   in time and vminit crams 0 pages. */
static void kstore64(uint64_t unslid_lo, uint64_t val)
{
	uint8_t *p = kc_phys(unslid_lo, 8);
	if (p)
		memcpy(p, &val, 8);
	if (g_kaddr >= 0x100000ull)
		gva_write(kslide_base() + unslid_lo, &val, 8);
}

static uint64_t kload64(uint64_t unslid_lo)
{
	uint64_t v = 0;
	uint8_t *p = kc_phys(unslid_lo, 8);
	if (p)
		memcpy(&v, p, 8);
	if (!v && g_kaddr >= 0x100000ull)
		gva_read(kslide_base() + unslid_lo, &v, 8);
	return v;
}

static int plant_early_zone_mem(void)
{
	uint64_t b, pages, meta, packed, zbase;
	uint64_t map_data, sz_map = 0x4000, sz_ent = 0x3000, sz_hole = 0x1000;
	static int planted;

	if (g_kaddr < 0x100000ull)
		return 0;
	b = kslide_base();
	map_data = kload64(0x13cecf8ull);
	if (map_data) {
		if (planted < 2)
			fprintf(stderr, "fast86: early zone mem already %lx\n",
			        (unsigned long)map_data);
		planted = 1;
		return 1;
	}
	pages = b + 0x13be000ull;
	meta = b + 0x13bbb30ull;
	packed = (pages >> 8) & 0xffffffff0ull;
	zbase = meta - packed;
	kstore64(0x13ced00ull, sz_map);
	kstore64(0x13ced10ull, sz_ent);
	kstore64(0x13ced20ull, sz_hole);
	kstore64(0x218d78ull, zbase);
	kstore64(0x218d10ull, pages);
	kstore64(0x218d18ull, b + 0x13c6000ull);
	kstore64(0x218d40ull, b + 0x13bc000ull);
	kstore64(0x218d48ull, b + 0x13bc000ull + 0x1000ull);
	kstore64(0x13bc040ull, 0x100000001ull);
	kstore64(0x13cecf8ull, pages);
	kstore64(0x13ced08ull, pages + sz_map);
	kstore64(0x13ced18ull, pages + sz_map + sz_ent);
	/* z_self must point at the zone so zalloc_ext(zone->z_self, ...) works. */
	{
		unsigned zi;
		for (zi = 15; zi <= 17; zi++) {
			uint64_t zva = b + 0x13640c0ull + (uint64_t)zi * 256ull;
			kstore64(0x13640c0ull + (uint64_t)zi * 256ull, zva);
		}
	}
	planted = 1;
	fprintf(stderr,
	        "fast86: planted steal pages=%lx meta=%lx zbase=%lx map=%lx/%lx/%lx\n",
	        (unsigned long)pages, (unsigned long)meta, (unsigned long)zbase,
	        (unsigned long)sz_map, (unsigned long)sz_ent, (unsigned long)sz_hole);
	return 1;
}

static void f86_fast_zsteal(void)
{
	F86CPU *c = g_cpu;
	/* Idempotent: native steal already filled map_data. */
	if (kload64(0x13cecf8ull)) {
		if (c && !pop_ret(c) && g_kaddr >= 0x100000ull)
			c->rip = kslide_base() + 0xbd6383ull;
		if (c)
			f86_set_next(c->rip);
		return;
	}
	plant_early_zone_mem();
	if (c && !pop_ret(c) && g_kaddr >= 0x100000ull)
		c->rip = kslide_base() + 0xbd6383ull;
	if (c)
		f86_set_next(c->rip);
}

static uint32_t gva_ld32(uint64_t va)
{
	uint32_t v = 0;
	gva_read(va, &v, 4);
	return v;
}

static void gva_st32(uint64_t va, uint32_t v)
{
	gva_write(va, &v, 4);
}

static uint64_t gva_ld64(uint64_t va)
{
	uint64_t v = 0;
	gva_read(va, &v, 8);
	return v;
}

static void gva_st64(uint64_t va, uint64_t v)
{
	gva_write(va, &v, 8);
}

/*
 * XNU zba_init_chunk() for the 4KiB startup bitmap page.
 * 0x44ed80: hdr=0xd8 (n==0) or 0x40, chunk=0x1000, granule=8, max_order=8.
 */
#define ZBA_CHUNK     0x1000u
#define ZBA_GRANULE   8u
#define ZBA_MAX_ORDER 8u

static uint32_t zba_idx(uint64_t page, uint64_t p)
{
	return (uint32_t)((p - page) / ZBA_GRANULE);
}

static size_t zba_node(uint64_t page, uint64_t addr, uint32_t order)
{
	uint64_t offs = (addr - page) / ZBA_GRANULE;
	return (size_t)((offs >> order) + (1u << (ZBA_MAX_ORDER - order + 1)) - 1);
}

static uint64_t zba_addr_for_node(uint64_t page, size_t node, uint32_t order)
{
	uint64_t offs = (uint64_t)((node - (1u << (ZBA_MAX_ORDER - order + 1)) + 1) << order);
	return page + offs * ZBA_GRANULE;
}

static void zba_flip(uint64_t page, size_t node)
{
	uint64_t at = page + (node / 64) * 8;
	uint64_t v = gva_ld64(at);
	v ^= 1ull << (node % 64);
	gva_st64(at, v);
}

static void zba_push(uint64_t page, uint64_t zbc, uint32_t order, int extra)
{
	/* heads: page+64+8 (after left/right), 9 regular then 9 extra */
	uint64_t hd = page + 64 + 8 + (uint64_t)(extra ? 9 : 0) * 8 +
	              (uint64_t)order * 8;
	uint32_t hd_index = zba_idx(page, hd);
	uint32_t index = zba_idx(page, zbc);
	uint32_t nxt = gva_ld32(hd);
	if (nxt) {
		uint64_t next = page + (uint64_t)nxt * ZBA_GRANULE;
		gva_st32(next + 4, index);
	}
	gva_st32(zbc, nxt);
	gva_st32(zbc + 4, hd_index);
	gva_st32(hd, index);
}

static void f86_nop_ret(void)
{
	F86CPU *c = g_cpu;
	uint32_t edi;
	uint8_t sil;
	uint64_t page, hdr_size, size;
	int extra;
	int o;

	if (!c)
		return;
	edi = (uint32_t)c->r[R_RDI];
	sil = (uint8_t)c->r[R_RSI];
	page = kload64(0x218d40ull);
	if (!page)
		gva_read(kslide_base() + 0x218d40ull, &page, 8);
	page = (page + ((uint64_t)edi << 12)) & ~0xfffull;
	hdr_size = edi ? 0x40ull : 0xd8ull;
	extra = sil != 0;
	{
		static int nz;
		if (nz++ < 8)
			fprintf(stderr, "fast86: zba-init_chunk edi=%u sil=%u page=%lx hdr=%lx\n",
			        edi, sil, (unsigned long)page, (unsigned long)hdr_size);
	}
	if (!page || (page >> 47) != 0x1ffffull) {
		c->r[R_RAX] = 0;
		if (!pop_ret(c))
			c->rip = kslide_base() + 0x44ee97ull;
		f86_set_next(c->rip);
		return;
	}
	/* Zero the header bits; steal already stored left/right at +0x40. */
	{
		uint64_t z = 0;
		unsigned i;
		for (i = 0; i < 8; i++)
			gva_st64(page + (uint64_t)i * 8, z);
	}
	size = ZBA_CHUNK;
	for (o = (int)ZBA_MAX_ORDER; o >= 0; o--) {
		size_t node, parent;
		uint64_t blk;
		if (size < hdr_size + (ZBA_GRANULE << (unsigned)o))
			continue;
		size -= ZBA_GRANULE << (unsigned)o;
		blk = page + size;
		node = zba_node(page, blk, (uint32_t)o);
		parent = (node - 1) / 2;
		zba_flip(page, parent);
		zba_push(page, zba_addr_for_node(page, node, (uint32_t)o),
		         (uint32_t)o, extra);
	}
	c->r[R_RAX] = 0;
	if (!pop_ret(c))
		c->rip = kslide_base() + 0x44ee97ull;
	f86_set_next(c->rip);
}

/*
 * zalloc_ext at 0x450220. Native magazines/zba are empty because C
 * zone_cram_early only bumps z_elems_free. Serve VM bootstrap zones
 * 15/16/17 from the stolen pages, and everything else from a physmap
 * bump so kmem_init's vm_map_create/enter can finish.
 * Returns kalloc_result: rax=addr, rdx=size.
 */
#define ZBUMP_PA  0x30000000ull
#define ZBUMP_SZ  (8ull << 20)

static uint64_t zone_bump_elem(unsigned id, uint16_t esz)
{
	static uint64_t next_e[20];
	static const uint32_t spans[20] = {
		[15] = 0x4000, [16] = 0x3000, [17] = 0x1000
	};
	uint64_t pg = 0, e, lim, b;
	uint8_t tmp[256];
	uint32_t cur = 0;

	if (id < 15 || id > 17 || !esz || esz > sizeof tmp)
		return 0;
	if (id == 15)
		pg = kload64(0x13cecf8ull);
	else if (id == 16)
		pg = kload64(0x13ced08ull);
	else
		pg = kload64(0x13ced18ull);
	b = kslide_base();
	if (!pg)
		pg = b + 0x13be000ull + (id == 15 ? 0 :
		     id == 16 ? 0x4000ull : 0x7000ull);
	lim = pg + spans[id];
	e = next_e[id];
	if (!e) {
		uint16_t offs = 0;
		gva_read(kslide_base() + 0x13640c0ull + (uint64_t)id * 256ull + 0x36ull,
		         &offs, 2);
		e = pg + (offs < esz ? offs : 0);
	}
	if (e + esz > lim)
		return 0;
	memset(tmp, 0, esz);
	if (!gva_write(e, tmp, esz))
		return 0;
	next_e[id] = e + esz;
	gva_read(b + 0x13640c0ull + (uint64_t)id * 256ull + 0xa8ull, &cur, 4);
	if (cur)
		cur--;
	gva_write(b + 0x13640c0ull + (uint64_t)id * 256ull + 0xa8ull, &cur, 4);
	{
		uint8_t *p = kc_phys(0x13640c0ull + (uint64_t)id * 256ull + 0xa8ull, 4);
		if (p)
			memcpy(p, &cur, 4);
	}
	return e;
}

static uint64_t zone_generic_elem(uint16_t esz)
{
	static uint32_t off;
	uint64_t pa, va;
	uint8_t tmp[256];
	uint32_t n;

	if (!esz)
		esz = 64;
	n = (uint32_t)((esz + 15u) & ~15u);
	if (n > sizeof tmp)
		n = (uint32_t)sizeof tmp;
	if (off + n > ZBUMP_SZ)
		return 0;
	pa = ZBUMP_PA + off;
	off += n;
	va = 0xfffff68000000000ull + pa;
	memset(tmp, 0, n);
	if (!gva_write(va, tmp, n)) {
		/* physmap may not walk yet; write physical. */
		if (pa + n <= f86_ram_size())
			memset(f86_ram() + pa, 0, n);
		else
			return 0;
	}
	return va;
}

static void f86_zalloc(void)
{
	F86CPU *c = g_cpu;
	uint64_t b, z, za, e = 0;
	unsigned id = 0;
	uint16_t esz = 0;
	uint32_t flags;
	static int nlog;

	if (!c || g_kaddr < 0x100000ull)
		return;
	b = kslide_base();
	z = c->r[R_RDI];
	flags = (uint32_t)c->r[R_RDX];
	za = b + 0x13640c0ull;
	if (z >= za && z < za + 690ull * 256ull)
		id = (unsigned)((z - za) / 256ull);
	else if (z) {
		uint64_t self = gva_ld64(z);
		if (self >= za && self < za + 690ull * 256ull) {
			id = (unsigned)((self - za) / 256ull);
			z = self;
		}
	}
	if (z)
		gva_read(z + 0x34, &esz, 2);
	if (!esz) {
		static const uint16_t es[] = {
			[15] = 0xb0, [16] = 0x50, [17] = 0x20, [18] = 0x48
		};
		if (id <= 18 && es[id])
			esz = es[id];
	}
	if (id >= 15 && id <= 17 && esz)
		e = zone_bump_elem(id, esz);
	if (!e && esz)
		e = zone_generic_elem(esz);
	c->r[R_RAX] = e;
	c->r[R_RDX] = esz;
	if (nlog++ < 40)
		fprintf(stderr, "fast86: zalloc id=%u z=%lx esz=%u fl=%x -> %lx\n",
		        id, (unsigned long)z, esz, flags, (unsigned long)e);
	if (id == 16 && nlog < 40) {
		uint64_t map = kload64(0x13cecf8ull);
		uint64_t hole, hmin = 0, hmax = 0, n0, n1, mn, mx, nxt, prv;
		uint32_t nent = 0;
		if (map) {
			gva_read(map + 0x0c, &nent, 4);
			mn = gva_ld64(map + 0x20);
			mx = gva_ld64(map + 0x28);
			hole = gva_ld64(map + 0x90);
			nxt = gva_ld64(map + 0x10);
			prv = gva_ld64(map + 0x18);
			n0 = gva_ld64(map + 0x88);
			n1 = gva_ld64(map + 0x98);
			if (hole) {
				hmin = gva_ld64(hole + 0x10);
				hmax = gva_ld64(hole + 0x18);
			}
			fprintf(stderr,
			        "fast86: kernel_map %lx nent=%u min=%lx max=%lx hdr=%lx/%lx hole=%lx [%lx,%lx) s88=%lx s98=%lx\n",
			        (unsigned long)map, nent, (unsigned long)mn,
			        (unsigned long)mx, (unsigned long)nxt,
			        (unsigned long)prv, (unsigned long)hole,
			        (unsigned long)hmin, (unsigned long)hmax,
			        (unsigned long)n0, (unsigned long)n1);
		}
	}
	if (!pop_ret(c))
		c->rip = b + 0x36e760ull;
	f86_set_next(c->rip);
}

static void gva_st16(uint64_t va, uint16_t v)
{
	gva_write(va, &v, 2);
}

static uint16_t gva_ld16(uint64_t va)
{
	uint16_t v = 0;
	gva_read(va, &v, 2);
	return v;
}

static void gva_or32(uint64_t va, uint32_t bits)
{
	uint32_t v = gva_ld32(va);
	gva_st32(va, v | bits);
}

/* Native vm_map_create (0x4942d0): zalloc map + hole, then field init. */
static void f86_map_create(void)
{
	F86CPU *c = g_cpu;
	uint64_t pmap, min, max, map, hdr, hole, hole_max, b;
	uint32_t opt, extra, flg = 0, cnt = 0;
	uint16_t w;

	if (!c || g_kaddr < 0x100000ull)
		return;
	b = kslide_base();
	pmap = c->r[R_RDI];
	min = c->r[R_RSI];
	max = c->r[R_RDX];
	opt = (uint32_t)c->r[R_RCX];
	map = zone_bump_elem(15, 0xb0);
	if (!map) {
		fprintf(stderr, "fast86: map-create failed pmap=%lx min=%lx max=%lx\n",
		        (unsigned long)pmap, (unsigned long)min, (unsigned long)max);
		c->r[R_RAX] = 0;
		if (!pop_ret(c))
			c->rip = b + 0x49444aull;
		f86_set_next(c->rip);
		return;
	}
	hdr = map + 0x10;
	gva_st64(map + 0x10, hdr);
	gva_st64(map + 0x18, hdr);
	gva_st64(map + 0x38, 0);
	w = gva_ld16(map + 0x36);
	w = (uint16_t)((w & ~1u) | (opt & 1u));
	gva_st16(map + 0x36, w);
	if (!gva_ld32(map + 0x30))
		gva_st16(map + 0x34, 0xc);
	gva_st64(map + 0x50, 0x7fffffffffffffffull);
	gva_st64(map + 0x58, 0x7fffffffffffffffull);
	gva_st64(map + 0x60, 0x7fffffe00000ull);
	gva_st32(map + 0x78, 1);
	gva_st64(map + 0x40, pmap);
	gva_st64(map + 0x20, min);
	gva_st64(map + 0x28, max);
	gva_st64(map + 0x98, hdr);
	gva_st64(map + 0x88, hdr);
	if (opt & 8u) {
		uint8_t a2 = 0;
		gva_read(map + 0xa2, &a2, 1);
		a2 |= 4;
		gva_write(map + 0xa2, &a2, 1);
	}
	extra = 0x800;
	if (!(opt & 2u) && !(opt & 4u)) {
		hole = zone_bump_elem(17, 0x20);
		if (hole) {
			hole_max = max > 0x7fffffe00000ull ? max : 0x7fffffe00000ull;
			gva_st64(hole + 0x10, min);
			gva_st64(hole + 0x18, hole_max);
			gva_st64(map + 0x90, hole);
			gva_st64(map + 0x98, hole);
			gva_st64(hole + 8, hole);
			gva_st64(hole, hole);
			extra = 0x80;
		}
	}
	if (!(opt & 4u))
		gva_or32(map + 0xa0, extra);
	gva_st32(map + 0xa4, 0);
	gva_read(b + 0x21bba4ull, &flg, 4);
	flg = ((flg >> 15) & 2u) ^ 0x42u;
	gva_st64(map, 0x33000000ull);
	gva_st16(map + 8, 0);
	gva_st16(map + 0xa, (uint16_t)flg);
	gva_st32(map + 0xc, 0);
	gva_read(b + 0x111fb04ull, &cnt, 4);
	cnt++;
	gva_write(b + 0x111fb04ull, &cnt, 4);
	c->r[R_RAX] = map;
	{
		static int n;
		if (n++ < 8)
			fprintf(stderr,
			        "fast86: map-create map=%lx pmap=%lx min=%lx max=%lx opt=%x hole=%lx\n",
			        (unsigned long)map, (unsigned long)pmap,
			        (unsigned long)min, (unsigned long)max, opt,
			        (unsigned long)gva_ld64(map + 0x90));
	}
	if (!pop_ret(c))
		c->rip = b + 0x49444aull;
	f86_set_next(c->rip);
}

/* Early vm_map_enter: carve from the compact hole at map+0x90. */
static void f86_map_enter(void)
{
	F86CPU *c = g_cpu;
	uint64_t map, addrp, size, flags, want = 0, hole, hmin, hmax, e, sent, last;
	uint32_t nent = 0;
	static int nlog;

	if (!c)
		return;
	map = c->r[R_RDI];
	addrp = c->r[R_RSI];
	size = c->r[R_RDX];
	flags = c->r[R_R8];
	gva_read(addrp, &want, 8);
	hole = gva_ld64(map + 0x90);
	hmin = hole ? gva_ld64(hole + 0x10) : 0;
	hmax = hole ? gva_ld64(hole + 0x18) : 0;
	if (nlog++ < 12)
		fprintf(stderr,
		        "fast86: map-enter map=%lx want=%lx size=%lx fl=%lx hole=[%lx,%lx)\n",
		        (unsigned long)map, (unsigned long)want, (unsigned long)size,
		        (unsigned long)flags, (unsigned long)hmin, (unsigned long)hmax);
	size = (size + 0xfffull) & ~0xfffull;
	if ((flags & 1ull) || want < 0x1000ull)
		want = hmin;
	want &= ~0xfffull;
	/*
	 * kmem_init reserves [VM_MIN, start). That swallows the first 2GiB
	 * kext_alloc_init needs. Keep [VM_MIN, VM_MIN+2GiB) as a hole.
	 */
	if (want == 0xffffff7f80000000ull && size > 0x80000000ull) {
		uint64_t end = want + size;
		want = 0xffffff8000000000ull;
		if (end > want)
			size = end - want;
	}
	if (!hole || !size || want < hmin || want + size < want || want + size > hmax) {
		c->r[R_RAX] = 3;
		if (!pop_ret(c))
			c->rip = kslide_base() + 0x49d000ull;
		f86_set_next(c->rip);
		return;
	}
	e = zone_bump_elem(16, 0x50);
	if (!e)
		e = zone_generic_elem(0x50);
	if (!e) {
		c->r[R_RAX] = 3;
		if (!pop_ret(c))
			c->rip = kslide_base() + 0x49d000ull;
		f86_set_next(c->rip);
		return;
	}
	sent = map + 0x10;
	last = gva_ld64(map + 0x18);
	if (!last)
		last = sent;
	gva_st64(e, last);
	gva_st64(e + 8, sent);
	gva_st64(e + 0x10, want);
	gva_st64(e + 0x18, want + size);
	if (last == sent)
		gva_st64(map + 0x10, e);
	else
		gva_st64(last + 8, e);
	gva_st64(map + 0x18, e);
	if (want > hmin && want + size < hmax) {
		uint64_t h2 = zone_bump_elem(17, 0x20);
		gva_st64(hole + 0x18, want);
		if (h2) {
			uint64_t hn = gva_ld64(hole);
			gva_st64(h2 + 0x10, want + size);
			gva_st64(h2 + 0x18, hmax);
			gva_st64(h2, hn);
			gva_st64(h2 + 8, hole);
			gva_st64(hole, h2);
			if (hn)
				gva_st64(hn + 8, h2);
		}
	} else if (want > hmin)
		gva_st64(hole + 0x18, want);
	else
		gva_st64(hole + 0x10, want + size);
	gva_st64(map + 0x88, e);
	gva_st64(map + 0x38, e + 0x20);
	gva_read(map + 0x30, &nent, 4);
	nent++;
	gva_write(map + 0x30, &nent, 4);
	gva_st64(addrp, want);
	c->r[R_RAX] = 0;
	if (nlog < 16)
		fprintf(stderr, "fast86: map-enter ok addr=%lx size=%lx entry=%lx nent=%u\n",
		        (unsigned long)want, (unsigned long)size, (unsigned long)e, nent);
	if (!pop_ret(c))
		c->rip = kslide_base() + 0x49d000ull;
	f86_set_next(c->rip);
}

static void f86_zfree_early(void)
{
	F86CPU *c = g_cpu;
	uint64_t addr, pages;
	static int n;
	if (!c)
		return;
	addr = c->r[R_RDX];
	pages = kload64(0x13cecf8ull);
	if (n++ < 16)
		fprintf(stderr, "fast86: zfree-early addr=%lx zone=%lx\n",
		        (unsigned long)addr, (unsigned long)c->r[R_RDI]);
	(void)pages;
	if (!pop_ret(c))
		c->rip = kslide_base() + 0x44f600ull;
	f86_set_next(c->rip);
}

static void f86_fast_zcram(void)
{
	F86CPU *c = g_cpu;
	uint64_t z, pg, sz, b;
	uint16_t esz = 0, cpg = 1;
	uint32_t add = 0, cur = 0;
	unsigned id = 0;
	if (!c || g_kaddr < 0x100000ull)
		return;
	b = kslide_base();
	z = c->r[R_RDI];
	pg = c->r[R_RSI];
	sz = c->r[R_RDX];
	if (z) {
		uint64_t za = b + 0x13640c0ull;
		id = (unsigned)((z - za) / 256ull);
		gva_read(z + 0x34, &esz, 2);
		{
			uint8_t *p = kc_phys(0x13640c0ull + (uint64_t)id * 256ull + 0x38ull, 2);
			if (p)
				memcpy(p, &cpg, 2);
			gva_write(z + 0x38, &cpg, 2);
		}
		if (esz && sz)
			add = (uint32_t)(sz / esz);
		gva_read(z + 0xa8, &cur, 4);
		cur += add;
		gva_write(z + 0xa8, &cur, 4);
		/* zone_page_metadata.zm_index so zone_require() accepts elems. */
		if (pg && sz >= 0x1000ull) {
			uint64_t meta0 = b + 0x13bbb30ull;
			uint64_t pages0 = kload64(0x13cecf8ull);
			uint64_t zbase = kload64(0x218d78ull);
			uint32_t np = (uint32_t)(sz / 0x1000ull), pi;
			int inl = esz && (0x1000u / esz) <= 32u;
			uint16_t bits = (uint16_t)((id & 0x3ffu) |
			                           (inl ? (1u << 11) : 0) | (1u << 12));
			for (pi = 0; pi < np; pi++) {
				uint64_t page = pg + (uint64_t)pi * 0x1000ull;
				uint8_t rec[16];
				uint64_t slot;
				memset(rec, 0, sizeof rec);
				memcpy(rec, &bits, 2);
				if (pages0 && page >= pages0)
					slot = meta0 + ((page - pages0) / 0x1000ull) * 16ull;
				else
					slot = meta0 + (uint64_t)pi * 16ull;
				gva_write(slot, rec, 16);
				{
					uint8_t *mp = kc_phys(0x13bbb30ull +
					                      (slot - meta0), 16);
					if (mp)
						memcpy(mp, rec, 16);
				}
				if (zbase) {
					int32_t pva = (int32_t)(uint32_t)(page >> 12);
					uint64_t alt = zbase + (int64_t)pva * 16;
					if ((alt >> 32) == 0xffffff80ull)
						gva_write(alt, rec, 16);
					alt = zbase + ((page >> 8) & ~0xfull);
					if ((alt >> 32) == 0xffffff80ull)
						gva_write(alt, rec, 16);
				}
			}
			fprintf(stderr,
			        "fast86: zone-meta id=%u pg=%lx np=%u bits=%x meta0=%lx zbase=%lx\n",
			        id, (unsigned long)pg, np, bits,
			        (unsigned long)meta0, (unsigned long)zbase);
		}
		{
			uint8_t *p = kc_phys(0x13640c0ull + (uint64_t)id * 256ull + 0xa8ull, 4);
			if (p)
				memcpy(p, &cur, 4);
		}
		/* z_self / z_stats: native zalloc_ext loads these. */
		gva_st64(z, z);
		kstore64(0x13640c0ull + (uint64_t)id * 256ull, z);
		if (!gva_ld64(z + 8)) {
			uint64_t st = b + 0x13bbd00ull + (uint64_t)id * 64ull;
			gva_st64(z + 8, st);
			kstore64(0x13640c0ull + (uint64_t)id * 256ull + 8ull, st);
		}
	}
	fprintf(stderr, "fast86: cram-early-ret z=%lx id=%u pg=%lx sz=%lx esz=%u free=%u\n",
	        (unsigned long)z, id, (unsigned long)pg, (unsigned long)sz, esz, cur);
	c->r[R_RAX] = 0;
	if (!pop_ret(c))
		c->rip = b + 0xbd26c8ull;
	f86_set_next(c->rip);
}

static void f86_fast_cons(void)
{
	F86CPU *c = g_cpu;
	if (!c)
		return;
	uint64_t p = c->r[R_RDI];
	uint64_t narg = c->r[R_RSI];
	uint32_t n;
	/* printf-style: rdi = C string. write-style: rdi=buf, rsi=len. */
	if ((narg >> 47) == 0x1ffffull || narg > 4096ull)
		n = 0;
	else
		n = (uint32_t)narg;
	if (!n && p) {
		for (n = 0; n < 512; n++) {
			uint8_t z = 0;
			if (!gva_read(p + n, &z, 1) || !z)
				break;
		}
	}
	if (n > 512)
		n = 512;
	uint8_t buf[4097];
	uint32_t got = 0;
	for (uint32_t i = 0; i < n; i++) {
		uint8_t ch = 0;
		if (!gva_read(p + i, &ch, 1))
			break;
		if (ch == '\n') {
			if (got < sizeof buf - 2) {
				buf[got++] = '\r';
				buf[got++] = '\n';
			}
		} else if (ch && got < sizeof buf - 1)
			buf[got++] = ch;
	}
	if (got) {
		int printable = 0;
		for (uint32_t i = 0; i < got; i++)
			if (buf[i] >= 0x20 && buf[i] < 0x7f)
				printable++;
		if (printable * 4 >= (int)got * 3) {
			buf[got] = 0;
			fprintf(stderr, "xnu: %s", buf);
			if (buf[got - 1] != '\n')
				fputc('\n', stderr);
			if (strstr((char *)buf, "VM boostrap") ||
			    strstr((char *)buf, "VM bootstrap")) {
				uint64_t b = kslide_base(), md = 0, mdi = 0, zf = 0;
				uint64_t lo;
				gva_read(b + 0x13cecf8ull, &md, 8);
				lo = (b + 0x13cecf8ull) & 0xffffffffull;
				if (lo + 8 <= f86_ram_size())
					memcpy(&mdi, f86_ram() + lo, 8);
				gva_read(b + 0x1364fc0ull + 0xa8ull, &zf, 4);
				{
					uint8_t *tp = kc_phys(0x13d5800ull, 16);
					uint8_t *cp = kc_phys(0x13b56b0ull, 8);
					uint32_t s0 = 0;
					uint64_t f0 = 0, cur = 0;
					if (tp) {
						memcpy(&s0, tp, 4);
						memcpy(&f0, tp + 8, 8);
					}
					if (cp)
						memcpy(&cur, cp, 8);
					fprintf(stderr,
					        "fast86: zone dump map_data walk=%lx ident=%lx z15_free=%lx tbl0=%u:%lx cur=%lx\n",
					        (unsigned long)md, (unsigned long)mdi,
					        (unsigned long)zf, s0, (unsigned long)f0,
					        (unsigned long)cur);
				}
			}
			if (strstr((char *)buf, "vm_page_bootstrap"))
				plant_early_zone_mem();
			if (strstr((char *)buf, "swap files") ||
			    strstr((char *)buf, "kmem_suballoc")) {
				uint64_t map = kload64(0x13cecf8ull);
				uint64_t hole = 0, hmin = 0, hmax = 0, mn = 0, mx = 0, nxt = 0;
				uint32_t nent = 0;
				if (map) {
					gva_read(map + 0x0c, &nent, 4);
					mn = gva_ld64(map + 0x20);
					mx = gva_ld64(map + 0x28);
					hole = gva_ld64(map + 0x90);
					nxt = gva_ld64(map + 0x10);
					if (hole) {
						hmin = gva_ld64(hole + 0x10);
						hmax = gva_ld64(hole + 0x18);
					}
					if (nent == 0 && nxt && nxt != map + 0x10) {
						uint32_t one = 1;
						gva_write(map + 0x0c, &one, 4);
						nent = 1;
						fprintf(stderr, "fast86: map nentries 0->1\n");
					}
					fprintf(stderr,
					        "fast86: map-dump map=%lx nent=%u min=%lx max=%lx hdr.next=%lx hole=%lx [%lx,%lx) hole.lnk=%lx/%lx\n",
					        (unsigned long)map, nent,
					        (unsigned long)mn, (unsigned long)mx,
					        (unsigned long)nxt, (unsigned long)hole,
					        (unsigned long)hmin, (unsigned long)hmax,
					        (unsigned long)(hole ? gva_ld64(hole) : 0),
					        (unsigned long)(hole ? gva_ld64(hole + 8) : 0));
					{
						unsigned wi;
						fprintf(stderr, "fast86: map-words");
						for (wi = 0; wi < 0xb0; wi += 8)
							fprintf(stderr, " %02x:%lx", wi,
							        (unsigned long)gva_ld64(map + wi));
						fputc('\n', stderr);
					}
					if (nxt && nxt != map + 0x10) {
						fprintf(stderr,
						        "fast86: map-dump entry %lx lnk=%lx/%lx range=[%lx,%lx) +20=%lx +28=%lx +40=%lx\n",
						        (unsigned long)nxt,
						        (unsigned long)gva_ld64(nxt),
						        (unsigned long)gva_ld64(nxt + 8),
						        (unsigned long)gva_ld64(nxt + 0x10),
						        (unsigned long)gva_ld64(nxt + 0x18),
						        (unsigned long)gva_ld64(nxt + 0x20),
						        (unsigned long)gva_ld64(nxt + 0x28),
						        (unsigned long)gva_ld64(nxt + 0x40));
					}
				}
			}
			if (!g_stride_done &&
			    (strstr((char *)buf, "vm_page_bootstrap") ||
			     strstr((char *)buf, "VM boostrap") ||
			     strstr((char *)buf, "VM bootstrap"))) {
				g_stride_done = 1;
				g_irq_ok = 1;
				if (g_kaddr >= 0x100000ull) {
					map_evict(kslide_base() + 0x44f480ull);
					uint64_t b = 0xffffff8000000000ull |
					             ((g_kaddr - 0x100000ull) & 0xffffffffull);
					/*
					 * Force the sleepable path (inc lock-count, then
					 * the real cmpxchg). Do not hook wait/unlock —
					 * those left zone_cram_early with 0 free elements.
					 * Sites: exclusive, try-exclusive, shared.
					 */
					static const uint64_t sites[] = {
						0x3f13f3ull, 0x3f14a3ull, 0x3f1549ull
					};
					int npat = 0;
					for (unsigned s = 0; s < 3; s++) {
						uint8_t *ip = gva_host(b + sites[s], 6);
						if (ip && ip[0] == 0xf6 && ip[1] == 0x47 &&
						    ip[4] == 0x75) {
							uint8_t rel = (uint8_t)(ip[5] + 4);
							ip[0] = 0xeb;
							ip[1] = rel;
							memset(ip + 2, 0x90, 4);
							map_evict(b + sites[s]);
							map_evict(b + sites[s] - 0x13ull);
							npat++;
						}
					}
					map_evict(b + 0x3f0ad0ull);
					map_evict(b + 0x3f12a0ull);
					map_evict(b + 0x3f13e0ull);
					map_evict(b + 0x3f1490ull);
					map_evict(b + 0x3f1540ull);
					fprintf(stderr, "fast86: patched %d rwlock sleepable checks\n",
					        npat);
				}
			}
		}
	}
	c->r[R_RBX] = 1;
	c->r[R_R14] = p + n;
	if (g_kaddr >= 0x100000ull) {
		uint64_t b = 0xffffff8000000000ull |
		             ((g_kaddr - 0x100000ull) & 0xffffffffull);
		if (c->rip == b + 0x4fef40ull) {
			uint64_t ret = 0, gpa = 0;
			if (f86_gva_to_gpa(c->r[R_RSP], &gpa) &&
			    gpa + 8 <= f86_ram_size()) {
				memcpy(&ret, f86_ram() + gpa, 8);
				c->r[R_RSP] += 8;
			}
			c->r[R_RAX] = n;
			c->rip = ret ? ret : (b + 0x4fefc3ull);
		} else
			c->rip = b + 0x4fefc3ull;
		{ /* steal+vminit injected at zone_init instead */ }
	}
	f86_set_next(c->rip);
}

static void f86_fast_stride(void)
{
	F86CPU *c = g_cpu;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t r12 = c->r[R_R12], r13 = c->r[R_R13];
	uint64_t base = 0xffffff8000000000ull |
	                ((g_kaddr - 0x100000ull) & 0xffffffffull);
	if (r12 >= r13) {
		c->rip = base + 0x4d1521ull;
		f86_set_next(c->rip);
		return;
	}
	c->r[R_R12] = r12 + 0x38;
	c->rip = base + 0x4d1434ull;
	f86_set_next(c->rip);
}

static void f86_fast_timebase(void)
{
	F86CPU *c = g_cpu;
	uint64_t obj, ret = 0, tsc_base = 0, ns_base = 0;
	uint32_t scale = 0, shift = 0, gen = 0;
	uint32_t lo, hi;
	uint64_t tsc, ns;
	unsigned __int128 prod;
	uint8_t *p;

	if (!c)
		return;
	obj = c->r[R_RDI];
	p = gva_host(obj, 0x20);
	if (p) {
		memcpy(&tsc_base, p + 0x00, 8);
		memcpy(&ns_base, p + 0x08, 8);
		memcpy(&scale, p + 0x10, 4);
		memcpy(&shift, p + 0x14, 4);
		memcpy(&gen, p + 0x18, 4);
		if (!gen || !scale) {
			scale = tsc_to_ns_scale();
			shift = 0;
			tsc_base = 0;
			ns_base = 0;
			gen = 1;
			memcpy(p + 0x00, &tsc_base, 8);
			memcpy(p + 0x08, &ns_base, 8);
			memcpy(p + 0x10, &scale, 4);
			memcpy(p + 0x14, &shift, 4);
			memcpy(p + 0x18, &gen, 4);
			static int nplant;
			if (nplant++ < 4)
				fprintf(stderr,
				        "fast86: timebase plant obj=%lx scale=%x hz=%lu\n",
				        (unsigned long)obj, scale,
				        (unsigned long)f86_host_tsc_hz());
		}
	} else {
		scale = tsc_to_ns_scale();
	}
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	tsc = ((uint64_t)hi << 32) | lo;
	if (tsc < tsc_base)
		tsc = 0;
	else
		tsc -= tsc_base;
	if (shift && shift < 64)
		tsc <<= shift;
	prod = (unsigned __int128)tsc * (unsigned __int128)(scale ? scale : 1u);
	ns = (uint64_t)(prod >> 32) + ns_base;
	c->r[R_RAX] = ns;
	c->r[R_RDX] = 0;
	if (gva_read(c->r[R_RSP], &ret, 8) && ret) {
		c->r[R_RSP] += 8;
		c->rip = ret;
	} else if (g_kaddr >= 0x100000ull) {
		uint64_t b = 0xffffff8000000000ull |
		             ((g_kaddr - 0x100000ull) & 0xffffffffull);
		c->rip = b + 0x36f140ull;
	}
	f86_set_next(c->rip);
}

static void rw_force_word(uint64_t lk, uint32_t keep_or)
{
	uint64_t tlo = 0xffffff8000000000ull |
	               ((g_kaddr - 0x100000ull + 0x2e4000ull) & 0xffffffffull);
	uint64_t thi = tlo + 0xa14000ull;
	if ((lk >> 47) != 0x1ffffull || (lk >= tlo && lk < thi))
		return;
	uint8_t *p = gva_host(lk, 4);
	if (!p)
		return;
	uint32_t v = 0;
	memcpy(&v, p, 4);
	uint32_t nv = (v & ~0xdffffu) | keep_or;
	memcpy(p, &nv, 4);
	static int ns;
	if (ns++ < 12)
		fprintf(stderr, "fast86: rw force [%lx] %x -> %x\n",
		        (unsigned long)lk, v, nv);
}

static int pop_ret(F86CPU *c)
{
	uint64_t ret = 0;
	if (!gva_read(c->r[R_RSP], &ret, 8) || !ret)
		return 0;
	c->r[R_RSP] += 8;
	c->rip = ret;
	return 1;
}

static void f86_fast_rwspin(void)
{
	F86CPU *c = g_cpu;
	uint32_t v = 0;
	uint8_t *p;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t b = 0xffffff8000000000ull |
	             ((g_kaddr - 0x100000ull) & 0xffffffffull);
	/* Drop a stuck INTERLOCK bit and retry the real cmpxchg.
	   Do not force exclusive — that corrupted zone/ticket words. */
	if (c->r[R_R14] < 0x1000ull && (c->r[R_RBX] >> 47) == 0x1ffffull)
		c->r[R_R14] = c->r[R_RBX];
	if (c->r[R_R14] >= 0x1000ull && (c->r[R_R14] >> 47) == 0 &&
	    c->r[R_R14] < f86_ram_size())
		c->r[R_R14] |= 0xfffff68000000000ull;
	if (c->r[R_R14] < 0x1000ull) {
		c->rip = b + 0x3f0b13ull;
		f86_set_next(c->rip);
		return;
	}
	p = gva_host(c->r[R_R14], 4);
	if (!p && (c->r[R_R14] >> 32) == 0xffffff80ull) {
		uint64_t lo = c->r[R_R14] & 0xffffffffull;
		if (lo + 4 <= f86_ram_size())
			p = f86_ram() + lo;
	}
	if (p) {
		memcpy(&v, p, 4);
		if (v & 0x10000u) {
			v &= ~0x10000u;
			memcpy(p, &v, 4);
		}
	}
	{
		static int ns;
		if (ns++ < 8)
			fprintf(stderr, "fast86: rwspin word@%lx p=%p v=%x\n",
			        (unsigned long)c->r[R_R14], (void *)p, v);
	}
	c->rip = b + 0x3f0aa0ull;
	f86_set_next(c->rip);
}

static void f86_fast_rwwait(void)
{
	F86CPU *c = g_cpu;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t b = 0xffffff8000000000ull |
	             ((g_kaddr - 0x100000ull) & 0xffffffffull);
	uint64_t off = c->rip - b;
	uint64_t lk;
	uint32_t mask;
	if (off == 0x3f12a0ull) {
		uint64_t lock = c->r[R_RDI];
		uint8_t *p;
		uint32_t v = 0;
		p = gva_host(lock + 8, 4);
		if (!p && (lock >> 32) == 0xffffff80ull) {
			uint64_t lo = (lock + 8) & 0xffffffffull;
			if (lo + 4 <= f86_ram_size())
				p = f86_ram() + lo;
		}
		if (lock && (lock < b + 0x2e4000ull || lock >= b + 0xa14000ull) && p) {
			memcpy(&v, p, 4);
			v = (v & ~0xdffffu) | 0x80000u;
			memcpy(p, &v, 4);
			c->r[R_RAX] = 1;
		} else
			c->r[R_RAX] = 0;
		static int nt;
		if (nt++ < 8)
			fprintf(stderr, "fast86: rwwait grant lock=%lx word=%x rax=%lx\n",
			        (unsigned long)lock, v, (unsigned long)c->r[R_RAX]);
		if (!pop_ret(c))
			c->rip = b + 0x3f13b4ull;
		f86_set_next(c->rip);
		return;
	} else if (off == 0x3f2f80ull || off == 0x3f2f83ull ||
	           off == 0x3f2f98ull) {
		c->rip = b + 0x3f306eull;
		f86_set_next(c->rip);
		return;
	} else if (off == 0x3f2580ull || off == 0x3f2582ull) {
		lk = c->r[R_RBX];
		mask = 0x10000u;
	} else {
		lk = c->r[R_R15];
		mask = (uint32_t)c->r[R_R14];
		if (!mask)
			mask = 0x4ffffu;
	}
	uint8_t *p = gva_host(lk + 8, 4);
	if (p) {
		uint32_t v = 0;
		memcpy(&v, p, 4);
		uint32_t nv = v & ~mask;
		memcpy(p, &nv, 4);
		static int nw;
		if (nw++ < 8)
			fprintf(stderr, "fast86: rw word [%lx+8] %x -> %x mask=%x off=%lx\n",
			        (unsigned long)lk, v, nv, mask, (unsigned long)off);
	}
	c->r[R_RAX] = 0;
	if (off == 0x3f12a0ull) {
		if (!pop_ret(c))
			c->rip = b + 0x3f13b4ull;
	} else if (off == 0x3f2580ull || off == 0x3f2582ull)
		c->rip = b + 0x3f2550ull;
	else
		c->rip = b + 0x3f139dull;
	f86_set_next(c->rip);
}

static int gva_push(F86CPU *c, uint64_t v)
{
	c->r[R_RSP] -= 8;
	return gva_write(c->r[R_RSP], &v, 8);
}

static void f86_fast_rwassert(void)
{
	F86CPU *c = g_cpu;
	if (!c || g_kaddr < 0x100000ull)
		return;
	uint64_t b = 0xffffff8000000000ull |
	             ((g_kaddr - 0x100000ull) & 0xffffffffull);
	uint64_t off = c->rip - b;
	uint64_t lock = c->r[R_RDI];
	if (!lock || (lock >= b + 0x2e4000ull && lock < b + 0xa14000ull)) {
		/* Do not fake-hold a missing lock; fail the acquire. */
		c->r[R_RAX] = 0;
		if (!pop_ret(c))
			c->rip = b + 0x3f1478ull;
		f86_set_next(c->rip);
		return;
	}
	if (off == 0x3f13e0ull) {
		/* Prologue: push rbp; mov rbp,rsp; push r14; push rbx */
		gva_push(c, c->r[R_RBP]);
		c->r[R_RBP] = c->r[R_RSP];
		gva_push(c, c->r[R_R14]);
		gva_push(c, c->r[R_RBX]);
		c->r[R_RBX] = lock;
		{
			uint8_t *p = gva_host(c->gs_base + 0x10, 8);
			if (p)
				memcpy(&c->r[R_R14], p, 8);
		}
	}
	/* Mark the lock sleepable so the preempt check is skipped, then
	   continue the real acquire. Do not smash the lock word. */
	if ((lock >> 47) == 0x1ffffull) {
		uint8_t *attr = gva_host(lock + 0xa, 1);
		if (attr)
			*attr |= 0x40;
	}
	static int na;
	if (na++ < 6)
		fprintf(stderr, "fast86: rwassert sleepable off=%lx lock=%lx\n",
		        (unsigned long)off, (unsigned long)lock);
	c->rip = b + 0x3f13f3ull;
	f86_set_next(c->rip);
}

static void f86_soft_memop(void)
{
	F86CPU *c = g_cpu;
	if (!c)
		return;
	static int nsoft;
	for (int step = 0; step < (g_alias ? 1 : 32); step++) {
		const uint8_t *ip = f86_gva_code(c->rip, 16);
		F86Insn d;
		if (!ip || !f86_decode(ip, ip + 16, &d) || (d.flags & F86_BAD) || !d.len)
			break;
		if (d.flags & (F86_SYSOP | F86_PRIV | F86_SYSCALL | F86_JCC8 |
		               F86_JCC32 | F86_JMP8 | F86_JMP32 | F86_CALL32 |
		               F86_RET | F86_FF_CALL | F86_FF_JMP | F86_LOOP | F86_WRFS))
			break;
		if (d.opcode0 == 0x8D || !insn_touches_mem(ip, &d))
			break;
		uint64_t igpa = 0;
		if (!f86_gva_to_gpa(c->rip, &igpa))
			break;
		ucontext_t uc;
		memset(&uc, 0, sizeof uc);
		for (int i = 0; i < 16; i++)
			uc.uc_mcontext.gregs[k_greg[i]] = (greg_t)c->r[i];
		uc.uc_mcontext.gregs[REG_EFL] = (greg_t)c->rflags;
		uc.uc_mcontext.gregs[REG_RIP] = (greg_t)igpa;
		uint64_t ea;
		uint8_t op = d.opcode0;
		if (op >= 0x50 && op <= 0x57)
			ea = c->r[R_RSP] - 8;
		else if (op >= 0x58 && op <= 0x5F)
			ea = c->r[R_RSP];
		else if (op == 0x68 || op == 0x6A || op == 0x9C)
			ea = c->r[R_RSP] - 8;
		else if (op == 0x9D || op == 0xC9)
			ea = c->r[R_RSP];
		else if (op == 0xA4 || op == 0xA5 || op == 0xA6 || op == 0xA7)
			ea = c->r[R_RSI];
		else if (op == 0xAA || op == 0xAB)
			ea = c->r[R_RDI];
		else
			ea = compute_ea(c, ip, &d);
		if (!emulate_page0(&uc, (void *)(uintptr_t)ea)) {
			if (g_strop_fault_set) {
				/* a REP string element faulted: deliver #PF there */
				uint64_t cr2 = g_strop_fault_gva;
				uint32_t err = g_strop_fault_err;
				g_strop_fault_set = 0;
				for (int i = 0; i < 16; i++)
					c->r[i] = (uint64_t)uc.uc_mcontext.gregs[k_greg[i]];
				c->rflags = (c->rflags & ~0x8d5ull) |
				            ((uint64_t)uc.uc_mcontext.gregs[REG_EFL] & 0x8d5ull);
				if (f86_sys_inject_exc(c, 14, err, cr2))
					break;
			}
			static int skip = -1;
			if (skip < 0)
				skip = getenv("F86_SKIP_MEMOP") != NULL;
			fprintf(stderr, "fast86: softmem: unhandled %02x%02x at rip=%lx ea=%lx%s\n",
			        d.opcode0, d.opcode1, (unsigned long)c->rip, (unsigned long)ea,
			        skip ? " (skipped)" : "");
			if (!skip) {
				c->exited = 1;
				c->exit_code = 127;
				return;
			}
			c->rip += d.len;
			break;
		}
		for (int i = 0; i < 16; i++)
			c->r[i] = (uint64_t)uc.uc_mcontext.gregs[k_greg[i]];
		c->rflags = (c->rflags & ~0x8d5ull) |
		            ((uint64_t)uc.uc_mcontext.gregs[REG_EFL] & 0x8d5ull);
		uint64_t adv = (uint64_t)uc.uc_mcontext.gregs[REG_RIP] - igpa;
		if (!adv || adv > 15)
			adv = d.len;
		c->rip += adv;
		nsoft++;
		if (nsoft < 8 || (nsoft % 20000) == 0)
			fprintf(stderr, "fast86: softmem n=%d rip=%lx ea=%lx\n",
			        nsoft, (unsigned long)c->rip, (unsigned long)ea);
	}
	f86_set_next(c->rip);
}

static void xlat_fault_inner(int sig, siginfo_t *si, void *u)
{
	ucontext_t *uc = u;
	/* The guest address of the fault: si_addr, or for alias faults the
	   address the guest used (alias faults for RAM are resolved by
	   mapping the page and retrying; the rest fall through to the
	   emulator / #PF injection with the guest address). */
	uint64_t fault_gva = si ? (uint64_t)(uintptr_t)si->si_addr : 0;
	if (sig == SIGSEGV && g_alias && si) {
		uint64_t fa = (uint64_t)(uintptr_t)si->si_addr;
		unsigned long hip0 = uc ? (unsigned long)uc->uc_mcontext.gregs[REG_RIP] : 0;
		int in_jit0 = (g_rx && hip0 >= (unsigned long)g_rx &&
		               hip0 < (unsigned long)g_rx + CACHE_SZ);
		if (fa - (uint64_t)(uintptr_t)g_alias < ALIAS_SZ) {
			uint64_t gva = 0;
			if (alias_populate(fa, &gva))
				return;
			fault_gva = gva;
		} else if (fa && in_jit0) {
			/* Every guest access in cache code goes through FS, so a
			   fault outside the reservation (user VAs above 512 GiB,
			   wild pointers) still names guest EA + offset. */
			fault_gva = fa - g_alias_off;
		} else if (!fa && uc) {
			/* #GP (non-canonical host EA): recover the guest EA from
			   the registers of the faulting cache instruction. */
			const uint8_t *hp = (const uint8_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
			F86Insn fd;
			uint64_t ea = 0;
			if (hp && f86_decode(hp, hp + 16, &fd) && fd.len && uc_ea(uc, hp, &fd, &ea)) {
				fault_gva = ea;
				static int ngp;
				if (ngp++ < 8)
					fprintf(stderr, "fast86: non-canonical alias access gva=%lx\n",
					        (unsigned long)ea);
			}
		}
	}
	if (sig == SIGSEGV && emulate_page0(uc, (void *)(uintptr_t)fault_gva))
		return;
	if (sig == SIGILL && f86_in_system() && f86_sys_bs_exited() && g_cpu) {
		unsigned long hip = uc ? (unsigned long)uc->uc_mcontext.gregs[REG_RIP] : 0;
		uint64_t grip = 0;
		int in_jit = (g_rx && hip >= (unsigned long)g_rx &&
		              hip < (unsigned long)g_rx + CACHE_SZ);
		if (in_jit)
			grip = host_to_guest((uint8_t *)(uintptr_t)hip);
		if (grip)
			g_cpu->rip = grip;
		{
			static int nill;
			const uint8_t *gp = grip ? f86_gva_code(grip, 16) : NULL;
			const uint8_t *hp = (const uint8_t *)(uintptr_t)hip;
			if (nill++ < 12) {
				fprintf(stderr, "fast86: SIGILL guest=%lx host=%lx guest bytes:",
				        (unsigned long)(grip ? grip : g_cpu->rip), hip);
				for (int k = 0; gp && k < 12; k++)
					fprintf(stderr, " %02x", gp[k]);
				fprintf(stderr, "  cache bytes:");
				for (int k = 0; hp && k < 12; k++)
					fprintf(stderr, " %02x", hp[k]);
				fprintf(stderr, "\n");
			}
		}
		/* A #UD in cache code is either a translation bug (report it) or a
		   guest instruction the host refuses at CPL3; skipping it silently
		   (the old behaviour, F86_SKIP_UD=1) corrupted corecrypto's SHA.
		   Inject #UD so the kernel reports it. */
		static int skip_ud = -1;
		if (skip_ud < 0)
			skip_ud = getenv("F86_SKIP_UD") != NULL;
		if (grip && skip_ud && looks_like_code(grip)) {
			const uint8_t *gp = f86_gva_code(grip, 16);
			F86Insn di;
			if (gp && f86_decode(gp, gp + 16, &di) && di.len) {
				g_cpu->rip = grip + di.len;
				void *h = f86_translate(g_cpu, g_cpu->rip);
				if (h && uc) {
					uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)h;
					return;
				}
			}
		}
		if (grip && uc) {
			greg_t *g = uc->uc_mcontext.gregs;
			for (int i = 0; i < 16; i++)
				g_cpu->r[i] = (uint64_t)g[k_greg[i]];
			f86_rflags_set_arch(g_cpu, (f86_rflags_arch(g_cpu) & ~0x8d5ull) | ((uint64_t)g[REG_EFL] & 0x8d5ull));
			if (f86_sys_inject_exc(g_cpu, 6, 0, 0)) {
				for (int i = 0; i < 16; i++)
					g[k_greg[i]] = (greg_t)g_cpu->r[i];
				g[REG_EFL] = (greg_t)(((uint64_t)g[REG_EFL] & ~0x8d5ull) |
				                      (f86_rflags_arch(g_cpu) & 0x8d5ull));
				void *h = f86_translate(g_cpu, g_cpu->rip);
				if (h) {
					g[REG_RIP] = (greg_t)(uintptr_t)h;
					return;
				}
			}
		}
	}
	if (sig == SIGFPE && f86_in_system() && uc) {
		unsigned long hip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
		unsigned char *ip = (unsigned char *)(uintptr_t)hip;
		F86Insn d;
		if (ip && f86_decode(ip, ip + 16, &d) && d.len) {
			static int nfpe;
			if (nfpe++ < 8)
				fprintf(stderr, "fast86: SIGFPE skip op=%02x%02x hip=%lx\n",
				        d.opcode0, d.opcode1, hip);
			uc->uc_mcontext.gregs[REG_RAX] = (greg_t)1000000000ull;
			uc->uc_mcontext.gregs[REG_RDX] = 0;
			uc->uc_mcontext.gregs[REG_RIP] += d.len;
			return;
		}
	}
	if (sig == SIGSEGV && f86_in_system() && f86_sys_bs_exited() && g_cpu && uc &&
	    !(g_scr && *((volatile uint8_t *)g_scr + SCR_OFF_INEXIT))) {
		unsigned long hip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
		int in_jit = (g_rx && hip >= (unsigned long)g_rx &&
		              hip < (unsigned long)g_rx + CACHE_SZ);
		uint64_t grip = in_jit ? host_to_guest((uint8_t *)(uintptr_t)hip) : 0;
		if (grip) {
			greg_t *g = uc->uc_mcontext.gregs;
			for (int i = 0; i < 16; i++)
				g_cpu->r[i] = (uint64_t)g[k_greg[i]];
			g_cpu->rip = grip;
			f86_rflags_set_arch(g_cpu, (f86_rflags_arch(g_cpu) & ~0x8d5ull) | ((uint64_t)g[REG_EFL] & 0x8d5ull));
			uint32_t err = 0; /* not-present, supervisor */
			{
				/* W bit from the faulting instruction (store forms). */
				const uint8_t *fip = (const uint8_t *)(uintptr_t)hip;
				F86Insn fd;
				if (fip && f86_decode(fip, fip + 16, &fd) && fd.len) {
					int o = fd.opcode0;
					if (o == 0x88 || o == 0x89 || o == 0xC6 || o == 0xC7 ||
					    (o < 0x40 && (o & 7) < 2) || o == 0x80 || o == 0x81 ||
					    o == 0x83 || o == 0xFE || o == 0xFF || o == 0xAA ||
					    o == 0xAB || o == 0xA4 || o == 0xA5 || o == 0x86 ||
					    o == 0x87 || (o == 0x0F && (fd.opcode1 == 0xB1 || fd.opcode1 == 0xC1 ||
					                                 fd.opcode1 == 0xAB || fd.opcode1 == 0xB3 ||
					                                 fd.opcode1 == 0x11 || fd.opcode1 == 0x29 ||
					                                 fd.opcode1 == 0x7F)))
						err |= 2;
				}
			}
			{
				static int npf;
				if (npf < 40) {
					uint64_t slide = g_kaddr >= 0x100000ull ? g_kaddr - 0x100000ull : 0;
					fprintf(stderr, "fast86: inject #PF cr2=%lx err=%x rip=%lx (unslid %lx) rsp=%lx\n",
					        (unsigned long)fault_gva, err, (unsigned long)grip,
					        (unsigned long)(grip - slide), (unsigned long)g_cpu->r[R_RSP]);
					npf++;
				}
			}
			{
				extern const char *f86_inject_fail;
				uint64_t slide = g_kaddr >= 0x100000ull ? g_kaddr - 0x100000ull : 0;
				fprintf(stderr, "fast86:   r14=%lx rdi=%lx rsi=%lx stack:", (unsigned long)g_cpu->r[R_R14],
				        (unsigned long)g_cpu->r[R_RDI], (unsigned long)g_cpu->r[R_RSI]);
				for (int k = 0; k < 48; k++) {
					uint64_t w = 0;
					if (!gva_read(g_cpu->r[R_RSP] + 8ull * k, &w, 8))
						break;
					if (w >= 0xffffff8000100000ull + slide && w < 0xffffff8001200000ull + slide)
						fprintf(stderr, " %lx", (unsigned long)(w - slide));
				}
				fprintf(stderr, "\n");
				{
					uint64_t q[16];
					memset(q, 0, sizeof q);
					if (g_cpu->r[R_R14] && gva_read(g_cpu->r[R_R14], q, sizeof q)) {
						fprintf(stderr, "fast86:   [r14]:");
						for (int k = 0; k < 16; k++)
							fprintf(stderr, " %lx", (unsigned long)q[k]);
						fprintf(stderr, "\n");
					}
				}
				(void)f86_inject_fail;
			}
			int injected = f86_sys_inject_exc(g_cpu, 14, err, fault_gva);
			if (!injected) {
				extern const char *f86_inject_fail;
				fprintf(stderr, "fast86: #PF injection failed: %s (idt_base=%lx)\n",
				        f86_inject_fail, (unsigned long)g_cpu->idt_base);
			}
			if (injected) {
				for (int i = 0; i < 16; i++)
					g[k_greg[i]] = (greg_t)g_cpu->r[i];
				g[REG_EFL] = (greg_t)(((uint64_t)g[REG_EFL] & ~0x8d5ull) |
				                      (f86_rflags_arch(g_cpu) & 0x8d5ull));
				void *h = f86_translate(g_cpu, g_cpu->rip);
				if (h) {
					g[REG_RIP] = (greg_t)(uintptr_t)h;
					return;
				}
			}
		}
	}
	{
		char buf[160];
		int n = snprintf(buf, sizeof buf, "fast86: FAULT sig=%d addr=%p rip=%lx\n",
		                 sig, si ? si->si_addr : NULL,
		                 uc ? (unsigned long)uc->uc_mcontext.gregs[REG_RIP] : 0);
		if (n > 0)
			write(2, buf, (size_t)n);
	}
	unsigned long ip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
	fprintf(stderr,
	        "fast86: %s si_addr=%p rip=%lx rax=%lx rcx=%lx rdx=%lx rbx=%lx rsp=%lx r11=%lx guest_rip=%lx\n",
	        sig == SIGSEGV ? "SIGSEGV" : sig == SIGFPE ? "SIGFPE" : "SIGILL",
	        si->si_addr, ip,
	        (unsigned long)uc->uc_mcontext.gregs[REG_RAX],
	        (unsigned long)uc->uc_mcontext.gregs[REG_RCX],
	        (unsigned long)uc->uc_mcontext.gregs[REG_RDX],
	        (unsigned long)uc->uc_mcontext.gregs[REG_RBX],
	        (unsigned long)uc->uc_mcontext.gregs[REG_RSP],
	        (unsigned long)uc->uc_mcontext.gregs[REG_R11],
	        (unsigned long)(g_cpu ? g_cpu->rip : 0));
	if (ip > 0x10000 && ip < 0x0000800000000000ull) {
		unsigned char *p = (unsigned char *)(ip - 16);
		fprintf(stderr, "  around");
		for (int i = 0; i < 32; i++) {
			if (i == 16)
				fprintf(stderr, " |");
			fprintf(stderr, " %02x", p[i]);
		}
		fprintf(stderr, "\n");
	}
	fflush(stderr);
	wr_fs(g_host_fs);
	if (f86_in_system())
		wr_gs(g_host_gs);
	_exit(139);
}

static void xlat_fault(int sig, siginfo_t *si, void *u)
{
	if (!f86_in_system()) {
		xlat_fault_inner(sig, si, u);
		return;
	}
	/* Guest code runs with FS = alias offset and GS = guest GS; glibc
	   (fprintf, errno) in the handler needs the host bases. */
	uint64_t sfs = rd_fs(), sgs = rd_gs();
	wr_fs(g_host_fs);
	wr_gs(g_host_gs);
	xlat_fault_inner(sig, si, u);
	wr_fs(sfs);
	wr_gs(sgs);
}

static void *mmap_above_4g(size_t n, int prot, int flags, int fd, off_t off)
{
	static uintptr_t hint = 0x100000000ull;
	void *p = mmap((void *)hint, n, prot, flags, fd, off);
	if (p != MAP_FAILED) {
		uintptr_t e = (uintptr_t)p + n;
		if (e > hint)
			hint = (e + 0xffffffull) & ~0xffffffull;
		return p;
	}
	return mmap(NULL, n, prot, flags, fd, off);
}

static int map_code_cache(void)
{
	int fd = memfd_create("f86cache", 0);
	if (fd >= 0 && ftruncate(fd, CACHE_SZ) == 0) {
		g_rw = mmap_above_4g(CACHE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		g_rx = mmap_above_4g(CACHE_SZ, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
		close(fd);
		if (g_rw != MAP_FAILED && g_rx != MAP_FAILED)
			return 0;
	}
	g_rw = mmap_above_4g(CACHE_SZ, PROT_READ | PROT_WRITE | PROT_EXEC,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	g_rx = g_rw;
	return g_rw == MAP_FAILED ? -1 : 0;
}

void f86_cache_init(void)
{
	init_env_flags();
	if (map_code_cache() != 0) {
		perror("mmap cache");
		exit(1);
	}
	g_emit = g_rw;
	g_cend = g_rw + CACHE_SZ - 4096;
	memset(g_map, 0, sizeof(g_map));
	g_scr = mmap((void *)SCRATCH, 2u << 20, PROT_READ | PROT_WRITE,
	             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (g_scr == MAP_FAILED) {
		perror("mmap scratch");
		exit(1);
	}
	g_exit_tramp = NULL;
	alias_reserve();
}

static uint8_t *g_emit_base;
static int g_half;

void f86_cache_flush(void)
{
	memset(g_map, 0, sizeof(g_map));
	memset(g_phead, 0, sizeof(g_phead));
	g_npatch = 0;
	g_nrev = 0;
	g_nspec = 0;
	g_stride_done = 0;
	g_irq_ok = 0;
	g_vminit_ready = 0;
	if (g_emit_base) {
		/* Flushes run inside C helpers whose stub tail (segment restore,
		   register fill, dispatch) still executes from the cache after the
		   helper returns. Restarting emission at the base overwrote that
		   tail whenever the stub sat in one of the first blocks
		   (benches/syspop.S: a MOV CR3 in the third block returned into
		   the middle of a movabs). Alternate between two halves: the half
		   holding the running stub is not reused before the next flush,
		   and that cannot happen before its tail has run. */
		size_t half = (size_t)((g_rw + CACHE_SZ - 4096) - g_emit_base) / 2;
		g_half ^= 1;
		g_emit = g_emit_base + (size_t)g_half * half;
		g_cend = g_emit + half;
	}
	/* Shadow return stack holds host addresses into the cache: drop it,
	   or a RET after the flush jumps into overwritten code (B3). */
	if (g_scr)
		*(volatile uint64_t *)((uint8_t *)g_scr + SCR_OFF_SHN) = 0;
}

void f86_set_next(uint64_t guest_rip)
{
	if (!g_cpu)
		return;
	g_next_host = f86_translate(g_cpu, guest_rip);
}

void f86_replant_dt(void)
{
	if (!g_dt_slot || !g_dt_phys || !f86_ram())
		return;
	if (g_dt_slot + 24 >= f86_ram_size())
		return;
	uint64_t cur = 0;
	memcpy(&cur, f86_ram() + g_dt_slot, 8);
	if (cur >= 0xffffff8000000000ull && (cur >> 40) != 0xffffdeull)
		return;
	uint64_t dt_va = 0xffffff8000000000ull | g_dt_phys;
	uint64_t ln = 0;
	memcpy(&ln, f86_ram() + g_dt_slot + 8, 8);
	if (ln < 8)
		ln = 0x1ab8;
	uint64_t en = dt_va + ln;
	memcpy(f86_ram() + g_dt_slot, &dt_va, 8);
	memcpy(f86_ram() + g_dt_slot + 8, &ln, 8);
	memcpy(f86_ram() + g_dt_slot + 16, &en, 8);
	static int n;
	if (n++ < 4)
		fprintf(stderr, "fast86: replant DTStart was %lx now %lx\n",
		        (unsigned long)cur, (unsigned long)dt_va);
}

void f86_irq_from_signal(void *u)
{
	ucontext_t *uc = u;
	uint64_t save_fs = rd_fs();
	uint64_t save_gs = f86_in_system() ? rd_gs() : 0;
	wr_fs(g_host_fs);
	if (f86_in_system())
		wr_gs(g_host_gs);
	f86_sys_timer_pulse();
	F86CPU *c = g_cpu;
	if (!c || c->exited)
		goto out;
	unsigned long hip = uc ? (unsigned long)uc->uc_mcontext.gregs[REG_RIP] : 0;
	int in_jit = (g_rx && hip >= (unsigned long)g_rx &&
	              hip < (unsigned long)g_rx + CACHE_SZ);
	static int nt;
	static uint64_t last_hip, same_count;
	if (hip == last_hip && hip)
		same_count++;
	else
		same_count = 0;
	last_hip = hip;
	if (same_count == 2 && getenv("F86_BT")) {
		void *ba[20];
		int n = backtrace(ba, 20);
		fprintf(stderr, "fast86: host backtrace:\n");
		backtrace_symbols_fd(ba, n, 2);
	}
	if ((same_count == 3 || same_count == 50) && uc && in_jit) {
		/* Guest is spinning at one host PC: dump the live registers and
		   the memory each pointer register addresses, so lock spins can
		   be diagnosed (which word, which bit, what value). */
		static const int gr[16] = { REG_RAX, REG_RCX, REG_RDX, REG_RBX,
			REG_RSP, REG_RBP, REG_RSI, REG_RDI, REG_R8, REG_R9, REG_R10,
			REG_R11, REG_R12, REG_R13, REG_R14, REG_R15 };
		static const char *gn[16] = { "rax", "rcx", "rdx", "rbx", "rsp",
			"rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
			"r14", "r15" };
		fprintf(stderr, "fast86: spin#%lu guest=%lx hip=%lx\n",
		        (unsigned long)same_count, (unsigned long)host_to_guest((uint8_t *)hip),
		        hip);
		for (int i = 0; i < 16; i++) {
			uint64_t v = (uint64_t)uc->uc_mcontext.gregs[gr[i]], g = 0, m = 0;
			int ok = v >= 0x1000 && f86_gva_to_gpa(v, &g) && g + 8 <= f86_ram_size();
			if (ok)
				memcpy(&m, f86_ram() + g, 8);
			fprintf(stderr, "  %-3s=%016lx%s", gn[i], (unsigned long)v, ok ? " ->" : "   ");
			if (ok)
				fprintf(stderr, " gpa=%lx [%016lx]", (unsigned long)g, (unsigned long)m);
			fprintf(stderr, "\n");
		}
	}
	if (nt < 8 || (nt % 400) == 0) {
		uint64_t g2 = 0;
		uint64_t base = 0xffffff8000000000ull |
		                ((g_kaddr - 0x100000ull) & 0xffffffffull);
		if (g_kaddr >= 0x100000ull) {
			uint64_t ci = 0, cg = 0;
			if (f86_gva_to_gpa(base + 0x1192368ull, &cg) &&
			    cg + 8 < f86_ram_size()) {
				memcpy(&ci, f86_ram() + cg, 8);
				uint64_t cg2 = 0;
				if (ci && f86_gva_to_gpa(ci, &cg2) && cg2 + 0x1f0 < f86_ram_size()) {
					uint32_t fam = 0, mod = 0, cf = 0, n = 0, m = 0;
					memcpy(&fam, f86_ram() + cg2 + 0x4c, 4);
					memcpy(&mod, f86_ram() + cg2 + 0x4d, 1);
					memcpy(&cf, f86_ram() + cg2 + 0x1a0, 4);
					memcpy(&n, f86_ram() + cg2 + 0x1d8, 4);
					memcpy(&m, f86_ram() + cg2 + 0x1dc, 4);
					fprintf(stderr,
					        "fast86: cpuinfo@%lx fam=%u model=%02x cpufamily=%x N=%u M=%u\n",
					        (unsigned long)ci, fam, mod, cf, n, m);
				}
			}
		}
		if (g_kaddr >= 0x100000ull &&
		    f86_gva_to_gpa(c->rip - 0x22, &g2) && g2 + 64 < f86_ram_size()) {
			uint8_t b[64];
			memcpy(b, f86_ram() + g2, 64);
			fprintf(stderr, "fast86: bytes@%lx:", (unsigned long)(c->rip - 0x22));
			for (int i = 0; i < 64; i++)
				fprintf(stderr, " %02x", b[i]);
			fprintf(stderr, "\n");
			/* find a 48 8b 05 disp32 in the window */
			for (int i = 0; i + 7 < 64; i++) {
				if (b[i] == 0x48 && b[i + 1] == 0x8b && b[i + 2] == 0x05) {
					int32_t disp = (int32_t)(b[i + 3] | (b[i + 4] << 8) |
					                         (b[i + 5] << 16) | (b[i + 6] << 24));
					uint64_t tgt = (c->rip - 0x22) + i + 7 + (int64_t)disp;
					uint64_t g3 = 0;
					uint64_t v[4] = { 0, 0, 0, 0 };
					if (f86_gva_to_gpa(tgt, &g3) && g3 + 32 < f86_ram_size())
						memcpy(v, f86_ram() + g3, 32);
					fprintf(stderr,
					        "fast86: mov(rip+%lx)=%lx -> %lx %lx %lx %lx\n",
					        (unsigned long)(int64_t)disp, (unsigned long)tgt,
					        (unsigned long)v[0], (unsigned long)v[1],
					        (unsigned long)v[2], (unsigned long)v[3]);
					break;
				}
			}
		}
		fprintf(stderr,
		        "fast86: tick host=%lx guest=%lx jit=%d cr=%lx cr3=%lx if=%d idt=%lx pend\n",
		        hip, (unsigned long)c->rip, in_jit,
		        (unsigned long)c->cr0, (unsigned long)c->cr3,
		        f86_sys_if(), (unsigned long)c->idt_base);
	}
	nt++;
	int inexit = g_scr ? *((volatile uint8_t *)g_scr + SCR_OFF_INEXIT) : 0;
	if (in_jit && uc && !inexit) {
		uint64_t grip = host_to_guest_exact((uint8_t *)(uintptr_t)hip);
		if (grip) {
			greg_t *g = uc->uc_mcontext.gregs;
			uint64_t hrs = (uint64_t)g[REG_RSP];
			/* Only publish GPRs when the JIT is on the guest stack.
			   Helper stubs keep host RSP and scratch rax. */
			if ((hrs >> 47) == 0x1ffffull) {
				for (int i = 0; i < 16; i++)
					c->r[i] = (uint64_t)g[k_greg[i]];
				f86_rflags_set_arch(c, (f86_rflags_arch(c) & ~0x8d5ull) | ((uint64_t)g[REG_EFL] & 0x8d5ull));
			}
			c->rip = grip;
			if ((grip & 0xffff) == 0x4910 || (grip & 0xffff) == 0x491a) {
				static int ns;
				if (ns++ < 4)
					fprintf(stderr,
					        "fast86: scan r15=%lx rax=%lx r12=%lx\n",
					        (unsigned long)c->r[R_R15], (unsigned long)c->r[R_RAX],
					        (unsigned long)c->r[R_R12]);
			}
			if (f86_sys_deliver_irq(c)) {
				for (int i = 0; i < 16; i++)
					g[k_greg[i]] = (greg_t)c->r[i];
				g[REG_EFL] = (greg_t)(((uint64_t)g[REG_EFL] & ~0x8d5ull) |
				                      (f86_rflags_arch(c) & 0x8d5ull));
				void *h = f86_translate(c, c->rip);
				if (h)
					g[REG_RIP] = (greg_t)(uintptr_t)h;
			}
		}
	}
out_gs:
	;
out:
	wr_fs(save_fs);
	if (f86_in_system())
		wr_gs(save_gs);
}

static void on_sigterm(int sig)
{
	(void)sig;
	if (g_cpu) {
		g_cpu->exited = 1;
		g_cpu->exit_code = 143;
	}
}

void f86_run(F86CPU *cpu, uint64_t entry)
{
	g_cpu = cpu;
	g_host_fs = rd_fs();
	g_host_gs = rd_gs();
	alias_reserve(); /* system mode is only known once f86_sys_init ran */
	if (f86_in_system())
		f86_sys_refresh_gs();
	if (!cpu->fs_base && !f86_in_system())
		cpu->fs_base = g_host_fs;
	cpu->rip = entry;
	/* Shared exit trampoline embeds &g_cpu / &g_host_fs — emit it now. */
	if (!g_exit_tramp) {
		g_exit_tramp = rx_of(g_emit);
		emit_exit_body();
		while ((uintptr_t)g_emit & 15)
			em1(0x90);
		g_emit_base = g_emit;
	}
	{
		static char altstk[1 << 18];
		stack_t ss;
		memset(&ss, 0, sizeof ss);
		ss.ss_sp = altstk;
		ss.ss_size = sizeof altstk;
		sigaltstack(&ss, NULL);
		struct sigaction sa;
		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = xlat_fault;
		sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
		sigaddset(&sa.sa_mask, SIGALRM); /* the tick walks page tables too */
		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGILL, &sa, NULL);
		sigaction(SIGFPE, &sa, NULL);
		sigaction(SIGBUS, &sa, NULL);
		/* SIGTERM: stop at the next helper so the exit statistics print */
		struct sigaction st;
		memset(&st, 0, sizeof st);
		st.sa_handler = on_sigterm;
		sigaction(SIGTERM, &st, NULL);
	}
	g_next_host = f86_translate(cpu, entry);

	uint8_t *prolog = g_emit;
	emit_guest_segs();
	emit_fill_all();
	emit_jmp_next_host();
	void (*fn)(void) = (void (*)(void))rx_of(prolog);
	if (setjmp(g_done) == 0)
		fn();
	wr_fs(g_host_fs);
	if (f86_in_system())
		wr_gs(g_host_gs);
}

/* ---------------- ELF + stack ---------------- */

static uint64_t g_phdr_addr, g_phnum;
static uint64_t g_text_lo[8], g_text_hi[8];
static int g_ntext;

int f86_load_elf(const char *path, uint64_t *entry, uint64_t *brk_out)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		return -1;
	}
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}
	uint8_t *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return -1;

	Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_machine != EM_X86_64) {
		fprintf(stderr, "fast86: not an x86_64 ELF\n");
		munmap(map, (size_t)st.st_size);
		return -1;
	}
	if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
		fprintf(stderr, "fast86: need ET_EXEC or ET_DYN\n");
		munmap(map, (size_t)st.st_size);
		return -1;
	}

	uint64_t load_bias = 0;
	if (eh->e_type == ET_DYN)
		load_bias = 0x400000;
	g_ntext = 0;

	Elf64_Phdr *ph = (Elf64_Phdr *)(map + eh->e_phoff);
	uint64_t brk = 0;
	g_phnum = eh->e_phnum;
	g_phdr_addr = 0;

	for (int i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD)
			continue;
		uint64_t va = ph[i].p_vaddr + load_bias;
		uint64_t mem = ph[i].p_memsz;
		uint64_t fo = ph[i].p_offset;
		uint64_t fs = ph[i].p_filesz;
		uint64_t page = va & ~0xfffull;
		uint64_t end = (va + mem + 0xfff) & ~0xfffull;
		int prot = PROT_READ | PROT_WRITE | PROT_EXEC;

		void *p = mmap((void *)page, end - page, prot,
		               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (p == MAP_FAILED) {
			perror("mmap load");
			munmap(map, (size_t)st.st_size);
			return -1;
		}
		memcpy((void *)va, map + fo, (size_t)fs);
		if ((ph[i].p_flags & PF_X) && g_ntext < 8) {
			g_text_lo[g_ntext] = va;
			g_text_hi[g_ntext] = va + fs;
			g_ntext++;
		}
		if (va + mem > brk)
			brk = va + mem;
		if (!g_phdr_addr)
			g_phdr_addr = va - ph[i].p_offset + eh->e_phoff;
	}
	*entry = eh->e_entry + load_bias;
	*brk_out = brk;
	munmap(map, (size_t)st.st_size);
	return 0;
}

int f86_setup_stack(F86CPU *cpu, int argc, char **argv, char **envp,
                    uint64_t entry, uint64_t phdr, uint64_t phnum)
{
	if (phdr)
		g_phdr_addr = phdr;
	if (phnum)
		g_phnum = phnum;
	const size_t SZ = 8 << 20;
	uint8_t *stk = mmap(NULL, SZ, PROT_READ | PROT_WRITE,
	                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stk == MAP_FAILED)
		return -1;
	uint8_t *top = stk + SZ;
	uint64_t rnd[2] = { 0x1111111111111111ull, 0x2222222222222222ull };

	char **e = envp;
	int envc = 0;
	if (e)
		while (e[envc]) envc++;

	char *strp = (char *)top;
	char **argp = calloc((size_t)argc + 1, sizeof(char *));
	char **envP = calloc((size_t)envc + 1, sizeof(char *));
	if (!argp || !envP) {
		free(argp);
		free(envP);
		return -1;
	}
	for (int i = argc - 1; i >= 0; i--) {
		size_t n = strlen(argv[i]) + 1;
		strp -= n;
		memcpy(strp, argv[i], n);
		argp[i] = strp;
	}
	for (int i = envc - 1; i >= 0; i--) {
		size_t n = strlen(envp[i]) + 1;
		strp -= n;
		memcpy(strp, envp[i], n);
		envP[i] = strp;
	}
	strp -= 16;
	memcpy(strp, rnd, 16);
	char *rndp = strp;
	strp = (char *)((uintptr_t)strp & ~0xfull);

	uint64_t *w = (uint64_t *)strp;
	#define PUSH(v) do { *--w = (uint64_t)(v); } while (0)
	PUSH(0); PUSH(AT_NULL);
	PUSH((uint64_t)rndp); PUSH(AT_RANDOM);
	PUSH(entry); PUSH(AT_ENTRY);
	PUSH(0x1000); PUSH(AT_PAGESZ);
	PUSH(g_phnum); PUSH(AT_PHNUM);
	PUSH(56); PUSH(AT_PHENT);
	PUSH(g_phdr_addr); PUSH(AT_PHDR);
	PUSH(getauxval(AT_HWCAP)); PUSH(AT_HWCAP);
#ifdef AT_HWCAP2
	PUSH(getauxval(AT_HWCAP2)); PUSH(AT_HWCAP2);
#endif
#ifdef AT_MINSIGSTKSZ
	{
		unsigned long mss = getauxval(AT_MINSIGSTKSZ);
		if (mss) {
			PUSH(mss); PUSH(AT_MINSIGSTKSZ);
		}
	}
#endif
	PUSH((uint64_t)sysconf(_SC_CLK_TCK)); PUSH(AT_CLKTCK);
	PUSH(0); PUSH(AT_SECURE);
	PUSH(0); PUSH(AT_FLAGS);
	PUSH(0); PUSH(AT_BASE);
	PUSH(getuid()); PUSH(AT_UID);
	PUSH(geteuid()); PUSH(AT_EUID);
	PUSH(getgid()); PUSH(AT_GID);
	PUSH(getegid()); PUSH(AT_EGID);
	PUSH(0);
	for (int i = envc - 1; i >= 0; i--)
		PUSH(envP[i]);
	PUSH(0);
	for (int i = argc - 1; i >= 0; i--)
		PUSH(argp[i]);
	PUSH((uint64_t)argc);
	#undef PUSH
	if ((uintptr_t)w & 0xf) {
		size_t nbytes = (size_t)((char *)strp - (char *)w);
		uint64_t *nw = w - 1;
		memmove(nw, w, nbytes);
		w = nw;
	}
	cpu->r[R_RSP] = (uint64_t)w;
	cpu->r[R_RDX] = 0;
	free(argp);
	free(envP);
	return 0;
}

static uint64_t g_sys_site[MAX_SYS];
static int g_nsys;

static int sys_site_hit(uint64_t rip)
{
	for (int i = 0; i < g_nsys; i++)
		if (g_sys_site[i] == rip)
			return 1;
	return 0;
}

static void sys_site_add(uint64_t rip)
{
	if (g_nsys < MAX_SYS)
		g_sys_site[g_nsys++] = rip;
}

static void direct_trap(int sig, siginfo_t *si, void *u)
{
	(void)si;
	ucontext_t *uc = u;
	greg_t *g = uc->uc_mcontext.gregs;
	uint64_t rip = (uint64_t)g[REG_RIP];
	unsigned long guest_fs = rd_fs();
	wr_fs(g_host_fs);
	if (sig == SIGTRAP)
		rip -= 1;
	if (!sys_site_hit(rip)) {
		if ((sig == SIGSEGV || sig == SIGILL) &&
		    (uint64_t)g[REG_RIP] > 0x1000 &&
		    *(uint8_t *)g[REG_RIP] == 0xF4) {
			g_cpu->exit_code = 127;
			g_cpu->exited = 1;
			longjmp(g_done, 1);
		}
		wr_fs(g_cpu->fs_base ? g_cpu->fs_base : guest_fs);
		abort();
	}
	g_cpu->r[R_RAX] = (uint64_t)g[REG_RAX];
	g_cpu->r[R_RDI] = (uint64_t)g[REG_RDI];
	g_cpu->r[R_RSI] = (uint64_t)g[REG_RSI];
	g_cpu->r[R_RDX] = (uint64_t)g[REG_RDX];
	g_cpu->r[R_R10] = (uint64_t)g[REG_R10];
	g_cpu->r[R_R8]  = (uint64_t)g[REG_R8];
	g_cpu->r[R_R9]  = (uint64_t)g[REG_R9];
	g_cpu->r[R_RSP] = (uint64_t)g[REG_RSP];
	if (!g_cpu->fs_base)
		g_cpu->fs_base = guest_fs;
	long r = f86_do_syscall(g_cpu);
	if (g_cpu->exited)
		longjmp(g_done, 1);
	g[REG_RAX] = (greg_t)r;
	g[REG_RIP] = (greg_t)(rip + 2);
	wr_fs(g_cpu->fs_base);
}

void f86_run_direct(F86CPU *cpu, uint64_t entry)
{
	init_env_flags();
	g_cpu = cpu;
	g_host_fs = rd_fs();
	cpu->fs_base = g_host_fs;
	g_nsys = 0;
	memset(g_sys_site, 0, sizeof(g_sys_site));
	for (int t = 0; t < g_ntext; t++) {
		uint8_t *p = (uint8_t *)g_text_lo[t];
		uint8_t *end = (uint8_t *)g_text_hi[t];
		while (p + 1 < end) {
			F86Insn d;
			if (!f86_decode(p, end, &d) || d.len == 0) {
				p++;
				continue;
			}
			if ((d.flags & F86_SYSCALL) && g_nsys < MAX_SYS) {
				sys_site_add((uint64_t)p);
				p[0] = 0xCC;
				p[1] = 0x90;
			}
			p += d.len;
		}
	}
	if (g_dbg)
		fprintf(stderr, "direct: patched %d syscalls\n", g_nsys);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = direct_trap;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);

	if (setjmp(g_done) != 0)
		return;

	uint64_t rsp = cpu->r[R_RSP];
	__asm__ volatile(
		"mov %[rsp], %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"xor %%rdx, %%rdx\n"
		"jmp *%[entry]\n"
		:
		: [rsp] "r"(rsp), [entry] "r"(entry)
		: "memory", "rdx", "rbp");
	__builtin_unreachable();
}
