#define _GNU_SOURCE
#include "f86.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define CR0_PE (1ull << 0)
#define CR0_PG (1ull << 31)
#define EFER_LME (1ull << 8)
#define EFER_LMA (1ull << 10)

#define BS_MAGIC 0x465536425353ull /* "F86BSS" */

static int      g_system;
static int      g_exited_bs;
static uint8_t *g_ram;
static size_t   g_ram_sz;
static int      g_ram_fd = -1;
static char     g_root[512];
static char     g_mac_root[512];
static char     g_image_path[512];
static uint64_t g_alloc_next;
static uint8_t  g_idbit[256]; /* 2048 x 2MiB granules in 4GiB */
static uint64_t g_image_base, g_image_size;
static int      g_disk_fd = -1;
static uint8_t *g_disk_map;
static size_t   g_disk_sz;
static uint64_t g_part_lba, g_part_n;
extern F86CPU *f86_alive_cpu(void);

/* engine exports used here */
void f86_cache_flush(void);
extern void f86_halt(void);

static F86CPU *cpu(void)
{
	return f86_alive_cpu();
}

int f86_in_system(void) { return g_system; }

int f86_sys_is_mmio(uint64_t addr)
{
	if (addr >= 0xf0000000ull && addr < 0x100000000ull)
		return 1; /* PCI ECAM (MMCONFIG) window, 256 buses */
	if (addr >= 0xfe000000ull && addr < 0xfe100000ull)
		return 1;
	if (addr >= 0xfec00000ull && addr < 0xfec02000ull)
		return 1;
	if (addr >= 0xfed00000ull && addr < 0xfed01000ull)
		return 1;
	if (addr >= 0xfee00000ull && addr < 0xfee01000ull)
		return 1;
	return 0;
}

static uint8_t  g_uart_lsr = 0x60;
static uint32_t g_lapic[256];
static uint32_t g_lapic_cur;
static uint8_t  g_ioapic_idx;
static uint32_t g_ioapic_red[48];
static uint64_t g_hpet_cfg = 1;
static uint64_t g_hpet_cmp;
static uint64_t g_hpet_t0cfg;
static uint64_t g_hpet_cnt;
static uint32_t g_pending_irq;
static uint64_t g_tsc_deadline;
uint64_t g_invpcid_n[4];
static uint64_t g_star, g_lstar, g_cstar, g_sfmask;
static uint32_t g_pci_addr;
static uint8_t  g_cmos_idx;
static uint8_t  g_cmos[128];
static uint8_t  g_pic_mask[2] = { 0xff, 0xff };
static uint8_t  g_pic_isr[2];
static uint16_t g_pit_div;
static int      g_pit_phase;
static uint8_t  g_pit_lat;
static uint32_t g_pm_tmr;
static uint64_t g_xcr0 = 0x7; /* x87 | SSE | AVX */

/* Virtual IF and DF. c->rflags holds the translator's packed status flags
   (bits 7:0 = OF, bits 15:8 = LAHF byte: SF ZF 0 AF 0 PF 1 CF; bits 63:16
   are junk from the spill). Bit 9 of that word is LAHF's constant 1, so it
   must never be read as IF. Interrupt frames, IRET, SYSCALL/SYSRET and
   PUSHF/POPF convert between the packed form and architectural RFLAGS. */
static int g_vif = 1, g_vdf = 0;
int f86_sys_if(void) { return g_vif; }
int f86_sys_df(void) { return g_vdf; }

uint64_t f86_rflags_arch(const F86CPU *c)
{
	uint64_t p = c->rflags, a = 0x2;
	if (p & 0x100) a |= 1;        /* CF */
	if (p & 0x400) a |= 4;        /* PF */
	if (p & 0x1000) a |= 0x10;    /* AF */
	if (p & 0x4000) a |= 0x40;    /* ZF */
	if (p & 0x8000) a |= 0x80;    /* SF */
	if (p & 0x1) a |= 0x800;      /* OF */
	if (g_vif) a |= 0x200;
	if (g_vdf) a |= 0x400;
	return a;
}

void f86_rflags_set_arch(F86CPU *c, uint64_t a)
{
	uint64_t p = 0x200; /* LAHF constant bit */
	if (a & 1) p |= 0x100;
	if (a & 4) p |= 0x400;
	if (a & 0x10) p |= 0x1000;
	if (a & 0x40) p |= 0x4000;
	if (a & 0x80) p |= 0x8000;
	if (a & 0x800) p |= 0x1;
	c->rflags = (c->rflags & ~0xffffull) | p;
	g_vif = (a >> 9) & 1;
	g_vdf = (a >> 10) & 1;
}
static uint32_t g_irq_n;
static uint64_t g_idt_gpa;
static uint64_t g_dummy_cpu = 0x104000;
uint64_t f86_gs_host;
#define GS_POISON 0xffffdeadbeefee00ull

/* PCI config space model. Minimal q35-ish topology; everything else reads as
   an absent device (0xffffffff) so guest PCI scans terminate cleanly. */
static uint32_t pci_cfg_read(uint32_t bus, uint32_t dev, uint32_t fn, uint32_t reg)
{
	if (bus == 0 && dev == 0 && fn == 0) {
		if (reg == 0x00)
			return 0x29c08086u; /* vendor 0x8086, device 0x29c0 (host bridge) */
		if (reg == 0x08)
			return 0x06000000u; /* class code: bridge / host */
		return 0;
	}
	if (bus == 0 && dev == 0x1f && fn == 0) {
		/* ICH9 LPC bridge (q35). OpenCore finds the ACPI PM timer through
		   PMBASE/ACPI_CNTL here and measures the TSC rate against it. */
		if (reg == 0x00)
			return 0x29188086u;
		if (reg == 0x08)
			return 0x06010002u; /* ISA bridge */
		if (reg == 0x0c)
			return 0x00800000u; /* multifunction header */
		if (reg == 0x40)
			return 0x00000401u; /* PMBASE = 0x400 (I/O) */
		if (reg == 0x44)
			return 0x00000080u; /* ACPI_CNTL.ACPI_EN */
		return 0;
	}
	return 0xffffffffu;
}

static void pci_cfg_write(uint32_t bus, uint32_t dev, uint32_t fn, uint32_t reg,
                          uint32_t v)
{
	(void)bus; (void)dev; (void)fn; (void)reg; (void)v;
}

static uint64_t ecam_read(uint64_t addr, int sz)
{
	uint32_t off = (uint32_t)(addr - 0xf0000000ull);
	uint32_t bus = (off >> 20) & 0xff;
	uint32_t dev = (off >> 15) & 0x1f;
	uint32_t fn  = (off >> 12) & 0x7;
	uint32_t reg = off & 0xfff;
	if (sz == 8) {
		uint64_t lo = pci_cfg_read(bus, dev, fn, reg & ~7u);
		uint64_t hi = pci_cfg_read(bus, dev, fn, (reg & ~7u) + 4);
		return lo | (hi << 32);
	}
	uint32_t v = pci_cfg_read(bus, dev, fn, reg & ~3u);
	if (sz == 1)
		return (v >> ((reg & 3) * 8)) & 0xff;
	if (sz == 2)
		return (v >> ((reg & 3) * 8)) & 0xffff;
	return v;
}

static void ecam_write(uint64_t addr, uint64_t v, int sz)
{
	uint32_t off = (uint32_t)(addr - 0xf0000000ull);
	uint32_t bus = (off >> 20) & 0xff;
	uint32_t dev = (off >> 15) & 0x1f;
	uint32_t fn  = (off >> 12) & 0x7;
	uint32_t reg = off & 0xfff;
	pci_cfg_write(bus, dev, fn, reg & ~3u, (uint32_t)v);
	(void)sz;
}

static int in_device_window(uint64_t addr)
{
	/* LAPIC, IOAPIC, HPET and the debug UART sit inside the ECAM range;
	   they must be matched before the PCI config window swallows them. */
	return (addr >= 0xfee00000ull && addr < 0xfee01000ull) ||
	       (addr >= 0xfec00000ull && addr < 0xfec02000ull) ||
	       (addr >= 0xfed00000ull && addr < 0xfed01000ull) ||
	       (addr >= 0xfe036000ull && addr < 0xfe038000ull);
}

uint64_t f86_sys_mmio_read(uint64_t addr, int sz)
{
	uint64_t v = 0;
	if (addr >= 0xf0000000ull && addr < 0x100000000ull && !in_device_window(addr))
		return ecam_read(addr, sz);
	if (addr >= 0xfe036000ull && addr < 0xfe036020ull) {
		uint64_t off = addr - 0xfe036000ull;
		if (off == 0x14)
			v = g_uart_lsr;
		else if (off == 0)
			v = 0;
		else
			v = 0;
		return v & (sz == 1 ? 0xff : sz == 2 ? 0xffff : 0xffffffffu);
	}
	if (addr >= 0xfe037000ull && addr < 0xfe038000ull)
		return 0;
	if (addr >= 0xfee00000ull && addr < 0xfee01000ull) {
		uint32_t off = (uint32_t)(addr - 0xfee00000ull);
		uint32_t i = off / 4;
		if (i >= 256)
			return 0;
		if (off == 0x20)
			return 0; /* APIC ID */
		if (off == 0x30)
			return g_lapic[i] ? g_lapic[i] : 0x00050014;
		if (off == 0x80)
			return g_lapic[i];
		if (off == 0xf0)
			return g_lapic[i] ? g_lapic[i] : 0x1ff;
		if (off == 0x390)
			return g_lapic_cur;
		return g_lapic[i];
	}
	if (addr >= 0xfec00000ull && addr < 0xfec02000ull) {
		if ((addr & 0xff) == 0)
			return g_ioapic_idx;
		if ((addr & 0xff) == 0x10) {
			if (g_ioapic_idx == 0)
				return 0;
			if (g_ioapic_idx == 1)
				return 0x00170011; /* 24 entries, version 0x11 */
			if (g_ioapic_idx >= 0x10 && g_ioapic_idx < 0x40)
				return g_ioapic_red[g_ioapic_idx - 0x10];
		}
		return 0;
	}
	if (addr >= 0xfed00000ull && addr < 0xfed01000ull) {
		uint64_t off = addr - 0xfed00000ull;
		if (off == 0)
			return 0x8086a201008086a2ull; /* cap: 64-bit, 1 timer, 14.32MHz-ish */
		if (off == 0x10)
			return g_hpet_cfg;
		if (off == 0xf0)
			return g_hpet_cnt;
		if (off == 0x100)
			return g_hpet_t0cfg;
		if (off == 0x108)
			return g_hpet_cmp;
		return 0;
	}
	(void)sz;
	return 0xffffffffu;
}

void f86_sys_mmio_write(uint64_t addr, uint64_t v, int sz)
{
	if (addr >= 0xf0000000ull && addr < 0x100000000ull && !in_device_window(addr)) {
		ecam_write(addr, v, sz);
		return;
	}
	if (addr >= 0xfe036000ull && addr < 0xfe037000ull) {
		uint64_t off = addr - 0xfe036000ull;
		if (off == 0 || off == 0x00) {
			unsigned char c = (unsigned char)v;
			if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f))
				fputc(c, stderr);
			fflush(stderr);
		}
		return;
	}
	if (addr >= 0xfe037000ull && addr < 0xfe038000ull)
		return;
	if (addr >= 0xfee00000ull && addr < 0xfee01000ull) {
		uint32_t off = (uint32_t)(addr - 0xfee00000ull);
		if (off / 4 < 256)
			g_lapic[off / 4] = (uint32_t)v;
		if (off == 0x380)
			g_lapic_cur = (uint32_t)v;
		if (off == 0x80) {
			F86CPU *c = cpu();
			if (c)
				c->cr8 = ((uint32_t)v >> 4) & 0xff;
		}
		return;
	}
	if (addr >= 0xfec00000ull && addr < 0xfec02000ull) {
		if ((addr & 0xff) == 0)
			g_ioapic_idx = (uint8_t)v;
		else if ((addr & 0xff) == 0x10 && g_ioapic_idx >= 0x10 &&
		         g_ioapic_idx < 0x40)
			g_ioapic_red[g_ioapic_idx - 0x10] = (uint32_t)v;
		return;
	}
	if (addr >= 0xfed00000ull && addr < 0xfed01000ull) {
		if (addr - 0xfed00000ull == 0x10)
			g_hpet_cfg = v;
		else if (addr - 0xfed00000ull == 0x100)
			g_hpet_t0cfg = v;
		else if (addr - 0xfed00000ull == 0x108)
			g_hpet_cmp = v;
		else if (addr - 0xfed00000ull == 0xf0)
			g_hpet_cnt = v;
		return;
	}
}

static void poke_apple_debug_thre(void);

static void raise_irq(uint32_t vec)
{
	if (vec && vec < 256)
		g_pending_irq = vec;
}

static void fire_ioapic(int pin)
{
	if (pin < 0 || pin > 23)
		return;
	uint32_t lo = g_ioapic_red[(unsigned)pin * 2];
	if (lo & (1u << 16))
		return;
	uint32_t vec = lo & 0xff;
	if (!vec)
		vec = 0x20u + (uint32_t)pin;
	raise_irq(vec);
}

void f86_sys_timer_pulse(void)
{
	g_hpet_cnt += 14318; /* ~1ms at 14.318MHz */
	g_pm_tmr += 3579;
	poke_apple_debug_thre();
	if (g_exited_bs) {
		static int fbdiv;
		if (++fbdiv >= 2000) {
			fbdiv = 0;
			f86_uefi_dump_fb("/tmp/f86-gop.ppm");
		}
	}

	uint32_t lvt = g_lapic[0x320 / 4];
	uint32_t init = g_lapic[0x380 / 4];
	if (init && !(lvt & (1u << 16))) {
		if (g_lapic_cur > init / 8 && init / 8)
			g_lapic_cur -= init / 8 ? init / 8 : 1;
		else {
			g_lapic_cur = (lvt & (1u << 17)) ? init : 0;
			uint32_t vec = lvt & 0xff;
			if (vec)
				raise_irq(vec);
		}
	}
	if (g_tsc_deadline) {
		uint32_t lo, hi;
		__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
		uint64_t t = ((uint64_t)hi << 32) | lo;
		if (t >= g_tsc_deadline) {
			g_tsc_deadline = 0;
			uint32_t vec = lvt & 0xff;
			raise_irq(vec ? vec : 0xec);
		}
	}
	if ((g_hpet_cfg & 1) && (g_hpet_t0cfg & (1ull << 2)) && g_hpet_cmp &&
	    g_hpet_cnt >= g_hpet_cmp) {
		if (g_hpet_t0cfg & (1ull << 3))
			g_hpet_cmp += g_hpet_cmp ? g_hpet_cmp : 14318;
		fire_ioapic(2);
		uint32_t vec = lvt & 0xff;
		if (vec)
			raise_irq(vec);
	}
	if (g_pit_div) {
		static int pit_acc;
		if (++pit_acc >= 10) {
			pit_acc = 0;
			fire_ioapic(0);
		}
	}
	/* Author's heuristic: raise vector 0x20 on every tick once the IDT
	   has a gate for it, with no device behind it. Spurious once the
	   virtual IF is honoured; opt-in via F86_FAKE_IRQ20=1. */
	static int fake20 = -1;
	if (fake20 < 0)
		fake20 = getenv("F86_FAKE_IRQ20") != NULL;
	if (fake20 && g_exited_bs && !g_pending_irq && g_idt_gpa) {
		uint64_t lo0 = 0, lo20 = 0, hi20 = 0;
		memcpy(&lo0, g_ram + g_idt_gpa, 8);
		memcpy(&lo20, g_ram + g_idt_gpa + 0x20 * 16, 8);
		memcpy(&hi20, g_ram + g_idt_gpa + 0x20 * 16 + 8, 8);
		uint64_t off = (lo20 & 0xffffull) | ((lo20 >> 32) & 0xffff0000ull) |
		               (hi20 << 32);
		int type = (int)((lo20 >> 40) & 0xf);
		if (((lo20 >> 47) & 1) && lo20 != lo0 &&
		    (type == 0xE || type == 0xF) &&
		    (off >> 47) == 0x1ffffull &&
		    off >= 0xffffff8000100000ull && off < 0xffffff8100000000ull)
			raise_irq(0x20);
	}
}

const char *f86_inject_fail = "";
static int push_int_frame(F86CPU *c, int vec, int has_err, uint32_t err)
{
	f86_inject_fail = "";
	if (!c || !c->idt_base) {
		f86_inject_fail = "no idt";
		return 0;
	}
	uint64_t gpa = 0;
	if (g_idt_gpa)
		gpa = g_idt_gpa + (uint64_t)(unsigned)vec * 16ull;
	else {
		uint64_t gea = c->idt_base + (uint64_t)(unsigned)vec * 16ull;
		if (!f86_gva_to_gpa(gea, &gpa))
			return 0;
	}
	if (gpa + 16 > g_ram_sz) {
		f86_inject_fail = "idt gpa out of ram";
		return 0;
	}
	uint64_t lo = 0, hi = 0;
	memcpy(&lo, g_ram + gpa, 8);
	memcpy(&hi, g_ram + gpa + 8, 8);
	if (!((lo >> 47) & 1)) {
		f86_inject_fail = "gate not present";
		return 0;
	}
	uint64_t off = (lo & 0xffffull) | ((lo >> 32) & 0xffff0000ull) | (hi << 32);
	if (!off) {
		f86_inject_fail = "gate offset 0";
		return 0;
	}
	int type = (int)((lo >> 40) & 0xf);
	if (type != 0xE && type != 0xF) {
		f86_inject_fail = "gate type";
		return 0;
	}
	{
		/* XNU's IDT points at the double-mapped __HIB stubs
		   (0xfffff6b8c0002800-style VAs, outside the static kernel
		   window), so the only sane check is "canonical kernel-half
		   address that the current page tables map to RAM". */
		uint64_t top = off >> 47, hg = 0;
		if (top != 0x1ffffull || !f86_gva_to_gpa(off, &hg) || hg >= g_ram_sz) {
			static char why[96];
			snprintf(why, sizeof why, "gate offset %lx not mapped", (unsigned long)off);
			f86_inject_fail = why;
			return 0;
		}
	}
	uint64_t rsp = c->r[R_RSP] & ~0xfull;
	uint64_t fr = has_err ? 48ull : 40ull;
	rsp -= fr;
	uint64_t spg = 0;
	if (!f86_gva_to_gpa(rsp, &spg) || spg + fr > g_ram_sz) {
		spg = g_dummy_cpu + 0x7f00 - fr;
		rsp = 0xffffff8000000000ull | spg;
		if (spg + fr > g_ram_sz) {
			f86_inject_fail = "stack";
			return 0;
		}
	}
	uint64_t ss = 0x10, cs = (lo >> 16) & 0xffffull, rfl = f86_rflags_arch(c);
	uint64_t orip = c->rip, orsp = c->r[R_RSP];
	size_t o = 0;
	if (has_err) {
		uint64_t e = err;
		memcpy(g_ram + spg, &e, 8);
		o = 8;
	}
	memcpy(g_ram + spg + o + 0, &orip, 8);
	memcpy(g_ram + spg + o + 8, &cs, 8);
	memcpy(g_ram + spg + o + 16, &rfl, 8);
	memcpy(g_ram + spg + o + 24, &orsp, 8);
	memcpy(g_ram + spg + o + 32, &ss, 8);
	c->r[R_RSP] = rsp;
	if (type == 0xE)
		g_vif = 0;
	c->rip = off;
	return 1;
}

int f86_sys_inject_exc(F86CPU *c, int vec, uint32_t err, uint64_t cr2)
{
	static int nexc;
	if (!c || !g_exited_bs)
		return 0;
	if ((cr2 & ~0xfffull) == GS_POISON)
		return 0;
	if (nexc > 64)
		return 0;
	int has_err = (vec == 8 || vec == 10 || vec == 11 || vec == 12 ||
	               vec == 13 || vec == 14 || vec == 17);
	if (vec == 14)
		c->cr2 = cr2;
	if (!push_int_frame(c, vec, has_err, err))
		return 0;
	if (nexc < 16 || (nexc % 64) == 0)
		fprintf(stderr,
		        "fast86: exc %d err=%x cr2=%lx -> %lx from rsp=%lx\n",
		        vec, err, (unsigned long)cr2, (unsigned long)c->rip,
		        (unsigned long)c->r[R_RSP]);
	nexc++;
	return 1;
}

int f86_sys_deliver_irq(F86CPU *c)
{
	if (!c || !g_pending_irq || !g_exited_bs)
		return 0;
	if (!g_vif)
		return 0;
	if (!c->idt_base || !c->idt_limit)
		return 0;
	if (c->gs_base < 0xffffff8000000000ull || c->gs_base == GS_POISON)
		return 0;
	uint32_t vec = g_pending_irq;
	if ((c->cr8 << 4) >= (vec & 0xf0) && vec >= 0x20)
		return 0;
	uint64_t orip = c->rip;
	if (!push_int_frame(c, (int)vec, 0, 0)) {
		static int nf;
		if (nf++ < 6)
			fprintf(stderr, "fast86: irq %u push fail idt=%lx rip=%lx (%s)\n",
			        vec, (unsigned long)c->idt_base, (unsigned long)c->rip,
			        f86_inject_fail);
		return 0;
	}
	g_pending_irq = 0;
	g_lapic[0xb0 / 4] = 0;
	if (g_irq_n < 12 || (g_irq_n % 256) == 0)
		fprintf(stderr,
		        "fast86: irq %u -> %lx from %lx rsp=%lx idt=%lx\n",
		        vec, (unsigned long)c->rip, (unsigned long)orip,
		        (unsigned long)c->r[R_RSP], (unsigned long)c->idt_base);
	g_irq_n++;
	return 1;
}

static void ebs_tick(int sig, siginfo_t *si, void *u)
{
	(void)sig;
	(void)si;
	f86_irq_from_signal(u);
}

static void poke_apple_debug_thre(void)
{
	uint64_t base = f86_sys_image_base();
	if (!base || base + 0xad300 >= f86_ram_size())
		return;
	uint64_t *slot = f86_gpa_hva(base + 0xad2f8);
	if (!slot)
		return;
	uint64_t obj = *slot;
	if (obj < 0x1000 || obj + 0x20 >= f86_ram_size())
		return;
	uint32_t *st = f86_gpa_hva(obj + 0x14);
	if (st)
		*st |= 0x20;
}

void f86_sys_exited_bs(void)
{
	g_exited_bs = 1;
	{
		uint64_t b = f86_sys_image_base();
		uint64_t *p0 = f86_gpa_hva(b + 0xad2f0);
		uint64_t *p1 = f86_gpa_hva(b + 0xad2f8);
		fprintf(stderr, "fast86: debug slots base=%lx [ad2f0]=%lx [ad2f8]=%lx\n",
		        (unsigned long)b,
		        p0 ? (unsigned long)*p0 : 0,
		        p1 ? (unsigned long)*p1 : 0);
	}
	/* Debug UART is MMIO at 0xfe036000 — do not patch boot.efi. */
	fprintf(stderr, "fast86: boot services ended — kernel path\n");
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = ebs_tick;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);
	{
		struct itimerval it;
		memset(&it, 0, sizeof it);
		it.it_interval.tv_usec = 2000;
		it.it_value.tv_usec = 2000;
		setitimer(ITIMER_REAL, &it, NULL);
	}
}

int f86_sys_bs_exited(void) { return g_exited_bs; }

uint8_t *f86_ram(void) { return g_ram; }
size_t   f86_ram_size(void) { return g_ram_sz; }

static int identity_ok(uint64_t gpa, size_t n)
{
	if (n && gpa + n < gpa)
		return 0;
	return gpa >= 0x1000 && (gpa + n) <= 0x0000000100000000ull &&
	       (gpa + n) <= g_ram_sz;
}

/* Guest pointer: prefer identity (GPA==HVA) so copied insns work. */
void *f86_gpa_hva(uint64_t gpa)
{
	if (!gpa || gpa >= g_ram_sz || f86_sys_is_mmio(gpa))
		return NULL;
	return g_ram + gpa;
}

static int pte_tbl(uint64_t pte, uint64_t *tbl)
{
	if (!(pte & 1))
		return 0;
	uint64_t pa = pte & 0x000ffffffffff000ull;
	if (pa + 0x1000 > g_ram_sz)
		return 0;
	*tbl = pa;
	return 1;
}

#define WLK_N 256
static uint64_t g_wlk_va[WLK_N], g_wlk_pa[WLK_N];
static uint8_t  g_wlk_sh[WLK_N];
static int      g_wlk_shift = 12; /* page size (log2) of the last translation */

int f86_ram_fd(void) { return g_ram_fd; }
int f86_walk_shift(void) { return g_wlk_shift; }

static void walk_cache_inval(void)
{
	memset(g_wlk_va, 0, sizeof g_wlk_va);
}

/* DBLMAP / physmap: low 4GiB is identity GPA. Kernel window (0xffffff80)
 * is walked first — treating it as identity skipped the guest PT and
 * made zone_info / early-cram stores miss the pages XNU actually uses. */
static int physmap_alias(uint64_t gva, uint64_t *gpa)
{
	uint64_t lo = gva & 0xffffffffull;
	if (lo < 0x1000 || lo >= g_ram_sz)
		return 0;
	uint64_t top40 = gva >> 40;
	if (top40 == 0xfffff6ull || top40 == 0xfffff7ull ||
	    top40 == 0xfffffeull || top40 == 0xfffffdull) {
		*gpa = lo;
		return 1;
	}
	return 0;
}

static int kernel_window_alias(uint64_t gva, uint64_t *gpa)
{
	uint64_t lo = gva & 0xffffffffull;
	if ((gva >> 32) != 0xffffff80ull || lo < 0x1000 || lo >= g_ram_sz)
		return 0;
	*gpa = lo;
	return 1;
}

int f86_gva_to_gpa(uint64_t gva, uint64_t *out)
{
	F86CPU *c = cpu();
	uint64_t gpa = gva;
	uint64_t page = gva & ~0xfffull;
	if (c && (c->cr0 & CR0_PG)) {
		uint64_t hi = gva >> 47;
		if (hi != 0 && hi != 0x1ffffull)
			return 0; /* non-canonical: no translation */
	}
	unsigned h = (unsigned)((page >> 12) & (WLK_N - 1));
	g_wlk_shift = (c && (c->cr0 & CR0_PG)) ? 12 : 21; /* no paging: 2 MiB identity granules */
	if (page && g_wlk_va[h] == page) {
		gpa = g_wlk_pa[h] | (gva & 0xfff);
		g_wlk_shift = g_wlk_sh[h];
		goto have;
	}
	/* Always walk the guest page tables first. XNU's physmap base is
	   KVADDR(PML4 slot, rand64 & 0xff, 0, 0): the random L3 index puts
	   non-zero bits in VA[31:30], so "GPA = low 32 bits" is wrong for 3/4
	   of the possible bases (and DBLMAP VAs are offsets into __HIB, never
	   GPAs). The aliases remain only as a fallback when the walk misses,
	   e.g. before the physmap exists. */
	if (c && (c->cr0 & CR0_PG)) {
		uint64_t a = c->cr3 & 0x000ffffffffff000ull;
		uint64_t i4 = (gva >> 39) & 0x1ff;
		uint64_t i3 = (gva >> 30) & 0x1ff;
		uint64_t i2 = (gva >> 21) & 0x1ff;
		uint64_t i1 = (gva >> 12) & 0x1ff;
		uint64_t tbl;
		int miss = 0;
		if (!pte_tbl(a | 1, &tbl))
			miss = 1;
		else {
			uint64_t p4 = ((uint64_t *)(g_ram + tbl))[i4];
			if (!pte_tbl(p4, &tbl)) {
				static int nfail;
				if (nfail < 12) {
					fprintf(stderr, "fast86: walk miss gva=%lx cr3=%lx pml4[%lx]=%lx\n",
					        (unsigned long)gva, (unsigned long)a,
					        (unsigned long)i4, (unsigned long)p4);
					nfail++;
				}
				miss = 1;
			} else if (p4 & (1ull << 7))
				miss = 1;
			else {
				uint64_t p3 = ((uint64_t *)(g_ram + tbl))[i3];
				if (!(p3 & 1))
					miss = 1;
				else if (p3 & (1ull << 7)) {
					gpa = (p3 & 0x000fffffc0000000ull) | (gva & 0x3fffffffull);
					g_wlk_shift = 30;
				}
				else if (!pte_tbl(p3, &tbl))
					miss = 1;
				else {
					uint64_t p2 = ((uint64_t *)(g_ram + tbl))[i2];
					if (!(p2 & 1))
						miss = 1;
					else if (p2 & (1ull << 7)) {
						gpa = (p2 & 0x000fffffffe00000ull) | (gva & 0x1fffffull);
						g_wlk_shift = 21;
					}
					else if (!pte_tbl(p2, &tbl))
						miss = 1;
					else {
						uint64_t p1 = ((uint64_t *)(g_ram + tbl))[i1];
						if (!(p1 & 1))
							miss = 1;
						else
							gpa = (p1 & 0x000ffffffffff000ull) | (gva & 0xfff);
					}
				}
			}
		}
		if (miss) {
			/* A real walk miss is a guest #PF. The old fallback aliased
			   the VA to its low 32 bits AND cached that, so the kernel's
			   first touch of a not-yet-mapped page (e.g. the console ring
			   from kmem_alloc) pinned a random physical page for good. */
			return 0;
		}
	}
have:
	if (page) {
		g_wlk_va[h] = page;
		g_wlk_pa[h] = gpa & ~0xfffull;
		g_wlk_sh[h] = (uint8_t)g_wlk_shift;
	}
	if (f86_sys_is_mmio(gpa)) {
		if (out)
			*out = gpa;
		return 1;
	}
	if (gpa >= g_ram_sz)
		return 0;
	if (out)
		*out = gpa;
	return 1;
}

/* Walk gva once, uncached, reporting the page-table pages it traversed:
   level 4..1 with the guest VA base each page covers. Returns the number of
   levels recorded (0 when paging is off or the walk misses early). */
int f86_walk_tables(uint64_t gva, uint64_t tbl[4], uint64_t base[4], int lvl[4])
{
	F86CPU *c = cpu();
	int n = 0;
	if (!c || !(c->cr0 & CR0_PG))
		return 0;
	uint64_t hi = gva >> 47;
	if (hi != 0 && hi != 0x1ffffull)
		return 0;
	uint64_t a = c->cr3 & 0x000ffffffffff000ull;
	uint64_t i4 = (gva >> 39) & 0x1ff, i3 = (gva >> 30) & 0x1ff, i2 = (gva >> 21) & 0x1ff;
	uint64_t t;
	if (!pte_tbl(a | 1, &t))
		return 0;
	tbl[n] = t; base[n] = 0; lvl[n] = 4; n++;
	uint64_t p4 = ((uint64_t *)(g_ram + t))[i4];
	if (!pte_tbl(p4, &t) || (p4 & (1ull << 7)))
		return n;
	uint64_t b3 = i4 << 39;
	if (i4 & 0x100)
		b3 |= 0xffff000000000000ull;
	tbl[n] = t; base[n] = b3; lvl[n] = 3; n++;
	uint64_t p3 = ((uint64_t *)(g_ram + t))[i3];
	if (!(p3 & 1) || (p3 & (1ull << 7)) || !pte_tbl(p3, &t))
		return n;
	uint64_t b2 = b3 + (i3 << 30);
	tbl[n] = t; base[n] = b2; lvl[n] = 2; n++;
	uint64_t p2 = ((uint64_t *)(g_ram + t))[i2];
	if (!(p2 & 1) || (p2 & (1ull << 7)) || !pte_tbl(p2, &t))
		return n;
	tbl[n] = t; base[n] = b2 + (i2 << 21); lvl[n] = 1; n++;
	return n;
}

const uint8_t *f86_gva_code(uint64_t gva, size_t n)
{
	uint64_t gpa = 0;
	if (!f86_gva_to_gpa(gva, &gpa) || gpa + n > g_ram_sz)
		return NULL;
	return g_ram + gpa;
}

static uint64_t gpa_read(uint64_t gpa, int sz)
{
	if (gpa + (unsigned)sz > g_ram_sz)
		return 0;
	uint64_t v = 0;
	memcpy(&v, g_ram + gpa, (size_t)sz);
	return v;
}

static void gpa_write(uint64_t gpa, uint64_t v, int sz)
{
	if (gpa + (unsigned)sz > g_ram_sz)
		return;
	memcpy(g_ram + gpa, &v, (size_t)sz);
}

int f86_sys_init(size_t ram_bytes)
{
	if (ram_bytes < (64u << 20))
		ram_bytes = 64u << 20;
	if (ram_bytes > (4ull << 30))
		ram_bytes = 4ull << 30;
	g_ram_sz = (ram_bytes + 0xfffull) & ~0xfffull;
	g_ram_fd = memfd_create("f86ram", 0);
	if (g_ram_fd < 0 || ftruncate(g_ram_fd, (off_t)g_ram_sz) != 0) {
		perror("memfd ram");
		return -1;
	}
	g_ram = mmap((void *)(uintptr_t)0x200000000ull, g_ram_sz, PROT_READ | PROT_WRITE,
	             MAP_SHARED | MAP_FIXED_NOREPLACE, g_ram_fd, 0);
	if (g_ram == MAP_FAILED)
		g_ram = mmap(NULL, g_ram_sz, PROT_READ | PROT_WRITE,
		             MAP_SHARED, g_ram_fd, 0);
	if (g_ram == MAP_FAILED) {
		perror("mmap ram");
		return -1;
	}
	/* Low 1 MiB except page 0 (mmap_min_addr / NULL-deref guards).
	   ACPI/SMBIOS scans at 0xe0000. Accesses to 0x40E are emulated. */
	{
		void *p = mmap((void *)(uintptr_t)0x1000, 0x100000 - 0x1000,
		               PROT_READ | PROT_WRITE | PROT_EXEC,
		               MAP_SHARED | MAP_FIXED_NOREPLACE, g_ram_fd, 0x1000);
		if (p != (void *)(uintptr_t)0x1000 && p != MAP_FAILED)
			munmap(p, 0x100000 - 0x1000);
	}
	/* 1 MiB firmware window at 1 MiB — UEFI tables live here. */
	{
		void *p = mmap((void *)(uintptr_t)0x100000, 0x100000,
		               PROT_READ | PROT_WRITE | PROT_EXEC,
		               MAP_SHARED | MAP_FIXED_NOREPLACE, g_ram_fd, 0x100000);
		if (p != (void *)(uintptr_t)0x100000 && p != MAP_FAILED)
			munmap(p, 0x100000);
	}
	/* Identity-map 2 MiB granules wherever the host VA is free. */
	size_t chunk = 2u << 20;
	size_t mapped = 0, skipped = 0;
	for (uint64_t gpa = chunk; gpa + chunk <= g_ram_sz; gpa += chunk) {
		if (f86_sys_is_mmio(gpa) ||
		    (gpa < 0xfe100000ull && gpa + chunk > 0xfe000000ull) ||
		    (gpa < 0xfee01000ull && gpa + chunk > 0xfec00000ull)) {
			skipped += chunk;
			continue;
		}
		void *p = mmap((void *)(uintptr_t)gpa, chunk,
		               PROT_READ | PROT_WRITE | PROT_EXEC,
		               MAP_SHARED | MAP_FIXED_NOREPLACE, g_ram_fd, (off_t)gpa);
		if (p == (void *)(uintptr_t)gpa) {
			mapped += chunk;
			{
				uint32_t i = (uint32_t)(gpa >> 21);
				if (i < 2048)
					g_idbit[i >> 3] |= (uint8_t)(1u << (i & 7));
			}
		} else {
			static int nsk;
			skipped += chunk;
			if (nsk++ < 12)
				fprintf(stderr, "fast86: identity skip gpa=%lx\n",
				        (unsigned long)gpa);
			if (p != MAP_FAILED)
				munmap(p, chunk);
		}
	}
	fprintf(stderr, "fast86: system ram=%zuMiB identity=%zuMiB skipped=%zuMiB ram_hva=%p\n",
	        g_ram_sz >> 20, mapped >> 20, skipped >> 20, (void *)g_ram);
	/* Keep allocations in the low 2 GiB so RIP/pointers never look
	   sign-extended, and below the 0x7e000000 translator scratch. */
	g_alloc_next = 0x70000000ull;
	if (g_alloc_next > g_ram_sz - (8u << 20))
		g_alloc_next = g_ram_sz - (8u << 20);
	g_system = 1;
	g_root[0] = 0;
	if (g_dummy_cpu + 0x8000 < g_ram_sz) {
		memset(g_ram + g_dummy_cpu, 0, 0x8000);
		memcpy(g_ram + g_dummy_cpu, &g_dummy_cpu, 8);
		uint64_t desc = g_dummy_cpu + 0x1000;
		uint64_t stk = g_dummy_cpu + 0x8000;
		memcpy(g_ram + g_dummy_cpu + 0x38, &desc, 8);
		memcpy(g_ram + desc + 8, &stk, 8);
	}
	f86_gs_host = g_dummy_cpu;
	return 0;
}

void f86_sys_refresh_gs(void)
{
	F86CPU *c = cpu();
	if (!c) {
		f86_gs_host = g_dummy_cpu;
		return;
	}
	uint64_t g = c->gs_base;
	if (f86_alias_on()) {
		/* Host GS = guest GS + alias offset, so gs:disp lands in the alias
		   like every other guest access. An unset/poisoned base points at
		   the dummy page through the kernel-window alias of its GPA. */
		uint64_t base = (!g || g == GS_POISON) ? (0xffffff8000000000ull | g_dummy_cpu) : g;
		uint64_t h = base + f86_alias_off();
		uint64_t top = h >> 47;
		if (top != 0 && top != 0x1ffffull) {
			static int nnc;
			if (nnc++ < 4)
				fprintf(stderr, "fast86: guest GS base %lx not representable in the alias\n",
				        (unsigned long)g);
			h = (0xffffff8000000000ull | g_dummy_cpu) + f86_alias_off();
		}
		f86_gs_host = h;
		return;
	}
	if (!g || g == GS_POISON) {
		f86_gs_host = g_dummy_cpu;
		return;
	}
	uint64_t gpa = 0;
	if (f86_gva_to_gpa(g, &gpa) && gpa + 16 < g_ram_sz && !f86_sys_is_mmio(gpa))
		f86_gs_host = gpa;
	else
		f86_gs_host = g_dummy_cpu;
}

void f86_sys_set_root(const char *dir)
{
	snprintf(g_root, sizeof g_root, "%s", dir ? dir : "");
}

void f86_sys_set_mac_root(const char *dir)
{
	snprintf(g_mac_root, sizeof g_mac_root, "%s", dir ? dir : "");
}

void f86_sys_set_image_path(const char *path)
{
	snprintf(g_image_path, sizeof g_image_path, "%s", path ? path : "");
}

const char *f86_sys_image_path(void)
{
	return g_image_path[0] ? g_image_path : NULL;
}

void f86_sys_set_disk(const char *path)
{
	if (g_disk_map && g_disk_sz)
		munmap(g_disk_map, g_disk_sz);
	if (g_disk_fd >= 0)
		close(g_disk_fd);
	g_disk_map = NULL;
	g_disk_sz = 0;
	g_disk_fd = -1;
	if (!path || !path[0])
		return;
	g_disk_fd = open(path, O_RDONLY);
	if (g_disk_fd < 0) {
		perror(path);
		return;
	}
	struct stat st;
	if (fstat(g_disk_fd, &st) != 0) {
		close(g_disk_fd);
		g_disk_fd = -1;
		return;
	}
	g_disk_sz = (size_t)st.st_size;
	g_disk_map = mmap(NULL, g_disk_sz, PROT_READ, MAP_PRIVATE, g_disk_fd, 0);
	if (g_disk_map == MAP_FAILED) {
		perror("mmap disk");
		g_disk_map = NULL;
		close(g_disk_fd);
		g_disk_fd = -1;
		g_disk_sz = 0;
		return;
	}
	g_part_lba = 0;
	g_part_n = g_disk_sz / 512ull;
	if (g_disk_sz > 1024 && memcmp(g_disk_map + 512, "EFI PART", 8) == 0) {
		uint64_t ents_lba = 0;
		uint32_t nents = 0, esz = 0;
		memcpy(&ents_lba, g_disk_map + 512 + 72, 8);
		memcpy(&nents, g_disk_map + 512 + 80, 4);
		memcpy(&esz, g_disk_map + 512 + 84, 4);
		if (esz >= 128 && esz <= 4096 && nents && nents <= 4096 &&
		    ents_lba < (g_disk_sz / 512ull) &&
		    ents_lba * 512ull <= g_disk_sz - (uint64_t)nents * esz) {
			const uint8_t *ents = g_disk_map + ents_lba * 512ull;
			/* Apple HFS GUID 48465300-0000-11AA-AA11-00306543ECAC */
			static const uint8_t hfs[16] = {
				0x00,0x53,0x46,0x48,0x00,0x00,0xAA,0x11,
				0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC
			};
			for (uint32_t i = 0; i < nents; i++) {
				const uint8_t *e = ents + (size_t)i * esz;
				uint64_t sl, el;
				memcpy(&sl, e + 32, 8);
				memcpy(&el, e + 40, 8);
				if (!sl && !el)
					continue;
				if (memcmp(e, hfs, 16) == 0 && el >= sl &&
				    el < g_disk_sz / 512ull) {
					g_part_lba = sl;
					g_part_n = el - sl + 1;
					break;
				}
			}
		}
	}
	fprintf(stderr, "fast86: disk %s %zuMiB part_lba=%llu n=%llu\n",
	        path, g_disk_sz >> 20,
	        (unsigned long long)g_part_lba, (unsigned long long)g_part_n);
}

uint64_t f86_sys_part_lba(void) { return g_part_lba; }
uint64_t f86_sys_part_blocks(void) { return g_part_n; }

int f86_sys_disk_read(uint64_t lba, uint32_t nbyte, void *dst)
{
	if (!g_disk_map || !dst || lba >= g_disk_sz / 512ull)
		return -1;
	uint64_t off = lba * 512ull;
	if (off + nbyte > g_disk_sz) {
		if (off >= g_disk_sz)
			return -1;
		nbyte = (uint32_t)(g_disk_sz - off);
	}
	memcpy(dst, g_disk_map + off, nbyte);
	return 0;
}

uint64_t f86_sys_disk_blocks(void)
{
	return g_disk_sz / 512ull;
}

int f86_sys_load_raw(uint64_t gpa, const void *data, size_t n)
{
	if (gpa + n > g_ram_sz)
		return -1;
	memcpy(g_ram + gpa, data, n);
	return 0;
}

int f86_sys_load_file(uint64_t gpa, const char *path, size_t *out_n)
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
	if ((uint64_t)st.st_size + gpa > g_ram_sz) {
		fprintf(stderr, "fast86: %s too large for guest ram\n", path);
		close(fd);
		return -1;
	}
	size_t n = (size_t)st.st_size;
	if (read(fd, g_ram + gpa, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	close(fd);
	if (out_n)
		*out_n = n;
	return 0;
}

/* ---------------- I/O ---------------- */

static uint8_t g_io_3ff, g_io_3f8;

static void io_write(uint16_t port, uint32_t v, int sz)
{
	(void)sz;
	if (port == 0x3ff) {
		g_io_3ff = (uint8_t)v;
		return;
	}
	if (port == 0x3f8 || port == 0x3f9 || port == 0x3fa || port == 0x3fb ||
	    port == 0x3fc || port == 0xe9) {
		if (port == 0x3f8 || port == 0xe9) {
			unsigned char c = (unsigned char)v;
			g_io_3f8 = c;
			{
				/* F86_SERIAL_LOG=path: raw copy of every COM1 byte. */
				static FILE *slog;
				static int slog_tried;
				if (!slog_tried) {
					slog_tried = 1;
					const char *sp = getenv("F86_SERIAL_LOG");
					if (sp)
						slog = fopen(sp, "wb");
				}
				if (slog) {
					fputc(c, slog);
					fflush(slog);
				}
			}
			if (c == '\n' || (c >= 0x20 && c < 0x7f) || c == '\r' || c == '\t')
				fputc(c, stderr);
			else {
				/* Who is writing binary to the console? Dump the guest
				   stack (unslid) once in a while so it can be symbolized. */
				static int ngarb;
				F86CPU *cc = cpu();
				if (ngarb < 4 && cc && g_exited_bs) {
					uint64_t slide = f86_kernel_base() >= 0x100000ull ?
					                 f86_kernel_base() - 0x100000ull : 0;
					fprintf(stderr, "\nfast86: binary console byte %02x rip=%lx (unslid %lx) rsp=%lx stack:",
					        c, (unsigned long)cc->rip, (unsigned long)(cc->rip - slide),
					        (unsigned long)cc->r[R_RSP]);
					for (int k = 0; k < 40; k++) {
						uint64_t gp = 0, w = 0;
						if (!f86_gva_to_gpa(cc->r[R_RSP] + 8ull * k, &gp) || gp + 8 > g_ram_sz)
							break;
						memcpy(&w, g_ram + gp, 8);
						if (w >= 0xffffff8000000000ull + slide && w < 0xffffff8002000000ull + slide)
							fprintf(stderr, " %lx", (unsigned long)(w - slide));
					}
					fprintf(stderr, "\n");
					ngarb++;
				}
			}
			fflush(stderr);
		}
		return;
	}
	if (port == 0x300 || port == 0x304)
		return;
	if (port == 0x20 || port == 0x21 || port == 0xa0 || port == 0xa1) {
		int sl = (port == 0xa0 || port == 0xa1);
		if (port == 0x21 || port == 0xa1)
			g_pic_mask[sl] = (uint8_t)v;
		else if ((uint8_t)v == 0x20)
			g_pic_isr[sl] = 0;
		return;
	}
	if (port == 0x43) {
		g_pit_phase = 0;
		return;
	}
	if (port == 0x40) {
		if (g_pit_phase == 0) {
			g_pit_lat = (uint8_t)v;
			g_pit_phase = 1;
		} else {
			g_pit_div = (uint16_t)g_pit_lat | ((uint16_t)v << 8);
			if (!g_pit_div)
				g_pit_div = 1;
			g_pit_phase = 0;
		}
		return;
	}
	if (port == 0x70) {
		g_cmos_idx = (uint8_t)v;
		return;
	}
	if (port == 0x71) {
		g_cmos[g_cmos_idx & 0x7f] = (uint8_t)v;
		return;
	}
	if (port == 0xcf8) {
		g_pci_addr = v;
		return;
	}
	if (port == 0xcfc || port == 0xcfd || port == 0xcfe || port == 0xcff)
		return;
	if (port == 0x404) /* PM1a control */
		return;
	if (port == 0xcf9)
		return;
}

static uint32_t io_read(uint16_t port, int sz)
{
	(void)sz;
	if (port == 0x3ff)
		return g_io_3ff;
	if (port == 0x3fd)
		return 0x60;
	if (port == 0x3f8)
		return g_io_3f8;
	if (port == 0x64)
		return 0x14;
	if (port == 0x60)
		return 0;
	if (port == 0x20 || port == 0xa0)
		return g_pic_isr[port == 0xa0];
	if (port == 0x21 || port == 0xa1)
		return g_pic_mask[port == 0xa1];
	if (port == 0x40)
		return 0;
	if (port == 0x61)
		return 0x20;
	if (port == 0x70)
		return g_cmos_idx;
	if (port == 0x71) {
		uint8_t i = g_cmos_idx & 0x7f;
		if (i == 0x0d)
			return 0x80;
		if (i == 0x14)
			return 0x44;
		return g_cmos[i];
	}
	if (port == 0x408) {
		/* ACPI PM timer, 3.579545 MHz, 24-bit, derived from the host clock
		   so firmware TSC calibration loops measure the real TSC rate. */
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		/* seconds and nanoseconds separately: ns * 3579545 overflowed
		   uint64 after ~86 minutes of host uptime and the timer went
		   non-monotonic (OpenCore then measured a 2^63 Hz TSC). */
		uint64_t ticks = (uint64_t)ts.tv_sec * 3579545ull +
		                 ((uint64_t)ts.tv_nsec * 3579545ull) / 1000000000ull;
		return (uint32_t)ticks & 0xffffffu;
	}
	if (port == 0x400)
		return 0;
	if (port == 0x404)
		return 1;
	if (port == 0xcf8)
		return g_pci_addr;
	if (port == 0xcfc || port == 0xcfd || port == 0xcfe || port == 0xcff) {
		uint32_t bus = (g_pci_addr >> 16) & 0xff;
		uint32_t dev = (g_pci_addr >> 11) & 0x1f;
		uint32_t fn = (g_pci_addr >> 8) & 7;
		uint32_t reg = g_pci_addr & 0xfc;
		uint32_t val = pci_cfg_read(bus, dev, fn, reg);
		uint32_t sh = (uint32_t)(port - 0xcfc) * 8u;
		if (sz == 1)
			return (val >> sh) & 0xff;
		if (sz == 2)
			return (val >> sh) & 0xffff;
		return val;
	}
	return 0xff;
}

/* ---------------- UEFI stubs live in guest RAM ---------------- */

void f86_emit_stub(uint8_t *p, uint32_t id)
{
	/* Do not touch rcx/rdx/r8/r9 — those are EFI args.
	   Identity is (rip - stub_base) / STUB_SIZE. */
	(void)id;
	p[0] = 0xf4; /* hlt */
	p[1] = 0xc3; /* ret */
	memset(p + 2, 0x90, 14);
}

static uint64_t g_stack_lo, g_stack_hi; /* identity stack granule */

uint64_t f86_uefi_alloc(uint64_t pages)
{
	uint64_t n = pages * 4096ull;
	/* The bump allocator walks down from 0x70000000 through the 2 MiB
	   granule holding the UEFI stack. A 68 MiB kernel-collection pool
	   allocation used to land on top of the stack and zero it (memset
	   below), which silently ended the run. Step over the stack. */
	if (g_stack_hi && g_alloc_next > g_stack_lo &&
	    (g_alloc_next < g_stack_hi || g_alloc_next - n < g_stack_hi))
		g_alloc_next = g_stack_lo;
	/* Floor: never hand out the firmware region (stubs/tables below 2 MiB
	   and the loaded image/stack area are reserved separately). */
	if (g_alloc_next < 0x200000ull + n + 0x1000ull)
		return 0;
	g_alloc_next -= n;
	g_alloc_next &= ~0xfffull;
	memset(g_ram + g_alloc_next, 0, (size_t)n);
	return g_alloc_next;
}

const char *f86_sys_root(void)
{
	return g_root[0] ? g_root : NULL;
}

const char *f86_sys_mac_root(void)
{
	return g_mac_root[0] ? g_mac_root : NULL;
}

uint64_t f86_sys_image_base(void) { return g_image_base; }
uint64_t f86_sys_image_size(void) { return g_image_size; }

static uint8_t checksum8(const uint8_t *p, size_t n)
{
	uint8_t s = 0;
	for (size_t i = 0; i < n; i++)
		s = (uint8_t)(s + p[i]);
	return (uint8_t)(0u - s);
}

/* Identity-mapped firmware tables so OC's SMBIOS/ACPI probes do not NULL-deref. */
void f86_sys_plant_fw(void)
{
	if (!g_ram || g_ram_sz < 0x100000)
		return;
	/* SMBIOS 2.8: type 0 BIOS, type 1 iMacPro1,1 (Sequoia PlatformSupport). */
	uint8_t *tab = g_ram + 0xF0100;
	memset(tab, 0, 512);
	uint8_t *p = tab;
	/* Type 0 */
	p[0] = 0;
	p[1] = 24;
	p[2] = 0x00;
	p[3] = 0x00;
	p[4] = 1; /* vendor str */
	p[5] = 2; /* version str */
	p[6] = 0x00;
	p[7] = 0xe8; /* segment */
	p[8] = 3; /* date str */
	p[9] = 0;
	p[10] = 0x08; /* rom size */
	p[11] = 0x08;
	memset(p + 12, 0xff, 8);
	p[20] = 0x03;
	p[21] = 0x0d;
	p[22] = 1;
	p[23] = 1;
	{
		char *s = (char *)(p + 24);
		size_t n = 0;
		memcpy(s + n, "Apple Inc.", 11); n += 11;
		memcpy(s + n, "IMPRO191.0000.0.0.0", 20); n += 20;
		memcpy(s + n, "10/12/2024", 11); n += 11;
		p += 24 + n;
		*p++ = 0;
	}
	/* Type 1 */
	p[0] = 1;
	p[1] = 27;
	p[2] = 0x01;
	p[3] = 0x00;
	p[4] = 1; /* manufacturer */
	p[5] = 2; /* product */
	p[6] = 3; /* version */
	p[7] = 4; /* serial */
	/* UUID */
	static const uint8_t uuid[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
	};
	memcpy(p + 8, uuid, 16);
	p[24] = 6; /* wakeup */
	p[25] = 5; /* sku */
	p[26] = 6; /* family */
	{
		char *s = (char *)(p + 27);
		size_t n = 0;
		memcpy(s + n, "Apple Inc.", 11); n += 11;
		memcpy(s + n, "iMacPro1,1", 11); n += 11;
		memcpy(s + n, "1.0", 4); n += 4;
		memcpy(s + n, "C02F86FAST86", 13); n += 13;
		memcpy(s + n, "Default", 8); n += 8;
		memcpy(s + n, "iMac Pro", 9); n += 9;
		p += 27 + n;
		*p++ = 0;
	}
	/* Type 127 */
	p[0] = 127;
	p[1] = 4;
	p[2] = 0xff;
	p[3] = 0xff;
	p += 4;
	*p++ = 0;
	*p++ = 0;
	uint16_t tlen = (uint16_t)(p - tab);
	uint16_t nstr = 3;
	uint8_t *ep = g_ram + 0xF0000;
	memset(ep, 0, 32);
	memcpy(ep, "_SM_", 4);
	ep[5] = 0x1F;
	ep[6] = 2;
	ep[7] = 8;
	ep[8] = 64;
	ep[9] = 0;
	memcpy(ep + 16, "_DMI_", 5);
	uint32_t taddr = 0xF0100;
	memcpy(ep + 22, &tlen, 2);
	memcpy(ep + 24, &taddr, 4);
	memcpy(ep + 28, &nstr, 2);
	ep[30] = 0x28;
	ep[21] = checksum8(ep + 16, 15);
	ep[4] = checksum8(ep, 0x1F);

	/* ACPI 2.0: RSDP → XSDT {FACP, APIC, HPET, DSDT via FADT, SSDTs}. */
	{
		static const uint8_t dsdt_aml[] = {
			0x44,0x53,0x44,0x54,0xcc,0x01,0x00,0x00,0x02,0xf7,0x41,0x50,0x50,0x4c,0x45,0x20,
			0x46,0x38,0x36,0x44,0x53,0x44,0x54,0x00,0x00,0x00,0x01,0x00,0x49,0x4e,0x54,0x4c,
		};
		/* Prefer the compiled DSDT next to the tree; fall back to a stub header. */
		uint8_t *dsdt = g_ram + 0xE0800;
		size_t dsdt_n = 0;
		const char *paths[] = {
			"macos-boot/dsdt.aml", "/root/fast86/macos-boot/dsdt.aml", NULL
		};
		for (int i = 0; paths[i]; i++) {
			int fd = open(paths[i], O_RDONLY);
			if (fd < 0)
				continue;
			ssize_t n = read(fd, dsdt, 0x800);
			close(fd);
			if (n > 36 && memcmp(dsdt, "DSDT", 4) == 0) {
				dsdt_n = (size_t)n;
				break;
			}
		}
		if (!dsdt_n) {
			memset(dsdt, 0, 36);
			memcpy(dsdt, dsdt_aml, sizeof dsdt_aml);
			uint32_t ln = 36;
			memcpy(dsdt + 4, &ln, 4);
			dsdt[8] = 2;
			dsdt[9] = checksum8(dsdt, 36);
			dsdt_n = 36;
		}

		uint8_t *facs = g_ram + 0xE0500;
		memset(facs, 0, 64);
		memcpy(facs, "FACS", 4);
		uint32_t flen = 64;
		memcpy(facs + 4, &flen, 4);

		uint8_t *madt = g_ram + 0xE0600;
		memset(madt, 0, 80);
		memcpy(madt, "APIC", 4);
		uint32_t mlen = 44 + 8 + 12 + 6;
		memcpy(madt + 4, &mlen, 4);
		madt[8] = 3;
		memcpy(madt + 10, "APPLE ", 6);
		memcpy(madt + 16, "APIC    ", 8);
		memcpy(madt + 28, "F86 ", 4);
		uint32_t lapic = 0xFEE00000;
		memcpy(madt + 36, &lapic, 4);
		uint32_t mflags = 1; /* PCAT_COMPAT */
		memcpy(madt + 40, &mflags, 4);
		/* Local APIC */
		madt[44] = 0;
		madt[45] = 8;
		madt[46] = 0;
		madt[47] = 0;
		uint32_t en = 1;
		memcpy(madt + 48, &en, 4);
		/* IO APIC */
		madt[52] = 1;
		madt[53] = 12;
		madt[54] = 1;
		madt[55] = 0;
		uint32_t ioa = 0xFEC00000;
		memcpy(madt + 56, &ioa, 4);
		memset(madt + 60, 0, 4);
		/* Local APIC NMI */
		madt[64] = 4;
		madt[65] = 6;
		madt[66] = 0xff;
		madt[67] = 5; /* lint1, active high edge */
		madt[68] = 0;
		madt[69] = 1;
		madt[9] = checksum8(madt, mlen);

		uint8_t *hpet = g_ram + 0xE0700;
		memset(hpet, 0, 56);
		memcpy(hpet, "HPET", 4);
		uint32_t hlen = 56;
		memcpy(hpet + 4, &hlen, 4);
		hpet[8] = 1;
		memcpy(hpet + 10, "APPLE ", 6);
		memcpy(hpet + 16, "HPET    ", 8);
		memcpy(hpet + 28, "F86 ", 4);
		uint32_t hid = 0x8086a201;
		memcpy(hpet + 36, &hid, 4);
		hpet[40] = 0; /* gas space mem */
		hpet[43] = 64; /* bit width */
		uint64_t haddr = 0xFED00000ull;
		memcpy(hpet + 44, &haddr, 8);
		hpet[52] = 0;
		hpet[53] = 0;
		hpet[9] = checksum8(hpet, hlen);

		uint8_t *fadt = g_ram + 0xE0300;
		memset(fadt, 0, 268);
		memcpy(fadt, "FACP", 4);
		uint32_t falen = 268;
		memcpy(fadt + 4, &falen, 4);
		fadt[8] = 5;
		memcpy(fadt + 10, "APPLE ", 6);
		memcpy(fadt + 16, "FACP    ", 8);
		memcpy(fadt + 28, "F86 ", 4);
		uint32_t facs_a = 0xE0500, dsdt_a = 0xE0800;
		memcpy(fadt + 36, &facs_a, 4);
		memcpy(fadt + 40, &dsdt_a, 4);
		fadt[45] = 0; /* no SCI SMI */
		uint16_t sci = 9;
		memcpy(fadt + 46, &sci, 2);
		uint32_t pm1a_evt = 0x400, pm1a_cnt = 0x404, pm_tmr = 0x408;
		memcpy(fadt + 56, &pm1a_evt, 4);
		memcpy(fadt + 64, &pm1a_cnt, 4);
		memcpy(fadt + 76, &pm_tmr, 4);
		fadt[88] = 4;
		fadt[89] = 2;
		fadt[91] = 4;
		uint16_t pmlen = 4, tmrlen = 4;
		memcpy(fadt + 94, &pmlen, 2);
		memcpy(fadt + 96, &pmlen, 2);
		memcpy(fadt + 100, &tmrlen, 2);
		uint32_t fflags = (1u << 0) | (1u << 1) | (1u << 10) | (1u << 20);
		memcpy(fadt + 112, &fflags, 4);
		fadt[116] = 0; /* reset gas mem? use IO 0xCF9 */
		fadt[119] = 8;
		uint64_t rst = 0xCF9;
		memcpy(fadt + 120, &rst, 8);
		fadt[128] = 0x06;
		uint64_t xfacs = 0xE0500, xdsdt = 0xE0800;
		memcpy(fadt + 132, &xfacs, 8);
		memcpy(fadt + 140, &xdsdt, 8);
		fadt[9] = checksum8(fadt, falen);

		uint64_t xsdt_ents[8];
		int ne = 0;
		xsdt_ents[ne++] = 0xE0300; /* FADT */
		xsdt_ents[ne++] = 0xE0600; /* MADT */
		xsdt_ents[ne++] = 0xE0700; /* HPET */

		uint8_t *xsdt = g_ram + 0xE0100;
		uint32_t xlen = 36 + (uint32_t)ne * 8;
		memset(xsdt, 0, 128);
		memcpy(xsdt, "XSDT", 4);
		memcpy(xsdt + 4, &xlen, 4);
		xsdt[8] = 1;
		memcpy(xsdt + 10, "APPLE ", 6);
		memcpy(xsdt + 16, "XSDT    ", 8);
		memcpy(xsdt + 28, "F86 ", 4);
		memcpy(xsdt + 36, xsdt_ents, (size_t)ne * 8);
		xsdt[9] = checksum8(xsdt, xlen);

		uint8_t *rsdt = g_ram + 0xE0200;
		uint32_t rlen = 36 + (uint32_t)ne * 4;
		memset(rsdt, 0, 80);
		memcpy(rsdt, "RSDT", 4);
		memcpy(rsdt + 4, &rlen, 4);
		rsdt[8] = 1;
		memcpy(rsdt + 10, "APPLE ", 6);
		memcpy(rsdt + 16, "RSDT    ", 8);
		memcpy(rsdt + 28, "F86 ", 4);
		for (int i = 0; i < ne; i++) {
			uint32_t a = (uint32_t)xsdt_ents[i];
			memcpy(rsdt + 36 + i * 4, &a, 4);
		}
		rsdt[9] = checksum8(rsdt, rlen);

		uint8_t *rsdp = g_ram + 0xE0000;
		memset(rsdp, 0, 36);
		memcpy(rsdp, "RSD PTR ", 8);
		memcpy(rsdp + 9, "APPLE  ", 6);
		rsdp[15] = 2;
		uint32_t rsdt_a = 0xE0200;
		memcpy(rsdp + 16, &rsdt_a, 4);
		rsdp[8] = checksum8(rsdp, 20);
		uint32_t rsdplen = 36;
		memcpy(rsdp + 20, &rsdplen, 4);
		uint64_t xsdt_a = 0xE0100;
		memcpy(rsdp + 24, &xsdt_a, 8);
		rsdp[32] = checksum8(rsdp, 36);
		fprintf(stderr, "fast86: planted SMBIOS@f0000 ACPI@e0000 dsdt=%zu\n", dsdt_n);
	}
}

int f86_uefi_install(uint64_t *out_st);

/* ---------------- privileged / system op emulation ---------------- */

static uint64_t insn_ea(F86CPU *c, const uint8_t *ip, const F86Insn *d)
{
	int rm = d->modrm & 7;
	if (d->rex & 1)
		rm |= 8;
	if (d->flags & F86_RIPREL)
		return c->rip + d->len + (int64_t)d->disp;
	if ((d->modrm & 7) == 4) {
		uint8_t sib = ip[d->modrm_off + 1];
		int base = sib & 7, idx = (sib >> 3) & 7, sc = sib >> 6;
		if (d->rex & 1)
			base |= 8;
		if (d->rex & 2)
			idx |= 8;
		uint64_t addr = 0;
		if (idx != 4)
			addr += c->r[idx] << sc;
		if ((d->modrm >> 6) == 0 && (sib & 7) == 5)
			addr += (int32_t)d->disp;
		else {
			addr += c->r[base];
			if (d->modrm >> 6)
				addr += (int64_t)d->disp;
		}
		return addr;
	}
	uint64_t addr = c->r[rm];
	if (d->modrm >> 6)
		addr += (int64_t)d->disp;
	return addr;
}

static int emulate_sysop(F86CPU *c, const uint8_t *ip, const F86Insn *d)
{
	uint8_t op = d->opcode0, op2 = d->opcode1;
	if (op == 0xF4) {
		/* HLT: UEFI boot-service trampoline or real halt */
		{
			uint32_t sid = 0;
			if (f86_uefi_stub_id(c->rip, &sid)) {
				int r = f86_uefi_dispatch(c, sid);
				if (r != 2)
					c->rip += d->len;
				return r == 1;
			}
		}
		if (g_exited_bs) {
			c->rip += d->len;
			static uint64_t nhlt;
			nhlt++;
			if (!f86_sys_deliver_irq(c)) {
				struct timespec ts = { 0, 50000 };
				nanosleep(&ts, NULL);
				f86_sys_timer_pulse();
				if (!f86_sys_deliver_irq(c) && (nhlt % 20000) == 0) {
					uint32_t lo, hi;
					__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
					uint64_t now = ((uint64_t)hi << 32) | lo;
					fprintf(stderr, "fast86: HLT idle n=%lu pending=%u if=%d deadline=%lx now=%lx lvt=%x cr8=%lx\n",
					        (unsigned long)nhlt, g_pending_irq, g_vif,
					        (unsigned long)g_tsc_deadline, (unsigned long)now,
					        g_lapic[0x320 / 4], (unsigned long)c->cr8);
				}
			}
			return 0;
		}
		fprintf(stderr, "fast86: HLT before ExitBootServices at rip=%lx rsp=%lx\n",
		        (unsigned long)c->rip, (unsigned long)c->r[R_RSP]);
		c->exited = 1;
		c->exit_code = 0;
		return 1;
	}
	if (op == 0xFA) { /* cli */
		g_vif = 0;
		c->rip += d->len;
		return 0;
	}
	if (op == 0xFB) { /* sti */
		g_vif = 1;
		c->rip += d->len;
		f86_sys_deliver_irq(c);
		return 0;
	}
	if (op == 0xFC) { /* cld */
		g_vdf = 0;
		c->rip += d->len;
		return 0;
	}
	if (op == 0xFD) { /* std */
		g_vdf = 1;
		c->rip += d->len;
		return 0;
	}
	if (op == 0x9C) { /* pushfq: architectural RFLAGS with the virtual IF/DF */
		uint64_t a = f86_rflags_arch(c), sp = c->r[R_RSP] - 8, gpa = 0;
		if (f86_gva_to_gpa(sp, &gpa) && gpa + 8 <= g_ram_sz) {
			memcpy(g_ram + gpa, &a, 8);
			c->r[R_RSP] = sp;
		}
		c->rip += d->len;
		return 0;
	}
	if (op == 0x9D) { /* popfq */
		uint64_t a = 0, gpa = 0;
		if (f86_gva_to_gpa(c->r[R_RSP], &gpa) && gpa + 8 <= g_ram_sz) {
			memcpy(&a, g_ram + gpa, 8);
			c->r[R_RSP] += 8;
			f86_rflags_set_arch(c, a);
		}
		c->rip += d->len;
		if (g_vif)
			f86_sys_deliver_irq(c);
		return 0;
	}
	if (op >= 0x6C && op <= 0x6F) {
		/* INS/OUTS [rep]: size 1 for 6C/6E, else 32-bit (16 with 0x66) */
		int sz = (op & 1) ? 4 : 1;
		int rep = 0;
		for (const uint8_t *q = ip; q < ip + d->len - 1; q++) {
			if (*q == 0xF3 || *q == 0xF2) rep = 1;
			if (*q == 0x66 && sz == 4) sz = 2;
		}
		uint64_t n = rep ? c->r[R_RCX] : 1;
		if (n > (1u << 20))
			n = 1u << 20;
		uint16_t port = (uint16_t)c->r[R_RDX];
		int64_t step = g_vdf ? -sz : sz;
		uint64_t i = 0;
		for (; i < n; i++) {
			uint64_t gpa = 0;
			if (op <= 0x6D) { /* INS: port -> [rdi] */
				uint32_t v = io_read(port, sz);
				if (!f86_gva_to_gpa(c->r[R_RDI], &gpa) || gpa + (unsigned)sz > g_ram_sz)
					break;
				memcpy(g_ram + gpa, &v, (size_t)sz);
				c->r[R_RDI] += (uint64_t)step;
			} else {          /* OUTS: [rsi] -> port */
				uint32_t v = 0;
				if (!f86_gva_to_gpa(c->r[R_RSI], &gpa) || gpa + (unsigned)sz > g_ram_sz)
					break;
				memcpy(&v, g_ram + gpa, (size_t)sz);
				io_write(port, v, sz);
				c->r[R_RSI] += (uint64_t)step;
			}
		}
		if (rep)
			c->r[R_RCX] -= i;
		c->rip += d->len;
		return 0;
	}
	if (op == 0xE4 || op == 0xE5) {
		uint8_t port = ip[d->len - 1];
		uint32_t v = io_read(port, op == 0xE4 ? 1 : 4);
		if (op == 0xE4)
			c->r[R_RAX] = (c->r[R_RAX] & ~0xffull) | (v & 0xff);
		else
			c->r[R_RAX] = (c->r[R_RAX] & ~0xffffffffull) | v;
		c->rip += d->len;
		return 0;
	}
	if (op == 0xE6 || op == 0xE7) {
		uint8_t port = ip[d->len - 1];
		io_write(port, (uint32_t)c->r[R_RAX], op == 0xE6 ? 1 : 4);
		c->rip += d->len;
		return 0;
	}
	if (op == 0xEC || op == 0xED) {
		uint16_t port = (uint16_t)c->r[R_RDX];
		uint32_t v = io_read(port, op == 0xEC ? 1 : 4);
		if (op == 0xEC)
			c->r[R_RAX] = (c->r[R_RAX] & ~0xffull) | (v & 0xff);
		else
			c->r[R_RAX] = (c->r[R_RAX] & ~0xffffffffull) | v;
		c->rip += d->len;
		return 0;
	}
	if (op == 0xEE || op == 0xEF) {
		io_write((uint16_t)c->r[R_RDX], (uint32_t)c->r[R_RAX],
		         op == 0xEE ? 1 : 4);
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0xA2) {
		/* Coffee Lake-class CPU, no hypervisor bit — Sequoia 15.4.1
		   recovery accepts iMacPro1,1 / VMM; AppleHV/KVM PV stays off. */
		uint32_t leaf = (uint32_t)c->r[R_RAX];
		uint32_t sub = (uint32_t)c->r[R_RCX];
		uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
		if (leaf == 0) {
			eax = 22;
			ebx = 0x756e6547; /* Genu */
			edx = 0x49656e69; /* ineI */
			ecx = 0x6c65746e; /* ntel */
		} else if (leaf == 1) {
			eax = 0x000906EB; /* Coffee Lake */
			ebx = 0x00010800; /* 1 logical processor, APIC 0 */
			/* hypervisor bit 31 CLEAR */
			ecx = 0x7ffaf7bf; /* no x2APIC */
			edx = 0xbfebfbff;
		} else if (leaf == 2) {
			eax = 0x76036301;
			ebx = 0x00f0b5ff;
			ecx = 0x00000000;
			edx = 0x00c30000;
		} else if (leaf == 4) {
			if (sub == 0) {
				eax = 0x00004121; /* 1 core, 1 thread */
				ebx = 0x01c0003f;
				ecx = 0x0000003f;
				edx = 0x00000000;
			} else if (sub == 1) {
				eax = 0x00004122;
				ebx = 0x01c0003f;
				ecx = 0x0000003f;
				edx = 0x00000000;
			} else if (sub == 2) {
				eax = 0x00004143;
				ebx = 0x00c0003f;
				ecx = 0x000003ff;
				edx = 0x00000000;
			} else if (sub == 3) {
				eax = 0x00000163;
				ebx = 0x03c0003f;
				ecx = 0x00001fff;
				edx = 0x00000006;
			}
		} else if (leaf == 0xb) {
			/* Extended topology: one SMT thread, one core. */
			if (sub == 0) {
				eax = 0x00000001;
				ebx = 0x00000001;
				ecx = 0x00000100;
				edx = 0;
			} else if (sub == 1) {
				eax = 0x00000001;
				ebx = 0x00000001;
				ecx = 0x00000201;
				edx = 0;
			}
		} else if (leaf == 7 && sub == 0) {
			ebx = 0x009c6fbb; /* AVX2 BMI SMEP SMAP */
			ecx = 0x00000000;
			edx = 0x00000000;
		} else if (leaf == 0x15) {
			/* TSC/crystal ratio: the guest TSC is the host TSC. */
			uint64_t hz = f86_host_tsc_hz();
			eax = 2;
			ebx = (uint32_t)((hz * 2 + 12000000ull) / 24000000ull);
			ecx = 24000000;
		} else if (leaf == 0x16) {
			uint64_t mhz = f86_host_tsc_hz() / 1000000ull;
			eax = (uint32_t)mhz; /* base MHz */
			ebx = (uint32_t)mhz; /* max MHz */
			ecx = 100;           /* bus MHz */
		} else if (leaf == 0x0d && sub == 0) {
			eax = 0x00000007; /* x87 SSE AVX */
			ebx = 0x00000340;
			ecx = 0x00000340;
		} else if (leaf == 0x80000000) {
			eax = 0x80000008;
		} else if (leaf == 0x80000001) {
			edx = 0x2c100800; /* NX, SYSCALL, RDTSCP */
			ecx = 0x00000121;
		} else if (leaf == 0x80000007) {
			edx = 0x00000100; /* invariant TSC */
		} else if (leaf == 0x80000008) {
			eax = 0x00003027; /* phys 39, virt 48 */
		}
		c->r[R_RAX] = eax;
		c->r[R_RBX] = ebx;
		c->r[R_RCX] = ecx;
		c->r[R_RDX] = edx;
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0xC7) {
		int ext = (d->modrm >> 3) & 7;
		int rm = d->modrm & 7;
		if (d->rex & 1)
			rm |= 8;
		if (ext == 6 || ext == 7) {
			uint32_t lo, hi;
			__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
			uint64_t v = ((uint64_t)hi << 32) | lo;
			v ^= (v << 13) ^ (c->rip * 0x9e3779b97f4a7c15ull);
			v ^= (uint64_t)c->n_sysops << 17;
			c->r[rm] = v ? v : 0x123456789abcdef0ull;
			/* Bit 0 = real CF; bit 8 = CF in the LAHF/SAHF spill slot. */
			c->rflags |= 0x101ull;
			c->rip += d->len;
			{
				static int nr;
				if (nr++ < 4)
					fprintf(stderr, "fast86: rdrand/rdseed -> %lx\n",
					        (unsigned long)c->r[rm]);
			}
			return 0;
		}
	}
	if (op == 0x0F && op2 == 0x31) {
		/* rdtsc — host tsc is fine */
		uint32_t lo, hi;
		__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
		c->r[R_RAX] = lo;
		c->r[R_RDX] = hi;
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x32) { /* rdmsr */
		uint32_t m = (uint32_t)c->r[R_RCX];
		uint64_t v = 0;
		if (m == 0xC0000080)
			v = c->efer;
		else if (m == 0x1B) {
			v = c->apic_base ? c->apic_base : 0xFEE00000ull;
			fprintf(stderr, "fast86: rdmsr APIC_BASE -> %lx (rip=%lx)\n", (unsigned long)v, (unsigned long)c->rip);
		}
		else if (m == 0xC0000100)
			v = c->fs_base;
		else if (m == 0xC0000101)
			v = c->gs_base;
		else if (m == 0xC0000102)
			v = c->kernel_gs;
		else if (m == 0x6E0)
			v = g_tsc_deadline;
		else if (m == 0x10)
			v = 24; /* TSC_ADJUST / unused */
		else if (m == 0x3A)
			v = 0; /* IA32_FEATURE_CONTROL */
		else if (m == 0xC0000081)
			v = g_star;
		else if (m == 0xC0000082)
			v = g_lstar;
		else if (m == 0xC0000083)
			v = g_cstar;
		else if (m == 0xC0000084)
			v = g_sfmask;
		else if (m == 0x17A || m == 0x17B || m == 0x48 || m == 0x49)
			v = 0; /* SMBASE / debug */
		else if (m == 0x2A || m == 0x2B)
			v = 0;
		else if ((m >= 0x200 && m <= 0x2FF) || m == 0xFE || m == 0x2FF)
			v = 0; /* MTRR */
		else if (m == 0x277)
			v = 0x0007040600070406ull; /* PAT */
		else if (m == 0x1A0)
			v = 0x00850089; /* misc enable */
		else if (m == 0xCE) {
			/* MSR_PLATFORM_INFO: bits 15:8 max non-turbo ratio. XNU's
			   tsc_init multiplies this by the 100 MHz bus clock. */
			uint64_t ratio = (f86_host_tsc_hz() + 50000000ull) / 100000000ull;
			if (ratio < 1) ratio = 1;
			v = (ratio << 8) | (ratio << 40);
		} else if (m == 0x35)
			v = 0x00010001; /* MSR_CORE_THREAD_COUNT: 1 core, 1 thread */
		else if (m == 0x198 || m == 0x199) {
			uint64_t ratio = (f86_host_tsc_hz() + 50000000ull) / 100000000ull;
			v = ratio << 8; /* PERF_STATUS / PERF_CTL current ratio */
		} else if (m == 0xE2 || m == 0xE4 || m == 0x194 || m == 0x1AA || m == 0x1FC || m == 0x606 || m == 0x610 || m == 0x611 || m == 0x639 || m == 0x641 || m == 0x619)
			v = 0; /* PKG_CST_CONFIG, PMG_IO_CAPTURE, FLEX_RATIO, MISC_PWR_MGMT, POWER_CTL, RAPL */
		else
			fprintf(stderr, "fast86: rdmsr %x -> 0 (rip=%lx)\n",
			        m, (unsigned long)c->rip);
		c->r[R_RAX] = (uint32_t)v;
		c->r[R_RDX] = (uint32_t)(v >> 32);
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x30) { /* wrmsr */
		uint32_t m = (uint32_t)c->r[R_RCX];
		uint64_t v = (c->r[R_RAX] & 0xffffffffull) |
		             (c->r[R_RDX] << 32);
		if (m == 0xC0000080)
			c->efer = v;
		else if (m == 0xC0000081) {
			g_star = v;
			fprintf(stderr, "fast86: wrmsr STAR=%lx\n", (unsigned long)v);
		} else if (m == 0xC0000082) {
			g_lstar = v;
			fprintf(stderr, "fast86: wrmsr LSTAR=%lx\n", (unsigned long)v);
		} else if (m == 0xC0000083)
			g_cstar = v;
		else if (m == 0xC0000084)
			g_sfmask = v;
		else if (m == 0x1B) {
			fprintf(stderr, "fast86: wrmsr APIC_BASE = %lx (rip=%lx)\n", (unsigned long)v, (unsigned long)c->rip);
			c->apic_base = v;
		}
		else if (m == 0xC0000100)
			c->fs_base = v;
		else if (m == 0xC0000101) {
			/* (An earlier hack rewrote cpu_data+0x28c, XNU's cdi_idtu,
			   with the boot IDT here, which together with the old LIDT
			   window check kept every trap on master_boot_idt64's HLT
			   stub. Both are gone: the real double-mapped IDT loads.) */
			c->gs_base = v;
			f86_sys_refresh_gs();
			fprintf(stderr, "fast86: wrmsr GS_BASE=%lx host=%lx\n",
			        (unsigned long)v, (unsigned long)f86_gs_host);
		} else if (m == 0xC0000102) {
			c->kernel_gs = v;
			fprintf(stderr, "fast86: wrmsr KERNEL_GS=%lx\n", (unsigned long)v);
		}
		else if (m == 0x6E0) {
			g_tsc_deadline = v;
			static int ndl;
			if (ndl++ < 24 || (ndl % 5000) == 0) {
				uint32_t lo, hi;
				__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
				uint64_t now = ((uint64_t)hi << 32) | lo;
				fprintf(stderr, "fast86: wrmsr TSC_DEADLINE=%lx now=%lx delta=%.3f ms (n=%d)\n",
				        (unsigned long)v, (unsigned long)now,
				        (double)(int64_t)(v - now) / (double)f86_host_tsc_hz() * 1000.0, ndl);
			}
		}
		else
			fprintf(stderr, "fast86: wrmsr %x = %lx (rip=%lx)\n",
			        m, (unsigned long)v, (unsigned long)c->rip);
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && (op2 == 0x21 || op2 == 0x23)) {
		/* MOV r64, DRn reads 0; MOV DRn, r64 is ignored (no debug regs). */
		if (op2 == 0x21) {
			int rm = d->modrm & 7;
			if (d->rex & 1)
				rm |= 8;
			c->r[rm] = 0;
		}
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && (op2 == 0x20 || op2 == 0x22)) {
		int rm = d->modrm & 7;
		if (d->rex & 1)
			rm |= 8;
		int cr = (d->modrm >> 3) & 7;
		if (d->rex & 4)
			cr |= 8;
		if (op2 == 0x20) {
			uint64_t v = 0;
			if (cr == 0) v = c->cr0;
			else if (cr == 2) v = c->cr2;
			else if (cr == 3) v = c->cr3;
			else if (cr == 4) v = c->cr4;
			else if (cr == 8) v = c->cr8;
			c->r[rm] = v;
		} else {
			uint64_t old = c->cr0;
			uint64_t old3 = c->cr3;
			uint64_t old4 = c->cr4;
			if (cr == 0) c->cr0 = c->r[rm];
			else if (cr == 2) c->cr2 = c->r[rm];
			else if (cr == 3) c->cr3 = c->r[rm];
			else if (cr == 4) c->cr4 = c->r[rm];
			else if (cr == 8) {
				c->cr8 = c->r[rm] & 0xff;
				g_lapic[0x80 / 4] = (uint32_t)(c->cr8 << 4);
			}
			if (cr != 8 && (cr != 3 || ((old3 ^ c->cr3) & ~0xfffull)))
				fprintf(stderr, "fast86: mov cr%u = %lx (rip=%lx)\n",
				        cr, (unsigned long)c->r[rm], (unsigned long)c->rip);
			if (cr == 0 && ((old ^ c->cr0) & CR0_PG)) {
				f86_cache_flush();
				walk_cache_inval();
				f86_alias_drop_all();
			}
			if (cr == 4 && ((old4 ^ c->cr4) & 0x200b0ull)) {
				/* PSE/PAE/PGE/PCIDE change: full TLB flush */
				walk_cache_inval();
				f86_alias_drop_all();
			}
			if (cr == 3) {
				static int once_pt;
				walk_cache_inval();
				/* A different address space: drop the user half and
				   apply pending page-table changes; a same-value reload
				   is XNU's kernel-wide TLB flush: apply changes only. */
				f86_alias_flush(((old3 ^ c->cr3) & 0x000ffffffffff000ull) ? 1 : 2);
				/* Same CR3 = TLB shootdown; keep translations. */
				if ((old3 ^ c->cr3) & ~0xfffull)
					f86_cache_flush();
				uint64_t a = c->cr3 & 0x000ffffffffff000ull;
				if (once_pt++)
					a = ~0ull; /* skip rebuild on later kernel CR3 loads */
				if (a != ~0ull && a + 4096 <= g_ram_sz) {
					uint64_t *p4 = (uint64_t *)(g_ram + a);
					uint64_t pdpt = p4[0] & 0x000ffffffffff000ull;
					fprintf(stderr, "fast86: pml4[0]=%lx pml4[1ff]=%lx\n",
					        (unsigned long)p4[0], (unsigned long)p4[511]);
					if (pdpt + 32 <= g_ram_sz) {
						uint64_t *d = (uint64_t *)(g_ram + pdpt);
						/* Rebuild 2MiB identity pages for the whole 4GiB so
						   kvtophys/PHYSMAP_PTOV cover every GPA we emulate. */
						for (int i = 0; i < 4; i++) {
							uint64_t pd = d[i] & 0x000ffffffffff000ull;
							if (!pd || pd + 4096 > g_ram_sz)
								continue;
							uint64_t *e = (uint64_t *)(g_ram + pd);
							for (int j = 0; j < 512; j++) {
								uint64_t pa = ((uint64_t)i << 30) |
								              ((uint64_t)j << 21);
								e[j] = pa | 0x83; /* P+RW+PS */
							}
						}
						fprintf(stderr,
						        "fast86: pdpt[0]=%lx [1]=%lx [2]=%lx [3]=%lx (2MiB identity)\n",
						        (unsigned long)d[0], (unsigned long)d[1],
						        (unsigned long)d[2], (unsigned long)d[3]);
					}
				}
			}
		}
		c->rip += d->len;
		return 0;
	}
	if (op == 0xEA || op == 0x9A) {
		/* 32-bit far jmp/call: ignore selector, take 32-bit offset. */
		uint32_t off = 0;
		memcpy(&off, ip + 1, 4);
		fprintf(stderr, "fast86: ljmp %04x:%08x from %lx\n",
		        (unsigned)(ip[5] | (ip[6] << 8)), off,
		        (unsigned long)c->rip);
		c->rip = off;
		return 2;
	}
	if (op == 0xFF) {
		int reg = (d->modrm >> 3) & 7;
		if (reg == 3 || reg == 5) {
			/* far call/jmp m16:32 — load offset from EA, ignore CS */
			uint64_t addr;
			int rm = d->modrm & 7;
			if (d->rex & 1)
				rm |= 8;
			if (d->flags & F86_RIPREL)
				addr = c->rip + d->len + (int64_t)d->disp;
			else if ((d->modrm & 7) == 4) {
				uint8_t sib = ip[d->modrm_off + 1];
				int base = sib & 7, idx = (sib >> 3) & 7, sc = sib >> 6;
				if (d->rex & 1) base |= 8;
				if (d->rex & 2) idx |= 8;
				addr = 0;
				if (idx != 4)
					addr += c->r[idx] << sc;
				if ((d->modrm >> 6) == 0 && (sib & 7) == 5)
					addr += (int32_t)d->disp;
				else {
					addr += c->r[base];
					if (d->modrm >> 6)
						addr += (int64_t)d->disp;
				}
			} else {
				addr = c->r[rm];
				if (d->modrm >> 6)
					addr += (int64_t)d->disp;
			}
			uint32_t off = 0;
			uint64_t gpa = 0;
			if (f86_gva_to_gpa(addr, &gpa) && gpa + 4 <= g_ram_sz)
				memcpy(&off, g_ram + gpa, 4);
			fprintf(stderr, "fast86: ljmp m16:32 [%lx] -> %x from %lx\n",
			        (unsigned long)addr, off, (unsigned long)c->rip);
			if (off) {
				c->rip = off;
				return 2;
			}
			c->rip += d->len;
			return 0;
		}
	}
	if (op == 0x8E || op == 0x8C) {
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x00) {
		/* sldt / str / lldt / ltr */
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0xB9) {
		/* UD1 — skip */
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x0B) {
		{
			uint64_t gpa = 0;
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 32 < g_ram_sz &&
			    memmem(g_ram + gpa, 80, "non-sleepable RW lock", 21)) {
				fprintf(stderr, "fast86: skip RW-lock UD2\n");
				uint64_t rbp = c->r[R_RBP], gp = 0, sv = 0, ret = 0;
				if (f86_gva_to_gpa(rbp, &gp) && gp + 16 <= g_ram_sz) {
					memcpy(&sv, g_ram + gp, 8);
					memcpy(&ret, g_ram + gp + 8, 8);
					if (ret > 0x1000) {
						c->r[R_RBP] = sv;
						c->r[R_RSP] = rbp + 16;
						c->rip = ret;
						return 2;
					}
				}
				c->rip += d->len;
				return 0;
			}
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 20 < g_ram_sz &&
			    (memmem(g_ram + gpa, 96, "accounting mismatch", 19) ||
			     memmem(g_ram + gpa, 96, "freelist is corrupt", 19) ||
			     memmem(g_ram + gpa, 80, "Releasing non-exclusive", 23) ||
			     memmem(g_ram + gpa, 96, "isn't aligned to zone", 21) ||
			     memmem(g_ram + gpa, 64, "Invalid waitq", 13))) {
				fprintf(stderr, "fast86: skip zone/rwlock UD2\n");
				uint64_t rbp = c->r[R_RBP], gp = 0, sv = 0, ret = 0;
				if (f86_gva_to_gpa(rbp, &gp) && gp + 16 <= g_ram_sz) {
					memcpy(&sv, g_ram + gp, 8);
					memcpy(&ret, g_ram + gp + 8, 8);
					if (ret >= 0xffffff8000100000ull) {
						c->r[R_RBP] = sv;
						c->r[R_RSP] = rbp + 16;
						c->rip = ret;
						return 2;
					}
				}
				c->rip += d->len;
				return 0;
			}
			if (f86_gva_to_gpa(c->r[R_RDI], &gpa) && gpa + 16 < g_ram_sz &&
			    (memcmp(g_ram + gpa, "DBLMAP", 6) == 0 ||
			     memcmp(g_ram + gpa, "PHYSMAP", 7) == 0)) {
				uint64_t va = c->r[R_RDX];
				if ((va >> 40) != 0xfffff6ull && va < 0x100000000ull)
					va |= 0xfffff68000000000ull;
				fprintf(stderr, "fast86: DBLMAP/PHYSMAP ud2 skip -> %lx\n",
				        (unsigned long)va);
				c->r[R_RAX] = va;
				{
					uint64_t rbp = c->r[R_RBP], gp = 0, sv = 0, ret = 0;
					if (f86_gva_to_gpa(rbp, &gp) && gp + 16 <= g_ram_sz) {
						memcpy(&sv, g_ram + gp, 8);
						memcpy(&ret, g_ram + gp + 8, 8);
						if (ret > 0x1000) {
							c->r[R_RBP] = sv;
							c->r[R_RSP] = rbp + 16;
							c->rip = ret;
							return 2;
						}
					}
				}
				c->rip += d->len;
				return 0;
			}
		}
		fprintf(stderr,
		        "fast86: UD2/panic at %lx rax=%lx rdi=%lx rsi=%lx rdx=%lx rcx=%lx rbx=%lx rsp=%lx\n",
		        (unsigned long)c->rip,
		        (unsigned long)c->r[R_RAX], (unsigned long)c->r[R_RDI],
		        (unsigned long)c->r[R_RSI], (unsigned long)c->r[R_RDX],
		        (unsigned long)c->r[R_RCX], (unsigned long)c->r[R_RBX],
		        (unsigned long)c->r[R_RSP]);
		{
			uint64_t gpa = 0;
			if (f86_gva_to_gpa(c->r[R_RSI], &gpa) && gpa + 8 < g_ram_sz) {
				char buf[128];
				memset(buf, 0, sizeof buf);
				memcpy(buf, g_ram + gpa, 120);
				fprintf(stderr, "fast86: panic rsi@%lx '%s'\n",
				        (unsigned long)c->r[R_RSI], buf);
			}
			if (f86_gva_to_gpa(c->r[R_RDI], &gpa) && gpa + 8 < g_ram_sz) {
				char buf[128];
				memset(buf, 0, sizeof buf);
				memcpy(buf, g_ram + gpa, 120);
				fprintf(stderr, "fast86: panic rdi@%lx '%s'\n",
				        (unsigned long)c->r[R_RDI], buf);
			}
		}
		c->exited = 1;
		c->exit_code = 127;
		return 1;
	}
	if (op == 0x0F && (op2 == 0x08 || op2 == 0x09 || op2 == 0x06)) {
		/* invd / wbinvd / clts */
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x38) {
		/* INVPCID r64, m128: type in the register, {pcid, addr} descriptor
		   in memory. XNU (pmap_tlbi_range) uses ALLG for every kernel
		   flush and SINGLE/ASPACE for user pmaps. */
		int reg = (d->modrm >> 3) & 7;
		if (d->rex & 4)
			reg |= 8;
		uint64_t type = c->r[reg];
		uint64_t ea = insn_ea(c, ip, d), gpa = 0, dpcid = 0, daddr = 0;
		if (f86_gva_to_gpa(ea, &gpa) && gpa + 16 <= g_ram_sz) {
			memcpy(&dpcid, g_ram + gpa, 8);
			memcpy(&daddr, g_ram + gpa + 8, 8);
		}
		walk_cache_inval();
		if (type == 0)
			f86_alias_inval(daddr);
		else if (type == 1 && (dpcid & 0xfff) != 0)
			f86_alias_flush(1); /* one user address space: the low half */
		else
			f86_alias_flush(2); /* kernel-wide: apply page-table changes */
		g_invpcid_n[type & 3]++;
		c->rip += d->len;
		return 0;
	}
	if (op == 0x0F && op2 == 0x01) {
		int ext = (d->modrm >> 3) & 7;
		int mod = d->modrm >> 6;
		if (mod != 3) {
			uint64_t ea = insn_ea(c, ip, d), gpa = 0;
			if (ext == 7) {
				/* INVLPG: the guest changed a translation. Drop the
				   walk cache so page-table reads (XNU's recursive PTE
				   window, physmap) stop seeing stale physical pages,
				   and the alias page so the host MMU re-faults. */
				walk_cache_inval();
				f86_alias_inval(ea);
			}
			if (ext == 0 || ext == 1 || ext == 2 || ext == 3) {
				if (f86_gva_to_gpa(ea, &gpa) && gpa + 10 <= g_ram_sz) {
					if (ext == 2 || ext == 3) {
						uint16_t lim = 0;
						uint64_t base = 0;
						memcpy(&lim, g_ram + gpa, 2);
						memcpy(&base, g_ram + gpa + 2, 8);
						if (ext == 2) {
							if (base > 0x1000) {
								c->gdt_limit = lim;
								c->gdt_base = base;
							}
							fprintf(stderr, "fast86: lgdt %lx lim=%x\n",
							        (unsigned long)base, lim);
						} else {
							/* Any canonical kernel-half base: XNU's real
							   IDT lives in the double map (0xfffff6...). */
							if ((base >> 47) == 0x1ffffull && lim >= 0x100) {
								c->idt_limit = lim;
								c->idt_base = base;
								uint64_t gp = 0;
								g_idt_gpa = 0;
								if (f86_gva_to_gpa(base, &gp))
									g_idt_gpa = gp;
							}
							fprintf(stderr, "fast86: lidt %lx lim=%x keep=%lx (ea=%lx gpa=%lx rip=%lx)\n",
							        (unsigned long)base, lim,
							        (unsigned long)c->idt_base,
							        (unsigned long)ea, (unsigned long)gpa,
							        (unsigned long)c->rip);
							{
								/* debug: compare RAM view with the alias view */
								uint64_t av = 0, dd = 0, db = 0, dm = 0;
								uint64_t hv = ea + f86_alias_off();
								memcpy(&av, (void *)(uintptr_t)(hv + 2), 8);
								uint64_t g1 = 0, g2 = 0, g3 = 0;
								uint64_t b = 0xffffff8000000000ull | ((f86_kernel_base() - 0x100000ull) & 0xffffffffull);
								if (f86_gva_to_gpa(b + 0x12da188ull, &g1)) memcpy(&dd, g_ram + g1, 8);
								if (f86_gva_to_gpa(b + 0x12da178ull, &g2)) memcpy(&db, g_ram + g2, 8);
								if (f86_gva_to_gpa(b + 0x12da180ull, &g3)) memcpy(&dm, g_ram + g3, 8);
								fprintf(stderr, "fast86:   alias view base=%lx dblmap_dist=%lx base=%lx max=%lx\n",
								        (unsigned long)av, (unsigned long)dd, (unsigned long)db, (unsigned long)dm);
							}
						}
					} else {
						uint16_t lim = (ext == 0) ? c->gdt_limit : c->idt_limit;
						uint64_t base = (ext == 0) ? c->gdt_base : c->idt_base;
						memcpy(g_ram + gpa, &lim, 2);
						memcpy(g_ram + gpa + 2, &base, 8);
					}
				}
			}
		} else if (d->modrm == 0xF8) {
			uint64_t t = c->gs_base;
			c->gs_base = c->kernel_gs;
			c->kernel_gs = t;
			f86_sys_refresh_gs();
			fprintf(stderr, "fast86: swapgs gs=%lx kgs=%lx host=%lx\n",
			        (unsigned long)c->gs_base, (unsigned long)c->kernel_gs,
			        (unsigned long)f86_gs_host);
		} else if (d->modrm == 0xD0) {
			/* XGETBV: ECX=0 -> XCR0 (x87|SSE|AVX as advertised by CPUID 0xD) */
			static uint64_t *xcr0p;
			if (!xcr0p) xcr0p = &g_xcr0;
			uint64_t v = ((uint32_t)c->r[R_RCX] == 0) ? g_xcr0 : 0;
			c->r[R_RAX] = (uint32_t)v;
			c->r[R_RDX] = (uint32_t)(v >> 32);
		} else if (d->modrm == 0xD1) {
			/* XSETBV */
			if ((uint32_t)c->r[R_RCX] == 0)
				g_xcr0 = ((uint64_t)(uint32_t)c->r[R_RDX] << 32) | (uint32_t)c->r[R_RAX];
		} else if (d->modrm == 0xF9) {
			uint32_t lo, hi;
			__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
			c->r[R_RAX] = lo;
			c->r[R_RDX] = hi;
			c->r[R_RCX] = 0;
		}
		c->rip += d->len;
		return 0;
	}
	if (op == 0xCC) {
		fprintf(stderr, "fast86: int3 at %lx rax=%lx rdi=%lx rsi=%lx rdx=%lx rcx=%lx r8=%lx r9=%lx r10=%lx rsp=%lx\n",
		        (unsigned long)c->rip,
		        (unsigned long)c->r[R_RAX], (unsigned long)c->r[R_RDI],
		        (unsigned long)c->r[R_RSI], (unsigned long)c->r[R_RDX],
		        (unsigned long)c->r[R_RCX], (unsigned long)c->r[R_R8],
		        (unsigned long)c->r[R_R9], (unsigned long)c->r[R_R10],
		        (unsigned long)c->r[R_RSP]);
		{
			uint64_t regs[4] = { c->r[R_RSI], c->r[R_RDX], c->r[R_RCX], c->r[R_R8] };
			const char *nm[4] = { "rsi", "rdx", "rcx", "r8" };
			for (int i = 0; i < 4; i++) {
				uint64_t gpa = 0;
				if (!f86_gva_to_gpa(regs[i], &gpa) || gpa + 8 >= g_ram_sz)
					continue;
				if (g_ram[gpa] < 0x20 || g_ram[gpa] >= 0x7f)
					continue;
				char s[160];
				memset(s, 0, sizeof s);
				memcpy(s, g_ram + gpa, 150);
				fprintf(stderr, "fast86: %s \"%s\"\n", nm[i], s);
			}
		}
		{
			uint64_t gpa = 0;
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 20 < g_ram_sz &&
			    (memmem(g_ram + gpa, 96, "accounting mismatch", 19) ||
			     memmem(g_ram + gpa, 96, "freelist is corrupt", 19) ||
			     memmem(g_ram + gpa, 80, "Releasing non-exclusive", 23) ||
			     memmem(g_ram + gpa, 96, "isn't aligned to zone", 21) ||
			     memmem(g_ram + gpa, 64, "Invalid waitq", 13))) {
				fprintf(stderr, "fast86: skip zone/rwlock panic\n");
				uint64_t rbp = c->r[R_RBP], gp = 0, sv = 0, ret = 0;
				if (f86_gva_to_gpa(rbp, &gp) && gp + 16 <= g_ram_sz) {
					memcpy(&sv, g_ram + gp, 8);
					memcpy(&ret, g_ram + gp + 8, 8);
					if (ret >= 0xffffff8000100000ull) {
						c->r[R_RBP] = sv;
						c->r[R_RSP] = rbp + 16;
						c->rip = ret;
						return 2;
					}
				}
				c->rip += d->len;
				return 0;
			}
		}
		for (int i = 0; i < 16; i++) {
			uint64_t a = c->r[R_RSP] + (uint64_t)i * 8, gpa = 0, v = 0;
			if (!f86_gva_to_gpa(a, &gpa) || gpa + 8 > g_ram_sz)
				break;
			memcpy(&v, g_ram + gpa, 8);
			fprintf(stderr, "  stack[%d] %lx", i, (unsigned long)v);
			if (f86_gva_to_gpa(v, &gpa) && gpa + 8 < g_ram_sz &&
			    g_ram[gpa] >= 0x20 && g_ram[gpa] < 0x7f) {
				char s[80];
				memset(s, 0, sizeof s);
				memcpy(s, g_ram + gpa, 72);
				fprintf(stderr, " \"%s\"", s);
			}
			fprintf(stderr, "\n");
		}
		/* Walk the frame chain to find the DBLMAP_CHECK caller. */
		{
			uint64_t fp = c->r[R_RBP];
			for (int fr = 0; fr < 8 && fp; fr++) {
				uint64_t gpa = 0, sfp = 0, ret = 0;
				if (!f86_gva_to_gpa(fp, &gpa) || gpa + 16 > g_ram_sz)
					break;
				memcpy(&sfp, g_ram + gpa, 8);
				memcpy(&ret, g_ram + gpa + 8, 8);
				fprintf(stderr, "  frame[%d] rbp=%lx ret=%lx\n", fr,
				        (unsigned long)sfp, (unsigned long)ret);
				if (sfp <= fp || sfp > fp + 0x100000)
					break;
				fp = sfp;
			}
		}
		/* pmap_map_bd: Invalid kernel address — dump the EFI runtime map
		   that efi_init is walking so we can see the failing VirtualStart. */
		{
			uint64_t gpa = 0;
			int is_mbd = 0;
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 16 < g_ram_sz &&
			    memmem(g_ram + gpa, 64, "map_bd", 7))
				is_mbd = 1;
			if (f86_gva_to_gpa(c->r[R_RSI], &gpa) && gpa + 16 < g_ram_sz &&
			    memmem(g_ram + gpa, 64, "map_bd", 7))
				is_mbd = 1;
			/* Always dump the EFI map on a kernel panic: cheap and
			   invaluable for the runtime-map panics. */
			if (!is_mbd) {
				uint64_t ba = f86_kernel_boot_args();
				if (ba && ba + 1160 < g_ram_sz) {
					uint8_t *p = g_ram + ba;
					uint32_t mm = 0, msz = 0, dsz = 0;
					memcpy(&mm, p + 1032, 4);
					memcpy(&msz, p + 1036, 4);
					memcpy(&dsz, p + 1040, 4);
					fprintf(stderr, "fast86: [panic] efi map mm=%x sz=%u dsz=%u\n",
					        mm, msz, dsz);
					if (dsz >= 40 && mm && mm + msz <= g_ram_sz) {
						for (uint32_t i = 0; i < msz / dsz && i < 16; i++) {
							const uint8_t *d = g_ram + mm + (uint64_t)i * dsz;
							uint32_t ty; uint64_t ph, vt, pg, at;
							memcpy(&ty, d, 4);
							memcpy(&ph, d + 8, 8);
							memcpy(&vt, d + 16, 8);
							memcpy(&pg, d + 24, 8);
							memcpy(&at, d + 32, 8);
							fprintf(stderr, "  [%u] ty=%u phys=%lx virt=%lx pg=%lx at=%lx\n",
							        i, ty, (unsigned long)ph, (unsigned long)vt,
							        (unsigned long)pg, (unsigned long)at);
						}
					}
				}
			}
			if (is_mbd) {
				uint64_t ba = f86_kernel_boot_args();
				fprintf(stderr, "fast86: pmap_map_bd panic — boot_args@%lx\n",
				        (unsigned long)ba);
				if (ba && ba + 1160 < g_ram_sz) {
					uint8_t *p = g_ram + ba;
					uint32_t mm = 0, msz = 0, dsz = 0, kaddr = 0, ksz = 0;
					uint64_t rtv = 0;
					uint32_t rtp = 0, rtcnt = 0;
					uint64_t rtv2 = 0;
					memcpy(&mm, p + 1032, 4);
					memcpy(&msz, p + 1036, 4);
					memcpy(&dsz, p + 1040, 4);
					memcpy(&kaddr, p + 1076, 4);
					memcpy(&ksz, p + 1080, 4);
					memcpy(&rtp, p + 1084, 4);
					memcpy(&rtcnt, p + 1088, 4);
					memcpy(&rtv2, p + 1092, 8);
					fprintf(stderr,
					        "fast64: mm=%x sz=%u dsz=%u kaddr=%x ksz=%x rt.{p=%x,c=%u,v=%lx}\n",
				        mm, msz, dsz, kaddr, ksz, rtp, rtcnt, (unsigned long)rtv2);
					if (dsz >= 40 && mm && mm + msz <= g_ram_sz) {
						for (uint32_t i = 0; i < msz / dsz && i < 16; i++) {
							const uint8_t *d = g_ram + mm + (uint64_t)i * dsz;
							uint32_t ty; uint64_t ph, vt, pg, at;
							memcpy(&ty, d, 4);
							memcpy(&ph, d + 8, 8);
							memcpy(&vt, d + 16, 8);
							memcpy(&pg, d + 24, 8);
							memcpy(&at, d + 32, 8);
							fprintf(stderr, "  [%u] ty=%u phys=%lx virt=%lx pg=%lx at=%lx\n",
							        i, ty, (unsigned long)ph, (unsigned long)vt,
							        (unsigned long)pg, (unsigned long)at);
						}
					}
				}
			}
		}
		/* The panic() path formats the message into a guest buffer before
		   trapping. Find the *formatted* DBLMAP/PHYSMAP message (which
		   carries the real varargs + file:line) instead of guessing from
		   clobbered registers. Bounded to the kernel image so this stays
		   fast (was scanning all of RAM and stalling boot for a minute). */
		uint64_t ka = f86_kernel_base();
		uint64_t scan_lo = 0, scan_hi = g_ram_sz;
		if (ka >= 0x100000ull && ka + 0x1000000ull < g_ram_sz) {
			scan_lo = ka - 0x200000ull;
			scan_hi = ka + 0x1000000ull;
		}
		for (uint64_t off = scan_lo; off + 16 < scan_hi; off++) {
			if (memcmp(g_ram + off, "DBLMAP bounds exceeded, 0x", 26) == 0 ||
			    memcmp(g_ram + off, "PHYSMAP_PTOV bounds exceeded, 0x", 34) == 0) {
				char s[160];
				size_t n = g_ram_sz - off;
				if (n > sizeof s - 1)
					n = sizeof s - 1;
				memcpy(s, g_ram + off, n);
				s[n] = 0;
				fprintf(stderr, "fast86: panic-msg@gpa=%lx: %s\n",
				        (unsigned long)off, s);
			}
		}
		/* DBLMAP panics because idt64_hndl_table0[1]/[3] (the __HIB exit
		   trampolines) were not KASLR-relocated. Read them to confirm. */
		{
			uint64_t gpa = 0;
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 16 < g_ram_sz) {
				uint64_t slide = c->rip - 0xffffff80003da736ull;
				uint64_t tbl = 0xffffff800010b000ull + slide;
				uint64_t tbl_u = 0xffffff800010b000ull;
				fprintf(stderr, "fast86: slide=%lx idt64_hndl_table0=%lx unslid=%lx\n",
				        (unsigned long)slide, (unsigned long)tbl,
				        (unsigned long)tbl_u);
				{
					/* xnu-11417.101.15 globals (unslid): dblmap_base/max/dist,
					   hdescseg, physmap_base, vm_kernel_slide; and the kernel
					   entry's __HIB LC vmaddr at kernel header + 0xc98. */
					static const struct { const char *n; uint64_t a; } g[] = {
						{ "dblmap_base", 0xffffff80012da178ull },
						{ "dblmap_max", 0xffffff80012da180ull },
						{ "dblmap_dist", 0xffffff80012da188ull },
						{ "hdescseg", 0xffffff80012da170ull },
						{ "physmap_base", 0xffffff800130f1c0ull },
						{ "physmap_max", 0xffffff800119a438ull },
						{ "vm_kernel_slide", 0xffffff800133b0a0ull },
						{ "collection_base_pointers[0]", 0xffffff800133b020ull },
						{ "collection_mach_headers[0]", 0xffffff800133b040ull },
						{ "collection_slide[0]", 0xffffff800133b060ull },
						{ "kc_highest_nonlinkedit_vmaddr", 0xffffff800133b010ull },
					};
					uint64_t hseg = 0;
					for (unsigned i = 0; i < sizeof g / sizeof g[0]; i++) {
						uint64_t va = g[i].a + slide, gp = 0, v = 0;
						if (f86_gva_to_gpa(va, &gp) && gp + 8 <= g_ram_sz)
							memcpy(&v, g_ram + gp, 8);
						fprintf(stderr, "fast86:   %s @%lx = %lx\n", g[i].n,
						        (unsigned long)va, (unsigned long)v);
						if (i == 3)
							hseg = v;
					}
					if (hseg) {
						uint64_t gp = 0, v = 0;
						if (f86_gva_to_gpa(hseg + 24, &gp) && gp + 8 <= g_ram_sz)
							memcpy(&v, g_ram + gp, 8);
						fprintf(stderr, "fast86:   hdescseg->vmaddr = %lx\n", (unsigned long)v);
					}
					{
						/* the Mach-O header PE_set_kc_header recorded */
						uint64_t mhva = 0, gp = 0;
						for (int ki = 0; ki < 3; ki++) {
							uint64_t hv = 0, sv = 0, g1 = 0, g2 = 0;
							if (f86_gva_to_gpa(0xffffff800133b040ull + slide + 8ull * ki, &g1) && g1 + 8 <= g_ram_sz)
								memcpy(&hv, g_ram + g1, 8);
							if (f86_gva_to_gpa(0xffffff800133b060ull + slide + 8ull * ki, &g2) && g2 + 8 <= g_ram_sz)
								memcpy(&sv, g_ram + g2, 8);
							fprintf(stderr, "fast86:   collection[%d]: header=%lx slide=%lx\n", ki,
							        (unsigned long)hv, (unsigned long)sv);
							if (hv && !mhva)
								mhva = hv;
						}
						uint32_t w[8];
						memset(w, 0, sizeof w);
						if (mhva && f86_gva_to_gpa(mhva, &gp) && gp + 32 <= g_ram_sz)
							memcpy(w, g_ram + gp, 32);
						fprintf(stderr, "fast86:   kc header @%lx (gpa %lx): magic=%x cputype=%x filetype=%x ncmds=%x flags=%x\n",
						        (unsigned long)mhva, (unsigned long)gp, w[0], w[1], w[3], w[4], w[6]);
					}
					{
						uint64_t kb = f86_kernel_base();
						uint64_t hib_field = kb + 0x1e4000ull + 0xc98ull;
						uint64_t text_field = kb + 0x1e4000ull + 0x38ull;
						uint64_t v1 = 0, v2 = 0;
						if (hib_field + 8 <= g_ram_sz) memcpy(&v1, g_ram + hib_field, 8);
						if (text_field + 8 <= g_ram_sz) memcpy(&v2, g_ram + text_field, 8);
						fprintf(stderr, "fast86:   runtime kernel header: __TEXT vmaddr=%lx __HIB vmaddr=%lx (kbase=%lx)\n",
						        (unsigned long)v2, (unsigned long)v1, (unsigned long)kb);
					}
				}
				for (int i = 0; i < 8; i++) {
					uint64_t a = tbl + (uint64_t)i * 8, g2 = 0, v = 0;
					uint64_t au = tbl_u + (uint64_t)i * 8, g3 = 0, w = 0;
					if (!f86_gva_to_gpa(a, &g2) || g2 + 8 > g_ram_sz)
						break;
					memcpy(&v, g_ram + g2, 8);
					if (f86_gva_to_gpa(au, &g3) && g3 + 8 <= g_ram_sz)
						memcpy(&w, g_ram + g3, 8);
					fprintf(stderr, "  hndl_table0[%d] slid=%lx unslid=%lx\n", i,
					        (unsigned long)v, (unsigned long)w);
				}
				{
					uint64_t b = 0xffffff80012da178ull + slide;
					const char *nm[3] = { "base", "max", "dist" };
					for (int i = 0; i < 3; i++) {
						uint64_t a = b + (uint64_t)i * 8, g2 = 0, v = 0;
						if (!f86_gva_to_gpa(a, &g2) || g2 + 8 > g_ram_sz)
							break;
						memcpy(&v, g_ram + g2, 8);
						fprintf(stderr, "  dblmap_%s = %lx\n", nm[i],
						        (unsigned long)v);
					}
				}
			}
		}
		{
			uint64_t gpa = 0;
			int is_ptov = 0;
			if (f86_gva_to_gpa(c->r[R_RDX], &gpa) && gpa + 16 < g_ram_sz &&
			    memcmp(g_ram + gpa, "PHYSMAP_PTOV", 12) == 0)
				is_ptov = 1;
			if (!is_ptov && f86_gva_to_gpa(c->r[R_RDX], &gpa) &&
			    gpa + 80 < g_ram_sz) {
				if (memmem(g_ram + gpa, 80, "non-sleepable RW lock", 21))
					is_ptov = 2;
			}
			if (is_ptov) {
				if (is_ptov == 1) {
					uint64_t pa = c->r[R_RCX];
					uint64_t va = pa;
					if (va < 0xffff800000000000ull)
						va |= 0xffffff8000000000ull;
					fprintf(stderr, "fast86: PHYSMAP skip pa=%lx -> %lx\n",
					        (unsigned long)pa, (unsigned long)va);
					c->r[R_RAX] = va;
				} else
					fprintf(stderr, "fast86: skip bootstrap panic\n");
				{
					uint64_t rbp = c->r[R_RBP], gp = 0, sv = 0, ret = 0;
					if (f86_gva_to_gpa(rbp, &gp) && gp + 16 <= g_ram_sz) {
						memcpy(&sv, g_ram + gp, 8);
						memcpy(&ret, g_ram + gp + 8, 8);
						if (ret >= 0xffffff8000100000ull) {
							c->r[R_RBP] = sv;
							c->r[R_RSP] = rbp + 16;
							c->rip = ret;
							return 2;
						}
					}
				}
				if (is_ptov == 2) {
					uint64_t ret = 0, gp = 0;
					if (f86_gva_to_gpa(c->r[R_RSP] + 32, &gp) &&
					    gp + 8 <= g_ram_sz) {
						memcpy(&ret, g_ram + gp, 8);
						if (ret >= 0xffffff8000100000ull) {
							c->rip = ret;
							c->r[R_RSP] += 40;
							return 2;
						}
					}
				}
				if (f86_gva_to_gpa(c->r[R_RSP] + 32, &gpa) && gpa + 8 < g_ram_sz) {
					uint64_t ret = 0;
					memcpy(&ret, g_ram + gpa, 8);
					if (ret > 0x1000) {
						c->rip = ret;
						c->r[R_RSP] += 40;
						return 2;
					}
				}
			}
		}
		c->exited = 1;
		c->exit_code = 127;
		return 1;
	}
	if (op == 0xCD) {
		fprintf(stderr, "fast86: int 0x%02x at %lx\n",
		        ip[d->len - 1], (unsigned long)c->rip);
		c->rip += d->len;
		return 0;
	}
	if (op == 0xCF) {
		/* IRETQ: pop RIP, CS, RFLAGS, RSP, SS */
		uint64_t sp = c->r[R_RSP], gpa, rip = 0, rfl = 0, nsp = 0, ign = 0;
		if (!f86_gva_to_gpa(sp, &gpa) || gpa + 40 > g_ram_sz) {
			fprintf(stderr, "fast86: iret stack walk fail rsp=%lx\n",
			        (unsigned long)sp);
			c->exited = 1;
			c->exit_code = 127;
			return 1;
		}
		memcpy(&rip, g_ram + gpa, 8);
		memcpy(&ign, g_ram + gpa + 8, 8);
		memcpy(&rfl, g_ram + gpa + 16, 8);
		memcpy(&nsp, g_ram + gpa + 24, 8);
		c->rip = rip;
		f86_rflags_set_arch(c, rfl | 2);
		c->r[R_RSP] = nsp;
		if (g_vif)
			f86_sys_deliver_irq(c);
		fprintf(stderr, "fast86: iretq -> %lx rsp=%lx rfl=%lx\n",
		        (unsigned long)rip, (unsigned long)nsp, (unsigned long)rfl);
		return 2;
	}
	if (op == 0x0F && op2 == 0x07) {
		/* SYSRETQ */
		c->rip = c->r[R_RCX];
		f86_rflags_set_arch(c, (c->r[R_R11] & ~2ull) | 2ull);
		fprintf(stderr, "fast86: sysret -> %lx rfl=%lx\n",
		        (unsigned long)c->rip, (unsigned long)c->rflags);
		return 2;
	}
	if (op == 0xCE) {
		c->rip += d->len;
		return 0;
	}
	fprintf(stderr, "fast86: sysop %02x %02x at %lx not emulated\n",
	        op, op2, (unsigned long)c->rip);
	c->exited = 1;
	c->exit_code = 127;
	return 1;
}

int f86_sys_take_syscall(F86CPU *c)
{
	if (!c || !g_lstar || !g_exited_bs)
		return 0;
	c->r[R_RCX] = c->rip; /* next insn, already stored */
	{
		uint64_t a = f86_rflags_arch(c);
		c->r[R_R11] = a;
		f86_rflags_set_arch(c, a & ~g_sfmask);
	}
	c->rip = g_lstar;
	fprintf(stderr, "fast86: syscall rax=%lx -> %lx\n",
	        (unsigned long)c->r[R_RAX], (unsigned long)g_lstar);
	return 1;
}

void f86_on_sysop(void)
{
	F86CPU *c = cpu();
	if (!c)
		return;
	c->n_sysops++;
	const uint8_t *ip = f86_gva_code(c->rip, 16);
	if (!ip) {
		fprintf(stderr, "fast86: sysop fetch fail rip=%lx\n",
		        (unsigned long)c->rip);
		c->exited = 1;
		c->exit_code = 127;
		return;
	}
	F86Insn d;
	if (!f86_decode(ip, ip + 16, &d)) {
		fprintf(stderr, "fast86: sysop decode fail rip=%lx\n",
		        (unsigned long)c->rip);
		c->exited = 1;
		c->exit_code = 127;
		return;
	}
	if (g_exited_bs && ((c->n_sysops < 16) || (c->n_sysops % 20000) == 0))
		fprintf(stderr, "fast86: sysop %02x%02x rip=%lx n=%lu rax=%lx rdi=%lx\n",
		        d.opcode0, d.opcode1, (unsigned long)c->rip,
		        (unsigned long)c->n_sysops,
		        (unsigned long)c->r[R_RAX], (unsigned long)c->r[R_RDI]);
	emulate_sysop(c, ip, &d);
	if (!c->exited) {
		f86_sys_refresh_gs();
		if ((c->n_sysops & 0xff) == 0)
			f86_replant_dt();
		f86_sys_deliver_irq(c);
		f86_set_next(c->rip);
	}
}

/* ---------------- PE32+ EFI loader ---------------- */

#pragma pack(push, 1)
typedef struct {
	uint32_t pe_off;
} DosMini;
typedef struct {
	uint16_t machine, nsec;
	uint32_t timedate, symoff, nsym;
	uint16_t opthdr, chars;
} CoffHdr;
typedef struct {
	uint16_t magic;
	uint8_t  lmaj, lmin;
	uint32_t code, idata, udata;
	uint32_t entry, codebase;
	uint64_t imagebase;
	uint32_t sectalign, filealign;
	uint16_t osmaj, osmin, imaj, imin, smaj, smin;
	uint32_t win32, imagesz, hdrsz, chksum;
	uint16_t subsys, dllch;
	uint64_t stackr, stackc, heapr, heapc;
	uint32_t loader, ndir;
} Opt64;
typedef struct {
	char name[8];
	uint32_t vsz, va, rawsz, rawptr, rel, ln;
	uint16_t nrel, nln;
	uint32_t chars;
} SectHdr;
#pragma pack(pop)

int f86_sys_load_efi(const char *path, uint64_t *entry)
{
	size_t n = 0;
	/* park the file at 0x200000 temporarily, then relocate into alloc */
	uint64_t tmp = 0x200000;
	if (f86_sys_load_file(tmp, path, &n) != 0)
		return -1;
	uint8_t *img = g_ram + tmp;
	if (n < 0x40 || img[0] != 'M' || img[1] != 'Z') {
		fprintf(stderr, "fast86: %s not MZ\n", path);
		return -1;
	}
	uint32_t pe = 0;
	memcpy(&pe, img + 0x3c, 4);
	if (pe + sizeof(CoffHdr) + 4 > n || memcmp(img + pe, "PE\0\0", 4) != 0) {
		fprintf(stderr, "fast86: %s not PE\n", path);
		return -1;
	}
	CoffHdr *ch = (CoffHdr *)(img + pe + 4);
	fprintf(stderr, "fast86: pe coff machine=%x nsec=%u opthdr=%u tmp[0x5018]=%02x%02x%02x%02x\n",
	        ch->machine, ch->nsec, ch->opthdr,
	        img[0x5018], img[0x5019], img[0x501a], img[0x501b]);
	if (ch->machine != 0x8664) {
		fprintf(stderr, "fast86: %s not x86_64 (mach=%x)\n", path, ch->machine);
		return -1;
	}
	/* Untrusted image: every header-derived offset/size is checked
	   against the file size n and the image size before use. */
	if (ch->opthdr < sizeof(Opt64) ||
	    (uint64_t)pe + 4 + sizeof(CoffHdr) + ch->opthdr +
	    (uint64_t)ch->nsec * sizeof(SectHdr) > n) {
		fprintf(stderr, "fast86: %s headers exceed file\n", path);
		return -1;
	}
	Opt64 *oh = (Opt64 *)(img + pe + 4 + sizeof(CoffHdr));
	if (oh->magic != 0x20b) {
		fprintf(stderr, "fast86: %s not PE32+\n", path);
		return -1;
	}
	if (oh->imagesz < 0x1000 || oh->imagesz > (256u << 20) ||
	    oh->hdrsz > oh->imagesz || oh->entry >= oh->imagesz) {
		fprintf(stderr, "fast86: %s bad SizeOfImage/headers/entry\n", path);
		return -1;
	}
	uint64_t dest = f86_uefi_alloc((oh->imagesz + 0xfff) / 0x1000 + 1);
	if (!dest || dest + oh->imagesz > g_ram_sz) {
		fprintf(stderr, "fast86: no room for %s\n", path);
		return -1;
	}
	memset(g_ram + dest, 0, oh->imagesz);
	memcpy(g_ram + dest, img, oh->hdrsz < n ? oh->hdrsz : n);
	SectHdr *sh = (SectHdr *)(img + pe + 4 + sizeof(CoffHdr) + ch->opthdr);
	for (int i = 0; i < ch->nsec; i++) {
		fprintf(stderr, "fast86: sect %d va=%x raw=%x rawsz=%x\n",
		        i, sh[i].va, sh[i].rawptr, sh[i].rawsz);
		if (!sh[i].rawptr || !sh[i].rawsz)
			continue;
		if (sh[i].rawptr >= n || sh[i].va >= oh->imagesz)
			continue;
		uint64_t va = dest + sh[i].va;
		size_t cpy = sh[i].rawsz;
		if ((uint64_t)sh[i].rawptr + cpy > n)
			cpy = n - sh[i].rawptr;
		if (sh[i].vsz && cpy > sh[i].vsz)
			cpy = sh[i].vsz;
		if ((uint64_t)sh[i].va + cpy > oh->imagesz)
			cpy = oh->imagesz - sh[i].va;
		memcpy(g_ram + va, img + sh[i].rawptr, cpy);
	}
	/* apply base relocs if ImageBase != dest */
	if (oh->imagebase != dest && oh->ndir > 5) {
		/* DataDirectory[5] is basereloc — 8-byte entries after Opt64 */
		uint32_t *dd = (uint32_t *)((uint8_t *)oh + sizeof(Opt64));
		uint32_t rva = dd[10], rsz = dd[11];
		if ((uint64_t)rva + rsz > oh->imagesz)
			rsz = 0; /* bogus relocation directory: skip */
		uint8_t *rel = g_ram + dest + rva;
		uint8_t *rend = rel + rsz;
		int64_t delta = (int64_t)dest - (int64_t)oh->imagebase;
		while (rel + 8 <= rend) {
			uint32_t page, sz;
			memcpy(&page, rel, 4);
			memcpy(&sz, rel + 4, 4);
			if (sz < 8 || rel + sz > rend)
				break;
			uint16_t *ents = (uint16_t *)(rel + 8);
			int ne = (int)((sz - 8) / 2);
			for (int i = 0; i < ne; i++) {
				int type = ents[i] >> 12;
				int off = ents[i] & 0xfff;
				if (type == 10) { /* DIR64 */
					if ((uint64_t)page + off + 8 > oh->imagesz)
						continue;
					uint64_t *p = (uint64_t *)(g_ram + dest + page + off);
					*p += (uint64_t)delta;
				} else if (type == 0)
					;
			}
			rel += sz;
		}
	}
	*entry = dest + oh->entry;
	g_image_base = dest;
	g_image_size = oh->imagesz;
	fprintf(stderr, "fast86: efi %s -> gpa=%lx entry=%lx size=%x\n",
	        path, (unsigned long)dest, (unsigned long)*entry, oh->imagesz);
	if (oh->imagesz > 0x5020) {
		unsigned char *g = g_ram + dest + 0x5018;
		fprintf(stderr, "fast86: debug [image+0x5018] %02x%02x%02x%02x %02x%02x %02x%02x\n",
		        g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
	}
	return 0;
}

static uint64_t pick_identity_stack(void)
{
	uint32_t i;
	for (i = (0x6e000000u >> 21); i > 2; i--) {
		if (g_idbit[i >> 3] & (uint8_t)(1u << (i & 7))) {
			uint64_t gpa = (uint64_t)i << 21;
			g_stack_lo = gpa;
			g_stack_hi = gpa + 0x200000ull;
			fprintf(stderr, "fast86: uefi stack %lx\n",
			        (unsigned long)(gpa + 0x1ff000ull));
			return gpa + 0x1ff000ull;
		}
	}
	return g_ram_sz > 0x20000ull ? g_ram_sz - 0x10000ull : 0x80000ull;
}

int f86_sys_prepare_cpu(F86CPU *c, uint64_t entry)
{
	memset(c, 0, sizeof(*c));
	c->rflags = 0x2;
	c->cr0 = CR0_PE | (1ull << 1) | (1ull << 4) | (1ull << 5); /* PE+MP+ET+NE */
	c->cr4 = (1ull << 5) | (1ull << 7) | (1ull << 9) | (1ull << 10); /* PAE+PGE+OSFXSR+OSXMM */
	c->efer = EFER_LME | EFER_LMA;
	c->apic_base = 0xFEE00000ull | (1ull << 11) | (1ull << 8); /* enabled + BSP: lapic_init insists on both */
	c->rip = entry;
	c->r[R_RSP] = pick_identity_stack();
	/* EFI: rdx = SystemTable, rcx = ImageHandle */
	uint64_t st = 0;
	f86_uefi_install(&st);
	c->r[R_RDX] = st;
	c->r[R_RCX] = 0x10; /* fake image handle */
	return 0;
}
