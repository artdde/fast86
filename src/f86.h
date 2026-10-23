#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
	F86_MODRM   = 1u << 0,
	F86_RIPREL  = 1u << 1,
	F86_JCC8    = 1u << 2,
	F86_JCC32   = 1u << 3,
	F86_JMP8    = 1u << 4,
	F86_JMP32   = 1u << 5,
	F86_CALL32  = 1u << 6,
	F86_RET     = 1u << 7,
	F86_SYSCALL = 1u << 8,
	F86_FF_CALL = 1u << 9,
	F86_FF_JMP  = 1u << 10,
	F86_PRIV    = 1u << 11,
	F86_BAD     = 1u << 12,
	F86_LOOP    = 1u << 13, /* E0–E3: LOOP/LOOPE/LOOPNE/JRCXZ */
	F86_WRFS    = 1u << 14, /* wrfsbase / wrgsbase */
	F86_SYSOP   = 1u << 15, /* CPUID/MSR/CR/IO/INT/IRET/CLI/LGDT… */
};

typedef struct {
	uint8_t  len;
	uint32_t flags;
	uint8_t  rex;
	uint8_t  vex_len;     /* 0, 2, 3, or 4 (EVEX) */
	uint8_t  opcode0, opcode1;
	uint8_t  modrm;
	int32_t  disp;
	int32_t  rel;
	uint8_t  imm_off;
	uint8_t  modrm_off;
} F86Insn;

typedef struct {
	uint64_t r[16];
	uint64_t rip;
	uint64_t rflags;
	uint64_t fs_base, gs_base;
	uint64_t cr0, cr2, cr3, cr4, cr8, efer, apic_base;
	uint64_t gdt_base, idt_base;
	uint16_t gdt_limit, idt_limit;
	uint64_t kernel_gs;
	uint64_t brk, brk_base;
	uint64_t exited;
	int      exit_code;
	uint64_t n_blocks, n_insns, n_exits, n_syscalls, n_sysops;
} F86CPU;

bool f86_decode(const uint8_t *p, const uint8_t *end, F86Insn *out);

int  f86_load_elf(const char *path, uint64_t *entry, uint64_t *brk);
int  f86_setup_stack(F86CPU *cpu, int argc, char **argv, char **envp,
                     uint64_t entry, uint64_t phdr, uint64_t phnum);
void f86_run(F86CPU *cpu, uint64_t entry);
void f86_run_direct(F86CPU *cpu, uint64_t entry);
long f86_do_syscall(F86CPU *cpu);
void *f86_translate(F86CPU *cpu, uint64_t guest_rip);
void f86_cache_init(void);
void f86_cache_flush(void);

int  f86_sys_init(size_t ram_bytes);
int  f86_sys_load_raw(uint64_t gpa, const void *data, size_t n);
int  f86_sys_load_file(uint64_t gpa, const char *path, size_t *out_n);
int  f86_sys_load_efi(const char *path, uint64_t *entry);
int  f86_sys_prepare_cpu(F86CPU *cpu, uint64_t entry);
void f86_sys_set_root(const char *dir);
void f86_sys_set_mac_root(const char *dir);
const char *f86_sys_mac_root(void);
void f86_sys_set_image_path(const char *path);
const char *f86_sys_image_path(void);
void f86_sys_set_disk(const char *path);
int f86_sys_disk_read(uint64_t lba, uint32_t nbyte, void *dst);
uint64_t f86_sys_disk_blocks(void);
uint64_t f86_sys_part_lba(void);
uint64_t f86_sys_part_blocks(void);
void f86_on_sysop(void);
void f86_set_next(uint64_t guest_rip);
void *f86_gpa_hva(uint64_t gpa);
uint8_t *f86_ram(void);
size_t f86_ram_size(void);
uint64_t f86_uefi_alloc(uint64_t pages);
const char *f86_sys_root(void);
void f86_emit_stub(uint8_t *p, uint32_t id);
uint64_t f86_sys_image_base(void);
uint64_t f86_sys_image_size(void);
void f86_sys_plant_fw(void);
int f86_uefi_install(uint64_t *out_st);
int f86_uefi_dispatch(F86CPU *c, uint32_t id);
int f86_uefi_stub_id(uint64_t rip, uint32_t *id);
int  f86_in_system(void);
const uint8_t *f86_gva_code(uint64_t gva, size_t n);
int f86_gva_to_gpa(uint64_t gva, uint64_t *gpa);
void f86_sys_exited_bs(void);
int f86_sys_bs_exited(void);
int f86_sys_is_mmio(uint64_t addr);
uint64_t f86_sys_mmio_read(uint64_t addr, int sz);
void f86_sys_mmio_write(uint64_t addr, uint64_t v, int sz);
void f86_sys_timer_pulse(void);
int  f86_sys_deliver_irq(F86CPU *c);
int  f86_sys_inject_exc(F86CPU *c, int vec, uint32_t err, uint64_t cr2);
void f86_sys_refresh_gs(void);
void f86_replant_dt(void);
int  f86_sys_take_syscall(F86CPU *c);
void f86_irq_from_signal(void *ucontext);
void f86_uefi_dump_fb(const char *path);
int f86_kernel_pages_ready(void);
uint64_t f86_kernel_boot_args(void); /* guest PA of boot_args, from HIB entry */
uint64_t f86_kernel_base(void); /* guest PA of kernel image base */
extern uint64_t f86_gs_host;
uint64_t f86_host_tsc_hz(void); /* host TSC rate, also the guest TSC rate */
int f86_sys_if(void);            /* virtual IF (system mode) */
int f86_sys_df(void);            /* virtual DF (system mode) */
uint64_t f86_rflags_arch(const F86CPU *c);
void f86_rflags_set_arch(F86CPU *c, uint64_t a);
int  f86_ram_fd(void);           /* memfd backing guest RAM (-1 if none) */
int  f86_walk_shift(void);       /* log2 page size of the last f86_gva_to_gpa */
/* segment-alias softmmu (engine.c) */
uint64_t f86_alias_off(void);
int  f86_alias_on(void);
void f86_alias_inval(uint64_t gva);
void f86_alias_flush(int which);
void f86_alias_drop_all(void);
int  f86_walk_tables(uint64_t gva, uint64_t tbl[4], uint64_t base[4], int lvl[4]);
void f86_alias_stats(uint64_t *pop, uint64_t *pop2m, uint64_t *inv, uint64_t *fl);

enum {
	R_RAX, R_RCX, R_RDX, R_RBX, R_RSP, R_RBP, R_RSI, R_RDI,
	R_R8,  R_R9,  R_R10, R_R11, R_R12, R_R13, R_R14, R_R15
};
