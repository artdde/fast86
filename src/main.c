#define _GNU_SOURCE
#include "f86.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
	int direct = 0, system = 0;
	int argi = 1;
	size_t ram = 4096u << 20;
	const char *efi_root = NULL;
	const char *mac_root = NULL;
	const char *disk = NULL;
	while (argi < argc && argv[argi][0] == '-') {
		if (strcmp(argv[argi], "--direct") == 0) {
			direct = 1;
			argi++;
		} else if (strcmp(argv[argi], "--system") == 0) {
			system = 1;
			argi++;
		} else if (strcmp(argv[argi], "--mem") == 0 && argi + 1 < argc) {
			ram = (size_t)strtoull(argv[++argi], NULL, 0) << 20;
			argi++;
		} else if (strcmp(argv[argi], "--root") == 0 && argi + 1 < argc) {
			efi_root = argv[++argi];
			argi++;
		} else if (strcmp(argv[argi], "--mac-root") == 0 && argi + 1 < argc) {
			mac_root = argv[++argi];
			argi++;
		} else if (strcmp(argv[argi], "--disk") == 0 && argi + 1 < argc) {
			disk = argv[++argi];
			argi++;
		} else
			break;
	}
	if (argc <= argi) {
		fprintf(stderr,
		        "usage: fast86 [--direct] <static-x86_64-elf> [args...]\n"
		        "       fast86 --system [--mem MiB] [--root dir] [--mac-root dir] [--disk img] <raw.bin|*.efi>\n");
		return 2;
	}

	if (!direct)
		f86_cache_init();

	F86CPU cpu;
	memset(&cpu, 0, sizeof(cpu));
	uint64_t entry = 0, brk = 0;

	if (system) {
		if (f86_sys_init(ram) != 0)
			return 1;
		if (efi_root)
			f86_sys_set_root(efi_root);
		if (mac_root)
			f86_sys_set_mac_root(mac_root);
		if (disk)
			f86_sys_set_disk(disk);
		const char *path = argv[argi];
		if (efi_root && path) {
			size_t rl = strlen(efi_root);
			if (strncmp(path, efi_root, rl) == 0 && path[rl] == '/')
				f86_sys_set_image_path(path + rl);
			else
				f86_sys_set_image_path(path);
		}
		size_t plen = strlen(path);
		int is_efi = plen > 4 && (strcmp(path + plen - 4, ".efi") == 0 ||
		                          strcmp(path + plen - 4, ".EFI") == 0);
		if (is_efi) {
			if (f86_sys_load_efi(path, &entry) != 0)
				return 1;
		} else {
			size_t n = 0;
			if (f86_sys_load_file(0x200000, path, &n) != 0)
				return 1;
			entry = 0x200000;
		}
		f86_sys_prepare_cpu(&cpu, entry);
	} else {
		if (f86_load_elf(argv[argi], &entry, &brk) != 0)
			return 1;
		cpu.brk = cpu.brk_base = brk;
		cpu.rflags = 0x202;
		if (f86_setup_stack(&cpu, argc - argi, argv + argi, environ, entry, 0, 0) != 0) {
			perror("stack");
			return 1;
		}
	}

	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (direct && !system)
		f86_run_direct(&cpu, entry);
	else
		f86_run(&cpu, entry);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	fprintf(stderr,
	        "fast86: exit=%d  %.4fs  blocks=%lu insns=%lu exits=%lu syscalls=%lu sysops=%lu\n",
	        cpu.exit_code, sec,
	        (unsigned long)cpu.n_blocks, (unsigned long)cpu.n_insns,
	        (unsigned long)cpu.n_exits, (unsigned long)cpu.n_syscalls,
	        (unsigned long)cpu.n_sysops);
	if (f86_alias_on()) {
		uint64_t pop = 0, pop2m = 0, inv = 0, fl = 0;
		f86_alias_stats(&pop, &pop2m, &inv, &fl);
		extern uint64_t g_invpcid_n[4];
		fprintf(stderr, "fast86: alias pages=%lu 2m=%lu invlpg=%lu flushes=%lu invpcid=%lu/%lu/%lu/%lu\n",
		        (unsigned long)pop, (unsigned long)pop2m, (unsigned long)inv,
		        (unsigned long)fl, (unsigned long)g_invpcid_n[0], (unsigned long)g_invpcid_n[1],
		        (unsigned long)g_invpcid_n[2], (unsigned long)g_invpcid_n[3]);
	}
	return cpu.exit_code;
}
