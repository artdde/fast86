/* Probe spill/fill and stack slots across CALL / JCC. */
#include <stdint.h>

static long sys_write(int fd, const void *buf, unsigned long n)
{
	long r;
	__asm__ volatile("syscall"
	                 : "=a"(r)
	                 : "a"(1), "D"(fd), "S"(buf), "d"(n)
	                 : "rcx", "r11", "memory");
	return r;
}
static void sys_exit(int c)
{
	__asm__ volatile("syscall" : : "a"(60), "D"(c) : "rcx", "r11");
	for (;;)
		;
}
static void puts_s(const char *s)
{
	unsigned long n = 0;
	while (s[n]) n++;
	sys_write(1, s, n);
}

__attribute__((noinline))
static uint64_t add1(uint64_t x)
{
	return x + 1;
}

__attribute__((noinline))
static uint64_t stacky(uint64_t a, uint64_t b)
{
	volatile uint64_t slot[16];
	for (int i = 0; i < 16; i++)
		slot[i] = a + (uint64_t)i * 0x1111111111111111ull;
	uint64_t r = add1(b);
	uint64_t s = 0;
	for (int i = 0; i < 16; i++)
		s += slot[i];
	return r + s;
}

__attribute__((noinline))
static uint64_t keepers(uint64_t x)
{
	register uint64_t r12 __asm__("r12") = 0x0c0c0c0c0c0c0c0cull;
	register uint64_t r13 __asm__("r13") = 0x0d0d0d0d0d0d0d0dull;
	register uint64_t r14 __asm__("r14") = 0x0e0e0e0e0e0e0e0eull;
	register uint64_t r15 __asm__("r15") = 0x0f0f0f0f0f0f0f0full;
	register uint64_t rbx __asm__("rbx") = 0xb1b1b1b1b1b1b1b1ull;
	__asm__ volatile("" : "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(rbx));
	uint64_t y = add1(x);
	__asm__ volatile("" : "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(rbx));
	if (r12 != 0x0c0c0c0c0c0c0c0cull) { puts_s("r12\n"); return 1; }
	if (r13 != 0x0d0d0d0d0d0d0d0dull) { puts_s("r13\n"); return 1; }
	if (r14 != 0x0e0e0e0e0e0e0e0eull) { puts_s("r14\n"); return 1; }
	if (r15 != 0x0f0f0f0f0f0f0f0full) { puts_s("r15\n"); return 1; }
	if (rbx != 0xb1b1b1b1b1b1b1b1ull) { puts_s("rbx\n"); return 1; }
	if (y != x + 1) { puts_s("ret-val\n"); return 1; }
	return 0;
}

void _start(void)
{
	int bad = 0;
	if (keepers(41))
		bad = 1;

	uint64_t s = stacky(1, 2);
	uint64_t expect = 3;
	for (int i = 0; i < 16; i++)
		expect += 1 + (uint64_t)i * 0x1111111111111111ull;
	if (s != expect) { puts_s("stacky\n"); bad = 1; }

	uint64_t f = 0;
	__asm__ volatile(
		"mov $1, %%eax\n"
		"cmp $2, %%eax\n"
		"jne 1f\n"
		"mov $0xdead, %[f]\n"
		"jmp 2f\n"
		"1:\n"
		"mov $0xbeef, %[f]\n"
		"2:\n"
		: [f]"=r"(f) : : "eax", "cc");
	if (f != 0xbeef) { puts_s("jcc\n"); bad = 1; }

	if (!bad)
		puts_s("regs-ok\n");
	sys_exit(bad);
}
