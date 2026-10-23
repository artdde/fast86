/* Freestanding correctness probes: live GPRs across RET, RIP-rel with r11,
   mid-block backward JCC, nested CALL, register-indirect CALL. */
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
	while (s[n])
		n++;
	sys_write(1, s, n);
}

__attribute__((noinline))
static uint64_t ident(uint64_t x)
{
	return x;
}

__attribute__((noinline))
static uint64_t keep_volatile(uint64_t x)
{
	register uint64_t rdx __asm__("rdx") = 0xd2d2d2d2d2d2d2d2ull;
	register uint64_t rsi __asm__("rsi") = 0x5151515151515151ull;
	register uint64_t rcx __asm__("rcx") = 0xc1c1c1c1c1c1c1c1ull;
	register uint64_t r11 __asm__("r11") = 0xb1b1b1b1b1b1b1b1ull;
	__asm__ volatile("" : "+r"(rdx), "+r"(rsi), "+r"(rcx), "+r"(r11));
	uint64_t y = ident(x);
	__asm__ volatile("" : "+r"(rdx), "+r"(rsi), "+r"(rcx), "+r"(r11));
	if (rdx != 0xd2d2d2d2d2d2d2d2ull) { puts_s("rdx\n"); return 1; }
	if (rsi != 0x5151515151515151ull) { puts_s("rsi\n"); return 1; }
	if (rcx != 0xc1c1c1c1c1c1c1c1ull) { puts_s("rcx\n"); return 1; }
	if (r11 != 0xb1b1b1b1b1b1b1b1ull) { puts_s("r11\n"); return 1; }
	if (y != x) { puts_s("ident\n"); return 1; }
	return 0;
}

static const uint64_t k_riprel = 0x0123456789abcdefull;

__attribute__((noinline))
static uint64_t load_riprel_r11(void)
{
	uint64_t v;
	/* RIP-relative load into r11 (reg field is r11). */
	__asm__ volatile(
		"movq %1, %%r11\n\t"
		"movq %%r11, %0\n"
		: "=r"(v)
		: "m"(k_riprel)
		: "r11");
	return v;
}

__attribute__((noinline))
static uint64_t add_riprel_r11(uint64_t x)
{
	uint64_t v;
	__asm__ volatile(
		"movq %1, %%r11\n\t"
		"addq %2, %%r11\n\t"
		"movq %%r11, %0\n"
		: "=r"(v)
		: "r"(x), "m"(k_riprel)
		: "r11");
	return v;
}

__attribute__((noinline))
static uint64_t midblock_loop(uint32_t n)
{
	uint64_t s = 0;
	/* Force a loop whose header is not the function entry. */
	s += 1;
	s += 2;
	s += 3;
	for (uint32_t i = 0; i < n; i++)
		s += i;
	return s;
}

__attribute__((noinline))
static uint64_t nest(uint32_t n)
{
	if (n == 0)
		return 1;
	return nest(n - 1) + 3;
}

__attribute__((noinline))
static uint64_t add2(uint64_t x)
{
	return x + 2;
}

void _start(void)
{
	int bad = 0;
	if (keep_volatile(7))
		bad = 1;

	if (load_riprel_r11() != 0x0123456789abcdefull) {
		puts_s("riprel\n");
		bad = 1;
	}
	if (add_riprel_r11(1) != 0x0123456789abcdefull + 1) {
		puts_s("riprel-add\n");
		bad = 1;
	}
	{
		uint64_t v = 0;
		__asm__ volatile(
			"xor %%eax, %%eax\n\t"
			"cmove %1, %%rax\n"
			: "=&a"(v)
			: "m"(k_riprel)
			: "cc");
		if (v != 0x0123456789abcdefull) {
			puts_s("riprel-cmov\n");
			bad = 1;
		}
	}

	/* 0+1+...+99 = 4950, plus the 1+2+3 prefix */
	if (midblock_loop(100) != 4950 + 6) {
		puts_s("loop\n");
		bad = 1;
	}

	if (nest(20) != 1 + 20 * 3) {
		puts_s("nest\n");
		bad = 1;
	}

	uint64_t (*fp)(uint64_t) = add2;
	if (fp(40) != 42) {
		puts_s("icall\n");
		bad = 1;
	}

	if (!bad)
		puts_s("correct-ok\n");
	sys_exit(bad);
}
