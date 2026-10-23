/* Freestanding: no libc. Same-ISA DBT vs TCG comparison. */
#include <stdint.h>
#include <stddef.h>

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

static void putu(uint64_t v)
{
	char b[32];
	int i = 32;
	b[--i] = '\n';
	if (v == 0)
		b[--i] = '0';
	while (v) {
		b[--i] = (char)('0' + (v % 10));
		v /= 10;
	}
	sys_write(1, b + i, (unsigned long)(32 - i));
}

void _start(void)
{
	const uint64_t N = 800000000ull;
	uint64_t a = 1, b = 1, c = 0;
	for (uint64_t i = 0; i < N; i++) {
		c = a + b;
		a = b;
		b = c ^ (i * 0x9e3779b97f4a7c15ull);
	}
	putu(b);
	sys_exit(0);
}
