/* -O0 recursive tests so CALL/RET stay obvious. */
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
static void putu(uint64_t v)
{
	char b[32];
	int i = 32;
	b[--i] = '\n';
	if (!v)
		b[--i] = '0';
	while (v) {
		b[--i] = (char)('0' + (v % 10));
		v /= 10;
	}
	sys_write(1, b + i, (unsigned long)(32 - i));
}

__attribute__((noinline))
static uint64_t rec(uint64_t n)
{
	if (n == 0)
		return 1;
	return rec(n - 1) + 1;
}

__attribute__((noinline))
static uint64_t fib0(uint32_t n)
{
	if (n < 2)
		return n;
	return fib0(n - 1) + fib0(n - 2);
}

void _start(void)
{
	/* rec(10) == 11, fib0(10) == 55 */
	putu(rec(10));
	putu(fib0(10));
	sys_exit(0);
}
