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

static uint64_t fib(uint32_t n)
{
	if (n < 2)
		return n;
	return fib(n - 1) + fib(n - 2);
}

void _start(void)
{
	putu(fib(38));
	sys_exit(0);
}
