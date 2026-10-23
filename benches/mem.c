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
/* mmap: r10/r8/r9 must be explicit */
static void *mmap_anon(unsigned long len)
{
	void *p;
	register unsigned long r10 __asm__("r10") = 0x22; /* PRIVATE|ANON */
	register unsigned long r8 __asm__("r8") = (unsigned long)-1;
	register unsigned long r9 __asm__("r9") = 0;
	__asm__ volatile("syscall"
	                 : "=a"(p)
	                 : "a"(9), "D"(0), "S"(len), "d"(3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return p;
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

void _start(void)
{
	const unsigned long N = 64ul << 20;
	uint8_t *p = mmap_anon(N);
	if ((long)p < 0)
		sys_exit(1);
	for (unsigned long i = 0; i < N; i++) {
		p[i] = (uint8_t)(0xA5 ^ (uint8_t)i);
		asm volatile("" : "+m"(p[i]));
	}
	uint64_t s = 0;
	for (int r = 0; r < 8; r++) {
		for (unsigned long i = 0; i < N; i += 64)
			s += p[i];
		p[r] = (uint8_t)s;
	}
	putu(s);
	sys_exit(0);
}
