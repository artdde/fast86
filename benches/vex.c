/* Regression: RIP-relative VEX2/VEX3/BMI2 operands rewritten through a
   scratch register (corecrypto's SHA kernels), VEX register forms whose
   map opcode collides with push/pop/leave (vxorps = 0F 57, vpunpckhbw =
   0F 68), and r11 as the destination of a RIP-relative load. */
#include <stdint.h>

static long sys_write(int fd, const void *buf, unsigned long n)
{
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(1), "D"(fd), "S"(buf), "d"(n) : "rcx", "r11", "memory");
	return r;
}
static void sys_exit(int c)
{
	__asm__ volatile("syscall" : : "a"(60), "D"(c) : "rcx", "r11");
	for (;;)
		;
}

const uint8_t shuf[16] __attribute__((aligned(16))) = {3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12};
const uint32_t k[4] __attribute__((aligned(16))) = {1,2,3,4};
const uint64_t q = 0x123456789abcdef0ull;

__attribute__((force_align_arg_pointer)) void _start(void)
{
	uint8_t in[16], out[16], exp[16], z[16];
	for (int i = 0; i < 16; i++)
		in[i] = (uint8_t)(i * 7 + 1);
	__asm__ volatile(
		"vmovups (%1), %%xmm0\n\t"
		"vpshufb shuf(%%rip), %%xmm0, %%xmm2\n\t"   /* VEX3 rip-relative */
		"vpaddd k(%%rip), %%xmm2, %%xmm2\n\t"       /* VEX2 rip-relative */
		"vmovups %%xmm2, (%0)\n\t"
		"vxorps %%xmm3, %%xmm3, %%xmm3\n\t"         /* VEX map opcode 0x57 (push-like) */
		"vpunpckhbw %%xmm3, %%xmm3, %%xmm3\n\t"     /* 0x68 (push imm-like) */
		"vmovups %%xmm3, (%2)\n\t"
		: : "r"(out), "r"(in), "r"(z) : "xmm0", "xmm2", "xmm3", "memory");
	for (int i = 0; i < 16; i++)
		exp[i] = in[shuf[i]];
	for (int i = 0; i < 4; i++) {
		uint32_t v = (uint32_t)exp[4 * i] | ((uint32_t)exp[4 * i + 1] << 8) |
		             ((uint32_t)exp[4 * i + 2] << 16) | ((uint32_t)exp[4 * i + 3] << 24);
		v += k[i];
		exp[4 * i] = (uint8_t)v; exp[4 * i + 1] = (uint8_t)(v >> 8);
		exp[4 * i + 2] = (uint8_t)(v >> 16); exp[4 * i + 3] = (uint8_t)(v >> 24);
	}
	uint64_t r1, r2;
	__asm__ volatile("rorxq $13, q(%%rip), %0" : "=r"(r1));
	__asm__ volatile("movq q(%%rip), %%r11\n\t movq %%r11, %0" : "=r"(r2) : : "r11");
	uint64_t e1 = (q >> 13) | (q << (64 - 13));
	int ok = r1 == e1 && r2 == q;
	for (int i = 0; i < 16; i++)
		if (out[i] != exp[i] || z[i] != 0)
			ok = 0;
	/* rsp must be unchanged by the register-only VEX forms: probe via a call */
	sys_write(1, ok ? "vex-ok\n" : "vex-FAIL\n", ok ? 7 : 9);
	sys_exit(ok ? 0 : 1);
}
