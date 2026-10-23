/* Compare f86_decode lengths against objdump -d of an ELF. */
#include "f86.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standalone build: no system emulator. Length decoding does not depend on
   boot-service state, so report the default (pre-ExitBootServices) state. */
int f86_sys_bs_exited(void) { return 0; }
int f86_in_system(void) { return 0; }

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: lenchk <objdump -d output>\n");
		return 2;
	}
	FILE *f = fopen(argv[1], "r");
	if (!f) {
		perror(argv[1]);
		return 1;
	}
	char line[512];
	uint8_t buf[16];
	int nbuf = 0, mism = 0, n = 0;
	unsigned long pending = 0;
	char mn[128] = "";
	while (fgets(line, sizeof line, f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		char *colon = strchr(p, ':');
		int new_insn = 0;
		unsigned long a = 0;
		if (colon && isxdigit((unsigned char)*p)) {
			a = strtoul(p, NULL, 16);
			/* objdump addrs are typically > 0x1000 */
			if (colon - p <= 16)
				new_insn = 1;
		}
		if (new_insn && nbuf) {
			F86Insn d;
			int ok = f86_decode(buf, buf + nbuf, &d) && !(d.flags & F86_BAD);
			if (!ok || d.len != nbuf) {
				printf("MISMATCH %lx obj=%d dec=%s%d  ",
				       pending, nbuf, ok ? "" : "BAD ", ok ? d.len : 0);
				for (int i = 0; i < nbuf; i++)
					printf("%02x", buf[i]);
				printf("  %s\n", mn);
				if (++mism >= 80)
					break;
			}
			n++;
			nbuf = 0;
			mn[0] = 0;
		}
		if (new_insn) {
			pending = a;
			p = colon + 1;
		}
		/* collect hex bytes */
		while (*p) {
			while (*p == ' ' || *p == '\t') p++;
			if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]) ||
			    (p[2] && p[2] != ' ' && p[2] != '\t' && p[2] != '\n'))
				break;
			if (nbuf < 16)
				buf[nbuf++] = (uint8_t)strtoul(p, NULL, 16);
			p += 2;
		}
		while (*p == ' ' || *p == '\t') p++;
		if (*p && *p != '\n' && !mn[0]) {
			strncpy(mn, p, sizeof mn - 1);
			char *nl = strchr(mn, '\n');
			if (nl) *nl = 0;
		}
	}
	if (nbuf && mism < 40) {
		F86Insn d;
		int ok = f86_decode(buf, buf + nbuf, &d) && !(d.flags & F86_BAD);
		if (!ok || d.len != nbuf) {
			printf("MISMATCH %lx obj=%d dec=%s%d\n", pending, nbuf,
			       ok ? "" : "BAD ", ok ? d.len : 0);
			mism++;
		}
		n++;
	}
	printf("checked %d insns, %d mismatches\n", n, mism);
	fclose(f);
	return mism ? 1 : 0;
}
