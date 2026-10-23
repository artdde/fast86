#include "f86.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	int fd = open(argv[1], O_RDONLY);
	struct stat st;
	fstat(fd, &st);
	uint8_t *m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	Elf64_Ehdr *eh = (Elf64_Ehdr *)m;
	Elf64_Phdr *ph = (Elf64_Phdr *)(m + eh->e_phoff);
	uint64_t text_off = 0, text_va = 0, text_sz = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
			text_off = ph[i].p_offset;
			text_va = ph[i].p_vaddr;
			text_sz = ph[i].p_filesz;
			break;
		}
	}
	uint8_t *p = m + text_off, *end = p + text_sz;
	uint64_t va = text_va;
	int bad = 0, n = 0;
	while (p < end) {
		F86Insn d;
		if (!f86_decode(p, end, &d) || (d.flags & F86_BAD) || d.len == 0) {
			printf("BAD %lx: %02x %02x %02x %02x\n",
			       (unsigned long)va, p[0], p[1], p[2], p[3]);
			bad++;
			p++;
			va++;
			if (bad > 20)
				break;
			continue;
		}
		n++;
		p += d.len;
		va += d.len;
	}
	printf("decoded %d insns, %d bad\n", n, bad);
	return bad ? 1 : 0;
}
