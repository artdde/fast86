#include "f86.h"
#include <string.h>

/* has_modrm for primary opcode (64-bit long mode) */
static const uint8_t MODRM1[256] = {
	1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0, /* 00 */
	1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0, /* 10 */
	1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0, /* 20 */
	1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0, /* 30 */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* 40 REX */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* 50 */
	0,0,1,1,0,0,0,0, 0,1,0,1,0,0,0,0, /* 60 */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* 70 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 80 */
	0,0,0,0,0,0,0,0, 0,0,1,0,0,0,0,0, /* 90 */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* A0 */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* B0 */
	1,1,0,0,1,1,1,1, 0,0,0,0,0,0,0,0, /* C0 */
	1,1,1,1,0,0,0,0, 1,1,1,1,1,1,1,1, /* D0 */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* E0 */
	0,0,0,0,0,0,1,1, 0,0,0,0,0,0,1,1, /* F0 */
};

/*
 * 0F xx has_modrm. Corrections vs the old table:
 *   0B UD2 and 0E FEMMS have no ModRM.
 */
static const uint8_t MODRM0F[256] = {
	1,1,1,1,0,0,0,0, 0,0,0,0,0,1,0,1, /* 00  0B=UD2, 0E=FEMMS */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 10 */
	1,1,1,1,1,0,1,0, 1,1,1,1,1,1,1,1, /* 20 */
	0,0,0,0,0,0,0,0, 1,0,1,0,0,0,0,0, /* 30 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 40 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 50 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 60 */
	1,1,1,1,1,1,1,0, 1,1,1,1,1,1,1,1, /* 70  77=EMMS */
	0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, /* 80 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* 90 */
	0,0,0,1,1,1,0,0, 0,0,0,1,1,1,1,1, /* A0 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* B0 */
	1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0, /* C0 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* D0 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* E0 */
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, /* F0 */
};

static bool parse_modrm(const uint8_t **pp, const uint8_t *end, F86Insn *out)
{
	const uint8_t *p = *pp;
	uint8_t m = out->modrm;
	int mod = m >> 6, rm = m & 7;
	if (mod != 3) {
		int disp = 0;
		if (rm == 4) {
			if (p >= end)
				return false;
			uint8_t sib = *p++;
			int base = sib & 7;
			if (mod == 0 && base == 5)
				disp = 4;
		}
		if (mod == 0 && rm == 5) {
			out->flags |= F86_RIPREL;
			disp = 4;
		} else if (mod == 1)
			disp = 1;
		else if (mod == 2)
			disp = 4;
		if (disp) {
			if (p + disp > end)
				return false;
			if (disp == 1)
				out->disp = (int8_t)*p;
			else
				out->disp = (int32_t)(p[0] | (p[1] << 8) |
				                       (p[2] << 16) | (p[3] << 24));
			p += disp;
		}
	}
	*pp = p;
	return true;
}

static int imm_size_1(uint8_t op, int opsz16, int rex_w)
{
	switch (op) {
	case 0x04: case 0x0C: case 0x14: case 0x1C:
	case 0x24: case 0x2C: case 0x34: case 0x3C:
	case 0x6A: case 0x80: case 0x82: case 0x83:
	case 0xA8: case 0xB0: case 0xB1: case 0xB2: case 0xB3:
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
	case 0xC0: case 0xC1: case 0xC6: case 0xCD:
	case 0xD4: case 0xD5: case 0xE4: case 0xE5: case 0xE6: case 0xE7:
	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
	case 0xEB: case 0xE0: case 0xE1: case 0xE2: case 0xE3:
		return 1;
	case 0xC2: case 0xCA:
		return 2;
	case 0x05: case 0x0D: case 0x15: case 0x1D:
	case 0x25: case 0x2D: case 0x35: case 0x3D:
	case 0x68: case 0x69: case 0x81: case 0xA9: case 0xC7:
		return (opsz16 && !rex_w) ? 2 : 4; /* REX.W overrides 0x66: imm32 */
	case 0xE8: case 0xE9:
		return opsz16 ? 2 : 4;
	case 0x6B:
		return 1;
	case 0xC8: /* ENTER iw, ib */
		return 3;
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		return rex_w ? 8 : (opsz16 ? 2 : 4);
	case 0xA0: case 0xA1: case 0xA2: case 0xA3:
		return 8; /* moffs in 64-bit */
	default:
		return 0;
	}
}

static int imm_size_0f(uint8_t op, int opsz16)
{
	switch (op) {
	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0xA4: case 0xAC: case 0xBA: case 0xC2:
	case 0xC4: case 0xC5: case 0xC6:
		return 1;
	case 0x80: case 0x81: case 0x82: case 0x83:
	case 0x84: case 0x85: case 0x86: case 0x87:
	case 0x88: case 0x89: case 0x8A: case 0x8B:
	case 0x8C: case 0x8D: case 0x8E: case 0x8F:
		return opsz16 ? 2 : 4;
	default:
		return 0;
	}
}

/* VEX/EVEX map: 1=0F, 2=0F38, 3=0F3A, 4–6=EVEX extra maps. */
static int vex_imm(int map, uint8_t op)
{
	if (map == 3)
		return 1; /* 0F 3A: virtually all have ib */
	if (map == 1) {
		switch (op) {
		case 0x70: case 0x71: case 0x72: case 0x73:
		case 0xC2: case 0xC4: case 0xC5: case 0xC6:
			return 1;
		default:
			return 0;
		}
	}
	return 0;
}

static int vex_has_modrm(int map, uint8_t op)
{
	/* vzeroupper / vzeroall / emms: VEX.0F 77, no ModRM. */
	if (map == 1 && op == 0x77)
		return 0;
	return 1;
}

static bool decode_vex(const uint8_t **pp, const uint8_t *end, const uint8_t *s,
                       F86Insn *out)
{
	const uint8_t *p = *pp;
	int map;
	if (*p == 0xC5) {
		if (p + 3 > end)
			return false;
		p += 2;
		out->vex_len = 2;
		map = 1;
	} else if (*p == 0xC4) {
		if (p + 4 > end)
			return false;
		map = p[1] & 0x1f;
		p += 3;
		out->vex_len = 3;
	} else { /* EVEX 62 */
		if (p + 5 > end)
			return false;
		map = p[1] & 0x07;
		p += 4;
		out->vex_len = 4;
	}
	if (p >= end)
		return false;
	out->opcode0 = *p++;
	if (vex_has_modrm(map, out->opcode0)) {
		if (p >= end)
			return false;
		out->flags |= F86_MODRM;
		out->modrm_off = (uint8_t)(p - s);
		out->modrm = *p++;
		if (!parse_modrm(&p, end, out))
			return false;
	}
	{
		int imm = vex_imm(map, out->opcode0);
		if (imm) {
			if (p + imm > end)
				return false;
			out->imm_off = (uint8_t)(p - s);
			p += imm;
		}
	}
	out->len = (uint8_t)(p - s);
	*pp = p;
	return out->len > 0 && out->len <= 15;
}

bool f86_decode(const uint8_t *p, const uint8_t *end, F86Insn *out)
{
	const uint8_t *s = p;
	memset(out, 0, sizeof(*out));
	if (p >= end)
		return false;

	int opsz16 = 0, rex = 0, rex_w = 0, have_f3 = 0, have_f2 = 0;
	for (int i = 0; i < 15 && p < end; i++) {
		uint8_t b = *p;
		if (b == 0x66) { opsz16 = 1; p++; continue; }
		if (b == 0xF2) { have_f2 = 1; p++; continue; }
		if (b == 0xF3) { have_f3 = 1; p++; continue; }
		if (b == 0x67 || b == 0xF0 ||
		    b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
		    b == 0x64 || b == 0x65) {
			p++;
			continue;
		}
		if (b >= 0x40 && b <= 0x4F) {
			rex = b;
			rex_w = (b >> 3) & 1;
			p++;
			continue;
		}
		break;
	}
	out->rex = (uint8_t)rex;
	if (p >= end)
		goto bad;

	if (*p == 0xC4 || *p == 0xC5 || *p == 0x62) {
		if (!decode_vex(&p, end, s, out))
			goto bad;
		return true;
	}

	uint8_t op = *p++;
	out->opcode0 = op;

	if (op == 0x0F) {
		if (p >= end) goto bad;
		uint8_t op2 = *p++;
		out->opcode1 = op2;
		if (op2 == 0x38 || op2 == 0x3A) {
			if (p >= end) goto bad;
			op = *p++;
			out->flags |= F86_MODRM;
			if (p >= end) goto bad;
			out->modrm_off = (uint8_t)(p - s);
			out->modrm = *p++;
			if (!parse_modrm(&p, end, out))
				goto bad;
			if (op2 == 0x38 && op == 0x82 && f86_in_system())
				out->flags |= F86_SYSOP; /* invpcid */
			if (op2 == 0x3A) {
				if (p >= end) goto bad;
				out->imm_off = (uint8_t)(p - s);
				p++;
			}
			out->len = (uint8_t)(p - s);
			return out->len > 0 && out->len <= 15;
		}
		if (op2 == 0x05) {
			out->flags |= F86_SYSCALL;
			out->len = (uint8_t)(p - s);
			return true;
		}
		if (op2 == 0x0B) {
			out->flags |= F86_SYSOP; /* ud2 */
			out->len = (uint8_t)(p - s);
			return true;
		}
		if (op2 == 0x07 || op2 == 0x34 || op2 == 0x35 ||
		    op2 == 0x06 || op2 == 0x08 || op2 == 0x09) {
			out->flags |= F86_PRIV | F86_SYSOP;
			out->len = (uint8_t)(p - s);
			return true;
		}
		if (op2 == 0x30 || op2 == 0x32 || op2 == 0xA2) {
			/* wrmsr / rdmsr / cpuid — rdtsc (0x31) stays native */
			out->flags |= F86_SYSOP;
			out->len = (uint8_t)(p - s);
			return true;
		}
		if (op2 >= 0x80 && op2 <= 0x8F) {
			out->flags |= F86_JCC32;
			if (p + (opsz16 ? 2 : 4) > end) goto bad;
			if (opsz16) {
				out->rel = (int16_t)(p[0] | (p[1] << 8));
				p += 2;
			} else {
				out->rel = (int32_t)(p[0] | (p[1] << 8) |
				                     (p[2] << 16) | (p[3] << 24));
				p += 4;
			}
			out->len = (uint8_t)(p - s);
			return true;
		}
		if (MODRM0F[op2]) {
			out->flags |= F86_MODRM;
			if (p >= end) goto bad;
			out->modrm_off = (uint8_t)(p - s);
			out->modrm = *p++;
			if (!parse_modrm(&p, end, out))
				goto bad;
			if (op2 == 0xAE && have_f3 && !have_f2) {
				int reg = (out->modrm >> 3) & 7;
				int mod = out->modrm >> 6;
				if (mod == 3 && (reg == 2 || reg == 3))
					out->flags |= F86_WRFS;
			}
			/* mov cr/dr, lgdt/lidt/invlpg/swapgs */
			if (op2 == 0x20 || op2 == 0x21 || op2 == 0x22 || op2 == 0x23 ||
			    op2 == 0x01 || op2 == 0x00 || op2 == 0xB9)
				out->flags |= F86_SYSOP;
			if (op2 == 0xC7) {
				int ext = (out->modrm >> 3) & 7;
				int mod = out->modrm >> 6;
				if (mod == 3 && (ext == 6 || ext == 7) && f86_sys_bs_exited())
					out->flags |= F86_SYSOP;
			}
		}
		{
			int imm = imm_size_0f(op2, opsz16);
			if (imm) {
				if (p + imm > end) goto bad;
				out->imm_off = (uint8_t)(p - s);
				p += imm;
			}
		}
		out->len = (uint8_t)(p - s);
		return out->len > 0 && out->len <= 15;
	}

	if (op >= 0x70 && op <= 0x7F) {
		out->flags |= F86_JCC8;
		if (p >= end) goto bad;
		out->rel = (int8_t)*p++;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op >= 0xE0 && op <= 0xE3) {
		out->flags |= F86_LOOP;
		if (p >= end) goto bad;
		out->rel = (int8_t)*p++;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xEB) {
		out->flags |= F86_JMP8;
		if (p >= end) goto bad;
		out->rel = (int8_t)*p++;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xE9) {
		out->flags |= F86_JMP32;
		if (p + 4 > end) goto bad;
		out->rel = (int32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
		p += 4;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xE8) {
		out->flags |= F86_CALL32;
		if (p + 4 > end) goto bad;
		out->rel = (int32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
		p += 4;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xF4) {
		out->flags |= F86_PRIV | F86_SYSOP;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if ((op == 0x9C || op == 0x9D) && f86_in_system()) {
		/* pushf/popf: the guest kernel must see its virtual IF/DF, not the
		   host's RFLAGS (it runs at host CPL3 where IF is always 1). */
		out->flags |= F86_SYSOP;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xFA || op == 0xFB || op == 0xFC || op == 0xFD ||
	    op == 0xCF || op == 0xCC || op == 0xCE) {
		out->flags |= F86_SYSOP;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xCD) {
		out->flags |= F86_SYSOP;
		if (p >= end) goto bad;
		p++;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) {
		out->flags |= F86_SYSOP;
		if (p >= end) goto bad;
		p++;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xEC || op == 0xED || op == 0xEE || op == 0xEF) {
		out->flags |= F86_SYSOP;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op >= 0x6C && op <= 0x6F && f86_in_system()) {
		/* INS/OUTS: port I/O through the device model, not the host */
		out->flags |= F86_SYSOP;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xEA || op == 0x9A) {
		/* far jmp/call — 32-bit trampoline (ptr16:32) */
		int n = opsz16 ? 4 : 6;
		if (p + n > end) goto bad;
		out->flags |= F86_SYSOP;
		p += n;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xC3 || op == 0xCB) {
		out->flags |= F86_RET;
		out->len = (uint8_t)(p - s);
		return true;
	}
	if (op == 0xC2 || op == 0xCA) {
		out->flags |= F86_RET;
		if (p + 2 > end) goto bad;
		p += 2;
		out->len = (uint8_t)(p - s);
		return true;
	}

	if (MODRM1[op]) {
		out->flags |= F86_MODRM;
		if (p >= end) goto bad;
		out->modrm_off = (uint8_t)(p - s);
		out->modrm = *p++;
		if (op == 0xFF) {
			int reg = (out->modrm >> 3) & 7;
			if (reg == 2) out->flags |= F86_FF_CALL;
			if (reg == 4) out->flags |= F86_FF_JMP;
			if (reg == 3 || reg == 5)
				out->flags |= F86_SYSOP; /* far call/jmp */
		}
		if (op == 0x8E || op == 0x8C)
			out->flags |= F86_SYSOP; /* mov sreg */
		if (!parse_modrm(&p, end, out))
			goto bad;
	}

	{
		int imm = imm_size_1(op, opsz16, rex_w);
		if (op == 0xF6 || op == 0xF7) {
			int reg = (out->modrm >> 3) & 7;
			if (reg == 0 || reg == 1)
				imm = (op == 0xF6) ? 1 : (opsz16 ? 2 : 4);
			else
				imm = 0;
		}
		if (imm) {
			out->imm_off = (uint8_t)(p - s);
			if (p + imm > end) goto bad;
			p += imm;
		}
	}
	out->len = (uint8_t)(p - s);
	if (out->len == 0 || out->len > 15) goto bad;
	return true;
bad:
	out->flags |= F86_BAD;
	out->len = 1;
	return false;
}
