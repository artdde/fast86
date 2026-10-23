/* Bare-metal 64-bit: print via COM1 (0x3f8) and HLT.
   Loaded at GPA 0x200000 by `fast86 --system`. */
	.code64
	.globl _start
_start:
	mov	$0x3f8, %dx
	lea	msg(%rip), %rsi
1:
	movzb	(%rsi), %eax
	test	%al, %al
	jz	2f
	out	%al, %dx
	inc	%rsi
	jmp	1b
2:
	hlt
	jmp	2b

msg:
	.asciz	"fast86-system-ok\n"
