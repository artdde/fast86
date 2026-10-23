/* Bare-metal ALU loop + one serial line. Compares --system vs qemu-system TCG. */
	.code64
	.globl _start
_start:
	mov	$80000000, %rcx
	xor	%eax, %eax
	mov	$1, %edx
1:
	add	%edx, %eax
	xor	%ecx, %eax
	add	$0x9e3779b9, %edx
	dec	%rcx
	jnz	1b
	mov	$0x3f8, %dx
	lea	msg(%rip), %rsi
2:
	movzb	(%rsi), %ebx
	test	%bl, %bl
	jz	3f
	mov	%bl, %al
	out	%al, %dx
	inc	%rsi
	jmp	2b
3:
	hlt
	jmp	3b
msg:
	.asciz	"sysloop-ok\n"
