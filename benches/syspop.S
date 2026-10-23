/* Bare-metal 64-bit regression test: stack ops on a kernel-half stack.

   fast86 runs guest code natively. A kernel-half (0xffffff80...) stack is
   not host-mapped, so every push/pop/ret on it is a SIGSEGV that the engine
   emulates one instruction at a time. This checks, at both 16-byte stack
   phases:
     - PUSH RSP pushes the pre-decrement value
     - POP RSP ends with RSP = the popped value (it used to become ADD RSP,8,
       which shifted every callee-saved pop in XNU's running_timer_setup
       epilogue and left a scheduler lock held)
     - the clang stack-realignment epilogue that running_timer_setup uses
   Loaded at GPA 0x200000 by `fast86 --system`; prints the verdict on COM1. */
	.code64
	.globl _start
_start:
	/* Page tables at 0x300000: PML4[0] and PML4[511] -> PDPT; PDPT[0] and
	   PDPT[480] -> PD; PD = 512 x 2 MiB identity pages. So
	   0xffffff8000000000 + x aliases physical x for the first GiB. */
	mov	$0x300000, %edi
	mov	$0x301003, %eax		/* PDPT | P | RW */
	mov	%rax, (%rdi)
	mov	%rax, 511*8(%rdi)
	mov	$0x301000, %edi
	mov	$0x302003, %eax		/* PD | P | RW */
	mov	%rax, (%rdi)
	mov	%rax, 480*8(%rdi)
	mov	$0x302000, %edi
	mov	$0x83, %eax		/* P | RW | PS */
	mov	$512, %ecx
1:	mov	%rax, (%rdi)
	add	$0x200000, %rax
	add	$8, %rdi
	dec	%ecx
	jnz	1b
	mov	$0x300000, %eax
	mov	%rax, %cr3
	mov	%cr0, %rax
	bts	$31, %rax
	mov	%rax, %cr0

	/* Switch to the kernel-half alias of our stack. */
	movabs	$0xffffff8000000000, %r13
	lea	stack_top(%rip), %rsp
	add	%r13, %rsp

	/* 1: PUSH RSP pushes the pre-decrement value and POP restores RSP. */
	mov	%rsp, %rcx
	push	%rsp
	pop	%rax
	cmp	%rax, %rcx
	jne	fail1
	cmp	%rsp, %rcx
	jne	fail1

	/* 2: POP RSP loads RSP from the stack; the increment is not applied
	   on top of the loaded value. */
	mov	%rsp, %rcx
	lea	-64(%rsp), %rax
	mov	%rcx, (%rax)		/* [rsp-64] = original rsp */
	mov	%rax, %rsp		/* rsp = rsp-64 */
	pop	%rsp			/* rsp = original */
	cmp	%rsp, %rcx
	jne	fail2

	/* 3: realigning epilogue, rsp == 0 mod 16 at the call */
	and	$-16, %rsp
	call	check_func
	test	%r10, %r10
	jnz	fail3

	/* 4: same with rsp == 8 mod 16 at the call */
	sub	$8, %rsp
	call	check_func
	add	$8, %rsp
	test	%r10, %r10
	jnz	fail4

	lea	ok_msg(%rip), %rsi
	jmp	print
fail1:	lea	f1_msg(%rip), %rsi
	jmp	print
fail2:	lea	f2_msg(%rip), %rsi
	jmp	print
fail3:	lea	f3_msg(%rip), %rsi
	jmp	print
fail4:	lea	f4_msg(%rip), %rsi
print:
	mov	$0x3f8, %dx
1:	movzb	(%rsi), %eax
	test	%al, %al
	jz	2f
	out	%al, %dx
	inc	%rsi
	jmp	1b
2:	hlt
	jmp	2b

/* Sets callee-saved registers to known values, calls func (which clobbers
   and restores them through the realigning epilogue), and leaves r10 = 0
   when rsp and every callee-saved register came back intact and func ran. */
check_func:
	mov	$0x1111, %ebx
	mov	$0x2222, %r12d
	mov	$0x3333, %r14d
	mov	$0x4444, %r15d
	mov	$0x5555, %ebp
	mov	%rsp, %r9
	mov	$1, %r10d
	call	func
	cmp	%rsp, %r9
	jne	1f
	cmp	$0x77, %rax
	jne	1f
	cmp	$0x1111, %rbx
	jne	1f
	cmp	$0x2222, %r12
	jne	1f
	cmp	$0x3333, %r14
	jne	1f
	cmp	$0x4444, %r15
	jne	1f
	cmp	$0x5555, %rbp
	jne	1f
	xor	%r10d, %r10d
1:	ret

/* Mirrors XNU 24.4.0 running_timer_setup's kdebug probe site: realign the
   stack, stash the old rsp, patched-out call (nops), then `pop %rsp`. */
func:
	push	%rbp
	mov	%rsp, %rbp
	push	%r15
	push	%r14
	push	%r12
	push	%rbx
	mov	$0xaaaa, %ebx
	mov	$0xbbbb, %r12d
	mov	$0xcccc, %r14d
	mov	$0xdddd, %r15d
	mov	%rsp, %rax
	sub	$8, %rax
	and	$-16, %rax
	mov	%rsp, (%rax)
	mov	%rax, %rsp
	sub	$16, %rsp
	mov	%rax, (%rsp)
	nop
	nop
	nop
	add	$16, %rsp
	pop	%rsp
	mov	$0x77, %eax
	pop	%rbx
	pop	%r12
	pop	%r14
	pop	%r15
	pop	%rbp
	ret

ok_msg:	.asciz	"fast86-syspop-ok\n"
f1_msg:	.asciz	"fast86-syspop-FAIL1 push rsp\n"
f2_msg:	.asciz	"fast86-syspop-FAIL2 pop rsp\n"
f3_msg:	.asciz	"fast86-syspop-FAIL3 realign epilogue (rsp%16==0)\n"
f4_msg:	.asciz	"fast86-syspop-FAIL4 realign epilogue (rsp%16==8)\n"

	.p2align 4
	.space	1024
stack_top:
