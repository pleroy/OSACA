; Line 27
	mov	DWORD PTR i$2[rbp], 0
	jmp	SHORT $LN7@kernel
$LN5@kernel:
	mov	eax, DWORD PTR i$2[rbp]
	inc	eax
	mov	DWORD PTR i$2[rbp], eax
$LN7@kernel:
	mov	eax, DWORD PTR cur_elements$[rbp]
	cmp	DWORD PTR i$2[rbp], eax
	jge	SHORT $LN6@kernel
; Line 28
	movsxd	rax, DWORD PTR i$2[rbp]
	movsxd	rcx, DWORD PTR i$2[rbp]
	movsxd	rdx, DWORD PTR i$2[rbp]
	mov	r8, QWORD PTR c$[rbp]
	mov	r9, QWORD PTR d$[rbp]
	movsd	xmm0, QWORD PTR [r8+rcx*8]
	mulsd	xmm0, QWORD PTR [r9+rdx*8]
	mov	rcx, QWORD PTR b$[rbp]
	movsd	xmm1, QWORD PTR [rcx+rax*8]
	addsd	xmm1, xmm0
	movaps	xmm0, xmm1
	movsxd	rax, DWORD PTR i$2[rbp]
	mov	rcx, QWORD PTR a$[rbp]
	movsd	QWORD PTR [rcx+rax*8], xmm0
; Line 29
	jmp	SHORT $LN5@kernel
$LN6@kernel:
