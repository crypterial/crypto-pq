.intel_syntax noprefix
vmovdqu xmm4, xmmword ptr [rdi]
vmovdqu xmm5, xmmword ptr [rdi + 16]
vmovdqu xmm12, xmmword ptr [r8]
vmovdqu xmm13, xmmword ptr [r8 + 32]
mov rax, qword ptr [rcx + 32]
mov r10, rsi
mov r11, rdx
1:
vmovq xmm14, rax
vpxor xmm3, xmm14, xmmword ptr [rcx + 16]
vmovdqa xmm0, xmm4
vmovdqa xmm1, xmm5
vmovdqu xmm2, xmmword ptr [rcx]
vpbroadcastd xmm6, dword ptr [r10 + 0]
vpbroadcastd xmm11, dword ptr [r10 + 8]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 16]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 4]
vpbroadcastd xmm11, dword ptr [r10 + 12]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 20]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 56]
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 40]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 48]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 60]
vpbroadcastd xmm11, dword ptr [r10 + 36]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 44]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 52]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 56]
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 36]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 52]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 40]
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 60]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 20]
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 0]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 44]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 12]
vpbroadcastd xmm11, dword ptr [r10 + 48]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 8]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 44]
vpbroadcastd xmm11, dword ptr [r10 + 48]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 20]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 60]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 32]
vpbroadcastd xmm11, dword ptr [r10 + 0]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 8]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 52]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 36]
vpbroadcastd xmm11, dword ptr [r10 + 40]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 12]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 16]
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 24]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 28]
vpbroadcastd xmm11, dword ptr [r10 + 12]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 52]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 44]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 36]
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 48]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 60]
vpbroadcastd xmm11, dword ptr [r10 + 8]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 20]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 32]
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 40]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 0]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 36]
vpbroadcastd xmm11, dword ptr [r10 + 20]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 8]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 40]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 0]
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 16]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 60]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 12]
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 44]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 52]
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 48]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 8]
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 0]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 48]
vpbroadcastd xmm11, dword ptr [r10 + 40]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 44]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 12]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 4]
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 28]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 60]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 36]
vpbroadcastd xmm11, dword ptr [r10 + 52]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 20]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 48]
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 56]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 20]
vpbroadcastd xmm11, dword ptr [r10 + 60]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 52]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 40]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 32]
vpbroadcastd xmm11, dword ptr [r10 + 0]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 24]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 36]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 44]
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 12]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 8]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 52]
vpbroadcastd xmm11, dword ptr [r10 + 28]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 48]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 12]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 44]
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 4]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 36]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 8]
vpbroadcastd xmm11, dword ptr [r10 + 20]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 60]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 40]
vpbroadcastd xmm11, dword ptr [r10 + 0]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 16]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 24]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 24]
vpbroadcastd xmm11, dword ptr [r10 + 56]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 44]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 0]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 60]
vpbroadcastd xmm11, dword ptr [r10 + 36]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 12]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 40]
vpbroadcastd xmm11, dword ptr [r10 + 48]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 52]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 20]
vpbroadcastd xmm11, dword ptr [r10 + 8]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 28]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpbroadcastd xmm6, dword ptr [r10 + 40]
vpbroadcastd xmm11, dword ptr [r10 + 32]
vpblendd xmm6, xmm6, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 28]
vpblendd xmm6, xmm6, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 4]
vpblendd xmm6, xmm6, xmm11, 0x08
vpbroadcastd xmm7, dword ptr [r10 + 8]
vpbroadcastd xmm11, dword ptr [r10 + 16]
vpblendd xmm7, xmm7, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 24]
vpblendd xmm7, xmm7, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 20]
vpblendd xmm7, xmm7, xmm11, 0x08
vpbroadcastd xmm8, dword ptr [r10 + 52]
vpbroadcastd xmm11, dword ptr [r10 + 60]
vpblendd xmm8, xmm8, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 36]
vpblendd xmm8, xmm8, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 12]
vpblendd xmm8, xmm8, xmm11, 0x08
vpbroadcastd xmm9, dword ptr [r10 + 0]
vpbroadcastd xmm11, dword ptr [r10 + 44]
vpblendd xmm9, xmm9, xmm11, 0x02
vpbroadcastd xmm10, dword ptr [r10 + 56]
vpblendd xmm9, xmm9, xmm10, 0x04
vpbroadcastd xmm11, dword ptr [r10 + 48]
vpblendd xmm9, xmm9, xmm11, 0x08
vpaddd xmm0, xmm0, xmm6
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm7
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x93
vpshufd xmm2, xmm2, 0x39
vpshufd xmm3, xmm3, 0x4e
vpaddd xmm0, xmm0, xmm8
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm12
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 20
vpsrld xmm1, xmm1, 12
vpor xmm1, xmm1, xmm10
vpaddd xmm0, xmm0, xmm9
vpaddd xmm0, xmm0, xmm1
vpxor xmm3, xmm3, xmm0
vpshufb xmm3, xmm3, xmm13
vpaddd xmm2, xmm2, xmm3
vpxor xmm1, xmm1, xmm2
vpslld xmm10, xmm1, 25
vpsrld xmm1, xmm1, 7
vpor xmm1, xmm1, xmm10
vpshufd xmm0, xmm0, 0x39
vpshufd xmm2, xmm2, 0x93
vpshufd xmm3, xmm3, 0x4e
vpxor xmm0, xmm0, xmm2
vpxor xmm4, xmm4, xmm0
vpxor xmm1, xmm1, xmm3
vpxor xmm5, xmm5, xmm1
add r10, 64
add rax, 64
dec r11
jnz 1b
vmovdqu xmmword ptr [rdi], xmm4
vmovdqu xmmword ptr [rdi + 16], xmm5
vzeroupper
.att_syntax prefix
