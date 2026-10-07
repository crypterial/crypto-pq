.intel_syntax noprefix
vmovdqu ymm4, ymmword ptr [rdi]
vmovdqu ymm5, ymmword ptr [rdi + 32]
vmovdqu ymm12, ymmword ptr [r8]
vmovdqu ymm13, ymmword ptr [r8 + 32]
mov rax, qword ptr [rcx + 64]
mov r9, qword ptr [rcx + 72]
mov r10, rsi
mov r11, rdx
1:
vmovq xmm14, rax
vpinsrq xmm14, xmm14, r9, 1
vpxor ymm3, ymm14, ymmword ptr [rcx + 32]
vmovdqa ymm0, ymm4
vmovdqa ymm1, ymm5
vmovdqu ymm2, ymmword ptr [rcx]
vpbroadcastq ymm6, qword ptr [r10 + 0]
vpbroadcastq ymm11, qword ptr [r10 + 16]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 32]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 8]
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 40]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 112]
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 80]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 120]
vpbroadcastq ymm11, qword ptr [r10 + 72]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 88]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 112]
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 72]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 80]
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 120]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 40]
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 0]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 88]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 24]
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 16]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 88]
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 40]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 120]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 64]
vpbroadcastq ymm11, qword ptr [r10 + 0]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 16]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 72]
vpbroadcastq ymm11, qword ptr [r10 + 80]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 24]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 32]
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 48]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 56]
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 104]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 88]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 72]
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 96]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 120]
vpbroadcastq ymm11, qword ptr [r10 + 16]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 40]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 64]
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 80]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 0]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 72]
vpbroadcastq ymm11, qword ptr [r10 + 40]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 16]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 80]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 0]
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 32]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 120]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 24]
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 88]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 104]
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 96]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 16]
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 0]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 96]
vpbroadcastq ymm11, qword ptr [r10 + 80]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 88]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 8]
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 56]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 120]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 72]
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 40]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 96]
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 112]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 40]
vpbroadcastq ymm11, qword ptr [r10 + 120]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 104]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 80]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 64]
vpbroadcastq ymm11, qword ptr [r10 + 0]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 48]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 72]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 88]
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 24]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 16]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 104]
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 96]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 88]
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 8]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 72]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 16]
vpbroadcastq ymm11, qword ptr [r10 + 40]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 120]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 80]
vpbroadcastq ymm11, qword ptr [r10 + 0]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 32]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 48]
vpbroadcastq ymm11, qword ptr [r10 + 112]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 88]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 0]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 120]
vpbroadcastq ymm11, qword ptr [r10 + 72]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 24]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 80]
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 104]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 40]
vpbroadcastq ymm11, qword ptr [r10 + 16]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 56]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 80]
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 56]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 16]
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 48]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 40]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 104]
vpbroadcastq ymm11, qword ptr [r10 + 120]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 72]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 0]
vpbroadcastq ymm11, qword ptr [r10 + 88]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 112]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 0]
vpbroadcastq ymm11, qword ptr [r10 + 16]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 32]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 8]
vpbroadcastq ymm11, qword ptr [r10 + 24]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 40]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 112]
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 80]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 120]
vpbroadcastq ymm11, qword ptr [r10 + 72]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 88]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpbroadcastq ymm6, qword ptr [r10 + 112]
vpbroadcastq ymm11, qword ptr [r10 + 32]
vpblendd ymm6, ymm6, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 72]
vpblendd ymm6, ymm6, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 104]
vpblendd ymm6, ymm6, ymm11, 0xc0
vpbroadcastq ymm7, qword ptr [r10 + 80]
vpbroadcastq ymm11, qword ptr [r10 + 64]
vpblendd ymm7, ymm7, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 120]
vpblendd ymm7, ymm7, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 48]
vpblendd ymm7, ymm7, ymm11, 0xc0
vpbroadcastq ymm8, qword ptr [r10 + 40]
vpbroadcastq ymm11, qword ptr [r10 + 8]
vpblendd ymm8, ymm8, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 0]
vpblendd ymm8, ymm8, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 88]
vpblendd ymm8, ymm8, ymm11, 0xc0
vpbroadcastq ymm9, qword ptr [r10 + 24]
vpbroadcastq ymm11, qword ptr [r10 + 96]
vpblendd ymm9, ymm9, ymm11, 0x0c
vpbroadcastq ymm10, qword ptr [r10 + 16]
vpblendd ymm9, ymm9, ymm10, 0x30
vpbroadcastq ymm11, qword ptr [r10 + 56]
vpblendd ymm9, ymm9, ymm11, 0xc0
vpaddq ymm0, ymm0, ymm6
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm7
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x93
vpermq ymm2, ymm2, 0x39
vpermq ymm3, ymm3, 0x4e
vpaddq ymm0, ymm0, ymm8
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufd ymm3, ymm3, 0xb1
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpshufb ymm1, ymm1, ymm12
vpaddq ymm0, ymm0, ymm9
vpaddq ymm0, ymm0, ymm1
vpxor ymm3, ymm3, ymm0
vpshufb ymm3, ymm3, ymm13
vpaddq ymm2, ymm2, ymm3
vpxor ymm1, ymm1, ymm2
vpaddq ymm10, ymm1, ymm1
vpsrlq ymm1, ymm1, 63
vpor ymm1, ymm1, ymm10
vpermq ymm0, ymm0, 0x39
vpermq ymm2, ymm2, 0x93
vpermq ymm3, ymm3, 0x4e
vpxor ymm0, ymm0, ymm2
vpxor ymm4, ymm4, ymm0
vpxor ymm1, ymm1, ymm3
vpxor ymm5, ymm5, ymm1
add r10, 128
add rax, 128
adc r9, 0
dec r11
jnz 1b
vmovdqu ymmword ptr [rdi], ymm4
vmovdqu ymmword ptr [rdi + 32], ymm5
vzeroupper
.att_syntax prefix
