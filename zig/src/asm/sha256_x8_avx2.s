.intel_syntax noprefix
vmovdqu ymm0, ymmword ptr [rdi + 0]
vmovdqu ymm1, ymmword ptr [rdi + 32]
vmovdqu ymm2, ymmword ptr [rdi + 64]
vmovdqu ymm3, ymmword ptr [rdi + 96]
vmovdqu ymm4, ymmword ptr [rdi + 128]
vmovdqu ymm5, ymmword ptr [rdi + 160]
vmovdqu ymm6, ymmword ptr [rdi + 192]
vmovdqu ymm7, ymmword ptr [rdi + 224]
vpxor ymm10, ymm1, ymm2
vmovdqu ymm12, ymmword ptr [rsi + 0]
vmovdqa ymmword ptr [rcx + 0], ymm12
vpsrld ymm8, ymm4, 6
vpslld ymm9, ymm4, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm5, ymm6
vpand ymm9, ymm9, ymm4
vpxor ymm9, ymm9, ymm6
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm9
vpaddd ymm7, ymm7, ymmword ptr [rdx + 0]
vpaddd ymm7, ymm7, ymm12
vpaddd ymm3, ymm3, ymm7
vpsrld ymm8, ymm0, 2
vpslld ymm9, ymm0, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm0, ymm1
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm1
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 32]
vmovdqa ymmword ptr [rcx + 32], ymm12
vpsrld ymm8, ymm3, 6
vpslld ymm9, ymm3, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm4, ymm5
vpand ymm9, ymm9, ymm3
vpxor ymm9, ymm9, ymm5
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm9
vpaddd ymm6, ymm6, ymmword ptr [rdx + 32]
vpaddd ymm6, ymm6, ymm12
vpaddd ymm2, ymm2, ymm6
vpsrld ymm8, ymm7, 2
vpslld ymm9, ymm7, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm7, ymm0
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm0
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 64]
vmovdqa ymmword ptr [rcx + 64], ymm12
vpsrld ymm8, ymm2, 6
vpslld ymm9, ymm2, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm3, ymm4
vpand ymm9, ymm9, ymm2
vpxor ymm9, ymm9, ymm4
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm9
vpaddd ymm5, ymm5, ymmword ptr [rdx + 64]
vpaddd ymm5, ymm5, ymm12
vpaddd ymm1, ymm1, ymm5
vpsrld ymm8, ymm6, 2
vpslld ymm9, ymm6, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm6, ymm7
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm7
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 96]
vmovdqa ymmword ptr [rcx + 96], ymm12
vpsrld ymm8, ymm1, 6
vpslld ymm9, ymm1, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm2, ymm3
vpand ymm9, ymm9, ymm1
vpxor ymm9, ymm9, ymm3
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm9
vpaddd ymm4, ymm4, ymmword ptr [rdx + 96]
vpaddd ymm4, ymm4, ymm12
vpaddd ymm0, ymm0, ymm4
vpsrld ymm8, ymm5, 2
vpslld ymm9, ymm5, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm5, ymm6
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm6
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 128]
vmovdqa ymmword ptr [rcx + 128], ymm12
vpsrld ymm8, ymm0, 6
vpslld ymm9, ymm0, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm1, ymm2
vpand ymm9, ymm9, ymm0
vpxor ymm9, ymm9, ymm2
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm9
vpaddd ymm3, ymm3, ymmword ptr [rdx + 128]
vpaddd ymm3, ymm3, ymm12
vpaddd ymm7, ymm7, ymm3
vpsrld ymm8, ymm4, 2
vpslld ymm9, ymm4, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm4, ymm5
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm5
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 160]
vmovdqa ymmword ptr [rcx + 160], ymm12
vpsrld ymm8, ymm7, 6
vpslld ymm9, ymm7, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm0, ymm1
vpand ymm9, ymm9, ymm7
vpxor ymm9, ymm9, ymm1
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm9
vpaddd ymm2, ymm2, ymmword ptr [rdx + 160]
vpaddd ymm2, ymm2, ymm12
vpaddd ymm6, ymm6, ymm2
vpsrld ymm8, ymm3, 2
vpslld ymm9, ymm3, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm3, ymm4
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm4
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 192]
vmovdqa ymmword ptr [rcx + 192], ymm12
vpsrld ymm8, ymm6, 6
vpslld ymm9, ymm6, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm7, ymm0
vpand ymm9, ymm9, ymm6
vpxor ymm9, ymm9, ymm0
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm9
vpaddd ymm1, ymm1, ymmword ptr [rdx + 192]
vpaddd ymm1, ymm1, ymm12
vpaddd ymm5, ymm5, ymm1
vpsrld ymm8, ymm2, 2
vpslld ymm9, ymm2, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm2, ymm3
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm3
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 224]
vmovdqa ymmword ptr [rcx + 224], ymm12
vpsrld ymm8, ymm5, 6
vpslld ymm9, ymm5, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm6, ymm7
vpand ymm9, ymm9, ymm5
vpxor ymm9, ymm9, ymm7
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm9
vpaddd ymm0, ymm0, ymmword ptr [rdx + 224]
vpaddd ymm0, ymm0, ymm12
vpaddd ymm4, ymm4, ymm0
vpsrld ymm8, ymm1, 2
vpslld ymm9, ymm1, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm1, ymm2
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm2
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 256]
vmovdqa ymmword ptr [rcx + 256], ymm12
vpsrld ymm8, ymm4, 6
vpslld ymm9, ymm4, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm5, ymm6
vpand ymm9, ymm9, ymm4
vpxor ymm9, ymm9, ymm6
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm9
vpaddd ymm7, ymm7, ymmword ptr [rdx + 256]
vpaddd ymm7, ymm7, ymm12
vpaddd ymm3, ymm3, ymm7
vpsrld ymm8, ymm0, 2
vpslld ymm9, ymm0, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm0, ymm1
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm1
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 288]
vmovdqa ymmword ptr [rcx + 288], ymm12
vpsrld ymm8, ymm3, 6
vpslld ymm9, ymm3, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm4, ymm5
vpand ymm9, ymm9, ymm3
vpxor ymm9, ymm9, ymm5
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm9
vpaddd ymm6, ymm6, ymmword ptr [rdx + 288]
vpaddd ymm6, ymm6, ymm12
vpaddd ymm2, ymm2, ymm6
vpsrld ymm8, ymm7, 2
vpslld ymm9, ymm7, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm7, ymm0
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm0
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 320]
vmovdqa ymmword ptr [rcx + 320], ymm12
vpsrld ymm8, ymm2, 6
vpslld ymm9, ymm2, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm3, ymm4
vpand ymm9, ymm9, ymm2
vpxor ymm9, ymm9, ymm4
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm9
vpaddd ymm5, ymm5, ymmword ptr [rdx + 320]
vpaddd ymm5, ymm5, ymm12
vpaddd ymm1, ymm1, ymm5
vpsrld ymm8, ymm6, 2
vpslld ymm9, ymm6, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm6, ymm7
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm7
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 352]
vmovdqa ymmword ptr [rcx + 352], ymm12
vpsrld ymm8, ymm1, 6
vpslld ymm9, ymm1, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm2, ymm3
vpand ymm9, ymm9, ymm1
vpxor ymm9, ymm9, ymm3
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm9
vpaddd ymm4, ymm4, ymmword ptr [rdx + 352]
vpaddd ymm4, ymm4, ymm12
vpaddd ymm0, ymm0, ymm4
vpsrld ymm8, ymm5, 2
vpslld ymm9, ymm5, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm5, ymm6
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm6
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 384]
vmovdqa ymmword ptr [rcx + 384], ymm12
vpsrld ymm8, ymm0, 6
vpslld ymm9, ymm0, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm1, ymm2
vpand ymm9, ymm9, ymm0
vpxor ymm9, ymm9, ymm2
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm9
vpaddd ymm3, ymm3, ymmword ptr [rdx + 384]
vpaddd ymm3, ymm3, ymm12
vpaddd ymm7, ymm7, ymm3
vpsrld ymm8, ymm4, 2
vpslld ymm9, ymm4, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm4, ymm5
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm5
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 416]
vmovdqa ymmword ptr [rcx + 416], ymm12
vpsrld ymm8, ymm7, 6
vpslld ymm9, ymm7, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm0, ymm1
vpand ymm9, ymm9, ymm7
vpxor ymm9, ymm9, ymm1
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm9
vpaddd ymm2, ymm2, ymmword ptr [rdx + 416]
vpaddd ymm2, ymm2, ymm12
vpaddd ymm6, ymm6, ymm2
vpsrld ymm8, ymm3, 2
vpslld ymm9, ymm3, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm3, ymm4
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm4
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm11
vmovdqu ymm12, ymmword ptr [rsi + 448]
vmovdqa ymmword ptr [rcx + 448], ymm12
vpsrld ymm8, ymm6, 6
vpslld ymm9, ymm6, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm7, ymm0
vpand ymm9, ymm9, ymm6
vpxor ymm9, ymm9, ymm0
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm9
vpaddd ymm1, ymm1, ymmword ptr [rdx + 448]
vpaddd ymm1, ymm1, ymm12
vpaddd ymm5, ymm5, ymm1
vpsrld ymm8, ymm2, 2
vpslld ymm9, ymm2, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm2, ymm3
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm3
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm10
vmovdqu ymm12, ymmword ptr [rsi + 480]
vmovdqa ymmword ptr [rcx + 480], ymm12
vpsrld ymm8, ymm5, 6
vpslld ymm9, ymm5, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm6, ymm7
vpand ymm9, ymm9, ymm5
vpxor ymm9, ymm9, ymm7
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm9
vpaddd ymm0, ymm0, ymmword ptr [rdx + 480]
vpaddd ymm0, ymm0, ymm12
vpaddd ymm4, ymm4, ymm0
vpsrld ymm8, ymm1, 2
vpslld ymm9, ymm1, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm1, ymm2
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm2
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm11
lea r8, [rdx + 512]
mov eax, 3
1:
vmovdqa ymm12, ymmword ptr [rcx + 32]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 448]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 288]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 0]
vmovdqa ymmword ptr [rcx + 0], ymm12
vpsrld ymm8, ymm4, 6
vpslld ymm9, ymm4, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm5, ymm6
vpand ymm9, ymm9, ymm4
vpxor ymm9, ymm9, ymm6
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm9
vpaddd ymm7, ymm7, ymmword ptr [r8 + 0]
vpaddd ymm7, ymm7, ymm12
vpaddd ymm3, ymm3, ymm7
vpsrld ymm8, ymm0, 2
vpslld ymm9, ymm0, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm0, ymm1
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm1
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 64]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 480]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 320]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 32]
vmovdqa ymmword ptr [rcx + 32], ymm12
vpsrld ymm8, ymm3, 6
vpslld ymm9, ymm3, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm4, ymm5
vpand ymm9, ymm9, ymm3
vpxor ymm9, ymm9, ymm5
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm9
vpaddd ymm6, ymm6, ymmword ptr [r8 + 32]
vpaddd ymm6, ymm6, ymm12
vpaddd ymm2, ymm2, ymm6
vpsrld ymm8, ymm7, 2
vpslld ymm9, ymm7, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm7, ymm0
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm0
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 96]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 0]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 352]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 64]
vmovdqa ymmword ptr [rcx + 64], ymm12
vpsrld ymm8, ymm2, 6
vpslld ymm9, ymm2, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm3, ymm4
vpand ymm9, ymm9, ymm2
vpxor ymm9, ymm9, ymm4
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm9
vpaddd ymm5, ymm5, ymmword ptr [r8 + 64]
vpaddd ymm5, ymm5, ymm12
vpaddd ymm1, ymm1, ymm5
vpsrld ymm8, ymm6, 2
vpslld ymm9, ymm6, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm6, ymm7
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm7
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 128]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 32]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 384]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 96]
vmovdqa ymmword ptr [rcx + 96], ymm12
vpsrld ymm8, ymm1, 6
vpslld ymm9, ymm1, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm2, ymm3
vpand ymm9, ymm9, ymm1
vpxor ymm9, ymm9, ymm3
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm9
vpaddd ymm4, ymm4, ymmword ptr [r8 + 96]
vpaddd ymm4, ymm4, ymm12
vpaddd ymm0, ymm0, ymm4
vpsrld ymm8, ymm5, 2
vpslld ymm9, ymm5, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm5, ymm6
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm6
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 160]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 64]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 416]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 128]
vmovdqa ymmword ptr [rcx + 128], ymm12
vpsrld ymm8, ymm0, 6
vpslld ymm9, ymm0, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm1, ymm2
vpand ymm9, ymm9, ymm0
vpxor ymm9, ymm9, ymm2
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm9
vpaddd ymm3, ymm3, ymmword ptr [r8 + 128]
vpaddd ymm3, ymm3, ymm12
vpaddd ymm7, ymm7, ymm3
vpsrld ymm8, ymm4, 2
vpslld ymm9, ymm4, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm4, ymm5
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm5
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 192]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 96]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 448]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 160]
vmovdqa ymmword ptr [rcx + 160], ymm12
vpsrld ymm8, ymm7, 6
vpslld ymm9, ymm7, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm0, ymm1
vpand ymm9, ymm9, ymm7
vpxor ymm9, ymm9, ymm1
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm9
vpaddd ymm2, ymm2, ymmword ptr [r8 + 160]
vpaddd ymm2, ymm2, ymm12
vpaddd ymm6, ymm6, ymm2
vpsrld ymm8, ymm3, 2
vpslld ymm9, ymm3, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm3, ymm4
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm4
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 224]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 128]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 480]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 192]
vmovdqa ymmword ptr [rcx + 192], ymm12
vpsrld ymm8, ymm6, 6
vpslld ymm9, ymm6, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm7, ymm0
vpand ymm9, ymm9, ymm6
vpxor ymm9, ymm9, ymm0
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm9
vpaddd ymm1, ymm1, ymmword ptr [r8 + 192]
vpaddd ymm1, ymm1, ymm12
vpaddd ymm5, ymm5, ymm1
vpsrld ymm8, ymm2, 2
vpslld ymm9, ymm2, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm2, ymm3
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm3
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 256]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 160]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 0]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 224]
vmovdqa ymmword ptr [rcx + 224], ymm12
vpsrld ymm8, ymm5, 6
vpslld ymm9, ymm5, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm6, ymm7
vpand ymm9, ymm9, ymm5
vpxor ymm9, ymm9, ymm7
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm9
vpaddd ymm0, ymm0, ymmword ptr [r8 + 224]
vpaddd ymm0, ymm0, ymm12
vpaddd ymm4, ymm4, ymm0
vpsrld ymm8, ymm1, 2
vpslld ymm9, ymm1, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm1, ymm2
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm2
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 288]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 192]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 32]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 256]
vmovdqa ymmword ptr [rcx + 256], ymm12
vpsrld ymm8, ymm4, 6
vpslld ymm9, ymm4, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm5, ymm6
vpand ymm9, ymm9, ymm4
vpxor ymm9, ymm9, ymm6
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm9
vpaddd ymm7, ymm7, ymmword ptr [r8 + 256]
vpaddd ymm7, ymm7, ymm12
vpaddd ymm3, ymm3, ymm7
vpsrld ymm8, ymm0, 2
vpslld ymm9, ymm0, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm0, ymm1
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm1
vpaddd ymm7, ymm7, ymm8
vpaddd ymm7, ymm7, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 320]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 224]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 64]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 288]
vmovdqa ymmword ptr [rcx + 288], ymm12
vpsrld ymm8, ymm3, 6
vpslld ymm9, ymm3, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm4, ymm5
vpand ymm9, ymm9, ymm3
vpxor ymm9, ymm9, ymm5
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm9
vpaddd ymm6, ymm6, ymmword ptr [r8 + 288]
vpaddd ymm6, ymm6, ymm12
vpaddd ymm2, ymm2, ymm6
vpsrld ymm8, ymm7, 2
vpslld ymm9, ymm7, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm7, ymm0
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm0
vpaddd ymm6, ymm6, ymm8
vpaddd ymm6, ymm6, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 352]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 256]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 96]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 320]
vmovdqa ymmword ptr [rcx + 320], ymm12
vpsrld ymm8, ymm2, 6
vpslld ymm9, ymm2, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm3, ymm4
vpand ymm9, ymm9, ymm2
vpxor ymm9, ymm9, ymm4
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm9
vpaddd ymm5, ymm5, ymmword ptr [r8 + 320]
vpaddd ymm5, ymm5, ymm12
vpaddd ymm1, ymm1, ymm5
vpsrld ymm8, ymm6, 2
vpslld ymm9, ymm6, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm6, ymm7
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm7
vpaddd ymm5, ymm5, ymm8
vpaddd ymm5, ymm5, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 384]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 288]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 128]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 352]
vmovdqa ymmword ptr [rcx + 352], ymm12
vpsrld ymm8, ymm1, 6
vpslld ymm9, ymm1, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm2, ymm3
vpand ymm9, ymm9, ymm1
vpxor ymm9, ymm9, ymm3
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm9
vpaddd ymm4, ymm4, ymmword ptr [r8 + 352]
vpaddd ymm4, ymm4, ymm12
vpaddd ymm0, ymm0, ymm4
vpsrld ymm8, ymm5, 2
vpslld ymm9, ymm5, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm5, ymm6
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm6
vpaddd ymm4, ymm4, ymm8
vpaddd ymm4, ymm4, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 416]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 320]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 160]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 384]
vmovdqa ymmword ptr [rcx + 384], ymm12
vpsrld ymm8, ymm0, 6
vpslld ymm9, ymm0, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm0, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm0, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm1, ymm2
vpand ymm9, ymm9, ymm0
vpxor ymm9, ymm9, ymm2
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm9
vpaddd ymm3, ymm3, ymmword ptr [r8 + 384]
vpaddd ymm3, ymm3, ymm12
vpaddd ymm7, ymm7, ymm3
vpsrld ymm8, ymm4, 2
vpslld ymm9, ymm4, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm4, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm4, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm4, ymm5
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm5
vpaddd ymm3, ymm3, ymm8
vpaddd ymm3, ymm3, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 448]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 352]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 192]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 416]
vmovdqa ymmword ptr [rcx + 416], ymm12
vpsrld ymm8, ymm7, 6
vpslld ymm9, ymm7, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm7, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm7, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm0, ymm1
vpand ymm9, ymm9, ymm7
vpxor ymm9, ymm9, ymm1
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm9
vpaddd ymm2, ymm2, ymmword ptr [r8 + 416]
vpaddd ymm2, ymm2, ymm12
vpaddd ymm6, ymm6, ymm2
vpsrld ymm8, ymm3, 2
vpslld ymm9, ymm3, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm3, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm3, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm3, ymm4
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm4
vpaddd ymm2, ymm2, ymm8
vpaddd ymm2, ymm2, ymm11
vmovdqa ymm12, ymmword ptr [rcx + 480]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 384]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 224]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 448]
vmovdqa ymmword ptr [rcx + 448], ymm12
vpsrld ymm8, ymm6, 6
vpslld ymm9, ymm6, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm6, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm6, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm7, ymm0
vpand ymm9, ymm9, ymm6
vpxor ymm9, ymm9, ymm0
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm9
vpaddd ymm1, ymm1, ymmword ptr [r8 + 448]
vpaddd ymm1, ymm1, ymm12
vpaddd ymm5, ymm5, ymm1
vpsrld ymm8, ymm2, 2
vpslld ymm9, ymm2, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm2, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm2, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm11, ymm2, ymm3
vpand ymm10, ymm10, ymm11
vpxor ymm10, ymm10, ymm3
vpaddd ymm1, ymm1, ymm8
vpaddd ymm1, ymm1, ymm10
vmovdqa ymm12, ymmword ptr [rcx + 0]
vpsrld ymm13, ymm12, 7
vpslld ymm14, ymm12, 25
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 18
vpxor ymm13, ymm13, ymm14
vpslld ymm14, ymm12, 14
vpxor ymm13, ymm13, ymm14
vpsrld ymm14, ymm12, 3
vpxor ymm13, ymm13, ymm14
vmovdqa ymm12, ymmword ptr [rcx + 416]
vpsrld ymm14, ymm12, 17
vpslld ymm15, ymm12, 15
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 19
vpxor ymm14, ymm14, ymm15
vpslld ymm15, ymm12, 13
vpxor ymm14, ymm14, ymm15
vpsrld ymm15, ymm12, 10
vpxor ymm14, ymm14, ymm15
vpaddd ymm13, ymm13, ymm14
vpaddd ymm13, ymm13, ymmword ptr [rcx + 256]
vpaddd ymm12, ymm13, ymmword ptr [rcx + 480]
vmovdqa ymmword ptr [rcx + 480], ymm12
vpsrld ymm8, ymm5, 6
vpslld ymm9, ymm5, 26
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 11
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 21
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm5, 25
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm5, 7
vpxor ymm8, ymm8, ymm9
vpxor ymm9, ymm6, ymm7
vpand ymm9, ymm9, ymm5
vpxor ymm9, ymm9, ymm7
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm9
vpaddd ymm0, ymm0, ymmword ptr [r8 + 480]
vpaddd ymm0, ymm0, ymm12
vpaddd ymm4, ymm4, ymm0
vpsrld ymm8, ymm1, 2
vpslld ymm9, ymm1, 30
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 13
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 19
vpxor ymm8, ymm8, ymm9
vpsrld ymm9, ymm1, 22
vpxor ymm8, ymm8, ymm9
vpslld ymm9, ymm1, 10
vpxor ymm8, ymm8, ymm9
vpxor ymm10, ymm1, ymm2
vpand ymm11, ymm11, ymm10
vpxor ymm11, ymm11, ymm2
vpaddd ymm0, ymm0, ymm8
vpaddd ymm0, ymm0, ymm11
add r8, 512
dec eax
jnz 1b
vpaddd ymm0, ymm0, ymmword ptr [rdi + 0]
vmovdqu ymmword ptr [rdi + 0], ymm0
vpaddd ymm1, ymm1, ymmword ptr [rdi + 32]
vmovdqu ymmword ptr [rdi + 32], ymm1
vpaddd ymm2, ymm2, ymmword ptr [rdi + 64]
vmovdqu ymmword ptr [rdi + 64], ymm2
vpaddd ymm3, ymm3, ymmword ptr [rdi + 96]
vmovdqu ymmword ptr [rdi + 96], ymm3
vpaddd ymm4, ymm4, ymmword ptr [rdi + 128]
vmovdqu ymmword ptr [rdi + 128], ymm4
vpaddd ymm5, ymm5, ymmword ptr [rdi + 160]
vmovdqu ymmword ptr [rdi + 160], ymm5
vpaddd ymm6, ymm6, ymmword ptr [rdi + 192]
vmovdqu ymmword ptr [rdi + 192], ymm6
vpaddd ymm7, ymm7, ymmword ptr [rdi + 224]
vmovdqu ymmword ptr [rdi + 224], ymm7
vzeroupper
.att_syntax prefix
