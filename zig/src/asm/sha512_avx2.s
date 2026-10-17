.intel_syntax noprefix
mov rsi, qword ptr [rdi + 1312]
mov rdx, qword ptr [rdi + 1296]
mov rcx, qword ptr [rdi + 1304]
vmovdqa ymm15, ymmword ptr [rsi + 1280]
vmovdqu xmm0, xmmword ptr [rdx + 0]
vinserti128 ymm0, ymm0, xmmword ptr [rcx + 0], 1
vpshufb ymm0, ymm0, ymm15
vmovdqu xmm1, xmmword ptr [rdx + 16]
vinserti128 ymm1, ymm1, xmmword ptr [rcx + 16], 1
vpshufb ymm1, ymm1, ymm15
vmovdqu xmm2, xmmword ptr [rdx + 32]
vinserti128 ymm2, ymm2, xmmword ptr [rcx + 32], 1
vpshufb ymm2, ymm2, ymm15
vmovdqu xmm3, xmmword ptr [rdx + 48]
vinserti128 ymm3, ymm3, xmmword ptr [rcx + 48], 1
vpshufb ymm3, ymm3, ymm15
vmovdqu xmm4, xmmword ptr [rdx + 64]
vinserti128 ymm4, ymm4, xmmword ptr [rcx + 64], 1
vpshufb ymm4, ymm4, ymm15
vmovdqu xmm5, xmmword ptr [rdx + 80]
vinserti128 ymm5, ymm5, xmmword ptr [rcx + 80], 1
vpshufb ymm5, ymm5, ymm15
vmovdqu xmm6, xmmword ptr [rdx + 96]
vinserti128 ymm6, ymm6, xmmword ptr [rcx + 96], 1
vpshufb ymm6, ymm6, ymm15
vmovdqu xmm7, xmmword ptr [rdx + 112]
vinserti128 ymm7, ymm7, xmmword ptr [rcx + 112], 1
vpshufb ymm7, ymm7, ymm15
vpaddq ymm15, ymm0, ymmword ptr [rsi]
vmovdqa ymmword ptr [rdi], ymm15
mov r12, qword ptr [rdi + 1280]
mov rax, qword ptr [r12 + 0]
mov rbx, qword ptr [r12 + 8]
mov rcx, qword ptr [r12 + 16]
mov r8, qword ptr [r12 + 24]
mov rdx, qword ptr [r12 + 32]
mov r9, qword ptr [r12 + 40]
mov r10, qword ptr [r12 + 48]
mov r11, qword ptr [r12 + 56]
mov r14, rbx
xor r14, rcx
xor r15d, r15d
1:
vpaddq ymm15, ymm1, ymmword ptr [rsi + r15 + 32]
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 0]
vmovdqa ymmword ptr [rdi + r15 + 32], ymm15
xor r12, r13
rorx r13, rdx, 41
vpalignr ymm8, ymm1, ymm0, 8
xor r12, r13
andn r13, rdx, r10
vpalignr ymm9, ymm5, ymm4, 8
add r11, r13
mov r13, rdx
vpsrlq ymm10, ymm8, 1
and r13, r9
add r11, r13
vpsllq ymm11, ymm8, 63
add r11, r12
add r8, r11
vpxor ymm10, ymm10, ymm11
rorx r12, rax, 28
rorx r13, rax, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rax, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rax
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, rbx
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, rbx
add r12, r14
vpaddq ymm9, ymm9, ymm0
add r11, r12
rorx r12, r8, 14
rorx r14, r8, 18
vpaddq ymm9, ymm9, ymm10
add r10, qword ptr [rdi + r15 + 8]
xor r12, r14
vpsrlq ymm10, ymm7, 6
rorx r14, r8, 41
xor r12, r14
vpsrlq ymm11, ymm7, 19
andn r14, r8, r9
add r10, r14
vpxor ymm10, ymm10, ymm11
mov r14, r8
and r14, rdx
vpsllq ymm11, ymm7, 45
add r10, r14
add r10, r12
vpxor ymm10, ymm10, ymm11
add rcx, r10
rorx r12, r11, 28
vpsrlq ymm11, ymm7, 61
rorx r14, r11, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r11, 39
xor r12, r14
vpsllq ymm11, ymm7, 3
mov r14, r11
xor r14, rax
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rax
vpaddq ymm0, ymm9, ymm10
add r12, r13
add r10, r12
vpaddq ymm15, ymm2, ymmword ptr [rsi + r15 + 64]
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 32]
vmovdqa ymmword ptr [rdi + r15 + 64], ymm15
xor r12, r13
rorx r13, rcx, 41
vpalignr ymm8, ymm2, ymm1, 8
xor r12, r13
andn r13, rcx, rdx
vpalignr ymm9, ymm6, ymm5, 8
add r9, r13
mov r13, rcx
vpsrlq ymm10, ymm8, 1
and r13, r8
add r9, r13
vpsllq ymm11, ymm8, 63
add r9, r12
add rbx, r9
vpxor ymm10, ymm10, ymm11
rorx r12, r10, 28
rorx r13, r10, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, r10, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, r10
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r11
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r11
add r12, r14
vpaddq ymm9, ymm9, ymm1
add r9, r12
rorx r12, rbx, 14
rorx r14, rbx, 18
vpaddq ymm9, ymm9, ymm10
add rdx, qword ptr [rdi + r15 + 40]
xor r12, r14
vpsrlq ymm10, ymm0, 6
rorx r14, rbx, 41
xor r12, r14
vpsrlq ymm11, ymm0, 19
andn r14, rbx, r8
add rdx, r14
vpxor ymm10, ymm10, ymm11
mov r14, rbx
and r14, rcx
vpsllq ymm11, ymm0, 45
add rdx, r14
add rdx, r12
vpxor ymm10, ymm10, ymm11
add rax, rdx
rorx r12, r9, 28
vpsrlq ymm11, ymm0, 61
rorx r14, r9, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r9, 39
xor r12, r14
vpsllq ymm11, ymm0, 3
mov r14, r9
xor r14, r10
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, r10
vpaddq ymm1, ymm9, ymm10
add r12, r13
add rdx, r12
vpaddq ymm15, ymm3, ymmword ptr [rsi + r15 + 96]
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 64]
vmovdqa ymmword ptr [rdi + r15 + 96], ymm15
xor r12, r13
rorx r13, rax, 41
vpalignr ymm8, ymm3, ymm2, 8
xor r12, r13
andn r13, rax, rcx
vpalignr ymm9, ymm7, ymm6, 8
add r8, r13
mov r13, rax
vpsrlq ymm10, ymm8, 1
and r13, rbx
add r8, r13
vpsllq ymm11, ymm8, 63
add r8, r12
add r11, r8
vpxor ymm10, ymm10, ymm11
rorx r12, rdx, 28
rorx r13, rdx, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rdx, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rdx
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r9
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r9
add r12, r14
vpaddq ymm9, ymm9, ymm2
add r8, r12
rorx r12, r11, 14
rorx r14, r11, 18
vpaddq ymm9, ymm9, ymm10
add rcx, qword ptr [rdi + r15 + 72]
xor r12, r14
vpsrlq ymm10, ymm1, 6
rorx r14, r11, 41
xor r12, r14
vpsrlq ymm11, ymm1, 19
andn r14, r11, rbx
add rcx, r14
vpxor ymm10, ymm10, ymm11
mov r14, r11
and r14, rax
vpsllq ymm11, ymm1, 45
add rcx, r14
add rcx, r12
vpxor ymm10, ymm10, ymm11
add r10, rcx
rorx r12, r8, 28
vpsrlq ymm11, ymm1, 61
rorx r14, r8, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r8, 39
xor r12, r14
vpsllq ymm11, ymm1, 3
mov r14, r8
xor r14, rdx
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rdx
vpaddq ymm2, ymm9, ymm10
add r12, r13
add rcx, r12
vpaddq ymm15, ymm4, ymmword ptr [rsi + r15 + 128]
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 96]
vmovdqa ymmword ptr [rdi + r15 + 128], ymm15
xor r12, r13
rorx r13, r10, 41
vpalignr ymm8, ymm4, ymm3, 8
xor r12, r13
andn r13, r10, rax
vpalignr ymm9, ymm0, ymm7, 8
add rbx, r13
mov r13, r10
vpsrlq ymm10, ymm8, 1
and r13, r11
add rbx, r13
vpsllq ymm11, ymm8, 63
add rbx, r12
add r9, rbx
vpxor ymm10, ymm10, ymm11
rorx r12, rcx, 28
rorx r13, rcx, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rcx, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rcx
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r8
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r8
add r12, r14
vpaddq ymm9, ymm9, ymm3
add rbx, r12
rorx r12, r9, 14
rorx r14, r9, 18
vpaddq ymm9, ymm9, ymm10
add rax, qword ptr [rdi + r15 + 104]
xor r12, r14
vpsrlq ymm10, ymm2, 6
rorx r14, r9, 41
xor r12, r14
vpsrlq ymm11, ymm2, 19
andn r14, r9, r11
add rax, r14
vpxor ymm10, ymm10, ymm11
mov r14, r9
and r14, r10
vpsllq ymm11, ymm2, 45
add rax, r14
add rax, r12
vpxor ymm10, ymm10, ymm11
add rdx, rax
rorx r12, rbx, 28
vpsrlq ymm11, ymm2, 61
rorx r14, rbx, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, rbx, 39
xor r12, r14
vpsllq ymm11, ymm2, 3
mov r14, rbx
xor r14, rcx
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rcx
vpaddq ymm3, ymm9, ymm10
add r12, r13
add rax, r12
vpaddq ymm15, ymm5, ymmword ptr [rsi + r15 + 160]
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 128]
vmovdqa ymmword ptr [rdi + r15 + 160], ymm15
xor r12, r13
rorx r13, rdx, 41
vpalignr ymm8, ymm5, ymm4, 8
xor r12, r13
andn r13, rdx, r10
vpalignr ymm9, ymm1, ymm0, 8
add r11, r13
mov r13, rdx
vpsrlq ymm10, ymm8, 1
and r13, r9
add r11, r13
vpsllq ymm11, ymm8, 63
add r11, r12
add r8, r11
vpxor ymm10, ymm10, ymm11
rorx r12, rax, 28
rorx r13, rax, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rax, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rax
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, rbx
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, rbx
add r12, r14
vpaddq ymm9, ymm9, ymm4
add r11, r12
rorx r12, r8, 14
rorx r14, r8, 18
vpaddq ymm9, ymm9, ymm10
add r10, qword ptr [rdi + r15 + 136]
xor r12, r14
vpsrlq ymm10, ymm3, 6
rorx r14, r8, 41
xor r12, r14
vpsrlq ymm11, ymm3, 19
andn r14, r8, r9
add r10, r14
vpxor ymm10, ymm10, ymm11
mov r14, r8
and r14, rdx
vpsllq ymm11, ymm3, 45
add r10, r14
add r10, r12
vpxor ymm10, ymm10, ymm11
add rcx, r10
rorx r12, r11, 28
vpsrlq ymm11, ymm3, 61
rorx r14, r11, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r11, 39
xor r12, r14
vpsllq ymm11, ymm3, 3
mov r14, r11
xor r14, rax
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rax
vpaddq ymm4, ymm9, ymm10
add r12, r13
add r10, r12
vpaddq ymm15, ymm6, ymmword ptr [rsi + r15 + 192]
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 160]
vmovdqa ymmword ptr [rdi + r15 + 192], ymm15
xor r12, r13
rorx r13, rcx, 41
vpalignr ymm8, ymm6, ymm5, 8
xor r12, r13
andn r13, rcx, rdx
vpalignr ymm9, ymm2, ymm1, 8
add r9, r13
mov r13, rcx
vpsrlq ymm10, ymm8, 1
and r13, r8
add r9, r13
vpsllq ymm11, ymm8, 63
add r9, r12
add rbx, r9
vpxor ymm10, ymm10, ymm11
rorx r12, r10, 28
rorx r13, r10, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, r10, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, r10
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r11
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r11
add r12, r14
vpaddq ymm9, ymm9, ymm5
add r9, r12
rorx r12, rbx, 14
rorx r14, rbx, 18
vpaddq ymm9, ymm9, ymm10
add rdx, qword ptr [rdi + r15 + 168]
xor r12, r14
vpsrlq ymm10, ymm4, 6
rorx r14, rbx, 41
xor r12, r14
vpsrlq ymm11, ymm4, 19
andn r14, rbx, r8
add rdx, r14
vpxor ymm10, ymm10, ymm11
mov r14, rbx
and r14, rcx
vpsllq ymm11, ymm4, 45
add rdx, r14
add rdx, r12
vpxor ymm10, ymm10, ymm11
add rax, rdx
rorx r12, r9, 28
vpsrlq ymm11, ymm4, 61
rorx r14, r9, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r9, 39
xor r12, r14
vpsllq ymm11, ymm4, 3
mov r14, r9
xor r14, r10
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, r10
vpaddq ymm5, ymm9, ymm10
add r12, r13
add rdx, r12
vpaddq ymm15, ymm7, ymmword ptr [rsi + r15 + 224]
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 192]
vmovdqa ymmword ptr [rdi + r15 + 224], ymm15
xor r12, r13
rorx r13, rax, 41
vpalignr ymm8, ymm7, ymm6, 8
xor r12, r13
andn r13, rax, rcx
vpalignr ymm9, ymm3, ymm2, 8
add r8, r13
mov r13, rax
vpsrlq ymm10, ymm8, 1
and r13, rbx
add r8, r13
vpsllq ymm11, ymm8, 63
add r8, r12
add r11, r8
vpxor ymm10, ymm10, ymm11
rorx r12, rdx, 28
rorx r13, rdx, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rdx, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rdx
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r9
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r9
add r12, r14
vpaddq ymm9, ymm9, ymm6
add r8, r12
rorx r12, r11, 14
rorx r14, r11, 18
vpaddq ymm9, ymm9, ymm10
add rcx, qword ptr [rdi + r15 + 200]
xor r12, r14
vpsrlq ymm10, ymm5, 6
rorx r14, r11, 41
xor r12, r14
vpsrlq ymm11, ymm5, 19
andn r14, r11, rbx
add rcx, r14
vpxor ymm10, ymm10, ymm11
mov r14, r11
and r14, rax
vpsllq ymm11, ymm5, 45
add rcx, r14
add rcx, r12
vpxor ymm10, ymm10, ymm11
add r10, rcx
rorx r12, r8, 28
vpsrlq ymm11, ymm5, 61
rorx r14, r8, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, r8, 39
xor r12, r14
vpsllq ymm11, ymm5, 3
mov r14, r8
xor r14, rdx
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rdx
vpaddq ymm6, ymm9, ymm10
add r12, r13
add rcx, r12
vpaddq ymm15, ymm0, ymmword ptr [rsi + r15 + 256]
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 224]
vmovdqa ymmword ptr [rdi + r15 + 256], ymm15
xor r12, r13
rorx r13, r10, 41
vpalignr ymm8, ymm0, ymm7, 8
xor r12, r13
andn r13, r10, rax
vpalignr ymm9, ymm4, ymm3, 8
add rbx, r13
mov r13, r10
vpsrlq ymm10, ymm8, 1
and r13, r11
add rbx, r13
vpsllq ymm11, ymm8, 63
add rbx, r12
add r9, rbx
vpxor ymm10, ymm10, ymm11
rorx r12, rcx, 28
rorx r13, rcx, 34
vpsrlq ymm11, ymm8, 7
xor r12, r13
rorx r13, rcx, 39
vpxor ymm10, ymm10, ymm11
xor r12, r13
mov r13, rcx
vpshufb ymm11, ymm8, ymmword ptr [rsi + 1312]
xor r13, r8
and r14, r13
vpxor ymm10, ymm10, ymm11
xor r14, r8
add r12, r14
vpaddq ymm9, ymm9, ymm7
add rbx, r12
rorx r12, r9, 14
rorx r14, r9, 18
vpaddq ymm9, ymm9, ymm10
add rax, qword ptr [rdi + r15 + 232]
xor r12, r14
vpsrlq ymm10, ymm6, 6
rorx r14, r9, 41
xor r12, r14
vpsrlq ymm11, ymm6, 19
andn r14, r9, r11
add rax, r14
vpxor ymm10, ymm10, ymm11
mov r14, r9
and r14, r10
vpsllq ymm11, ymm6, 45
add rax, r14
add rax, r12
vpxor ymm10, ymm10, ymm11
add rdx, rax
rorx r12, rbx, 28
vpsrlq ymm11, ymm6, 61
rorx r14, rbx, 34
xor r12, r14
vpxor ymm10, ymm10, ymm11
rorx r14, rbx, 39
xor r12, r14
vpsllq ymm11, ymm6, 3
mov r14, rbx
xor r14, rcx
vpxor ymm10, ymm10, ymm11
and r13, r14
xor r13, rcx
vpaddq ymm7, ymm9, ymm10
add r12, r13
add rax, r12
add r15, 256
cmp r15, 1024
jb 1b
vpaddq ymm15, ymm1, ymmword ptr [rsi + r15 + 32]
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 0]
xor r12, r13
rorx r13, rdx, 41
xor r12, r13
andn r13, rdx, r10
add r11, r13
mov r13, rdx
and r13, r9
add r11, r13
add r11, r12
add r8, r11
rorx r12, rax, 28
rorx r13, rax, 34
xor r12, r13
rorx r13, rax, 39
xor r12, r13
mov r13, rax
xor r13, rbx
and r14, r13
xor r14, rbx
add r12, r14
add r11, r12
vmovdqa ymmword ptr [rdi + r15 + 32], ymm15
rorx r12, r8, 14
rorx r14, r8, 18
add r10, qword ptr [rdi + r15 + 8]
xor r12, r14
rorx r14, r8, 41
xor r12, r14
andn r14, r8, r9
add r10, r14
mov r14, r8
and r14, rdx
add r10, r14
add r10, r12
add rcx, r10
rorx r12, r11, 28
rorx r14, r11, 34
xor r12, r14
rorx r14, r11, 39
xor r12, r14
mov r14, r11
xor r14, rax
and r13, r14
xor r13, rax
add r12, r13
add r10, r12
vpaddq ymm15, ymm2, ymmword ptr [rsi + r15 + 64]
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 32]
xor r12, r13
rorx r13, rcx, 41
xor r12, r13
andn r13, rcx, rdx
add r9, r13
mov r13, rcx
and r13, r8
add r9, r13
add r9, r12
add rbx, r9
rorx r12, r10, 28
rorx r13, r10, 34
xor r12, r13
rorx r13, r10, 39
xor r12, r13
mov r13, r10
xor r13, r11
and r14, r13
xor r14, r11
add r12, r14
add r9, r12
vmovdqa ymmword ptr [rdi + r15 + 64], ymm15
rorx r12, rbx, 14
rorx r14, rbx, 18
add rdx, qword ptr [rdi + r15 + 40]
xor r12, r14
rorx r14, rbx, 41
xor r12, r14
andn r14, rbx, r8
add rdx, r14
mov r14, rbx
and r14, rcx
add rdx, r14
add rdx, r12
add rax, rdx
rorx r12, r9, 28
rorx r14, r9, 34
xor r12, r14
rorx r14, r9, 39
xor r12, r14
mov r14, r9
xor r14, r10
and r13, r14
xor r13, r10
add r12, r13
add rdx, r12
vpaddq ymm15, ymm3, ymmword ptr [rsi + r15 + 96]
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 64]
xor r12, r13
rorx r13, rax, 41
xor r12, r13
andn r13, rax, rcx
add r8, r13
mov r13, rax
and r13, rbx
add r8, r13
add r8, r12
add r11, r8
rorx r12, rdx, 28
rorx r13, rdx, 34
xor r12, r13
rorx r13, rdx, 39
xor r12, r13
mov r13, rdx
xor r13, r9
and r14, r13
xor r14, r9
add r12, r14
add r8, r12
vmovdqa ymmword ptr [rdi + r15 + 96], ymm15
rorx r12, r11, 14
rorx r14, r11, 18
add rcx, qword ptr [rdi + r15 + 72]
xor r12, r14
rorx r14, r11, 41
xor r12, r14
andn r14, r11, rbx
add rcx, r14
mov r14, r11
and r14, rax
add rcx, r14
add rcx, r12
add r10, rcx
rorx r12, r8, 28
rorx r14, r8, 34
xor r12, r14
rorx r14, r8, 39
xor r12, r14
mov r14, r8
xor r14, rdx
and r13, r14
xor r13, rdx
add r12, r13
add rcx, r12
vpaddq ymm15, ymm4, ymmword ptr [rsi + r15 + 128]
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 96]
xor r12, r13
rorx r13, r10, 41
xor r12, r13
andn r13, r10, rax
add rbx, r13
mov r13, r10
and r13, r11
add rbx, r13
add rbx, r12
add r9, rbx
rorx r12, rcx, 28
rorx r13, rcx, 34
xor r12, r13
rorx r13, rcx, 39
xor r12, r13
mov r13, rcx
xor r13, r8
and r14, r13
xor r14, r8
add r12, r14
add rbx, r12
vmovdqa ymmword ptr [rdi + r15 + 128], ymm15
rorx r12, r9, 14
rorx r14, r9, 18
add rax, qword ptr [rdi + r15 + 104]
xor r12, r14
rorx r14, r9, 41
xor r12, r14
andn r14, r9, r11
add rax, r14
mov r14, r9
and r14, r10
add rax, r14
add rax, r12
add rdx, rax
rorx r12, rbx, 28
rorx r14, rbx, 34
xor r12, r14
rorx r14, rbx, 39
xor r12, r14
mov r14, rbx
xor r14, rcx
and r13, r14
xor r13, rcx
add r12, r13
add rax, r12
vpaddq ymm15, ymm5, ymmword ptr [rsi + r15 + 160]
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 128]
xor r12, r13
rorx r13, rdx, 41
xor r12, r13
andn r13, rdx, r10
add r11, r13
mov r13, rdx
and r13, r9
add r11, r13
add r11, r12
add r8, r11
rorx r12, rax, 28
rorx r13, rax, 34
xor r12, r13
rorx r13, rax, 39
xor r12, r13
mov r13, rax
xor r13, rbx
and r14, r13
xor r14, rbx
add r12, r14
add r11, r12
vmovdqa ymmword ptr [rdi + r15 + 160], ymm15
rorx r12, r8, 14
rorx r14, r8, 18
add r10, qword ptr [rdi + r15 + 136]
xor r12, r14
rorx r14, r8, 41
xor r12, r14
andn r14, r8, r9
add r10, r14
mov r14, r8
and r14, rdx
add r10, r14
add r10, r12
add rcx, r10
rorx r12, r11, 28
rorx r14, r11, 34
xor r12, r14
rorx r14, r11, 39
xor r12, r14
mov r14, r11
xor r14, rax
and r13, r14
xor r13, rax
add r12, r13
add r10, r12
vpaddq ymm15, ymm6, ymmword ptr [rsi + r15 + 192]
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 160]
xor r12, r13
rorx r13, rcx, 41
xor r12, r13
andn r13, rcx, rdx
add r9, r13
mov r13, rcx
and r13, r8
add r9, r13
add r9, r12
add rbx, r9
rorx r12, r10, 28
rorx r13, r10, 34
xor r12, r13
rorx r13, r10, 39
xor r12, r13
mov r13, r10
xor r13, r11
and r14, r13
xor r14, r11
add r12, r14
add r9, r12
vmovdqa ymmword ptr [rdi + r15 + 192], ymm15
rorx r12, rbx, 14
rorx r14, rbx, 18
add rdx, qword ptr [rdi + r15 + 168]
xor r12, r14
rorx r14, rbx, 41
xor r12, r14
andn r14, rbx, r8
add rdx, r14
mov r14, rbx
and r14, rcx
add rdx, r14
add rdx, r12
add rax, rdx
rorx r12, r9, 28
rorx r14, r9, 34
xor r12, r14
rorx r14, r9, 39
xor r12, r14
mov r14, r9
xor r14, r10
and r13, r14
xor r13, r10
add r12, r13
add rdx, r12
vpaddq ymm15, ymm7, ymmword ptr [rsi + r15 + 224]
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 192]
xor r12, r13
rorx r13, rax, 41
xor r12, r13
andn r13, rax, rcx
add r8, r13
mov r13, rax
and r13, rbx
add r8, r13
add r8, r12
add r11, r8
rorx r12, rdx, 28
rorx r13, rdx, 34
xor r12, r13
rorx r13, rdx, 39
xor r12, r13
mov r13, rdx
xor r13, r9
and r14, r13
xor r14, r9
add r12, r14
add r8, r12
vmovdqa ymmword ptr [rdi + r15 + 224], ymm15
rorx r12, r11, 14
rorx r14, r11, 18
add rcx, qword ptr [rdi + r15 + 200]
xor r12, r14
rorx r14, r11, 41
xor r12, r14
andn r14, r11, rbx
add rcx, r14
mov r14, r11
and r14, rax
add rcx, r14
add rcx, r12
add r10, rcx
rorx r12, r8, 28
rorx r14, r8, 34
xor r12, r14
rorx r14, r8, 39
xor r12, r14
mov r14, r8
xor r14, rdx
and r13, r14
xor r13, rdx
add r12, r13
add rcx, r12
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 224]
xor r12, r13
rorx r13, r10, 41
xor r12, r13
andn r13, r10, rax
add rbx, r13
mov r13, r10
and r13, r11
add rbx, r13
add rbx, r12
add r9, rbx
rorx r12, rcx, 28
rorx r13, rcx, 34
xor r12, r13
rorx r13, rcx, 39
xor r12, r13
mov r13, rcx
xor r13, r8
and r14, r13
xor r14, r8
add r12, r14
add rbx, r12
rorx r12, r9, 14
rorx r14, r9, 18
add rax, qword ptr [rdi + r15 + 232]
xor r12, r14
rorx r14, r9, 41
xor r12, r14
andn r14, r9, r11
add rax, r14
mov r14, r9
and r14, r10
add rax, r14
add rax, r12
add rdx, rax
rorx r12, rbx, 28
rorx r14, rbx, 34
xor r12, r14
rorx r14, rbx, 39
xor r12, r14
mov r14, rbx
xor r14, rcx
and r13, r14
xor r13, rcx
add r12, r13
add rax, r12
mov r12, qword ptr [rdi + 1280]
add rax, qword ptr [r12 + 0]
mov qword ptr [r12 + 0], rax
add rbx, qword ptr [r12 + 8]
mov qword ptr [r12 + 8], rbx
add rcx, qword ptr [r12 + 16]
mov qword ptr [r12 + 16], rcx
add r8, qword ptr [r12 + 24]
mov qword ptr [r12 + 24], r8
add rdx, qword ptr [r12 + 32]
mov qword ptr [r12 + 32], rdx
add r9, qword ptr [r12 + 40]
mov qword ptr [r12 + 40], r9
add r10, qword ptr [r12 + 48]
mov qword ptr [r12 + 48], r10
add r11, qword ptr [r12 + 56]
mov qword ptr [r12 + 56], r11
cmp qword ptr [rdi + 1320], 2
jne 3f
mov r12, qword ptr [rdi + 1288]
mov rax, qword ptr [r12 + 0]
mov rbx, qword ptr [r12 + 8]
mov rcx, qword ptr [r12 + 16]
mov r8, qword ptr [r12 + 24]
mov rdx, qword ptr [r12 + 32]
mov r9, qword ptr [r12 + 40]
mov r10, qword ptr [r12 + 48]
mov r11, qword ptr [r12 + 56]
mov r14, rbx
xor r14, rcx
xor r15d, r15d
2:
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 16]
xor r12, r13
rorx r13, rdx, 41
xor r12, r13
andn r13, rdx, r10
add r11, r13
mov r13, rdx
and r13, r9
add r11, r13
add r11, r12
add r8, r11
rorx r12, rax, 28
rorx r13, rax, 34
xor r12, r13
rorx r13, rax, 39
xor r12, r13
mov r13, rax
xor r13, rbx
and r14, r13
xor r14, rbx
add r12, r14
add r11, r12
rorx r12, r8, 14
rorx r14, r8, 18
add r10, qword ptr [rdi + r15 + 24]
xor r12, r14
rorx r14, r8, 41
xor r12, r14
andn r14, r8, r9
add r10, r14
mov r14, r8
and r14, rdx
add r10, r14
add r10, r12
add rcx, r10
rorx r12, r11, 28
rorx r14, r11, 34
xor r12, r14
rorx r14, r11, 39
xor r12, r14
mov r14, r11
xor r14, rax
and r13, r14
xor r13, rax
add r12, r13
add r10, r12
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 48]
xor r12, r13
rorx r13, rcx, 41
xor r12, r13
andn r13, rcx, rdx
add r9, r13
mov r13, rcx
and r13, r8
add r9, r13
add r9, r12
add rbx, r9
rorx r12, r10, 28
rorx r13, r10, 34
xor r12, r13
rorx r13, r10, 39
xor r12, r13
mov r13, r10
xor r13, r11
and r14, r13
xor r14, r11
add r12, r14
add r9, r12
rorx r12, rbx, 14
rorx r14, rbx, 18
add rdx, qword ptr [rdi + r15 + 56]
xor r12, r14
rorx r14, rbx, 41
xor r12, r14
andn r14, rbx, r8
add rdx, r14
mov r14, rbx
and r14, rcx
add rdx, r14
add rdx, r12
add rax, rdx
rorx r12, r9, 28
rorx r14, r9, 34
xor r12, r14
rorx r14, r9, 39
xor r12, r14
mov r14, r9
xor r14, r10
and r13, r14
xor r13, r10
add r12, r13
add rdx, r12
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 80]
xor r12, r13
rorx r13, rax, 41
xor r12, r13
andn r13, rax, rcx
add r8, r13
mov r13, rax
and r13, rbx
add r8, r13
add r8, r12
add r11, r8
rorx r12, rdx, 28
rorx r13, rdx, 34
xor r12, r13
rorx r13, rdx, 39
xor r12, r13
mov r13, rdx
xor r13, r9
and r14, r13
xor r14, r9
add r12, r14
add r8, r12
rorx r12, r11, 14
rorx r14, r11, 18
add rcx, qword ptr [rdi + r15 + 88]
xor r12, r14
rorx r14, r11, 41
xor r12, r14
andn r14, r11, rbx
add rcx, r14
mov r14, r11
and r14, rax
add rcx, r14
add rcx, r12
add r10, rcx
rorx r12, r8, 28
rorx r14, r8, 34
xor r12, r14
rorx r14, r8, 39
xor r12, r14
mov r14, r8
xor r14, rdx
and r13, r14
xor r13, rdx
add r12, r13
add rcx, r12
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 112]
xor r12, r13
rorx r13, r10, 41
xor r12, r13
andn r13, r10, rax
add rbx, r13
mov r13, r10
and r13, r11
add rbx, r13
add rbx, r12
add r9, rbx
rorx r12, rcx, 28
rorx r13, rcx, 34
xor r12, r13
rorx r13, rcx, 39
xor r12, r13
mov r13, rcx
xor r13, r8
and r14, r13
xor r14, r8
add r12, r14
add rbx, r12
rorx r12, r9, 14
rorx r14, r9, 18
add rax, qword ptr [rdi + r15 + 120]
xor r12, r14
rorx r14, r9, 41
xor r12, r14
andn r14, r9, r11
add rax, r14
mov r14, r9
and r14, r10
add rax, r14
add rax, r12
add rdx, rax
rorx r12, rbx, 28
rorx r14, rbx, 34
xor r12, r14
rorx r14, rbx, 39
xor r12, r14
mov r14, rbx
xor r14, rcx
and r13, r14
xor r13, rcx
add r12, r13
add rax, r12
rorx r12, rdx, 14
rorx r13, rdx, 18
add r11, qword ptr [rdi + r15 + 144]
xor r12, r13
rorx r13, rdx, 41
xor r12, r13
andn r13, rdx, r10
add r11, r13
mov r13, rdx
and r13, r9
add r11, r13
add r11, r12
add r8, r11
rorx r12, rax, 28
rorx r13, rax, 34
xor r12, r13
rorx r13, rax, 39
xor r12, r13
mov r13, rax
xor r13, rbx
and r14, r13
xor r14, rbx
add r12, r14
add r11, r12
rorx r12, r8, 14
rorx r14, r8, 18
add r10, qword ptr [rdi + r15 + 152]
xor r12, r14
rorx r14, r8, 41
xor r12, r14
andn r14, r8, r9
add r10, r14
mov r14, r8
and r14, rdx
add r10, r14
add r10, r12
add rcx, r10
rorx r12, r11, 28
rorx r14, r11, 34
xor r12, r14
rorx r14, r11, 39
xor r12, r14
mov r14, r11
xor r14, rax
and r13, r14
xor r13, rax
add r12, r13
add r10, r12
rorx r12, rcx, 14
rorx r13, rcx, 18
add r9, qword ptr [rdi + r15 + 176]
xor r12, r13
rorx r13, rcx, 41
xor r12, r13
andn r13, rcx, rdx
add r9, r13
mov r13, rcx
and r13, r8
add r9, r13
add r9, r12
add rbx, r9
rorx r12, r10, 28
rorx r13, r10, 34
xor r12, r13
rorx r13, r10, 39
xor r12, r13
mov r13, r10
xor r13, r11
and r14, r13
xor r14, r11
add r12, r14
add r9, r12
rorx r12, rbx, 14
rorx r14, rbx, 18
add rdx, qword ptr [rdi + r15 + 184]
xor r12, r14
rorx r14, rbx, 41
xor r12, r14
andn r14, rbx, r8
add rdx, r14
mov r14, rbx
and r14, rcx
add rdx, r14
add rdx, r12
add rax, rdx
rorx r12, r9, 28
rorx r14, r9, 34
xor r12, r14
rorx r14, r9, 39
xor r12, r14
mov r14, r9
xor r14, r10
and r13, r14
xor r13, r10
add r12, r13
add rdx, r12
rorx r12, rax, 14
rorx r13, rax, 18
add r8, qword ptr [rdi + r15 + 208]
xor r12, r13
rorx r13, rax, 41
xor r12, r13
andn r13, rax, rcx
add r8, r13
mov r13, rax
and r13, rbx
add r8, r13
add r8, r12
add r11, r8
rorx r12, rdx, 28
rorx r13, rdx, 34
xor r12, r13
rorx r13, rdx, 39
xor r12, r13
mov r13, rdx
xor r13, r9
and r14, r13
xor r14, r9
add r12, r14
add r8, r12
rorx r12, r11, 14
rorx r14, r11, 18
add rcx, qword ptr [rdi + r15 + 216]
xor r12, r14
rorx r14, r11, 41
xor r12, r14
andn r14, r11, rbx
add rcx, r14
mov r14, r11
and r14, rax
add rcx, r14
add rcx, r12
add r10, rcx
rorx r12, r8, 28
rorx r14, r8, 34
xor r12, r14
rorx r14, r8, 39
xor r12, r14
mov r14, r8
xor r14, rdx
and r13, r14
xor r13, rdx
add r12, r13
add rcx, r12
rorx r12, r10, 14
rorx r13, r10, 18
add rbx, qword ptr [rdi + r15 + 240]
xor r12, r13
rorx r13, r10, 41
xor r12, r13
andn r13, r10, rax
add rbx, r13
mov r13, r10
and r13, r11
add rbx, r13
add rbx, r12
add r9, rbx
rorx r12, rcx, 28
rorx r13, rcx, 34
xor r12, r13
rorx r13, rcx, 39
xor r12, r13
mov r13, rcx
xor r13, r8
and r14, r13
xor r14, r8
add r12, r14
add rbx, r12
rorx r12, r9, 14
rorx r14, r9, 18
add rax, qword ptr [rdi + r15 + 248]
xor r12, r14
rorx r14, r9, 41
xor r12, r14
andn r14, r9, r11
add rax, r14
mov r14, r9
and r14, r10
add rax, r14
add rax, r12
add rdx, rax
rorx r12, rbx, 28
rorx r14, rbx, 34
xor r12, r14
rorx r14, rbx, 39
xor r12, r14
mov r14, rbx
xor r14, rcx
and r13, r14
xor r13, rcx
add r12, r13
add rax, r12
add r15, 256
cmp r15, 1280
jb 2b
mov r12, qword ptr [rdi + 1288]
add rax, qword ptr [r12 + 0]
mov qword ptr [r12 + 0], rax
add rbx, qword ptr [r12 + 8]
mov qword ptr [r12 + 8], rbx
add rcx, qword ptr [r12 + 16]
mov qword ptr [r12 + 16], rcx
add r8, qword ptr [r12 + 24]
mov qword ptr [r12 + 24], r8
add rdx, qword ptr [r12 + 32]
mov qword ptr [r12 + 32], rdx
add r9, qword ptr [r12 + 40]
mov qword ptr [r12 + 40], r9
add r10, qword ptr [r12 + 48]
mov qword ptr [r12 + 48], r10
add r11, qword ptr [r12 + 56]
mov qword ptr [r12 + 56], r11
3:
cmp qword ptr [rdi + 1328], 0
je 4f
vpxor xmm0, xmm0, xmm0
vmovdqa ymmword ptr [rdi + 0], ymm0
vmovdqa ymmword ptr [rdi + 32], ymm0
vmovdqa ymmword ptr [rdi + 64], ymm0
vmovdqa ymmword ptr [rdi + 96], ymm0
vmovdqa ymmword ptr [rdi + 128], ymm0
vmovdqa ymmword ptr [rdi + 160], ymm0
vmovdqa ymmword ptr [rdi + 192], ymm0
vmovdqa ymmword ptr [rdi + 224], ymm0
vmovdqa ymmword ptr [rdi + 256], ymm0
vmovdqa ymmword ptr [rdi + 288], ymm0
vmovdqa ymmword ptr [rdi + 320], ymm0
vmovdqa ymmword ptr [rdi + 352], ymm0
vmovdqa ymmword ptr [rdi + 384], ymm0
vmovdqa ymmword ptr [rdi + 416], ymm0
vmovdqa ymmword ptr [rdi + 448], ymm0
vmovdqa ymmword ptr [rdi + 480], ymm0
vmovdqa ymmword ptr [rdi + 512], ymm0
vmovdqa ymmword ptr [rdi + 544], ymm0
vmovdqa ymmword ptr [rdi + 576], ymm0
vmovdqa ymmword ptr [rdi + 608], ymm0
vmovdqa ymmword ptr [rdi + 640], ymm0
vmovdqa ymmword ptr [rdi + 672], ymm0
vmovdqa ymmword ptr [rdi + 704], ymm0
vmovdqa ymmword ptr [rdi + 736], ymm0
vmovdqa ymmword ptr [rdi + 768], ymm0
vmovdqa ymmword ptr [rdi + 800], ymm0
vmovdqa ymmword ptr [rdi + 832], ymm0
vmovdqa ymmword ptr [rdi + 864], ymm0
vmovdqa ymmword ptr [rdi + 896], ymm0
vmovdqa ymmword ptr [rdi + 928], ymm0
vmovdqa ymmword ptr [rdi + 960], ymm0
vmovdqa ymmword ptr [rdi + 992], ymm0
vmovdqa ymmword ptr [rdi + 1024], ymm0
vmovdqa ymmword ptr [rdi + 1056], ymm0
vmovdqa ymmword ptr [rdi + 1088], ymm0
vmovdqa ymmword ptr [rdi + 1120], ymm0
vmovdqa ymmword ptr [rdi + 1152], ymm0
vmovdqa ymmword ptr [rdi + 1184], ymm0
vmovdqa ymmword ptr [rdi + 1216], ymm0
vmovdqa ymmword ptr [rdi + 1248], ymm0
4:
vzeroupper
.att_syntax prefix
