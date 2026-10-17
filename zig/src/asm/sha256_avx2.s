.intel_syntax noprefix
mov rsi, qword ptr [rdi + 544]
mov rdx, qword ptr [rdi + 528]
mov rcx, qword ptr [rdi + 536]
vmovdqa ymm15, ymmword ptr [rsi + 512]
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
vpaddd ymm15, ymm0, ymmword ptr [rsi]
vmovdqa ymmword ptr [rdi], ymm15
mov r12, qword ptr [rdi + 512]
mov eax, dword ptr [r12 + 0]
mov ebx, dword ptr [r12 + 4]
mov ecx, dword ptr [r12 + 8]
mov r8d, dword ptr [r12 + 12]
mov edx, dword ptr [r12 + 16]
mov r9d, dword ptr [r12 + 20]
mov r10d, dword ptr [r12 + 24]
mov r11d, dword ptr [r12 + 28]
mov r14d, ebx
xor r14d, ecx
xor r15d, r15d
1:
vpaddd ymm15, ymm1, ymmword ptr [rsi + r15 + 32]
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 0]
xor r12d, r13d
vmovdqa ymmword ptr [rdi + r15 + 32], ymm15
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
vpalignr ymm4, ymm1, ymm0, 4
add r11d, r13d
mov r13d, edx
and r13d, r9d
vpalignr ymm5, ymm3, ymm2, 4
add r11d, r13d
add r11d, r12d
add r8d, r11d
vpsrld ymm6, ymm4, 7
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
vpslld ymm7, ymm4, 25
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
vpxor ymm6, ymm6, ymm7
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
vpsrld ymm7, ymm4, 18
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
vpxor ymm6, ymm6, ymm7
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 4]
xor r12d, r14d
vpslld ymm7, ymm4, 14
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
vpxor ymm6, ymm6, ymm7
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
vpsrld ymm7, ymm4, 3
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
vpxor ymm6, ymm6, ymm7
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
vpaddd ymm5, ymm5, ymm0
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
vpaddd ymm5, ymm5, ymm6
and r13d, r14d
xor r13d, eax
add r12d, r13d
vpshufd ymm6, ymm3, 0xfa
add r10d, r12d
rorx r12d, ecx, 6
rorx r13d, ecx, 11
vpsrld ymm7, ymm6, 10
add r9d, dword ptr [rdi + r15 + 8]
xor r12d, r13d
rorx r13d, ecx, 25
vpsrlq ymm8, ymm6, 17
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
vpxor ymm7, ymm7, ymm8
mov r13d, ecx
and r13d, r8d
add r9d, r13d
vpsrlq ymm8, ymm6, 19
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
vpxor ymm7, ymm7, ymm8
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 544]
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
vpaddd ymm5, ymm5, ymm7
xor r14d, r11d
add r12d, r14d
add r9d, r12d
vpshufd ymm6, ymm5, 0x50
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 12]
vpsrld ymm7, ymm6, 10
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
vpsrlq ymm8, ymm6, 17
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
vpxor ymm7, ymm7, ymm8
and r14d, ecx
add edx, r14d
add edx, r12d
vpsrlq ymm8, ymm6, 19
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
vpxor ymm7, ymm7, ymm8
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 576]
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
vpaddd ymm0, ymm5, ymm7
xor r13d, r10d
add r12d, r13d
add edx, r12d
vpaddd ymm15, ymm2, ymmword ptr [rsi + r15 + 64]
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 32]
xor r12d, r13d
vmovdqa ymmword ptr [rdi + r15 + 64], ymm15
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
vpalignr ymm4, ymm2, ymm1, 4
add r8d, r13d
mov r13d, eax
and r13d, ebx
vpalignr ymm5, ymm0, ymm3, 4
add r8d, r13d
add r8d, r12d
add r11d, r8d
vpsrld ymm6, ymm4, 7
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
vpslld ymm7, ymm4, 25
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
vpxor ymm6, ymm6, ymm7
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
vpsrld ymm7, ymm4, 18
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
vpxor ymm6, ymm6, ymm7
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 36]
xor r12d, r14d
vpslld ymm7, ymm4, 14
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
vpxor ymm6, ymm6, ymm7
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
vpsrld ymm7, ymm4, 3
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
vpxor ymm6, ymm6, ymm7
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
vpaddd ymm5, ymm5, ymm1
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
vpaddd ymm5, ymm5, ymm6
and r13d, r14d
xor r13d, edx
add r12d, r13d
vpshufd ymm6, ymm0, 0xfa
add ecx, r12d
rorx r12d, r10d, 6
rorx r13d, r10d, 11
vpsrld ymm7, ymm6, 10
add ebx, dword ptr [rdi + r15 + 40]
xor r12d, r13d
rorx r13d, r10d, 25
vpsrlq ymm8, ymm6, 17
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
vpxor ymm7, ymm7, ymm8
mov r13d, r10d
and r13d, r11d
add ebx, r13d
vpsrlq ymm8, ymm6, 19
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
vpxor ymm7, ymm7, ymm8
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 544]
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
vpaddd ymm5, ymm5, ymm7
xor r14d, r8d
add r12d, r14d
add ebx, r12d
vpshufd ymm6, ymm5, 0x50
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 44]
vpsrld ymm7, ymm6, 10
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
vpsrlq ymm8, ymm6, 17
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
vpxor ymm7, ymm7, ymm8
and r14d, r10d
add eax, r14d
add eax, r12d
vpsrlq ymm8, ymm6, 19
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
vpxor ymm7, ymm7, ymm8
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 576]
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
vpaddd ymm1, ymm5, ymm7
xor r13d, ecx
add r12d, r13d
add eax, r12d
vpaddd ymm15, ymm3, ymmword ptr [rsi + r15 + 96]
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 64]
xor r12d, r13d
vmovdqa ymmword ptr [rdi + r15 + 96], ymm15
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
vpalignr ymm4, ymm3, ymm2, 4
add r11d, r13d
mov r13d, edx
and r13d, r9d
vpalignr ymm5, ymm1, ymm0, 4
add r11d, r13d
add r11d, r12d
add r8d, r11d
vpsrld ymm6, ymm4, 7
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
vpslld ymm7, ymm4, 25
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
vpxor ymm6, ymm6, ymm7
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
vpsrld ymm7, ymm4, 18
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
vpxor ymm6, ymm6, ymm7
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 68]
xor r12d, r14d
vpslld ymm7, ymm4, 14
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
vpxor ymm6, ymm6, ymm7
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
vpsrld ymm7, ymm4, 3
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
vpxor ymm6, ymm6, ymm7
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
vpaddd ymm5, ymm5, ymm2
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
vpaddd ymm5, ymm5, ymm6
and r13d, r14d
xor r13d, eax
add r12d, r13d
vpshufd ymm6, ymm1, 0xfa
add r10d, r12d
rorx r12d, ecx, 6
rorx r13d, ecx, 11
vpsrld ymm7, ymm6, 10
add r9d, dword ptr [rdi + r15 + 72]
xor r12d, r13d
rorx r13d, ecx, 25
vpsrlq ymm8, ymm6, 17
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
vpxor ymm7, ymm7, ymm8
mov r13d, ecx
and r13d, r8d
add r9d, r13d
vpsrlq ymm8, ymm6, 19
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
vpxor ymm7, ymm7, ymm8
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 544]
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
vpaddd ymm5, ymm5, ymm7
xor r14d, r11d
add r12d, r14d
add r9d, r12d
vpshufd ymm6, ymm5, 0x50
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 76]
vpsrld ymm7, ymm6, 10
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
vpsrlq ymm8, ymm6, 17
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
vpxor ymm7, ymm7, ymm8
and r14d, ecx
add edx, r14d
add edx, r12d
vpsrlq ymm8, ymm6, 19
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
vpxor ymm7, ymm7, ymm8
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 576]
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
vpaddd ymm2, ymm5, ymm7
xor r13d, r10d
add r12d, r13d
add edx, r12d
vpaddd ymm15, ymm0, ymmword ptr [rsi + r15 + 128]
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 96]
xor r12d, r13d
vmovdqa ymmword ptr [rdi + r15 + 128], ymm15
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
vpalignr ymm4, ymm0, ymm3, 4
add r8d, r13d
mov r13d, eax
and r13d, ebx
vpalignr ymm5, ymm2, ymm1, 4
add r8d, r13d
add r8d, r12d
add r11d, r8d
vpsrld ymm6, ymm4, 7
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
vpslld ymm7, ymm4, 25
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
vpxor ymm6, ymm6, ymm7
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
vpsrld ymm7, ymm4, 18
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
vpxor ymm6, ymm6, ymm7
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 100]
xor r12d, r14d
vpslld ymm7, ymm4, 14
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
vpxor ymm6, ymm6, ymm7
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
vpsrld ymm7, ymm4, 3
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
vpxor ymm6, ymm6, ymm7
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
vpaddd ymm5, ymm5, ymm3
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
vpaddd ymm5, ymm5, ymm6
and r13d, r14d
xor r13d, edx
add r12d, r13d
vpshufd ymm6, ymm2, 0xfa
add ecx, r12d
rorx r12d, r10d, 6
rorx r13d, r10d, 11
vpsrld ymm7, ymm6, 10
add ebx, dword ptr [rdi + r15 + 104]
xor r12d, r13d
rorx r13d, r10d, 25
vpsrlq ymm8, ymm6, 17
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
vpxor ymm7, ymm7, ymm8
mov r13d, r10d
and r13d, r11d
add ebx, r13d
vpsrlq ymm8, ymm6, 19
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
vpxor ymm7, ymm7, ymm8
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 544]
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
vpaddd ymm5, ymm5, ymm7
xor r14d, r8d
add r12d, r14d
add ebx, r12d
vpshufd ymm6, ymm5, 0x50
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 108]
vpsrld ymm7, ymm6, 10
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
vpsrlq ymm8, ymm6, 17
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
vpxor ymm7, ymm7, ymm8
and r14d, r10d
add eax, r14d
add eax, r12d
vpsrlq ymm8, ymm6, 19
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
vpxor ymm7, ymm7, ymm8
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
vpshufb ymm7, ymm7, ymmword ptr [rsi + 576]
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
vpaddd ymm3, ymm5, ymm7
xor r13d, ecx
add r12d, r13d
add eax, r12d
add r15, 128
cmp r15, 384
jb 1b
vpaddd ymm15, ymm1, ymmword ptr [rsi + r15 + 32]
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 0]
xor r12d, r13d
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
add r11d, r13d
mov r13d, edx
and r13d, r9d
add r11d, r13d
add r11d, r12d
add r8d, r11d
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 4]
xor r12d, r14d
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
and r13d, r14d
xor r13d, eax
add r12d, r13d
add r10d, r12d
vmovdqa ymmword ptr [rdi + r15 + 32], ymm15
rorx r12d, ecx, 6
rorx r13d, ecx, 11
add r9d, dword ptr [rdi + r15 + 8]
xor r12d, r13d
rorx r13d, ecx, 25
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
mov r13d, ecx
and r13d, r8d
add r9d, r13d
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
xor r14d, r11d
add r12d, r14d
add r9d, r12d
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 12]
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
and r14d, ecx
add edx, r14d
add edx, r12d
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
xor r13d, r10d
add r12d, r13d
add edx, r12d
vpaddd ymm15, ymm2, ymmword ptr [rsi + r15 + 64]
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 32]
xor r12d, r13d
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
add r8d, r13d
mov r13d, eax
and r13d, ebx
add r8d, r13d
add r8d, r12d
add r11d, r8d
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 36]
xor r12d, r14d
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
and r13d, r14d
xor r13d, edx
add r12d, r13d
add ecx, r12d
vmovdqa ymmword ptr [rdi + r15 + 64], ymm15
rorx r12d, r10d, 6
rorx r13d, r10d, 11
add ebx, dword ptr [rdi + r15 + 40]
xor r12d, r13d
rorx r13d, r10d, 25
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
mov r13d, r10d
and r13d, r11d
add ebx, r13d
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
xor r14d, r8d
add r12d, r14d
add ebx, r12d
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 44]
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
and r14d, r10d
add eax, r14d
add eax, r12d
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
xor r13d, ecx
add r12d, r13d
add eax, r12d
vpaddd ymm15, ymm3, ymmword ptr [rsi + r15 + 96]
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 64]
xor r12d, r13d
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
add r11d, r13d
mov r13d, edx
and r13d, r9d
add r11d, r13d
add r11d, r12d
add r8d, r11d
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 68]
xor r12d, r14d
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
and r13d, r14d
xor r13d, eax
add r12d, r13d
add r10d, r12d
vmovdqa ymmword ptr [rdi + r15 + 96], ymm15
rorx r12d, ecx, 6
rorx r13d, ecx, 11
add r9d, dword ptr [rdi + r15 + 72]
xor r12d, r13d
rorx r13d, ecx, 25
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
mov r13d, ecx
and r13d, r8d
add r9d, r13d
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
xor r14d, r11d
add r12d, r14d
add r9d, r12d
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 76]
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
and r14d, ecx
add edx, r14d
add edx, r12d
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
xor r13d, r10d
add r12d, r13d
add edx, r12d
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 96]
xor r12d, r13d
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
add r8d, r13d
mov r13d, eax
and r13d, ebx
add r8d, r13d
add r8d, r12d
add r11d, r8d
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 100]
xor r12d, r14d
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
and r13d, r14d
xor r13d, edx
add r12d, r13d
add ecx, r12d
rorx r12d, r10d, 6
rorx r13d, r10d, 11
add ebx, dword ptr [rdi + r15 + 104]
xor r12d, r13d
rorx r13d, r10d, 25
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
mov r13d, r10d
and r13d, r11d
add ebx, r13d
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
xor r14d, r8d
add r12d, r14d
add ebx, r12d
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 108]
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
and r14d, r10d
add eax, r14d
add eax, r12d
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
xor r13d, ecx
add r12d, r13d
add eax, r12d
mov r12, qword ptr [rdi + 512]
add eax, dword ptr [r12 + 0]
mov dword ptr [r12 + 0], eax
add ebx, dword ptr [r12 + 4]
mov dword ptr [r12 + 4], ebx
add ecx, dword ptr [r12 + 8]
mov dword ptr [r12 + 8], ecx
add r8d, dword ptr [r12 + 12]
mov dword ptr [r12 + 12], r8d
add edx, dword ptr [r12 + 16]
mov dword ptr [r12 + 16], edx
add r9d, dword ptr [r12 + 20]
mov dword ptr [r12 + 20], r9d
add r10d, dword ptr [r12 + 24]
mov dword ptr [r12 + 24], r10d
add r11d, dword ptr [r12 + 28]
mov dword ptr [r12 + 28], r11d
cmp qword ptr [rdi + 552], 2
jne 3f
mov r12, qword ptr [rdi + 520]
mov eax, dword ptr [r12 + 0]
mov ebx, dword ptr [r12 + 4]
mov ecx, dword ptr [r12 + 8]
mov r8d, dword ptr [r12 + 12]
mov edx, dword ptr [r12 + 16]
mov r9d, dword ptr [r12 + 20]
mov r10d, dword ptr [r12 + 24]
mov r11d, dword ptr [r12 + 28]
mov r14d, ebx
xor r14d, ecx
xor r15d, r15d
2:
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 16]
xor r12d, r13d
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
add r11d, r13d
mov r13d, edx
and r13d, r9d
add r11d, r13d
add r11d, r12d
add r8d, r11d
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 20]
xor r12d, r14d
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
and r13d, r14d
xor r13d, eax
add r12d, r13d
add r10d, r12d
rorx r12d, ecx, 6
rorx r13d, ecx, 11
add r9d, dword ptr [rdi + r15 + 24]
xor r12d, r13d
rorx r13d, ecx, 25
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
mov r13d, ecx
and r13d, r8d
add r9d, r13d
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
xor r14d, r11d
add r12d, r14d
add r9d, r12d
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 28]
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
and r14d, ecx
add edx, r14d
add edx, r12d
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
xor r13d, r10d
add r12d, r13d
add edx, r12d
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 48]
xor r12d, r13d
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
add r8d, r13d
mov r13d, eax
and r13d, ebx
add r8d, r13d
add r8d, r12d
add r11d, r8d
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 52]
xor r12d, r14d
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
and r13d, r14d
xor r13d, edx
add r12d, r13d
add ecx, r12d
rorx r12d, r10d, 6
rorx r13d, r10d, 11
add ebx, dword ptr [rdi + r15 + 56]
xor r12d, r13d
rorx r13d, r10d, 25
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
mov r13d, r10d
and r13d, r11d
add ebx, r13d
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
xor r14d, r8d
add r12d, r14d
add ebx, r12d
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 60]
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
and r14d, r10d
add eax, r14d
add eax, r12d
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
xor r13d, ecx
add r12d, r13d
add eax, r12d
rorx r12d, edx, 6
rorx r13d, edx, 11
add r11d, dword ptr [rdi + r15 + 80]
xor r12d, r13d
rorx r13d, edx, 25
xor r12d, r13d
andn r13d, edx, r10d
add r11d, r13d
mov r13d, edx
and r13d, r9d
add r11d, r13d
add r11d, r12d
add r8d, r11d
rorx r12d, eax, 2
rorx r13d, eax, 13
xor r12d, r13d
rorx r13d, eax, 22
xor r12d, r13d
mov r13d, eax
xor r13d, ebx
and r14d, r13d
xor r14d, ebx
add r12d, r14d
add r11d, r12d
rorx r12d, r8d, 6
rorx r14d, r8d, 11
add r10d, dword ptr [rdi + r15 + 84]
xor r12d, r14d
rorx r14d, r8d, 25
xor r12d, r14d
andn r14d, r8d, r9d
add r10d, r14d
mov r14d, r8d
and r14d, edx
add r10d, r14d
add r10d, r12d
add ecx, r10d
rorx r12d, r11d, 2
rorx r14d, r11d, 13
xor r12d, r14d
rorx r14d, r11d, 22
xor r12d, r14d
mov r14d, r11d
xor r14d, eax
and r13d, r14d
xor r13d, eax
add r12d, r13d
add r10d, r12d
rorx r12d, ecx, 6
rorx r13d, ecx, 11
add r9d, dword ptr [rdi + r15 + 88]
xor r12d, r13d
rorx r13d, ecx, 25
xor r12d, r13d
andn r13d, ecx, edx
add r9d, r13d
mov r13d, ecx
and r13d, r8d
add r9d, r13d
add r9d, r12d
add ebx, r9d
rorx r12d, r10d, 2
rorx r13d, r10d, 13
xor r12d, r13d
rorx r13d, r10d, 22
xor r12d, r13d
mov r13d, r10d
xor r13d, r11d
and r14d, r13d
xor r14d, r11d
add r12d, r14d
add r9d, r12d
rorx r12d, ebx, 6
rorx r14d, ebx, 11
add edx, dword ptr [rdi + r15 + 92]
xor r12d, r14d
rorx r14d, ebx, 25
xor r12d, r14d
andn r14d, ebx, r8d
add edx, r14d
mov r14d, ebx
and r14d, ecx
add edx, r14d
add edx, r12d
add eax, edx
rorx r12d, r9d, 2
rorx r14d, r9d, 13
xor r12d, r14d
rorx r14d, r9d, 22
xor r12d, r14d
mov r14d, r9d
xor r14d, r10d
and r13d, r14d
xor r13d, r10d
add r12d, r13d
add edx, r12d
rorx r12d, eax, 6
rorx r13d, eax, 11
add r8d, dword ptr [rdi + r15 + 112]
xor r12d, r13d
rorx r13d, eax, 25
xor r12d, r13d
andn r13d, eax, ecx
add r8d, r13d
mov r13d, eax
and r13d, ebx
add r8d, r13d
add r8d, r12d
add r11d, r8d
rorx r12d, edx, 2
rorx r13d, edx, 13
xor r12d, r13d
rorx r13d, edx, 22
xor r12d, r13d
mov r13d, edx
xor r13d, r9d
and r14d, r13d
xor r14d, r9d
add r12d, r14d
add r8d, r12d
rorx r12d, r11d, 6
rorx r14d, r11d, 11
add ecx, dword ptr [rdi + r15 + 116]
xor r12d, r14d
rorx r14d, r11d, 25
xor r12d, r14d
andn r14d, r11d, ebx
add ecx, r14d
mov r14d, r11d
and r14d, eax
add ecx, r14d
add ecx, r12d
add r10d, ecx
rorx r12d, r8d, 2
rorx r14d, r8d, 13
xor r12d, r14d
rorx r14d, r8d, 22
xor r12d, r14d
mov r14d, r8d
xor r14d, edx
and r13d, r14d
xor r13d, edx
add r12d, r13d
add ecx, r12d
rorx r12d, r10d, 6
rorx r13d, r10d, 11
add ebx, dword ptr [rdi + r15 + 120]
xor r12d, r13d
rorx r13d, r10d, 25
xor r12d, r13d
andn r13d, r10d, eax
add ebx, r13d
mov r13d, r10d
and r13d, r11d
add ebx, r13d
add ebx, r12d
add r9d, ebx
rorx r12d, ecx, 2
rorx r13d, ecx, 13
xor r12d, r13d
rorx r13d, ecx, 22
xor r12d, r13d
mov r13d, ecx
xor r13d, r8d
and r14d, r13d
xor r14d, r8d
add r12d, r14d
add ebx, r12d
rorx r12d, r9d, 6
rorx r14d, r9d, 11
add eax, dword ptr [rdi + r15 + 124]
xor r12d, r14d
rorx r14d, r9d, 25
xor r12d, r14d
andn r14d, r9d, r11d
add eax, r14d
mov r14d, r9d
and r14d, r10d
add eax, r14d
add eax, r12d
add edx, eax
rorx r12d, ebx, 2
rorx r14d, ebx, 13
xor r12d, r14d
rorx r14d, ebx, 22
xor r12d, r14d
mov r14d, ebx
xor r14d, ecx
and r13d, r14d
xor r13d, ecx
add r12d, r13d
add eax, r12d
add r15, 128
cmp r15, 512
jb 2b
mov r12, qword ptr [rdi + 520]
add eax, dword ptr [r12 + 0]
mov dword ptr [r12 + 0], eax
add ebx, dword ptr [r12 + 4]
mov dword ptr [r12 + 4], ebx
add ecx, dword ptr [r12 + 8]
mov dword ptr [r12 + 8], ecx
add r8d, dword ptr [r12 + 12]
mov dword ptr [r12 + 12], r8d
add edx, dword ptr [r12 + 16]
mov dword ptr [r12 + 16], edx
add r9d, dword ptr [r12 + 20]
mov dword ptr [r12 + 20], r9d
add r10d, dword ptr [r12 + 24]
mov dword ptr [r12 + 24], r10d
add r11d, dword ptr [r12 + 28]
mov dword ptr [r12 + 28], r11d
3:
cmp qword ptr [rdi + 560], 0
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
4:
vzeroupper
.att_syntax prefix
