.intel_syntax noprefix
3:
mov rax, qword ptr [rsi + 216]
mov rcx, qword ptr [rsi + 232]
mov rbx, qword ptr [rax + 0]
xor qword ptr [rdi + 0], rbx
mov rbx, qword ptr [rax + 8]
xor qword ptr [rdi + 8], rbx
mov rbx, qword ptr [rax + 16]
xor qword ptr [rdi + 16], rbx
mov rbx, qword ptr [rax + 24]
xor qword ptr [rdi + 24], rbx
mov rbx, qword ptr [rax + 32]
xor qword ptr [rdi + 32], rbx
mov rbx, qword ptr [rax + 40]
xor qword ptr [rdi + 40], rbx
mov rbx, qword ptr [rax + 48]
xor qword ptr [rdi + 48], rbx
mov rbx, qword ptr [rax + 56]
xor qword ptr [rdi + 56], rbx
mov rbx, qword ptr [rax + 64]
xor qword ptr [rdi + 64], rbx
cmp rcx, 9
je 4f
mov rbx, qword ptr [rax + 72]
xor qword ptr [rdi + 72], rbx
mov rbx, qword ptr [rax + 80]
xor qword ptr [rdi + 80], rbx
mov rbx, qword ptr [rax + 88]
xor qword ptr [rdi + 88], rbx
mov rbx, qword ptr [rax + 96]
xor qword ptr [rdi + 96], rbx
cmp rcx, 13
je 4f
mov rbx, qword ptr [rax + 104]
xor qword ptr [rdi + 104], rbx
mov rbx, qword ptr [rax + 112]
xor qword ptr [rdi + 112], rbx
mov rbx, qword ptr [rax + 120]
xor qword ptr [rdi + 120], rbx
mov rbx, qword ptr [rax + 128]
xor qword ptr [rdi + 128], rbx
cmp rcx, 17
je 4f
mov rbx, qword ptr [rax + 136]
xor qword ptr [rdi + 136], rbx
cmp rcx, 18
je 4f
mov rbx, qword ptr [rax + 144]
xor qword ptr [rdi + 144], rbx
mov rbx, qword ptr [rax + 152]
xor qword ptr [rdi + 152], rbx
mov rbx, qword ptr [rax + 160]
xor qword ptr [rdi + 160], rbx
4:
lea rax, [rax + 8 * rcx]
mov qword ptr [rsi + 216], rax
mov rdx, qword ptr [rsi + 200]
1:
mov rax, qword ptr [rdi + 0]
xor rax, qword ptr [rdi + 40]
xor rax, qword ptr [rdi + 80]
xor rax, qword ptr [rdi + 120]
xor rax, qword ptr [rdi + 160]
mov rbx, qword ptr [rdi + 8]
xor rbx, qword ptr [rdi + 48]
xor rbx, qword ptr [rdi + 88]
xor rbx, qword ptr [rdi + 128]
xor rbx, qword ptr [rdi + 168]
mov rcx, qword ptr [rdi + 16]
xor rcx, qword ptr [rdi + 56]
xor rcx, qword ptr [rdi + 96]
xor rcx, qword ptr [rdi + 136]
xor rcx, qword ptr [rdi + 176]
mov r8, qword ptr [rdi + 24]
xor r8, qword ptr [rdi + 64]
xor r8, qword ptr [rdi + 104]
xor r8, qword ptr [rdi + 144]
xor r8, qword ptr [rdi + 184]
mov r9, qword ptr [rdi + 32]
xor r9, qword ptr [rdi + 72]
xor r9, qword ptr [rdi + 112]
xor r9, qword ptr [rdi + 152]
xor r9, qword ptr [rdi + 192]
rorx r10, rbx, 63
xor r10, r9
rorx r11, rcx, 63
xor r11, rax
rorx r12, r8, 63
xor r12, rbx
rorx r13, r9, 63
xor r13, rcx
rorx r14, rax, 63
xor r14, r8
mov rax, qword ptr [rdi + 0]
xor rax, r10
mov rbx, qword ptr [rdi + 48]
xor rbx, r11
rorx rbx, rbx, 20
mov rcx, qword ptr [rdi + 96]
xor rcx, r12
rorx rcx, rcx, 21
mov r8, qword ptr [rdi + 144]
xor r8, r13
rorx r8, r8, 43
mov r9, qword ptr [rdi + 192]
xor r9, r14
rorx r9, r9, 50
andn r15, rbx, rcx
xor r15, rax
xor r15, qword ptr [rdx + 0]
mov qword ptr [rsi + 0], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rsi + 8], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rsi + 16], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rsi + 24], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rsi + 32], r15
mov rax, qword ptr [rdi + 24]
xor rax, r13
rorx rax, rax, 36
mov rbx, qword ptr [rdi + 72]
xor rbx, r14
rorx rbx, rbx, 44
mov rcx, qword ptr [rdi + 80]
xor rcx, r10
rorx rcx, rcx, 61
mov r8, qword ptr [rdi + 128]
xor r8, r11
rorx r8, r8, 19
mov r9, qword ptr [rdi + 176]
xor r9, r12
rorx r9, r9, 3
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rsi + 40], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rsi + 48], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rsi + 56], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rsi + 64], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rsi + 72], r15
mov rax, qword ptr [rdi + 8]
xor rax, r11
rorx rax, rax, 63
mov rbx, qword ptr [rdi + 56]
xor rbx, r12
rorx rbx, rbx, 58
mov rcx, qword ptr [rdi + 104]
xor rcx, r13
rorx rcx, rcx, 39
mov r8, qword ptr [rdi + 152]
xor r8, r14
rorx r8, r8, 56
mov r9, qword ptr [rdi + 160]
xor r9, r10
rorx r9, r9, 46
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rsi + 80], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rsi + 88], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rsi + 96], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rsi + 104], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rsi + 112], r15
mov rax, qword ptr [rdi + 32]
xor rax, r14
rorx rax, rax, 37
mov rbx, qword ptr [rdi + 40]
xor rbx, r10
rorx rbx, rbx, 28
mov rcx, qword ptr [rdi + 88]
xor rcx, r11
rorx rcx, rcx, 54
mov r8, qword ptr [rdi + 136]
xor r8, r12
rorx r8, r8, 49
mov r9, qword ptr [rdi + 184]
xor r9, r13
rorx r9, r9, 8
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rsi + 120], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rsi + 128], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rsi + 136], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rsi + 144], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rsi + 152], r15
mov rax, qword ptr [rdi + 16]
xor rax, r12
rorx rax, rax, 2
mov rbx, qword ptr [rdi + 64]
xor rbx, r13
rorx rbx, rbx, 9
mov rcx, qword ptr [rdi + 112]
xor rcx, r14
rorx rcx, rcx, 25
mov r8, qword ptr [rdi + 120]
xor r8, r10
rorx r8, r8, 23
mov r9, qword ptr [rdi + 168]
xor r9, r11
rorx r9, r9, 62
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rsi + 160], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rsi + 168], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rsi + 176], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rsi + 184], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rsi + 192], r15
mov rax, qword ptr [rsi + 0]
xor rax, qword ptr [rsi + 40]
xor rax, qword ptr [rsi + 80]
xor rax, qword ptr [rsi + 120]
xor rax, qword ptr [rsi + 160]
mov rbx, qword ptr [rsi + 8]
xor rbx, qword ptr [rsi + 48]
xor rbx, qword ptr [rsi + 88]
xor rbx, qword ptr [rsi + 128]
xor rbx, qword ptr [rsi + 168]
mov rcx, qword ptr [rsi + 16]
xor rcx, qword ptr [rsi + 56]
xor rcx, qword ptr [rsi + 96]
xor rcx, qword ptr [rsi + 136]
xor rcx, qword ptr [rsi + 176]
mov r8, qword ptr [rsi + 24]
xor r8, qword ptr [rsi + 64]
xor r8, qword ptr [rsi + 104]
xor r8, qword ptr [rsi + 144]
xor r8, qword ptr [rsi + 184]
mov r9, qword ptr [rsi + 32]
xor r9, qword ptr [rsi + 72]
xor r9, qword ptr [rsi + 112]
xor r9, qword ptr [rsi + 152]
xor r9, qword ptr [rsi + 192]
rorx r10, rbx, 63
xor r10, r9
rorx r11, rcx, 63
xor r11, rax
rorx r12, r8, 63
xor r12, rbx
rorx r13, r9, 63
xor r13, rcx
rorx r14, rax, 63
xor r14, r8
mov rax, qword ptr [rsi + 0]
xor rax, r10
mov rbx, qword ptr [rsi + 48]
xor rbx, r11
rorx rbx, rbx, 20
mov rcx, qword ptr [rsi + 96]
xor rcx, r12
rorx rcx, rcx, 21
mov r8, qword ptr [rsi + 144]
xor r8, r13
rorx r8, r8, 43
mov r9, qword ptr [rsi + 192]
xor r9, r14
rorx r9, r9, 50
andn r15, rbx, rcx
xor r15, rax
xor r15, qword ptr [rdx + 8]
mov qword ptr [rdi + 0], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rdi + 8], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rdi + 16], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rdi + 24], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rdi + 32], r15
mov rax, qword ptr [rsi + 24]
xor rax, r13
rorx rax, rax, 36
mov rbx, qword ptr [rsi + 72]
xor rbx, r14
rorx rbx, rbx, 44
mov rcx, qword ptr [rsi + 80]
xor rcx, r10
rorx rcx, rcx, 61
mov r8, qword ptr [rsi + 128]
xor r8, r11
rorx r8, r8, 19
mov r9, qword ptr [rsi + 176]
xor r9, r12
rorx r9, r9, 3
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rdi + 40], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rdi + 48], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rdi + 56], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rdi + 64], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rdi + 72], r15
mov rax, qword ptr [rsi + 8]
xor rax, r11
rorx rax, rax, 63
mov rbx, qword ptr [rsi + 56]
xor rbx, r12
rorx rbx, rbx, 58
mov rcx, qword ptr [rsi + 104]
xor rcx, r13
rorx rcx, rcx, 39
mov r8, qword ptr [rsi + 152]
xor r8, r14
rorx r8, r8, 56
mov r9, qword ptr [rsi + 160]
xor r9, r10
rorx r9, r9, 46
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rdi + 80], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rdi + 88], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rdi + 96], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rdi + 104], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rdi + 112], r15
mov rax, qword ptr [rsi + 32]
xor rax, r14
rorx rax, rax, 37
mov rbx, qword ptr [rsi + 40]
xor rbx, r10
rorx rbx, rbx, 28
mov rcx, qword ptr [rsi + 88]
xor rcx, r11
rorx rcx, rcx, 54
mov r8, qword ptr [rsi + 136]
xor r8, r12
rorx r8, r8, 49
mov r9, qword ptr [rsi + 184]
xor r9, r13
rorx r9, r9, 8
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rdi + 120], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rdi + 128], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rdi + 136], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rdi + 144], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rdi + 152], r15
mov rax, qword ptr [rsi + 16]
xor rax, r12
rorx rax, rax, 2
mov rbx, qword ptr [rsi + 64]
xor rbx, r13
rorx rbx, rbx, 9
mov rcx, qword ptr [rsi + 112]
xor rcx, r14
rorx rcx, rcx, 25
mov r8, qword ptr [rsi + 120]
xor r8, r10
rorx r8, r8, 23
mov r9, qword ptr [rsi + 168]
xor r9, r11
rorx r9, r9, 62
andn r15, rbx, rcx
xor r15, rax
mov qword ptr [rdi + 160], r15
andn r15, rcx, r8
xor r15, rbx
mov qword ptr [rdi + 168], r15
andn r15, r8, r9
xor r15, rcx
mov qword ptr [rdi + 176], r15
andn r15, r9, rax
xor r15, r8
mov qword ptr [rdi + 184], r15
andn r15, rax, rbx
xor r15, r9
mov qword ptr [rdi + 192], r15
add rdx, 16
cmp rdx, qword ptr [rsi + 208]
jb 1b
dec qword ptr [rsi + 224]
jnz 3b
.att_syntax prefix
