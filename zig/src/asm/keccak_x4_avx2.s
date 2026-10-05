.intel_syntax noprefix
vmovdqu ymm0, ymmword ptr [rdi + 0]
vmovdqu ymm1, ymmword ptr [rdi + 200]
vmovdqu ymm2, ymmword ptr [rdi + 400]
vmovdqu ymm3, ymmword ptr [rdi + 600]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 0], ymm0
vmovdqu ymmword ptr [rsi + 32], ymm1
vmovdqu ymmword ptr [rsi + 64], ymm2
vmovdqu ymmword ptr [rsi + 96], ymm3
vmovdqu ymm0, ymmword ptr [rdi + 32]
vmovdqu ymm1, ymmword ptr [rdi + 232]
vmovdqu ymm2, ymmword ptr [rdi + 432]
vmovdqu ymm3, ymmword ptr [rdi + 632]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 128], ymm0
vmovdqu ymmword ptr [rsi + 160], ymm1
vmovdqu ymmword ptr [rsi + 192], ymm2
vmovdqu ymmword ptr [rsi + 224], ymm3
vmovdqu ymm0, ymmword ptr [rdi + 64]
vmovdqu ymm1, ymmword ptr [rdi + 264]
vmovdqu ymm2, ymmword ptr [rdi + 464]
vmovdqu ymm3, ymmword ptr [rdi + 664]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 256], ymm0
vmovdqu ymmword ptr [rsi + 288], ymm1
vmovdqu ymmword ptr [rsi + 320], ymm2
vmovdqu ymmword ptr [rsi + 352], ymm3
vmovdqu ymm0, ymmword ptr [rdi + 96]
vmovdqu ymm1, ymmword ptr [rdi + 296]
vmovdqu ymm2, ymmword ptr [rdi + 496]
vmovdqu ymm3, ymmword ptr [rdi + 696]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 384], ymm0
vmovdqu ymmword ptr [rsi + 416], ymm1
vmovdqu ymmword ptr [rsi + 448], ymm2
vmovdqu ymmword ptr [rsi + 480], ymm3
vmovdqu ymm0, ymmword ptr [rdi + 128]
vmovdqu ymm1, ymmword ptr [rdi + 328]
vmovdqu ymm2, ymmword ptr [rdi + 528]
vmovdqu ymm3, ymmword ptr [rdi + 728]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 512], ymm0
vmovdqu ymmword ptr [rsi + 544], ymm1
vmovdqu ymmword ptr [rsi + 576], ymm2
vmovdqu ymmword ptr [rsi + 608], ymm3
vmovdqu ymm0, ymmword ptr [rdi + 160]
vmovdqu ymm1, ymmword ptr [rdi + 360]
vmovdqu ymm2, ymmword ptr [rdi + 560]
vmovdqu ymm3, ymmword ptr [rdi + 760]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rsi + 640], ymm0
vmovdqu ymmword ptr [rsi + 672], ymm1
vmovdqu ymmword ptr [rsi + 704], ymm2
vmovdqu ymmword ptr [rsi + 736], ymm3
vmovq xmm0, qword ptr [rdi + 192]
vpinsrq xmm0, xmm0, qword ptr [rdi + 392], 1
vmovq xmm1, qword ptr [rdi + 592]
vpinsrq xmm1, xmm1, qword ptr [rdi + 792], 1
vinserti128 ymm0, ymm0, xmm1, 1
vmovdqu ymmword ptr [rsi + 768], ymm0
mov r8, rdx
mov eax, 12
1:
vmovdqa ymm0, ymmword ptr [rsi + 0]
vpxor ymm0, ymm0, ymmword ptr [rsi + 160]
vpxor ymm0, ymm0, ymmword ptr [rsi + 320]
vpxor ymm0, ymm0, ymmword ptr [rsi + 480]
vpxor ymm0, ymm0, ymmword ptr [rsi + 640]
vmovdqa ymm1, ymmword ptr [rsi + 32]
vpxor ymm1, ymm1, ymmword ptr [rsi + 192]
vpxor ymm1, ymm1, ymmword ptr [rsi + 352]
vpxor ymm1, ymm1, ymmword ptr [rsi + 512]
vpxor ymm1, ymm1, ymmword ptr [rsi + 672]
vmovdqa ymm2, ymmword ptr [rsi + 64]
vpxor ymm2, ymm2, ymmword ptr [rsi + 224]
vpxor ymm2, ymm2, ymmword ptr [rsi + 384]
vpxor ymm2, ymm2, ymmword ptr [rsi + 544]
vpxor ymm2, ymm2, ymmword ptr [rsi + 704]
vmovdqa ymm3, ymmword ptr [rsi + 96]
vpxor ymm3, ymm3, ymmword ptr [rsi + 256]
vpxor ymm3, ymm3, ymmword ptr [rsi + 416]
vpxor ymm3, ymm3, ymmword ptr [rsi + 576]
vpxor ymm3, ymm3, ymmword ptr [rsi + 736]
vmovdqa ymm4, ymmword ptr [rsi + 128]
vpxor ymm4, ymm4, ymmword ptr [rsi + 288]
vpxor ymm4, ymm4, ymmword ptr [rsi + 448]
vpxor ymm4, ymm4, ymmword ptr [rsi + 608]
vpxor ymm4, ymm4, ymmword ptr [rsi + 768]
vpsrlq ymm10, ymm1, 63
vpaddq ymm11, ymm1, ymm1
vpor ymm10, ymm10, ymm11
vpxor ymm5, ymm10, ymm4
vpsrlq ymm10, ymm2, 63
vpaddq ymm11, ymm2, ymm2
vpor ymm10, ymm10, ymm11
vpxor ymm6, ymm10, ymm0
vpsrlq ymm10, ymm3, 63
vpaddq ymm11, ymm3, ymm3
vpor ymm10, ymm10, ymm11
vpxor ymm7, ymm10, ymm1
vpsrlq ymm10, ymm4, 63
vpaddq ymm11, ymm4, ymm4
vpor ymm10, ymm10, ymm11
vpxor ymm8, ymm10, ymm2
vpsrlq ymm10, ymm0, 63
vpaddq ymm11, ymm0, ymm0
vpor ymm10, ymm10, ymm11
vpxor ymm9, ymm10, ymm3
vpxor ymm0, ymm5, ymmword ptr [rsi + 0]
vpxor ymm1, ymm6, ymmword ptr [rsi + 192]
vpsrlq ymm10, ymm1, 20
vpsllq ymm1, ymm1, 44
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm7, ymmword ptr [rsi + 384]
vpsrlq ymm10, ymm2, 21
vpsllq ymm2, ymm2, 43
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm8, ymmword ptr [rsi + 576]
vpsrlq ymm10, ymm3, 43
vpsllq ymm3, ymm3, 21
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm9, ymmword ptr [rsi + 768]
vpsrlq ymm10, ymm4, 50
vpsllq ymm4, ymm4, 14
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vpxor ymm11, ymm11, ymmword ptr [r8 + 0]
vmovdqa ymmword ptr [rsi + 800], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 832], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 864], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 896], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 928], ymm11
vpxor ymm0, ymm8, ymmword ptr [rsi + 96]
vpsrlq ymm10, ymm0, 36
vpsllq ymm0, ymm0, 28
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm9, ymmword ptr [rsi + 288]
vpsrlq ymm10, ymm1, 44
vpsllq ymm1, ymm1, 20
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm5, ymmword ptr [rsi + 320]
vpsrlq ymm10, ymm2, 61
vpsllq ymm2, ymm2, 3
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm6, ymmword ptr [rsi + 512]
vpsrlq ymm10, ymm3, 19
vpsllq ymm3, ymm3, 45
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm7, ymmword ptr [rsi + 704]
vpsrlq ymm10, ymm4, 3
vpsllq ymm4, ymm4, 61
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 960], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 992], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 1024], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 1056], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 1088], ymm11
vpxor ymm0, ymm6, ymmword ptr [rsi + 32]
vpsrlq ymm10, ymm0, 63
vpsllq ymm0, ymm0, 1
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm7, ymmword ptr [rsi + 224]
vpsrlq ymm10, ymm1, 58
vpsllq ymm1, ymm1, 6
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm8, ymmword ptr [rsi + 416]
vpsrlq ymm10, ymm2, 39
vpsllq ymm2, ymm2, 25
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm9, ymmword ptr [rsi + 608]
vpshufb ymm3, ymm3, ymmword ptr [rcx]
vpxor ymm4, ymm5, ymmword ptr [rsi + 640]
vpsrlq ymm10, ymm4, 46
vpsllq ymm4, ymm4, 18
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 1120], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 1152], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 1184], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 1216], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 1248], ymm11
vpxor ymm0, ymm9, ymmword ptr [rsi + 128]
vpsrlq ymm10, ymm0, 37
vpsllq ymm0, ymm0, 27
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm5, ymmword ptr [rsi + 160]
vpsrlq ymm10, ymm1, 28
vpsllq ymm1, ymm1, 36
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm6, ymmword ptr [rsi + 352]
vpsrlq ymm10, ymm2, 54
vpsllq ymm2, ymm2, 10
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm7, ymmword ptr [rsi + 544]
vpsrlq ymm10, ymm3, 49
vpsllq ymm3, ymm3, 15
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm8, ymmword ptr [rsi + 736]
vpshufb ymm4, ymm4, ymmword ptr [rcx + 32]
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 1280], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 1312], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 1344], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 1376], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 1408], ymm11
vpxor ymm0, ymm7, ymmword ptr [rsi + 64]
vpsrlq ymm10, ymm0, 2
vpsllq ymm0, ymm0, 62
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm8, ymmword ptr [rsi + 256]
vpsrlq ymm10, ymm1, 9
vpsllq ymm1, ymm1, 55
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm9, ymmword ptr [rsi + 448]
vpsrlq ymm10, ymm2, 25
vpsllq ymm2, ymm2, 39
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm5, ymmword ptr [rsi + 480]
vpsrlq ymm10, ymm3, 23
vpsllq ymm3, ymm3, 41
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm6, ymmword ptr [rsi + 672]
vpsrlq ymm10, ymm4, 62
vpsllq ymm4, ymm4, 2
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 1440], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 1472], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 1504], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 1536], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 1568], ymm11
vmovdqa ymm0, ymmword ptr [rsi + 800]
vpxor ymm0, ymm0, ymmword ptr [rsi + 960]
vpxor ymm0, ymm0, ymmword ptr [rsi + 1120]
vpxor ymm0, ymm0, ymmword ptr [rsi + 1280]
vpxor ymm0, ymm0, ymmword ptr [rsi + 1440]
vmovdqa ymm1, ymmword ptr [rsi + 832]
vpxor ymm1, ymm1, ymmword ptr [rsi + 992]
vpxor ymm1, ymm1, ymmword ptr [rsi + 1152]
vpxor ymm1, ymm1, ymmword ptr [rsi + 1312]
vpxor ymm1, ymm1, ymmword ptr [rsi + 1472]
vmovdqa ymm2, ymmword ptr [rsi + 864]
vpxor ymm2, ymm2, ymmword ptr [rsi + 1024]
vpxor ymm2, ymm2, ymmword ptr [rsi + 1184]
vpxor ymm2, ymm2, ymmword ptr [rsi + 1344]
vpxor ymm2, ymm2, ymmword ptr [rsi + 1504]
vmovdqa ymm3, ymmword ptr [rsi + 896]
vpxor ymm3, ymm3, ymmword ptr [rsi + 1056]
vpxor ymm3, ymm3, ymmword ptr [rsi + 1216]
vpxor ymm3, ymm3, ymmword ptr [rsi + 1376]
vpxor ymm3, ymm3, ymmword ptr [rsi + 1536]
vmovdqa ymm4, ymmword ptr [rsi + 928]
vpxor ymm4, ymm4, ymmword ptr [rsi + 1088]
vpxor ymm4, ymm4, ymmword ptr [rsi + 1248]
vpxor ymm4, ymm4, ymmword ptr [rsi + 1408]
vpxor ymm4, ymm4, ymmword ptr [rsi + 1568]
vpsrlq ymm10, ymm1, 63
vpaddq ymm11, ymm1, ymm1
vpor ymm10, ymm10, ymm11
vpxor ymm5, ymm10, ymm4
vpsrlq ymm10, ymm2, 63
vpaddq ymm11, ymm2, ymm2
vpor ymm10, ymm10, ymm11
vpxor ymm6, ymm10, ymm0
vpsrlq ymm10, ymm3, 63
vpaddq ymm11, ymm3, ymm3
vpor ymm10, ymm10, ymm11
vpxor ymm7, ymm10, ymm1
vpsrlq ymm10, ymm4, 63
vpaddq ymm11, ymm4, ymm4
vpor ymm10, ymm10, ymm11
vpxor ymm8, ymm10, ymm2
vpsrlq ymm10, ymm0, 63
vpaddq ymm11, ymm0, ymm0
vpor ymm10, ymm10, ymm11
vpxor ymm9, ymm10, ymm3
vpxor ymm0, ymm5, ymmword ptr [rsi + 800]
vpxor ymm1, ymm6, ymmword ptr [rsi + 992]
vpsrlq ymm10, ymm1, 20
vpsllq ymm1, ymm1, 44
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm7, ymmword ptr [rsi + 1184]
vpsrlq ymm10, ymm2, 21
vpsllq ymm2, ymm2, 43
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm8, ymmword ptr [rsi + 1376]
vpsrlq ymm10, ymm3, 43
vpsllq ymm3, ymm3, 21
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm9, ymmword ptr [rsi + 1568]
vpsrlq ymm10, ymm4, 50
vpsllq ymm4, ymm4, 14
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vpxor ymm11, ymm11, ymmword ptr [r8 + 32]
vmovdqa ymmword ptr [rsi + 0], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 32], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 64], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 96], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 128], ymm11
vpxor ymm0, ymm8, ymmword ptr [rsi + 896]
vpsrlq ymm10, ymm0, 36
vpsllq ymm0, ymm0, 28
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm9, ymmword ptr [rsi + 1088]
vpsrlq ymm10, ymm1, 44
vpsllq ymm1, ymm1, 20
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm5, ymmword ptr [rsi + 1120]
vpsrlq ymm10, ymm2, 61
vpsllq ymm2, ymm2, 3
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm6, ymmword ptr [rsi + 1312]
vpsrlq ymm10, ymm3, 19
vpsllq ymm3, ymm3, 45
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm7, ymmword ptr [rsi + 1504]
vpsrlq ymm10, ymm4, 3
vpsllq ymm4, ymm4, 61
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 160], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 192], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 224], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 256], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 288], ymm11
vpxor ymm0, ymm6, ymmword ptr [rsi + 832]
vpsrlq ymm10, ymm0, 63
vpsllq ymm0, ymm0, 1
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm7, ymmword ptr [rsi + 1024]
vpsrlq ymm10, ymm1, 58
vpsllq ymm1, ymm1, 6
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm8, ymmword ptr [rsi + 1216]
vpsrlq ymm10, ymm2, 39
vpsllq ymm2, ymm2, 25
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm9, ymmword ptr [rsi + 1408]
vpshufb ymm3, ymm3, ymmword ptr [rcx]
vpxor ymm4, ymm5, ymmword ptr [rsi + 1440]
vpsrlq ymm10, ymm4, 46
vpsllq ymm4, ymm4, 18
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 320], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 352], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 384], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 416], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 448], ymm11
vpxor ymm0, ymm9, ymmword ptr [rsi + 928]
vpsrlq ymm10, ymm0, 37
vpsllq ymm0, ymm0, 27
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm5, ymmword ptr [rsi + 960]
vpsrlq ymm10, ymm1, 28
vpsllq ymm1, ymm1, 36
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm6, ymmword ptr [rsi + 1152]
vpsrlq ymm10, ymm2, 54
vpsllq ymm2, ymm2, 10
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm7, ymmword ptr [rsi + 1344]
vpsrlq ymm10, ymm3, 49
vpsllq ymm3, ymm3, 15
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm8, ymmword ptr [rsi + 1536]
vpshufb ymm4, ymm4, ymmword ptr [rcx + 32]
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 480], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 512], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 544], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 576], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 608], ymm11
vpxor ymm0, ymm7, ymmword ptr [rsi + 864]
vpsrlq ymm10, ymm0, 2
vpsllq ymm0, ymm0, 62
vpor ymm0, ymm0, ymm10
vpxor ymm1, ymm8, ymmword ptr [rsi + 1056]
vpsrlq ymm10, ymm1, 9
vpsllq ymm1, ymm1, 55
vpor ymm1, ymm1, ymm10
vpxor ymm2, ymm9, ymmword ptr [rsi + 1248]
vpsrlq ymm10, ymm2, 25
vpsllq ymm2, ymm2, 39
vpor ymm2, ymm2, ymm10
vpxor ymm3, ymm5, ymmword ptr [rsi + 1280]
vpsrlq ymm10, ymm3, 23
vpsllq ymm3, ymm3, 41
vpor ymm3, ymm3, ymm10
vpxor ymm4, ymm6, ymmword ptr [rsi + 1472]
vpsrlq ymm10, ymm4, 62
vpsllq ymm4, ymm4, 2
vpor ymm4, ymm4, ymm10
vpandn ymm11, ymm1, ymm2
vpxor ymm11, ymm11, ymm0
vmovdqa ymmword ptr [rsi + 640], ymm11
vpandn ymm11, ymm2, ymm3
vpxor ymm11, ymm11, ymm1
vmovdqa ymmword ptr [rsi + 672], ymm11
vpandn ymm11, ymm3, ymm4
vpxor ymm11, ymm11, ymm2
vmovdqa ymmword ptr [rsi + 704], ymm11
vpandn ymm11, ymm4, ymm0
vpxor ymm11, ymm11, ymm3
vmovdqa ymmword ptr [rsi + 736], ymm11
vpandn ymm11, ymm0, ymm1
vpxor ymm11, ymm11, ymm4
vmovdqa ymmword ptr [rsi + 768], ymm11
add r8, 64
dec eax
jnz 1b
vmovdqu ymm0, ymmword ptr [rsi + 0]
vmovdqu ymm1, ymmword ptr [rsi + 32]
vmovdqu ymm2, ymmword ptr [rsi + 64]
vmovdqu ymm3, ymmword ptr [rsi + 96]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 0], ymm0
vmovdqu ymmword ptr [rdi + 200], ymm1
vmovdqu ymmword ptr [rdi + 400], ymm2
vmovdqu ymmword ptr [rdi + 600], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 128]
vmovdqu ymm1, ymmword ptr [rsi + 160]
vmovdqu ymm2, ymmword ptr [rsi + 192]
vmovdqu ymm3, ymmword ptr [rsi + 224]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 32], ymm0
vmovdqu ymmword ptr [rdi + 232], ymm1
vmovdqu ymmword ptr [rdi + 432], ymm2
vmovdqu ymmword ptr [rdi + 632], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 256]
vmovdqu ymm1, ymmword ptr [rsi + 288]
vmovdqu ymm2, ymmword ptr [rsi + 320]
vmovdqu ymm3, ymmword ptr [rsi + 352]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 64], ymm0
vmovdqu ymmword ptr [rdi + 264], ymm1
vmovdqu ymmword ptr [rdi + 464], ymm2
vmovdqu ymmword ptr [rdi + 664], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 384]
vmovdqu ymm1, ymmword ptr [rsi + 416]
vmovdqu ymm2, ymmword ptr [rsi + 448]
vmovdqu ymm3, ymmword ptr [rsi + 480]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 96], ymm0
vmovdqu ymmword ptr [rdi + 296], ymm1
vmovdqu ymmword ptr [rdi + 496], ymm2
vmovdqu ymmword ptr [rdi + 696], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 512]
vmovdqu ymm1, ymmword ptr [rsi + 544]
vmovdqu ymm2, ymmword ptr [rsi + 576]
vmovdqu ymm3, ymmword ptr [rsi + 608]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 128], ymm0
vmovdqu ymmword ptr [rdi + 328], ymm1
vmovdqu ymmword ptr [rdi + 528], ymm2
vmovdqu ymmword ptr [rdi + 728], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 640]
vmovdqu ymm1, ymmword ptr [rsi + 672]
vmovdqu ymm2, ymmword ptr [rsi + 704]
vmovdqu ymm3, ymmword ptr [rsi + 736]
vpunpcklqdq ymm4, ymm0, ymm1
vpunpckhqdq ymm5, ymm0, ymm1
vpunpcklqdq ymm6, ymm2, ymm3
vpunpckhqdq ymm7, ymm2, ymm3
vperm2i128 ymm0, ymm4, ymm6, 32
vperm2i128 ymm1, ymm5, ymm7, 32
vperm2i128 ymm2, ymm4, ymm6, 49
vperm2i128 ymm3, ymm5, ymm7, 49
vmovdqu ymmword ptr [rdi + 160], ymm0
vmovdqu ymmword ptr [rdi + 360], ymm1
vmovdqu ymmword ptr [rdi + 560], ymm2
vmovdqu ymmword ptr [rdi + 760], ymm3
vmovdqu ymm0, ymmword ptr [rsi + 768]
vextracti128 xmm1, ymm0, 1
vmovq qword ptr [rdi + 192], xmm0
vpextrq qword ptr [rdi + 392], xmm0, 1
vmovq qword ptr [rdi + 592], xmm1
vpextrq qword ptr [rdi + 792], xmm1, 1
vzeroupper
.att_syntax prefix
