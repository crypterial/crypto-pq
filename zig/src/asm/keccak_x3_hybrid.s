.arch_extension sha3
sub sp, sp, #48
str x0, [sp, #24]
add x2, x1, #192
stp x1, x2, [sp, #32]
add x2, x0, #200
ldr d0, [x0, #0]
ld1 {v0.d}[1], [x2], #8
ldr d1, [x0, #8]
ld1 {v1.d}[1], [x2], #8
ldr d2, [x0, #16]
ld1 {v2.d}[1], [x2], #8
ldr d3, [x0, #24]
ld1 {v3.d}[1], [x2], #8
ldr d4, [x0, #32]
ld1 {v4.d}[1], [x2], #8
ldr d5, [x0, #40]
ld1 {v5.d}[1], [x2], #8
ldr d6, [x0, #48]
ld1 {v6.d}[1], [x2], #8
ldr d7, [x0, #56]
ld1 {v7.d}[1], [x2], #8
ldr d8, [x0, #64]
ld1 {v8.d}[1], [x2], #8
ldr d9, [x0, #72]
ld1 {v9.d}[1], [x2], #8
ldr d10, [x0, #80]
ld1 {v10.d}[1], [x2], #8
ldr d11, [x0, #88]
ld1 {v11.d}[1], [x2], #8
ldr d12, [x0, #96]
ld1 {v12.d}[1], [x2], #8
ldr d13, [x0, #104]
ld1 {v13.d}[1], [x2], #8
ldr d14, [x0, #112]
ld1 {v14.d}[1], [x2], #8
ldr d15, [x0, #120]
ld1 {v15.d}[1], [x2], #8
ldr d16, [x0, #128]
ld1 {v16.d}[1], [x2], #8
ldr d17, [x0, #136]
ld1 {v17.d}[1], [x2], #8
ldr d18, [x0, #144]
ld1 {v18.d}[1], [x2], #8
ldr d19, [x0, #152]
ld1 {v19.d}[1], [x2], #8
ldr d20, [x0, #160]
ld1 {v20.d}[1], [x2], #8
ldr d21, [x0, #168]
ld1 {v21.d}[1], [x2], #8
ldr d22, [x0, #176]
ld1 {v22.d}[1], [x2], #8
ldr d23, [x0, #184]
ld1 {v23.d}[1], [x2], #8
ldr d24, [x0, #192]
ld1 {v24.d}[1], [x2], #8
ldr x1, [x0, #408]
ldr x2, [x0, #416]
ldr x3, [x0, #424]
ldr x4, [x0, #432]
ldr x5, [x0, #440]
ldr x6, [x0, #448]
ldr x7, [x0, #456]
ldr x8, [x0, #464]
ldr x9, [x0, #472]
ldr x10, [x0, #480]
ldr x11, [x0, #488]
ldr x12, [x0, #496]
ldr x13, [x0, #504]
ldr x14, [x0, #512]
ldr x15, [x0, #520]
ldr x16, [x0, #528]
ldr x17, [x0, #536]
ldr x19, [x0, #544]
ldr x20, [x0, #552]
ldr x21, [x0, #560]
ldr x22, [x0, #568]
ldr x23, [x0, #576]
ldr x24, [x0, #584]
ldr x25, [x0, #592]
ldr x0, [x0, #400]
1:
eor3 v25.16b, v0.16b, v5.16b, v10.16b
stp x4, x9, [sp]
str x14, [sp, #16]
eor3 v25.16b, v25.16b, v15.16b, v20.16b
eor x4, x4, x9
eor x4, x4, x14
eor3 v26.16b, v1.16b, v6.16b, v11.16b
eor x4, x4, x20
eor x4, x4, x25
eor3 v26.16b, v26.16b, v16.16b, v21.16b
eor x26, x0, x5
eor3 v27.16b, v2.16b, v7.16b, v12.16b
eor x26, x26, x10
eor x26, x26, x15
eor3 v27.16b, v27.16b, v17.16b, v22.16b
eor x26, x26, x21
eor x27, x1, x6
eor3 v28.16b, v3.16b, v8.16b, v13.16b
eor x27, x27, x11
eor3 v28.16b, v28.16b, v18.16b, v23.16b
eor x27, x27, x16
eor x27, x27, x22
eor3 v29.16b, v4.16b, v9.16b, v14.16b
eor x28, x2, x7
eor x28, x28, x12
eor3 v29.16b, v29.16b, v19.16b, v24.16b
eor x28, x28, x17
eor x28, x28, x23
rax1 v30.2d, v29.2d, v26.2d
eor x9, x3, x8
rax1 v31.2d, v25.2d, v27.2d
eor x9, x9, x13
eor x9, x9, x19
rax1 v26.2d, v26.2d, v28.2d
eor x9, x9, x24
eor x14, x26, x28, ror #63
rax1 v27.2d, v27.2d, v29.2d
eor x1, x1, x14
rax1 v28.2d, v28.2d, v25.2d
eor x6, x6, x14
eor x11, x11, x14
mov v25.16b, v1.16b
eor x16, x16, x14
eor x22, x22, x14
xar v1.2d, v6.2d, v31.2d, #20
eor x14, x27, x9, ror #63
eor x28, x28, x4, ror #63
xar v6.2d, v9.2d, v28.2d, #44
eor x9, x9, x26, ror #63
xar v9.2d, v22.2d, v26.2d, #3
eor x4, x4, x27, ror #63
eor x2, x2, x14
xar v22.2d, v14.2d, v28.2d, #25
eor x7, x7, x14
eor x12, x12, x14
xar v14.2d, v20.2d, v30.2d, #46
eor x17, x17, x14
xar v20.2d, v2.2d, v26.2d, #2
eor x23, x23, x14
eor x0, x0, x4
xar v2.2d, v12.2d, v26.2d, #21
eor x5, x5, x4
eor x10, x10, x4
xar v12.2d, v13.2d, v27.2d, #39
eor x15, x15, x4
eor x21, x21, x4
xar v13.2d, v19.2d, v28.2d, #56
eor x3, x3, x28
xar v19.2d, v23.2d, v27.2d, #8
eor x8, x8, x28
eor x13, x13, x28
xar v23.2d, v15.2d, v30.2d, #23
eor x19, x19, x28
eor x24, x24, x28
xar v15.2d, v4.2d, v28.2d, #37
ldr x4, [sp]
xar v4.2d, v24.2d, v28.2d, #50
ldr x14, [sp, #16]
ldr x26, [sp, #8]
xar v24.2d, v21.2d, v31.2d, #62
eor x4, x4, x9
eor x14, x14, x9
xar v21.2d, v8.2d, v27.2d, #9
eor x20, x20, x9
eor x25, x25, x9
xar v8.2d, v16.2d, v31.2d, #19
eor x9, x26, x9
xar v16.2d, v5.2d, v30.2d, #28
mov x26, x1
ror x1, x6, #20
xar v5.2d, v3.2d, v27.2d, #36
ror x6, x9, #44
ror x9, x23, #3
xar v3.2d, v18.2d, v27.2d, #43
ror x23, x14, #25
xar v18.2d, v17.2d, v26.2d, #49
ror x14, x21, #46
ror x21, x2, #2
xar v17.2d, v11.2d, v31.2d, #54
ror x2, x12, #21
ror x12, x13, #39
xar v11.2d, v7.2d, v26.2d, #58
ror x13, x20, #56
xar v7.2d, v10.2d, v30.2d, #61
ror x20, x24, #8
ror x24, x15, #23
xar v10.2d, v25.2d, v31.2d, #63
ror x15, x4, #37
ror x4, x25, #50
eor v0.16b, v0.16b, v30.16b
ror x25, x22, #62
ror x22, x8, #9
mov v25.16b, v0.16b
ror x8, x16, #19
mov v26.16b, v1.16b
ror x16, x5, #28
ror x5, x3, #36
bcax v0.16b, v0.16b, v2.16b, v1.16b
ror x3, x19, #43
ror x19, x17, #49
bcax v1.16b, v1.16b, v3.16b, v2.16b
ror x17, x11, #54
bcax v2.16b, v2.16b, v4.16b, v3.16b
ror x11, x7, #58
ror x7, x10, #61
bcax v3.16b, v3.16b, v25.16b, v4.16b
ror x10, x26, #63
bic x26, x2, x1
bcax v4.16b, v4.16b, v26.16b, v25.16b
bic x27, x3, x2
bic x28, x4, x3
mov v25.16b, v5.16b
eor x2, x2, x28
mov v26.16b, v6.16b
bic x28, x0, x4
eor x3, x3, x28
bcax v5.16b, v5.16b, v7.16b, v6.16b
bic x28, x1, x0
eor x4, x4, x28
bcax v6.16b, v6.16b, v8.16b, v7.16b
eor x0, x0, x26
bcax v7.16b, v7.16b, v9.16b, v8.16b
eor x1, x1, x27
bic x26, x7, x6
bcax v8.16b, v8.16b, v25.16b, v9.16b
bic x27, x8, x7
bic x28, x9, x8
bcax v9.16b, v9.16b, v26.16b, v25.16b
eor x7, x7, x28
bic x28, x5, x9
mov v25.16b, v10.16b
eor x8, x8, x28
mov v26.16b, v11.16b
bic x28, x6, x5
eor x9, x9, x28
bcax v10.16b, v10.16b, v12.16b, v11.16b
eor x5, x5, x26
eor x6, x6, x27
bcax v11.16b, v11.16b, v13.16b, v12.16b
bic x26, x12, x11
bcax v12.16b, v12.16b, v14.16b, v13.16b
bic x27, x13, x12
bic x28, x14, x13
bcax v13.16b, v13.16b, v25.16b, v14.16b
eor x12, x12, x28
bic x28, x10, x14
bcax v14.16b, v14.16b, v26.16b, v25.16b
eor x13, x13, x28
bic x28, x11, x10
mov v25.16b, v15.16b
eor x14, x14, x28
mov v26.16b, v16.16b
eor x10, x10, x26
eor x11, x11, x27
bcax v15.16b, v15.16b, v17.16b, v16.16b
bic x26, x17, x16
bic x27, x19, x17
bcax v16.16b, v16.16b, v18.16b, v17.16b
bic x28, x20, x19
bcax v17.16b, v17.16b, v19.16b, v18.16b
eor x17, x17, x28
bic x28, x15, x20
bcax v18.16b, v18.16b, v25.16b, v19.16b
eor x19, x19, x28
bic x28, x16, x15
bcax v19.16b, v19.16b, v26.16b, v25.16b
eor x20, x20, x28
eor x15, x15, x26
mov v25.16b, v20.16b
eor x16, x16, x27
mov v26.16b, v21.16b
bic x26, x23, x22
bic x27, x24, x23
bcax v20.16b, v20.16b, v22.16b, v21.16b
bic x28, x25, x24
eor x23, x23, x28
bcax v21.16b, v21.16b, v23.16b, v22.16b
bic x28, x21, x25
bcax v22.16b, v22.16b, v24.16b, v23.16b
eor x24, x24, x28
bic x28, x22, x21
bcax v23.16b, v23.16b, v25.16b, v24.16b
eor x25, x25, x28
eor x21, x21, x26
bcax v24.16b, v24.16b, v26.16b, v25.16b
eor x22, x22, x27
ldr x26, [sp, #32]
ldr x27, [x26], #8
str x26, [sp, #32]
eor x0, x0, x27
dup v26.2d, x27
eor v0.16b, v0.16b, v26.16b
eor3 v25.16b, v0.16b, v5.16b, v10.16b
stp x4, x9, [sp]
str x14, [sp, #16]
eor3 v25.16b, v25.16b, v15.16b, v20.16b
eor x4, x4, x9
eor x4, x4, x14
eor3 v26.16b, v1.16b, v6.16b, v11.16b
eor x4, x4, x20
eor x4, x4, x25
eor3 v26.16b, v26.16b, v16.16b, v21.16b
eor x26, x0, x5
eor3 v27.16b, v2.16b, v7.16b, v12.16b
eor x26, x26, x10
eor x26, x26, x15
eor3 v27.16b, v27.16b, v17.16b, v22.16b
eor x26, x26, x21
eor x27, x1, x6
eor3 v28.16b, v3.16b, v8.16b, v13.16b
eor x27, x27, x11
eor3 v28.16b, v28.16b, v18.16b, v23.16b
eor x27, x27, x16
eor x27, x27, x22
eor3 v29.16b, v4.16b, v9.16b, v14.16b
eor x28, x2, x7
eor x28, x28, x12
eor3 v29.16b, v29.16b, v19.16b, v24.16b
eor x28, x28, x17
eor x28, x28, x23
rax1 v30.2d, v29.2d, v26.2d
eor x9, x3, x8
rax1 v31.2d, v25.2d, v27.2d
eor x9, x9, x13
eor x9, x9, x19
rax1 v26.2d, v26.2d, v28.2d
eor x9, x9, x24
eor x14, x26, x28, ror #63
rax1 v27.2d, v27.2d, v29.2d
eor x1, x1, x14
rax1 v28.2d, v28.2d, v25.2d
eor x6, x6, x14
eor x11, x11, x14
mov v25.16b, v1.16b
eor x16, x16, x14
eor x22, x22, x14
xar v1.2d, v6.2d, v31.2d, #20
eor x14, x27, x9, ror #63
eor x28, x28, x4, ror #63
xar v6.2d, v9.2d, v28.2d, #44
eor x9, x9, x26, ror #63
xar v9.2d, v22.2d, v26.2d, #3
eor x4, x4, x27, ror #63
eor x2, x2, x14
xar v22.2d, v14.2d, v28.2d, #25
eor x7, x7, x14
eor x12, x12, x14
xar v14.2d, v20.2d, v30.2d, #46
eor x17, x17, x14
xar v20.2d, v2.2d, v26.2d, #2
eor x23, x23, x14
eor x0, x0, x4
xar v2.2d, v12.2d, v26.2d, #21
eor x5, x5, x4
eor x10, x10, x4
xar v12.2d, v13.2d, v27.2d, #39
eor x15, x15, x4
eor x21, x21, x4
xar v13.2d, v19.2d, v28.2d, #56
eor x3, x3, x28
xar v19.2d, v23.2d, v27.2d, #8
eor x8, x8, x28
eor x13, x13, x28
xar v23.2d, v15.2d, v30.2d, #23
eor x19, x19, x28
eor x24, x24, x28
xar v15.2d, v4.2d, v28.2d, #37
ldr x4, [sp]
xar v4.2d, v24.2d, v28.2d, #50
ldr x14, [sp, #16]
ldr x26, [sp, #8]
xar v24.2d, v21.2d, v31.2d, #62
eor x4, x4, x9
eor x14, x14, x9
xar v21.2d, v8.2d, v27.2d, #9
eor x20, x20, x9
eor x25, x25, x9
xar v8.2d, v16.2d, v31.2d, #19
eor x9, x26, x9
xar v16.2d, v5.2d, v30.2d, #28
mov x26, x1
ror x1, x6, #20
xar v5.2d, v3.2d, v27.2d, #36
ror x6, x9, #44
ror x9, x23, #3
xar v3.2d, v18.2d, v27.2d, #43
ror x23, x14, #25
xar v18.2d, v17.2d, v26.2d, #49
ror x14, x21, #46
ror x21, x2, #2
xar v17.2d, v11.2d, v31.2d, #54
ror x2, x12, #21
ror x12, x13, #39
xar v11.2d, v7.2d, v26.2d, #58
ror x13, x20, #56
xar v7.2d, v10.2d, v30.2d, #61
ror x20, x24, #8
ror x24, x15, #23
xar v10.2d, v25.2d, v31.2d, #63
ror x15, x4, #37
ror x4, x25, #50
eor v0.16b, v0.16b, v30.16b
ror x25, x22, #62
ror x22, x8, #9
mov v25.16b, v0.16b
ror x8, x16, #19
mov v26.16b, v1.16b
ror x16, x5, #28
ror x5, x3, #36
bcax v0.16b, v0.16b, v2.16b, v1.16b
ror x3, x19, #43
ror x19, x17, #49
bcax v1.16b, v1.16b, v3.16b, v2.16b
ror x17, x11, #54
bcax v2.16b, v2.16b, v4.16b, v3.16b
ror x11, x7, #58
ror x7, x10, #61
bcax v3.16b, v3.16b, v25.16b, v4.16b
ror x10, x26, #63
bic x26, x2, x1
bcax v4.16b, v4.16b, v26.16b, v25.16b
bic x27, x3, x2
bic x28, x4, x3
mov v25.16b, v5.16b
eor x2, x2, x28
mov v26.16b, v6.16b
bic x28, x0, x4
eor x3, x3, x28
bcax v5.16b, v5.16b, v7.16b, v6.16b
bic x28, x1, x0
eor x4, x4, x28
bcax v6.16b, v6.16b, v8.16b, v7.16b
eor x0, x0, x26
bcax v7.16b, v7.16b, v9.16b, v8.16b
eor x1, x1, x27
bic x26, x7, x6
bcax v8.16b, v8.16b, v25.16b, v9.16b
bic x27, x8, x7
bic x28, x9, x8
bcax v9.16b, v9.16b, v26.16b, v25.16b
eor x7, x7, x28
bic x28, x5, x9
mov v25.16b, v10.16b
eor x8, x8, x28
mov v26.16b, v11.16b
bic x28, x6, x5
eor x9, x9, x28
bcax v10.16b, v10.16b, v12.16b, v11.16b
eor x5, x5, x26
eor x6, x6, x27
bcax v11.16b, v11.16b, v13.16b, v12.16b
bic x26, x12, x11
bcax v12.16b, v12.16b, v14.16b, v13.16b
bic x27, x13, x12
bic x28, x14, x13
bcax v13.16b, v13.16b, v25.16b, v14.16b
eor x12, x12, x28
bic x28, x10, x14
bcax v14.16b, v14.16b, v26.16b, v25.16b
eor x13, x13, x28
bic x28, x11, x10
mov v25.16b, v15.16b
eor x14, x14, x28
mov v26.16b, v16.16b
eor x10, x10, x26
eor x11, x11, x27
bcax v15.16b, v15.16b, v17.16b, v16.16b
bic x26, x17, x16
bic x27, x19, x17
bcax v16.16b, v16.16b, v18.16b, v17.16b
bic x28, x20, x19
bcax v17.16b, v17.16b, v19.16b, v18.16b
eor x17, x17, x28
bic x28, x15, x20
bcax v18.16b, v18.16b, v25.16b, v19.16b
eor x19, x19, x28
bic x28, x16, x15
bcax v19.16b, v19.16b, v26.16b, v25.16b
eor x20, x20, x28
eor x15, x15, x26
mov v25.16b, v20.16b
eor x16, x16, x27
mov v26.16b, v21.16b
bic x26, x23, x22
bic x27, x24, x23
bcax v20.16b, v20.16b, v22.16b, v21.16b
bic x28, x25, x24
eor x23, x23, x28
bcax v21.16b, v21.16b, v23.16b, v22.16b
bic x28, x21, x25
bcax v22.16b, v22.16b, v24.16b, v23.16b
eor x24, x24, x28
bic x28, x22, x21
bcax v23.16b, v23.16b, v25.16b, v24.16b
eor x25, x25, x28
eor x21, x21, x26
bcax v24.16b, v24.16b, v26.16b, v25.16b
eor x22, x22, x27
ldr x26, [sp, #32]
ldr x27, [x26], #8
str x26, [sp, #32]
eor x0, x0, x27
dup v26.2d, x27
eor v0.16b, v0.16b, v26.16b
ldr x28, [sp, #40]
cmp x26, x28
b.ne 1b
ldr x26, [sp, #24]
str x0, [x26, #400]
str x1, [x26, #408]
str x2, [x26, #416]
str x3, [x26, #424]
str x4, [x26, #432]
str x5, [x26, #440]
str x6, [x26, #448]
str x7, [x26, #456]
str x8, [x26, #464]
str x9, [x26, #472]
str x10, [x26, #480]
str x11, [x26, #488]
str x12, [x26, #496]
str x13, [x26, #504]
str x14, [x26, #512]
str x15, [x26, #520]
str x16, [x26, #528]
str x17, [x26, #536]
str x19, [x26, #544]
str x20, [x26, #552]
str x21, [x26, #560]
str x22, [x26, #568]
str x23, [x26, #576]
str x24, [x26, #584]
str x25, [x26, #592]
add x27, x26, #200
str d0, [x26, #0]
st1 {v0.d}[1], [x27], #8
str d1, [x26, #8]
st1 {v1.d}[1], [x27], #8
str d2, [x26, #16]
st1 {v2.d}[1], [x27], #8
str d3, [x26, #24]
st1 {v3.d}[1], [x27], #8
str d4, [x26, #32]
st1 {v4.d}[1], [x27], #8
str d5, [x26, #40]
st1 {v5.d}[1], [x27], #8
str d6, [x26, #48]
st1 {v6.d}[1], [x27], #8
str d7, [x26, #56]
st1 {v7.d}[1], [x27], #8
str d8, [x26, #64]
st1 {v8.d}[1], [x27], #8
str d9, [x26, #72]
st1 {v9.d}[1], [x27], #8
str d10, [x26, #80]
st1 {v10.d}[1], [x27], #8
str d11, [x26, #88]
st1 {v11.d}[1], [x27], #8
str d12, [x26, #96]
st1 {v12.d}[1], [x27], #8
str d13, [x26, #104]
st1 {v13.d}[1], [x27], #8
str d14, [x26, #112]
st1 {v14.d}[1], [x27], #8
str d15, [x26, #120]
st1 {v15.d}[1], [x27], #8
str d16, [x26, #128]
st1 {v16.d}[1], [x27], #8
str d17, [x26, #136]
st1 {v17.d}[1], [x27], #8
str d18, [x26, #144]
st1 {v18.d}[1], [x27], #8
str d19, [x26, #152]
st1 {v19.d}[1], [x27], #8
str d20, [x26, #160]
st1 {v20.d}[1], [x27], #8
str d21, [x26, #168]
st1 {v21.d}[1], [x27], #8
str d22, [x26, #176]
st1 {v22.d}[1], [x27], #8
str d23, [x26, #184]
st1 {v23.d}[1], [x27], #8
str d24, [x26, #192]
st1 {v24.d}[1], [x27], #8
add sp, sp, #48
