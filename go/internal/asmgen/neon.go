package main

import "fmt"

// Advanced SIMD instructions that Go 1.25's arm64 assembler does not know, emitted as WORD with
// the instruction in a comment. Each encoding below follows the Arm Architecture Reference Manual;
// the tests of the kernels that use them compare with the portable code.

// An element of a vector register: register number and lane.
type element struct {
	reg, lane int
}

// The by-element forms with 32-bit lanes: L and H hold the lane, M:Rm the register.
func byElement32(base uint32, d, n int, m element) uint32 {
	return base | uint32(m.lane&1)<<21 | uint32(m.reg&16)<<16 | uint32(m.reg&15)<<16 | uint32(m.lane>>1)<<11 | uint32(n)<<5 | uint32(d)
}

// The by-element forms with 16-bit lanes: L, M and H hold the lane, Rm one of V0-V15.
func byElement16(base uint32, d, n int, m element) uint32 {
	if m.reg > 15 {
		panic("16-bit element operands must be in V0-V15")
	}

	return base | uint32(m.lane&2)<<20 | uint32(m.lane&1)<<20 | uint32(m.reg)<<16 | uint32(m.lane>>2)<<11 | uint32(n)<<5 | uint32(d)
}

func vector3(base uint32, d, n, m int) uint32 {
	return base | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
}

func (a *asm) word(encoding uint32, format string, args ...any) {
	a.op("WORD\t$%#08x // %s", encoding, fmt.Sprintf(format, args...))
}

// MUL Vd.4S, Vn.4S, Vm.S[i]
func (a *asm) mulElement32(d, n int, m element) {
	a.word(byElement32(0x4f808000, d, n, m), "mul v%d.4s, v%d.4s, v%d.s[%d]", d, n, m.reg, m.lane)
}

// MLS Vd.4S, Vn.4S, Vm.S[i]
func (a *asm) mlsElement32(d, n int, m element) {
	a.word(byElement32(0x6f804000, d, n, m), "mls v%d.4s, v%d.4s, v%d.s[%d]", d, n, m.reg, m.lane)
}

// UMULL Vd.2D, Vn.2S, Vm.S[i] (the low two lanes of n), or UMULL2 with high set (the high two).
func (a *asm) umullElement32(d, n int, m element, high bool) {
	base, name := uint32(0x2f80a000), "umull"

	if high {
		base, name = 0x6f80a000, "umull2"
	}

	a.word(byElement32(base, d, n, m), "%s v%d.2d, v%d.%s, v%d.s[%d]", name, d, n, map[bool]string{false: "2s", true: "4s"}[high], m.reg, m.lane)
}

// MUL Vd.4S, Vn.4S, Vm.4S
func (a *asm) mulVector32(d, n, m int) {
	a.word(vector3(0x4ea09c00, d, n, m), "mul v%d.4s, v%d.4s, v%d.4s", d, n, m)
}

// UMULL Vd.2D, Vn.2S, Vm.2S, or UMULL2 Vd.2D, Vn.4S, Vm.4S with high set.
func (a *asm) umullVector32(d, n, m int, high bool) {
	base, name, arrangement := uint32(0x2ea0c000), "umull", "2s"

	if high {
		base, name, arrangement = 0x6ea0c000, "umull2", "4s"
	}

	a.word(vector3(base, d, n, m), "%s v%d.2d, v%d.%s, v%d.%s", name, d, n, arrangement, m, arrangement)
}

// MUL Vd.8H, Vn.8H, Vm.H[i]
func (a *asm) mulElement16(d, n int, m element) {
	a.word(byElement16(0x4f408000, d, n, m), "mul v%d.8h, v%d.8h, v%d.h[%d]", d, n, m.reg, m.lane)
}

// MLS Vd.8H, Vn.8H, Vm.H[i]
func (a *asm) mlsElement16(d, n int, m element) {
	a.word(byElement16(0x6f404000, d, n, m), "mls v%d.8h, v%d.8h, v%d.h[%d]", d, n, m.reg, m.lane)
}

// UMULL Vd.4S, Vn.4H, Vm.H[i], or UMULL2 Vd.4S, Vn.8H, Vm.H[i] with high set.
func (a *asm) umullElement16(d, n int, m element, high bool) {
	base, name, arrangement := uint32(0x2f40a000), "umull", "4h"

	if high {
		base, name, arrangement = 0x6f40a000, "umull2", "8h"
	}

	a.word(byElement16(base, d, n, m), "%s v%d.4s, v%d.%s, v%d.h[%d]", name, d, n, arrangement, m.reg, m.lane)
}

// MUL Vd.8H, Vn.8H, Vm.8H
func (a *asm) mulVector16(d, n, m int) {
	a.word(vector3(0x4e609c00, d, n, m), "mul v%d.8h, v%d.8h, v%d.8h", d, n, m)
}

// UMULL Vd.4S, Vn.4H, Vm.4H, or UMULL2 Vd.4S, Vn.8H, Vm.8H with high set.
func (a *asm) umullVector16(d, n, m int, high bool) {
	base, name, arrangement := uint32(0x2e60c000), "umull", "4h"

	if high {
		base, name, arrangement = 0x6e60c000, "umull2", "8h"
	}

	a.word(vector3(base, d, n, m), "%s v%d.4s, v%d.%s, v%d.%s", name, d, n, arrangement, m, arrangement)
}

// MLS Vd.8H, Vn.8H, Vm.8H
func (a *asm) mlsVector16(d, n, m int) {
	a.word(vector3(0x6e609400, d, n, m), "mls v%d.8h, v%d.8h, v%d.8h", d, n, m)
}

// MLS Vd.4S, Vn.4S, Vm.4S
func (a *asm) mlsVector32(d, n, m int) {
	a.word(vector3(0x6ea09400, d, n, m), "mls v%d.4s, v%d.4s, v%d.4s", d, n, m)
}
