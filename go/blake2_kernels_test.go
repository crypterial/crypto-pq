package cryptopq

import (
	"math/rand/v2"
	"testing"
)

// The BLAKE2 kernels load the message word by word wherever the block starts, so they are checked
// against the portable code at every alignment of a 32-byte vector, on one to three blocks.
func TestBlake2KernelsAlignment(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 3))

	var buffer [3*128 + 32]byte

	for offset := range 32 {
		for blocks := 1; blocks <= 3; blocks++ {
			fillBytes(r, buffer[:])

			var h64 [8]uint64

			fillWords64(r, h64[:])

			counter64 := [2]uint64{r.Uint64(), r.Uint64()}

			flag64 := -uint64(offset & 1)

			message := buffer[offset : offset+128*blocks]

			wantH, gotH, wantC, gotC := h64, h64, counter64, counter64

			blake2bBlocksGeneric(&wantH, &wantC, flag64, message)

			blake2bBlocks(&gotH, &gotC, flag64, message)

			if gotH != wantH || gotC != wantC {
				t.Fatalf("blake2bBlocks of %d blocks at offset %d differs from the portable code", blocks, offset)
			}

			var h32 [8]uint32

			fillWords32(r, h32[:])

			counter32 := [2]uint32{r.Uint32(), r.Uint32()}

			flag32 := uint32(flag64)

			message = buffer[offset : offset+64*blocks]

			want32, got32, wantC32, gotC32 := h32, h32, counter32, counter32

			blake2sBlocksGeneric(&want32, &wantC32, flag32, message)

			blake2sBlocks(&got32, &gotC32, flag32, message)

			if got32 != want32 || gotC32 != wantC32 {
				t.Fatalf("blake2sBlocks of %d blocks at offset %d differs from the portable code", blocks, offset)
			}
		}
	}
}

// Every message word in turn set alone, so that a word loaded into the wrong lane or round shows
// up whatever the other words are.
func TestBlake2KernelsSingleWords(t *testing.T) {
	for word := range 16 {
		for _, value := range kernelEdges[1:] {
			var block [128]byte

			for j := range 8 {
				block[8*word+j] = byte(value >> (8 * j))
			}

			h64 := blake2bIV

			counter64 := [2]uint64{}

			wantH, gotH, wantC, gotC := h64, h64, counter64, counter64

			blake2bBlocksGeneric(&wantH, &wantC, ^uint64(0), block[:])

			blake2bBlocks(&gotH, &gotC, ^uint64(0), block[:])

			if gotH != wantH || gotC != wantC {
				t.Fatalf("blake2bBlocks with word %d = %#x alone differs from the portable code", word, value)
			}

			var small [64]byte

			for j := range 4 {
				small[4*word+j] = byte(value >> (8 * j))
			}

			h32 := iv256

			counter32 := [2]uint32{}

			want32, got32, wantC32, gotC32 := h32, h32, counter32, counter32

			blake2sBlocksGeneric(&want32, &wantC32, ^uint32(0), small[:])

			blake2sBlocks(&got32, &gotC32, ^uint32(0), small[:])

			if got32 != want32 || gotC32 != wantC32 {
				t.Fatalf("blake2sBlocks with word %d = %#x alone differs from the portable code", word, uint32(value))
			}
		}
	}
}
