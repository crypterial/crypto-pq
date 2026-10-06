//go:build !purego

package cryptopq

//go:noescape
func blake2bBlocksARM(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte)

//go:noescape
func blake2sBlocksARM(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte)

// The kernels need only the base instruction set; they take whole blocks.

func blake2bBlocks(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte) {
	if n := len(blocks) &^ 127; n > 0 {
		blake2bBlocksARM(h, counter, flag, blocks[:n])
	}
}

func blake2sBlocks(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte) {
	if n := len(blocks) &^ 63; n > 0 {
		blake2sBlocksARM(h, counter, flag, blocks[:n])
	}
}
