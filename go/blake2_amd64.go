//go:build !purego

package cryptopq

//go:noescape
func blake2bBlocksAVX(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte)

//go:noescape
func blake2sBlocksAVX(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte)

// The kernels take whole blocks; the BLAKE2s one needs only AVX, which AVX2 implies.

func blake2bBlocks(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte) {
	if !useAVX2 {
		blake2bBlocksGeneric(h, counter, flag, blocks)

		return
	}

	if n := len(blocks) &^ 127; n > 0 {
		blake2bBlocksAVX(h, counter, flag, blocks[:n])
	}
}

func blake2sBlocks(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte) {
	if !useAVX2 {
		blake2sBlocksGeneric(h, counter, flag, blocks)

		return
	}

	if n := len(blocks) &^ 63; n > 0 {
		blake2sBlocksAVX(h, counter, flag, blocks[:n])
	}
}
