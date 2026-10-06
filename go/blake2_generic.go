//go:build (!arm64 && !amd64) || purego

package cryptopq

func blake2bBlocks(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte) {
	blake2bBlocksGeneric(h, counter, flag, blocks)
}

func blake2sBlocks(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte) {
	blake2sBlocksGeneric(h, counter, flag, blocks)
}
