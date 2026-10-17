//go:build !amd64 || purego

package cryptopq

func x25519Kernels() []x25519Kernel {
	return []x25519Kernel{{"dispatch", x25519}}
}

func x25519BaseKernels() []x25519BaseKernel {
	return []x25519BaseKernel{{"dispatch", x25519Base}}
}
