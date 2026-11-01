# Sourced by the build scripts (sh): Debian cross gcc for i686 and armv7 (glibc, static
# binaries), the i386 and armhf OpenSSL of the image for openssl-sys and oqs-sys, and clang
# sysroots for bindgen. wasm32-wasip1 gets no C toolchain: C-backed crates count there only if
# they build with the Rust toolchain alone.
export CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc
export CXX_i686_unknown_linux_gnu=i686-linux-gnu-g++
export AR_i686_unknown_linux_gnu=i686-linux-gnu-ar
export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc
# The C code gets the Rust target's baseline (i686-unknown-linux-gnu is Pentium 4, with SSE2),
# above the cross gcc's default (i686, no SSE): blake2b-rs picks its SSE2 code from the Rust
# target features and stops with #error without -msse2.
export CFLAGS_i686_unknown_linux_gnu=-msse2
export CXXFLAGS_i686_unknown_linux_gnu=-msse2
export I686_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/i386-linux-gnu
export I686_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include
export BINDGEN_EXTRA_CLANG_ARGS_i686_unknown_linux_gnu="--sysroot=/usr/i686-linux-gnu -I/usr/include/i386-linux-gnu"
export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
export CXX_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-g++
export AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_LIB_DIR=/usr/lib/arm-linux-gnueabihf
export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_INCLUDE_DIR=/usr/include
export BINDGEN_EXTRA_CLANG_ARGS_armv7_unknown_linux_gnueabihf="--sysroot=/usr/arm-linux-gnueabihf -I/usr/include/arm-linux-gnueabihf"
export OPENSSL_STATIC=1
export PKG_CONFIG_ALLOW_CROSS=1
export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_RUNNER="qemu-i386 -L /usr/i686-linux-gnu"
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUNNER="qemu-arm -L /usr/arm-linux-gnueabihf"
