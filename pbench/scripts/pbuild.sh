# In the port-eng container (or the workflow's build container): build the pbench binaries for each
# target in $TARGETS into $OUT/<target>/ (default /t/pb/bin): new (all bins), base and aa flavors
# (kc, rv, meas) and meas-alt (blake2b-rs instead of libsodium). Static on i686 and armv7, where
# Debian's static libcrypto.a also needs zstd and zlib from $XLIB (default /usr/lib); a 256 MiB
# stack on wasm32-wasip1 (the harnesses' thread stack elsewhere). CARGO_FLAGS adds flags (for example --locked or --offline).
. "${SCRIPTS:-/p/scripts}/cross-env.sh"
XLIB=${XLIB:-/usr/lib}
OUT=${OUT:-/t/pb/bin}
TD=${TD:-/t/pb/t}
static="-C target-feature=+crt-static -C link-arg=-lzstd -C link-arg=-lz"
export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_RUSTFLAGS="$static -C link-arg=-L$XLIB/i386-linux-gnu"
# Debian's armhf libc has no rcrt1.o for static PIE: armv7 links static non-PIE.
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUSTFLAGS="$static -C relocation-model=static -C link-arg=-L$XLIB/arm-linux-gnueabihf"
export CARGO_TARGET_WASM32_WASIP1_RUSTFLAGS="-C link-arg=-zstack-size=268435456"
cd "${SRC:-/p/bench/pbench}"
fail=0
for T in ${TARGETS:-i686-unknown-linux-gnu armv7-unknown-linux-gnueabihf wasm32-wasip1}; do
  O=$OUT/$T
  mkdir -p $O
  for flavor in new base aa alt wb; do
    case $flavor in
      new) f=""; bins="--bins" ;;
      alt) f="--no-default-features --features alt"; bins="--bin meas" ;;
      wb) f="--features flavor-wb"; bins="--bin kc" ;;
      *) f="--features flavor-$flavor"; bins="--bin kc --bin rv --bin meas" ;;
    esac
    # No C toolchain on wasm32 for blake2b-rs; the wb barrier differs from new on wasm32 only.
    if [ $flavor = alt ] && [ $T = wasm32-wasip1 ]; then
      continue
    fi
    if [ $flavor = wb ] && [ $T != wasm32-wasip1 ]; then
      continue
    fi
    cargo +1.99.0 build --release --ignore-rust-version $CARGO_FLAGS --target $T --target-dir $TD $f $bins > ${LOGS:-/p/logs}/pb-$T-$flavor.log 2>&1
    rc=$?
    echo "$T $flavor rc=$rc"
    if [ $rc != 0 ]; then
      fail=1
      # Every error block and linker message in full (to the next blank line), so that a failed
      # run can be read from the workflow log alone; lines cut at 4000 characters (the link
      # command line).
      awk '/^(error|warning: linker std(err|out))/ { on = 1 } on { print substr($0, 1, 4000); n++ } /^$/ { on = 0 } n > 600 { exit }' ${LOGS:-/p/logs}/pb-$T-$flavor.log
      continue
    fi
    for b in kc kem kem2 dsa rv slh meas; do
      for x in "" .wasm; do
        src=$TD/$T/release/$b$x
        if [ -f $src ] && echo " $bins " | grep -qE -- "--bins | $b "; then
          cp $src $O/$b-$flavor$x
        fi
      done
    done
  done
  ls -la $O
done
exit $fail
