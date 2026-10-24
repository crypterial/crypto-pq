#!/bin/sh
# Builds liboqs (one configuration) and links the harness statically against it.
# Usage: build-liboqs.sh <source dir> <name> <extra cmake flags...>
set -eu
SRC=$1
NAME=$2
shift 2
ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;KEM_frodokem_976_aes;KEM_frodokem_976_shake;KEM_frodokem_1344_aes;KEM_frodokem_1344_shake;KEM_efrodokem_976_aes;KEM_efrodokem_976_shake;KEM_efrodokem_1344_aes;KEM_efrodokem_1344_shake"
for s in sha2_128s sha2_128f sha2_192s sha2_192f sha2_256s sha2_256f shake_128s shake_128f shake_192s shake_192f shake_256s shake_256f; do
  ALGS="$ALGS;SIG_slh_dsa_pure_$s"
done
"${CMAKE:-/tmp/cmake/bin/cmake}" -S "$SRC" -B "/tmp/build-$NAME" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD="$ALGS" "$@" > "/tmp/cmake-$NAME.log" 2>&1
nice -n 19 make -C "/tmp/build-$NAME" -j2 oqs > "/tmp/make-$NAME.log" 2>&1
gcc -O3 -o "/tmp/cmp-$NAME" "$(dirname "$0")/cmp.c" -I"/tmp/build-$NAME/include" "/tmp/build-$NAME/lib/liboqs.a"
grep -E "OQS_DIST_BUILD|OQS_OPT_TARGET|OQS_USE_ARM|OQS_ENABLE_KEM_ml_kem_768_aarch64|OQS_ENABLE_SIG_ml_dsa_65_aarch64|CMAKE_C_FLAGS:|OQS_DIST_ARM64|OQS_USE_(AVX2|AVX512|BMI2|SHA)|OQS_ENABLE_(KEM_ml_kem_768|SIG_ml_dsa_65)_(avx2|x86_64)" "/tmp/build-$NAME/CMakeCache.txt" | sort || true
grep -E "^#define OQS_(USE|ENABLE_KEM_ml_kem_768|ENABLE_SIG_ml_dsa_65|DIST|SHA3|ENABLE_SHA3|OPT)" "/tmp/build-$NAME/include/oqs/oqsconfig.h" | sort || true
echo "avx512vl symbols in liboqs.a ($NAME): $(nm "/tmp/build-$NAME/lib/liboqs.a" 2>/dev/null | grep -ci avx512vl || true)"
echo "built /tmp/cmp-$NAME"
