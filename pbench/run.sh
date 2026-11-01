#!/bin/sh
# port-eng phase 1: the pbench binaries of one target under one runtime. First every output
# check (CHECK OK, or CHECK FAIL and no timing), then the timed rows unless MODE=check.
# Usage: run.sh <native|qemu-i386|qemu-arm|wasmtime|node> <bin dir> [MODE]
# Environment: WASMTIME (wasmtime binary), WASI_RUN (wasi-run.mjs), and the round counts below.
RT=$1
DIR=$2
MODE=${3:-all}
: "${R_PAIR:=5}" "${PAIR_BUDGET_S:=2}" "${MEAS_ROUNDS:=8}" "${DSA_ROUNDS:=9}" "${SLH_ROUNDS:=3}" "${KEM_ROUNDS:=31}"

# run <bin> <env assignments separated by commas, or -> <args...>
run() {
  bin=$1
  vars=$2
  shift 2
  set -f
  envs=""
  wenvs=""
  if [ "$vars" != "-" ]; then
    for v in $(echo "$vars" | tr ',' ' '); do
      envs="$envs $v"
      wenvs="$wenvs --env $v"
    done
  fi
  case $RT in
    native) env $envs "$DIR/$bin" "$@" ;;
    qemu-i386) env $envs qemu-i386 "$DIR/$bin" "$@" ;;
    qemu-arm) env $envs qemu-arm "$DIR/$bin" "$@" ;;
    wasmtime) "$WASMTIME" run $wenvs "$DIR/$bin.wasm" "$@" ;;
    node) env $envs node --no-warnings "$WASI_RUN" "$DIR/$bin.wasm" "$@" ;;
  esac
  rc=$?
  set +f
  return $rc
}

have() {
  case $RT in
    wasmtime|node) [ -f "$DIR/$1.wasm" ] ;;
    *) [ -f "$DIR/$1" ] ;;
  esac
}

fail=0

# Two known exclusions, the same as on x86-64 and ARM64 in the earlier runs: RustCrypto xmss
# 0.1.0-pre.0 rejects its own signatures, equal to crypto-pq's, for XMSSMT-SHA2_20/2_256 and
# 20/4_256 (sha-eng notes; its verify rows there are dropped); oqs and pqcrypto-frodo implement
# the unsalted round-3 FrodoKEM, so they count for the eFrodoKEM sets only (meas-eng run 1).
# Any other MISMATCH line fails the check.
KNOWN='^MISMATCH	RustCrypto	XMSSMT-SHA2_20/[24]_256: it rejects crypto-pq.s signature \(verify rows dropped\)$|^MISMATCH	FrodoKEM-(976|1344)-(AES|SHAKE)	(oqs|pqcrypto-frodo)	ciphertext size (15744 \(crypto-pq 15792\)|21632 \(crypto-pq 21696\))$'

check() {
  name=$1
  shift
  out=$(run "$@" 2>&1)
  rc=$?
  echo "$out" | sed "s/^/C $name\t/"
  if [ $rc != 0 ]; then
    echo "CHECKRC $name rc=$rc"
    fail=1
  fi
  if echo "$out" | grep -E '^MISMATCH' | grep -qvE "$KNOWN"; then
    echo "CHECKMISMATCH $name"
    fail=1
  fi
}

echo "RUNTIME $RT $(date -u +%FT%TZ)"
check kc kc-new - check
if have kc-wb; then
  check kc-wb kc-wb - check
fi
check rv rv-new - check
check meas meas-new PB_CHECK=1 all 1
check meas-base meas-base PB_CHECK=1 frodo 1
if have meas-alt; then
  check meas-alt meas-alt PB_CHECK=1 blake 1 blake2b
fi
check dsa dsa-new PB_CHECK=1 1
check slh slh-new PB_CHECK=1 port 1
check kem kem-new PB_CHECK=1 1
check kem2 kem2-new PB_CHECK=1 1

if [ $fail != 0 ]; then
  echo "CHECK FAIL $RT"
  exit 1
fi

echo "CHECK OK $RT"

[ "$MODE" = check ] && exit 0

t() {
  name=$1
  shift
  s=$(date +%s)
  run "$@" 2>&1 | sed "s/^/T $name\t/"
  echo "TIME $name $(( $(date +%s) - s )) s"
}

t kc kc-new PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR
t kc-base kc-base KC_MAIN=1,PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR
t kc-aa kc-aa KC_MAIN=aa,PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR
# The wasm32 barrier variant (bench 2): ML-KEM only, the one kc family with masks.
if have kc-wb; then
  t kc-wb kc-wb KC_MAIN=wb,PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR ML-KEM
fi
t rv rv-new PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR
# Base and A/A of category 4: SHA-2, HMAC and HKDF cases (filter "sha"); the stateful-signature
# code is the same in new and base.
t rv-base rv-base KC_MAIN=1,PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR sha
t rv-aa rv-aa KC_MAIN=aa,PAIR_BUDGET_S=$PAIR_BUDGET_S pair --rounds=$R_PAIR sha
t meas meas-new - all $MEAS_ROUNDS
t meas-base meas-base - frodo $MEAS_ROUNDS
if have meas-alt; then
  t meas-alt meas-alt - blake $MEAS_ROUNDS blake2b
fi
t dsa dsa-new - $DSA_ROUNDS
t slh slh-new - port $SLH_ROUNDS
t kem kem-new - $KEM_ROUNDS
t kem2 kem2-new - $KEM_ROUNDS
echo "DONE $RT $(date -u +%FT%TZ)"
