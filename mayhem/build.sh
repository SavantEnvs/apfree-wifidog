#!/usr/bin/env bash
#
# mayhem/build.sh — build the apfree-wifidog fuzz harnesses, their standalone reproducers and the
# self-test. Runs inside the commit image as `mayhem` in /mayhem; offline (every dependency is an
# apt package or lives under /opt/toolchains/deps).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The daemon only needs uci's headers here (uci_helper.h); no libuci symbol is linked by any target.
UCI=/opt/toolchains/deps/uci-f49a2fd
CPPFLAGS="-DAW_FW4 -DHAVE_LIBBPF -I$SRC/src -I$SRC/include -I$UCI/include"
LIBS="-lbpf -ljson-c -lmosquitto -levent -levent_openssl -lssl -lcrypto -lpthread -lresolv"
# Upstream's CMakeLists builds with --std=gnu99.
CSTD="-std=gnu99"
# Daemon sources linked into every harness. A harness that exercises a file other than conf.c or
# dns_snoop.c #includes it, so the instrumented copy is the one under test; fuzz_dns_response links conf.o.
LIB_SRCS="debug safe util"
# SanCov on the library objects, unconditionally, so the fuzzed code reports edges.
COV="-fsanitize=fuzzer-no-link"

FUZZ_BUILD="$SRC/build/fuzz"
TEST_BUILD="$SRC/build/tests"
rm -rf "$FUZZ_BUILD" "$TEST_BUILD"
mkdir -p "$FUZZ_BUILD" "$TEST_BUILD"

# 1) Sanitized project objects + harness support objects.
for f in $LIB_SRCS; do
    $CC $CSTD -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS $CPPFLAGS -c "src/$f.c" -o "$FUZZ_BUILD/$f.o"
done
$CC $CSTD -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS $CPPFLAGS -c mayhem/stubs.c -o "$FUZZ_BUILD/stubs.o"
# Daemon sources the control-channel targets link (fuzz_ws_frame: all four; fuzz_roam_event, which
# #includes roam_sync.c: conf and client_list), plus their stubs (mayhem/ctrl_stubs.c).
for f in conf client_list roam_sync api_handlers; do
    $CC $CSTD -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS $CPPFLAGS -c "src/$f.c" -o "$FUZZ_BUILD/$f.o"
done
$CC $CSTD -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS $CPPFLAGS -c mayhem/ctrl_stubs.c -o "$FUZZ_BUILD/ctrl_stubs.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$FUZZ_BUILD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

BASE_OBJS="$FUZZ_BUILD/debug.o $FUZZ_BUILD/safe.o $FUZZ_BUILD/util.o $FUZZ_BUILD/stubs.o $FUZZ_BUILD/lsan_off.o"

# 2) Each harness twice: libFuzzer and standalone (run-once) reproducer.
for t in fuzz_dns_response fuzz_conf_lists fuzz_ws_frame fuzz_roam_event; do
    case "$t" in
        fuzz_dns_response) OBJS="$BASE_OBJS $FUZZ_BUILD/conf.o" ;;
        fuzz_ws_frame) OBJS="$BASE_OBJS $FUZZ_BUILD/conf.o $FUZZ_BUILD/client_list.o $FUZZ_BUILD/roam_sync.o $FUZZ_BUILD/api_handlers.o $FUZZ_BUILD/ctrl_stubs.o" ;;
        fuzz_roam_event) OBJS="$BASE_OBJS $FUZZ_BUILD/conf.o $FUZZ_BUILD/client_list.o $FUZZ_BUILD/ctrl_stubs.o" ;;
        *) OBJS="$BASE_OBJS" ;;
    esac
    # ws_receive reads the 16/64-bit extended length with an unaligned *(uint64_t *)(data + 2); UBSan's
    # alignment check fires on every 127-length frame before the length check can be reached, so only
    # that one check is relaxed for this harness (ASan and the rest of UBSan stay on and halting).
    RELAX=""
    [ "$t" = fuzz_ws_frame ] && RELAX="-fno-sanitize=alignment"
    $CC $CSTD -O1 $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $CPPFLAGS $LIB_FUZZING_ENGINE \
        "mayhem/harnesses/$t.c" $OBJS $LIBS -o "$SRC/$t"
    $CC $CSTD -O1 $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $CPPFLAGS \
        "mayhem/harnesses/$t.c" "$FUZZ_BUILD/standalone_main.o" $OBJS $LIBS -o "$SRC/$t-standalone"
done

# 3) The self-test with the project's normal flags, independent of the sanitized build.
for f in $LIB_SRCS; do
    $CC $CSTD -O2 $COVERAGE_FLAGS $CPPFLAGS -c "src/$f.c" -o "$TEST_BUILD/$f.o"
done
$CC $CSTD -O2 $COVERAGE_FLAGS $CPPFLAGS -c mayhem/stubs.c -o "$TEST_BUILD/stubs.o"
$CC $CSTD -O2 $COVERAGE_FLAGS $CPPFLAGS mayhem/selftest.c \
    "$TEST_BUILD/debug.o" "$TEST_BUILD/safe.o" "$TEST_BUILD/util.o" "$TEST_BUILD/stubs.o" \
    $LIBS $COVERAGE_FLAGS -o "$SRC/build/tests/selftest"

# 4) Upstream's own CTest `review_fixes` (src/CMakeLists.txt: test/test_review_fixes.c + util, debug,
# safe, client_list; pthread). The test defines program_argv0, config_get_config,
# is_portal_auth_disabled and roam_cache_purge_expired itself, so it links neither stubs.o nor conf.o.
$CC $CSTD -O2 $COVERAGE_FLAGS $CPPFLAGS -c src/client_list.c -o "$TEST_BUILD/client_list.o"
$CC $CSTD -O2 $COVERAGE_FLAGS $CPPFLAGS test/test_review_fixes.c \
    "$TEST_BUILD/debug.o" "$TEST_BUILD/safe.o" "$TEST_BUILD/util.o" "$TEST_BUILD/client_list.o" \
    $LIBS $COVERAGE_FLAGS -o "$SRC/build/tests/test_review_fixes"
