#!/usr/bin/env bash
#
# mayhem/build.sh — build FRR's fuzz harnesses (sanitized) and its unit-test programs (normal flags).
# Runs in the commit image as `mayhem` in /mayhem; offline and re-runnable (all deps come from apt in the image).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# FRR's typesafe containers (lib/typerb.h, typesafe.h) recover the container from an embedded
# member with container_of(), which trips UBSan's combined type_mismatch handler (null / alignment /
# object-size) in a constructor before main(); the call-through-cast callbacks trip `function`.
# Only these four checks are relaxed; ASan and every other UBSan check keep halting.
RELAX="-fno-sanitize=function,null,alignment,object-size"
CONF_OPTS="--disable-doc --disable-grpc --disable-scripting --disable-snmp --disable-zeromq"
FUZZ_DIR="$SRC/mayhem/build-fuzz"
TEST_DIR="$SRC/mayhem/build-test"

./bootstrap.sh

# 1) The project, sanitized, for the harnesses. The clippy host tool is built with the same flags and
#    run during the build, hence detect_leaks=0 for the build step only (LSan is off in the targets
#    themselves via lsan_off.c).
mkdir -p "$FUZZ_DIR"
cd "$FUZZ_DIR"
if [ ! -f Makefile ]; then
    "$SRC/configure" CC="$CC" CFLAGS="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1" \
        LDFLAGS="${SANITIZER_FLAGS}" $CONF_OPTS
fi
ASAN_OPTIONS=detect_leaks=0 make -j"$MAYHEM_JOBS" lib/libfrr.la isisd/libisis.a

# 2) Harnesses: each linked twice (libFuzzer, and a run-once -standalone reproducer).
CPP="-I$SRC/lib/assert -I$SRC -I$SRC/include -I$SRC/lib -I$FUZZ_DIR -DHAVE_CONFIG_H"
ACF="-fms-extensions -fno-omit-frame-pointer -funwind-tables -Wno-microsoft-anon-tag"
HF="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1"
LIBS="-Wl,--whole-archive lib/.libs/libfrr.a -Wl,--no-whole-archive -lyang -ljson-c -latomic -lrt -lcap -lm -lcrypt"
OBJ="$FUZZ_DIR/obj"
mkdir -p "$OBJ"

$CC $HF -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
$CC $HF $CPP $ACF -c "$SRC/mayhem/fuzz_isis_tlv.c" -o "$OBJ/fuzz_isis_tlv.o"
$CC $HF $CPP $ACF -I"$SRC/tests/isisd" -c "$SRC/tests/isisd/test_common.c" -o "$OBJ/test_common.o"
$CC $HF $CPP $ACF -c "$SRC/mayhem/fuzz_prefix.c" -o "$OBJ/fuzz_prefix.o"
$CC $HF $CPP $ACF -c "$SRC/tests/lib/fuzz_zlog.c" -o "$OBJ/fuzz_zlog.o"
$CC $HF -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

# fuzz_isis_tlv: libFuzzer harness over the IS-IS TLV codec
$CC $SANITIZER_FLAGS $LIB_FUZZING_ENGINE -o /mayhem/fuzz_isis_tlv \
    "$OBJ/fuzz_isis_tlv.o" "$OBJ/test_common.o" "$OBJ/lsan_off.o" isisd/libisis.a $LIBS
$CC $SANITIZER_FLAGS -o /mayhem/fuzz_isis_tlv-standalone \
    "$OBJ/standalone_main.o" "$OBJ/fuzz_isis_tlv.o" "$OBJ/test_common.o" "$OBJ/lsan_off.o" isisd/libisis.a $LIBS

# fuzz_prefix: libFuzzer harness over lib/ address-string parsers
$CC $SANITIZER_FLAGS $LIB_FUZZING_ENGINE -o /mayhem/fuzz_prefix "$OBJ/fuzz_prefix.o" "$OBJ/lsan_off.o" $LIBS
$CC $SANITIZER_FLAGS -o /mayhem/fuzz_prefix-standalone \
    "$OBJ/standalone_main.o" "$OBJ/fuzz_prefix.o" "$OBJ/lsan_off.o" $LIBS

# fuzz_zlog: upstream's own stdin-driven zlog fuzzer (a plain main(), not libFuzzer)
$CC $SANITIZER_FLAGS -o /mayhem/fuzz_zlog "$OBJ/fuzz_zlog.o" "$OBJ/lsan_off.o" $LIBS

# 3) Unit tests, normal flags, clean independent build tree.
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
if [ ! -f Makefile ]; then
    env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" $CONF_OPTS
fi
make -j"$MAYHEM_JOBS" \
    tests/lib/test_stream tests/lib/test_ttable tests/lib/test_graph tests/lib/test_network_address \
    tests/lib/test_prefix2str tests/lib/test_printfrr \
    tests/isisd/test_isis_spf tests/isisd/test_isis_vertex_queue tests/isisd/test_fuzz_isis_tlv
