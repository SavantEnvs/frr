#!/usr/bin/env bash
#
# mayhem/build.sh — build FRR's bgpd fuzz harness (sanitized) and its unit-test programs (normal flags).
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
# This tree predates libyang 3 (the image's libyang-dev): its one removed flag name is spelled the new way.
COMPAT="-DLYD_NEW_PATH_OUTPUT=LYD_NEW_VAL_OUTPUT"
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
    "$SRC/configure" CC="$CC" CFLAGS="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $COMPAT" \
        LDFLAGS="${SANITIZER_FLAGS}" $CONF_OPTS
fi
# This tree does not declare that lib/mgmt.pb-c.h must exist before the objects that include it: build it first.
ASAN_OPTIONS=detect_leaks=0 make lib/mgmt.pb-c.h
ASAN_OPTIONS=detect_leaks=0 make -j"$MAYHEM_JOBS" lib/libfrr.la
ASAN_OPTIONS=detect_leaks=0 make -j"$MAYHEM_JOBS" bgpd/libbgp.a bgpd/rfp-example/librfp/librfp.a

# 2) Harness: linked twice (libFuzzer, and a run-once -standalone reproducer).
CPP="-I$SRC/lib/assert -I$SRC -I$SRC/include -I$SRC/lib -I$FUZZ_DIR -DHAVE_CONFIG_H"
ACF="-fms-extensions -fno-omit-frame-pointer -funwind-tables -Wno-microsoft-anon-tag"
HF="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1"
LIBS="bgpd/libbgp.a bgpd/rfp-example/librfp/librfp.a -Wl,--whole-archive lib/.libs/libfrr.a -Wl,--no-whole-archive -lyang -ljson-c -lprotobuf-c -latomic -lrt -lcap -lm -lcrypt"
OBJ="$FUZZ_DIR/obj"
mkdir -p "$OBJ"

$CC $HF -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
$CC $HF $CPP $ACF -c "$SRC/mayhem/fuzz_bgp_capability.c" -o "$OBJ/fuzz_bgp_capability.o"
$CC $HF -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

# fuzz_bgp_capability: libFuzzer harness over bgpd's Dynamic Capability message parser
$CC $SANITIZER_FLAGS $LIB_FUZZING_ENGINE -o /mayhem/fuzz_bgp_capability \
    "$OBJ/fuzz_bgp_capability.o" "$OBJ/lsan_off.o" $LIBS
$CC $SANITIZER_FLAGS -o /mayhem/fuzz_bgp_capability-standalone \
    "$OBJ/standalone_main.o" "$OBJ/fuzz_bgp_capability.o" "$OBJ/lsan_off.o" $LIBS

# 3) Unit tests, normal flags, clean independent build tree.
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
if [ ! -f Makefile ]; then
    env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="-g -O2 $COMPAT $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" $CONF_OPTS
fi
make lib/mgmt.pb-c.h
make -j"$MAYHEM_JOBS" lib/libfrr.la
make -j"$MAYHEM_JOBS" tests/bgpd/test_capability tests/bgpd/test_mp_attr tests/lib/test_stream
