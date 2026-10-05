#!/usr/bin/env bash
# printf/mayhem/build.sh — build the sanitized printf engine + the fuzz_printf libFuzzer harness (and
# its standalone reproducer), plus mpaland/printf's own Catch test suite (NORMAL flags) for mayhem/test.sh.
#
# printf is a single C translation unit (printf.c + printf.h). The fuzz build compiles printf.c with
# $SANITIZER_FLAGS so the FUZZED CODE is instrumented (not just the harness), and links it into the
# harness. The Catch test suite is a separate, clean C++ build with the project's normal flags so
# test.sh stays an honest PATCH oracle (it only RUNS, never compiles).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENV, overridable. SANITIZER_FLAGS uses `=` (not `:=`) so an explicit empty
# value (--build-arg SANITIZER_FLAGS=) is honored → no-sanitizer build (natural crash).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# DWARF debug info pinned to version ≤ 3 (§6.2 item 10): Mayhem's triage can't read DWARF ≥ 4, and
# clang-19's plain `-g` emits DWARF-5. The base exports DEBUG_FLAGS (e.g. -gdwarf-3); fall back to a
# safe default with `:=` so an unset/empty value still yields DWARF < 4 (this is a hard requirement,
# not an off-switch). Threaded through EVERY fuzz/harness/standalone compile+link below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS DEBUG_FLAGS

cd "$SRC"

# 1) Build the PROJECT (the printf engine the harness fuzzes) WITH $SANITIZER_FLAGS so the fuzzed
#    code is instrumented. Single TU → sanitized object → static lib.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=c99 -I"$SRC" -c "$SRC/printf.c" -o /tmp/printf.san.o
ar rcs /tmp/libprintf.san.a /tmp/printf.san.o

# The LeakSanitizer off-switch (mayhem/lsan_off.c), linked into both sanitized binaries below.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o /tmp/lsan_off.o

# 2a) The libFuzzer harness (the Mayhem target): harness + engine + sanitized lib.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=c99 -I"$SRC" \
    "$SRC/mayhem/fuzz_printf.c" /tmp/lsan_off.o $LIB_FUZZING_ENGINE /tmp/libprintf.san.a \
    -o /mayhem/fuzz_printf

# 2b) Standalone (non-fuzzer) reproducer: same harness + LLVM's run-once driver instead of the engine.
#     C harness, so $STANDALONE_FUZZ_MAIN compiles cleanly with $CC. Respects $SANITIZER_FLAGS.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=c99 -I"$SRC" \
    "$SRC/mayhem/fuzz_printf.c" /tmp/lsan_off.o /tmp/standalone_main.o /tmp/libprintf.san.a \
    -o /mayhem/fuzz_printf-standalone

# 3) printf's OWN functional test suite (Catch, test/test_suite.cpp), built with the project's NORMAL
#    flags (no sanitizers) in a separate location so mayhem/test.sh only RUNS it. The suite #includes
#    ../printf.h and ../printf.c inside a `test` namespace, so it needs only the .cpp + the headers.
#    CATCH_CONFIG_NO_POSIX_SIGNALS: the vendored Catch v2.7.0 declares `constexpr sigStackSize` from
#    MINSIGSTKSZ, which on modern glibc expands to a non-constexpr sysconf() call and fails to compile.
#    Disabling Catch's POSIX signal handler (only used to pretty-print on SIGSEGV/etc.) sidesteps it
#    without touching upstream; the assertions/oracle are unaffected.
$CXX -std=c++11 -O2 -DCATCH_CONFIG_NO_POSIX_SIGNALS -I"$SRC" -I"$SRC/test" \
     "$SRC/test/test_suite.cpp" -o /mayhem/test_suite
