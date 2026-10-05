#!/usr/bin/env bash
# printf/mayhem/test.sh — RUN mpaland/printf's own Catch test suite (the test_suite binary built by
# mayhem/build.sh with normal flags) → CTRF. PATCH-grade oracle: it never compiles, only runs, and it
# asserts BEHAVIOR (every TEST_CASE is REQUIRE(...)'d output equality), so a no-op/exit(0) patch fails.
# Catch v2 exits non-zero on any failing test and prints a summary like:
#   "test cases: 32 | 32 passed"   (all pass) or "test cases: 32 | 30 passed | 2 failed".
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/test_suite"
[ -x "$BIN" ] || { echo "missing $BIN — run mayhem/build.sh first" >&2; exit 2; }

# Run the Catch suite at TEST-CASE granularity (-s would be assertion-level; case-level maps cleanly
# to CTRF tests). Capture output regardless of exit code so we can parse the summary line.
out="$("$BIN" 2>&1)"; rc=$?; echo "$out"

# Catch summary forms:
#   "test cases: 32 | 32 passed"                 -> passed=32 failed=0
#   "test cases: 32 | 30 passed | 2 failed"      -> passed=30 failed=2
#   "All tests passed (N assertions in 32 test cases)"  (when run with no failures, alt phrasing)
summ="$(printf '%s\n' "$out" | grep -E '^test cases:' | tail -1)"
passed="$(printf '%s\n' "$summ" | sed -n 's/.*| \([0-9][0-9]*\) passed.*/\1/p')"
failed="$(printf '%s\n' "$summ" | sed -n 's/.*| \([0-9][0-9]*\) failed.*/\1/p')"

if [ -z "${passed:-}" ] && [ -z "${failed:-}" ]; then
  # Fall back to the "All tests passed (... in N test cases)" phrasing.
  allpass="$(printf '%s\n' "$out" | sed -n 's/.*All tests passed (.* in \([0-9][0-9]*\) test case.*/\1/p' | tail -1)"
  if [ -n "$allpass" ]; then
    emit_ctrf "catch2" "$allpass" 0; exit $?
  fi
  echo "could not parse Catch summary; using exit code $rc" >&2
  emit_ctrf "catch2" 0 "$([ "$rc" -eq 0 ] && echo 0 || echo 1)"
  exit $?
fi
: "${passed:=0}" "${failed:=0}"

emit_ctrf "catch2" "$passed" "$failed"
