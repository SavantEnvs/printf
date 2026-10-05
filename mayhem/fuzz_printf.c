// mayhem/fuzz_printf.c — libFuzzer harness for mpaland/printf's format-string engine.
//
// Ported from the original mayhemheroes integration (target: fuzz_printf). The old harness fed the
// raw fuzz bytes straight to printf_() WITHOUT a NUL terminator — printf_ reads a C string, so that
// tripped an out-of-bounds read on essentially every input (the fuzzer never reached the format
// parser). Here we NUL-terminate the input first so the engine actually parses it as a format string,
// then drive the bounded snprintf_ path (count-limited buffer + the full conversion machinery), which
// is the natural surface for this tiny embedded printf: %d/%x/%f/%s, width/precision/flags, etc.
//
// TYPE-MATCHED ARGUMENTS. A fixed vararg list is wrong for a fuzzed format: `%s` would read the
// first int as a char* and crash in _strnlen_s, which is the caller's undefined behaviour, not a
// printf bug. So the format is cut into segments of literal text plus at most one conversion, parsed
// the way _vsnprintf() parses it, and each segment is formatted with arguments of exactly the types
// that conversion reads ('*' ints first, then the value). Values rotate through a small pool so the
// edge cases (0, negative, INT_MIN, huge/tiny doubles, NaN/inf) are all reachable.
//
// BOUNDED WIDTH. _out_rev()/_ntoa_format() emit width padding one character at a time and keep going
// after the buffer is full, so `%999999999d` costs seconds and reaches no new code. A segment whose
// numeric width exceeds MAX_WIDTH is skipped. '*' widths come from the pool and are always small.
// Precision is not limited: integer precision is capped by the library's conversion buffer, and a
// huge %f precision is a real _ftoa bug (out-of-bounds pow10[] read) that must stay reachable.
#include "printf.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_WIDTH 4096

// printf.h requires the integrator to supply _putchar (the sink for printf_/vprintf_). We never call
// those direct-output variants in the harness, but the symbol must exist to link; make it a no-op.
void _putchar(char character) {
  (void)character;
}

enum arg_kind { ARG_NONE, ARG_INT, ARG_UINT, ARG_LL, ARG_ULL, ARG_DOUBLE, ARG_STR, ARG_PTR };

static const int int_pool[] = {0, 1, -1, 42, -12345, 2147483647, (-2147483647 - 1)};
static const long long ll_pool[] = {0, -1, 9223372036854775807LL, (-9223372036854775807LL - 1), 1234567890123LL};
static const double dbl_pool[] = {0.0, -0.0, 3.14159, -2.5e-7, 1e308, 4.9e-324, 1e20, 123456789.987654321};
static const int star_pool[] = {0, 4, 12, -12, 64};
static char str_arg[] = "harness";

#define POOL(p, i) (p[(i) % (sizeof(p) / sizeof(p[0]))])

// One snprintf_ call with nstars leading '*' ints followed by the value of the given kind.
#define CALL(value)                                                                 \
  do {                                                                              \
    if (nstars == 0) snprintf_(out, sizeof(out), seg, value);                       \
    else if (nstars == 1) snprintf_(out, sizeof(out), seg, s1, value);              \
    else snprintf_(out, sizeof(out), seg, s1, s2, value);                           \
  } while (0)

static void format_segment(const char *seg, int nstars, enum arg_kind kind, unsigned i) {
  char out[256];
  int s1 = POOL(star_pool, i), s2 = POOL(star_pool, i + 1);
  double d = POOL(dbl_pool, i);
  if (i % 11 == 7) d = NAN;
  if (i % 11 == 9) d = -INFINITY;
  switch (kind) {
    case ARG_NONE:
      // No value is read, but '*' ints still are, even when the spec has no specifier.
      if (nstars == 0) snprintf_(out, sizeof(out), seg);
      else if (nstars == 1) snprintf_(out, sizeof(out), seg, s1);
      else snprintf_(out, sizeof(out), seg, s1, s2);
      break;
    case ARG_INT:    CALL(POOL(int_pool, i)); break;
    case ARG_UINT:   CALL((unsigned)POOL(int_pool, i)); break;
    case ARG_LL:     CALL(POOL(ll_pool, i)); break;
    case ARG_ULL:    CALL((unsigned long long)POOL(ll_pool, i)); break;
    case ARG_DOUBLE: CALL(d); break;
    case ARG_STR:    CALL((const char *)str_arg); break;
    case ARG_PTR:    CALL((void *)(uintptr_t)POOL(ll_pool, i)); break;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Make a NUL-terminated copy so the format string is a valid C string (no OOB read on the format).
  char *fmt = (char *)malloc(size + 1);
  if (!fmt) return 0;
  memcpy(fmt, data, size);
  fmt[size] = '\0';

  const char *p = fmt, *start = fmt;
  for (unsigned i = 0; *p; i++) {
    // Literal text up to the next conversion.
    while (*p && *p != '%') p++;
    enum arg_kind kind = ARG_NONE;
    int nstars = 0, too_wide = 0;
    if (*p == '%') {
      p++;
      // Flags, width, precision and length, in _vsnprintf()'s order.
      while (*p == '0' || *p == '-' || *p == '+' || *p == ' ' || *p == '#') p++;
      if (*p == '*') {
        nstars++;
        p++;
      } else {
        unsigned long width = 0;
        while (*p >= '0' && *p <= '9') {
          if (width <= MAX_WIDTH) width = width * 10 + (unsigned long)(*p - '0');
          p++;
        }
        too_wide = width > MAX_WIDTH;
      }
      if (*p == '.') {
        p++;
        if (*p == '*') {
          nstars++;
          p++;
        } else {
          while (*p >= '0' && *p <= '9') p++;
        }
      }
      int is_long = 0;
      if (*p == 'l' || *p == 'j' || *p == 'z' || *p == 't') {
        is_long = 1;
        if (*p++ == 'l' && *p == 'l') p++;
      } else if (*p == 'h') {
        if (*++p == 'h') p++;
      }
      switch (*p) {
        case 'd': case 'i': kind = is_long ? ARG_LL : ARG_INT; break;
        case 'u': case 'x': case 'X': case 'o': case 'b': kind = is_long ? ARG_ULL : ARG_UINT; break;
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': kind = ARG_DOUBLE; break;
        case 'c': kind = ARG_INT; break;
        case 's': kind = ARG_STR; break;
        case 'p': kind = ARG_PTR; break;
        default: break;  // '%', an unknown specifier, or the end of the string: no value is read
      }
      // A spec cut off by the end of the string stays in the segment as-is: _vsnprintf() then steps
      // past the terminator, which is a real bug the fuzzer must be able to reach.
      if (*p) p++;
    }
    // Each segment gets its own exact-size copy. A spec cut off by the end of the string makes
    // _vsnprintf() read past the terminator; with a shared, larger buffer it would read stale bytes
    // of an earlier segment (e.g. a leftover `%s`) and fake a different crash. Exact size puts the
    // over-read straight into ASan's redzone, so it is reported as the bug it is.
    size_t len = (size_t)(p - start);
    char *seg = (char *)malloc(len + 1);
    if (!seg) break;
    memcpy(seg, start, len);
    seg[len] = '\0';
    if (!too_wide) format_segment(seg, nstars, kind, i);
    free(seg);
    start = p;
  }

  free(fmt);
  return 0;
}
