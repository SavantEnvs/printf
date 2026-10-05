/*
 * mayhem/lsan_off.c — the sanctioned build-time LeakSanitizer off-switch (SPEC §6.2 item 15).
 *
 * Turns off ONLY the leak check at process exit; AddressSanitizer and UndefinedBehaviorSanitizer
 * stay fully active. Compiled with the same $SANITIZER_FLAGS as the harness and linked by
 * mayhem/build.sh into both sanitized binaries: /mayhem/fuzz_printf and /mayhem/fuzz_printf-standalone.
 */
int __lsan_is_turned_off(void) { return 1; }
