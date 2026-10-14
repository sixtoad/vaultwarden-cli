/* Reviewed self-contained Linux x86-64/AArch64 fixture. The only syscall is
 * exit. No libc, loader, file, network, subprocess, or helper access. */
typedef unsigned long word;
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
__attribute__((noreturn)) static void finish(int status) {
#if defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60L), "D"((long)status) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 93;
    register long x0 __asm__("x0") = status;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory", "cc");
#else
#error supported architectures are Linux x86-64 and AArch64
#endif
    for (;;) {}
}
void run(word *stack) {
    word argc = stack[0];
    char **argv = (char **)(stack + 1);
    char **env = argv + argc + 1;
    if (argc != 2 || !same(argv[1], "rehearsal.invalid")) finish(40);
    int found = 0;
    for (; *env; ++env) {
        if (same(*env, "REHEARSAL_CREDENTIAL=disposable-rehearsal-field-v1")) ++found;
        else if (!same(*env, "LANG=C") && !same(*env, "LC_ALL=C")) finish(41);
    }
    finish(found == 1 ? 0 : 42);
}
#if defined(__x86_64__)
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall run\nud2\n");
#elif defined(__aarch64__)
__asm__(".global _start\n_start:\nmov x0,sp\nbl run\nbrk #0\n");
#endif
