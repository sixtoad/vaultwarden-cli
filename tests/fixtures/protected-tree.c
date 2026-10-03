/* Synthetic native Linux x86-64/AArch64 self-contained ELF; no libc, loader or runtime dependencies. */
typedef unsigned long U;
#if defined(__x86_64__)
#define NR_exit 60
#define NR_write 1
#define NR_wait4 61
#define NR_kill 62
#define NR_getpid 39
#define NR_setsid 112
#define NR_openat 257
#define NR_close 3
#define NR_faccessat 269
#define NR_sigaction 13
#define NR_sigsuspend 130
static long call(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static long fork_process(void) { return call(57,0,0,0,0); }
#elif defined(__aarch64__)
#define NR_exit 93
#define NR_write 64
#define NR_wait4 260
#define NR_kill 129
#define NR_getpid 172
#define NR_setsid 157
#define NR_openat 56
#define NR_close 57
#define NR_faccessat 48
#define NR_sigaction 134
#define NR_sigsuspend 133
static long call(long n, long a, long b, long c, long d) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
    return x0;
}
/* clone(SIGCHLD, NULL, NULL, NULL, NULL) has fork semantics on AArch64. */
static long fork_process(void) { return call(220,17,0,0,0); }
#else
#error unsupported synthetic fixture architecture
#endif
static void wait_signal(void) { U mask = 0; call(NR_sigsuspend,(long)&mask,8,0,0); }
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void finish(long code) { call(NR_exit, code, 0, 0, 0); for (;;) {} }
static void ignore_term(void) { U action[4] = {1,0,0,0}; call(NR_sigaction, 15, (long)action, 0, 8); }
void run(U *stack) {
    U argc = stack[0]; char **argv = (char **)(stack+1); char **env = argv+argc+1;
    if (argc != 3) finish(50);
    int found = 0;
    for (; *env; ++env) {
        if (same(*env, "LOGIN_TOKEN=story18-synthetic-secret") || same(*env, "LOGIN_TOKEN=synthetic-password-sentinel")) found++;
        else if (!same(*env, "LANG=C") && !same(*env, "LC_ALL=C")) finish(51);
    }
    if (found != 1) finish(52);
    const char output[] = "story18-synthetic-secret\n";
    long writer = fork_process();
    if (writer < 0) finish(54);
    /* Concurrent processes each emit 200 KiB to a different standard stream. */
    long stream = writer == 0 ? 2 : 1;
    for (int i=0; i<8192; i++) {
        if (call(NR_write, stream, (long)output, sizeof(output)-1, 0) != sizeof(output)-1) finish(55);
    }
    if (writer == 0) finish(0);
    int status = 0;
    if (call(NR_wait4,writer,(long)&status,0,0) != writer || status != 0) finish(56);
    if (same(argv[1], "exit")) finish(0);
    if (same(argv[1], "nonzero")) finish(23);
    if (same(argv[1], "signal")) {
        call(NR_kill, call(NR_getpid,0,0,0,0), 9, 0, 0); /* self SIGKILL */
        finish(57);
    }
    ignore_term();
    if (fork_process() == 0) {
        call(NR_setsid,0,0,0,0); /* setsid */
        if (fork_process() != 0) finish(0);
        long fd = call(NR_openat,-100,(long)argv[2], 0101|01000,0600);
        if (fd < 0) finish(53);
        call(NR_write,fd,(long)"ready",5,0); call(NR_close,fd,0,0,0);
        for (;;) wait_signal();
    }
    while (call(NR_faccessat,-100,(long)argv[2],0,0) != 0) { }
    if (same(argv[1], "orphan")) finish(0);
    for (;;) wait_signal();
}
#if defined(__x86_64__)
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall run\nud2\n");

#elif defined(__aarch64__)
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\nbrk #0\n");
#endif
