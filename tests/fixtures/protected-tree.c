/* Synthetic x86-64 self-contained ELF; no libc, loader or runtime dependencies. */
typedef unsigned long U;
static long call(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void finish(long code) { call(60, code, 0, 0, 0); for (;;) {} }
static void ignore_term(void) { U action[4] = {1,0,0,0}; call(13, 15, (long)action, 0, 8); }
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
    long writer = call(57,0,0,0,0);
    if (writer < 0) finish(54);
    /* Concurrent processes each emit 200 KiB to a different standard stream. */
    long stream = writer == 0 ? 2 : 1;
    for (int i=0; i<8192; i++) {
        if (call(1, stream, (long)output, sizeof(output)-1, 0) != sizeof(output)-1) finish(55);
    }
    if (writer == 0) finish(0);
    int status = 0;
    if (call(61,writer,(long)&status,0,0) != writer || status != 0) finish(56);
    if (same(argv[1], "exit")) finish(0);
    if (same(argv[1], "nonzero")) finish(23);
    if (same(argv[1], "signal")) {
        call(62, call(39,0,0,0,0), 9, 0, 0); /* self SIGKILL */
        finish(57);
    }
    ignore_term();
    if (call(57,0,0,0,0) == 0) {
        call(112,0,0,0,0); /* setsid */
        if (call(57,0,0,0,0) != 0) finish(0);
        long fd = call(257,-100,(long)argv[2], 0101|01000,0600);
        if (fd < 0) finish(53);
        call(1,fd,(long)"ready",5,0); call(3,fd,0,0,0);
        for (;;) call(34,0,0,0,0);
    }
    while (call(21,(long)argv[2],0,0,0) != 0) { }
    if (same(argv[1], "orphan")) finish(0);
    for (;;) call(34,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall run\nud2\n");
