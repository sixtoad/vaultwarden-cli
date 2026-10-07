/* Synthetic native Linux x86-64/AArch64 self-contained ELF; no libc, loader or runtime dependencies. */
typedef unsigned long U;
#if defined(__x86_64__)
#define NR_read 0
#define NR_exit 60
#define NR_write 1
#define NR_wait4 61
#define NR_kill 62
#define NR_getpid 39
#define NR_setsid 112
#define NR_openat 257
#define NR_readlinkat 267
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
#define NR_read 63
#define NR_exit 93
#define NR_write 64
#define NR_wait4 260
#define NR_kill 129
#define NR_getpid 172
#define NR_setsid 157
#define NR_openat 56
#define NR_readlinkat 78
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
static int prefix(const char *a,const char *b) {while (*b && *a == *b) {++a;++b;}return !*b;}
static int read_material(const char *path,const char *expected) {
    long fd=call(NR_openat,-100,(long)path,0,0);if(fd<0)return 0;
    char data[4096];long count=call(NR_read,fd,(long)data,sizeof(data),0);call(NR_close,fd,0,0,0);int needed=0;while(expected[needed])needed++;return count>=needed && prefix(data,expected);
}
static void mark(const char *path) {long fd=call(NR_openat,-100,(long)path,0101|01000,0600);if(fd<0)finish(71);call(NR_write,fd,(long)"ready",5,0);call(NR_close,fd,0,0,0);}
static char *quoted_path(char *option,int offset) {
    char *path=option+offset;int length=0;while(path[length])length++;
    if(length<2 || path[length-1]!='"')finish(66);path[length-1]=0;return path;
}
static int output_sink_is_null(const char *path) {
    char target[64];const char expected[]="/dev/null";
    long count=call(NR_readlinkat,-100,(long)path,(long)target,sizeof(target));
    if(count!=sizeof(expected)-1)return 0;
    for(U i=0;i<sizeof(expected)-1;i++)if(target[i]!=expected[i])return 0;
    return 1;
}
static void ssh_run(U argc,char **argv,char **env) {
    if(argc != 60 || !same(argv[1],"-F") || !same(argv[2],"/dev/null"))finish(60);
    const char *required[]={"CertificateFile=none","IdentityAgent=none","IdentitiesOnly=yes","GlobalKnownHostsFile=/dev/null","StrictHostKeyChecking=yes","UpdateHostKeys=no","VerifyHostKeyDNS=no","CheckHostIP=no","BatchMode=yes","PreferredAuthentications=publickey","PasswordAuthentication=no","KbdInteractiveAuthentication=no","ForwardAgent=no","ForwardX11=no","ClearAllForwardings=yes","ProxyCommand=none","ProxyJump=none","PermitLocalCommand=no","ControlMaster=no","ControlPath=none","RequestTTY=no","EscapeChar=none","LogLevel=QUIET"};
    if(!same(argv[3],"-o") || !prefix(argv[4],"IdentityFile=\"") || !same(argv[5],"-o") || !prefix(argv[6],"UserKnownHostsFile=\""))finish(61);
    for(int i=0;i<23;i++)if(!same(argv[7+i*2],"-o") || !same(argv[8+i*2],required[i]))finish(62);
    if(!same(argv[53],"-p") || !same(argv[54],"2222") || !same(argv[55],"-l") || !same(argv[56],"backup") || !same(argv[57],"--") || !same(argv[58],"backup.example.test"))finish(63);
    /* The argv count below is also checked; environment has no agent/signing socket or ambient overrides. */
    for(;*env;env++)if(!same(*env,"LANG=C") && !same(*env,"LC_ALL=C"))finish(64);
    /* Inspect actual inherited descriptors independently of journal attribution. */
    if(!output_sink_is_null("/proc/self/fd/1") || !output_sink_is_null("/proc/self/fd/2")) {mark("ssh-output-unsafe");finish(68);}
    mark("ssh-output-sinks-verified");
    const char output[]="ssh-raw-output-sentinel\n";
    if(call(NR_write,1,(long)output,sizeof(output)-1,0)!=sizeof(output)-1 || call(NR_write,2,(long)output,sizeof(output)-1,0)!=sizeof(output)-1)finish(69);
    ignore_term();
    if(fork_process()==0) {
        call(NR_setsid,0,0,0,0);if(fork_process()!=0)finish(0);
        if(!read_material(quoted_path(argv[4],14),"-----BEGIN OPENSSH PRIVATE KEY-----") || !read_material(quoted_path(argv[6],20),"[backup.example.test]:2222 ssh-ed25519 "))finish(65);
        mark("ssh-material-readable");mark("tree-ready");
        for(;;)wait_signal();
    }
    while(call(NR_faccessat,-100,(long)"tree-ready",0,0)!=0){}
    if(same(argv[59],"/srv/ssh-nonzero"))finish(23);
    if(same(argv[59],"/srv/ssh-signal")) {call(NR_kill,call(NR_getpid,0,0,0,0),9,0,0);finish(67);}
    if(same(argv[59],"/srv/ssh-exit") || same(argv[59],"/srv/ssh-uncertain") || same(argv[59],"/srv/ssh-cleanup-failure"))finish(0);
    for(;;)wait_signal();
}
void run(U *stack) {
    U argc = stack[0]; char **argv = (char **)(stack+1); char **env = argv+argc+1;
    if (argc > 3 && same(argv[1], "-F")) {ssh_run(argc,argv,env);finish(70);}
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
