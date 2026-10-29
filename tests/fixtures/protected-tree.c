/* Synthetic native Linux x86-64/AArch64 self-contained ELF; no libc, loader or runtime dependencies. */
typedef unsigned long U;
#if defined(__x86_64__)
#define NR_socket 41
#define NR_connect 42
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
#define NR_nanosleep 35
static long call(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static long fork_process(void) { return call(57,0,0,0,0); }
#elif defined(__aarch64__)
#define NR_socket 198
#define NR_connect 203
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
#define NR_nanosleep 101
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
/* Only the external test owner ends fixtures, after asserting survival. */
static char finish_path[4096];
static void set_finish_path(const char *marker) {
    int i=0;for(;marker[i] && i<4088;i++)finish_path[i]=marker[i];
    const char suffix[]=".finish";for(int j=0;j<8;j++)finish_path[i+j]=suffix[j];
}
static void wait_signal(void) {
    if(call(NR_faccessat,-100,(long)finish_path,0,0)==0)call(NR_exit,0,0,0,0);
    long delay[2]={0,50000000};call(NR_nanosleep,(long)delay,0,0,0);
}
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void finish(long code) { call(NR_exit, code, 0, 0, 0); for (;;) {} }
static void ignore_term(void) { U action[4] = {1,0,0,0}; call(NR_sigaction, 15, (long)action, 0, 8); }
static int prefix(const char *a,const char *b) {while (*b && *a == *b) {++a;++b;}return !*b;}
static int read_material(const char *path,const char *expected) {
    long fd=call(NR_openat,-100,(long)path,0,0);if(fd<0)return 0;
    char data[4096];long count=call(NR_read,fd,(long)data,sizeof(data),0);call(NR_close,fd,0,0,0);int needed=0;while(expected[needed])needed++;return count>=needed && prefix(data,expected);
}
static void mark(const char *path) {long fd=call(NR_openat,-100,(long)path,0101|01000,0600);if(fd<0)finish(71);call(NR_write,fd,(long)"ready",5,0);call(NR_close,fd,0,0,0);}
static void mark_pid(const char *path) {
    char reversed[24], digits[24];long pid=call(NR_getpid,0,0,0,0);int n=0;
    do { reversed[n++]='0'+pid%10;pid/=10; } while(pid);
    for(int i=0;i<n;i++)digits[i]=reversed[n-1-i];
    long fd=call(NR_openat,-100,(long)path,0101|01000,0600);if(fd<0)finish(71);
    call(NR_write,fd,(long)digits,n,0);call(NR_close,fd,0,0,0);
}
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
/* Exercise the actual request-local agent from the approved main process.
 * Cryptographic signing/interoperability is covered by Rust/OpenSSH tests. */
static long agent_fd = -1;
static int agent_identity(const char *path) {
    struct { unsigned short family; char path[108]; } address = {1,{0}};
    int n=0;while(path[n] && n<107){address.path[n]=path[n];n++;}
    if(path[n])return 0;
    long fd=call(NR_socket,1,1,0,0);if(fd<0)return 0;
    if(call(NR_connect,fd,(long)&address,n+3,0)!=0)return 0;
    const unsigned char query[]={0,0,0,1,11};
    if(call(NR_write,fd,(long)query,5,0)!=5)return 0;
    unsigned char response[512];U got=0;
    while(got<4){long size=call(NR_read,fd,(long)(response+got),4-got,0);if(size<=0)return 0;got+=size;}
    U size=((U)response[0]<<24)|((U)response[1]<<16)|((U)response[2]<<8)|response[3];
    if(size<9 || size>508)return 0;
    while(got<size+4){long count=call(NR_read,fd,(long)(response+got),size+4-got,0);if(count<=0)return 0;got+=count;}
    /* exactly one public identity, with no private-key export */
    if(response[4]!=12 || response[5] || response[6] || response[7] || response[8]!=1)return 0;
    /* Record the endpoint actually used, without reconstructing its private naming scheme. */
    long marker=call(NR_openat,-100,(long)"agent-path",0101|01000,0600);if(marker<0)return 0;
    long written=call(NR_write,marker,(long)path,n,0);call(NR_close,marker,0,0,0);if(written!=n)return 0;
    agent_fd=fd;
    return 1; /* keep the connection alive for cancellation/observation scenarios */
}
static void agent_exchange(const char *path,int expected,const char *output) {
    unsigned char bytes[2048];long file=call(NR_openat,-100,(long)path,0,0);if(file<0)finish(72);
    long n=call(NR_read,file,(long)bytes,sizeof(bytes),0);call(NR_close,file,0,0,0);
    if(n<5 || call(NR_write,agent_fd,(long)bytes,n,0)!=n)finish(73);
    U got=0;while(got<4){long count=call(NR_read,agent_fd,(long)(bytes+got),4-got,0);if(count<=0)finish(74);got+=count;}
    U size=((U)bytes[0]<<24)|((U)bytes[1]<<16)|((U)bytes[2]<<8)|bytes[3];
    if(size<1 || size>2044)finish(75);
    while(got<size+4){long count=call(NR_read,agent_fd,(long)(bytes+got),size+4-got,0);if(count<=0)finish(76);got+=count;}
    if(bytes[4]!=expected)finish(77);
    if(output){file=call(NR_openat,-100,(long)output,0101|01000,0600);if(file<0)finish(78);if(call(NR_write,file,(long)bytes,got,0)!=(long)got)finish(79);call(NR_close,file,0,0,0);}
}
static void ssh_run(U argc,char **argv,char **env) {
    if(argc != 60 || !same(argv[1],"-F") || !same(argv[2],"/dev/null"))finish(60);
    const char *required[]={"CertificateFile=none","IdentityAgent=request-scoped","IdentitiesOnly=no","GlobalKnownHostsFile=/dev/null","StrictHostKeyChecking=yes","UpdateHostKeys=no","VerifyHostKeyDNS=no","CheckHostIP=no","BatchMode=yes","PreferredAuthentications=publickey","PasswordAuthentication=no","KbdInteractiveAuthentication=no","ForwardAgent=no","ForwardX11=no","ClearAllForwardings=yes","ProxyCommand=none","ProxyJump=none","PermitLocalCommand=no","ControlMaster=no","ControlPath=none","RequestTTY=no","EscapeChar=none","LogLevel=QUIET"};
    if(!same(argv[3],"-o") || !same(argv[4],"IdentityFile=none") || !same(argv[5],"-o") || !prefix(argv[6],"UserKnownHostsFile=\""))finish(61);
    for(int i=0;i<23;i++)if(!same(argv[7+i*2],"-o") || (i==1 ? !prefix(argv[8+i*2],"IdentityAgent=\"") : !same(argv[8+i*2],required[i])))finish(62);
    if(!same(argv[53],"-p") || !same(argv[54],"2222") || !same(argv[55],"-l") || !same(argv[56],"backup") || !same(argv[57],"--") || !same(argv[58],"backup.example.test"))finish(63);
    /* The argv count below is also checked; environment has no agent/signing socket or ambient overrides. */
    for(;*env;env++)if(!same(*env,"LANG=C") && !same(*env,"LC_ALL=C"))finish(64);
    /* Inspect actual inherited descriptors independently of journal attribution. */
    if(!output_sink_is_null("/proc/self/fd/1") || !output_sink_is_null("/proc/self/fd/2")) {mark("ssh-output-unsafe");finish(68);}
    mark("ssh-output-sinks-verified");
    const char output[]="ssh-raw-output-sentinel\n";
    if(call(NR_write,1,(long)output,sizeof(output)-1,0)!=sizeof(output)-1 || call(NR_write,2,(long)output,sizeof(output)-1,0)!=sizeof(output)-1)finish(69);
    if(!read_material(quoted_path(argv[6],20),"[backup.example.test]:2222 ssh-ed25519 ") || !agent_identity(quoted_path(argv[10],15)))finish(65);
    if(same(argv[59],"/srv/ssh-nonzero")) {
        agent_exchange("ssh-bind-request",6,0);
        agent_exchange("ssh-sign-request",14,"ssh-sign-response");
    }
    mark("ssh-agent-ready");
    set_finish_path("tree-ready");
    ignore_term();
    if(fork_process()==0) {
        call(NR_setsid,0,0,0,0);if(fork_process()!=0)finish(0);
        mark_pid("tree-ready");
        if(same(argv[59],"/srv/ssh-clean-exit") || same(argv[59],"/srv/ssh-cleanup-failure"))finish(0);
        for(;;)wait_signal();
    }
    while(call(NR_faccessat,-100,(long)"tree-ready",0,0)!=0){}
    if(same(argv[59],"/srv/ssh-nonzero"))finish(23);
    if(same(argv[59],"/srv/ssh-signal")) {call(NR_kill,call(NR_getpid,0,0,0,0),9,0,0);finish(67);}
    if(same(argv[59],"/srv/ssh-clean-exit") || same(argv[59],"/srv/ssh-exit") || same(argv[59],"/srv/ssh-detached-recovery") || same(argv[59],"/srv/ssh-cleanup-failure"))finish(0);
    for(;;)wait_signal();
}
void run(U *stack) {
    U argc = stack[0]; char **argv = (char **)(stack+1); char **env = argv+argc+1;
    if (argc > 3 && same(argv[1], "-F")) {ssh_run(argc,argv,env);finish(70);}
    if (argc != 3) finish(50);
    int found = 0;
    int found_second = 0;
    for (; *env; ++env) {
        if (same(*env, "LOGIN_TOKEN=story18-synthetic-secret") || same(*env, "LOGIN_TOKEN=synthetic-password-sentinel")) found++;
        else if (same(*env, "LOGIN_TOKEN_TWO=synthetic-password-sentinel")) found_second++;
        else if (!same(*env, "LANG=C") && !same(*env, "LC_ALL=C")) finish(51);
    }
    if (found != 1) finish(52);
    if (found_second != (same(argv[1], "multi-tree") ? 1 : 0)) finish(58);
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
    set_finish_path(argv[2]);
    ignore_term();
    if (fork_process() == 0) {
        call(NR_setsid,0,0,0,0); /* setsid */
        if (fork_process() != 0) finish(0);
        mark_pid(argv[2]);
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
