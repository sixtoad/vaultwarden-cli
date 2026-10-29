/* Disposable, synthetic probes. These are deliberately NOT a supervisor.
 * All descendants register before release, never fork after release, and have
 * independent hard lifetime bounds. That finite fixture contract is not a
 * contract for arbitrary protected operations. No secret is printed. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef IMAGE_VARIANT
#define IMAGE_VARIANT "original"
#endif

static void emit_process(pid_t pid) {
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != (int)sizeof(info))
        _exit(70);
    char record[384];
    int n = snprintf(record, sizeof(record),
        "{\"pid\":%d,\"ppid\":%d,\"pgid\":%d,\"uid\":%u,"
        "\"start_sec\":%llu,\"start_usec\":%llu}\n",
        pid, (int)info.pbi_ppid, getpgid(pid), info.pbi_uid,
        (unsigned long long)info.pbi_start_tvsec,
        (unsigned long long)info.pbi_start_tvusec);
    if (n <= 0 || n >= (int)sizeof(record) || write(STDOUT_FILENO, record, n) != n)
        _exit(70);
}

static void emit_identity(void) { emit_process(getpid()); }

static void release_fd(int fd) {
    char value;
    if (read(fd, &value, 1) != 1 || value != 'R') _exit(71);
}

static void release_gate(void) { release_fd(STDIN_FILENO); }

static void bounded_wait(void) {
    mach_timebase_info_data_t base;
    if (mach_timebase_info(&base) != 0) _exit(70);
    uint64_t start = mach_continuous_time();
    while ((mach_continuous_time() - start) * (double)base.numer / base.denom < 1500000000.0)
        usleep(10000);
}

int main(int argc, char **argv) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 70;
    signal(SIGALRM, SIG_DFL);
    alarm(8); /* Backstop even while waiting for a failed controller. */
    if (argc < 2) return 64;
    if (!strcmp(argv[1], "observe") && argc == 3) {
        emit_process((pid_t)strtol(argv[2], NULL, 10)); return 0;
    }
    if (!strcmp(argv[1], "image")) { puts(IMAGE_VARIANT); return 0; }
    if (!strcmp(argv[1], "peer") && argc == 4) {
        uid_t uid; gid_t gid;
        if (getpeereid(atoi(argv[2]), &uid, &gid) != 0) return 70;
        if (uid != (uid_t)strtoul(argv[3], NULL, 10)) {
            puts("denied"); return 77;
        }
        puts("peer-matched"); return 0;
    }
    if (!strcmp(argv[1], "inspection")) {
        volatile unsigned char private_value[64];
        if (read(STDIN_FILENO, (void *)private_value, sizeof(private_value)) != (ssize_t)sizeof(private_value))
            return 71;
        emit_identity();
        release_gate();
        for (size_t i = 0; i < sizeof(private_value); ++i) private_value[i] = 0;
        return 0;
    }
    if (!strcmp(argv[1], "crash")) {
        emit_identity(); release_gate(); raise(SIGABRT); return 70;
    }
    if (!strcmp(argv[1], "descendants") && argc == 3) {
        int parent_gate = atoi(argv[2]);
        /* Exactly three processes, all known before any process is released.
         * Parent waits; child creates a new session then double-forks; the
         * grandchild leaves the original group and ignores graceful shutdown. */
        emit_identity();
        release_gate();
        pid_t child = fork();
        if (child < 0) return 70;
        if (child == 0) {
            close(parent_gate);
            alarm(8); /* alarm timers are not inherited across fork. */
            if (setsid() < 0) _exit(70);
            emit_identity(); release_gate();
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(70);
            if (grandchild == 0) {
                alarm(8);
                signal(SIGTERM, SIG_IGN);
                emit_identity(); release_gate();
                bounded_wait(); _exit(0);
            }
            _exit(0);
        }
        int status;
        if (waitpid(child, &status, 0) != child) return 70;
        /* Dedicated gate prevents the parent from exiting before the crash
         * probe. It never competes with the grandchild's stdin release. */
        release_fd(parent_gate);
        return 0;
    }
    return 64;
}
