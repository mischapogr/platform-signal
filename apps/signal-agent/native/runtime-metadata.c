/* Owned-child Linux syscall metadata profile. No attachment or payload capture.
 * The ONLY PTRACE_PEEKDATA site decodes connect's bounded sockaddr. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <linux/stat.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#else
#error Unsupported native architecture
#endif

#define MAX_STOPS 100000U
#define MAX_RECORDS 4096U
#define MAX_BYTES (1024U * 1024U)
static volatile sig_atomic_t cancelled;
static pid_t child = -1;
static uint64_t deadline, sequence, generation, start_ticks, mount_ns;
static unsigned stops, records, output_bytes;
static long clock_ticks;
static const char *capture, *config, *host;
static char boot[37];
static void on_signal(int sig) { cancelled = sig; }
static uint64_t wall_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (INT64_MAX - 999999999U) / 1000000000U) return UINT64_MAX;
    return (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec;
}
static uint64_t milliseconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000U + (uint64_t)t.tv_nsec / 1000000U;
}
static void reap(void) {
    if (child <= 0) return;
    kill(child, SIGKILL);
    /* No task can be created: task-creation syscalls are stopped at entry. */
    for (;;) {
        int status;
        pid_t result = waitpid(child, &status, 0);
        if (result < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            /* A live owned child must never be silently abandoned. */
            kill(child, SIGKILL);
            continue;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        /* A queued ptrace stop can precede fatal-signal delivery. */
        kill(child, SIGKILL);
        (void)ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGKILL);
    }
    child = -1;
}
static bool safe_token(const char *s, size_t min, size_t max, bool hex) {
    size_t n = strlen(s);
    if (n < min || n > max) return false;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) continue;
        if (!hex && ((c >= 'g' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     c == '-' || c == '_' || c == '.')) continue;
        return false;
    }
    return true;
}
static bool uuid(const char *s) {
    if (strlen(s) != 36) return false;
    for (unsigned i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return false;
        } else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    }
    return true;
}
static bool emit(const char *kind, const char *format, ...) {
    char extra[1024], line[2048];
    va_list ap;
    va_start(ap, format);
    int e = vsnprintf(extra, sizeof(extra), format, ap);
    va_end(ap);
    uint64_t now = wall_ns();
    if (e < 0 || (size_t)e >= sizeof(extra) || now == UINT64_MAX) return false;
    int n = snprintf(line, sizeof(line),
        "{\"schema_version\":1,\"profile\":\"linux-owned-syscall-metadata/v1\","
        "\"capture_id\":\"%s\",\"config_sha256\":\"%s\",\"host\":\"%s\","
        "\"boot_id\":\"%s\",\"sequence\":%" PRIu64 ",\"timestamp_ns\":%" PRIu64 ","
        "\"pid\":%d,\"tid\":%d,\"start_ticks\":%" PRIu64 ",\"clock_ticks\":%ld,"
        "\"mount_ns\":%" PRIu64 ",\"audit_arch\":%u,\"execution_generation\":%" PRIu64 ",\"kind\":\"%s\"%s}\n",
        capture, config, host, boot, ++sequence,
        now, child, child, start_ticks, clock_ticks, mount_ns, NATIVE_ARCH, generation, kind, extra);
    if (n <= 0 || (size_t)n >= sizeof(line) || ++records > MAX_RECORDS ||
        output_bytes + (unsigned)n > MAX_BYTES) return false;
    /* Nonblocking pipe output; no indefinite wait on a non-consuming caller. */
    size_t at = 0;
    while (at < (size_t)n) {
        ssize_t wrote = write(STDOUT_FILENO, line + at, (size_t)n - at);
        if (wrote > 0) { at += (size_t)wrote; continue; }
        if (wrote < 0 && errno == EINTR && !cancelled) continue;
        return false;
    }
    output_bytes += (unsigned)n;
    return true;
}
static int fail(const char *reason) {
    (void)emit("gap", ",\"reason\":\"%s\",\"stops\":%u", reason, stops);
    reap();
    return 2;
}
static bool identity(void) {
    char path[96], data[4096];
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, data, sizeof(data) - 1);
    close(fd);
    if (n != 37 || data[36] != '\n') return false;
    memcpy(boot, data, 36); boot[36] = 0;
    if (!uuid(boot)) return false;
    snprintf(path, sizeof(path), "/proc/%d/stat", child);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    n = read(fd, data, sizeof(data) - 1); close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(data) - 1) return false;
    data[n] = 0;
    char *p = strrchr(data, ')');
    if (!p || p[1] != ' ') return false;
    p += 2;
    for (unsigned field = 3; field < 22; ++field) {
        p = strchr(p, ' ');
        if (!p) return false;
        ++p;
    }
    errno = 0; char *end;
    start_ticks = strtoull(p, &end, 10);
    if (errno || end == p || *end != ' ' || !start_ticks) return false;
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", child);
    struct stat st;
    if (stat(path, &st)) return false;
    mount_ns = st.st_ino;
    clock_ticks = sysconf(_SC_CLK_TCK);
    return clock_ticks > 0;
}
struct pending {
    bool valid;
    uint64_t nr, requested, entry_ns;
    int fd, pin;
    struct statx object;
    char address[INET6_ADDRSTRLEN];
    unsigned family, port, scope;
};
static void clear(struct pending *p) {
    if (p->pin >= 0) close(p->pin);
    memset(p, 0, sizeof(*p)); p->pin = -1;
}
static bool pin_fd(struct pending *p) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", child, p->fd);
    p->pin = open(path, O_PATH | O_CLOEXEC);
    if (p->pin < 0) return errno == ENOENT || errno == EBADF;
    if (statx(p->pin, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
              STATX_TYPE | STATX_INO | STATX_CTIME | STATX_MNT_ID, &p->object)) return false;
    unsigned required = STATX_TYPE | STATX_INO | STATX_CTIME | STATX_MNT_ID;
    return (p->object.stx_mask & required) == required;
}
/* Caller proves pointer is connect.args[1] and length is a native sockaddr size.
 * Overlapping final word stays strictly within [pointer,pointer+length). */
static bool connect_address(uint64_t pointer, size_t length, unsigned char *out) {
    if (length < sizeof(long) || length > sizeof(struct sockaddr_in6) ||
        pointer > UINTPTR_MAX - length) return false;
    for (size_t offset = 0; offset < length;) {
        size_t base = offset;
        if (base + sizeof(long) > length) base = length - sizeof(long);
        errno = 0;
        long value = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)(pointer + base), NULL);
        if (value == -1 && errno) return false;
        size_t skip = offset - base;
        size_t take = sizeof(long) - skip;
        memcpy(out + offset, (unsigned char *)&value + skip, take);
        offset += take;
    }
    return true;
}
static bool forbidden(const struct ptrace_syscall_info *info) {
    uint64_t nr = info->entry.nr;
    /* File mappings can read bytes without a read stop. Initial qualification
     * therefore uses a static owned program and refuses file-backed mappings. */
    if (nr == SYS_mmap && !(info->entry.args[3] & MAP_ANONYMOUS)) return true;
    /* No cloned/shared task, namespace, asynchronous FD access or ptrace escape. */
    switch (nr) {
    case SYS_clone: case SYS_unshare: case SYS_setns: case SYS_ptrace:
    case SYS_prctl: case SYS_ioctl: case SYS_readv: case SYS_pread64:
    case SYS_preadv: case SYS_sendfile: case SYS_splice: case SYS_tee:
    case SYS_vmsplice: case SYS_recvmsg: case SYS_recvmmsg:
    case SYS_process_vm_readv:
#ifdef SYS_preadv2
    case SYS_preadv2:
#endif
#ifdef SYS_copy_file_range
    case SYS_copy_file_range:
#endif
#ifdef SYS_bpf
    case SYS_bpf:
#endif
#ifdef SYS_fork
    case SYS_fork:
#endif
#ifdef SYS_vfork
    case SYS_vfork:
#endif
#ifdef SYS_clone3
    case SYS_clone3:
#endif
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup: case SYS_io_uring_enter: case SYS_io_uring_register:
#endif
#ifdef SYS_io_setup
    case SYS_io_setup: case SYS_io_submit:
#endif
#ifdef SYS_seccomp
    case SYS_seccomp:
#endif
        return true;
    default: return false;
    }
}
static bool enter(struct pending *p, const struct ptrace_syscall_info *info) {
    p->valid = true; p->nr = info->entry.nr;
    p->entry_ns = wall_ns();
    if (p->entry_ns == UINT64_MAX) return false;
    if (p->nr != SYS_read && p->nr != SYS_connect) return true;
    uint64_t fd = info->entry.args[0];
    /* Linux uses the low signed 32 bits for file descriptors. */
    p->fd = (int32_t)(uint32_t)fd;
    if (!pin_fd(p)) return false;
    if (p->nr == SYS_read) { p->requested = info->entry.args[2]; return true; }
    size_t length = info->entry.args[2];
    if (length != sizeof(struct sockaddr_in) && length != sizeof(struct sockaddr_in6))
        return false;
    unsigned char address[sizeof(struct sockaddr_in6)] = {0};
    if (!connect_address(info->entry.args[1], length, address)) return false;
    sa_family_t family; memcpy(&family, address, sizeof(family));
    if (family == AF_INET && length == sizeof(struct sockaddr_in)) {
        struct sockaddr_in a; memcpy(&a, address, sizeof(a));
        p->family = 4; p->port = ntohs(a.sin_port);
        return inet_ntop(AF_INET, &a.sin_addr, p->address, sizeof(p->address)) != NULL;
    }
    if (family == AF_INET6 && length == sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 a; memcpy(&a, address, sizeof(a));
        p->family = 6; p->port = ntohs(a.sin6_port); p->scope = a.sin6_scope_id;
        return inet_ntop(AF_INET6, &a.sin6_addr, p->address, sizeof(p->address)) != NULL;
    }
    return false;
}
static bool leave(struct pending *p, const struct ptrace_syscall_info *info) {
    if (p->nr != SYS_read && p->nr != SYS_connect) return true;
    uint64_t exit_ns = wall_ns();
    if (exit_ns == UINT64_MAX || exit_ns < p->entry_ns) return false;
    int64_t result = info->exit.rval;
    bool error = info->exit.is_error != 0;
    if (result <= -512 && result >= -516) return false; /* Internal restart codes. */
    if (p->nr == SYS_read && !error && (result < 0 || (uint64_t)result > p->requested))
        return false;
    if (!error && result >= 0 && p->pin < 0) return false;
    unsigned type = p->pin < 0 ? 0 : p->object.stx_mode & S_IFMT;
    if (p->nr == SYS_connect && (!error && (result != 0 || type != S_IFSOCK)))
        return false;
    char object[512];
    int n = snprintf(object, sizeof(object),
        ",\"fd\":%d,\"object_type\":%u,\"dev_major\":%u,\"dev_minor\":%u,"
        "\"inode\":%" PRIu64 ",\"mount_id\":%" PRIu64 ",\"ctime_sec\":%" PRId64 ","
        "\"ctime_nsec\":%u,\"result\":%" PRId64 ",\"error\":%s,"
        "\"syscall_entry_ns\":%" PRIu64 ",\"syscall_exit_ns\":%" PRIu64,
        p->fd, type, p->object.stx_dev_major, p->object.stx_dev_minor,
        (uint64_t)p->object.stx_ino, (uint64_t)p->object.stx_mnt_id,
        (int64_t)p->object.stx_ctime.tv_sec, p->object.stx_ctime.tv_nsec,
        result, error ? "true" : "false", p->entry_ns, exit_ns);
    if (n < 0 || (size_t)n >= sizeof(object)) return false;
    if (p->nr == SYS_read)
        return emit("read", "%s,\"requested\":%" PRIu64, object, p->requested);
    return emit("connect", "%s,\"family\":%u,\"address\":\"%s\",\"port\":%u,\"scope_id\":%u",
                object, p->family, p->address, p->port, p->scope);
}
int main(int argc, char **argv) {
    if (argc < 7 || strcmp(argv[5], "--") || argv[6][0] != '/' ||
        !uuid(argv[1]) || !safe_token(argv[2], 64, 64, true) ||
        !safe_token(argv[3], 1, 128, false)) return 64;
    errno = 0; char *end;
    unsigned long timeout = strtoul(argv[4], &end, 10);
    if (errno || *end || timeout < 1 || timeout > 30000) return 64;
    capture = argv[1]; config = argv[2]; host = argv[3];
    struct stat output;
    if (fstat(STDOUT_FILENO, &output) || !S_ISFIFO(output.st_mode)) return 64;
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK)) return 64;
    struct sigaction action = {0}; action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    deadline = milliseconds() + timeout;
    pid_t tracer = getpid();
    child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (getppid() != tracer || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != tracer) _exit(126);
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0) _exit(126);
        for (int i = 0; i < 3; ++i) if (dup2(null, i) < 0) _exit(126);
        if (null > 2) close(null);
        /* close_range prevents inherited descriptor/capture-pipe leaks. */
        if (syscall(SYS_close_range, 3U, ~0U, 0U)) _exit(126);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(126);
        raise(SIGSTOP);
        execv(argv[6], &argv[6]);
        _exit(127);
    }
    struct pending pending = { .pin = -1 };
    bool initial = true, seen_entry = false, startup_exit = true, after_exec = false;
    for (;;) {
        if (cancelled) { clear(&pending); return fail("cancelled"); }
        if (milliseconds() >= deadline) { clear(&pending); return fail("timeout"); }
        int status;
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == 0) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); continue; }
        if (got < 0) { if (errno == EINTR) continue; clear(&pending); return fail("wait"); }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            clear(&pending);
            bool clean = !initial && generation > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            bool written = emit(clean ? "end" : "gap", ",\"reason\":\"%s\",\"stops\":%u",
                                clean ? "exited" : "child_failed", stops);
            child = -1;
            return clean && written ? 0 : 2;
        }
        if (!WIFSTOPPED(status) || ++stops > MAX_STOPS) { clear(&pending); return fail("stop_limit"); }
        int sig = WSTOPSIG(status);
        unsigned event = (unsigned)status >> 16;
        if (initial) {
            if (sig != SIGSTOP || event || !identity() ||
                ptrace(PTRACE_SETOPTIONS, child, NULL,
                       (void *)(uintptr_t)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)))
                return fail("initialization");
            initial = false;
        } else if (event == PTRACE_EVENT_EXEC && sig == SIGTRAP) {
            if (!pending.valid || (pending.nr != SYS_execve && pending.nr != SYS_execveat)) {
                clear(&pending); return fail("exec_pairing");
            }
            clear(&pending); ++generation; after_exec = true;
            if (!emit("exec", "")) return fail("output_limit");
        } else if (sig == (SIGTRAP | 0x80) && !event) {
            struct ptrace_syscall_info info = {0};
            long size = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info);
            size_t required;
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
                required = offsetof(struct ptrace_syscall_info, entry.args) + sizeof(info.entry.args);
            else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
                required = offsetof(struct ptrace_syscall_info, exit.is_error) + sizeof(info.exit.is_error);
            else { clear(&pending); return fail("syscall_operation"); }
            if (size < 0 || (size_t)size < required || info.arch != NATIVE_ARCH) {
                clear(&pending); return fail("syscall_abi");
            }
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                if (pending.valid || (info.entry.nr & UINT64_C(0x40000000)) || forbidden(&info)) {
                    clear(&pending); return fail("unsupported_syscall");
                }
                seen_entry = true; after_exec = false;
                if (!enter(&pending, &info)) { clear(&pending); return fail("entry_metadata"); }
            } else if (!pending.valid) {
                /* Initial SIGSTOP's tgkill return, or successful exec return. */
                if (!after_exec && (seen_entry || !startup_exit)) return fail("exit_pairing");
                startup_exit = false;
                after_exec = false;
            } else {
                if (!leave(&pending, &info)) { clear(&pending); return fail("exit_metadata"); }
                clear(&pending);
            }
        } else { clear(&pending); return fail("signal_or_event"); }
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL)) { clear(&pending); return fail("resume"); }
    }
}
