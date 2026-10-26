/* Synthetic owned process only. Payloads are test inputs, never collector output. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int connect_to(unsigned port, int family) {
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int result;
    if (family == AF_INET6) {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
        if (inet_pton(AF_INET6, "::1", &a.sin6_addr) != 1) return -1;
        result = connect(fd, (struct sockaddr *)&a, sizeof(a));
    } else {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
        if (inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) != 1) return -1;
        result = connect(fd, (struct sockaddr *)&a, sizeof(a));
    }
    if (result) { close(fd); return -1; }
    return fd;
}
int main(int argc, char **argv) {
    if (argc != 4) return 64;
    const char *mode = argv[1], *path = argv[2];
    unsigned port = (unsigned)strtoul(argv[3], NULL, 10);
    char buffer[64];
    if (!strcmp(mode, "hang")) { for (;;) pause(); }
    if (!strcmp(mode, "signal")) { raise(SIGUSR1); return 99; }
    if (!strcmp(mode, "clone")) { (void)syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0); return 99; }
    if (!strcmp(mode, "output")) {
        const char out[] = "SYNTHETIC-STDOUT-PAYLOAD-NEVER-CAPTURE";
        const char err[] = "SYNTHETIC-STDERR-PAYLOAD-NEVER-CAPTURE";
        if (write(1, out, sizeof(out)) < 0 || write(2, err, sizeof(err)) < 0) return 82;
    }
    if (!strcmp(mode, "socket")) {
        int s = connect_to(port, AF_INET);
        if (s < 0 || read(s, buffer, sizeof(buffer)) <= 0) return 70;
        close(s); return 0;
    }
    if (strcmp(mode, "connect") && strcmp(mode, "ipv6") && strcmp(mode, "badconnect")) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 71;
        if (!strcmp(mode, "pread")) {
            return pread(fd, buffer, sizeof(buffer), 0) < 0 ? 99 : 98;
        } else if (!strcmp(mode, "mmap")) {
            (void)mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0); return 99;
        } else if (!strcmp(mode, "eof")) {
            if (lseek(fd, 0, SEEK_END) < 0 || read(fd, buffer, sizeof(buffer)) != 0) return 72;
        } else if (!strcmp(mode, "error")) {
            if (read(-1, buffer, sizeof(buffer)) != -1 || errno != EBADF) return 73;
        } else if (!strcmp(mode, "fault")) {
            if (syscall(SYS_read, fd, (void *)1, 16) != -1 || errno != EFAULT) return 74;
        } else if (!strcmp(mode, "reuse")) {
            char other[4096];
            int n = snprintf(other, sizeof(other), "%s.other", path);
            if (n < 0 || (size_t)n >= sizeof(other)) return 75;
            close(fd);
            int next = open(other, O_RDONLY | O_CLOEXEC);
            if (next != fd || read(next, buffer, sizeof(buffer)) <= 0) return 76;
        } else if (!strcmp(mode, "rename")) {
            char moved[4096];
            int n = snprintf(moved, sizeof(moved), "%s.moved", path);
            if (n < 0 || (size_t)n >= sizeof(moved) || rename(path, moved) ||
                read(fd, buffer, sizeof(buffer)) <= 0 || rename(moved, path)) return 83;
        } else if (strcmp(mode, "open")) {
            if (read(fd, buffer, sizeof(buffer)) <= 0) return 77;
        }
        close(fd);
    }
    if (!strcmp(mode, "execfail")) {
        char *const args[] = {"missing", NULL};
        execv("/nonexistent-signal-synthetic-fixture", args);
        if (errno != ENOENT) return 78;
    }
    if (!strcmp(mode, "exec")) {
        char *const args[] = {argv[0], "connect", argv[2], argv[3], NULL};
        execv(argv[0], args); return 79;
    }
    int s = connect_to(port, !strcmp(mode, "ipv6") ? AF_INET6 : AF_INET);
    if (!strcmp(mode, "badconnect")) return s < 0 ? 0 : 80;
    if (s < 0) return 81;
    close(s);
    return 0;
}
