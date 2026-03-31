#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

#define LAUNCHER_SOCK_FD_ENV "BBOX_SECCOMP_NOTIFY_SOCK_FD"
#define PAYLOAD_SECCOMP_BPF_FLAG "--payload-seccomp-bpf"
#define X32_SYSCALL_BIT 0x40000000U

#if defined(__x86_64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_X86_64
static const uint32_t managed_syscalls[] = {
    __NR_socket,
    __NR_connect,
    __NR_getpeername,
    __NR_sendto,
    __NR_recvfrom,
    __NR_sendmsg,
    __NR_recvmsg,
    __NR_sendmmsg,
    __NR_recvmmsg,
#ifdef __NR_poll
    __NR_poll,
#endif
    __NR_ppoll,
    __NR_ioctl,
    __NR_close,
    __NR_dup,
    __NR_dup2,
    __NR_dup3,
    __NR_fcntl,
};
#elif defined(__aarch64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_AARCH64
static const uint32_t managed_syscalls[] = {
    __NR_socket,
    __NR_connect,
    __NR_getpeername,
    __NR_sendto,
    __NR_recvfrom,
    __NR_sendmsg,
    __NR_recvmsg,
    __NR_sendmmsg,
    __NR_recvmmsg,
#ifdef __NR_poll
    __NR_poll,
#endif
    __NR_ppoll,
    __NR_ioctl,
    __NR_close,
    __NR_dup,
    __NR_dup3,
    __NR_fcntl,
};
#else
#error "bbox-seccomp-launcher supports only x86_64 and aarch64"
#endif

static int starts_with_env(const char *entry) {
    size_t name_len = sizeof(LAUNCHER_SOCK_FD_ENV) - 1;
    return strncmp(entry, LAUNCHER_SOCK_FD_ENV "=", name_len + 1) == 0;
}

static int parse_sock_fd(void) {
    char *value = getenv(LAUNCHER_SOCK_FD_ENV);
    char *end = NULL;
    long fd = 0;

    if (value == NULL || *value == '\0') {
        fprintf(stderr, "%s is required\n", LAUNCHER_SOCK_FD_ENV);
        return -1;
    }

    errno = 0;
    fd = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || fd < 0 || fd > INT32_MAX) {
        fprintf(stderr, "parse %s: invalid fd\n", LAUNCHER_SOCK_FD_ENV);
        return -1;
    }
    return (int)fd;
}

static char **filtered_envp(void) {
    size_t count = 0;
    char **cursor = environ;
    char **envp = NULL;
    size_t idx = 0;

    for (; cursor != NULL && *cursor != NULL; ++cursor) {
        if (!starts_with_env(*cursor)) {
            ++count;
        }
    }

    envp = calloc(count + 1, sizeof(char *));
    if (envp == NULL) {
        return NULL;
    }

    for (cursor = environ; cursor != NULL && *cursor != NULL; ++cursor) {
        if (!starts_with_env(*cursor)) {
            envp[idx++] = *cursor;
        }
    }
    envp[idx] = NULL;
    return envp;
}

static int find_separator(int argc, char *argv[]) {
    int idx;
    for (idx = 1; idx < argc; ++idx) {
        if (strcmp(argv[idx], "--") == 0) {
            return idx;
        }
    }
    return -1;
}

static int parse_launcher_args(int argc, char *argv[], int *target_index, int *separator, const char **payload_seccomp_bpf) {
    int idx = 1;

    if (target_index == NULL || separator == NULL || payload_seccomp_bpf == NULL) {
        errno = EINVAL;
        return -1;
    }

    *payload_seccomp_bpf = NULL;
    while (idx < argc) {
        if (strcmp(argv[idx], PAYLOAD_SECCOMP_BPF_FLAG) == 0) {
            if (idx + 1 >= argc) {
                errno = EINVAL;
                return -1;
            }
            *payload_seccomp_bpf = argv[idx + 1];
            idx += 2;
            continue;
        }
        break;
    }

    if (idx >= argc) {
        errno = EINVAL;
        return -1;
    }

    *target_index = idx;
    *separator = find_separator(argc, argv);
    if (*separator < 0 || *separator + 1 >= argc || *separator <= *target_index) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int send_launcher_status(int sock_fd, uint8_t status, int send_fd, const char *message) {
    size_t message_len = message == NULL ? 0 : strlen(message);
    size_t payload_len = 1 + message_len;
    unsigned char *payload = malloc(payload_len);
    struct iovec iov;
    struct msghdr msg;
    char control[CMSG_SPACE(sizeof(int))];

    if (payload == NULL) {
        return -1;
    }
    payload[0] = status;
    if (message_len > 0) {
        memcpy(payload + 1, message, message_len);
    }

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = payload;
    iov.iov_len = payload_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (send_fd >= 0) {
        struct cmsghdr *cmsg;
        memset(control, 0, sizeof(control));
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(int));
    }

    if (sendmsg(sock_fd, &msg, 0) < 0) {
        free(payload);
        return -1;
    }

    free(payload);
    return 0;
}

static int install_notify_filter(int allowed_sendmsg_fd) {
#if defined(__x86_64__)
    static struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#ifdef __NR_poll
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_poll, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ppoll, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
#else
    static struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#ifdef __NR_poll
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_poll, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ppoll, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
#endif
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    long listener_fd;

#if defined(__x86_64__)
    filter[18].k = (uint32_t)allowed_sendmsg_fd;
#else
    filter[14].k = (uint32_t)allowed_sendmsg_fd;
#endif

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }

    listener_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener_fd < 0) {
        return -1;
    }

    return (int)listener_fd;
}

static int install_payload_seccomp_filter(const char *path) {
    int fd = -1;
    struct stat st;
    struct sock_filter *filter = NULL;
    struct sock_fprog prog;
    ssize_t total = 0;

    if (path == NULL || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    if (st.st_size <= 0 || (st.st_size % (off_t)sizeof(struct sock_filter)) != 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    filter = malloc((size_t)st.st_size);
    if (filter == NULL) {
        close(fd);
        return -1;
    }

    while (total < st.st_size) {
        ssize_t n = read(fd, ((char *)filter) + total, (size_t)(st.st_size - total));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(filter);
            close(fd);
            return -1;
        }
        if (n == 0) {
            free(filter);
            close(fd);
            errno = EINVAL;
            return -1;
        }
        total += n;
    }
    close(fd);

    prog.len = (unsigned short)(st.st_size / (off_t)sizeof(struct sock_filter));
    prog.filter = filter;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        int saved_errno = errno;
        free(filter);
        errno = saved_errno;
        return -1;
    }

    free(filter);
    return 0;
}

int main(int argc, char *argv[]) {
    int inherited_sock_fd = parse_sock_fd();
    int sock_fd = -1;
    int target_index = -1;
    int separator = -1;
    int notify_fd = -1;
    const char *payload_seccomp_bpf = NULL;
    char **envp = NULL;
    (void)managed_syscalls;

    if (inherited_sock_fd < 0) {
        return 1;
    }
    sock_fd = fcntl(inherited_sock_fd, F_DUPFD_CLOEXEC, 128);
    if (sock_fd < 0) {
        fprintf(stderr, "duplicate launcher socket: %s\n", strerror(errno));
        return 1;
    }
    close(inherited_sock_fd);
    if (argc < 4) {
        (void)send_launcher_status(sock_fd, 0, -1, "launcher target argv is required");
        fprintf(stderr, "launcher target argv is required\n");
        return 1;
    }

    if (parse_launcher_args(argc, argv, &target_index, &separator, &payload_seccomp_bpf) != 0) {
        (void)send_launcher_status(sock_fd, 0, -1, "launcher target argv is required");
        fprintf(stderr, "launcher target argv is required\n");
        return 1;
    }

    envp = filtered_envp();
    if (envp == NULL) {
        (void)send_launcher_status(sock_fd, 0, -1, "allocate launcher environment");
        fprintf(stderr, "allocate launcher environment: %s\n", strerror(errno));
        return 1;
    }

    notify_fd = install_notify_filter(sock_fd);
    if (notify_fd < 0) {
        (void)send_launcher_status(sock_fd, 0, -1, "install seccomp notify filter");
        fprintf(stderr, "install seccomp notify filter: %s\n", strerror(errno));
        free(envp);
        return 1;
    }

    if (send_launcher_status(sock_fd, 1, notify_fd, NULL) != 0) {
        fprintf(stderr, "send launcher status: %s\n", strerror(errno));
        free(envp);
        return 1;
    }

    close(sock_fd);

    if (payload_seccomp_bpf != NULL && install_payload_seccomp_filter(payload_seccomp_bpf) != 0) {
        fprintf(stderr, "install payload seccomp filter: %s\n", strerror(errno));
        free(envp);
        return 1;
    }

    execve(argv[target_index], &argv[separator + 1], envp);

    fprintf(stderr, "execve target: %s\n", strerror(errno));
    free(envp);
    return 1;
}
