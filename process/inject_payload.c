// inject_payload.c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

static int (*real_accept)(int sockfd,
                          struct sockaddr *addr,
                          socklen_t *addrlen) = NULL;
__attribute__((constructor))
static void injected_init(void) {
    // Simple proof of execution: write to a file in /tmp
    FILE *f = fopen("/tmp/inject.log", "a");

    if (!f) {
        char error[1000];
        snprintf(error, sizeof(error), "failed to open file from pid: %d\n", getpid());
        perror(error);

    } else {
        fprintf(f, "Injected into pid=%d\n", getpid());
        fclose(f);
        printf("Injected!\n");
        fflush(stdout);
    }

    real_accept = dlsym(RTLD_NEXT, "accept");
    if (!real_accept) {
        fprintf(stderr, "[hook] dlsym(accept) failed\n");
    } else {
        fprintf(stderr, "[hook] accept hook installed\n");
    }

    fprintf(stderr, "[inject.so] Injected into pid=%d\n", getpid());
    fflush(stderr);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    fprintf(stderr, "\nhooked 4!\n");
    fflush(stderr);

    return 1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

    fprintf(stderr, "\nhooked!\n");
    fflush(stderr);

    if (!real_accept) {
        real_accept = dlsym(RTLD_NEXT, "accept");
        if (!real_accept) {
            // If we *still* don't have it, bail out
            return -1;
        }
    }

    int client_fd = real_accept(sockfd, addr, addrlen);

    if (client_fd >= 0 && addr && addrlen && *addrlen > 0) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        unsigned short port = 0;

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(sa->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(sa6->sin6_port);
        } else {
            snprintf(ip_str, sizeof(ip_str), "unknown_af(%d)", addr->sa_family);
        }

        fprintf(stderr,
                "[hook] accept: sockfd=%d -> client_fd=%d, peer=%s:%u\n",
                sockfd, client_fd, ip_str, port);
    } else {
        fprintf(stderr, "[hook] accept: sockfd=%d -> client_fd=%d (no addr)\n",
                sockfd, client_fd);
    }

    return client_fd;
}
