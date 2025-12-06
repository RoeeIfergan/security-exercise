/*
 * Very simple multi-client HTTP server using select().
 * Listens on port 443 and replies "Hello, world!" to any request.
 *
 * NOTE:
 *  - This is plain HTTP, not TLS/HTTPS.
 *  - For real HTTPS you must add a TLS library (OpenSSL, mbedTLS, etc.).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

#define PORT 3000 //change to 443          /* change to 8080 if you don't want root */
#define BACKLOG 16
#define MAX_CLIENTS FD_SETSIZE

static const char RESPONSE[] =
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 13\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Hello, world!";

void load_libdl ()
{
    if (0) { //because linker is using --as-needed
        // never executed, but forces the linker to keep libdl
    }
    void *h = dlopen("does_not_exist.so", RTLD_LAZY);
    if (h) dlclose(h);
}
int main(void)
{
    load_libdl();

    int listen_fd, rc;
    struct sockaddr_in addr;
    int opt = 1;

    int client_fds[MAX_CLIENTS];
    int i;

    for (i = 0; i < MAX_CLIENTS; ++i) {
        client_fds[i] = -1;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    /* Allow fast restart after crash */
    rc = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (rc < 0) {
        perror("setsockopt");
        close(listen_fd);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    pid_t pid = getpid();

    printf("[%d]: Listening on port %d...\n", pid, PORT);

    while (1) {
        fd_set readfds;
        int maxfd = listen_fd;

        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);

        /* Add clients to fd set */
        for (i = 0; i < MAX_CLIENTS; ++i) {
            int fd = client_fds[i];
            if (fd >= 0) {
                FD_SET(fd, &readfds);
                if (fd > maxfd) {
                    maxfd = fd;
                }
            }
        }

        rc = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }

        /* New incoming connection? */
        if (FD_ISSET(listen_fd, &readfds)) {
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            printf("got to accept");
            int new_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (new_fd < 0) {
                perror("accept");
            } else {
                printf("New connection from %s:%d (fd=%d)\n",
                       inet_ntoa(cli_addr.sin_addr),
                       ntohs(cli_addr.sin_port),
                       new_fd);

                /* Store in first free slot */
                for (i = 0; i < MAX_CLIENTS; ++i) {
                    if (client_fds[i] < 0) {
                        client_fds[i] = new_fd;
                        break;
                    }
                }

                if (i == MAX_CLIENTS) {
                    fprintf(stderr, "Too many clients, closing fd=%d\n", new_fd);
                    close(new_fd);
                }
            }
        }

        /* Handle existing clients */
        for (i = 0; i < MAX_CLIENTS; ++i) {
            int fd = client_fds[i];
            if (fd < 0) {
                continue;
            }

            if (FD_ISSET(fd, &readfds)) {
                char buf[1024];
                ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
                if (n <= 0) {
                    /* error or client closed */
                    if (n < 0) {
                        perror("recv");
                    }
                    printf("Client fd=%d disconnected\n", fd);
                    close(fd);
                    client_fds[i] = -1;
                } else {
                    /* We ignore the request contents and always send same response */
                    ssize_t total = 0;
                    ssize_t len = (ssize_t)strlen(RESPONSE);
                    while (total < len) {
                        ssize_t sent = send(fd, RESPONSE + total, len - total, 0);
                        if (sent <= 0) {
                            perror("send");
                            break;
                        }
                        total += sent;
                    }
                    // close(fd);
                    client_fds[i] = -1;
                }
            }
        }
    }

    close(listen_fd);
    return 0;
}