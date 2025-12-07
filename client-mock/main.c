#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOME_IDENTIFIER "HOME_IDENTIFIER\n"
#define HOST "127.0.0.1"
#define PORT 443
#define BUF_SIZE 1024

int is_home_connection() {
    char buf[32];

    printf("Are you a legit or home connection?\n");
    printf("legit enter 0\nhome enter 1\n");
    printf("Please enter:\n");

    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "failed to read home input from user");
        return -1;
    }

    buf[strcspn(buf, "\n")] = '\0';

    if (strcmp(buf, "0") == 0) {
        return 0;
    } else if (strcmp(buf, "1") == 0) {
        return 1;
    }

    return -1;
}

int initiate_connection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)PORT);

    if (inet_aton(HOST, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", HOST);
        close(sock);

        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connetion!");
        close(sock);
        return -1;
    }

    return sock;
}

void print_server_response(char * buffer, const ssize_t buffer_size) {
    buffer[buffer_size] = '\0';

    char *p = buffer;

    while (*p) {
        char *newline = strchr(p, '\n');

        if (newline) {
            int len = (int)(newline - p);

            // Strip trailing '\r' if present
            if (len > 0 && p[len - 1] == '\r') {
                len--;
            }

            printf("[server] %.*s\n", len, p);
            p = newline + 1;  // move past '\n'
        } else {
            // Last chunk (no '\n'), also strip trailing '\r' if there
            int len = (int)strlen(p);
            if (len > 0 && p[len - 1] == '\r') {
                len--;
            }
            printf("[server] %.*s\n", len, p);
            break;
        }
    }
}

int interactive_session(int active_socket) {
    printf("Type messages and press Enter. Ctrl+D (EOF) to quit.\n");

    char sendbuf[BUF_SIZE];
    char recvbuf[BUF_SIZE];

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);

        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(active_socket, &readfds);

        int maxfd = (active_socket > STDIN_FILENO) ? active_socket : STDIN_FILENO;

        int rc = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Failed to read from select()");
            close(active_socket);
            return -1;
        }

        // Data from server
        if (FD_ISSET(active_socket, &readfds)) {
            ssize_t bytes_read = recv(active_socket, recvbuf, sizeof(recvbuf) - 1, 0);
            if (bytes_read < 0) {
                fprintf(stderr, "Failed to receive data from server");
                return -1;
            } else if (bytes_read == 0) {
                printf("Server closed connection\n");
                return -1;
            } else {
                print_server_response(recvbuf, bytes_read);
            }
        }

        // Input from user
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (!fgets(sendbuf, sizeof(sendbuf), stdin)) {
                // EOF (Ctrl+D) or error
                printf("EOF on stdin, exiting.\n");
                close(active_socket);
                return 1;
            }

            size_t len = strlen(sendbuf);
            if (len == 0)
                continue;

            // Send the whole line
            ssize_t total_sent = 0;
            while (total_sent < (ssize_t)len) {
                ssize_t sent = send(active_socket,
                                    sendbuf + total_sent,
                                    len - total_sent,
                                    0);
                if (sent < 0) {
                    fprintf(stderr, "Failed read user input!");
                    perror("send");
                    close(active_socket);
                    return -1;
                }
                total_sent += sent;
            }
        }
    }
}

int main()
{
    int is_home = is_home_connection();

    if (is_home == -1) {
        is_home = 0;
        printf("You will be a legit client!");
    }
    // int is_home_connection
    int sock = initiate_connection();

    if (sock < 0) {
        fprintf(stderr, "Failed to initiate connection!");
        return -1;
    }

    if (is_home == 1) {
        ssize_t sent = send(sock, HOME_IDENTIFIER, sizeof(HOME_IDENTIFIER), 0);
        if (sent < 0) {
            perror("sending failed!");
            close(sock);
            return 1;
        }
    } else {
        /* Simple HTTP/1.0 GET request */
        char request[256];
        snprintf(request, sizeof(request),
                 "GET / HTTP/1.0\r\n"
                 "Host: %s\r\n"
                 "\r\n", HOST);

        size_t request_len = strlen(request);
        size_t total_sent = 0;
        while (total_sent < request_len) {
            ssize_t bytes_sent = send(sock, request + total_sent, request_len - total_sent, 0);
            if (bytes_sent < 0) {
                fprintf(stderr, "Failed to send data to server!");
                close(sock);
                return 0;
            }
            total_sent += (size_t)bytes_sent;
        }
    }

    int closed_gracefully = interactive_session(sock);

    if (closed_gracefully != 1) {
        fprintf(stderr, "Client did not exit grcefully!");
    } else {
        fprintf(stdout, "Client exited gracefully!");
    }

    return 0;
}