//
// Created by root on 12/6/25.
//

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "unix_socket.h"

#include "helpers.h"

#define SOCKET_PATH "/tmp/inject_unix_socket"

//TODO: currently server can have 1 single client. what happens if the web server has multiple processes? ..

int initiate_unix_socket()
{
    int fd;
    struct sockaddr_un addr;
    // char buf[100];
    // int rc;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
        // exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove any existing entry at that path (important!)
    unlink(SOCKET_PATH);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(fd);
        return -1;
        // exit(EXIT_FAILURE);
    }

    if (chmod(SOCKET_PATH, 0777) == -1) {
        perror("chmod");
        return 1;
    }

    return fd;
}

int listen_to_unix_socket(int fd) {
    int client_fd;

    if (listen(fd, 5) == -1) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on %s\n", SOCKET_PATH);

    if ((client_fd = accept(fd, NULL, NULL)) == -1) {
        perror("accept");
        close(fd);
        return -1;
        // exit(EXIT_FAILURE);
    }

    return client_fd;
    // rc = read(client_fd, buf, sizeof(buf) - 1);
    // if (rc > 0) {
    //     buf[rc] = '\0';
    //     printf("Server received: %s\n", buf);
    // } else if (rc == -1) {
    //     perror("read");
    // }
    //
    // close(client_fd);
    // close(fd);
    // unlink(SOCKET_PATH);
    // return 0;
}

int connect_to_unix_socket() {
    int fd;
    struct sockaddr_un addr;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        debug_print(stderr, "Failed create FD instance!");
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        debug_print(stderr, "Failed to connect to socket!");
        perror("connect");
        close(fd);
        return -1;
    }

    // const char *msg = "hello via unix socket";
    // if (write(fd, msg, strlen(msg)) == -1) {
    //     perror("write");
    // }

    return fd;
    // close(fd);
    // return 0;
}
