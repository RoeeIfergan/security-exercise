#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "unix_socket.h"
#include <errno.h>

#include "helpers.h"

#define SOCKET_PATH "/tmp/inject_unix_socket"

int initiate_unix_socket()
{
    int unix_socket_fd;
    struct sockaddr_un addr;

    if ((unix_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove any existing entry at that path (if exists)
    unlink(SOCKET_PATH);

    if (bind(unix_socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(unix_socket_fd);
        return -1;
        // exit(EXIT_FAILURE);
    }

    /*
     *  Since were using /tmp, the server process probably won't have access to
     *  it. Therefore we change it's permissions!
     */
    if (chmod(SOCKET_PATH, 0777) == -1) {
        perror("chmod");
        return 1;
    }

    return unix_socket_fd;
}

int listen_to_unix_socket(const int unix_socket_fd) {
    int client_fd;

    if (listen(unix_socket_fd, 5) == -1) {
        perror("listen");
        close(unix_socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on %s\n", SOCKET_PATH);

    if ((client_fd = accept(unix_socket_fd, NULL, NULL)) == -1) {
        perror("accept");
        close(unix_socket_fd);
        return -1;
    }

    return client_fd;
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
    return fd;
}


int send_fd_over_unix_socket(const int unix_socket, int fd_to_send, char * buffer, const size_t buffer_size) {
    struct msghdr msg = {0};
    struct iovec iov;

    iov.iov_base = buffer;
    iov.iov_len  = buffer_size;
    msg.msg_iov  = &iov;
    msg.msg_iovlen = 1;

    // Set up ancillary data buffer
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (!cmsg) {
        return -1;
    }

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    // Copy fd into the ancillary data
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    // set msg_controllen to the actual length used
    msg.msg_controllen = sizeof(cmsgbuf);

    if (sendmsg(unix_socket, &msg, 0) == -1) {
        return -1;
    }
    return 0;
}

ssize_t recv_fd_over_unix_socket(
    int unix_socket,
    int *received_fd,        // out: received fd, or -1 if none
    void *buffer,
    size_t expected_len)
{
    size_t total_received_bytes = 0;
    int have_read_incoming_fd = 0;

    if (received_fd) {
        *received_fd = -1;
    }

    while (total_received_bytes < expected_len) {
        fprintf(stderr, "[hooked] read: %lu, need: %lu\n", total_received_bytes, expected_len);

        struct msghdr msg;
        struct iovec iov;

        memset(&msg, 0, sizeof(msg));

        iov.iov_base = (char *)buffer + total_received_bytes;
        iov.iov_len  = expected_len - total_received_bytes;
        msg.msg_iov  = &iov;
        msg.msg_iovlen = 1;

        char cmsgbuf[CMSG_SPACE(sizeof(int))];

        if (!have_read_incoming_fd && received_fd) {
            // Only ask for control data until we've got the fd once
            msg.msg_control = cmsgbuf;
            msg.msg_controllen = sizeof(cmsgbuf);
        } else {
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
        }

        ssize_t n = recvmsg(unix_socket, &msg, 0);
        if (n < 0) {
            // error
            return -1;
        }
        if (n == 0) {
            // peer closed before we got everything
            errno = ECONNRESET;
            return -1;
        }

        total_received_bytes += (size_t)n;

        // Parse FD from ancillary data, only once
        if (!have_read_incoming_fd && received_fd && msg.msg_controllen > 0) {
            struct cmsghdr *cmsg;
            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {

                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type  == SCM_RIGHTS) {

                    memcpy(received_fd, CMSG_DATA(cmsg), sizeof(int));
                    have_read_incoming_fd = 1;
                    break;
                    }
                 }
        }
    }

    return (ssize_t)total_received_bytes;
}