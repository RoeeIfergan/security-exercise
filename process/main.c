// find_port_owner.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "identify_listening_process_details.h"

int main(int argc, char *argv[]) {
    int port = 3000;

    printf("Looking for process listening on TCP port %d...\n", port);

    fd_details * listening_socket_details = (fd_details*) calloc(1, sizeof(fd_details));
    identify_listening_process_details(3000, listening_socket_details);

    if (listening_socket_details->pid == 0) {
        printf("No listening socket found on port %d (IPv4, /proc/net/tcp).\n", port);
        return 0;
    }

    printf("Found listening socket inode: %lu\n", listening_socket_details->inode);

    return 0;
}
