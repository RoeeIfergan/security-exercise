#define _GNU_SOURCE
#include "./hooked_accept.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>

#include <errno.h>

#include "../../../utils/unix_socket.h"
#include "../../../connection_management.h"

#include "hook_global_state.h"
#include "../../../utils/helpers.h"

int hooked_accept(const int sock_fd, struct sockaddr *addr, socklen_t *addr_len)
{
    debug_print(stdout, "[hooked] accept called\n");

    if (!real_accept) {
        // Fallback: resolve original accept if GOT hook didn't set it
        real_accept = (accept_f_type)dlsym(RTLD_NEXT, "accept");
        if (!real_accept) {
            // If this fails, avoid recursion and just bail
            errno = ENOSYS;
            return -1;
        }
    }

    debug_print(stdout, "[hooked] current unix socket: %d\n", unix_socket);

    if (unix_socket == -1) {
        debug_print(stdout, "[hooked] read connection from real accept on web server: %d\n", unix_socket);

        int client_fd = real_accept(sock_fd, addr, addr_len);

        return client_fd;
    }

    int * listening_fd = (int*) calloc(1, sizeof(int));

    if (listening_fd == NULL) {
        debug_print(stderr, "[hooked] Failed to allocate memory for received fd\n");
        return -1;
    }

    char required_buffer[sizeof(HOME_IDENTIFIER) + 1];
    debug_print(stderr, "[hooked] Waiting for socket from process. buff size: %lu\n", sizeof(HOME_IDENTIFIER));

    const ssize_t amount_of_bytes_read = recv_fd_over_unix_socket(unix_socket, listening_fd, required_buffer, sizeof(HOME_IDENTIFIER));

    if (amount_of_bytes_read <= 0) {
        debug_print(stderr, "[hooked] recv_fd_over_unix_socket failed: %zd\n",
                amount_of_bytes_read);
        return -1;
    }

    // debug_print(stdout, "[hooked] Receieved: \"%s\"\n", required_buffer);
    //
    // if (amount_of_bytes_read >= 0 &&
    // amount_of_bytes_read < (ssize_t)sizeof(required_buffer)) {
    //     required_buffer[amount_of_bytes_read] = '\0';  // now it's a C string
    // }

    debug_print(stdout, "[hooked] Receieved: \"%s\"\n", required_buffer);

    if (amount_of_bytes_read != sizeof(HOME_IDENTIFIER)) {
        debug_print(stderr, "[hooked] Received invalid msg size from process with socket. fd: %d, amount read: %ld\n", *listening_fd, amount_of_bytes_read);
        debug_print(stderr, "[hooked] Request: %lu\n", sizeof(HOME_IDENTIFIER));
        return -1;
    }

    debug_print(stderr, "[hooked] Received from process?\n");

    //TODO: Store required_buffer and return it in the recv

    if (fdt_set(&fd_table_storage, *listening_fd, required_buffer) != 0) {
        debug_print(stderr, "[hooked] Failed to save socket data. fd: %d, amount read: %ld\n", *listening_fd, amount_of_bytes_read);
        fdt_free(&fd_table_storage);
        return 1;
    }

    return *listening_fd;
}