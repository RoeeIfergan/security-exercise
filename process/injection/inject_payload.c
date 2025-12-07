#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <link.h>
#include <stdlib.h>

#include "../utils/unix_socket.h"
#include "./utils/got_injection.h"
#include "../utils/helpers.h"

#include "utils/hooks/hooked_accept.h"

#include "./utils/hooks/hook_global_state.h"
#include "utils/hooks/hook_read.h"

void initialize_icp(void *arg) {
    debug_print(stderr, "connection to unix-socket..\n");
    const int unix_socket_fd = connect_to_unix_socket();

    int * web_server_fd = (int*) calloc(1, sizeof(int));

    if (!web_server_fd) {
        debug_print(stderr, "Failed to allocacate web_server_fd\n");
        return;
    }
    const int rc = read(unix_socket_fd, web_server_fd, sizeof(*web_server_fd));

    if (rc > 0) {
        web_server_fd[rc] = '\0';
        debug_print(stdout, "Server received listening socket: %d\n", *web_server_fd);
    } else if (rc == -1) {
        debug_print(stderr, "Failed to read from unix socket");
        free(web_server_fd);

        return;
    }
    debug_print(stderr, "connected to unix-socket!\n");

    int web_server_fd_int = *web_server_fd;
    debug_print(stderr, "[libhook] created unix-socket! fd=%d, web_server_fd=%d, rc=%d\n", unix_socket_fd, web_server_fd_int, rc);

    char required_buffer[1] = {0};
    if (send_fd_over_unix_socket(unix_socket_fd, web_server_fd_int, required_buffer, 1) == -1) {
        debug_print(stderr, "Failed to send web server FD over unix socket to process via hook. fd: %d\n", *web_server_fd);
        free(web_server_fd);

        return;
    }
    debug_print(stdout, "sent listening fd: %d\n", web_server_fd_int);

    unix_socket = unix_socket_fd;

    debug_print(stdout, "set global unix socket fd: %d\n", unix_socket_fd);

    free(web_server_fd);
}

/*
 * Our Shared library injected!
 *
 * When the shared library is loaded, the constructor runs and does the following:
 * 1. A "connection storage" AKA a data structure to pass data between hooks
 * 2. Runs a PLT/GOT hook for accept & recv functions\
 *
 */
__attribute__((constructor))
static void injected_init(void)
{
    debug_print(stderr, "[libhook] constructor in pid=%d\n", getpid());

    if (init_connection_storage() != 0){
        debug_print(stderr, "Failed to allocate FdTable for connection storage!\n");
        return;
    }

    set_timeout(2, initialize_icp, NULL);

    if (hook_plt_symbol("accept", (void *)hooked_accept, (void **)&real_accept) == 0) {
        debug_print(stdout,
                "[libhook] GOT hook for accept installed, real_accept=%p\n",
                real_accept);
    } else {
        debug_print(stderr, "[libhook] FAILED to hook accept\n");
    }

    if (hook_plt_symbol("recv", (void *)my_recv, (void **)&real_recv) == 0) {
        debug_print(stdout, "[libhook] GOT hook for recv installed, real_recv=%p\n", real_recv);
    } else {
        debug_print(stderr, "[libhook] FAILED to hook recv\n");
    }
}
