#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/socket.h>

#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>

#include "../utils/unix_socket.h"
#include "./utils/got_injection.h"
#include "../utils/helpers.h"

#include <sys/socket.h>
#include <netinet/in.h>   // struct sockaddr_in (optional, for logging)
#include <arpa/inet.h>
#include <errno.h>

#include "../connection_management.h"
#include "utils/hooks/hooked_accept.h"

#include "./utils/hooks/hook_global_state.h"
#include "utils/hooks/hook_read.h"

//TODO: Supress all logs in this file so server doesn't know it was injected. use the debug_print()

// int unix_socket = -1;
// int amount_of_socks = 0;

// data_correlator * read_data;
// char * data[HOME_IDENTIFIER_LEN];

void initialize_icp(void *arg) {
    fprintf(stderr, "connection to unix-socket..\n");
    int unix_socket_fd = connect_to_unix_socket();

    int * web_server_fd = (int*) calloc(1, sizeof(int));

    int rc = read(unix_socket_fd, web_server_fd, sizeof(*web_server_fd));
    char buf[100];

    if (rc > 0) {
        buf[rc] = '\0';
        printf("Server received: %s\n", buf);
    } else if (rc == -1) {
        perror("read");
    }
    fprintf(stderr, "connected to unix-socket!\n");

    int web_server_fd_int = *web_server_fd;
    fprintf(stderr, "[libhook] created unix-socket! fd=%d, web_server_fd=%d, rc=%d\n", unix_socket_fd, web_server_fd_int, rc);

    char required_buffer[1] = {0};
    if (send_fd_over_unix_socket(unix_socket_fd, web_server_fd_int, required_buffer, 1) == -1) {
        printf("Failed to send web server FD over unix socket to process via hook. fd: %d\n", *web_server_fd);
        return;
    }
    printf("sent listening fd: %d\n", web_server_fd_int);

    unix_socket = unix_socket_fd;

    printf("set global unix socket fd: %d\n", unix_socket_fd);

    // data_correlator * read_data = (data_correlator*) malloc(sizeof(data_correlator));
    char * data[HOME_IDENTIFIER_LEN];

}

__attribute__((constructor))
static void injected_init(void)
{
    fprintf(stderr, "[libhook] constructor in pid=%d\n", getpid());

    if (init_connection_storage() != 0){
        fprintf(stderr, "Failed to allocate FdTable for connection storage!\n");
        return;
    }

    set_timeout(2, initialize_icp, NULL);
    // int unix_socket_fd = initiate_unix_socket();

    //sleep(5);

    if (hook_plt_symbol("accept", (void *)hooked_accept, (void **)&real_accept) == 0) {
        fprintf(stderr,
                "[libhook] GOT hook for accept installed, real_accept=%p\n",
                real_accept);
    } else {
        fprintf(stderr, "[libhook] FAILED to hook accept\n");
    }

    if (hook_plt_symbol("recv", (void *)my_recv, (void **)&real_recv) == 0) {
        fprintf(stderr, "[libhook] GOT hook for recv installed, real_recv=%p\n", real_recv);
    } else {
        fprintf(stderr, "[libhook] FAILED to hook recv\n");
    }
}
