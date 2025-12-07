#ifndef PROCESS_HOOKED_ACCEPT_H
#define PROCESS_HOOKED_ACCEPT_H

#include <stdio.h>
#include <sys/socket.h>

typedef int (*accept_f_type)(int sock_fd, struct sockaddr *addr, socklen_t * addr_len);
static accept_f_type real_accept = NULL;

int hooked_accept(int sock_fd, struct sockaddr *addr, socklen_t *addr_len);

#endif //PROCESS_HOOKED_ACCEPT_H