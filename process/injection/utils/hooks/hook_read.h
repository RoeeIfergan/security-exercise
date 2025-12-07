#ifndef PROCESS_HOOK_READ_H
#define PROCESS_HOOK_READ_H

#include <stdio.h>

typedef ssize_t (*recv_f_type)(int sockfd, void *buf, size_t len, int flags);
static recv_f_type real_recv = NULL;

ssize_t my_recv(int sock_fd, void *buffer, size_t len, int flags);

#endif //PROCESS_HOOK_READ_H